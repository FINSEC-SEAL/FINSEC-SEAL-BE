CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE application_instance_leases (
    id uuid PRIMARY KEY,
    started_at timestamptz NOT NULL,
    heartbeat_at timestamptz NOT NULL,
    lease_expires_at timestamptz NOT NULL,
    transition_secret_hash bytea NOT NULL,
    stopped_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_instance_lease_time CHECK (
        heartbeat_at >= started_at
        AND lease_expires_at >= heartbeat_at
        AND (stopped_at IS NULL OR stopped_at >= started_at)
    )
);

ALTER TABLE api_idempotency_records
    ADD COLUMN owner_instance_id uuid REFERENCES application_instance_leases(id) ON DELETE RESTRICT,
    ADD COLUMN execution_finished_at timestamptz,
    ADD COLUMN recovery_reason varchar(60);

DROP TRIGGER api_idempotency_record_guard ON api_idempotency_records;
ALTER TABLE api_idempotency_records DROP CONSTRAINT api_idempotency_records_state_check;
ALTER TABLE api_idempotency_records DROP CONSTRAINT ck_api_idempotency_completion;

INSERT INTO application_instance_leases
    (id, started_at, heartbeat_at, lease_expires_at, transition_secret_hash, stopped_at)
VALUES
    ('00000000-0000-7000-8000-000000000009', now(), now(), now(), digest(gen_random_bytes(32), 'sha256'), now());

UPDATE api_idempotency_records
   SET state = 'RECOVERY_REQUIRED',
       owner_instance_id = '00000000-0000-7000-8000-000000000009',
       execution_finished_at = now(),
       recovery_reason = 'UPGRADE_ORPHAN'
 WHERE state = 'PROCESSING';
UPDATE api_idempotency_records
   SET execution_finished_at = completed_at
 WHERE state = 'COMPLETED';

ALTER TABLE api_idempotency_records
    ADD CONSTRAINT ck_api_idempotency_state
        CHECK (state IN ('PROCESSING', 'RECOVERY_REQUIRED', 'COMPLETED')),
    ADD CONSTRAINT ck_api_idempotency_completion CHECK (
        (state = 'PROCESSING'
            AND owner_instance_id IS NOT NULL
            AND response_status IS NULL AND response_body IS NULL AND completed_at IS NULL
            AND execution_finished_at IS NULL AND recovery_reason IS NULL)
        OR
        (state = 'RECOVERY_REQUIRED'
            AND owner_instance_id IS NOT NULL
            AND response_status IS NULL AND response_body IS NULL AND completed_at IS NULL
            AND execution_finished_at IS NOT NULL AND recovery_reason IS NOT NULL)
        OR
        (state = 'COMPLETED'
            AND response_status IS NOT NULL AND response_trace_id IS NOT NULL
            AND response_body IS NOT NULL AND completed_at IS NOT NULL
            AND execution_finished_at IS NOT NULL AND recovery_reason IS NULL)
    );

ALTER TABLE idempotency_recoveries
    ADD CONSTRAINT ck_idempotency_recovery_actor
        CHECK (recovered_by LIKE 'operator:%'),
    ADD CONSTRAINT ck_idempotency_recovery_verification
        CHECK (char_length(verification_reference) BETWEEN 8 AND 300
            AND verification_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]+$');

CREATE OR REPLACE FUNCTION finsec_validate_idempotency_recovery()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    original api_idempotency_records%ROWTYPE;
BEGIN
    SELECT * INTO original
      FROM api_idempotency_records
     WHERE id = NEW.idempotency_record_id
     FOR UPDATE;
    IF original.id IS NULL THEN
        RAISE EXCEPTION 'idempotency recovery original record does not exist' USING ERRCODE = '23503';
    END IF;
    IF original.state <> 'RECOVERY_REQUIRED'
       OR original.workspace_id IS DISTINCT FROM NEW.workspace_id
       OR original.actor_id IS DISTINCT FROM NEW.actor_id
       OR original.http_method IS DISTINCT FROM NEW.http_method
       OR original.request_path IS DISTINCT FROM NEW.request_path
       OR original.idempotency_key IS DISTINCT FROM NEW.idempotency_key
       OR original.request_digest IS DISTINCT FROM NEW.request_digest
       OR original.expires_at IS DISTINCT FROM NEW.original_expires_at
       OR original.execution_finished_at IS NULL
       OR NEW.recovered_at < original.execution_finished_at THEN
        RAISE EXCEPTION 'idempotency recovery must exactly match a finished RECOVERY_REQUIRED reservation'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER idempotency_recovery_original_guard
BEFORE INSERT ON idempotency_recoveries
FOR EACH ROW EXECUTE FUNCTION finsec_validate_idempotency_recovery();

CREATE OR REPLACE FUNCTION finsec_guard_idempotency_record()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    supplied_secret text;
    stored_secret_hash bytea;
    owner_lease_expired boolean;
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.state = 'COMPLETED' AND OLD.expires_at <= now() THEN
            RETURN OLD;
        END IF;
        IF OLD.state = 'RECOVERY_REQUIRED' AND EXISTS (
            SELECT 1 FROM idempotency_recoveries recovery
             WHERE recovery.idempotency_record_id = OLD.id
               AND recovery.resolution = 'RELEASE'
               AND recovery.workspace_id = OLD.workspace_id
               AND recovery.actor_id = OLD.actor_id
               AND recovery.http_method = OLD.http_method
               AND recovery.request_path = OLD.request_path
               AND recovery.idempotency_key = OLD.idempotency_key
               AND recovery.request_digest = OLD.request_digest
               AND recovery.original_expires_at = OLD.expires_at
        ) THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'idempotency reservation deletion requires expiry or exact audited RELEASE recovery'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.workspace_id IS DISTINCT FROM NEW.workspace_id
       OR OLD.actor_id IS DISTINCT FROM NEW.actor_id
       OR OLD.http_method IS DISTINCT FROM NEW.http_method
       OR OLD.request_path IS DISTINCT FROM NEW.request_path
       OR OLD.idempotency_key IS DISTINCT FROM NEW.idempotency_key
       OR OLD.request_digest IS DISTINCT FROM NEW.request_digest
       OR OLD.owner_instance_id IS DISTINCT FROM NEW.owner_instance_id
       OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION 'idempotency request identity is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.state = 'PROCESSING' AND NEW.state IN ('COMPLETED', 'RECOVERY_REQUIRED') THEN
        supplied_secret := current_setting('finsec.idempotency_transition_secret', true);
        SELECT transition_secret_hash, stopped_at IS NOT NULL OR lease_expires_at <= now()
          INTO stored_secret_hash, owner_lease_expired
          FROM application_instance_leases
         WHERE id = OLD.owner_instance_id;
        IF supplied_secret IS NOT NULL
           AND digest(supplied_secret, 'sha256') = stored_secret_hash
           AND NEW.execution_finished_at IS NOT NULL
           AND (
               (NEW.state = 'COMPLETED' AND NEW.recovery_reason IS NULL)
               OR
               (NEW.state = 'RECOVERY_REQUIRED'
                   AND NEW.recovery_reason IN ('REQUEST_CHAIN_FAILED', 'HTTP_5XX_RESPONSE'))
           ) THEN
            RETURN NEW;
        END IF;
        IF NEW.state = 'RECOVERY_REQUIRED'
           AND NEW.recovery_reason = 'OWNER_LEASE_EXPIRED'
           AND OLD.expires_at <= now()
           AND owner_lease_expired THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'PROCESSING transition requires the owning instance proof or an expired owner lease'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.state = 'RECOVERY_REQUIRED' AND NEW.state = 'COMPLETED' AND EXISTS (
        SELECT 1 FROM idempotency_recoveries recovery
         WHERE recovery.idempotency_record_id = OLD.id
           AND recovery.resolution = 'COMPLETE'
           AND recovery.workspace_id = OLD.workspace_id
           AND recovery.actor_id = OLD.actor_id
           AND recovery.http_method = OLD.http_method
           AND recovery.request_path = OLD.request_path
           AND recovery.idempotency_key = OLD.idempotency_key
           AND recovery.request_digest = OLD.request_digest
           AND recovery.original_expires_at = OLD.expires_at
    ) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid idempotency state transition' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER api_idempotency_record_guard
BEFORE UPDATE OR DELETE ON api_idempotency_records
FOR EACH ROW EXECUTE FUNCTION finsec_guard_idempotency_record();

CREATE OR REPLACE FUNCTION finsec_guard_application_instance_lease()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    supplied_secret text;
BEGIN
    IF OLD.id IS DISTINCT FROM NEW.id
       OR OLD.started_at IS DISTINCT FROM NEW.started_at
       OR OLD.transition_secret_hash IS DISTINCT FROM NEW.transition_secret_hash
       OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION 'application instance lease identity and transition secret are immutable'
            USING ERRCODE = '55000';
    END IF;
    supplied_secret := current_setting('finsec.idempotency_transition_secret', true);
    IF supplied_secret IS NULL
       OR digest(supplied_secret, 'sha256') IS DISTINCT FROM OLD.transition_secret_hash THEN
        RAISE EXCEPTION 'application instance lease update requires the owning instance proof'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.heartbeat_at < OLD.heartbeat_at
       OR NEW.lease_expires_at < OLD.lease_expires_at
       OR NEW.lease_expires_at < NEW.heartbeat_at
       OR OLD.stopped_at IS NOT NULL THEN
        RAISE EXCEPTION 'application instance lease time cannot move backwards or expire before heartbeat'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER application_instance_lease_guard
BEFORE UPDATE ON application_instance_leases
FOR EACH ROW EXECUTE FUNCTION finsec_guard_application_instance_lease();
