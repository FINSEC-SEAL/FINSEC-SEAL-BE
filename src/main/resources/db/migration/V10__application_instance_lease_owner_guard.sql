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
