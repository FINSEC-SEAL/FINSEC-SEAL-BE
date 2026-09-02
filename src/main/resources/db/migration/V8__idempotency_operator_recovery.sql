CREATE TABLE idempotency_recoveries (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
    idempotency_record_id uuid NOT NULL UNIQUE,
    actor_id varchar(120) NOT NULL,
    http_method varchar(10) NOT NULL CHECK (http_method IN ('POST', 'PUT', 'PATCH', 'DELETE')),
    request_path varchar(1000) NOT NULL,
    idempotency_key varchar(128) NOT NULL,
    request_digest sha256_digest NOT NULL,
    resolution varchar(20) NOT NULL CHECK (resolution IN ('RELEASE', 'COMPLETE')),
    verification_reference varchar(300) NOT NULL,
    response_digest sha256_digest,
    recovered_by varchar(120) NOT NULL,
    original_expires_at timestamptz NOT NULL,
    recovered_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_idempotency_recovery_response CHECK (
        (resolution = 'RELEASE' AND response_digest IS NULL)
        OR (resolution = 'COMPLETE' AND response_digest IS NOT NULL)
    )
);

CREATE INDEX ix_idempotency_recovery_scope
    ON idempotency_recoveries(workspace_id, actor_id, http_method, request_path, idempotency_key);

CREATE OR REPLACE FUNCTION finsec_guard_idempotency_recovery()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'idempotency recovery records are append-only' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER idempotency_recovery_append_only
BEFORE UPDATE OR DELETE ON idempotency_recoveries
FOR EACH ROW EXECUTE FUNCTION finsec_guard_idempotency_recovery();

CREATE OR REPLACE FUNCTION finsec_guard_idempotency_record()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.state = 'COMPLETED' AND OLD.expires_at <= now() THEN
            RETURN OLD;
        END IF;
        IF OLD.state = 'PROCESSING' AND EXISTS (
            SELECT 1 FROM idempotency_recoveries recovery
             WHERE recovery.idempotency_record_id = OLD.id AND recovery.resolution = 'RELEASE'
        ) THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'idempotency reservation deletion requires expiry or audited RELEASE recovery'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.workspace_id IS DISTINCT FROM NEW.workspace_id
       OR OLD.actor_id IS DISTINCT FROM NEW.actor_id
       OR OLD.http_method IS DISTINCT FROM NEW.http_method
       OR OLD.request_path IS DISTINCT FROM NEW.request_path
       OR OLD.idempotency_key IS DISTINCT FROM NEW.idempotency_key
       OR OLD.request_digest IS DISTINCT FROM NEW.request_digest
       OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION 'idempotency request identity is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.state <> 'PROCESSING' OR NEW.state <> 'COMPLETED' THEN
        RAISE EXCEPTION 'only PROCESSING to COMPLETED idempotency transition is allowed'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER api_idempotency_record_guard
BEFORE UPDATE OR DELETE ON api_idempotency_records
FOR EACH ROW EXECUTE FUNCTION finsec_guard_idempotency_record();

CREATE OR REPLACE FUNCTION finsec_audit_resource_workspace(resource_kind varchar, target_id uuid)
RETURNS uuid
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    result uuid;
BEGIN
    CASE resource_kind
        WHEN 'AGENT' THEN
            SELECT workspace_id INTO result FROM agents WHERE id = target_id;
        WHEN 'AGENT_RELEASE' THEN
            SELECT agent.workspace_id INTO result
              FROM agent_releases release JOIN agents agent ON agent.id = release.agent_id
             WHERE release.id = target_id;
        WHEN 'TEST_RUN' THEN
            SELECT agent.workspace_id INTO result
              FROM test_runs run JOIN agent_releases release ON release.id = run.release_id
              JOIN agents agent ON agent.id = release.agent_id WHERE run.id = target_id;
        WHEN 'TEST_CASE_RUN' THEN
            SELECT agent.workspace_id INTO result
              FROM test_case_runs case_run JOIN test_runs run ON run.id = case_run.test_run_id
              JOIN agent_releases release ON release.id = run.release_id
              JOIN agents agent ON agent.id = release.agent_id WHERE case_run.id = target_id;
        WHEN 'EXECUTION_EVENT' THEN
            SELECT workspace_id INTO result FROM execution_events WHERE id = target_id;
        WHEN 'EVIDENCE_REFERENCE' THEN
            SELECT workspace_id INTO result FROM evidence_references WHERE id = target_id;
        WHEN 'RELEASE_DECISION' THEN
            SELECT agent.workspace_id INTO result
              FROM release_decisions decision
              JOIN agent_releases release ON release.id = decision.release_id
              JOIN agents agent ON agent.id = release.agent_id WHERE decision.id = target_id;
        WHEN 'RELEASE_ATTESTATION' THEN
            SELECT agent.workspace_id INTO result
              FROM release_attestations attestation
              JOIN release_decisions decision ON decision.id = attestation.release_decision_id
              JOIN agent_releases release ON release.id = decision.release_id
              JOIN agents agent ON agent.id = release.agent_id WHERE attestation.id = target_id;
        WHEN 'CONTRACT_VERSION' THEN
            SELECT contract.workspace_id INTO result
              FROM safety_contract_versions version
              JOIN safety_contracts contract ON contract.id = version.contract_id
             WHERE version.id = target_id;
        WHEN 'IDEMPOTENCY_RECOVERY' THEN
            SELECT workspace_id INTO result FROM idempotency_recoveries WHERE id = target_id;
        ELSE
            RAISE EXCEPTION 'unsupported audit resource type %', resource_kind USING ERRCODE = '23514';
    END CASE;
    IF result IS NULL THEN
        RAISE EXCEPTION 'audit resource does not exist' USING ERRCODE = '23503';
    END IF;
    RETURN result;
END;
$$;
