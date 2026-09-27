CREATE TABLE generation_operations (
    id uuid PRIMARY KEY,
    admission_id uuid UNIQUE,
    admission_digest sha256_digest,
    workspace_id uuid NOT NULL REFERENCES workspaces(id),
    release_id uuid NOT NULL REFERENCES agent_releases(id),
    kind varchar(20) NOT NULL CHECK(kind IN ('CONTRACT','PATCH')),
    status varchar(30) NOT NULL CHECK(status IN ('QUEUED','RUNNING','SUCCEEDED','FAILED','RECOVERY_REQUIRED')),
    version_id uuid NOT NULL UNIQUE,
    contract_key varchar(100) NOT NULL,
    version integer NOT NULL CHECK(version > 0),
    template_key varchar(100) NOT NULL,
    reviewer_json jsonb NOT NULL,
    authority_stamp varchar(100) NOT NULL,
    authority_expires_at timestamptz NOT NULL,
    source_json jsonb NOT NULL,
    claim_token uuid,
    lease_expires_at timestamptz,
    outcome varchar(30),
    result_json jsonb,
    error_code varchar(100),
    error_stage varchar(40),
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz,
    CHECK ((admission_id IS NULL) = (admission_digest IS NULL)),
    CHECK ((status IN ('SUCCEEDED','FAILED','RECOVERY_REQUIRED')) = (finished_at IS NOT NULL)),
    CHECK (status <> 'RUNNING' OR (claim_token IS NOT NULL AND lease_expires_at IS NOT NULL))
);
CREATE UNIQUE INDEX generation_one_active_release ON generation_operations(release_id)
    WHERE status IN ('QUEUED','RUNNING');
CREATE INDEX generation_queue ON generation_operations(created_at,id) WHERE status='QUEUED';
CREATE TABLE contract_generation_records (
    operation_id uuid PRIMARY KEY REFERENCES generation_operations(id),
    version_id uuid REFERENCES safety_contract_versions(id),
    patch_proposal_id uuid REFERENCES patch_proposals(id),
    metadata_json jsonb NOT NULL,
    metadata_hash sha256_digest NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION finsec_guard_generation_operation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status IN ('SUCCEEDED','FAILED','RECOVERY_REQUIRED') THEN
        RAISE EXCEPTION 'terminal generation operation is immutable' USING ERRCODE='55000';
    END IF;
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'generation operation cannot be deleted' USING ERRCODE='55000';
    END IF;
    IF ROW(NEW.id,NEW.admission_id,NEW.admission_digest,NEW.workspace_id,NEW.release_id,NEW.kind,NEW.version_id,NEW.contract_key,NEW.version,
           NEW.template_key,NEW.reviewer_json,NEW.authority_stamp,NEW.authority_expires_at,NEW.source_json,NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id,OLD.admission_id,OLD.admission_digest,OLD.workspace_id,OLD.release_id,OLD.kind,OLD.version_id,OLD.contract_key,OLD.version,
           OLD.template_key,OLD.reviewer_json,OLD.authority_stamp,OLD.authority_expires_at,OLD.source_json,OLD.created_at) THEN
        RAISE EXCEPTION 'generation input is immutable' USING ERRCODE='55000';
    END IF;
    IF NOT ((OLD.status='QUEUED' AND NEW.status IN ('RUNNING','FAILED'))
         OR (OLD.status='RUNNING' AND NEW.status IN ('SUCCEEDED','FAILED','RECOVERY_REQUIRED'))) THEN
        RAISE EXCEPTION 'invalid generation state transition' USING ERRCODE='23514';
    END IF;
    IF NEW.status='SUCCEEDED' AND NOT EXISTS (SELECT 1 FROM contract_generation_records WHERE operation_id=NEW.id) THEN
        RAISE EXCEPTION 'successful generation requires committed evidence' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER generation_operation_guard BEFORE UPDATE OR DELETE ON generation_operations
    FOR EACH ROW EXECUTE FUNCTION finsec_guard_generation_operation();
CREATE FUNCTION finsec_guard_generation_record() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'generation record is immutable' USING ERRCODE='55000';
END;
$$;
CREATE TRIGGER generation_record_guard BEFORE UPDATE OR DELETE ON contract_generation_records
    FOR EACH ROW EXECUTE FUNCTION finsec_guard_generation_record();

CREATE OR REPLACE FUNCTION finsec_audit_resource_workspace(resource_kind varchar, target_id uuid)
RETURNS uuid
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    result uuid;
BEGIN
    CASE resource_kind
        WHEN 'GENERATION_OPERATION' THEN
            SELECT workspace_id INTO result FROM generation_operations WHERE id=target_id;
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
        WHEN 'ORACLE_RESULT' THEN
            SELECT agent.workspace_id INTO result
              FROM oracle_results oracle
              JOIN test_case_runs case_run ON case_run.id = oracle.test_case_run_id
              JOIN test_runs run ON run.id = case_run.test_run_id
              JOIN agent_releases release ON release.id = run.release_id
              JOIN agents agent ON agent.id = release.agent_id
             WHERE oracle.id = target_id;
        WHEN 'FINDING' THEN
            SELECT agent.workspace_id INTO result
              FROM findings finding
              JOIN agent_releases release ON release.id = finding.release_id
              JOIN agents agent ON agent.id = release.agent_id
             WHERE finding.id = target_id;
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

CREATE FUNCTION finsec_check_generation_scope() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE owning_workspace uuid; expected_version uuid; current_status varchar;
BEGIN
    IF TG_TABLE_NAME='generation_operations' THEN
        SELECT a.workspace_id INTO owning_workspace FROM agent_releases r JOIN agents a ON a.id=r.agent_id WHERE r.id=NEW.release_id;
        IF owning_workspace IS DISTINCT FROM NEW.workspace_id OR NEW.source_json->'catalog'->>'releaseId' IS DISTINCT FROM NEW.release_id::text
           OR NEW.reviewer_json->>'workspaceId' IS DISTINCT FROM NEW.workspace_id::text THEN
            RAISE EXCEPTION 'generation workspace/source mismatch' USING ERRCODE='23514';
        END IF;
        IF NEW.admission_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM api_idempotency_records
            WHERE id=NEW.admission_id AND workspace_id=NEW.workspace_id AND actor_id=NEW.reviewer_json->>'actorId'
              AND request_digest=NEW.admission_digest AND http_method='POST' AND state='PROCESSING') THEN
            RAISE EXCEPTION 'generation admission binding mismatch' USING ERRCODE='23514';
        END IF;
    ELSE
        SELECT version_id,status INTO expected_version,current_status FROM generation_operations WHERE id=NEW.operation_id;
        IF current_status IS DISTINCT FROM 'RUNNING' OR (NEW.version_id IS NOT NULL AND NEW.version_id<>expected_version) THEN
            RAISE EXCEPTION 'generation evidence reservation mismatch' USING ERRCODE='23514';
        END IF;
        IF NEW.patch_proposal_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM patch_proposals
            WHERE id=NEW.patch_proposal_id AND validation_json->>'candidateVersionId'=NEW.version_id::text) THEN
            RAISE EXCEPTION 'generation proposal binding mismatch' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER generation_input_scope BEFORE INSERT ON generation_operations FOR EACH ROW EXECUTE FUNCTION finsec_check_generation_scope();
CREATE TRIGGER generation_evidence_scope BEFORE INSERT ON contract_generation_records FOR EACH ROW EXECUTE FUNCTION finsec_check_generation_scope();
