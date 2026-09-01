CREATE OR REPLACE FUNCTION finsec_forbid_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = '55000';
END;
$$;

CREATE OR REPLACE FUNCTION finsec_assert_release_draft(target_release_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    current_state varchar(30);
BEGIN
    SELECT lifecycle_state INTO current_state FROM agent_releases WHERE id = target_release_id;
    IF current_state IS NULL THEN
        RAISE EXCEPTION 'release does not exist' USING ERRCODE = '23503';
    END IF;
    IF current_state <> 'DRAFT' THEN
        RAISE EXCEPTION 'release fingerprint inputs are immutable after analyze' USING ERRCODE = '55000';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION finsec_protect_release_row()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'agent release cannot be deleted' USING ERRCODE = '55000';
    END IF;
    IF OLD.lifecycle_state <> 'DRAFT' AND (
        NEW.agent_id IS DISTINCT FROM OLD.agent_id OR
        NEW.version IS DISTINCT FROM OLD.version OR
        NEW.business_purpose IS DISTINCT FROM OLD.business_purpose OR
        NEW.manifest_schema_version IS DISTINCT FROM OLD.manifest_schema_version OR
        NEW.manifest_json IS DISTINCT FROM OLD.manifest_json OR
        NEW.agent_artifact_fingerprint IS DISTINCT FROM OLD.agent_artifact_fingerprint
    ) THEN
        RAISE EXCEPTION 'analyzed release manifest and agent fingerprint are immutable' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER agent_release_immutable_inputs
BEFORE UPDATE OR DELETE ON agent_releases
FOR EACH ROW EXECUTE FUNCTION finsec_protect_release_row();

CREATE OR REPLACE FUNCTION finsec_guard_release_child()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_release_id uuid;
BEGIN
    target_release_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.release_id ELSE NEW.release_id END;
    PERFORM finsec_assert_release_draft(target_release_id);
    IF TG_OP = 'UPDATE' AND OLD.release_id IS DISTINCT FROM NEW.release_id THEN
        PERFORM finsec_assert_release_draft(OLD.release_id);
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE TRIGGER release_artifact_lifecycle_guard
BEFORE INSERT OR UPDATE OR DELETE ON release_artifacts
FOR EACH ROW EXECUTE FUNCTION finsec_guard_release_child();

CREATE TRIGGER release_tool_lifecycle_guard
BEFORE INSERT OR UPDATE OR DELETE ON release_tools
FOR EACH ROW EXECUTE FUNCTION finsec_guard_release_child();

CREATE TRIGGER release_rag_lifecycle_guard
BEFORE INSERT OR UPDATE OR DELETE ON release_rag_sources
FOR EACH ROW EXECUTE FUNCTION finsec_guard_release_child();

CREATE OR REPLACE FUNCTION finsec_guard_referenced_definition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    is_frozen boolean;
BEGIN
    IF TG_TABLE_NAME = 'tool_definitions' THEN
        SELECT EXISTS (
            SELECT 1 FROM release_tools rt JOIN agent_releases ar ON ar.id = rt.release_id
            WHERE rt.tool_definition_id = OLD.id AND ar.lifecycle_state <> 'DRAFT'
        ) INTO is_frozen;
    ELSE
        SELECT EXISTS (
            SELECT 1 FROM release_rag_sources rr JOIN agent_releases ar ON ar.id = rr.release_id
            WHERE rr.rag_source_id = OLD.id AND ar.lifecycle_state <> 'DRAFT'
        ) INTO is_frozen;
    END IF;
    IF is_frozen THEN
        RAISE EXCEPTION 'definition referenced by analyzed release is immutable' USING ERRCODE = '55000';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE TRIGGER tool_definition_reference_guard
BEFORE UPDATE OR DELETE ON tool_definitions
FOR EACH ROW EXECUTE FUNCTION finsec_guard_referenced_definition();

CREATE TRIGGER rag_source_reference_guard
BEFORE UPDATE OR DELETE ON rag_sources
FOR EACH ROW EXECUTE FUNCTION finsec_guard_referenced_definition();

CREATE OR REPLACE FUNCTION finsec_validate_contract_scope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    release_workspace uuid;
BEGIN
    SELECT a.workspace_id INTO release_workspace
      FROM agent_releases ar JOIN agents a ON a.id = ar.agent_id
     WHERE ar.id = NEW.release_id;
    IF release_workspace IS NULL OR release_workspace <> NEW.workspace_id THEN
        RAISE EXCEPTION 'contract workspace and release workspace must match' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER safety_contract_scope_guard
BEFORE INSERT OR UPDATE ON safety_contracts
FOR EACH ROW EXECUTE FUNCTION finsec_validate_contract_scope();

CREATE OR REPLACE FUNCTION finsec_validate_test_run_scope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    release_workspace uuid;
    suite_workspace uuid;
    contract_release uuid;
    contract_state varchar(30);
    stored_agent_fingerprint sha256_digest;
    stored_release_fingerprint sha256_digest;
BEGIN
    SELECT a.workspace_id, ar.agent_artifact_fingerprint, ar.release_fingerprint
      INTO release_workspace, stored_agent_fingerprint, stored_release_fingerprint
      FROM agent_releases ar JOIN agents a ON a.id = ar.agent_id
     WHERE ar.id = NEW.release_id;
    IF release_workspace IS NULL THEN
        RAISE EXCEPTION 'run release does not exist' USING ERRCODE = '23503';
    END IF;
    IF NEW.agent_artifact_fingerprint <> stored_agent_fingerprint
       OR NEW.release_fingerprint <> stored_release_fingerprint THEN
        RAISE EXCEPTION 'run fingerprints must match release snapshot' USING ERRCODE = '23514';
    END IF;
    IF NEW.suite_id IS NOT NULL THEN
        SELECT workspace_id INTO suite_workspace FROM test_suites WHERE id = NEW.suite_id;
        IF suite_workspace IS NULL OR suite_workspace <> release_workspace THEN
            RAISE EXCEPTION 'run suite and release workspace must match' USING ERRCODE = '23514';
        END IF;
    END IF;
    IF NEW.contract_version_id IS NOT NULL THEN
        SELECT sc.release_id, scv.state INTO contract_release, contract_state
          FROM safety_contract_versions scv JOIN safety_contracts sc ON sc.id = scv.contract_id
         WHERE scv.id = NEW.contract_version_id;
        IF contract_release IS NULL OR contract_release <> NEW.release_id OR contract_state <> 'APPROVED' THEN
            RAISE EXCEPTION 'run contract must be an approved version for the same release' USING ERRCODE = '23514';
        END IF;
    END IF;
    IF NEW.mode = 'BASELINE' AND NEW.contract_version_id IS NOT NULL THEN
        RAISE EXCEPTION 'baseline run cannot reference a contract' USING ERRCODE = '23514';
    END IF;
    IF NEW.mode <> 'BASELINE' AND NEW.contract_version_id IS NULL THEN
        RAISE EXCEPTION 'non-baseline run requires an approved contract' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER test_run_scope_guard
BEFORE INSERT OR UPDATE ON test_runs
FOR EACH ROW EXECUTE FUNCTION finsec_validate_test_run_scope();

CREATE OR REPLACE FUNCTION finsec_validate_execution_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    run_workspace uuid;
    owning_run uuid;
    latest_sequence bigint;
    latest_hash sha256_digest;
BEGIN
    SELECT a.workspace_id INTO run_workspace
      FROM test_runs tr JOIN agent_releases ar ON ar.id = tr.release_id
      JOIN agents a ON a.id = ar.agent_id WHERE tr.id = NEW.run_id;
    IF run_workspace IS NULL OR run_workspace <> NEW.workspace_id THEN
        RAISE EXCEPTION 'event workspace and run workspace must match' USING ERRCODE = '23514';
    END IF;
    IF NEW.test_case_run_id IS NOT NULL THEN
        SELECT test_run_id INTO owning_run FROM test_case_runs WHERE id = NEW.test_case_run_id;
        IF owning_run IS NULL OR owning_run <> NEW.run_id THEN
            RAISE EXCEPTION 'event case-run must belong to event run' USING ERRCODE = '23514';
        END IF;
    END IF;
    SELECT sequence, event_hash INTO latest_sequence, latest_hash
      FROM execution_events WHERE run_id = NEW.run_id ORDER BY sequence DESC LIMIT 1;
    IF latest_sequence IS NULL THEN
        IF NEW.sequence <> 1 OR NEW.prev_event_hash IS NOT NULL THEN
            RAISE EXCEPTION 'first run event must have sequence 1 and no previous hash' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.sequence <= latest_sequence OR NEW.prev_event_hash IS DISTINCT FROM latest_hash THEN
        RAISE EXCEPTION 'event sequence or previous hash does not extend current head' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER execution_event_scope_guard
BEFORE INSERT ON execution_events
FOR EACH ROW EXECUTE FUNCTION finsec_validate_execution_event();

CREATE OR REPLACE FUNCTION finsec_validate_oracle_scope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    oracle_run uuid;
    event_run uuid;
    event_case_run uuid;
BEGIN
    SELECT test_run_id INTO oracle_run FROM test_case_runs WHERE id = NEW.test_case_run_id;
    IF oracle_run IS NULL THEN
        RAISE EXCEPTION 'oracle case-run does not exist' USING ERRCODE = '23503';
    END IF;
    IF NEW.source_event_id IS NOT NULL THEN
        SELECT run_id, test_case_run_id INTO event_run, event_case_run
          FROM execution_events WHERE id = NEW.source_event_id;
        IF event_run IS NULL OR event_run <> oracle_run
           OR event_case_run IS DISTINCT FROM NEW.test_case_run_id THEN
            RAISE EXCEPTION 'oracle source event must belong to the same case-run' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER oracle_result_scope_guard
BEFORE INSERT ON oracle_results
FOR EACH ROW EXECUTE FUNCTION finsec_validate_oracle_scope();

CREATE OR REPLACE FUNCTION finsec_validate_finding_scope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    oracle_release uuid;
    first_release uuid;
    latest_release uuid;
BEGIN
    SELECT tr.release_id INTO oracle_release
      FROM oracle_results result JOIN test_case_runs tcr ON tcr.id = result.test_case_run_id
      JOIN test_runs tr ON tr.id = tcr.test_run_id WHERE result.id = NEW.source_oracle_result_id;
    SELECT release_id INTO first_release FROM test_runs WHERE id = NEW.first_seen_run_id;
    SELECT release_id INTO latest_release FROM test_runs WHERE id = NEW.latest_seen_run_id;
    IF oracle_release IS NULL OR oracle_release <> NEW.release_id
       OR first_release IS DISTINCT FROM NEW.release_id OR latest_release IS DISTINCT FROM NEW.release_id THEN
        RAISE EXCEPTION 'finding evidence and runs must belong to the same release' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER finding_scope_guard
BEFORE INSERT OR UPDATE ON findings
FOR EACH ROW EXECUTE FUNCTION finsec_validate_finding_scope();

CREATE OR REPLACE FUNCTION finsec_evidence_owner_workspace(owner_kind varchar, target_id uuid)
RETURNS uuid
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    result uuid;
BEGIN
    CASE owner_kind
        WHEN 'EXECUTION_EVENT' THEN
            SELECT workspace_id INTO result FROM execution_events WHERE id = target_id;
        WHEN 'ORACLE_RESULT' THEN
            SELECT a.workspace_id INTO result FROM oracle_results o
              JOIN test_case_runs c ON c.id = o.test_case_run_id JOIN test_runs r ON r.id = c.test_run_id
              JOIN agent_releases ar ON ar.id = r.release_id JOIN agents a ON a.id = ar.agent_id
             WHERE o.id = target_id;
        WHEN 'FINDING' THEN
            SELECT a.workspace_id INTO result FROM findings f
              JOIN agent_releases ar ON ar.id = f.release_id JOIN agents a ON a.id = ar.agent_id
             WHERE f.id = target_id;
        WHEN 'RELEASE_DECISION' THEN
            SELECT a.workspace_id INTO result FROM release_decisions d
              JOIN agent_releases ar ON ar.id = d.release_id JOIN agents a ON a.id = ar.agent_id
             WHERE d.id = target_id;
        WHEN 'RELEASE_ATTESTATION' THEN
            SELECT a.workspace_id INTO result FROM release_attestations att
              JOIN release_decisions d ON d.id = att.release_decision_id
              JOIN agent_releases ar ON ar.id = d.release_id JOIN agents a ON a.id = ar.agent_id
             WHERE att.id = target_id;
        WHEN 'TEST_RUN' THEN
            SELECT a.workspace_id INTO result FROM test_runs r
              JOIN agent_releases ar ON ar.id = r.release_id JOIN agents a ON a.id = ar.agent_id
             WHERE r.id = target_id;
        WHEN 'TEST_CASE_RUN' THEN
            SELECT a.workspace_id INTO result FROM test_case_runs c
              JOIN test_runs r ON r.id = c.test_run_id JOIN agent_releases ar ON ar.id = r.release_id
              JOIN agents a ON a.id = ar.agent_id WHERE c.id = target_id;
        WHEN 'CONTRACT_VERSION' THEN
            SELECT sc.workspace_id INTO result FROM safety_contract_versions v
              JOIN safety_contracts sc ON sc.id = v.contract_id WHERE v.id = target_id;
        ELSE
            RAISE EXCEPTION 'unsupported evidence owner type %', owner_kind USING ERRCODE = '23514';
    END CASE;
    IF result IS NULL THEN
        RAISE EXCEPTION 'evidence owner does not exist' USING ERRCODE = '23503';
    END IF;
    RETURN result;
END;
$$;

CREATE OR REPLACE FUNCTION finsec_validate_evidence_reference()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    owner_workspace uuid;
    event_workspace uuid;
BEGIN
    owner_workspace := finsec_evidence_owner_workspace(NEW.owner_type, NEW.owner_id);
    IF owner_workspace <> NEW.workspace_id THEN
        RAISE EXCEPTION 'evidence owner and workspace must match' USING ERRCODE = '23514';
    END IF;
    IF NEW.source_event_id IS NOT NULL THEN
        SELECT workspace_id INTO event_workspace FROM execution_events WHERE id = NEW.source_event_id;
        IF event_workspace IS NULL OR event_workspace <> NEW.workspace_id THEN
            RAISE EXCEPTION 'evidence source event and workspace must match' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER evidence_reference_scope_guard
BEFORE INSERT ON evidence_references
FOR EACH ROW EXECUTE FUNCTION finsec_validate_evidence_reference();

CREATE OR REPLACE FUNCTION finsec_guard_approved_contract_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.state = 'APPROVED' THEN
        RAISE EXCEPTION 'approved contract version is immutable' USING ERRCODE = '55000';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE TRIGGER approved_contract_version_guard
BEFORE UPDATE OR DELETE ON safety_contract_versions
FOR EACH ROW EXECUTE FUNCTION finsec_guard_approved_contract_version();

CREATE TRIGGER execution_events_append_only BEFORE UPDATE OR DELETE ON execution_events
FOR EACH ROW EXECUTE FUNCTION finsec_forbid_mutation();
CREATE TRIGGER oracle_results_append_only BEFORE UPDATE OR DELETE ON oracle_results
FOR EACH ROW EXECUTE FUNCTION finsec_forbid_mutation();
CREATE TRIGGER audit_records_append_only BEFORE UPDATE OR DELETE ON audit_records
FOR EACH ROW EXECUTE FUNCTION finsec_forbid_mutation();
CREATE TRIGGER evidence_references_append_only BEFORE UPDATE OR DELETE ON evidence_references
FOR EACH ROW EXECUTE FUNCTION finsec_forbid_mutation();
CREATE TRIGGER release_decisions_append_only BEFORE UPDATE OR DELETE ON release_decisions
FOR EACH ROW EXECUTE FUNCTION finsec_forbid_mutation();
CREATE TRIGGER decision_invalidations_append_only BEFORE UPDATE OR DELETE ON decision_invalidations
FOR EACH ROW EXECUTE FUNCTION finsec_forbid_mutation();
CREATE TRIGGER release_attestations_append_only BEFORE UPDATE OR DELETE ON release_attestations
FOR EACH ROW EXECUTE FUNCTION finsec_forbid_mutation();
