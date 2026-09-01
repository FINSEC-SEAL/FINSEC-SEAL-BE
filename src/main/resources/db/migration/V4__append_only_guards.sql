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
    IF OLD.lifecycle_state <> 'DRAFT'
       AND (NEW.release_fingerprint IS DISTINCT FROM OLD.release_fingerprint
            OR NEW.safety_contract_hash IS DISTINCT FROM OLD.safety_contract_hash)
       AND NOT (
           (OLD.lifecycle_state = 'REMEDIATION' AND NEW.lifecycle_state = 'VERIFYING'
                AND NEW.effective_status = 'VERIFYING') OR
           (OLD.lifecycle_state IN ('PASS', 'REVIEW', 'BLOCKED')
                AND NEW.lifecycle_state = 'NEEDS_REVALIDATION'
                AND NEW.effective_status = 'NEEDS_REVALIDATION')
       ) THEN
        RAISE EXCEPTION 'release fingerprint change requires VERIFYING or NEEDS_REVALIDATION transition'
            USING ERRCODE = '55000';
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

CREATE OR REPLACE FUNCTION finsec_validate_release_rag_scope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    release_workspace uuid;
    source_workspace uuid;
BEGIN
    SELECT a.workspace_id INTO release_workspace
      FROM agent_releases ar JOIN agents a ON a.id = ar.agent_id
     WHERE ar.id = NEW.release_id;
    SELECT workspace_id INTO source_workspace FROM rag_sources WHERE id = NEW.rag_source_id;
    IF release_workspace IS NULL OR source_workspace IS NULL OR release_workspace <> source_workspace THEN
        RAISE EXCEPTION 'release and RAG source workspace must match' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER release_rag_scope_guard
BEFORE INSERT OR UPDATE ON release_rag_sources
FOR EACH ROW EXECUTE FUNCTION finsec_validate_release_rag_scope();

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
    suite_status varchar(30);
BEGIN
    SELECT a.workspace_id, ar.agent_artifact_fingerprint, ar.release_fingerprint
      INTO release_workspace, stored_agent_fingerprint, stored_release_fingerprint
      FROM agent_releases ar JOIN agents a ON a.id = ar.agent_id
     WHERE ar.id = NEW.release_id;
    IF release_workspace IS NULL THEN
        RAISE EXCEPTION 'run release does not exist' USING ERRCODE = '23503';
    END IF;
    IF TG_OP = 'INSERT' AND NEW.status IN ('COMPLETED', 'FAILED', 'CANCELLED') THEN
        RAISE EXCEPTION 'terminal test run must be reached through a sealed state transition'
            USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' AND (
        NEW.agent_artifact_fingerprint <> stored_agent_fingerprint
        OR NEW.release_fingerprint <> stored_release_fingerprint
    ) THEN
        RAISE EXCEPTION 'run fingerprints must match release snapshot' USING ERRCODE = '23514';
    END IF;
    IF NEW.suite_id IS NOT NULL THEN
        SELECT workspace_id, status INTO suite_workspace, suite_status
          FROM test_suites WHERE id = NEW.suite_id FOR UPDATE;
        IF suite_workspace IS NULL OR suite_workspace <> release_workspace THEN
            RAISE EXCEPTION 'run suite and release workspace must match' USING ERRCODE = '23514';
        END IF;
        IF suite_status <> 'READY' THEN
            RAISE EXCEPTION 'test run requires an immutable READY suite' USING ERRCODE = '23514';
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

CREATE OR REPLACE FUNCTION finsec_protect_test_run_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    child_count integer;
    terminal_child_count integer;
    error_child_count integer;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'test run cannot be deleted' USING ERRCODE = '55000';
    END IF;
    IF NEW.release_id IS DISTINCT FROM OLD.release_id
       OR NEW.suite_id IS DISTINCT FROM OLD.suite_id
       OR NEW.contract_version_id IS DISTINCT FROM OLD.contract_version_id
       OR NEW.mode IS DISTINCT FROM OLD.mode
       OR NEW.baseline_pair_group_id IS DISTINCT FROM OLD.baseline_pair_group_id
       OR NEW.agent_artifact_fingerprint IS DISTINCT FROM OLD.agent_artifact_fingerprint
       OR NEW.release_fingerprint IS DISTINCT FROM OLD.release_fingerprint
       OR NEW.config_json IS DISTINCT FROM OLD.config_json
       OR NEW.fixture_version IS DISTINCT FROM OLD.fixture_version
       OR NEW.fixture_digest IS DISTINCT FROM OLD.fixture_digest
       OR NEW.model_config_hash IS DISTINCT FROM OLD.model_config_hash
       OR NEW.random_seed IS DISTINCT FROM OLD.random_seed
       OR NEW.total_cases IS DISTINCT FROM OLD.total_cases THEN
        RAISE EXCEPTION 'test run identity snapshot is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.status IN ('COMPLETED', 'FAILED', 'CANCELLED') THEN
        RAISE EXCEPTION 'terminal test run result is immutable' USING ERRCODE = '55000';
    END IF;
    IF NEW.status IN ('COMPLETED', 'FAILED', 'CANCELLED') AND NEW.completed_at IS NULL THEN
        RAISE EXCEPTION 'terminal test run requires completed_at' USING ERRCODE = '23514';
    END IF;
    IF NEW.status IN ('COMPLETED', 'FAILED', 'CANCELLED') THEN
        SELECT count(*), count(*) FILTER (
            WHERE status IN ('PASSED', 'FAILED_SECURITY', 'FAILED_FUNCTIONAL', 'ERROR', 'CANCELLED')
        ), count(*) FILTER (WHERE status = 'ERROR')
          INTO child_count, terminal_child_count, error_child_count
          FROM test_case_runs WHERE test_run_id = OLD.id;
        IF child_count <> terminal_child_count OR NEW.completed_cases <> terminal_child_count THEN
            RAISE EXCEPTION 'terminal test run requires every materialized child sealed and counters reconciled'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.status = 'COMPLETED' AND child_count <> NEW.total_cases THEN
            RAISE EXCEPTION 'completed test run requires all planned cases materialized and completed'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.operational_error_count <> error_child_count THEN
            RAISE EXCEPTION 'terminal test run operational error count must match ERROR children'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER test_run_identity_guard
BEFORE UPDATE OR DELETE ON test_runs
FOR EACH ROW EXECUTE FUNCTION finsec_protect_test_run_identity();

CREATE OR REPLACE FUNCTION finsec_validate_test_case_run_scope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    run_suite uuid;
    run_status varchar(30);
    case_suite uuid;
BEGIN
    SELECT suite_id, status INTO run_suite, run_status
      FROM test_runs WHERE id = NEW.test_run_id FOR UPDATE;
    IF run_status IN ('COMPLETED', 'FAILED', 'CANCELLED') THEN
        RAISE EXCEPTION 'case-run graph is immutable after parent run termination' USING ERRCODE = '55000';
    END IF;
    IF NEW.status IN ('PASSED', 'FAILED_SECURITY', 'FAILED_FUNCTIONAL', 'ERROR', 'CANCELLED')
       AND NEW.completed_at IS NULL THEN
        RAISE EXCEPTION 'terminal test case run requires completed_at' USING ERRCODE = '23514';
    END IF;
    SELECT suite_id INTO case_suite FROM test_cases WHERE id = NEW.test_case_id;
    IF run_suite IS NULL OR case_suite IS NULL OR run_suite <> case_suite THEN
        RAISE EXCEPTION 'case-run test case must belong to the run suite' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER test_case_run_scope_guard
BEFORE INSERT OR UPDATE ON test_case_runs
FOR EACH ROW EXECUTE FUNCTION finsec_validate_test_case_run_scope();

CREATE OR REPLACE FUNCTION finsec_protect_test_case_run_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'test case run cannot be deleted' USING ERRCODE = '55000';
    END IF;
    IF NEW.test_run_id IS DISTINCT FROM OLD.test_run_id
       OR NEW.test_case_id IS DISTINCT FROM OLD.test_case_id
       OR NEW.trial_index IS DISTINCT FROM OLD.trial_index
       OR NEW.variant_hash IS DISTINCT FROM OLD.variant_hash THEN
        RAISE EXCEPTION 'test case run identity snapshot is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.status IN ('PASSED', 'FAILED_SECURITY', 'FAILED_FUNCTIONAL', 'ERROR', 'CANCELLED') THEN
        RAISE EXCEPTION 'terminal test case run result is immutable' USING ERRCODE = '55000';
    END IF;
    IF NEW.status IN ('PASSED', 'FAILED_SECURITY', 'FAILED_FUNCTIONAL', 'ERROR', 'CANCELLED')
       AND NEW.completed_at IS NULL THEN
        RAISE EXCEPTION 'terminal test case run requires completed_at' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER test_case_run_identity_guard
BEFORE UPDATE OR DELETE ON test_case_runs
FOR EACH ROW EXECUTE FUNCTION finsec_protect_test_case_run_identity();

CREATE OR REPLACE FUNCTION finsec_guard_used_test_definition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    is_used boolean;
BEGIN
    SELECT EXISTS (SELECT 1 FROM test_runs WHERE suite_id = OLD.id) INTO is_used;
    IF is_used THEN
        RAISE EXCEPTION 'test definition referenced by a run is immutable' USING ERRCODE = '55000';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE TRIGGER used_test_suite_guard
BEFORE UPDATE OR DELETE ON test_suites
FOR EACH ROW EXECUTE FUNCTION finsec_guard_used_test_definition();

CREATE OR REPLACE FUNCTION finsec_guard_frozen_test_case()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    old_suite uuid;
    new_suite uuid;
    suite_status varchar(30);
    suite_used boolean;
BEGIN
    old_suite := CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE OLD.suite_id END;
    new_suite := CASE WHEN TG_OP = 'DELETE' THEN NULL ELSE NEW.suite_id END;
    FOR suite_status, suite_used IN
        SELECT suite.status, EXISTS (SELECT 1 FROM test_runs run WHERE run.suite_id = suite.id)
          FROM test_suites suite
         WHERE suite.id = old_suite OR suite.id = new_suite
         ORDER BY suite.id
         FOR UPDATE OF suite
    LOOP
        IF suite_status = 'READY' OR suite_used THEN
            RAISE EXCEPTION 'test cases in a READY or used suite are immutable' USING ERRCODE = '55000';
        END IF;
    END LOOP;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE TRIGGER used_test_case_guard
BEFORE INSERT OR UPDATE OR DELETE ON test_cases
FOR EACH ROW EXECUTE FUNCTION finsec_guard_frozen_test_case();

CREATE OR REPLACE FUNCTION finsec_validate_replay_link_scope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    finding_release uuid;
    finding_source_case_run uuid;
    baseline_release uuid;
    replay_release uuid;
    baseline_case uuid;
    replay_case uuid;
    baseline_variant sha256_digest;
    replay_variant sha256_digest;
    baseline_agent_fingerprint sha256_digest;
    replay_agent_fingerprint sha256_digest;
    baseline_release_fingerprint sha256_digest;
    replay_release_fingerprint sha256_digest;
    baseline_fixture_digest sha256_digest;
    replay_fixture_digest sha256_digest;
    baseline_model_hash sha256_digest;
    replay_model_hash sha256_digest;
    baseline_mode varchar(30);
    replay_mode varchar(30);
    baseline_contract uuid;
    replay_contract uuid;
    baseline_run_status varchar(30);
    replay_run_status varchar(30);
    baseline_case_status varchar(30);
    replay_case_status varchar(30);
    baseline_trial_index integer;
    replay_trial_index integer;
    baseline_random_seed bigint;
    replay_random_seed bigint;
    baseline_pair_group uuid;
    replay_pair_group uuid;
    baseline_run_completed_at timestamptz;
    replay_run_completed_at timestamptz;
    baseline_case_completed_at timestamptz;
    replay_case_completed_at timestamptz;
    actual_same_agent boolean;
    actual_same_fixture boolean;
    actual_same_model boolean;
    actual_same_variant boolean;
    actual_policy_difference boolean;
BEGIN
    SELECT finding.release_id, oracle.test_case_run_id
      INTO finding_release, finding_source_case_run
      FROM findings finding
      JOIN oracle_results oracle ON oracle.id = finding.source_oracle_result_id
     WHERE finding.id = NEW.finding_id;
    SELECT tr.release_id, tcr.test_case_id, tcr.variant_hash,
           tr.agent_artifact_fingerprint, tr.release_fingerprint, tr.fixture_digest,
           tr.model_config_hash, tr.mode, tr.contract_version_id,
           tr.status, tcr.status, tcr.trial_index, tr.random_seed, tr.baseline_pair_group_id,
           tr.completed_at, tcr.completed_at
      INTO baseline_release, baseline_case, baseline_variant,
           baseline_agent_fingerprint, baseline_release_fingerprint, baseline_fixture_digest,
           baseline_model_hash, baseline_mode, baseline_contract,
           baseline_run_status, baseline_case_status, baseline_trial_index, baseline_random_seed,
           baseline_pair_group, baseline_run_completed_at, baseline_case_completed_at
      FROM test_case_runs tcr JOIN test_runs tr ON tr.id = tcr.test_run_id
     WHERE tcr.id = NEW.baseline_case_run_id;
    SELECT tr.release_id, tcr.test_case_id, tcr.variant_hash,
           tr.agent_artifact_fingerprint, tr.release_fingerprint, tr.fixture_digest,
           tr.model_config_hash, tr.mode, tr.contract_version_id,
           tr.status, tcr.status, tcr.trial_index, tr.random_seed, tr.baseline_pair_group_id,
           tr.completed_at, tcr.completed_at
      INTO replay_release, replay_case, replay_variant,
           replay_agent_fingerprint, replay_release_fingerprint, replay_fixture_digest,
           replay_model_hash, replay_mode, replay_contract,
           replay_run_status, replay_case_status, replay_trial_index, replay_random_seed,
           replay_pair_group, replay_run_completed_at, replay_case_completed_at
      FROM test_case_runs tcr JOIN test_runs tr ON tr.id = tcr.test_run_id
     WHERE tcr.id = NEW.replay_case_run_id;
    IF finding_release IS NULL OR baseline_release IS NULL OR replay_release IS NULL
       OR finding_release <> baseline_release OR finding_release <> replay_release THEN
        RAISE EXCEPTION 'replay finding and both case-runs must belong to the same release'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.baseline_case_run_id = NEW.replay_case_run_id
       OR finding_source_case_run IS DISTINCT FROM NEW.baseline_case_run_id THEN
        RAISE EXCEPTION 'replay baseline must be the finding source case-run' USING ERRCODE = '23514';
    END IF;

    actual_same_agent := baseline_agent_fingerprint = replay_agent_fingerprint;
    actual_same_fixture := baseline_fixture_digest = replay_fixture_digest;
    actual_same_model := baseline_model_hash = replay_model_hash;
    actual_same_variant := baseline_case = replay_case AND baseline_variant = replay_variant;
    actual_policy_difference := baseline_mode = 'BASELINE'
        AND baseline_contract IS NULL
        AND replay_mode = 'SEAL_REPLAY'
        AND replay_contract IS NOT NULL
        AND baseline_release_fingerprint <> replay_release_fingerprint;

    IF NEW.same_agent_artifact_fingerprint IS DISTINCT FROM actual_same_agent
       OR NEW.same_fixture_digest IS DISTINCT FROM actual_same_fixture
       OR NEW.same_model_config IS DISTINCT FROM actual_same_model
       OR NEW.same_variant_hash IS DISTINCT FROM actual_same_variant
       OR NEW.expected_policy_difference IS DISTINCT FROM actual_policy_difference THEN
        RAISE EXCEPTION 'replay comparison flags must match immutable run snapshots'
            USING ERRCODE = '23514';
    END IF;
    IF NOT actual_same_agent OR NOT actual_same_fixture OR NOT actual_same_model
       OR NOT actual_same_variant OR NOT actual_policy_difference THEN
        RAISE EXCEPTION 'replay must be a controlled baseline to SEAL replay comparison'
            USING ERRCODE = '23514';
    END IF;
    IF baseline_run_status <> 'COMPLETED' OR replay_run_status <> 'COMPLETED'
       OR baseline_run_completed_at IS NULL OR replay_run_completed_at IS NULL
       OR baseline_case_status NOT IN ('PASSED', 'FAILED_SECURITY', 'FAILED_FUNCTIONAL')
       OR replay_case_status NOT IN ('PASSED', 'FAILED_SECURITY', 'FAILED_FUNCTIONAL')
       OR baseline_case_completed_at IS NULL OR replay_case_completed_at IS NULL THEN
        RAISE EXCEPTION 'replay comparison requires completed runs and terminal case results'
            USING ERRCODE = '23514';
    END IF;
    IF baseline_trial_index <> replay_trial_index
       OR baseline_random_seed IS DISTINCT FROM replay_random_seed
       OR baseline_pair_group IS NULL
       OR baseline_pair_group IS DISTINCT FROM replay_pair_group THEN
        RAISE EXCEPTION 'replay comparison requires the same trial, random seed, and pair group'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER replay_link_scope_guard
BEFORE INSERT ON replay_links
FOR EACH ROW EXECUTE FUNCTION finsec_validate_replay_link_scope();

CREATE OR REPLACE FUNCTION finsec_validate_execution_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    run_workspace uuid;
    run_status varchar(30);
    owning_run uuid;
    latest_sequence bigint;
    latest_hash sha256_digest;
    counter_sequence bigint;
BEGIN
    SELECT a.workspace_id, tr.status INTO run_workspace, run_status
      FROM test_runs tr JOIN agent_releases ar ON ar.id = tr.release_id
      JOIN agents a ON a.id = ar.agent_id WHERE tr.id = NEW.run_id
      FOR UPDATE OF tr;
    IF run_workspace IS NULL OR run_workspace <> NEW.workspace_id THEN
        RAISE EXCEPTION 'event workspace and run workspace must match' USING ERRCODE = '23514';
    END IF;
    IF run_status IN ('COMPLETED', 'FAILED', 'CANCELLED') THEN
        RAISE EXCEPTION 'execution events cannot be appended after run termination' USING ERRCODE = '55000';
    END IF;
    IF NEW.test_case_run_id IS NOT NULL THEN
        SELECT test_run_id INTO owning_run FROM test_case_runs WHERE id = NEW.test_case_run_id;
        IF owning_run IS NULL OR owning_run <> NEW.run_id THEN
            RAISE EXCEPTION 'event case-run must belong to event run' USING ERRCODE = '23514';
        END IF;
    END IF;
    INSERT INTO run_event_counters (run_id, last_sequence)
    VALUES (NEW.run_id, 0)
    ON CONFLICT (run_id) DO NOTHING;
    SELECT last_sequence INTO counter_sequence
      FROM run_event_counters WHERE run_id = NEW.run_id FOR UPDATE;
    SELECT sequence, event_hash INTO latest_sequence, latest_hash
      FROM execution_events WHERE run_id = NEW.run_id ORDER BY sequence DESC LIMIT 1;
    IF counter_sequence IS DISTINCT FROM COALESCE(latest_sequence, 0) THEN
        RAISE EXCEPTION 'run event counter does not match persisted event head' USING ERRCODE = '23514';
    ELSIF latest_sequence IS NULL THEN
        IF NEW.sequence <> 1 OR NEW.prev_event_hash IS NOT NULL THEN
            RAISE EXCEPTION 'first run event must have sequence 1 and no previous hash' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.sequence <> latest_sequence + 1 OR NEW.prev_event_hash IS DISTINCT FROM latest_hash THEN
        RAISE EXCEPTION 'event sequence or previous hash does not extend current head' USING ERRCODE = '23514';
    END IF;
    UPDATE run_event_counters SET last_sequence = NEW.sequence WHERE run_id = NEW.run_id;
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
    oracle_run_status varchar(30);
    event_run uuid;
    event_case_run uuid;
BEGIN
    SELECT run.id, run.status INTO oracle_run, oracle_run_status
      FROM test_case_runs case_run
      JOIN test_runs run ON run.id = case_run.test_run_id
     WHERE case_run.id = NEW.test_case_run_id
     FOR UPDATE OF run;
    IF oracle_run IS NULL THEN
        RAISE EXCEPTION 'oracle case-run does not exist' USING ERRCODE = '23503';
    END IF;
    IF oracle_run_status IN ('COMPLETED', 'FAILED', 'CANCELLED') THEN
        RAISE EXCEPTION 'oracle evidence cannot be appended after run termination'
            USING ERRCODE = '55000';
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
    oracle_run uuid;
    oracle_run_status varchar(30);
    first_release uuid;
    latest_release uuid;
BEGIN
    SELECT tr.release_id, tr.id, tr.status INTO oracle_release, oracle_run, oracle_run_status
      FROM oracle_results result JOIN test_case_runs tcr ON tcr.id = result.test_case_run_id
      JOIN test_runs tr ON tr.id = tcr.test_run_id WHERE result.id = NEW.source_oracle_result_id
      FOR UPDATE OF tr;
    IF TG_OP = 'INSERT' AND oracle_run_status IN ('COMPLETED', 'FAILED', 'CANCELLED') THEN
        RAISE EXCEPTION 'finding evidence cannot be created after source run termination'
            USING ERRCODE = '55000';
    END IF;
    SELECT release_id INTO first_release FROM test_runs WHERE id = NEW.first_seen_run_id;
    SELECT release_id INTO latest_release FROM test_runs WHERE id = NEW.latest_seen_run_id;
    IF oracle_release IS NULL OR oracle_release <> NEW.release_id
       OR first_release IS DISTINCT FROM NEW.release_id OR latest_release IS DISTINCT FROM NEW.release_id THEN
        RAISE EXCEPTION 'finding evidence and runs must belong to the same release' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' AND oracle_run IS DISTINCT FROM NEW.first_seen_run_id THEN
        RAISE EXCEPTION 'new finding first-seen run must own its source oracle evidence'
            USING ERRCODE = '23514';
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
    owner_run uuid;
    owner_release uuid;
    event_workspace uuid;
    event_run uuid;
    event_release uuid;
BEGIN
    owner_workspace := finsec_evidence_owner_workspace(NEW.owner_type, NEW.owner_id);
    IF owner_workspace <> NEW.workspace_id THEN
        RAISE EXCEPTION 'evidence owner and workspace must match' USING ERRCODE = '23514';
    END IF;
    IF NEW.source_event_id IS NOT NULL THEN
        SELECT event.workspace_id, event.run_id, run.release_id
          INTO event_workspace, event_run, event_release
          FROM execution_events event JOIN test_runs run ON run.id = event.run_id
         WHERE event.id = NEW.source_event_id;
        IF event_workspace IS NULL OR event_workspace <> NEW.workspace_id THEN
            RAISE EXCEPTION 'evidence source event and workspace must match' USING ERRCODE = '23514';
        END IF;
        CASE NEW.owner_type
            WHEN 'EXECUTION_EVENT' THEN
                SELECT run_id, tr.release_id INTO owner_run, owner_release
                  FROM execution_events event JOIN test_runs tr ON tr.id = event.run_id
                 WHERE event.id = NEW.owner_id;
            WHEN 'ORACLE_RESULT' THEN
                SELECT tcr.test_run_id, tr.release_id INTO owner_run, owner_release
                  FROM oracle_results result JOIN test_case_runs tcr ON tcr.id = result.test_case_run_id
                  JOIN test_runs tr ON tr.id = tcr.test_run_id WHERE result.id = NEW.owner_id;
            WHEN 'TEST_RUN' THEN
                SELECT id, release_id INTO owner_run, owner_release FROM test_runs WHERE id = NEW.owner_id;
            WHEN 'TEST_CASE_RUN' THEN
                SELECT tr.id, tr.release_id INTO owner_run, owner_release
                  FROM test_case_runs tcr JOIN test_runs tr ON tr.id = tcr.test_run_id
                 WHERE tcr.id = NEW.owner_id;
            WHEN 'FINDING' THEN
                SELECT release_id INTO owner_release FROM findings WHERE id = NEW.owner_id;
            WHEN 'RELEASE_DECISION' THEN
                SELECT release_id INTO owner_release FROM release_decisions WHERE id = NEW.owner_id;
            WHEN 'RELEASE_ATTESTATION' THEN
                SELECT decision.release_id INTO owner_release
                  FROM release_attestations attestation
                  JOIN release_decisions decision ON decision.id = attestation.release_decision_id
                 WHERE attestation.id = NEW.owner_id;
            WHEN 'CONTRACT_VERSION' THEN
                SELECT contract.release_id INTO owner_release
                  FROM safety_contract_versions version
                  JOIN safety_contracts contract ON contract.id = version.contract_id
                 WHERE version.id = NEW.owner_id;
        END CASE;
        IF owner_run IS NOT NULL AND owner_run <> event_run THEN
            RAISE EXCEPTION 'run-scoped evidence owner and source event run must match' USING ERRCODE = '23514';
        ELSIF owner_run IS NULL AND owner_release <> event_release THEN
            RAISE EXCEPTION 'release-scoped evidence owner and source event release must match' USING ERRCODE = '23514';
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

CREATE OR REPLACE FUNCTION finsec_validate_release_fingerprint_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    approved_contract_exists boolean;
    invalidation_exists boolean;
    latest_decision_id uuid;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM safety_contract_versions version
        JOIN safety_contracts contract ON contract.id = version.contract_id
        WHERE contract.release_id = NEW.id
          AND version.state = 'APPROVED'
          AND version.policy_hash = NEW.safety_contract_hash
    ) INTO approved_contract_exists;
    IF NOT approved_contract_exists THEN
        RAISE EXCEPTION 'release fingerprint transition requires matching approved contract'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.lifecycle_state IN ('PASS', 'REVIEW', 'BLOCKED') THEN
        SELECT decision.id INTO latest_decision_id
          FROM release_decisions decision
         WHERE decision.release_id = NEW.id
         ORDER BY decision.confirmed_at DESC, decision.created_at DESC, decision.id DESC
         LIMIT 1;
        SELECT EXISTS (
            SELECT 1 FROM decision_invalidations invalidation
            WHERE invalidation.release_decision_id = latest_decision_id
        ) INTO invalidation_exists;
        IF latest_decision_id IS NULL OR NOT invalidation_exists THEN
            RAISE EXCEPTION 'terminal fingerprint transition requires latest decision invalidation evidence'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER release_fingerprint_transition_guard
AFTER UPDATE ON agent_releases
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN (OLD.lifecycle_state <> 'DRAFT'
      AND (NEW.release_fingerprint IS DISTINCT FROM OLD.release_fingerprint
      OR NEW.safety_contract_hash IS DISTINCT FROM OLD.safety_contract_hash)
)
EXECUTE FUNCTION finsec_validate_release_fingerprint_transition();

CREATE OR REPLACE FUNCTION finsec_lock_release_decision_parent()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM 1 FROM agent_releases WHERE id = NEW.release_id FOR UPDATE;
    RETURN NEW;
END;
$$;

CREATE TRIGGER release_decision_parent_lock
BEFORE INSERT ON release_decisions
FOR EACH ROW EXECUTE FUNCTION finsec_lock_release_decision_parent();

CREATE OR REPLACE FUNCTION finsec_validate_patch_approval_scope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    finding_release uuid;
    base_release uuid;
    base_policy_hash sha256_digest;
    result_release uuid;
    result_state varchar(30);
    result_policy_hash sha256_digest;
BEGIN
    PERFORM 1 FROM patch_proposals WHERE id = NEW.patch_proposal_id FOR UPDATE;
    SELECT finding.release_id INTO finding_release
      FROM patch_proposals proposal JOIN findings finding ON finding.id = proposal.finding_id
     WHERE proposal.id = NEW.patch_proposal_id;
    SELECT contract.release_id, version.policy_hash INTO base_release, base_policy_hash
      FROM patch_proposals proposal
      JOIN safety_contract_versions version ON version.id = proposal.base_contract_version_id
      JOIN safety_contracts contract ON contract.id = version.contract_id
     WHERE proposal.id = NEW.patch_proposal_id;
    IF base_release IS NOT NULL AND (base_release <> finding_release OR NEW.base_hash <> base_policy_hash) THEN
        RAISE EXCEPTION 'approval base contract must match proposal release and hash' USING ERRCODE = '23514';
    END IF;
    IF NEW.decision = 'APPROVED' THEN
        SELECT contract.release_id, version.state, version.policy_hash
          INTO result_release, result_state, result_policy_hash
          FROM safety_contract_versions version JOIN safety_contracts contract ON contract.id = version.contract_id
         WHERE version.id = NEW.resulting_contract_version_id;
        IF result_release IS NULL OR result_release <> finding_release OR result_state <> 'APPROVED'
           OR NEW.result_hash IS DISTINCT FROM result_policy_hash THEN
            RAISE EXCEPTION 'approved review requires matching approved result contract and hash'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.resulting_contract_version_id IS NOT NULL OR NEW.result_hash IS NOT NULL THEN
        RAISE EXCEPTION 'rejected review cannot reference a resulting contract' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER patch_approval_scope_guard
BEFORE INSERT ON patch_approvals
FOR EACH ROW EXECUTE FUNCTION finsec_validate_patch_approval_scope();

CREATE OR REPLACE FUNCTION finsec_guard_reviewed_patch_proposal()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM patch_approvals WHERE patch_proposal_id = OLD.id) THEN
        RAISE EXCEPTION 'reviewed patch proposal is immutable' USING ERRCODE = '55000';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE TRIGGER reviewed_patch_proposal_guard
BEFORE UPDATE OR DELETE ON patch_proposals
FOR EACH ROW EXECUTE FUNCTION finsec_guard_reviewed_patch_proposal();

CREATE OR REPLACE FUNCTION finsec_validate_sandbox_snapshot()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    run_fixture_version varchar(50);
    run_fixture_digest sha256_digest;
BEGIN
    SELECT fixture_version, fixture_digest INTO run_fixture_version, run_fixture_digest
      FROM test_runs WHERE id = NEW.id;
    IF run_fixture_version IS NULL OR NEW.fixture_version <> run_fixture_version
       OR NEW.fixture_digest <> run_fixture_digest THEN
        RAISE EXCEPTION 'sandbox namespace must match owning run fixture snapshot' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER sandbox_namespace_snapshot_guard
BEFORE INSERT OR UPDATE ON sandbox_namespaces
FOR EACH ROW EXECUTE FUNCTION finsec_validate_sandbox_snapshot();

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
CREATE TRIGGER patch_approvals_append_only BEFORE UPDATE OR DELETE ON patch_approvals
FOR EACH ROW EXECUTE FUNCTION finsec_forbid_mutation();
CREATE TRIGGER replay_links_append_only BEFORE UPDATE OR DELETE ON replay_links
FOR EACH ROW EXECUTE FUNCTION finsec_forbid_mutation();
