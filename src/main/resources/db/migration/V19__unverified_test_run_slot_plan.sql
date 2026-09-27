-- Store a provisional required-trial roster without issuing a certification.
-- Existing Runs have no plan row and remain LEGACY_UNCERTIFIED. A later,
-- separately reviewed migration must prove trusted Case policy and criticality
-- before it can introduce any CERTIFIED transition.

CREATE FUNCTION finsec_configured_trials_v1(policy jsonb)
RETURNS integer
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    key_count integer;
    configured text;
BEGIN
    IF policy IS NULL OR jsonb_typeof(policy) IS DISTINCT FROM 'object' THEN
        RETURN NULL;
    END IF;
    SELECT count(*) INTO key_count FROM jsonb_object_keys(policy);
    IF key_count <> 2
       OR policy->>'schemaVersion' IS DISTINCT FROM 'required-trials/1'
       OR jsonb_typeof(policy->'configuredTrials') IS DISTINCT FROM 'number' THEN
        RETURN NULL;
    END IF;
    configured := policy->>'configuredTrials';
    IF configured IS NULL OR configured !~ '^[1-5]$' THEN
        RETURN NULL;
    END IF;
    RETURN configured::integer;
END;
$$;

CREATE TABLE test_run_slot_plans (
    run_id uuid PRIMARY KEY REFERENCES test_runs(id) ON DELETE RESTRICT,
    schema_version varchar(40) NOT NULL DEFAULT 'required-slots/1'
        CHECK (schema_version = 'required-slots/1'),
    state varchar(20) NOT NULL DEFAULT 'UNVERIFIED'
        CHECK (state = 'UNVERIFIED'),
    suite_id uuid NOT NULL REFERENCES test_suites(id) ON DELETE RESTRICT,
    suite_version varchar(50) NOT NULL,
    suite_hash sha256_digest NOT NULL,
    expected_slot_count integer NOT NULL CHECK (expected_slot_count BETWEEN 1 AND 10000),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE test_run_slot_entries (
    run_id uuid NOT NULL REFERENCES test_run_slot_plans(run_id) ON DELETE RESTRICT,
    test_case_id uuid NOT NULL REFERENCES test_cases(id) ON DELETE RESTRICT,
    trial_index integer NOT NULL CHECK (trial_index BETWEEN 0 AND 4),
    ordinal integer NOT NULL CHECK (ordinal BETWEEN 0 AND 9999),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id, test_case_id, trial_index),
    CONSTRAINT uq_test_run_slot_ordinal UNIQUE (run_id, ordinal)
);

CREATE FUNCTION finsec_guard_unverified_run_slot_plan()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    run_status varchar(30);
    run_suite_id uuid;
    run_total integer;
    run_workspace uuid;
    suite_version varchar(50);
    suite_hash sha256_digest;
    suite_status varchar(30);
BEGIN
    -- CaseRun insertion and slot insertion also lock the same parent Run.
    -- A late provisional header cannot be attached after execution began.
    SELECT run.status, run.suite_id, run.total_cases, agent.workspace_id,
           suite.version, suite.suite_hash, suite.status
      INTO run_status, run_suite_id, run_total, run_workspace,
           suite_version, suite_hash, suite_status
      FROM test_runs run
      JOIN agent_releases release ON release.id = run.release_id
      JOIN agents agent ON agent.id = release.agent_id
      JOIN test_suites suite ON suite.id = run.suite_id
     WHERE run.id = NEW.run_id
     FOR UPDATE OF run, suite;
    IF NOT FOUND OR run_status <> 'QUEUED' OR suite_status <> 'READY'
       OR NEW.suite_id IS DISTINCT FROM run_suite_id
       OR NEW.suite_version IS DISTINCT FROM suite_version
       OR NEW.suite_hash IS DISTINCT FROM suite_hash
       OR NEW.expected_slot_count IS DISTINCT FROM run_total
       OR EXISTS (SELECT 1 FROM test_case_runs WHERE test_run_id = NEW.run_id)
       OR NOT EXISTS (
           SELECT 1 FROM test_run_reviewer_grants grant_row
            WHERE grant_row.run_id = NEW.run_id AND grant_row.workspace_id = run_workspace
       ) THEN
        RAISE EXCEPTION 'unverified Run slot plan requires a queued granted Run and matching READY suite'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER test_run_slot_plan_insert_guard
BEFORE INSERT ON test_run_slot_plans
FOR EACH ROW EXECUTE FUNCTION finsec_guard_unverified_run_slot_plan();

CREATE TRIGGER test_run_slot_plan_immutable_guard
BEFORE UPDATE OR DELETE ON test_run_slot_plans
FOR EACH ROW EXECUTE FUNCTION finsec_forbid_mutation();

CREATE FUNCTION finsec_guard_unverified_run_slot_entry()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    run_status varchar(30);
    run_suite_id uuid;
    plan_state varchar(20);
    expected_count integer;
    case_suite_id uuid;
    configured_trials integer;
    current_count integer;
BEGIN
    -- Serialize count checks with all other slot/CaseRun writes for this Run.
    SELECT run.status, run.suite_id, plan.state, plan.expected_slot_count
      INTO run_status, run_suite_id, plan_state, expected_count
      FROM test_runs run
      JOIN test_run_slot_plans plan ON plan.run_id = run.id
     WHERE run.id = NEW.run_id
     FOR UPDATE OF run;
    IF NOT FOUND OR run_status <> 'QUEUED' OR plan_state <> 'UNVERIFIED'
       OR NEW.ordinal >= expected_count THEN
        RAISE EXCEPTION 'slot requires a queued unverified Run plan within its planned count'
            USING ERRCODE = '23514';
    END IF;
    SELECT test_case.suite_id, finsec_configured_trials_v1(test_case.trial_policy_json)
      INTO case_suite_id, configured_trials
      FROM test_cases test_case
     WHERE test_case.id = NEW.test_case_id;
    IF NOT FOUND OR case_suite_id IS DISTINCT FROM run_suite_id
       OR configured_trials IS NULL OR NEW.trial_index >= configured_trials THEN
        RAISE EXCEPTION 'slot requires a same-suite Case with an exact v1 trial policy'
            USING ERRCODE = '23514';
    END IF;
    SELECT count(*) INTO current_count FROM test_run_slot_entries WHERE run_id = NEW.run_id;
    IF current_count >= expected_count THEN
        RAISE EXCEPTION 'Run slot plan exceeds its immutable planned count'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER test_run_slot_entry_insert_guard
BEFORE INSERT ON test_run_slot_entries
FOR EACH ROW EXECUTE FUNCTION finsec_guard_unverified_run_slot_entry();

CREATE TRIGGER test_run_slot_entry_immutable_guard
BEFORE UPDATE OR DELETE ON test_run_slot_entries
FOR EACH ROW EXECUTE FUNCTION finsec_forbid_mutation();

CREATE FUNCTION finsec_reject_case_run_for_unverified_plan()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM 1 FROM test_runs WHERE id = NEW.test_run_id FOR UPDATE;
    IF EXISTS (SELECT 1 FROM test_run_slot_plans WHERE run_id = NEW.test_run_id) THEN
        RAISE EXCEPTION 'CaseRun cannot materialize under an unverified slot plan'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER test_case_run_unverified_plan_guard
BEFORE INSERT ON test_case_runs
FOR EACH ROW EXECUTE FUNCTION finsec_reject_case_run_for_unverified_plan();
