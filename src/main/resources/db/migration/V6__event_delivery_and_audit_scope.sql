CREATE OR REPLACE FUNCTION finsec_assert_release_draft(target_release_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    current_state varchar(30);
BEGIN
    SELECT lifecycle_state INTO current_state
      FROM agent_releases
     WHERE id = target_release_id
     FOR UPDATE;
    IF current_state IS NULL THEN
        RAISE EXCEPTION 'release does not exist' USING ERRCODE = '23503';
    END IF;
    IF current_state <> 'DRAFT' THEN
        RAISE EXCEPTION 'release fingerprint inputs are immutable after analyze' USING ERRCODE = '55000';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION finsec_guard_referenced_definition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    is_frozen boolean;
BEGIN
    IF TG_TABLE_NAME = 'tool_definitions' THEN
        PERFORM 1
          FROM agent_releases release
          JOIN release_tools link ON link.release_id = release.id
         WHERE link.tool_definition_id = OLD.id
         ORDER BY release.id
         FOR UPDATE OF release;
        SELECT EXISTS (
            SELECT 1 FROM release_tools link
            JOIN agent_releases release ON release.id = link.release_id
            WHERE link.tool_definition_id = OLD.id AND release.lifecycle_state <> 'DRAFT'
        ) INTO is_frozen;
    ELSE
        PERFORM 1
          FROM agent_releases release
          JOIN release_rag_sources link ON link.release_id = release.id
         WHERE link.rag_source_id = OLD.id
         ORDER BY release.id
         FOR UPDATE OF release;
        SELECT EXISTS (
            SELECT 1 FROM release_rag_sources link
            JOIN agent_releases release ON release.id = link.release_id
            WHERE link.rag_source_id = OLD.id AND release.lifecycle_state <> 'DRAFT'
        ) INTO is_frozen;
    END IF;
    IF is_frozen THEN
        RAISE EXCEPTION 'definition referenced by analyzed release is immutable' USING ERRCODE = '55000';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE OR REPLACE FUNCTION finsec_require_active_release_agent()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    agent_state varchar(20);
BEGIN
    SELECT status INTO agent_state FROM agents WHERE id = NEW.agent_id FOR UPDATE;
    IF agent_state IS NULL THEN
        RAISE EXCEPTION 'release agent does not exist' USING ERRCODE = '23503';
    END IF;
    IF agent_state <> 'ACTIVE' THEN
        RAISE EXCEPTION 'archived agent cannot receive a release' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER agent_release_active_agent_guard
BEFORE INSERT ON agent_releases
FOR EACH ROW EXECUTE FUNCTION finsec_require_active_release_agent();

CREATE TABLE event_outbox (
    event_id uuid PRIMARY KEY REFERENCES execution_events(id) ON DELETE RESTRICT,
    run_id uuid NOT NULL REFERENCES test_runs(id) ON DELETE RESTRICT,
    sequence bigint NOT NULL CHECK (sequence > 0),
    event_type varchar(60) NOT NULL,
    publish_attempts integer NOT NULL DEFAULT 0 CHECK (publish_attempts >= 0),
    last_attempt_at timestamptz,
    published_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_event_outbox_run_sequence UNIQUE (run_id, sequence)
);

CREATE INDEX ix_event_outbox_pending
    ON event_outbox(created_at, event_id)
    WHERE published_at IS NULL;

CREATE OR REPLACE FUNCTION finsec_enqueue_execution_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO event_outbox (event_id, run_id, sequence, event_type)
    VALUES (NEW.id, NEW.run_id, NEW.sequence, NEW.event_type);
    RETURN NEW;
END;
$$;

CREATE TRIGGER execution_event_outbox_enqueue
AFTER INSERT ON execution_events
FOR EACH ROW EXECUTE FUNCTION finsec_enqueue_execution_event();

CREATE OR REPLACE FUNCTION finsec_protect_event_outbox()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'event outbox rows cannot be deleted' USING ERRCODE = '55000';
    END IF;
    IF NEW.event_id IS DISTINCT FROM OLD.event_id
       OR NEW.run_id IS DISTINCT FROM OLD.run_id
       OR NEW.sequence IS DISTINCT FROM OLD.sequence
       OR NEW.event_type IS DISTINCT FROM OLD.event_type
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'event outbox identity is immutable' USING ERRCODE = '55000';
    END IF;
    IF NEW.publish_attempts < OLD.publish_attempts
       OR NEW.publish_attempts > OLD.publish_attempts + 1
       OR (NEW.publish_attempts > OLD.publish_attempts AND NEW.last_attempt_at IS NULL)
       OR (OLD.published_at IS NOT NULL AND NEW.published_at IS DISTINCT FROM OLD.published_at)
       OR (OLD.published_at IS NULL AND NEW.published_at IS NOT NULL
           AND NEW.publish_attempts <= OLD.publish_attempts) THEN
        RAISE EXCEPTION 'invalid event outbox delivery transition' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER event_outbox_guard
BEFORE UPDATE OR DELETE ON event_outbox
FOR EACH ROW EXECUTE FUNCTION finsec_protect_event_outbox();

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
        ELSE
            RAISE EXCEPTION 'unsupported audit resource type %', resource_kind USING ERRCODE = '23514';
    END CASE;
    IF result IS NULL THEN
        RAISE EXCEPTION 'audit resource does not exist' USING ERRCODE = '23503';
    END IF;
    RETURN result;
END;
$$;

CREATE OR REPLACE FUNCTION finsec_validate_audit_scope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF finsec_audit_resource_workspace(NEW.resource_type, NEW.resource_id) <> NEW.workspace_id THEN
        RAISE EXCEPTION 'audit resource and workspace must match' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER audit_record_scope_guard
BEFORE INSERT ON audit_records
FOR EACH ROW EXECUTE FUNCTION finsec_validate_audit_scope();

ALTER TABLE test_case_runs
    ADD CONSTRAINT ck_test_case_run_status CHECK (status IN (
        'PENDING', 'EXECUTING', 'EVALUATING', 'PASSED', 'FAILED_SECURITY',
        'FAILED_FUNCTIONAL', 'ERROR', 'CANCELLED'
    ));

CREATE OR REPLACE FUNCTION finsec_validate_test_run_state_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    latest_event_type varchar(60);
BEGIN
    IF NEW.status = OLD.status THEN
        RETURN NEW;
    END IF;
    IF NOT (
        (OLD.status = 'QUEUED' AND NEW.status IN ('PREPARING', 'CANCELLING', 'FAILED', 'CANCELLED')) OR
        (OLD.status = 'PREPARING' AND NEW.status IN ('RUNNING', 'CANCELLING', 'FAILED', 'CANCELLED')) OR
        (OLD.status = 'RUNNING' AND NEW.status IN ('CANCELLING', 'COMPLETED', 'FAILED')) OR
        (OLD.status = 'CANCELLING' AND NEW.status IN ('CANCELLED', 'FAILED'))
    ) THEN
        RAISE EXCEPTION 'invalid test run state transition % -> %', OLD.status, NEW.status
            USING ERRCODE = '23514';
    END IF;
    IF NEW.status IN ('COMPLETED', 'FAILED', 'CANCELLED') THEN
        SELECT event_type INTO latest_event_type
          FROM execution_events
         WHERE run_id = OLD.id
         ORDER BY sequence DESC
         LIMIT 1;
        IF (NEW.status = 'COMPLETED' AND latest_event_type IS DISTINCT FROM 'RUN_COMPLETED')
           OR (NEW.status = 'FAILED' AND latest_event_type IS DISTINCT FROM 'RUN_FAILED')
           OR (NEW.status = 'CANCELLED' AND latest_event_type IS DISTINCT FROM 'RUN_CANCEL_REQUESTED') THEN
            RAISE EXCEPTION 'terminal test run transition requires its canonical terminal event first'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER test_run_state_transition_guard
BEFORE UPDATE ON test_runs
FOR EACH ROW EXECUTE FUNCTION finsec_validate_test_run_state_transition();

CREATE OR REPLACE FUNCTION finsec_validate_test_case_run_state_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status = OLD.status THEN
        RETURN NEW;
    END IF;
    IF NOT (
        (OLD.status = 'PENDING' AND NEW.status IN (
            'EXECUTING', 'EVALUATING', 'PASSED', 'FAILED_SECURITY', 'FAILED_FUNCTIONAL', 'ERROR', 'CANCELLED'
        )) OR
        (OLD.status = 'EXECUTING' AND NEW.status IN (
            'EVALUATING', 'PASSED', 'FAILED_SECURITY', 'FAILED_FUNCTIONAL', 'ERROR', 'CANCELLED'
        )) OR
        (OLD.status = 'EVALUATING' AND NEW.status IN (
            'PASSED', 'FAILED_SECURITY', 'FAILED_FUNCTIONAL', 'ERROR', 'CANCELLED'
        ))
    ) THEN
        RAISE EXCEPTION 'invalid test case run state transition % -> %', OLD.status, NEW.status
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER test_case_run_state_transition_guard
BEFORE UPDATE ON test_case_runs
FOR EACH ROW EXECUTE FUNCTION finsec_validate_test_case_run_state_transition();

CREATE OR REPLACE FUNCTION finsec_validate_test_case_run_capacity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    planned_count integer;
    materialized_count integer;
    run_status varchar(30);
BEGIN
    SELECT total_cases, status INTO planned_count, run_status
      FROM test_runs WHERE id = NEW.test_run_id FOR UPDATE;
    IF run_status IS NULL THEN
        RAISE EXCEPTION 'test case run parent does not exist' USING ERRCODE = '23503';
    END IF;
    IF run_status IN ('COMPLETED', 'FAILED', 'CANCELLED') THEN
        RAISE EXCEPTION 'test case run cannot be materialized after run termination'
            USING ERRCODE = '55000';
    END IF;
    SELECT count(*) INTO materialized_count
      FROM test_case_runs WHERE test_run_id = NEW.test_run_id;
    IF materialized_count >= planned_count THEN
        RAISE EXCEPTION 'materialized test case runs exceed the immutable planned total'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER test_case_run_capacity_guard
BEFORE INSERT ON test_case_runs
FOR EACH ROW EXECUTE FUNCTION finsec_validate_test_case_run_capacity();

CREATE OR REPLACE FUNCTION finsec_reject_event_after_terminal_marker()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    latest_event_type varchar(60);
BEGIN
    SELECT event_type INTO latest_event_type
      FROM execution_events
     WHERE run_id = NEW.run_id
     ORDER BY sequence DESC
     LIMIT 1;
    IF latest_event_type IS NULL AND NEW.event_type <> 'RUN_STARTED' THEN
        RAISE EXCEPTION 'execution event stream must begin with RUN_STARTED'
            USING ERRCODE = '23514';
    END IF;
    IF latest_event_type IS NOT NULL AND NEW.event_type = 'RUN_STARTED' THEN
        RAISE EXCEPTION 'RUN_STARTED can only be the first execution event'
            USING ERRCODE = '23514';
    END IF;
    IF latest_event_type IN ('RUN_COMPLETED', 'RUN_FAILED') THEN
        RAISE EXCEPTION 'execution event stream is sealed by a terminal marker'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER execution_event_terminal_marker_guard
BEFORE INSERT ON execution_events
FOR EACH ROW EXECUTE FUNCTION finsec_reject_event_after_terminal_marker();
