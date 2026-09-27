-- A signed reviewer session may grant authority only to its newly registered Run.
-- The admission service writes this row in the same transaction as test_runs and audit_records.
CREATE TABLE test_run_reviewer_grants (
    run_id uuid PRIMARY KEY REFERENCES test_runs(id) ON DELETE RESTRICT,
    workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
    actor_id varchar(120) NOT NULL CHECK (actor_id <> '' AND actor_id = btrim(actor_id)),
    reviewer_role varchar(40) NOT NULL CHECK (reviewer_role = 'AI_SECURITY_REVIEWER'),
    session_digest sha256_digest NOT NULL,
    authority_stamp varchar(100) NOT NULL CHECK (authority_stamp <> '' AND authority_stamp = btrim(authority_stamp)),
    authority_expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (authority_expires_at > created_at)
);

CREATE FUNCTION finsec_guard_test_run_reviewer_grant_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    run_workspace uuid;
    run_status varchar(30);
BEGIN
    SELECT agent.workspace_id, run.status INTO run_workspace, run_status
      FROM test_runs run
      JOIN agent_releases release ON release.id = run.release_id
      JOIN agents agent ON agent.id = release.agent_id
     WHERE run.id = NEW.run_id
     FOR UPDATE OF run;
    IF run_workspace IS NULL OR run_workspace <> NEW.workspace_id THEN
        RAISE EXCEPTION 'run reviewer grant workspace does not match the Run'
            USING ERRCODE = '23514';
    END IF;
    IF run_status <> 'QUEUED' THEN
        RAISE EXCEPTION 'run reviewer grant requires a newly queued Run'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER test_run_reviewer_grant_scope_guard
BEFORE INSERT ON test_run_reviewer_grants
FOR EACH ROW EXECUTE FUNCTION finsec_guard_test_run_reviewer_grant_insert();

CREATE TRIGGER test_run_reviewer_grant_immutable
BEFORE UPDATE OR DELETE ON test_run_reviewer_grants
FOR EACH ROW EXECUTE FUNCTION finsec_forbid_mutation();
