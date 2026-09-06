CREATE TABLE sandbox_tool_idempotency_records (
    id uuid PRIMARY KEY,
    test_case_run_id uuid NOT NULL
        REFERENCES test_case_runs(id) ON DELETE RESTRICT,
    tool_call_id uuid NOT NULL
        REFERENCES execution_events(id) ON DELETE RESTRICT,
    tool_name varchar(100) NOT NULL,
    request_digest sha256_digest NOT NULL,
    state varchar(20) NOT NULL
        CHECK (state IN ('PROCESSING', 'COMPLETED')),
    response_json jsonb,
    state_changed boolean,
    request_event_id uuid
        REFERENCES execution_events(id) ON DELETE RESTRICT,
    response_event_id uuid
        REFERENCES execution_events(id) ON DELETE RESTRICT,
    state_event_id uuid
        REFERENCES execution_events(id) ON DELETE RESTRICT,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT uq_sandbox_tool_idempotency_scope
        UNIQUE (test_case_run_id, tool_call_id),

    CONSTRAINT ck_sandbox_tool_idempotency_completion
        CHECK (
            (
                state = 'PROCESSING'
                AND response_json IS NULL
                AND state_changed IS NULL
                AND request_event_id IS NULL
                AND response_event_id IS NULL
                AND state_event_id IS NULL
                AND completed_at IS NULL
            )
            OR
            (
                state = 'COMPLETED'
                AND response_json IS NOT NULL
                AND state_changed IS NOT NULL
                AND request_event_id IS NOT NULL
                AND response_event_id IS NOT NULL
                AND completed_at IS NOT NULL
                AND (
                    (state_changed = false AND state_event_id IS NULL)
                    OR
                    (state_changed = true AND state_event_id IS NOT NULL)
                )
            )
        )
);

CREATE INDEX ix_sandbox_tool_idempotency_case_run
    ON sandbox_tool_idempotency_records(test_case_run_id);

CREATE OR REPLACE FUNCTION finsec_guard_sandbox_tool_idempotency()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'sandbox tool idempotency records cannot be deleted'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.test_case_run_id IS DISTINCT FROM NEW.test_case_run_id
       OR OLD.tool_call_id IS DISTINCT FROM NEW.tool_call_id
       OR OLD.tool_name IS DISTINCT FROM NEW.tool_name
       OR OLD.request_digest IS DISTINCT FROM NEW.request_digest
       OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION
            'sandbox tool idempotency identity is immutable'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.state <> 'PROCESSING'
       OR NEW.state <> 'COMPLETED' THEN
        RAISE EXCEPTION
            'only PROCESSING to COMPLETED transition is allowed'
            USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER sandbox_tool_idempotency_guard
BEFORE UPDATE OR DELETE ON sandbox_tool_idempotency_records
FOR EACH ROW
EXECUTE FUNCTION finsec_guard_sandbox_tool_idempotency();
