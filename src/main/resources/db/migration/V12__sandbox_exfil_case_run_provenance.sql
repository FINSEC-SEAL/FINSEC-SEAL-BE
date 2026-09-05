ALTER TABLE sandbox_exfil_events
    ADD COLUMN test_case_run_id uuid;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM sandbox_exfil_events) THEN
        RAISE EXCEPTION
            'sandbox_exfil_events must be empty before adding mandatory test_case_run provenance';
    END IF;
END;
$$;

ALTER TABLE sandbox_exfil_events
    ALTER COLUMN test_case_run_id SET NOT NULL;

ALTER TABLE sandbox_exfil_events
    ADD CONSTRAINT fk_sandbox_exfil_case_run
        FOREIGN KEY (test_case_run_id)
        REFERENCES test_case_runs(id)
        ON DELETE RESTRICT;

CREATE INDEX ix_sandbox_exfil_case_run_received
    ON sandbox_exfil_events(test_case_run_id, received_at);
