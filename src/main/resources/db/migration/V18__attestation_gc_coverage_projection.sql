-- Extend the append-only Decision-to-Attestation projection without changing V7/V14.3.
-- Historical Decisions without a GC report keep their original document shape;
-- current reports must be copied exactly, never replaced by an inferred false.
CREATE FUNCTION finsec_guard_attestation_gc_coverage_projection() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    decision_value text;
    decision_snapshot jsonb;
    expected_report jsonb;
    expected_coverage jsonb;
BEGIN
    SELECT decision, input_snapshot_json INTO decision_value, decision_snapshot
      FROM release_decisions WHERE id = NEW.release_decision_id;

    -- The current report has no complete negative-proof producer. A new PASS
    -- Attestation must wait for a separately validated, versioned contract.
    IF decision_value = 'PASS' THEN
        RAISE EXCEPTION 'attestation PASS requires verifiable GC negative proof'
            USING ERRCODE = '23514';
    END IF;

    IF decision_snapshot ? 'criticalInvariantAnySuccess' THEN
        expected_report := decision_snapshot->'criticalInvariantAnySuccess';
        expected_coverage := decision_snapshot->'criticalTrialCoverage';
        IF jsonb_typeof(expected_report) IS DISTINCT FROM 'object'
           OR jsonb_typeof(expected_report->'invariants') IS DISTINCT FROM 'array'
           OR jsonb_typeof(expected_coverage) IS DISTINCT FROM 'object'
           OR NEW.document_json->'criticalInvariantAnySuccess' IS DISTINCT FROM expected_report
           OR NEW.document_json->'criticalTrialCoverage' IS DISTINCT FROM expected_coverage THEN
            RAISE EXCEPTION 'attestation GC report or coverage does not match confirmed decision'
                USING ERRCODE = '23514';
        END IF;
        IF EXISTS (
            SELECT 1 FROM jsonb_array_elements(expected_report->'invariants') AS invariant(value)
             WHERE invariant.value->'anySuccess' = 'false'::jsonb
        ) THEN
            RAISE EXCEPTION 'attestation GC false lacks versioned negative proof'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.document_json ? 'criticalInvariantAnySuccess'
       OR NEW.document_json ? 'criticalTrialCoverage' THEN
        RAISE EXCEPTION 'legacy attestation cannot invent GC or coverage projection'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER release_attestation_zz_gc_coverage_guard
BEFORE INSERT ON release_attestations
FOR EACH ROW EXECUTE FUNCTION finsec_guard_attestation_gc_coverage_projection();
