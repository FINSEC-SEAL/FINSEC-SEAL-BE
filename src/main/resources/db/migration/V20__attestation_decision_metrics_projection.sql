-- INSERT-only extension of the immutable Decision projection. Existing reports
-- remain byte/hash preserving historical evidence; no backfill or guard removal.
CREATE FUNCTION finsec_guard_attestation_decision_metrics_projection()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    snapshot jsonb;
    field_name text;
BEGIN
    SELECT input_snapshot_json INTO snapshot
      FROM release_decisions WHERE id = NEW.release_decision_id;
    FOREACH field_name IN ARRAY ARRAY[
        'policyLatency', 'completionRate', 'trialSuccessDistribution', 'attackRateBreakdown'
    ] LOOP
        -- Presence is separate from value: absent, SQL NULL and JSON null must
        -- never be confused when extending a recorded report.
        IF (NEW.document_json ? field_name) IS DISTINCT FROM (snapshot ? field_name)
           OR NEW.document_json->field_name IS DISTINCT FROM snapshot->field_name THEN
            RAISE EXCEPTION 'attestation metric report must exactly project its Decision'
                USING ERRCODE = '23514';
        END IF;
    END LOOP;
    RETURN NEW;
END;
$$;

CREATE TRIGGER release_attestation_decision_metrics_guard
BEFORE INSERT ON release_attestations
FOR EACH ROW EXECUTE FUNCTION finsec_guard_attestation_decision_metrics_projection();
