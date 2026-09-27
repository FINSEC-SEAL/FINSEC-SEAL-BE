-- Extend the immutable Decision-to-Attestation projection without changing V7's checksum.
-- Both absent fields are equal for historical Decisions; a new count-bearing Decision
-- must project its exact observed effects into the stored Attestation document.
CREATE FUNCTION finsec_guard_attestation_observed_effect_projection() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    expected_counts jsonb;
BEGIN
    SELECT input_snapshot_json->'observedEffectCounts' INTO expected_counts
      FROM release_decisions WHERE id = NEW.release_decision_id;
    IF NEW.document_json->'observedEffectCounts' IS DISTINCT FROM expected_counts THEN
        RAISE EXCEPTION 'attestation observed effect counts do not match confirmed decision'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER release_attestation_z_observed_effect_guard
BEFORE INSERT ON release_attestations
FOR EACH ROW EXECUTE FUNCTION finsec_guard_attestation_observed_effect_projection();
