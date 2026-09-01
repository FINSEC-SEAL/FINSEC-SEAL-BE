CREATE OR REPLACE FUNCTION finsec_validate_release_attestation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    decision_release_id uuid;
    decision_value varchar(20);
    decision_gate_version varchar(50);
    decision_input_digest varchar(71);
    decision_confirmed_at timestamptz;
BEGIN
    SELECT release_id, decision, gate_policy_version, input_digest, confirmed_at
      INTO decision_release_id, decision_value, decision_gate_version,
           decision_input_digest, decision_confirmed_at
      FROM release_decisions
     WHERE id = NEW.release_decision_id
     FOR KEY SHARE;
    IF decision_release_id IS NULL THEN
        RAISE EXCEPTION 'attestation decision does not exist' USING ERRCODE = '23503';
    END IF;
    IF NEW.format_version <> '1.0'
       OR NEW.disclaimer_version <> 'finsec-internal/v1'
       OR NEW.document_json->>'schemaVersion' <> '1.0'
       OR NEW.document_json->>'attestationType' <> 'FINSEC_SEAL_INTERNAL_RELEASE_ATTESTATION'
       OR NEW.document_json#>>'{release,id}' <> decision_release_id::text
       OR NEW.document_json#>>'{decision,id}' <> NEW.release_decision_id::text
       OR NEW.document_json#>>'{decision,value}' <> decision_value
       OR NEW.document_json#>>'{decision,gatePolicyVersion}' <> decision_gate_version
       OR NEW.document_json#>>'{decision,inputDigest}' <> decision_input_digest
       OR NEW.generated_at IS DISTINCT FROM decision_confirmed_at
       OR NEW.document_json#>>'{disclaimer,version}' <> 'finsec-internal/v1'
       OR NEW.document_json#>>'{disclaimer,ko}' <>
          '본 Release Decision은 FINSEC SEAL MVP 내부 평가 정책에 따른 것이며 공식 금융보안 인증 또는 규제 준수 판정이 아니다.'
       OR NEW.document_json#>>'{disclaimer,en}' <>
          'This is an internal FINSEC SEAL MVP security assessment and not an official certification by any regulatory or financial-security authority.'
       OR position('공식 금융보안 인증' in NEW.html_content) = 0
       OR position('not an official certification' in NEW.html_content) = 0 THEN
        RAISE EXCEPTION 'attestation projection does not match its confirmed decision or immutable disclaimer'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER release_attestation_projection_guard
BEFORE INSERT ON release_attestations
FOR EACH ROW EXECUTE FUNCTION finsec_validate_release_attestation();
