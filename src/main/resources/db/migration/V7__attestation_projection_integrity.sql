CREATE OR REPLACE FUNCTION finsec_validate_release_attestation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    decision_release_id uuid;
    latest_decision_id uuid;
    decision_value varchar(20);
    decision_gate_version varchar(50);
    decision_input_digest varchar(71);
    decision_input_snapshot jsonb;
    decision_proposed_at timestamptz;
    decision_confirmed_at timestamptz;
    decision_confirmed_by varchar(120);
BEGIN
    SELECT release_id INTO decision_release_id
      FROM release_decisions
     WHERE id = NEW.release_decision_id;
    IF decision_release_id IS NULL THEN
        RAISE EXCEPTION 'attestation decision does not exist' USING ERRCODE = '23503';
    END IF;
    PERFORM 1 FROM agent_releases WHERE id = decision_release_id FOR UPDATE;
    SELECT decision, gate_policy_version, input_snapshot_json, input_digest,
           proposed_at, confirmed_at, confirmed_by
      INTO decision_value, decision_gate_version, decision_input_snapshot, decision_input_digest,
           decision_proposed_at, decision_confirmed_at, decision_confirmed_by
      FROM release_decisions
     WHERE id = NEW.release_decision_id
     FOR KEY SHARE;
    SELECT id INTO latest_decision_id
      FROM release_decisions
     WHERE release_id = decision_release_id
     ORDER BY confirmed_at DESC, created_at DESC, id DESC
     LIMIT 1;
    IF NEW.format_version <> '1.0'
       OR NEW.disclaimer_version <> 'finsec-internal/v1'
       OR latest_decision_id IS DISTINCT FROM NEW.release_decision_id
       OR NEW.document_json->>'schemaVersion' <> '1.0'
       OR NEW.document_json->>'attestationType' <> 'FINSEC_SEAL_INTERNAL_RELEASE_ATTESTATION'
       OR NEW.document_json->>'canonicalizationVersion' <> 'RFC8785+NFC/v1'
       OR NEW.document_json->'agent' IS DISTINCT FROM decision_input_snapshot->'agent'
       OR NEW.document_json->'release' IS DISTINCT FROM decision_input_snapshot->'release'
       OR NEW.document_json->'model' IS DISTINCT FROM decision_input_snapshot->'model'
       OR NEW.document_json->'systemPromptFingerprint'
          IS DISTINCT FROM decision_input_snapshot->'systemPromptFingerprint'
       OR NEW.document_json->'toolSetFingerprint'
          IS DISTINCT FROM decision_input_snapshot->'toolSetFingerprint'
       OR NEW.document_json->'toolSchemaFingerprints'
          IS DISTINCT FROM decision_input_snapshot->'toolSchemaFingerprints'
       OR NEW.document_json->'ragConfigurationFingerprint'
          IS DISTINCT FROM decision_input_snapshot->'ragConfigurationFingerprint'
       OR NEW.document_json->'safetyContract' IS DISTINCT FROM decision_input_snapshot->'safetyContract'
       OR NEW.document_json->'testSuite' IS DISTINCT FROM decision_input_snapshot->'testSuite'
       OR NEW.document_json->'sandbox' IS DISTINCT FROM decision_input_snapshot->'sandbox'
       OR NEW.document_json->'results' IS DISTINCT FROM decision_input_snapshot->'results'
       OR NEW.document_json->'metrics' IS DISTINCT FROM decision_input_snapshot->'metrics'
       OR NEW.document_json->'remainingFindings' IS DISTINCT FROM decision_input_snapshot->'remainingFindings'
       OR NEW.document_json->'approvedPatch' IS DISTINCT FROM decision_input_snapshot->'approvedPatch'
       OR NEW.document_json->'testedAt' IS DISTINCT FROM decision_input_snapshot->'testedAt'
       OR NEW.document_json#>>'{release,id}' <> decision_release_id::text
       OR NEW.document_json#>>'{decision,id}' <> NEW.release_decision_id::text
       OR NEW.document_json#>>'{decision,value}' <> decision_value
       OR NEW.document_json#>>'{decision,gatePolicyVersion}' <> decision_gate_version
       OR NEW.document_json#>'{decision,ruleTrace}'
          IS DISTINCT FROM decision_input_snapshot#>'{decision,ruleTrace}'
       OR NEW.document_json#>>'{decision,inputDigest}' <> decision_input_digest
       OR (NEW.document_json#>>'{decision,proposedAt}')::timestamptz IS DISTINCT FROM decision_proposed_at
       OR (NEW.document_json#>>'{decision,confirmedAt}')::timestamptz IS DISTINCT FROM decision_confirmed_at
       OR NEW.document_json#>>'{reviewer,actorId}' <> decision_confirmed_by
       OR NEW.document_json#>>'{reviewer,role}' <> 'AI_GOVERNANCE_REVIEWER'
       OR NEW.document_json#>>'{reviewer,demoMode}' <> 'true'
       OR NEW.document_json->'revalidationTriggers' IS DISTINCT FROM
          '["MODEL_CHANGE","SYSTEM_PROMPT_CHANGE","TOOL_SET_OR_SCHEMA_OR_DESCRIPTION_CHANGE",
            "RAG_CHANGE","SAFETY_CONTRACT_CHANGE","BUSINESS_PURPOSE_OR_CONTEXT_CHANGE"]'::jsonb
       OR (NEW.document_json->>'generatedAt')::timestamptz IS DISTINCT FROM decision_confirmed_at
       OR NEW.generated_at IS DISTINCT FROM decision_confirmed_at
       OR NEW.document_json#>>'{disclaimer,version}' <> 'finsec-internal/v1'
       OR NEW.document_json#>>'{disclaimer,ko}' <>
          '본 Release Decision은 FINSEC SEAL MVP 내부 평가 정책에 따른 것이며 공식 금융보안 인증 또는 규제 준수 판정이 아니다.'
       OR NEW.document_json#>>'{disclaimer,en}' <>
          'This is an internal FINSEC SEAL MVP security assessment and not an official certification by any regulatory or financial-security authority.'
       OR position('공식 금융보안 인증' in NEW.html_content) = 0
       OR position('not an official certification' in NEW.html_content) = 0
       OR position(decision_release_id::text in NEW.html_content) = 0
       OR position(decision_value in NEW.html_content) = 0
       OR position(NEW.document_hash in NEW.html_content) = 0 THEN
        RAISE EXCEPTION 'attestation projection does not match its confirmed decision or immutable disclaimer'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER release_attestation_projection_guard
BEFORE INSERT ON release_attestations
FOR EACH ROW EXECUTE FUNCTION finsec_validate_release_attestation();

CREATE OR REPLACE FUNCTION finsec_lock_decision_invalidation_release()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    decision_release_id uuid;
BEGIN
    SELECT release_id INTO decision_release_id
      FROM release_decisions
     WHERE id = NEW.release_decision_id;
    IF decision_release_id IS NULL THEN
        RAISE EXCEPTION 'invalidation decision does not exist' USING ERRCODE = '23503';
    END IF;
    PERFORM 1 FROM agent_releases WHERE id = decision_release_id FOR UPDATE;
    RETURN NEW;
END;
$$;

CREATE TRIGGER decision_invalidation_release_lock
BEFORE INSERT ON decision_invalidations
FOR EACH ROW EXECUTE FUNCTION finsec_lock_decision_invalidation_release();
