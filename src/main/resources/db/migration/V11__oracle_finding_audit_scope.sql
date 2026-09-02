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
        WHEN 'ORACLE_RESULT' THEN
            SELECT agent.workspace_id INTO result
              FROM oracle_results oracle
              JOIN test_case_runs case_run ON case_run.id = oracle.test_case_run_id
              JOIN test_runs run ON run.id = case_run.test_run_id
              JOIN agent_releases release ON release.id = run.release_id
              JOIN agents agent ON agent.id = release.agent_id
             WHERE oracle.id = target_id;
        WHEN 'FINDING' THEN
            SELECT agent.workspace_id INTO result
              FROM findings finding
              JOIN agent_releases release ON release.id = finding.release_id
              JOIN agents agent ON agent.id = release.agent_id
             WHERE finding.id = target_id;
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
        WHEN 'IDEMPOTENCY_RECOVERY' THEN
            SELECT workspace_id INTO result FROM idempotency_recoveries WHERE id = target_id;
        ELSE
            RAISE EXCEPTION 'unsupported audit resource type %', resource_kind USING ERRCODE = '23514';
    END CASE;
    IF result IS NULL THEN
        RAISE EXCEPTION 'audit resource does not exist' USING ERRCODE = '23503';
    END IF;
    RETURN result;
END;
$$;
