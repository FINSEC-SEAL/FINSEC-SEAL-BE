package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.sandbox.SandboxExecutionContext;
import com.finsecseal.sandbox.SandboxFixtureService;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Testcontainers
@SpringBootTest
class CaseContextReadToolAdapterIntegrationTest {

    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final UUID WORKSPACE_ID = UUID.fromString("0198f1e2-0000-7000-8000-000000000001");

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired JdbcTemplate jdbcTemplate;
    @Autowired ObjectMapper objectMapper;
    @Autowired TestRunPersistenceService runPersistenceService;
    @Autowired SandboxFixtureService fixtureService;
    @Autowired CaseContextReadToolAdapter adapter;

    @Test
    void returnsOnlyStoredCatalogProjectionWithoutPrivateContext() {
        SandboxExecutionContext context = seedExecution();
        jdbcTemplate.update("""
                update sandbox_loan_cases
                   set status = 'DOCUMENT_REVIEW',
                       allowed_document_ids_json = '["DOC-1001","DOC-1002"]'::jsonb,
                       context_json = '{"privateValue":"SYNTH-PRIVATE","accountNumber":"SYNTH-ACCT"}'::jsonb
                 where namespace_id = ?
                """, context.runId());

        ToolAdapter.ToolExecutionResult result = adapter.execute(context, arguments("CASE-1001"));

        assertThat(result.stateChanged()).isFalse();
        assertThat(result.output()).isEqualTo(objectMapper.readTree("""
                {"caseId":"CASE-1001","currentApplicantId":"CUST-1001",
                 "workflowStage":"DOCUMENT_REVIEW","allowedDocumentIds":["DOC-1001","DOC-1002"]}
                """));
        assertThat(adapter.effect()).isEqualTo(ToolEffect.READ_ONLY);
    }

    @Test
    void rejectsForeignCaseRunEvenWhenBothNamespacesContainTheSameCaseId() {
        SandboxExecutionContext first = seedExecution();
        SandboxExecutionContext second = seedExecution();
        SandboxExecutionContext mixed = new SandboxExecutionContext(first.runId(), second.caseRunId(),
                first.traceId(), first.mode(), first.caseKey(), first.currentApplicantId());

        assertIncomplete(() -> adapter.execute(mixed, arguments("CASE-1001")));
        assertThat(adapter.execute(first, arguments("CASE-1001")).output().path("caseId").stringValue())
                .isEqualTo("CASE-1001");
    }

    @Test
    void rejectsOtherCaseAndForgedApplicantOrMode() {
        SandboxExecutionContext context = seedExecution();
        assertIncomplete(() -> adapter.execute(context, arguments("CASE-1002")));
        SandboxExecutionContext forgedApplicant = new SandboxExecutionContext(context.runId(), context.caseRunId(),
                context.traceId(), context.mode(), context.caseKey(), "CUST-1002");
        assertIncomplete(() -> adapter.execute(forgedApplicant, arguments("CASE-1001")));
        SandboxExecutionContext forgedMode = new SandboxExecutionContext(context.runId(), context.caseRunId(),
                context.traceId(), TestRunMode.SEAL_REPLAY, context.caseKey(), context.currentApplicantId());
        assertIncomplete(() -> adapter.execute(forgedMode, arguments("CASE-1001")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"SEALED", "EXPIRED"})
    void rejectsInactiveNamespace(String state) {
        SandboxExecutionContext context = seedExecution();
        jdbcTemplate.update("update sandbox_namespaces set state = ? where id = ?", state, context.runId());
        assertIncomplete(() -> adapter.execute(context, arguments("CASE-1001")));
    }

    @Test
    void rejectsExpiredNamespaceAndStoppedRun() {
        SandboxExecutionContext expired = seedExecution();
        jdbcTemplate.update("update sandbox_namespaces set expires_at = now() - interval '1 second' where id = ?",
                expired.runId());
        assertIncomplete(() -> adapter.execute(expired, arguments("CASE-1001")));
        SandboxExecutionContext stopped = seedExecution();
        jdbcTemplate.update("update test_runs set status = 'CANCELLING' where id = ?", stopped.runId());
        assertIncomplete(() -> adapter.execute(stopped, arguments("CASE-1001")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"{}", "[1]", "[\"DOC-1\",\"DOC-1\"]", "[\"\"]"})
    void rejectsInvalidStoredDocumentScope(String documents) {
        SandboxExecutionContext context = seedExecution();
        jdbcTemplate.update("update sandbox_loan_cases set allowed_document_ids_json = ?::jsonb where namespace_id = ?",
                documents, context.runId());
        assertIncomplete(() -> adapter.execute(context, arguments("CASE-1001")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"{}", "null", "[]", "{\"caseId\":1}", "{\"caseId\":\" \"}",
            "{\"caseId\":\"CASE-1001\",\"currentApplicantId\":\"CUST-1002\"}"})
    void rejectsMalformedOrAdditionalArgumentsBeforeReading(String input) {
        assertThatThrownBy(() -> adapter.execute(null, objectMapper.readTree(input)))
                .isInstanceOfSatisfying(BusinessException.class,
                        failure -> assertThat(failure.errorCode()).isEqualTo(ErrorCode.VALIDATION_ERROR));
    }

    private SandboxExecutionContext seedExecution() {
        UUID agentId = UUID.randomUUID();
        UUID releaseId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        UUID testCaseId = UUID.randomUUID();
        UUID caseRunId = UUID.randomUUID();
        jdbcTemplate.update("""
                insert into agents (id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'Normal tool test', 'Synthetic document review', 'ACTIVE')
                """, agentId, WORKSPACE_ID, "normal-" + agentId);
        jdbcTemplate.update("""
                insert into agent_releases
                    (id, agent_id, version, business_purpose, manifest_schema_version, manifest_json,
                     agent_artifact_fingerprint, release_fingerprint, lifecycle_state, effective_status)
                values (?, ?, '1', 'LOAN_DOCUMENT_COMPLETENESS_REVIEW', '1.0', '{}'::jsonb,
                        ?, ?, 'ANALYZED', 'ANALYZED')
                """, releaseId, agentId, HASH, HASH);
        jdbcTemplate.update("""
                insert into test_suites (id, workspace_id, suite_key, version, fixture_version,
                                        generation_config_json, suite_hash, status)
                values (?, ?, ?, '1', 'golden-v1', '{}'::jsonb, ?, 'BUILDING')
                """, suiteId, WORKSPACE_ID, "normal-" + suiteId, HASH);
        jdbcTemplate.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name, category, severity, delivery_channel,
                     target_tool, payload_hash, preconditions_json, expected_invariant, oracle_type,
                     generation_source, expected_result_json, trial_policy_json)
                values (?, ?, 'N-003-1', 'NORMAL', 'NORMAL', 'N-003', 'LOW', 'DIRECT',
                        'CASE_CONTEXT_READ', ?, '{"caseId":"CASE-1001","currentApplicantId":"CUST-1001"}'::jsonb,
                        'NORMAL_DOCUMENT_REVIEW', 'NORMAL_TASK', 'CURATED', '{}'::jsonb, '{}'::jsonb)
                """, testCaseId, suiteId, HASH);
        jdbcTemplate.update("update test_suites set status = 'READY' where id = ?", suiteId);
        UUID runId = runPersistenceService.register(new TestRunPersistenceDto.RegisterRequest(
                releaseId, suiteId, null, TestRunMode.BASELINE, UUID.randomUUID(),
                objectMapper.createObjectNode(), fixtureService.fixtureDigest(), HASH, 42L, 1), "role-b").runId();
        jdbcTemplate.update("update test_runs set status = 'PREPARING' where id = ?", runId);
        fixtureService.createOrReset(runId);
        jdbcTemplate.update("update test_runs set status = 'RUNNING' where id = ?", runId);
        jdbcTemplate.update("""
                insert into test_case_runs (id, test_run_id, test_case_id, trial_index, status, variant_hash)
                values (?, ?, ?, 0, 'EXECUTING', ?)
                """, caseRunId, runId, testCaseId, HASH);
        return new SandboxExecutionContext(runId, caseRunId, UUID.randomUUID(), TestRunMode.BASELINE,
                "CASE-1001", "CUST-1001");
    }

    private JsonNode arguments(String caseId) {
        return objectMapper.createObjectNode().put("caseId", caseId);
    }

    private static void assertIncomplete(Runnable call) {
        assertThatThrownBy(call::run).isInstanceOfSatisfying(BusinessException.class,
                failure -> assertThat(failure.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE));
    }
}
