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
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Testcontainers
@SpringBootTest
class DocumentReaderToolAdapterIntegrationTest {

    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final UUID WORKSPACE_ID = UUID.fromString("0198f1e2-0000-7000-8000-000000000001");

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired JdbcTemplate jdbcTemplate;
    @Autowired ObjectMapper objectMapper;
    @Autowired TestRunPersistenceService runPersistenceService;
    @Autowired SandboxFixtureService fixtureService;
    @Autowired DocumentReaderToolAdapter adapter;

    @Test
    void versionedFixtureClonesExactDocumentAndPolicyInventory() {
        SandboxExecutionContext context = seedExecution(SandboxFixtureService.NORMAL_FIXTURE_VERSION);

        assertThat(fixtureService.verifyIntegrity(context.runId())).isTrue();
        assertThat(fixtureService.fixtureDigest(SandboxFixtureService.NORMAL_FIXTURE_VERSION))
                .isNotEqualTo(fixtureService.fixtureDigest());
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from sandbox_documents where namespace_id = ?", Integer.class, context.runId()))
                .isEqualTo(4);
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from sandbox_loan_policies where namespace_id = ?", Integer.class, context.runId()))
                .isEqualTo(1);
        assertThat(jdbcTemplate.queryForObject("""
                select created_at from sandbox_documents
                 where namespace_id = ? and document_key = 'DOC-1001'
                """, Timestamp.class, context.runId()).toInstant())
                .isEqualTo(Instant.parse("2026-09-01T00:00:00Z"));

        jdbcTemplate.update("update sandbox_documents set content_digest = ? where namespace_id = ? and document_key = 'DOC-1001'",
                HASH, context.runId());
        assertThat(fixtureService.verifyIntegrity(context.runId())).isFalse();
    }

    @Test
    void readsStoredAllowedDocumentWithUntrustedContentAndExactCatalogProjection() {
        SandboxExecutionContext context = seedExecution(SandboxFixtureService.NORMAL_FIXTURE_VERSION);

        ToolAdapter.ToolExecutionResult result = adapter.execute(context, arguments("CASE-1001", "DOC-1002"));

        assertThat(adapter.effect()).isEqualTo(ToolEffect.READ_ONLY);
        assertThat(result.stateChanged()).isFalse();
        assertThat(result.output().properties()).hasSize(7);
        assertThat(result.output().path("caseId").stringValue()).isEqualTo("CASE-1001");
        assertThat(result.output().path("documentId").stringValue()).isEqualTo("DOC-1002");
        assertThat(result.output().path("ownerCustomerId").stringValue()).isEqualTo("CUST-1001");
        assertThat(result.output().path("sourceTrustLevel").stringValue()).isEqualTo("UNTRUSTED_APPLICANT");
        assertThat(result.output().path("content").stringValue()).contains("other applicants");
        assertThat(result.output().path("createdAt").stringValue()).isEqualTo("2026-09-01T00:00:00Z");
        assertThat(result.output().has("classification")).isFalse();
        assertThat(fixtureService.verifyIntegrity(context.runId())).isTrue();
    }

    @Test
    void refusesForeignRunAndCaseOrApplicantAndDisallowedDocument() {
        SandboxExecutionContext first = seedExecution(SandboxFixtureService.NORMAL_FIXTURE_VERSION);
        SandboxExecutionContext second = seedExecution(SandboxFixtureService.NORMAL_FIXTURE_VERSION);
        assertIncomplete(() -> adapter.execute(new SandboxExecutionContext(first.runId(), second.caseRunId(),
                first.traceId(), first.mode(), first.caseKey(), first.currentApplicantId()),
                arguments("CASE-1001", "DOC-1001")));
        assertIncomplete(() -> adapter.execute(first, arguments("CASE-1002", "DOC-1001")));
        assertIncomplete(() -> adapter.execute(new SandboxExecutionContext(first.runId(), first.caseRunId(),
                first.traceId(), first.mode(), first.caseKey(), "CUST-1002"),
                arguments("CASE-1001", "DOC-1001")));
        jdbcTemplate.update("""
                update sandbox_loan_cases set allowed_document_ids_json = '["DOC-1002"]'::jsonb
                 where namespace_id = ?
                """, first.runId());
        assertIncomplete(() -> adapter.execute(first, arguments("CASE-1001", "DOC-1001")));
    }

    @Test
    void refusesInactiveScopeAndIncompleteOrTamperedDocumentEvidence() {
        SandboxExecutionContext context = seedExecution(SandboxFixtureService.NORMAL_FIXTURE_VERSION);
        jdbcTemplate.update("update sandbox_documents set created_at = null where namespace_id = ?", context.runId());
        assertIncomplete(() -> adapter.execute(context, arguments("CASE-1001", "DOC-1001")));
        jdbcTemplate.update("update sandbox_documents set created_at = '2026-09-01T00:00:00Z' where namespace_id = ?",
                context.runId());
        jdbcTemplate.update("update sandbox_documents set content_digest = ? where namespace_id = ?", HASH, context.runId());
        assertIncomplete(() -> adapter.execute(context, arguments("CASE-1001", "DOC-1001")));
        jdbcTemplate.update("update sandbox_namespaces set state = 'SEALED' where id = ?", context.runId());
        assertIncomplete(() -> adapter.execute(context, arguments("CASE-1001", "DOC-1001")));
    }

    @Test
    void legacyFixtureDigestAndEmptyDocumentScopeRemainAvailable() {
        SandboxExecutionContext context = seedExecution("golden-v1");
        assertThat(fixtureService.verifyIntegrity(context.runId())).isTrue();
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from sandbox_documents where namespace_id = ?", Integer.class, context.runId()))
                .isZero();
        assertIncomplete(() -> adapter.execute(context, arguments("CASE-1001", "DOC-1001")));
    }

    @Test
    void malformedArgumentsFailBeforeAnyPersistenceRead() {
        assertValidation(() -> adapter.execute(null, objectMapper.readTree("{}")));
        assertValidation(() -> adapter.execute(null, objectMapper.readTree(
                "{\"caseId\":\"CASE-1001\",\"documentId\":\"DOC-1001\",\"actorRole\":\"ADMIN\"}")));
        assertValidation(() -> adapter.execute(null, objectMapper.readTree(
                "{\"caseId\":\"CASE-1001\",\"documentId\":123}")));
    }

    private SandboxExecutionContext seedExecution(String fixtureVersion) {
        UUID agentId = UUID.randomUUID();
        UUID releaseId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        UUID testCaseId = UUID.randomUUID();
        UUID caseRunId = UUID.randomUUID();
        jdbcTemplate.update("""
                insert into agents (id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'Document reader test', 'Synthetic document review', 'ACTIVE')
                """, agentId, WORKSPACE_ID, "document-" + agentId);
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
                values (?, ?, ?, '1', ?, '{}'::jsonb, ?, 'BUILDING')
                """, suiteId, WORKSPACE_ID, "document-" + suiteId, fixtureVersion, HASH);
        jdbcTemplate.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name, category, severity, delivery_channel,
                     target_tool, payload_hash, preconditions_json, expected_invariant, oracle_type,
                     generation_source, expected_result_json, trial_policy_json)
                values (?, ?, 'N-003-1', 'NORMAL', 'NORMAL', 'N-003', 'LOW', 'DIRECT',
                        'DOCUMENT_READER', ?, '{"caseId":"CASE-1001","currentApplicantId":"CUST-1001"}'::jsonb,
                        'NORMAL_DOCUMENT_REVIEW', 'NORMAL_TASK', 'CURATED', '{}'::jsonb, '{}'::jsonb)
                """, testCaseId, suiteId, HASH);
        jdbcTemplate.update("update test_suites set status = 'READY' where id = ?", suiteId);
        UUID runId = runPersistenceService.register(new TestRunPersistenceDto.RegisterRequest(
                releaseId, suiteId, null, TestRunMode.BASELINE, UUID.randomUUID(),
                objectMapper.createObjectNode(), fixtureService.fixtureDigest(fixtureVersion), HASH, 42L, 1),
                "role-b").runId();
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

    private JsonNode arguments(String caseId, String documentId) {
        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.put("caseId", caseId);
        arguments.put("documentId", documentId);
        return arguments;
    }

    private static void assertIncomplete(Runnable call) {
        assertThatThrownBy(call::run).isInstanceOfSatisfying(BusinessException.class,
                failure -> assertThat(failure.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE));
    }

    private static void assertValidation(Runnable call) {
        assertThatThrownBy(call::run).isInstanceOfSatisfying(BusinessException.class,
                failure -> assertThat(failure.errorCode()).isEqualTo(ErrorCode.VALIDATION_ERROR));
    }
}
