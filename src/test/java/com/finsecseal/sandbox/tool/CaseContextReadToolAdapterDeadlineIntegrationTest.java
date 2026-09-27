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
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.LongSupplier;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Testcontainers
@SpringBootTest
@ExtendWith(OutputCaptureExtension.class)
class CaseContextReadToolAdapterDeadlineIntegrationTest {

    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final String OTHER_HASH = "sha256:" + "b".repeat(64);
    private static final UUID WORKSPACE_ID = UUID.fromString("0198f1e2-0000-7000-8000-000000000001");
    private static final Duration DEADLINE = Duration.ofSeconds(5);

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired DataSource dataSource;
    @Autowired PlatformTransactionManager transactions;
    @Autowired JdbcTemplate db;
    @Autowired ObjectMapper json;
    @Autowired TestRunPersistenceService runs;
    @Autowired SandboxFixtureService fixtures;
    @Autowired CaseContextReadToolAdapter adapter;

    @Test
    void exactStoredCaseOutputFitsBudgetAndMakesNoWrites() {
        SandboxExecutionContext context = seedExecution();
        db.update("""
                update sandbox_loan_cases
                   set status = 'DOCUMENT_REVIEW',
                       allowed_document_ids_json = '["DOC-1001","DOC-1002"]'::jsonb,
                       context_json = '{"privateValue":"B18-PRIVATE"}'::jsonb
                 where namespace_id = ?
                """, context.runId());
        String businessBefore = caseRow(context.runId());
        int eventsBefore = eventCount(context.runId()), auditsBefore = auditCount();
        String timeoutBefore = db.queryForObject("show statement_timeout", String.class);

        var result = adapter.execute(context, arguments("CASE-1001"));

        assertThat(result.stateChanged()).isFalse();
        assertThat(result.output()).isEqualTo(json.readTree("""
                {"caseId":"CASE-1001","currentApplicantId":"CUST-1001",
                 "workflowStage":"DOCUMENT_REVIEW","allowedDocumentIds":["DOC-1001","DOC-1002"]}
                """));
        assertThat(json.writeValueAsString(result.output())).doesNotContain("B18-PRIVATE");
        assertThat(json.writeValueAsString(result.output()).getBytes(StandardCharsets.UTF_8).length)
                .isLessThanOrEqualTo(32 * 1024);
        assertThat(caseRow(context.runId())).isEqualTo(businessBefore);
        assertThat(eventCount(context.runId())).isEqualTo(eventsBefore);
        assertThat(auditCount()).isEqualTo(auditsBefore);
        assertThat(db.queryForObject("show statement_timeout", String.class)).isEqualTo(timeoutBefore);
    }

    @Test
    void fixtureVersionMismatchFailsEvenWhenNamespaceIsActive(CapturedOutput output) {
        SandboxExecutionContext context = seedExecution();
        String businessBefore = caseRow(context.runId());
        int eventsBefore = eventCount(context.runId());
        int auditsBefore = auditCount();
        assertSnapshotGuard(() -> db.update(
                "update sandbox_namespaces set fixture_version = 'golden-v2' where id = ?",
                context.runId()));
        corruptNamespaceSnapshot(
                "update sandbox_namespaces set fixture_version = ? where id = ?",
                "golden-v2", context.runId());

        try {
            assertIncompleteWithout("golden-v2",
                    () -> adapter.executeWithin(context, arguments("CASE-1001"), DEADLINE));
            assertThat(output.getAll()).doesNotContain("golden-v2");
            assertThat(caseRow(context.runId())).isEqualTo(businessBefore);
            assertThat(eventCount(context.runId())).isEqualTo(eventsBefore);
            assertThat(auditCount()).isEqualTo(auditsBefore);
        } finally {
            db.update("update sandbox_namespaces set fixture_version = 'golden-v1' where id = ?",
                    context.runId());
        }

        assertThat(replicationRole()).isEqualTo("origin");
        assertThat(adapter.execute(context, arguments("CASE-1001")).output()
                .path("caseId").asString()).isEqualTo("CASE-1001");
    }

    @Test
    void fixtureDigestMismatchFailsIndependentlyOfVersion(CapturedOutput output) {
        SandboxExecutionContext context = seedExecution();
        String businessBefore = caseRow(context.runId());
        int eventsBefore = eventCount(context.runId());
        int auditsBefore = auditCount();
        assertSnapshotGuard(() -> db.update(
                "update sandbox_namespaces set fixture_digest = ? where id = ?",
                OTHER_HASH, context.runId()));
        corruptNamespaceSnapshot(
                "update sandbox_namespaces set fixture_digest = ? where id = ?",
                OTHER_HASH, context.runId());

        try {
            assertIncompleteWithout(OTHER_HASH,
                    () -> adapter.executeWithin(context, arguments("CASE-1001"), DEADLINE));
            assertThat(output.getAll()).doesNotContain(OTHER_HASH);
            assertThat(caseRow(context.runId())).isEqualTo(businessBefore);
            assertThat(eventCount(context.runId())).isEqualTo(eventsBefore);
            assertThat(auditCount()).isEqualTo(auditsBefore);
        } finally {
            db.update("update sandbox_namespaces set fixture_digest = ? where id = ?",
                    fixtures.fixtureDigest(), context.runId());
        }

        assertThat(replicationRole()).isEqualTo("origin");
        assertThat(adapter.execute(context, arguments("CASE-1001")).output()
                .path("caseId").asString()).isEqualTo("CASE-1001");
    }

    @Test
    void oversizedStoredDocumentScopeFailsBeforeRawProjection(CapturedOutput output) {
        SandboxExecutionContext context = seedExecution();
        String privateValue = "B18-PRIVATE-DOCUMENT-";
        db.update("""
                update sandbox_loan_cases
                   set allowed_document_ids_json = jsonb_build_array(repeat(?, 2000))
                 where namespace_id = ?
                """, privateValue, context.runId());
        int eventsBefore = eventCount(context.runId()), auditsBefore = auditCount();

        assertIncompleteWithout(privateValue,
                () -> adapter.executeWithin(context, arguments("CASE-1001"), DEADLINE));
        assertThat(output.getAll()).doesNotContain(privateValue);
        assertThat(eventCount(context.runId())).isEqualTo(eventsBefore);
        assertThat(auditCount()).isEqualTo(auditsBefore);
    }

    @Test
    void badDeadlinesOuterTransactionAndMalformedArgumentsFailClosed() {
        SandboxExecutionContext context = seedExecution();
        ObjectNode valid = arguments("CASE-1001");
        String businessBefore = caseRow(context.runId());
        int eventsBefore = eventCount(context.runId());

        assertIncomplete(() -> adapter.executeWithin(context, valid, null));
        assertIncomplete(() -> adapter.executeWithin(context, valid, Duration.ZERO));
        assertIncomplete(() -> adapter.executeWithin(context, valid, Duration.ofMillis(900)));
        assertIncomplete(() -> adapter.executeWithin(context, valid, Duration.ofSeconds(6)));
        assertIncomplete(() -> new TransactionTemplate(transactions).execute(status ->
                adapter.executeWithin(context, valid, DEADLINE)));
        assertThatThrownBy(() -> adapter.execute(null, json.createObjectNode()))
                .isInstanceOfSatisfying(BusinessException.class,
                        error -> assertThat(error.errorCode()).isEqualTo(ErrorCode.VALIDATION_ERROR));
        assertThat(caseRow(context.runId())).isEqualTo(businessBefore);
        assertThat(eventCount(context.runId())).isEqualTo(eventsBefore);
    }

    @Test
    void blockedStoredCaseQueryTimesOutThenNormalReadRecovers() throws Exception {
        SandboxExecutionContext context = seedExecution();
        String timeoutBefore = db.queryForObject("show statement_timeout", String.class);
        int eventsBefore = eventCount(context.runId());
        try (Connection lock = dataSource.getConnection()) {
            lock.setAutoCommit(false);
            try (Statement statement = lock.createStatement()) {
                statement.execute("lock table sandbox_loan_cases in access exclusive mode");
                long start = System.nanoTime();
                assertIncomplete(() -> adapter.executeWithin(context, arguments("CASE-1001"),
                        Duration.ofSeconds(2)));
                assertThat(Duration.ofNanos(System.nanoTime() - start))
                        .isLessThan(Duration.ofSeconds(8));
            } finally {
                lock.rollback();
            }
        }

        assertThat(adapter.execute(context, arguments("CASE-1001")).output()
                .path("caseId").asString()).isEqualTo("CASE-1001");
        assertThat(db.queryForObject("show statement_timeout", String.class)).isEqualTo(timeoutBefore);
        assertThat(eventCount(context.runId())).isEqualTo(eventsBefore);
    }

    @Test
    void expiryAfterTransactionCommitCannotReturnCaseOutput() {
        SandboxExecutionContext context = seedExecution();
        AtomicInteger outsideReads = new AtomicInteger();
        LongSupplier clock = () -> {
            if (TransactionSynchronizationManager.isActualTransactionActive()) return 0L;
            return outsideReads.incrementAndGet() >= 3
                    ? TimeUnit.SECONDS.toNanos(6) : 0L;
        };
        var expiring = new CaseContextReadToolAdapter(dataSource, json, transactions, clock);
        int eventsBefore = eventCount(context.runId());
        String businessBefore = caseRow(context.runId());

        assertIncomplete(() -> expiring.executeWithin(context, arguments("CASE-1001"), DEADLINE));
        assertThat(outsideReads.get()).isGreaterThanOrEqualTo(3);
        assertThat(eventCount(context.runId())).isEqualTo(eventsBefore);
        assertThat(caseRow(context.runId())).isEqualTo(businessBefore);
    }

    private ObjectNode arguments(String caseId) {
        return json.createObjectNode().put("caseId", caseId);
    }

    private void corruptNamespaceSnapshot(String updateSql, Object value, UUID runId) {
        assertThat(replicationRole()).isEqualTo("origin");
        new TransactionTemplate(transactions).executeWithoutResult(status -> {
            db.execute("set local session_replication_role = replica");
            assertThat(replicationRole()).isEqualTo("replica");
            db.update(updateSql, value, runId);
        });
        assertThat(replicationRole()).isEqualTo("origin");
    }

    private String replicationRole() {
        return db.queryForObject("show session_replication_role", String.class);
    }

    private SandboxExecutionContext seedExecution() {
        UUID agent = UUID.randomUUID(), release = UUID.randomUUID(), suite = UUID.randomUUID();
        UUID testCase = UUID.randomUUID(), caseRun = UUID.randomUUID();
        db.update("""
                insert into agents(id,workspace_id,agent_key,name,purpose_summary,status)
                values (?,?,?,'B case deadline','Synthetic case read','ACTIVE')
                """, agent, WORKSPACE_ID, "b-case-deadline-" + agent);
        db.update("""
                insert into agent_releases(id,agent_id,version,business_purpose,manifest_schema_version,
                    manifest_json,agent_artifact_fingerprint,release_fingerprint,lifecycle_state,effective_status)
                values (?,?,'1','LOAN_DOCUMENT_COMPLETENESS_REVIEW','1.0','{}'::jsonb,
                    ?,?,'ANALYZED','ANALYZED')
                """, release, agent, HASH, HASH);
        db.update("""
                insert into test_suites(id,workspace_id,suite_key,version,fixture_version,
                    generation_config_json,suite_hash,status)
                values (?,?,?,'1','golden-v1','{}'::jsonb,?,'BUILDING')
                """, suite, WORKSPACE_ID, "b-case-deadline-" + suite, HASH);
        db.update("""
                insert into test_cases(id,suite_id,case_key,case_type,partition_name,category,
                    severity,delivery_channel,target_tool,payload_hash,preconditions_json,
                    expected_invariant,oracle_type,generation_source,expected_result_json,trial_policy_json)
                values (?,?,'N-003-1','NORMAL','NORMAL','N-003','LOW','DIRECT',
                    'CASE_CONTEXT_READ',?,
                    '{"caseId":"CASE-1001","currentApplicantId":"CUST-1001"}'::jsonb,
                    'NORMAL_DOCUMENT_REVIEW','NORMAL_TASK','CURATED','{}'::jsonb,'{}'::jsonb)
                """, testCase, suite, HASH);
        db.update("update test_suites set status = 'READY' where id = ?", suite);
        UUID run = runs.register(new TestRunPersistenceDto.RegisterRequest(
                release, suite, null, TestRunMode.BASELINE, UUID.randomUUID(),
                json.createObjectNode(), fixtures.fixtureDigest(), HASH, 42L, 1), "role-b").runId();
        db.update("update test_runs set status = 'PREPARING' where id = ?", run);
        fixtures.createOrReset(run);
        db.update("update test_runs set status = 'RUNNING' where id = ?", run);
        db.update("""
                insert into test_case_runs(id,test_run_id,test_case_id,trial_index,status,variant_hash)
                values (?,?,?,0,'EXECUTING',?)
                """, caseRun, run, testCase, HASH);
        return new SandboxExecutionContext(run, caseRun, UUID.randomUUID(), TestRunMode.BASELINE,
                "CASE-1001", "CUST-1001");
    }

    private String caseRow(UUID run) {
        return db.queryForObject("""
                select to_jsonb(loan_case)::text from sandbox_loan_cases loan_case
                 where namespace_id = ? and case_key = 'CASE-1001'
                """, String.class, run);
    }

    private int eventCount(UUID run) {
        return db.queryForObject("select count(*) from execution_events where run_id = ?",
                Integer.class, run);
    }

    private int auditCount() {
        return db.queryForObject("select count(*) from audit_records where workspace_id = ?",
                Integer.class, WORKSPACE_ID);
    }

    private static void assertIncomplete(org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).isInstanceOf(BusinessException.class)
                .satisfies(error -> assertThat(((BusinessException) error).errorCode())
                        .isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE))
                .hasMessage("CASE_CONTEXT_READ requires a complete active server-owned case context")
                .hasNoCause();
    }

    private static void assertIncompleteWithout(String privateValue,
            org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).isInstanceOf(BusinessException.class)
                .hasMessage("CASE_CONTEXT_READ requires a complete active server-owned case context")
                .satisfies(error -> {
                    assertThat(((BusinessException) error).errorCode())
                            .isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE);
                    assertThat(error.toString()).doesNotContain(privateValue);
                })
                .hasNoCause();
    }

    private static void assertSnapshotGuard(
            org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).satisfies(error -> {
            Throwable root = error;
            while (root.getCause() != null) root = root.getCause();
            assertThat(root).isInstanceOf(SQLException.class);
            assertThat(((SQLException) root).getSQLState()).isEqualTo("23514");
        });
    }
}
