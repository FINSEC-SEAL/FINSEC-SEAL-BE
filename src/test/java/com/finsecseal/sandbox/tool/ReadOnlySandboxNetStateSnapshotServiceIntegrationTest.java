package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.policy.GatewayRuntimeObservations.InvocationKey;
import com.finsecseal.sandbox.SandboxFixtureService;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;

@Testcontainers
@SpringBootTest
class ReadOnlySandboxNetStateSnapshotServiceIntegrationTest {

    private static final String ACTOR = "b-net-state-test";
    private static final String TOOL = "CUSTOMER_DATA_READ";
    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final Duration DEADLINE = Duration.ofSeconds(5);
    private static final List<String> BUSINESS_TABLES = List.of("sandbox_customers",
            "sandbox_loan_cases", "sandbox_documents", "sandbox_loan_policies",
            "sandbox_review_notes", "sandbox_loan_decisions", "sandbox_exfil_events");

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired DataSource dataSource;
    @Autowired PlatformTransactionManager transactions;
    @Autowired JdbcTemplate db;
    @Autowired ObjectMapper json;
    @Autowired TestRunPersistenceService runs;
    @Autowired ExecutionEventService events;
    @Autowired SandboxFixtureService fixtures;
    @Autowired StoredGatewayPreCallScopeSource scopeSource;

    @Test
    void identicalSnapshotsYieldOneReceiptWithoutEventAuditOrBusinessWrites() {
        Seed seed = seed();
        int eventsBefore = eventCount(seed.runId());
        int auditsBefore = auditCount(seed.workspaceId());
        Map<String, String> stateBefore = businessState(seed.runId());
        String timeoutBefore = db.queryForObject("show statement_timeout", String.class);
        var source = source();

        var before = source.captureBefore(seed.key(), DEADLINE);
        var unchanged = source.compareAfter(seed.key(), before, DEADLINE);

        assertThat(before.key()).isEqualTo(seed.key());
        assertThat(before.namespaceId()).isEqualTo(seed.runId());
        assertThat(before.fingerprint()).matches("sha256:[0-9a-f]{64}");
        assertThat(unchanged.fingerprint()).isEqualTo(before.fingerprint());
        assertThat(unchanged.captureId()).isEqualTo(before.captureId());
        assertThat(before.toString()).doesNotContain("CUST-1001", "CASE-1001");
        assertThat(unchanged.toString()).doesNotContain("CUST-1001", "CASE-1001");
        assertThat(eventCount(seed.runId())).isEqualTo(eventsBefore);
        assertThat(auditCount(seed.workspaceId())).isEqualTo(auditsBefore);
        assertThat(businessState(seed.runId())).isEqualTo(stateBefore);
        assertThat(db.queryForObject("show statement_timeout", String.class))
                .isEqualTo(timeoutBefore);
        assertIncomplete(() -> source.compareAfter(seed.key(), before, DEADLINE));
    }

    @Test
    void eachOfSevenBusinessTablesIsIncludedInTheNetFingerprint() {
        List<String> tables = BUSINESS_TABLES;
        for (String table : tables) {
            Seed seed = seed();
            var source = source();
            var before = source.captureBefore(seed.key(), DEADLINE);
            changeBusinessRow(table, seed.runId(), seed.caseRunId());
            assertIncomplete(() -> source.compareAfter(seed.key(), before, DEADLINE));
        }
    }

    @Test
    void anotherNamespaceAndNamespaceMetadataCannotDisappearFromComparison() {
        Seed observed = seed();
        Seed unrelated = seed();
        var source = source();
        var before = source.captureBefore(observed.key(), DEADLINE);
        db.update("""
                update sandbox_customers set row_version = row_version + 1
                 where namespace_id = ? and customer_key = 'CUST-1002'
                """, unrelated.runId());
        assertIncomplete(() -> source.compareAfter(observed.key(), before, DEADLINE));

        Seed metadata = seed();
        var metadataSource = source();
        var metadataBefore = metadataSource.captureBefore(metadata.key(), DEADLINE);
        db.update("update sandbox_namespaces set expires_at = expires_at + interval '1 hour' where id = ?",
                metadata.runId());
        assertIncomplete(() -> metadataSource.compareAfter(metadata.key(), metadataBefore, DEADLINE));
    }

    @Test
    void changingOnlyAPrimaryKeyChangesTheFingerprintAndNeverLeaksTheKey() {
        Seed seed = seed();
        String canary = "PRIVATE-NOTE-KEY-" + UUID.randomUUID();
        db.update("""
                insert into sandbox_review_notes(namespace_id,note_key,case_key,
                    review_result_json,created_by_agent)
                values (?,?,'CASE-1001','{}'::jsonb,'test')
                """, seed.runId(), canary);
        var source = source();
        var before = source.captureBefore(seed.key(), DEADLINE);
        db.update("update sandbox_review_notes set note_key = ? where namespace_id = ? and note_key = ?",
                "MOVED-" + canary, seed.runId(), canary);

        assertThat(before.toString()).doesNotContain(canary);
        assertIncompleteWithout(seed.key(), canary,
                () -> source.compareAfter(seed.key(), before, DEADLINE));
    }

    @Test
    void wrongKeysReceiptsDeadlinesAndCallerTransactionsFailClosed() {
        Seed seed = seed();
        var source = source();
        InvocationKey key = seed.key();
        assertIncomplete(() -> source.captureBefore(new InvocationKey(UUID.randomUUID(),
                key.caseRunId(), key.traceId(), key.toolCallId(), key.requestDigest()), DEADLINE));
        assertIncomplete(() -> source.captureBefore(new InvocationKey(key.runId(),
                key.caseRunId(), key.traceId(), key.toolCallId(), "sha256:" + "b".repeat(64)), DEADLINE));
        assertIncomplete(() -> source.captureBefore(key, Duration.ZERO));
        assertIncomplete(() -> source.captureBefore(key, Duration.ofSeconds(6)));
        assertIncomplete(() -> source().captureBefore(key, Duration.ofMillis(900)));
        assertIncomplete(() -> new TransactionTemplate(transactions).execute(status ->
                source.captureBefore(key, DEADLINE)));

        var before = source.captureBefore(key, DEADLINE);
        var wrong = new ReadOnlySandboxNetStateSnapshotService.CaptureReceipt(key,
                UUID.randomUUID(), before.namespaceId(), before.fingerprint());
        assertIncomplete(() -> source.compareAfter(key, wrong, DEADLINE));
        assertIncomplete(() -> source.captureBefore(key, DEADLINE));
        assertThat(source.compareAfter(key, before, DEADLINE).fingerprint())
                .isEqualTo(before.fingerprint());
    }

    @Test
    void slotCapAndTtlIncludeConsumedAndFailedTombstones() {
        Seed seed = seed();
        AtomicLong clock = new AtomicLong(TimeUnit.SECONDS.toNanos(10));
        var source = new ReadOnlySandboxNetStateSnapshotService(dataSource, transactions,
                scopeSource, clock::get);
        InvocationKey first = seed.key();
        var firstCapture = source.captureBefore(first, DEADLINE);
        source.compareAfter(first, firstCapture, DEADLINE);
        assertIncomplete(() -> source.captureBefore(first, DEADLINE));

        InvocationKey invalid = new InvocationKey(first.runId(), first.caseRunId(),
                first.traceId(), first.toolCallId(), "sha256:" + "b".repeat(64));
        assertIncomplete(() -> source.captureBefore(invalid, DEADLINE));
        assertIncomplete(() -> source.captureBefore(invalid, DEADLINE));

        for (int count = 2; count < ReadOnlySandboxNetStateSnapshotService.MAX_SLOTS; count++) {
            source.captureBefore(anotherProposal(seed), DEADLINE);
        }
        InvocationKey next = anotherProposal(seed);
        assertIncomplete(() -> source.captureBefore(next, DEADLINE));
        clock.addAndGet(ReadOnlySandboxNetStateSnapshotService.TTL_NANOS + 1);
        assertIncomplete(() -> source.compareAfter(first, firstCapture, DEADLINE));
        assertThat(source.captureBefore(next, DEADLINE).key()).isEqualTo(next);
    }

    @Test
    void oversizedRowAndTruncatedScanNeverYieldSuccessfulCapture() {
        Seed large = seed();
        String huge = "x".repeat(ReadOnlySandboxNetStateSnapshotService.MAX_ROW_BYTES + 1);
        try {
            db.update("""
                    insert into sandbox_review_notes(namespace_id,note_key,case_key,
                        review_result_json,created_by_agent)
                    values (?,'OVERSIZE','CASE-1001',jsonb_build_object('body', ?),'test')
                    """, large.runId(), huge);
            assertIncomplete(() -> source().captureBefore(large.key(), DEADLINE));
        } finally {
            db.update("delete from sandbox_review_notes where namespace_id = ? and note_key = 'OVERSIZE'",
                    large.runId());
        }

        Seed many = seed();
        try {
            db.update("""
                    insert into sandbox_review_notes(namespace_id,note_key,case_key,
                        review_result_json,created_by_agent)
                    select ?, 'CAP-' || lpad(g::text, 5, '0'), 'CASE-1001',
                           '{}'::jsonb, 'test'
                      from generate_series(1, ?) g
                    """, many.runId(), ReadOnlySandboxNetStateSnapshotService.MAX_ROWS + 1);
            assertIncomplete(() -> source().captureBefore(many.key(), DEADLINE));
        } finally {
            db.update("delete from sandbox_review_notes where namespace_id = ? and note_key like 'CAP-%'",
                    many.runId());
        }
    }

    @Test
    void blockedDatabaseReadHasFiniteTimeoutAndNoHelperWrites() throws Exception {
        Seed seed = seed();
        int eventsBefore = eventCount(seed.runId());
        int auditsBefore = auditCount(seed.workspaceId());
        try (Connection blocker = DriverManager.getConnection(POSTGRES.getJdbcUrl(),
                POSTGRES.getUsername(), POSTGRES.getPassword())) {
            blocker.setAutoCommit(false);
            try (Statement statement = blocker.createStatement()) {
                statement.execute("lock table sandbox_review_notes in access exclusive mode");
            }
            long started = System.nanoTime();
            assertIncomplete(() -> source().captureBefore(seed.key(), Duration.ofSeconds(3)));
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(6));
            blocker.rollback();
        }
        assertThat(eventCount(seed.runId())).isEqualTo(eventsBefore);
        assertThat(auditCount(seed.workspaceId())).isEqualTo(auditsBefore);
    }

    @Test
    void postCommitDeadlineExpirySuppressesReceiptAndAmbientCompareIsRejected() {
        Seed seed = seed();
        AtomicLong clock = new AtomicLong(TimeUnit.SECONDS.toNanos(10));
        var slow = new ReadOnlySandboxNetStateSnapshotService(dataSource,
                advancingCommitManager(clock), scopeSource, clock::get);
        assertIncomplete(() -> slow.captureBefore(seed.key(), DEADLINE));

        var source = source();
        var before = source.captureBefore(seed.key(), DEADLINE);
        assertIncomplete(() -> new TransactionTemplate(transactions).execute(status ->
                source.compareAfter(seed.key(), before, DEADLINE)));
        assertThat(source.compareAfter(seed.key(), before, DEADLINE).fingerprint())
                .isEqualTo(before.fingerprint());
    }

    private ReadOnlySandboxNetStateSnapshotService source() {
        return new ReadOnlySandboxNetStateSnapshotService(dataSource, transactions, scopeSource);
    }

    private PlatformTransactionManager advancingCommitManager(AtomicLong clock) {
        return new PlatformTransactionManager() {
            @Override public TransactionStatus getTransaction(TransactionDefinition definition) {
                return transactions.getTransaction(definition);
            }
            @Override public void commit(TransactionStatus status) {
                transactions.commit(status);
                clock.addAndGet(TimeUnit.SECONDS.toNanos(6));
            }
            @Override public void rollback(TransactionStatus status) {
                transactions.rollback(status);
            }
        };
    }

    private void changeBusinessRow(String table, UUID runId, UUID caseRunId) {
        switch (table) {
            case "sandbox_customers" -> db.update("""
                    update sandbox_customers set row_version = row_version + 1
                     where namespace_id = ? and customer_key = 'CUST-1001'
                    """, runId);
            case "sandbox_loan_cases" -> db.update("""
                    update sandbox_loan_cases set row_version = row_version + 1
                     where namespace_id = ? and case_key = 'CASE-1001'
                    """, runId);
            case "sandbox_documents" -> db.update("""
                    update sandbox_documents set trust_level = 'TRUSTED_INTERNAL'
                     where namespace_id = ? and document_key = 'DOC-1001'
                    """, runId);
            case "sandbox_loan_policies" -> db.update("""
                    update sandbox_loan_policies set rule_code = 'CHANGED-RULE'
                     where namespace_id = ? and policy_key = 'POLICY-INCOME-01'
                    """, runId);
            case "sandbox_review_notes" -> db.update("""
                    insert into sandbox_review_notes(namespace_id,note_key,case_key,
                        review_result_json,created_by_agent)
                    values (?,'NOTE-CHANGED','CASE-1001','{}'::jsonb,'test')
                    """, runId);
            case "sandbox_loan_decisions" -> db.update("""
                    update sandbox_loan_decisions set row_version = row_version + 1
                     where namespace_id = ? and case_key = 'CASE-1001'
                    """, runId);
            case "sandbox_exfil_events" -> db.update("""
                    insert into sandbox_exfil_events(namespace_id,test_case_run_id,event_key,
                        url_label,body_redacted,sensitive_token_hashes_json,received_at)
                    values (?,?,?,'blocked-label','{}'::jsonb,'[]'::jsonb,now())
                    """, runId, caseRunId, UUID.randomUUID());
            default -> throw new AssertionError(table);
        }
    }

    private InvocationKey anotherProposal(Seed seed) {
        var args = json.createObjectNode();
        args.putArray("customerIds").add("CUST-1001");
        args.putArray("fields").add("incomeBand");
        ExecutionEventDto.Event proposal = events.append(seed.runId(),
                new ExecutionEventDto.AppendRequest(seed.caseRunId(), seed.traceId(),
                        ExecutionEventType.TOOL_PROPOSED, TOOL, args, null, null,
                        "STRUCTURED_TOOL_PROPOSAL", json.createObjectNode()), ACTOR);
        return new InvocationKey(seed.runId(), seed.caseRunId(), seed.traceId(),
                proposal.eventId(), proposal.payloadDigest());
    }

    private Seed seed() {
        UUID workspace = UUID.randomUUID(), agent = UUID.randomUUID(), release = UUID.randomUUID();
        UUID suite = UUID.randomUUID(), testCase = UUID.randomUUID(), trace = UUID.randomUUID();
        db.update("insert into workspaces(id,name,mode) values (?,?, 'DEMO')",
                workspace, "B net state " + workspace);
        db.update("""
                insert into agents(id,workspace_id,agent_key,name,purpose_summary,status)
                values (?,?,?,'B net state','Synthetic review','ACTIVE')
                """, agent, workspace, "b-net-state-" + agent);
        db.update("""
                insert into agent_releases(id,agent_id,version,business_purpose,manifest_schema_version,
                    manifest_json,agent_artifact_fingerprint,release_fingerprint,lifecycle_state,effective_status)
                values (?,?,'1.0','LOAN_DOCUMENT_COMPLETENESS_REVIEW','1.0',
                    '{}'::jsonb,?,?,'ANALYZED','ANALYZED')
                """, release, agent, HASH, HASH);
        db.update("""
                insert into test_suites(id,workspace_id,suite_key,version,fixture_version,
                    generation_config_json,suite_hash,status)
                values (?,?,?,'1.0','golden-v2','{}'::jsonb,?,'BUILDING')
                """, suite, workspace, "b-net-state-suite-" + suite, HASH);
        db.update("""
                insert into test_cases(id,suite_id,case_key,case_type,partition_name,category,
                    severity,delivery_channel,target_tool,payload_hash,preconditions_json,
                    expected_invariant,oracle_type,generation_source,expected_result_json,trial_policy_json)
                values (?,?,'NORMAL-1','NORMAL','NORMAL','NORMAL','LOW','DIRECT',
                    'CUSTOMER_DATA_READ',?,'{"caseId":"CASE-1001","currentApplicantId":"CUST-1001"}'::jsonb,
                    'INV-NORMAL','NORMAL_TASK','CURATED','{}'::jsonb,'{}'::jsonb)
                """, testCase, suite, HASH);
        db.update("update test_suites set status = 'READY' where id = ?", suite);
        UUID run = runs.register(new TestRunPersistenceDto.RegisterRequest(
                release, suite, null, TestRunMode.BASELINE, UUID.randomUUID(),
                json.createObjectNode(), fixtures.fixtureDigest("golden-v2"), HASH, 42L, 1), ACTOR).runId();
        events.append(run, new ExecutionEventDto.AppendRequest(null, trace,
                ExecutionEventType.RUN_STARTED, null, null, null, null,
                "NET_STATE_TEST", json.createObjectNode()), ACTOR);
        runs.updateStatus(run, new TestRunPersistenceDto.StatusRequest(
                TestRunStatus.PREPARING, 0, 0, null), ACTOR);
        fixtures.createOrReset(run);
        runs.updateStatus(run, new TestRunPersistenceDto.StatusRequest(
                TestRunStatus.RUNNING, 0, 0, null), ACTOR);
        UUID caseRun = runs.registerCase(run,
                new TestRunPersistenceDto.CaseRunRegisterRequest(testCase, 0, HASH), ACTOR).id();
        runs.updateCaseStatus(run, caseRun, new TestRunPersistenceDto.CaseRunStatusRequest(
                TestCaseRunStatus.EXECUTING, null, null, null, null, null, null), ACTOR);
        var args = json.createObjectNode();
        args.putArray("customerIds").add("CUST-1001");
        args.putArray("fields").add("incomeBand");
        ExecutionEventDto.Event proposal = events.append(run,
                new ExecutionEventDto.AppendRequest(caseRun, trace, ExecutionEventType.TOOL_PROPOSED,
                        TOOL, args, null, null, "STRUCTURED_TOOL_PROPOSAL",
                        json.createObjectNode()), ACTOR);
        return new Seed(workspace, run, caseRun, trace,
                new InvocationKey(run, caseRun, trace, proposal.eventId(), proposal.payloadDigest()));
    }

    private int eventCount(UUID runId) {
        return db.queryForObject("select count(*) from execution_events where run_id = ?",
                Integer.class, runId);
    }

    private int auditCount(UUID workspaceId) {
        return db.queryForObject("select count(*) from audit_records where workspace_id = ?",
                Integer.class, workspaceId);
    }

    private Map<String, String> businessState(UUID runId) {
        Map<String, String> values = new LinkedHashMap<>();
        for (String table : BUSINESS_TABLES) {
            values.put(table, db.queryForObject("select coalesce(jsonb_agg(to_jsonb(t) "
                    + "order by to_jsonb(t)::text)::text, '[]') from " + table
                    + " t where namespace_id = ?", String.class, runId));
        }
        return Map.copyOf(values);
    }

    private static void assertIncomplete(org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).isInstanceOf(BusinessException.class)
                .satisfies(error -> assertThat(((BusinessException) error).errorCode())
                        .isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE))
                .hasMessage("Sandbox net-state observation is incomplete")
                .hasNoCause();
    }

    private static void assertIncompleteWithout(InvocationKey key, String privateValue,
            org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).isInstanceOf(BusinessException.class)
                .hasMessage("Sandbox net-state observation is incomplete")
                .satisfies(error -> assertThat(error.getMessage())
                        .doesNotContain(privateValue, key.toolCallId().toString()))
                .hasNoCause();
    }

    private record Seed(UUID workspaceId, UUID runId, UUID caseRunId, UUID traceId,
            InvocationKey key) { }
}
