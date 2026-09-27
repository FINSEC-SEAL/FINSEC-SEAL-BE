package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

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
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;

@Testcontainers
@SpringBootTest
@ExtendWith(OutputCaptureExtension.class)
class StoredGatewayCustomerClassificationFactsSourceIntegrationTest {

    private static final String ACTOR = "b-gateway-customer-classification-test";
    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final String OTHER_HASH = "sha256:" + "b".repeat(64);
    private static final String CUSTOMER = CustomerDataReadToolAdapter.TOOL_NAME;
    private static final String CUSTOMER_ID = "CUST-1001";
    private static final String CASE_ID = "CASE-1001";
    private static final String FAILURE = "Stored Gateway customer classification facts are incomplete";
    private static final List<String> SANDBOX_TABLES = List.of(
            "sandbox_namespaces", "sandbox_customers", "sandbox_loan_cases",
            "sandbox_documents", "sandbox_loan_policies", "sandbox_review_notes",
            "sandbox_loan_decisions", "sandbox_exfil_events");

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired DataSource dataSource;
    @Autowired JdbcTemplate db;
    @Autowired ObjectMapper json;
    @Autowired PlatformTransactionManager transactions;
    @Autowired TestRunPersistenceService runs;
    @Autowired ExecutionEventService events;
    @Autowired SandboxFixtureService fixtures;
    @Autowired StoredGatewayPreCallScopeSource scopes;
    @MockitoSpyBean CustomerDataReadToolAdapter adapter;

    @Test
    void storedSetsAreImmutablePartialFactsWithNoRawProfileOrWrite(CapturedOutput output) {
        Seed seed = seed(CUSTOMER, CASE_ID, CUSTOMER_ID);
        String secret = db.queryForObject("""
                select profile_json ->> 'accountNumber' from sandbox_customers
                 where namespace_id = ? and customer_key = ?
                """, String.class, seed.runId(), CUSTOMER_ID);
        Map<String, String> before = sandboxState(seed.runId());
        int eventsBefore = eventCount(seed.runId());
        int auditsBefore = auditCount(seed.workspaceId());
        clearInvocations(adapter);

        var facts = inReadOnlyTransaction(() -> {
            String timeout = db.queryForObject("show statement_timeout", String.class);
            var observed = source().resolve(seed.key(), Duration.ofSeconds(5));
            assertThat(db.queryForObject("show statement_timeout", String.class)).isEqualTo(timeout);
            return observed;
        });

        assertThat(facts.key()).isEqualTo(seed.key());
        assertThat(facts.namespaceId()).isEqualTo(seed.runId());
        assertThat(facts.customerKey()).isEqualTo(CUSTOMER_ID);
        assertThat(facts.sensitiveFields()).containsExactly("accountNumber");
        assertThat(facts.criticalFields()).containsExactly("accountNumber");
        assertThat(facts.syntheticOnly()).isTrue();
        assertThat(facts.toString()).isEqualTo("StoredGatewayCustomerClassificationFacts[partial]")
                .doesNotContain(CUSTOMER_ID, "accountNumber", secret);
        assertThatThrownBy(() -> facts.sensitiveFields().add("incomeBand"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(output.getAll()).doesNotContain(secret);
        assertNoAdapterExecution();
        assertUnchanged(seed, before, eventsBefore, auditsBefore);
    }

    @Test
    void mismatchedInvocationKeyAndOtherToolCannotBorrowCustomerFacts() {
        Seed seed = seed(CUSTOMER, CASE_ID, CUSTOMER_ID);
        Seed otherTool = seed("LOAN_POLICY_SEARCH", CASE_ID, CUSTOMER_ID);
        Seed foreign = seed(CUSTOMER, CASE_ID, CUSTOMER_ID);
        InvocationKey key = seed.key();
        List<InvocationKey> mismatches = List.of(
                new InvocationKey(UUID.randomUUID(), key.caseRunId(), key.traceId(),
                        key.toolCallId(), key.requestDigest()),
                new InvocationKey(key.runId(), UUID.randomUUID(), key.traceId(),
                        key.toolCallId(), key.requestDigest()),
                new InvocationKey(key.runId(), key.caseRunId(), UUID.randomUUID(),
                        key.toolCallId(), key.requestDigest()),
                new InvocationKey(key.runId(), key.caseRunId(), key.traceId(),
                        UUID.randomUUID(), key.requestDigest()),
                new InvocationKey(key.runId(), key.caseRunId(), key.traceId(),
                        key.toolCallId(), OTHER_HASH));
        clearInvocations(adapter);
        for (InvocationKey wrong : mismatches) {
            assertIncomplete(() -> inReadOnlyTransaction(() ->
                    source().resolve(wrong, Duration.ofSeconds(5))));
        }
        assertIncomplete(() -> inReadOnlyTransaction(() ->
                source().resolve(otherTool.key(), Duration.ofSeconds(5))));
        assertIncomplete(() -> inReadOnlyTransaction(() -> source().resolve(
                new InvocationKey(foreign.runId(), foreign.caseRunId(), key.traceId(),
                        key.toolCallId(), key.requestDigest()), Duration.ofSeconds(5))));
        assertNoAdapterExecution();
        assertNoToolEffects(seed);
    }

    @Test
    void wrongCaseApplicantAndInactiveNamespaceFailClosed() {
        Seed wrongCase = seed(CUSTOMER, "CASE-FOREIGN", CUSTOMER_ID);
        Seed wrongApplicant = seed(CUSTOMER, CASE_ID, "CUST-FOREIGN");
        assertIncomplete(() -> inReadOnlyTransaction(() ->
                source().resolve(wrongCase.key(), Duration.ofSeconds(5))));
        assertIncomplete(() -> inReadOnlyTransaction(() ->
                source().resolve(wrongApplicant.key(), Duration.ofSeconds(5))));

        Seed sealed = seed(CUSTOMER, CASE_ID, CUSTOMER_ID);
        db.update("update sandbox_namespaces set state = 'SEALED' where id = ?", sealed.runId());
        assertIncomplete(() -> inReadOnlyTransaction(() ->
                source().resolve(sealed.key(), Duration.ofSeconds(5))));
        Seed expired = seed(CUSTOMER, CASE_ID, CUSTOMER_ID);
        db.update("update sandbox_namespaces set expires_at = now() - interval '1 second' where id = ?",
                expired.runId());
        assertIncomplete(() -> inReadOnlyTransaction(() ->
                source().resolve(expired.key(), Duration.ofSeconds(5))));
        assertNoToolEffects(sealed);
        assertNoToolEffects(expired);
    }

    @Test
    void namespaceFixtureVersionAndDigestMustMatchRun() {
        Seed version = seed(CUSTOMER, CASE_ID, CUSTOMER_ID);
        corruptNamespace("update sandbox_namespaces set fixture_version = ? where id = ?",
                "golden-v1", version.runId());
        try {
            assertIncomplete(() -> inReadOnlyTransaction(() ->
                    source().resolve(version.key(), Duration.ofSeconds(5))));
        } finally {
            db.update("update sandbox_namespaces set fixture_version = ? where id = ?",
                    SandboxFixtureService.NORMAL_FIXTURE_VERSION, version.runId());
        }
        Seed digest = seed(CUSTOMER, CASE_ID, CUSTOMER_ID);
        corruptNamespace("update sandbox_namespaces set fixture_digest = ? where id = ?",
                OTHER_HASH, digest.runId());
        try {
            assertIncomplete(() -> inReadOnlyTransaction(() ->
                    source().resolve(digest.key(), Duration.ofSeconds(5))));
        } finally {
            db.update("update sandbox_namespaces set fixture_digest = ? where id = ?",
                    fixtures.fixtureDigest(SandboxFixtureService.NORMAL_FIXTURE_VERSION), digest.runId());
        }
        assertThat(db.queryForObject("show session_replication_role", String.class)).isEqualTo("origin");
        assertNoAdapterExecution();
    }

    @Test
    void malformedLabelsAndMissingProfileKeyNeverBecomeSensitivityFacts() {
        Seed seed = seed(CUSTOMER, CASE_ID, CUSTOMER_ID);
        List<String> invalid = List.of(
                "[]",
                "{}",
                "{\"sensitiveFields\":[\"accountNumber\"],\"criticalFields\":[\"accountNumber\"]}",
                "{\"sensitiveFields\":[\"accountNumber\"],\"criticalFields\":[\"accountNumber\"],\"syntheticOnly\":false}",
                "{\"sensitiveFields\":[\"accountNumber\",\"accountNumber\"],\"criticalFields\":[\"accountNumber\"],\"syntheticOnly\":true}",
                "{\"sensitiveFields\":[\"incomeBand\"],\"criticalFields\":[\"accountNumber\"],\"syntheticOnly\":true}",
                "{\"sensitiveFields\":[\"missingField\"],\"criticalFields\":[],\"syntheticOnly\":true}",
                "{\"sensitiveFields\":[\"bad field\"],\"criticalFields\":[],\"syntheticOnly\":true}",
                "{\"sensitiveFields\":\"accountNumber\",\"criticalFields\":[],\"syntheticOnly\":true}",
                "{\"sensitiveFields\":[\"accountNumber\"],\"criticalFields\":[\"accountNumber\"],\"syntheticOnly\":true,\"unknown\":1}");
        int eventsBefore = eventCount(seed.runId());
        int auditsBefore = auditCount(seed.workspaceId());
        for (String labels : invalid) {
            db.update("update sandbox_customers set classification_json = ?::jsonb where namespace_id = ? and customer_key = ?",
                    labels, seed.runId(), CUSTOMER_ID);
            assertIncomplete(() -> inReadOnlyTransaction(() ->
                    source().resolve(seed.key(), Duration.ofSeconds(5))));
        }
        assertThat(eventCount(seed.runId())).isEqualTo(eventsBefore);
        assertThat(auditCount(seed.workspaceId())).isEqualTo(auditsBefore);
        assertNoToolEffects(seed);
    }

    @Test
    void oversizedLabelsAndProfileFailWithoutRawValueLeak(CapturedOutput output) {
        Seed seed = seed(CUSTOMER, CASE_ID, CUSTOMER_ID);
        String secret = "CUSTOMER-PROFILE-SECRET-SENTINEL";
        String oversizedLabels = "{\"sensitiveFields\":[],\"criticalFields\":[],\"syntheticOnly\":true,\"pad\":\""
                + "X".repeat(5_000) + "\"}";
        db.update("update sandbox_customers set classification_json = ?::jsonb where namespace_id = ? and customer_key = ?",
                oversizedLabels, seed.runId(), CUSTOMER_ID);
        assertIncomplete(() -> inReadOnlyTransaction(() ->
                source().resolve(seed.key(), Duration.ofSeconds(5))));
        restoreLabels(seed);

        db.update("update sandbox_customers set profile_json = '[]'::jsonb where namespace_id = ? and customer_key = ?",
                seed.runId(), CUSTOMER_ID);
        assertIncomplete(() -> inReadOnlyTransaction(() ->
                source().resolve(seed.key(), Duration.ofSeconds(5))));
        db.update("update sandbox_customers set profile_json = ?::jsonb where namespace_id = ? and customer_key = ?",
                "{\"accountNumber\":\"" + secret + "Y".repeat(33_000) + "\"}", seed.runId(), CUSTOMER_ID);
        assertIncomplete(() -> inReadOnlyTransaction(() ->
                source().resolve(seed.key(), Duration.ofSeconds(5))));
        assertThat(output.getAll()).doesNotContain(secret);
        assertNoAdapterExecution();
        assertNoToolEffects(seed);
    }

    @Test
    void transactionAndBudgetMustBeBoundReadOnlyRepeatableRead() {
        Seed seed = seed(CUSTOMER, CASE_ID, CUSTOMER_ID);
        assertIncomplete(() -> source().resolve(seed.key(), Duration.ofSeconds(5)));
        TransactionTemplate readCommitted = new TransactionTemplate(transactions);
        readCommitted.setReadOnly(true);
        readCommitted.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
        assertIncomplete(() -> readCommitted.execute(status ->
                source().resolve(seed.key(), Duration.ofSeconds(5))));
        TransactionTemplate writable = new TransactionTemplate(transactions);
        writable.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        assertIncomplete(() -> writable.execute(status ->
                source().resolve(seed.key(), Duration.ofSeconds(5))));
        assertIncomplete(() -> inReadOnlyTransaction(() ->
                new StoredGatewayCustomerClassificationFactsSource(
                        org.mockito.Mockito.mock(DataSource.class), scopes, json)
                        .resolve(seed.key(), Duration.ofSeconds(5))));
        assertIncomplete(() -> inReadOnlyTransaction(() -> source().resolve(seed.key(), null)));
        for (Duration invalid : List.of(Duration.ZERO, Duration.ofSeconds(-1),
                Duration.ofSeconds(6), Duration.ofMillis(900))) {
            assertIncomplete(() -> inReadOnlyTransaction(() -> source().resolve(seed.key(), invalid)));
        }
        assertNoToolEffects(seed);
    }

    @Test
    void monotonicExpiryAfterStoredScopeReturnsNoFacts() {
        Seed seed = seed(CUSTOMER, CASE_ID, CUSTOMER_ID);
        long budget = Duration.ofSeconds(5).toNanos();
        AtomicInteger ticks = new AtomicInteger();
        long[] times = {0, 0, budget};
        var expiring = new StoredGatewayCustomerClassificationFactsSource(dataSource, scopes, json,
                () -> times[Math.min(ticks.getAndIncrement(), times.length - 1)]);
        int eventsBefore = eventCount(seed.runId());
        assertIncomplete(() -> inReadOnlyTransaction(() ->
                expiring.resolve(seed.key(), Duration.ofSeconds(5))));
        assertThat(ticks.get()).isGreaterThanOrEqualTo(3);
        assertThat(eventCount(seed.runId())).isEqualTo(eventsBefore);
        assertNoAdapterExecution();
    }

    @Test
    void lockedPostgresReadExpiresAndLeavesEightTablesUnchanged() throws SQLException {
        Seed seed = seed(CUSTOMER, CASE_ID, CUSTOMER_ID);
        Map<String, String> before = sandboxState(seed.runId());
        int eventsBefore = eventCount(seed.runId());
        int auditsBefore = auditCount(seed.workspaceId());
        clearInvocations(adapter);
        try (Connection blocker = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())) {
            blocker.setAutoCommit(false);
            try (Statement lock = blocker.createStatement()) {
                lock.execute("lock table sandbox_customers in access exclusive mode");
            }
            long started = System.nanoTime();
            assertIncomplete(() -> inReadOnlyTransaction(() ->
                    source().resolve(seed.key(), Duration.ofSeconds(2))));
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(5));
            blocker.rollback();
        }
        assertNoAdapterExecution();
        assertUnchanged(seed, before, eventsBefore, auditsBefore);
        assertThat(inReadOnlyTransaction(() -> source().resolve(seed.key(), Duration.ofSeconds(5)))
                .sensitiveFields()).containsExactly("accountNumber");
    }

    private StoredGatewayCustomerClassificationFactsSource source() {
        return new StoredGatewayCustomerClassificationFactsSource(dataSource, scopes, json);
    }

    private <T> T inReadOnlyTransaction(Supplier<T> action) {
        TransactionTemplate tx = new TransactionTemplate(transactions);
        tx.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        tx.setReadOnly(true);
        return tx.execute(status -> action.get());
    }

    private Seed seed(String toolName, String caseId, String applicantId) {
        UUID workspace = UUID.randomUUID(), agent = UUID.randomUUID(), release = UUID.randomUUID();
        UUID suite = UUID.randomUUID(), testCase = UUID.randomUUID(), trace = UUID.randomUUID();
        db.update("insert into workspaces(id,name,mode) values (?,?, 'DEMO')",
                workspace, "B Gateway customer classification " + workspace);
        db.update("""
                insert into agents(id,workspace_id,agent_key,name,purpose_summary,status)
                values (?,?,?,'B Gateway classification','Synthetic review','ACTIVE')
                """, agent, workspace, "b-gw-classification-" + agent);
        db.update("""
                insert into agent_releases(id,agent_id,version,business_purpose,manifest_schema_version,
                    manifest_json,agent_artifact_fingerprint,release_fingerprint,lifecycle_state,effective_status)
                values (?,?,'1.0','LOAN_DOCUMENT_COMPLETENESS_REVIEW','1.0',
                    '{}'::jsonb,?,?,'ANALYZED','ANALYZED')
                """, release, agent, HASH, HASH);
        db.update("""
                insert into test_suites(id,workspace_id,suite_key,version,fixture_version,
                    generation_config_json,suite_hash,status)
                values (?,?,?,'1.0',?,'{}'::jsonb,?,'BUILDING')
                """, suite, workspace, "b-gw-classification-suite-" + suite,
                SandboxFixtureService.NORMAL_FIXTURE_VERSION, HASH);
        var preconditions = json.createObjectNode()
                .put("caseId", caseId).put("currentApplicantId", applicantId);
        db.update("""
                insert into test_cases(id,suite_id,case_key,case_type,partition_name,category,
                    severity,delivery_channel,target_tool,payload_hash,preconditions_json,
                    expected_invariant,oracle_type,generation_source,expected_result_json,trial_policy_json)
                values (?,?,'NORMAL-1','NORMAL','NORMAL','NORMAL','LOW','DIRECT',
                    'CUSTOMER_DATA_READ',?,?::jsonb,
                    'INV-NORMAL','NORMAL_TASK','CURATED','{}'::jsonb,'{}'::jsonb)
                """, testCase, suite, HASH, preconditions.toString());
        db.update("update test_suites set status = 'READY' where id = ?", suite);

        UUID run = runs.register(new TestRunPersistenceDto.RegisterRequest(
                release, suite, null, TestRunMode.BASELINE, UUID.randomUUID(),
                json.createObjectNode(), fixtures.fixtureDigest(SandboxFixtureService.NORMAL_FIXTURE_VERSION),
                HASH, 42L, 1), ACTOR).runId();
        events.append(run, new ExecutionEventDto.AppendRequest(null, trace,
                ExecutionEventType.RUN_STARTED, null, null, null, null,
                "GATEWAY_CLASSIFICATION_TEST", json.createObjectNode()), ACTOR);
        runs.updateStatus(run, new TestRunPersistenceDto.StatusRequest(
                TestRunStatus.PREPARING, 0, 0, null), ACTOR);
        fixtures.createOrReset(run);
        runs.updateStatus(run, new TestRunPersistenceDto.StatusRequest(
                TestRunStatus.RUNNING, 0, 0, null), ACTOR);
        UUID caseRun = runs.registerCase(run,
                new TestRunPersistenceDto.CaseRunRegisterRequest(testCase, 0, HASH), ACTOR).id();
        runs.updateCaseStatus(run, caseRun, new TestRunPersistenceDto.CaseRunStatusRequest(
                TestCaseRunStatus.EXECUTING, null, null, null, null, null, null), ACTOR);
        var arguments = json.createObjectNode();
        arguments.putArray("customerIds").add(CUSTOMER_ID);
        arguments.putArray("fields").add("incomeBand");
        ExecutionEventDto.Event proposal = events.append(run,
                new ExecutionEventDto.AppendRequest(caseRun, trace, ExecutionEventType.TOOL_PROPOSED,
                        toolName, arguments, null, null,
                        "STRUCTURED_TOOL_PROPOSAL", json.createObjectNode()), ACTOR);
        return new Seed(workspace, run, caseRun,
                new InvocationKey(run, caseRun, trace, proposal.eventId(), proposal.payloadDigest()));
    }

    private void restoreLabels(Seed seed) {
        db.update("""
                update sandbox_customers
                   set classification_json = '{"sensitiveFields":["accountNumber"],
                        "criticalFields":["accountNumber"],"syntheticOnly":true}'::jsonb
                 where namespace_id = ? and customer_key = ?
                """, seed.runId(), CUSTOMER_ID);
    }

    private void corruptNamespace(String sql, Object value, UUID runId) {
        assertThat(db.queryForObject("show session_replication_role", String.class)).isEqualTo("origin");
        new TransactionTemplate(transactions).executeWithoutResult(status -> {
            db.execute("set local session_replication_role = replica");
            db.update(sql, value, runId);
        });
        assertThat(db.queryForObject("show session_replication_role", String.class)).isEqualTo("origin");
    }

    private Map<String, String> sandboxState(UUID runId) {
        Map<String, String> digests = new LinkedHashMap<>();
        for (String table : SANDBOX_TABLES) {
            String key = table.equals("sandbox_namespaces") ? "id" : "namespace_id";
            digests.put(table, db.queryForObject("""
                    select encode(digest(coalesce(string_agg(to_jsonb(t)::text, ','
                        order by to_jsonb(t)::text), ''), 'sha256'), 'hex')
                      from %s t where %s = ?
                    """.formatted(table, key), String.class, runId));
        }
        return digests;
    }

    private void assertUnchanged(Seed seed, Map<String, String> before,
            int eventsBefore, int auditsBefore) {
        assertThat(sandboxState(seed.runId())).isEqualTo(before);
        assertThat(eventCount(seed.runId())).isEqualTo(eventsBefore);
        assertThat(auditCount(seed.workspaceId())).isEqualTo(auditsBefore);
        assertNoToolEffects(seed);
    }

    private void assertNoToolEffects(Seed seed) {
        assertThat(eventTypeCount(seed.runId(), ExecutionEventType.TOOL_REQUEST)).isZero();
        assertThat(eventTypeCount(seed.runId(), ExecutionEventType.TOOL_RESPONSE)).isZero();
        assertThat(eventTypeCount(seed.runId(), ExecutionEventType.SANDBOX_STATE_CHANGED)).isZero();
    }

    private int eventCount(UUID runId) {
        return db.queryForObject("select count(*) from execution_events where run_id = ?",
                Integer.class, runId);
    }

    private int eventTypeCount(UUID runId, ExecutionEventType type) {
        return db.queryForObject("select count(*) from execution_events where run_id = ? and event_type = ?",
                Integer.class, runId, type.name());
    }

    private int auditCount(UUID workspaceId) {
        return db.queryForObject("select count(*) from audit_records where workspace_id = ?",
                Integer.class, workspaceId);
    }

    private void assertNoAdapterExecution() {
        verify(adapter, never()).execute(any(), any());
        verify(adapter, never()).validateArguments(any());
    }

    private static void assertIncomplete(org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).isInstanceOfSatisfying(BusinessException.class, error -> {
            assertThat(error.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE);
            assertThat(error.getCause()).isNull();
            assertThat(error.getMessage()).isEqualTo(FAILURE);
        });
    }

    private record Seed(UUID workspaceId, UUID runId, UUID caseRunId, InvocationKey key) {
    }
}
