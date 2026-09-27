package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
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
class StoredGatewayFixedOperationSourceIntegrationTest {

    private static final String ACTOR = "b-gateway-fixed-operation-test";
    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final String OTHER_HASH = "sha256:" + "b".repeat(64);
    private static final String CUSTOMER = CustomerDataReadToolAdapter.TOOL_NAME;
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
    @Autowired List<ToolAdapter> adapters;
    @MockitoSpyBean CustomerDataReadToolAdapter adapter;

    @Test
    void actualCustomerAdapterReadIsIndependentOfWrongStoredCatalogOperation() {
        Seed seed = seed(CUSTOMER, "WRITE", "CASE-1001");
        assertThat(db.queryForObject("""
                select definition.operation from tool_definitions definition
                join release_tools link on link.tool_definition_id = definition.id
                where link.release_id = ? and definition.tool_key = ?
                """, String.class, seed.releaseId(), CUSTOMER)).isEqualTo("WRITE");
        Map<String, String> before = sandboxState(seed.runId());
        int eventCount = eventCount(seed.runId());
        int auditCount = auditCount(seed.workspaceId());
        clearInvocations(adapter);

        var facts = inTransaction(() -> {
            String previousTimeout = db.queryForObject("show statement_timeout", String.class);
            var observed = source().resolve(seed.key(), Duration.ofSeconds(5));
            assertThat(db.queryForObject("show statement_timeout", String.class))
                    .isEqualTo(previousTimeout);
            return observed;
        });

        assertThat(facts.key()).isEqualTo(seed.key());
        assertThat(facts.namespaceId()).isEqualTo(seed.runId());
        assertThat(facts.toolName()).isEqualTo(CUSTOMER);
        assertThat(facts.operation()).isEqualTo("READ");
        assertThat(facts.toString()).isEqualTo("StoredGatewayFixedOperation[READ]");
        assertNoAdapterExecution();
        assertUnchanged(seed, before, eventCount, auditCount);
    }

    @Test
    void wrongInvocationKeyAndOtherStoredToolCannotProduceReadFacts() {
        Seed seed = seed(CUSTOMER, "READ", "CASE-1001");
        Seed other = seed("LOAN_POLICY_SEARCH", "SEARCH", "CASE-1001");
        Seed foreign = seed(CUSTOMER, "READ", "CASE-1001");
        InvocationKey key = seed.key();
        List<InvocationKey> wrong = List.of(
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
        for (InvocationKey invalid : wrong) {
            assertIncomplete(() -> inTransaction(() ->
                    source().resolve(invalid, Duration.ofSeconds(5))));
        }
        assertIncomplete(() -> inTransaction(() ->
                source().resolve(other.key(), Duration.ofSeconds(5))));
        assertIncomplete(() -> inTransaction(() -> source().resolve(new InvocationKey(
                foreign.runId(), foreign.caseRunId(), key.traceId(),
                key.toolCallId(), key.requestDigest()), Duration.ofSeconds(5))));
        assertNoAdapterExecution();
        assertThat(eventTypeCount(seed.runId(), ExecutionEventType.TOOL_REQUEST)).isZero();
        assertThat(eventTypeCount(seed.runId(), ExecutionEventType.TOOL_RESPONSE)).isZero();
        assertThat(eventTypeCount(seed.runId(), ExecutionEventType.SANDBOX_STATE_CHANGED)).isZero();
    }

    @Test
    void wrongCaseContextAndInactiveOrExpiredNamespaceFailClosed() {
        Seed wrongCase = seed(CUSTOMER, "READ", "CASE-FOREIGN");
        assertIncomplete(() -> inTransaction(() ->
                source().resolve(wrongCase.key(), Duration.ofSeconds(5))));

        Seed sealed = seed(CUSTOMER, "READ", "CASE-1001");
        db.update("update sandbox_namespaces set state = 'SEALED' where id = ?", sealed.runId());
        assertIncomplete(() -> inTransaction(() ->
                source().resolve(sealed.key(), Duration.ofSeconds(5))));

        Seed expired = seed(CUSTOMER, "READ", "CASE-1001");
        db.update("update sandbox_namespaces set expires_at = now() - interval '1 second' where id = ?",
                expired.runId());
        assertIncomplete(() -> inTransaction(() ->
                source().resolve(expired.key(), Duration.ofSeconds(5))));
        assertThat(eventTypeCount(expired.runId(), ExecutionEventType.TOOL_REQUEST)).isZero();
    }

    @Test
    void missingDuplicateAndWrongAdapterTypesCannotInventAnOperation() {
        Seed seed = seed(CUSTOMER, "READ", "CASE-1001");
        ToolAdapter plain = mock(ToolAdapter.class);
        when(plain.toolName()).thenReturn(CUSTOMER);
        FixedOperationToolAdapter wrongConcrete = mock(FixedOperationToolAdapter.class);
        when(wrongConcrete.toolName()).thenReturn(CUSTOMER);
        when(wrongConcrete.fixedOperation()).thenReturn("READ");

        for (List<ToolAdapter> candidate : List.of(
                List.<ToolAdapter>of(), List.<ToolAdapter>of(adapter, adapter),
                List.<ToolAdapter>of(plain), List.<ToolAdapter>of(wrongConcrete))) {
            assertIncomplete(() -> inTransaction(() ->
                    source(candidate).resolve(seed.key(), Duration.ofSeconds(5))));
        }
        assertThat(eventTypeCount(seed.runId(), ExecutionEventType.TOOL_REQUEST)).isZero();
        assertThat(eventTypeCount(seed.runId(), ExecutionEventType.TOOL_RESPONSE)).isZero();
    }

    @Test
    void changingEffectOrDeclaredOperationOnTheMatchingAdapterFailsClosed() {
        Seed seed = seed(CUSTOMER, "READ", "CASE-1001");
        CustomerDataReadToolAdapter effectChanged = mock(CustomerDataReadToolAdapter.class);
        when(effectChanged.toolName()).thenReturn(CUSTOMER);
        when(effectChanged.effect()).thenReturn(ToolEffect.STATE_CHANGING);
        CustomerDataReadToolAdapter operationChanged = mock(CustomerDataReadToolAdapter.class);
        when(operationChanged.toolName()).thenReturn(CUSTOMER);
        when(operationChanged.effect()).thenReturn(ToolEffect.READ_ONLY);
        when(operationChanged.fixedOperation()).thenReturn("WRITE");

        assertIncomplete(() -> inTransaction(() -> source(List.of(effectChanged))
                .resolve(seed.key(), Duration.ofSeconds(5))));
        assertIncomplete(() -> inTransaction(() -> source(List.of(operationChanged))
                .resolve(seed.key(), Duration.ofSeconds(5))));
        verify(effectChanged, never()).execute(any(), any());
        verify(operationChanged, never()).execute(any(), any());
        assertThat(eventTypeCount(seed.runId(), ExecutionEventType.TOOL_REQUEST)).isZero();
    }

    @Test
    void requiresBoundRepeatableReadAndFiniteBudget() {
        Seed seed = seed(CUSTOMER, "READ", "CASE-1001");
        assertIncomplete(() -> source().resolve(seed.key(), Duration.ofSeconds(5)));
        TransactionTemplate readCommitted = new TransactionTemplate(transactions);
        readCommitted.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
        assertIncomplete(() -> readCommitted.execute(status -> {
            db.queryForObject("select 1", Integer.class);
            return source().resolve(seed.key(), Duration.ofSeconds(5));
        }));
        assertIncomplete(() -> inTransaction(() -> source().resolve(seed.key(), null)));
        for (Duration invalid : List.of(Duration.ZERO, Duration.ofSeconds(-1),
                Duration.ofSeconds(6), Duration.ofMillis(900))) {
            assertIncomplete(() -> inTransaction(() -> source().resolve(seed.key(), invalid)));
        }
        assertThat(eventTypeCount(seed.runId(), ExecutionEventType.TOOL_REQUEST)).isZero();
    }

    @Test
    void monotonicDeadlineExpiresEvenAfterStoredScopeRead() {
        Seed seed = seed(CUSTOMER, "READ", "CASE-1001");
        long budget = Duration.ofSeconds(5).toNanos();
        AtomicInteger tick = new AtomicInteger();
        long[] times = {0, 0, budget};
        var expiring = new StoredGatewayFixedOperationSource(dataSource, scopes, adapters,
                () -> times[Math.min(tick.getAndIncrement(), times.length - 1)]);
        int eventsBefore = eventCount(seed.runId());
        clearInvocations(adapter);

        assertIncomplete(() -> inTransaction(() ->
                expiring.resolve(seed.key(), Duration.ofSeconds(5))));
        assertThat(tick.get()).isGreaterThanOrEqualTo(3);
        assertNoAdapterExecution();
        assertThat(eventCount(seed.runId())).isEqualTo(eventsBefore);
    }

    @Test
    void lockedPostgresScopeCannotOutliveBudgetOrInvokeAdapter() throws SQLException {
        Seed seed = seed(CUSTOMER, "READ", "CASE-1001");
        Map<String, String> before = sandboxState(seed.runId());
        int eventsBefore = eventCount(seed.runId());
        int auditsBefore = auditCount(seed.workspaceId());
        clearInvocations(adapter);
        try (Connection blocker = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())) {
            blocker.setAutoCommit(false);
            try (Statement lock = blocker.createStatement()) {
                lock.execute("lock table test_runs in access exclusive mode");
            }
            long started = System.nanoTime();
            assertIncomplete(() -> inTransaction(() ->
                    source().resolve(seed.key(), Duration.ofSeconds(2))));
            assertThat(Duration.ofNanos(System.nanoTime() - started))
                    .isLessThan(Duration.ofSeconds(5));
            blocker.rollback();
        }
        assertNoAdapterExecution();
        assertUnchanged(seed, before, eventsBefore, auditsBefore);
        assertThat(inTransaction(() ->
                source().resolve(seed.key(), Duration.ofSeconds(5))).operation()).isEqualTo("READ");
    }

    private StoredGatewayFixedOperationSource source() {
        return source(adapters);
    }

    private StoredGatewayFixedOperationSource source(List<ToolAdapter> selected) {
        return new StoredGatewayFixedOperationSource(dataSource, scopes, selected);
    }

    private <T> T inTransaction(Supplier<T> action) {
        TransactionTemplate transaction = new TransactionTemplate(transactions);
        transaction.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        return transaction.execute(status -> {
            db.queryForObject("select 1", Integer.class);
            return action.get();
        });
    }

    private Seed seed(String proposedTool, String catalogOperation, String caseId) {
        UUID workspace = UUID.randomUUID(), agent = UUID.randomUUID(), release = UUID.randomUUID();
        UUID suite = UUID.randomUUID(), testCase = UUID.randomUUID(), trace = UUID.randomUUID();
        UUID definition = UUID.randomUUID();
        db.update("insert into workspaces(id,name,mode) values (?,?, 'DEMO')",
                workspace, "B Gateway fixed operation " + workspace);
        db.update("""
                insert into agents(id,workspace_id,agent_key,name,purpose_summary,status)
                values (?,?,?,'B Gateway fixed operation','Synthetic review','ACTIVE')
                """, agent, workspace, "b-gw-fixed-operation-" + agent);
        db.update("""
                insert into agent_releases(id,agent_id,version,business_purpose,manifest_schema_version,
                    manifest_json,agent_artifact_fingerprint,release_fingerprint,lifecycle_state,effective_status)
                values (?,?,'1.0','LOAN_DOCUMENT_COMPLETENESS_REVIEW','1.0',
                    '{}'::jsonb,?,?,'DRAFT','DRAFT')
                """, release, agent, HASH, HASH);
        db.update("""
                insert into tool_definitions(id,tool_key,version,operation,input_schema_json,
                    output_schema_json,description,trust_level,risk_level,
                    data_classifications_json,side_effect_type,adapter_key,
                    schema_hash,description_hash)
                values (?,?,?,?,'{}'::jsonb,'{}'::jsonb,'Synthetic fixed-operation test',
                    'TRUSTED_INTERNAL','LOW','[]'::jsonb,'NONE','customer_data_read',?,?)
                """, definition, CUSTOMER, "v-" + UUID.randomUUID(), catalogOperation, HASH, OTHER_HASH);
        db.update("insert into release_tools(release_id,tool_definition_id,enabled,ordinal) values (?,?,true,0)",
                release, definition);
        db.update("""
                update agent_releases set lifecycle_state = 'ANALYZED', effective_status = 'ANALYZED'
                 where id = ?
                """, release);
        db.update("""
                insert into test_suites(id,workspace_id,suite_key,version,fixture_version,
                    generation_config_json,suite_hash,status)
                values (?,?,?,'1.0',?,'{}'::jsonb,?,'BUILDING')
                """, suite, workspace, "b-gw-fixed-operation-suite-" + suite,
                SandboxFixtureService.NORMAL_FIXTURE_VERSION, HASH);
        var preconditions = json.createObjectNode()
                .put("caseId", caseId).put("currentApplicantId", "CUST-1001");
        db.update("""
                insert into test_cases(id,suite_id,case_key,case_type,partition_name,category,
                    severity,delivery_channel,target_tool,payload_hash,preconditions_json,
                    expected_invariant,oracle_type,generation_source,expected_result_json,trial_policy_json)
                values (?,?,'NORMAL-1','NORMAL','NORMAL','NORMAL','LOW','DIRECT',
                    ?,?,?::jsonb,'INV-NORMAL','NORMAL_TASK','CURATED','{}'::jsonb,'{}'::jsonb)
                """, testCase, suite, proposedTool, HASH, preconditions.toString());
        db.update("update test_suites set status = 'READY' where id = ?", suite);

        UUID run = runs.register(new TestRunPersistenceDto.RegisterRequest(
                release, suite, null, TestRunMode.BASELINE, UUID.randomUUID(),
                json.createObjectNode(), fixtures.fixtureDigest(SandboxFixtureService.NORMAL_FIXTURE_VERSION),
                HASH, 42L, 1), ACTOR).runId();
        events.append(run, new ExecutionEventDto.AppendRequest(null, trace,
                ExecutionEventType.RUN_STARTED, null, null, null, null,
                "GATEWAY_FIXED_OPERATION_TEST", json.createObjectNode()), ACTOR);
        runs.updateStatus(run, new TestRunPersistenceDto.StatusRequest(
                TestRunStatus.PREPARING, 0, 0, null), ACTOR);
        fixtures.createOrReset(run);
        runs.updateStatus(run, new TestRunPersistenceDto.StatusRequest(
                TestRunStatus.RUNNING, 0, 0, null), ACTOR);
        UUID caseRun = runs.registerCase(run,
                new TestRunPersistenceDto.CaseRunRegisterRequest(testCase, 0, HASH), ACTOR).id();
        runs.updateCaseStatus(run, caseRun, new TestRunPersistenceDto.CaseRunStatusRequest(
                TestCaseRunStatus.EXECUTING, null, null, null, null, null, null), ACTOR);
        var proposalArguments = json.createObjectNode();
        proposalArguments.putArray("customerIds").add("CUST-1001");
        proposalArguments.putArray("fields").add("incomeBand");
        ExecutionEventDto.Event proposal = events.append(run,
                new ExecutionEventDto.AppendRequest(caseRun, trace, ExecutionEventType.TOOL_PROPOSED,
                        proposedTool, proposalArguments, null, null,
                        "STRUCTURED_TOOL_PROPOSAL", json.createObjectNode()), ACTOR);
        return new Seed(workspace, release, run, caseRun, trace,
                new InvocationKey(run, caseRun, trace, proposal.eventId(), proposal.payloadDigest()));
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
            assertThat(error.getMessage()).isEqualTo("Stored Gateway fixed operation is incomplete");
        });
    }

    private record Seed(UUID workspaceId, UUID releaseId, UUID runId, UUID caseRunId,
                        UUID traceId, InvocationKey key) { }
}
