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
import com.finsecseal.sandbox.SandboxExecutionContext;
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
import java.util.concurrent.atomic.AtomicInteger;
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
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Testcontainers
@SpringBootTest
class ReadOnlyToolDurableInvocationReceiptServiceIntegrationTest {

    private static final String ACTOR = "b-readonly-receipt-test";
    private static final String TOOL = "CUSTOMER_DATA_READ";
    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final String OTHER_HASH = "sha256:" + "b".repeat(64);
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
    @Autowired List<ToolAdapter> adapters;

    @Test
    void committedClaimFencesOtherInstancesAndCompletionStoresOnlyRedactedResponse() throws Exception {
        Seed seed = seed(TestRunMode.BASELINE, "BASELINE", "ALLOW", true);
        var source = source();
        int eventsBefore = eventCount(seed.runId());
        int auditsBefore = auditCount(seed.workspaceId());
        Map<String, String> stateBefore = businessState(seed.runId());

        var claim = source.claim(seed.key(), seed.policyEventId(), DEADLINE);
        assertThat(claim.key()).isEqualTo(seed.key());
        assertThat(claim.toolName()).isEqualTo(TOOL);
        assertThat(receiptState(seed)).isEqualTo("PROCESSING");
        assertIncomplete(() -> source().claim(seed.key(), seed.policyEventId(), DEADLINE));
        assertThat(eventCount(seed.runId())).isEqualTo(eventsBefore);
        assertThat(auditCount(seed.workspaceId())).isEqualTo(auditsBefore);
        assertThat(businessState(seed.runId())).isEqualTo(stateBefore);

        ExecutionEventDto.Event request = request(seed, seed.traceId(), seed.key().toolCallId());
        ObjectNode raw = json.createObjectNode().put("accountNumber", "SYNTH-ACCOUNT-PRIVATE")
                .put("status", 200);
        ExecutionEventDto.Event response = response(seed, seed.traceId(), seed.key().toolCallId(),
                raw, true, "PENDING", false);
        int eventCount = eventCount(seed.runId());
        int auditCount = auditCount(seed.workspaceId());
        var completed = source.complete(claim, request.eventId(), response.eventId(), DEADLINE);

        assertThat(completed.id()).isEqualTo(claim.id());
        assertThat(completed.requestEventId()).isEqualTo(request.eventId());
        assertThat(completed.responseEventId()).isEqualTo(response.eventId());
        assertThat(receiptState(seed)).isEqualTo("COMPLETED");
        String savedResponse = db.queryForObject("""
                select response_json::text from sandbox_tool_idempotency_records
                 where test_case_run_id = ? and tool_call_id = ?
                """, String.class, seed.caseRunId(), seed.key().toolCallId());
        assertThat(json.readTree(savedResponse)).isEqualTo(response.output());
        assertThat(savedResponse).doesNotContain("SYNTH-ACCOUNT-PRIVATE");
        assertThat(db.queryForObject("""
                select state_changed from sandbox_tool_idempotency_records
                 where test_case_run_id = ? and tool_call_id = ?
                """, Boolean.class, seed.caseRunId(), seed.key().toolCallId())).isFalse();
        assertIncomplete(() -> source.complete(claim, request.eventId(), response.eventId(), DEADLINE));
        assertIncomplete(() -> source().claim(seed.key(), seed.policyEventId(), DEADLINE));
        assertThat(eventCount(seed.runId())).isEqualTo(eventCount);
        assertThat(auditCount(seed.workspaceId())).isEqualTo(auditCount);
        assertThat(businessState(seed.runId())).isEqualTo(stateBefore);
    }

    @Test
    void rejectsPolicyModeDecisionAndProposalIdentityMismatchWithoutClaimRow() {
        for (PolicyShape shape : List.of(
                new PolicyShape(TestRunMode.BASELINE, "ENFORCE", "ALLOW", true),
                new PolicyShape(TestRunMode.SEAL_REPLAY, "BASELINE", "ALLOW", true),
                new PolicyShape(TestRunMode.HELD_OUT, "ENFORCE", "DENY", true),
                new PolicyShape(TestRunMode.REGRESSION, "ENFORCE", "ALLOW", false))) {
            Seed seed = seed(shape.runMode(), shape.evaluationMode(),
                    shape.decisionType(), shape.allowed());
            assertIncomplete(() -> source().claim(seed.key(), seed.policyEventId(), DEADLINE));
            assertThat(receiptCount(seed)).isZero();
        }

        Seed seed = seed(TestRunMode.BASELINE, "BASELINE", "ALLOW", true);
        InvocationKey key = seed.key();
        assertIncomplete(() -> source().claim(new InvocationKey(UUID.randomUUID(), key.caseRunId(),
                key.traceId(), key.toolCallId(), key.requestDigest()), seed.policyEventId(), DEADLINE));
        assertIncomplete(() -> source().claim(new InvocationKey(key.runId(), UUID.randomUUID(),
                key.traceId(), key.toolCallId(), key.requestDigest()), seed.policyEventId(), DEADLINE));
        assertIncomplete(() -> source().claim(new InvocationKey(key.runId(), key.caseRunId(),
                UUID.randomUUID(), key.toolCallId(), key.requestDigest()), seed.policyEventId(), DEADLINE));
        assertIncomplete(() -> source().claim(new InvocationKey(key.runId(), key.caseRunId(),
                key.traceId(), UUID.randomUUID(), key.requestDigest()), seed.policyEventId(), DEADLINE));
        assertIncomplete(() -> source().claim(new InvocationKey(key.runId(), key.caseRunId(),
                key.traceId(), key.toolCallId(), OTHER_HASH), seed.policyEventId(), DEADLINE));
        assertIncomplete(() -> source().claim(key, UUID.randomUUID(), DEADLINE));
        assertThat(receiptCount(seed)).isZero();
    }

    @Test
    void preexistingRequestResponseOrStateEventWithoutV13RowBlocksClaim() {
        for (ExecutionEventType type : List.of(ExecutionEventType.TOOL_REQUEST,
                ExecutionEventType.TOOL_RESPONSE, ExecutionEventType.SANDBOX_STATE_CHANGED)) {
            Seed seed = seed(TestRunMode.BASELINE, "BASELINE", "ALLOW", true);
            ObjectNode metadata = json.createObjectNode()
                    .put("toolCallId", seed.key().toolCallId().toString());
            JsonNode input = type == ExecutionEventType.TOOL_REQUEST
                    ? json.createObjectNode().put("legacy", true) : null;
            JsonNode output = type == ExecutionEventType.TOOL_RESPONSE
                    ? json.createObjectNode().put("legacy", true) : null;
            events.append(seed.runId(), new ExecutionEventDto.AppendRequest(seed.caseRunId(),
                    seed.traceId(), type, TOOL, input, output, null,
                    "LEGACY_TOOL_PATH", metadata), ACTOR);
            assertThat(receiptCount(seed)).isZero();
            assertIncomplete(() -> source().claim(seed.key(), seed.policyEventId(), DEADLINE));
            assertThat(receiptCount(seed)).isZero();
        }
    }

    @Test
    void completionRejectsWrongScopeMetadataAndEventOrderLeavingProcessingFence() {
        Seed wrongTrace = seed(TestRunMode.BASELINE, "BASELINE", "ALLOW", true);
        var wrongTraceClaim = source().claim(wrongTrace.key(), wrongTrace.policyEventId(), DEADLINE);
        ExecutionEventDto.Event badRequest = request(wrongTrace, UUID.randomUUID(),
                wrongTrace.key().toolCallId());
        ExecutionEventDto.Event response = response(wrongTrace, wrongTrace.traceId(),
                wrongTrace.key().toolCallId(), json.createObjectNode().put("ok", true),
                true, "PENDING", false);
        assertIncomplete(() -> source().complete(wrongTraceClaim,
                badRequest.eventId(), response.eventId(), DEADLINE));
        assertThat(receiptState(wrongTrace)).isEqualTo("PROCESSING");

        Seed wrongMetadata = seed(TestRunMode.BASELINE, "BASELINE", "ALLOW", true);
        var metadataClaim = source().claim(wrongMetadata.key(), wrongMetadata.policyEventId(), DEADLINE);
        ExecutionEventDto.Event request = request(wrongMetadata, wrongMetadata.traceId(),
                wrongMetadata.key().toolCallId());
        ExecutionEventDto.Event badResponse = response(wrongMetadata, wrongMetadata.traceId(),
                wrongMetadata.key().toolCallId(), json.createObjectNode().put("ok", true),
                false, "PENDING", false);
        assertIncomplete(() -> source().complete(metadataClaim,
                request.eventId(), badResponse.eventId(), DEADLINE));
        assertThat(receiptState(wrongMetadata)).isEqualTo("PROCESSING");

        Seed wrongOrder = seed(TestRunMode.BASELINE, "BASELINE", "ALLOW", true);
        var orderClaim = source().claim(wrongOrder.key(), wrongOrder.policyEventId(), DEADLINE);
        ExecutionEventDto.Event earlierResponse = response(wrongOrder, wrongOrder.traceId(),
                wrongOrder.key().toolCallId(), json.createObjectNode().put("ok", true),
                true, "PENDING", false);
        ExecutionEventDto.Event laterRequest = request(wrongOrder, wrongOrder.traceId(),
                wrongOrder.key().toolCallId());
        assertIncomplete(() -> source().complete(orderClaim,
                laterRequest.eventId(), earlierResponse.eventId(), DEADLINE));
        assertThat(receiptState(wrongOrder)).isEqualTo("PROCESSING");
    }

    @Test
    void postCommitDeadlineExpiryReturnsNoSuccessButLeavesDurableFence() {
        Seed seed = seed(TestRunMode.BASELINE, "BASELINE", "ALLOW", true);
        AtomicLong clock = new AtomicLong(10_000_000_000L);
        PlatformTransactionManager slowCommit = advancingCommitManager(clock);
        var source = new ReadOnlyToolDurableInvocationReceiptService(dataSource, slowCommit,
                adapters, clock::get);
        assertIncomplete(() -> source.claim(seed.key(), seed.policyEventId(), DEADLINE));
        assertThat(receiptState(seed)).isEqualTo("PROCESSING");
        assertIncomplete(() -> source().claim(seed.key(), seed.policyEventId(), DEADLINE));
    }

    @Test
    void postCommitExpiryAlsoSuppressesCompletedReceiptAfterCommit() {
        Seed seed = seed(TestRunMode.BASELINE, "BASELINE", "ALLOW", true);
        var claim = source().claim(seed.key(), seed.policyEventId(), DEADLINE);
        ExecutionEventDto.Event request = request(seed, seed.traceId(), seed.key().toolCallId());
        ExecutionEventDto.Event response = response(seed, seed.traceId(), seed.key().toolCallId(),
                json.createObjectNode().put("ok", true), true, "PENDING", false);
        AtomicLong clock = new AtomicLong(10_000_000_000L);
        var source = new ReadOnlyToolDurableInvocationReceiptService(dataSource,
                advancingCommitManager(clock), adapters, clock::get);
        assertIncomplete(() -> source.complete(claim, request.eventId(), response.eventId(), DEADLINE));
        assertThat(receiptState(seed)).isEqualTo("COMPLETED");
    }

    @Test
    void rejectsUnsafeDeadlineAmbientTransactionAndStateChangingAdapter() {
        Seed seed = seed(TestRunMode.BASELINE, "BASELINE", "ALLOW", true);
        assertIncomplete(() -> source().claim(seed.key(), seed.policyEventId(), Duration.ZERO));
        assertIncomplete(() -> source().claim(seed.key(), seed.policyEventId(), Duration.ofSeconds(6)));
        assertIncomplete(() -> source().claim(seed.key(), seed.policyEventId(), Duration.ofMillis(900)));
        TransactionTemplate transaction = new TransactionTemplate(transactions);
        assertIncomplete(() -> transaction.execute(status ->
                source().claim(seed.key(), seed.policyEventId(), DEADLINE)));
        assertThat(receiptCount(seed)).isZero();

        AtomicInteger executions = new AtomicInteger();
        ToolAdapter stateChanging = new ToolAdapter() {
            @Override public String toolName() { return TOOL; }
            @Override public ToolEffect effect() { return ToolEffect.STATE_CHANGING; }
            @Override public ToolExecutionResult execute(SandboxExecutionContext context, JsonNode args) {
                executions.incrementAndGet();
                return new ToolExecutionResult(json.createObjectNode(), true);
            }
        };
        var unsafe = new ReadOnlyToolDurableInvocationReceiptService(dataSource, transactions,
                List.of(stateChanging));
        assertIncomplete(() -> unsafe.claim(seed.key(), seed.policyEventId(), DEADLINE));
        assertThat(receiptCount(seed)).isZero();
        assertThat(executions).hasValue(0);
    }

    @Test
    void blockedDatabaseClaimUsesFiniteDeadlineAndLeavesNoReceipt() throws Exception {
        Seed seed = seed(TestRunMode.BASELINE, "BASELINE", "ALLOW", true);
        try (Connection blocker = DriverManager.getConnection(POSTGRES.getJdbcUrl(),
                POSTGRES.getUsername(), POSTGRES.getPassword())) {
            blocker.setAutoCommit(false);
            try (Statement statement = blocker.createStatement()) {
                statement.execute("lock table sandbox_tool_idempotency_records in access exclusive mode");
            }
            long started = System.nanoTime();
            assertIncomplete(() -> source().claim(seed.key(), seed.policyEventId(), Duration.ofSeconds(3)));
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(6));
            blocker.rollback();
        }
        assertThat(receiptCount(seed)).isZero();
    }

    private ReadOnlyToolDurableInvocationReceiptService source() {
        return new ReadOnlyToolDurableInvocationReceiptService(dataSource, transactions, adapters);
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

    private ExecutionEventDto.Event request(Seed seed, UUID trace, UUID callId) {
        return events.append(seed.runId(), new ExecutionEventDto.AppendRequest(seed.caseRunId(), trace,
                ExecutionEventType.TOOL_REQUEST, TOOL, json.createObjectNode().put("request", true),
                null, null, null, metadata(callId)), ACTOR);
    }

    private ExecutionEventDto.Event response(Seed seed, UUID trace, UUID callId, JsonNode output,
            boolean pendingUndelivered, String deliveryState, boolean stateChanged) {
        ObjectNode metadata = metadata(callId).put("deliveryState", deliveryState)
                .put("stateChanged", stateChanged);
        if (pendingUndelivered) metadata.put("deliveredToAgent", false);
        return events.append(seed.runId(), new ExecutionEventDto.AppendRequest(seed.caseRunId(), trace,
                ExecutionEventType.TOOL_RESPONSE, TOOL, null, output, null,
                "TOOL_EXECUTED", metadata), ACTOR);
    }

    private ObjectNode metadata(UUID callId) {
        return json.createObjectNode().put("toolCallId", callId.toString());
    }

    private Seed seed(TestRunMode mode, String evaluationMode, String decisionType, boolean allowed) {
        UUID workspace = UUID.randomUUID(), agent = UUID.randomUUID(), release = UUID.randomUUID();
        UUID suite = UUID.randomUUID(), testCase = UUID.randomUUID(), trace = UUID.randomUUID();
        db.update("insert into workspaces(id,name,mode) values (?,?, 'DEMO')",
                workspace, "B durable receipt " + workspace);
        db.update("""
                insert into agents(id,workspace_id,agent_key,name,purpose_summary,status)
                values (?,?,?,'B durable receipt','Synthetic review','ACTIVE')
                """, agent, workspace, "b-durable-receipt-" + agent);
        db.update("""
                insert into agent_releases(id,agent_id,version,business_purpose,manifest_schema_version,
                    manifest_json,agent_artifact_fingerprint,release_fingerprint,lifecycle_state,effective_status)
                values (?,?,'1.0','LOAN_DOCUMENT_COMPLETENESS_REVIEW','1.0',
                    '{}'::jsonb,?,?,'DRAFT','DRAFT')
                """, release, agent, HASH, HASH);
        // Use the same runnable release and approved same-release contract shape as the
        // existing owner integration fixtures; V4's Run scope guard remains enabled.
        db.update("""
                update agent_releases set lifecycle_state = 'ANALYZED', effective_status = 'ANALYZED'
                 where id = ?
                """, release);
        UUID contractVersion = null;
        if (mode != TestRunMode.BASELINE) {
            UUID contract = UUID.randomUUID();
            contractVersion = UUID.randomUUID();
            db.update("""
                    insert into safety_contracts(id,workspace_id,release_id,contract_key,status)
                    values (?,?,?,?,'APPROVED')
                    """, contract, workspace, release, "b-receipt-contract-" + contract);
            db.update("""
                    insert into safety_contract_versions
                        (id,contract_id,version,state,policy_json,policy_hash,validation_json,
                         created_by,approved_by,approved_at)
                    values (?,?,1,'APPROVED','{}'::jsonb,?,'{}'::jsonb,'test-reviewer',
                            'test-reviewer',now())
                    """, contractVersion, contract, HASH);
        }
        db.update("""
                insert into test_suites(id,workspace_id,suite_key,version,fixture_version,
                    generation_config_json,suite_hash,status)
                values (?,?,?,'1.0','golden-v1','{}'::jsonb,?,'BUILDING')
                """, suite, workspace, "b-receipt-suite-" + suite, HASH);
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
                release, suite, contractVersion, mode, UUID.randomUUID(), json.createObjectNode(),
                fixtures.fixtureDigest(), HASH, 42L, 1), ACTOR).runId();
        events.append(run, new ExecutionEventDto.AppendRequest(null, trace,
                ExecutionEventType.RUN_STARTED, null, null, null, null,
                "DURABLE_RECEIPT_TEST", json.createObjectNode()), ACTOR);
        runs.updateStatus(run, new TestRunPersistenceDto.StatusRequest(
                TestRunStatus.PREPARING, 0, 0, null), ACTOR);
        fixtures.createOrReset(run);
        runs.updateStatus(run, new TestRunPersistenceDto.StatusRequest(
                TestRunStatus.RUNNING, 0, 0, null), ACTOR);
        UUID caseRun = runs.registerCase(run,
                new TestRunPersistenceDto.CaseRunRegisterRequest(testCase, 0, HASH), ACTOR).id();
        runs.updateCaseStatus(run, caseRun, new TestRunPersistenceDto.CaseRunStatusRequest(
                TestCaseRunStatus.EXECUTING, null, null, null, null, null, null), ACTOR);
        ObjectNode args = json.createObjectNode();
        args.putArray("customerIds").add("CUST-1001");
        args.putArray("fields").add("incomeBand");
        ExecutionEventDto.Event proposed = events.append(run,
                new ExecutionEventDto.AppendRequest(caseRun, trace, ExecutionEventType.TOOL_PROPOSED,
                        TOOL, args, null, null, "STRUCTURED_TOOL_PROPOSAL",
                        json.createObjectNode()), ACTOR);
        InvocationKey key = new InvocationKey(run, caseRun, trace, proposed.eventId(),
                proposed.payloadDigest());
        ObjectNode decision = json.createObjectNode().put("evaluationMode", evaluationMode)
                .put("decisionType", decisionType).put("allowed", allowed);
        ExecutionEventDto.Event policy = events.append(run,
                new ExecutionEventDto.AppendRequest(caseRun, trace, ExecutionEventType.POLICY_EVALUATED,
                        TOOL, null, null, decision, "TEST_POLICY", metadata(key.toolCallId())), ACTOR);
        return new Seed(workspace, run, caseRun, trace, key, policy.eventId());
    }

    private String receiptState(Seed seed) {
        return db.queryForObject("""
                select state from sandbox_tool_idempotency_records
                 where test_case_run_id = ? and tool_call_id = ?
                """, String.class, seed.caseRunId(), seed.key().toolCallId());
    }

    private int receiptCount(Seed seed) {
        return db.queryForObject("""
                select count(*) from sandbox_tool_idempotency_records
                 where test_case_run_id = ? and tool_call_id = ?
                """, Integer.class, seed.caseRunId(), seed.key().toolCallId());
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
                .hasMessage("Read-only Tool invocation receipt is incomplete")
                .hasNoCause();
    }

    private record PolicyShape(TestRunMode runMode, String evaluationMode,
            String decisionType, boolean allowed) { }

    private record Seed(UUID workspaceId, UUID runId, UUID caseRunId, UUID traceId,
            InvocationKey key, UUID policyEventId) { }
}
