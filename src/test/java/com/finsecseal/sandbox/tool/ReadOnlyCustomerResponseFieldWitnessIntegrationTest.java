package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.evidence.RedactionService;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.policy.GatewayRuntimeObservations.InvocationKey;
import com.finsecseal.policy.GatewayRuntimeObservations.StateCapture;
import com.finsecseal.runtime.ToolInvocation;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.sandbox.SandboxExecutionContext;
import com.finsecseal.sandbox.SandboxFixtureService;
import java.sql.Connection;
import java.sql.Statement;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
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
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Testcontainers
@SpringBootTest
@ExtendWith(OutputCaptureExtension.class)
class ReadOnlyCustomerResponseFieldWitnessIntegrationTest {

    private static final String HASH_A = "sha256:" + "a".repeat(64);
    private static final String HASH_B = "sha256:" + "b".repeat(64);
    private static final UUID WORKSPACE_ID = UUID.fromString("0198f1e2-0000-7000-8000-000000000001");
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
    @Autowired RedactionService redaction;
    @Autowired TestRunPersistenceService runs;
    @Autowired SandboxFixtureService fixtures;
    @MockitoSpyBean CustomerDataReadToolAdapter adapter;

    @Test
    void actualAdapterProjectionBindsOnlyReturnedNamesToSameRawDigestWithoutWrites(CapturedOutput logs) {
        UUID runId = seedRun("projection");
        ObjectNode arguments = arguments("incomeBand", "accountNumber", "requestedButMissing");
        Seed seed = seed(runId, arguments);
        String secret = db.queryForObject("""
                select profile_json ->> 'accountNumber' from sandbox_customers
                 where namespace_id = ? and customer_key = 'CUST-1002'
                """, String.class, runId);
        Map<String, String> before = sandboxState(runId);
        int eventsBefore = eventCount(runId), auditsBefore = auditCount();
        clearInvocations(adapter);

        var witness = new ReadOnlyToolResultWitnessCapture(redaction);
        UUID captureId = UUID.randomUUID();
        var captured = witness.executeCaptured(seed.key(), before(seed, captureId),
                seed.context(), seed.invocation(), adapter);
        var observed = witness.consume(seed.key(), captureId);

        verify(adapter, times(1)).execute(any(), any());
        assertThat(captured.result().stateChanged()).isFalse();
        assertThat(captured.result().output().path("rows").size()).isEqualTo(1);
        assertThat(captured.result().output().path("rows").path(0).path("fields").size()).isEqualTo(2);
        assertThat(observed.key()).isEqualTo(seed.key());
        assertThat(observed.captureId()).isEqualTo(captureId);
        assertThat(observed.rawOutputDigest()).isEqualTo(
                redaction.redact(captured.result().output().deepCopy()).originalDigest());
        var fields = observed.customerFields().orElseThrow();
        assertThat(fields.rowCount()).isEqualTo(1);
        assertThat(fields.fieldNamesByRow()).containsExactly(List.of("incomeBand", "accountNumber"));
        assertThat(fields.fieldNamesByRow().getFirst()).doesNotContain("requestedButMissing");
        assertThat(fields.toString()).doesNotContain(secret, "incomeBand", "accountNumber", "CUST-1002");
        assertThat(observed.toString()).doesNotContain(secret, "incomeBand", "accountNumber", "CUST-1002");
        assertThat(captured.toString()).doesNotContain(secret, "incomeBand", "accountNumber", "CUST-1002");
        assertThat(logs.getAll()).doesNotContain(secret);
        assertUnchanged(runId, before, eventsBefore, auditsBefore);
        assertIncomplete(() -> witness.consume(seed.key(), captureId));
    }

    @Test
    void foreignInvocationFailsBeforeAdapterAndPublishesNoMetadata() {
        UUID runId = seedRun("foreign-key");
        Seed seed = seed(runId, arguments("incomeBand"));
        InvocationKey foreign = new InvocationKey(UUID.randomUUID(), seed.key().caseRunId(),
                seed.key().traceId(), seed.key().toolCallId(), seed.key().requestDigest());
        Map<String, String> before = sandboxState(runId);
        int eventsBefore = eventCount(runId), auditsBefore = auditCount();
        clearInvocations(adapter);
        var witness = new ReadOnlyToolResultWitnessCapture(redaction);
        UUID captureId = UUID.randomUUID();

        assertIncomplete(() -> witness.executeCaptured(foreign, before(seed, captureId),
                seed.context(), seed.invocation(), adapter));
        assertIncomplete(() -> witness.consume(foreign, captureId));
        verifyNoInteractions(adapter);
        assertUnchanged(runId, before, eventsBefore, auditsBefore);
    }

    @Test
    void lockedCustomerReadFailsWithinFiniteAdapterBudgetWithoutPublishing(CapturedOutput logs)
            throws Exception {
        UUID runId = seedRun("locked-customer");
        Seed seed = seed(runId, arguments("accountNumber"));
        Map<String, String> before = sandboxState(runId);
        int eventsBefore = eventCount(runId), auditsBefore = auditCount();
        clearInvocations(adapter);
        var witness = new ReadOnlyToolResultWitnessCapture(redaction);
        UUID captureId = UUID.randomUUID();

        try (Connection lock = dataSource.getConnection()) {
            lock.setAutoCommit(false);
            try (Statement statement = lock.createStatement()) {
                statement.execute("lock table sandbox_customers in access exclusive mode");
                long started = System.nanoTime();
                assertIncomplete(() -> witness.executeCaptured(seed.key(), before(seed, captureId),
                        seed.context(), seed.invocation(), adapter));
                assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(12));
            } finally {
                lock.rollback();
            }
        }

        assertIncomplete(() -> witness.consume(seed.key(), captureId));
        // The adapter can spend the witness's entire 5 s TTL on the lock; post-TTL idempotency is separate.
        verify(adapter, times(1)).execute(any(), any());
        assertThat(logs.getAll()).doesNotContain("SYNTH-ACCT-1002");
        assertUnchanged(runId, before, eventsBefore, auditsBefore);
    }

    private UUID seedRun(String suffix) {
        UUID agent = UUID.randomUUID(), release = UUID.randomUUID(), suite = UUID.randomUUID();
        String key = suffix + '-' + agent.toString().substring(0, 8);
        db.update("""
                insert into agents(id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'B witness agent', 'Customer response field witness test', 'ACTIVE')
                """, agent, WORKSPACE_ID, "b-field-witness-agent-" + key);
        db.update("""
                insert into agent_releases(id, agent_id, version, business_purpose,
                    manifest_schema_version, manifest_json, agent_artifact_fingerprint,
                    release_fingerprint, lifecycle_state, effective_status)
                values (?, ?, '1.0.0', 'LOAN_DOCUMENT_COMPLETENESS_REVIEW', '1.0',
                    '{}'::jsonb, ?, ?, 'ANALYZED', 'ANALYZED')
                """, release, agent, HASH_A, HASH_A);
        db.update("""
                insert into test_suites(id, workspace_id, suite_key, version, fixture_version,
                    generation_config_json, suite_hash, status)
                values (?, ?, ?, '1.0.0', 'golden-v1', '{}'::jsonb, ?, 'READY')
                """, suite, WORKSPACE_ID, "b-field-witness-suite-" + key, HASH_B);
        UUID runId = runs.register(new TestRunPersistenceDto.RegisterRequest(
                release, suite, null, TestRunMode.BASELINE, UUID.randomUUID(),
                json.createObjectNode().put("schemaVersion", "1.0"),
                fixtures.fixtureDigest(), HASH_B, 42L, 1), "role-b").runId();
        fixtures.createOrReset(runId);
        return runId;
    }

    private Seed seed(UUID runId, ObjectNode arguments) {
        UUID caseRunId = UUID.randomUUID(), traceId = UUID.randomUUID();
        SandboxExecutionContext context = new SandboxExecutionContext(runId, caseRunId, traceId,
                TestRunMode.BASELINE, "CASE-1001", "CUST-1001");
        InvocationKey key = new InvocationKey(runId, caseRunId, traceId,
                UUID.randomUUID(), HASH_A);
        ToolInvocation invocation = new ToolInvocation(
                new ToolProposal(CustomerDataReadToolAdapter.TOOL_NAME, arguments),
                key.toolCallId(), key.requestDigest());
        return new Seed(context, key, invocation);
    }

    /** Synthetic pre-state satisfies this B witness API; it does not certify C full namespace capture. */
    private StateCapture before(Seed seed, UUID captureId) {
        return new StateCapture(seed.key(), captureId, seed.context().namespaceId(), HASH_B, true);
    }

    private ObjectNode arguments(String... fields) {
        ObjectNode arguments = json.createObjectNode();
        arguments.putArray("customerIds").add("CUST-1002");
        var projected = arguments.putArray("fields");
        for (String field : fields) projected.add(field);
        return arguments;
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

    private void assertUnchanged(UUID runId, Map<String, String> before,
            int eventsBefore, int auditsBefore) {
        assertThat(sandboxState(runId)).isEqualTo(before);
        assertThat(eventCount(runId)).isEqualTo(eventsBefore);
        assertThat(auditCount()).isEqualTo(auditsBefore);
        assertThat(eventTypeCount(runId, ExecutionEventType.TOOL_REQUEST)).isZero();
        assertThat(eventTypeCount(runId, ExecutionEventType.TOOL_RESPONSE)).isZero();
        assertThat(eventTypeCount(runId, ExecutionEventType.SANDBOX_STATE_CHANGED)).isZero();
    }

    private int eventCount(UUID runId) {
        return db.queryForObject("select count(*) from execution_events where run_id = ?",
                Integer.class, runId);
    }

    private int eventTypeCount(UUID runId, ExecutionEventType type) {
        return db.queryForObject("select count(*) from execution_events where run_id = ? and event_type = ?",
                Integer.class, runId, type.name());
    }

    private int auditCount() {
        return db.queryForObject("select count(*) from audit_records where workspace_id = ?",
                Integer.class, WORKSPACE_ID);
    }

    private static void assertIncomplete(org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).isInstanceOfSatisfying(BusinessException.class, failure -> {
            assertThat(failure.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE);
            assertThat(failure.getMessage()).isEqualTo("Read-only Tool result witness is incomplete");
            assertThat(failure.getCause()).isNull();
        });
    }

    private record Seed(SandboxExecutionContext context, InvocationKey key, ToolInvocation invocation) { }
}
