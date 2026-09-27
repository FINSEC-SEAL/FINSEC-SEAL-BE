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
class CustomerDataReadToolAdapterDeadlineIntegrationTest {

    private static final String HASH_A = "sha256:" + "a".repeat(64);
    private static final String HASH_B = "sha256:" + "b".repeat(64);
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
    @Autowired CustomerDataReadToolAdapter adapter;

    @Test
    void twentyCustomerIdsKeepOrderDuplicatesAndOutputUnderBoundWithoutWrites() {
        UUID run = seedRun("twenty");
        fixtures.createOrReset(run);
        ObjectNode arguments = arguments("incomeBand", "employmentStatus", "incomeBand");
        var ids = arguments.putArray("customerIds");
        for (int index = 0; index < 20; index++) ids.add(index % 2 == 0 ? "CUST-1002" : "CUST-1003");

        String businessBefore = customerRows(run);
        int eventsBefore = eventCount(run), auditsBefore = auditCount();
        String timeoutBefore = db.queryForObject("show statement_timeout", String.class);
        var result = adapter.execute(context(run), arguments);

        assertThat(result.stateChanged()).isFalse();
        assertThat(result.output().path("status").asInt()).isEqualTo(200);
        assertThat(result.output().path("rows").size()).isEqualTo(20);
        for (int index = 0; index < 20; index++) {
            var row = result.output().path("rows").path(index);
            assertThat(row.path("customerId").asString())
                    .isEqualTo(index % 2 == 0 ? "CUST-1002" : "CUST-1003");
            assertThat(row.path("fields").path("incomeBand").asString())
                    .isEqualTo(index % 2 == 0 ? "HIGH" : "LOW");
            assertThat(row.path("fields").path("employmentStatus").asString())
                    .isEqualTo(index % 2 == 0 ? "EMPLOYED" : "SELF_EMPLOYED");
            assertThat(row.path("fields").size()).isEqualTo(2);
            String fieldsJson = json.writeValueAsString(row.path("fields"));
            assertThat(fieldsJson.indexOf("incomeBand"))
                    .isLessThan(fieldsJson.indexOf("employmentStatus"));
        }
        assertThat(json.writeValueAsString(result.output()).getBytes(StandardCharsets.UTF_8).length)
                .isLessThanOrEqualTo(1024 * 1024);
        assertThat(customerRows(run)).isEqualTo(businessBefore);
        assertThat(eventCount(run)).isEqualTo(eventsBefore);
        assertThat(auditCount()).isEqualTo(auditsBefore);
        assertThat(db.queryForObject("show statement_timeout", String.class)).isEqualTo(timeoutBefore);
    }

    @Test
    void oversizedStoredProfileFailsClosedBeforeRawProjection(CapturedOutput output) {
        UUID run = seedRun("oversize");
        fixtures.createOrReset(run);
        String privateValue = "PRIVATE-B17-CUSTOMER-";
        db.update("""
                update sandbox_customers
                   set profile_json = jsonb_set(profile_json, '{incomeBand}',
                       to_jsonb(repeat(?, 2000)))
                 where namespace_id = ? and customer_key = 'CUST-1002'
                """, privateValue, run);
        int eventsBefore = eventCount(run), auditsBefore = auditCount();

        assertIncompleteWithout(privateValue,
                () -> adapter.executeWithin(context(run), arguments("incomeBand"), DEADLINE));
        assertThat(output.getAll()).doesNotContain(privateValue);
        assertThat(eventCount(run)).isEqualTo(eventsBefore);
        assertThat(auditCount()).isEqualTo(auditsBefore);
    }

    @Test
    void readsOnlyTheServerNamespaceAndKeepsMissingIdsOmitted() {
        UUID observed = seedRun("namespace-observed"), other = seedRun("namespace-other");
        fixtures.createOrReset(observed);
        fixtures.createOrReset(other);
        db.update("""
                update sandbox_customers
                   set profile_json = jsonb_set(profile_json, '{incomeBand}', '"B_ONLY"'::jsonb)
                 where namespace_id = ? and customer_key = 'CUST-1002'
                """, other);
        ObjectNode arguments = arguments("incomeBand");
        arguments.putArray("customerIds").add("MISSING").add("CUST-1002");

        var rows = adapter.executeWithin(context(observed), arguments, DEADLINE).output().path("rows");

        assertThat(rows.size()).isEqualTo(1);
        assertThat(rows.path(0).path("customerId").asString()).isEqualTo("CUST-1002");
        assertThat(rows.path(0).path("fields").path("incomeBand").asString()).isEqualTo("HIGH");
    }

    @Test
    void invalidDeadlinesAndOuterTransactionFailBeforeAnyRead() {
        UUID run = seedRun("invalid-deadline");
        fixtures.createOrReset(run);
        var context = context(run);
        var arguments = arguments("incomeBand");
        String before = customerRows(run);
        int eventsBefore = eventCount(run);

        assertIncomplete(() -> adapter.executeWithin(context, arguments, null));
        assertIncomplete(() -> adapter.executeWithin(context, arguments, Duration.ZERO));
        assertIncomplete(() -> adapter.executeWithin(context, arguments, Duration.ofMillis(900)));
        assertIncomplete(() -> adapter.executeWithin(context, arguments, Duration.ofSeconds(6)));
        assertIncomplete(() -> adapter.executeWithin(null, arguments, DEADLINE));
        assertIncomplete(() -> new TransactionTemplate(transactions).execute(status ->
                adapter.executeWithin(context, arguments, DEADLINE)));
        assertThat(customerRows(run)).isEqualTo(before);
        assertThat(eventCount(run)).isEqualTo(eventsBefore);
    }

    @Test
    void blockedPostgresSelectTimesOutAndNextCallRestoresNormalRead() throws Exception {
        UUID run = seedRun("blocked-select");
        fixtures.createOrReset(run);
        var context = context(run);
        var arguments = arguments("incomeBand");
        String timeoutBefore = db.queryForObject("show statement_timeout", String.class);
        int eventsBefore = eventCount(run);
        try (Connection lock = dataSource.getConnection()) {
            lock.setAutoCommit(false);
            try (Statement statement = lock.createStatement()) {
                statement.execute("lock table sandbox_customers in access exclusive mode");
                long start = System.nanoTime();
                assertIncomplete(() -> adapter.executeWithin(context, arguments, Duration.ofSeconds(2)));
                assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(8));
            } finally {
                lock.rollback();
            }
        }

        assertThat(adapter.execute(context, arguments).output().path("rows").size()).isEqualTo(1);
        assertThat(db.queryForObject("show statement_timeout", String.class)).isEqualTo(timeoutBefore);
        assertThat(eventCount(run)).isEqualTo(eventsBefore);
    }

    @Test
    void postCommitClockExpiryNeverReturnsCustomerResult() {
        UUID run = seedRun("post-commit");
        fixtures.createOrReset(run);
        AtomicInteger outsideReads = new AtomicInteger();
        LongSupplier clock = () -> {
            if (TransactionSynchronizationManager.isActualTransactionActive()) return 0L;
            return outsideReads.incrementAndGet() >= 3
                    ? TimeUnit.SECONDS.toNanos(6) : 0L;
        };
        var expiring = new CustomerDataReadToolAdapter(dataSource, json, transactions, clock);
        String businessBefore = customerRows(run);
        int eventsBefore = eventCount(run);

        assertIncomplete(() -> expiring.executeWithin(context(run), arguments("incomeBand"), DEADLINE));
        assertThat(outsideReads.get()).isGreaterThanOrEqualTo(3);
        assertThat(customerRows(run)).isEqualTo(businessBefore);
        assertThat(eventCount(run)).isEqualTo(eventsBefore);
    }

    private ObjectNode arguments(String... fields) {
        ObjectNode arguments = json.createObjectNode();
        arguments.putArray("customerIds").add("CUST-1002");
        var projected = arguments.putArray("fields");
        for (String field : fields) projected.add(field);
        return arguments;
    }

    private SandboxExecutionContext context(UUID run) {
        return new SandboxExecutionContext(run, UUID.randomUUID(), UUID.randomUUID(),
                TestRunMode.BASELINE, "CASE-1001", "CUST-1001");
    }

    private UUID seedRun(String suffix) {
        UUID agent = UUID.randomUUID(), release = UUID.randomUUID(), suite = UUID.randomUUID();
        String key = suffix + '-' + agent.toString().substring(0, 8);
        db.update("""
                insert into agents(id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'B deadline agent', 'Customer read deadline test', 'ACTIVE')
                """, agent, WORKSPACE_ID, "b-deadline-agent-" + key);
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
                """, suite, WORKSPACE_ID, "b-deadline-suite-" + key, HASH_B);
        return runs.register(new TestRunPersistenceDto.RegisterRequest(
                release, suite, null, TestRunMode.BASELINE, UUID.randomUUID(),
                json.createObjectNode().put("schemaVersion", "1.0"),
                fixtures.fixtureDigest(), HASH_B, 42L, 1), "role-b").runId();
    }

    private String customerRows(UUID run) {
        return db.queryForObject("""
                select coalesce(jsonb_agg(to_jsonb(customer) order by customer_key)::text, '[]')
                  from sandbox_customers customer where namespace_id = ?
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
                .hasMessage("CUSTOMER_DATA_READ execution is incomplete")
                .hasNoCause();
    }

    private static void assertIncompleteWithout(String privateValue,
            org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).isInstanceOf(BusinessException.class)
                .hasMessage("CUSTOMER_DATA_READ execution is incomplete")
                .satisfies(error -> assertThat(error.toString()).doesNotContain(privateValue))
                .hasNoCause();
    }
}
