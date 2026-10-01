package com.finsecseal.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.ArgumentMatchers.any;

import com.finsecseal.agent.AgentService;
import com.finsecseal.agent.AgentDto;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.ReleaseLifecycleState;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.contract.LoanReviewFinancialTemplate;
import com.finsecseal.evidence.AuthenticatedTestRunRegistrationService;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.evidence.RedactionService;
import com.finsecseal.evidence.StoredRunReviewerAuthoritySource;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.evidence.TestRunProjectionService;
import com.finsecseal.platform.contract.ContractReviewerCredentials;
import com.finsecseal.platform.contract.ContractPersistenceService;
import com.finsecseal.platform.contract.ContractReviewerSessionRevocations;
import com.finsecseal.policy.GatewayRuntimeObservations.InvocationKey;
import com.finsecseal.policy.LoanReviewPolicyGateway.FailureCode;
import com.finsecseal.policy.LoanReviewPolicyGateway.GatewayException;
import com.finsecseal.release.ReleaseService;
import com.finsecseal.runtime.ToolInvocation;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.sandbox.SandboxExecutionContext;
import com.finsecseal.sandbox.SandboxFixtureService;
import com.finsecseal.sandbox.tool.StateChangingToolExecutionService;
import com.finsecseal.sandbox.tool.StoredGatewayPreCallScopeSource;
import com.finsecseal.sandbox.tool.ToolAdapter;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.http.Cookie;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.UnaryOperator;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.AbstractDataSource;
import org.springframework.jdbc.datasource.ConnectionHolder;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Testcontainers
@SpringBootTest(properties = {
        "finsec.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "finsec.scheduling.enabled=false",
        "finsec.contract-access.key=test-reviewer-key-at-least-32-bytes-long",
        "finsec.contract-access.actor=stored-gateway-reviewer",
        "finsec.contract-access.workspace=0198f1e2-0000-7000-8000-000000000001",
        "spring.datasource.hikari.connection-timeout=2000"
})
class StoredGatewayReviewerContextSourceIntegrationTest {
    private static final String ACTOR = "stored-gateway-reviewer";
    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final String OTHER_HASH = "sha256:" + "b".repeat(64);
    private static final String FAILURE_EVENTS = "finsec.policy.gateway.reviewer.failure.events";
    // Fixed table/key allowlist; no SQL identifier comes from a request or fixture value.
    private static final List<SnapshotTable> SNAPSHOT_TABLES = List.of(
            new SnapshotTable("test_runs", "t.id"),
            new SnapshotTable("test_case_runs", "t.id"),
            new SnapshotTable("test_run_reviewer_grants", "t.run_id"),
            new SnapshotTable("reviewer_session_revocations", "t.session_digest"),
            new SnapshotTable("sandbox_namespaces", "t.id"),
            new SnapshotTable("sandbox_customers", "t.namespace_id, t.customer_key"),
            new SnapshotTable("sandbox_loan_cases", "t.namespace_id, t.case_key"),
            new SnapshotTable("sandbox_documents", "t.namespace_id, t.document_key"),
            new SnapshotTable("sandbox_loan_policies", "t.namespace_id, t.policy_key, t.version"),
            new SnapshotTable("sandbox_review_notes", "t.namespace_id, t.note_key"),
            new SnapshotTable("sandbox_loan_decisions", "t.namespace_id, t.case_key"),
            new SnapshotTable("sandbox_exfil_events", "t.namespace_id, t.event_key"),
            new SnapshotTable("execution_events", "t.run_id, t.sequence"),
            new SnapshotTable("run_event_counters", "t.run_id"),
            new SnapshotTable("sandbox_tool_idempotency_records", "t.id"),
            new SnapshotTable("audit_records", "t.id"));

    @Container @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired HikariDataSource dataSource;
    @Autowired AgentService agents;
    @Autowired ReleaseService releases;
    @Autowired ContractPersistenceService contracts;
    @Autowired PlatformTransactionManager ownerTransactions;
    @Autowired JdbcTemplate db;
    @Autowired ObjectMapper json;
    @Autowired ContractReviewerCredentials credentials;
    @Autowired ContractReviewerSessionRevocations revocations;
    @Autowired AuthenticatedTestRunRegistrationService admission;
    @Autowired TestRunPersistenceService runs;
    @Autowired ExecutionEventService events;
    @Autowired SandboxFixtureService fixtures;
    @Autowired StoredRunReviewerAuthoritySource authorities;
    @Autowired StoredGatewayPreCallScopeSource scopes;

    @Test
    void signedAdmissionAndActiveNamespaceResolveOneExactProposalWithoutWrites() {
        Fixture fixture = fixture();
        Counts before = counts(fixture);
        StoredGatewayReviewerContextSource reviewerSource = source();
        var resolution = reviewerSource.resolve(fixture.key(), Duration.ofSeconds(5));

        assertThat(resolution).isNotNull();
        assertThat(resolution.key()).isEqualTo(fixture.key());
        assertThat(resolution.reviewer().workspaceId()).isEqualTo(AgentService.DEMO_WORKSPACE_ID);
        assertThat(resolution.reviewer().actorId()).isEqualTo(ACTOR);
        assertThat(resolution.reviewer().role()).isEqualTo("AI_SECURITY_REVIEWER");
        assertThat(resolution.reviewer().sessionId())
                .isEqualTo(revocations.sessionDigest(fixture.session()))
                .matches("sha256:[0-9a-f]{64}");
        assertThat(resolution.reviewer().authenticated()).isTrue();
        assertThat(resolution.reviewer().csrfVerified()).isTrue();
        assertThat(resolution.reviewer().demoMode()).isFalse();
        assertThat(dataSource.getHikariPoolMXBean().getActiveConnections()).isZero();
        // Each successful read retires its lease; the next call must still acquire a healthy one.
        assertThat(reviewerSource.resolve(fixture.key(), Duration.ofSeconds(5))).isEqualTo(resolution);
        assertThat(dataSource.getHikariPoolMXBean().getActiveConnections()).isZero();
        assertThat(counts(fixture)).isEqualTo(before);
    }

    @Test
    @Timeout(20)
    void authorityThatExpiresDuringRollbackCannotEscapeFinalReturn() throws Exception {
        var probe = new RollbackExpiryProbe();
        try (HikariDataSource isolated = expiryRollbackPool(probe)) {
            var ownerA = spy(new StoredRunReviewerAuthoritySource(isolated, credentials));
            var ownerB = spy(new StoredGatewayPreCallScopeSource(isolated, json));
            AtomicBoolean authorityRead = new AtomicBoolean();
            AtomicBoolean scopeRead = new AtomicBoolean();
            doAnswer(call -> {
                var snapshot = call.callRealMethod();
                authorityRead.set(snapshot != null);
                return snapshot;
            }).when(ownerA).resolve(any(InvocationKey.class), any(Duration.class));
            doAnswer(call -> {
                var snapshot = call.callRealMethod();
                scopeRead.set(snapshot != null);
                return snapshot;
            }).when(ownerB).resolve(any(InvocationKey.class), any(Duration.class));
            var reviewers = new StoredGatewayReviewerContextSource(isolated, ownerA, ownerB);
            Fixture expiring = fixture(Duration.ofSeconds(2));
            Counts before = counts(expiring);
            probe.expiration.set(grantExpiration(expiring));
            long started = System.nanoTime();
            var expired = reviewers.resolve(expiring.key(), Duration.ofSeconds(5));
            Duration elapsed = Duration.ofNanos(System.nanoTime() - started);

            assertThat(authorityRead).isTrue();
            assertThat(scopeRead).isTrue();
            assertThat(probe.injected).isTrue();
            assertThat(probe.liveBeforeRollback).isTrue();
            assertThat(probe.expiredAfterRollback).isTrue();
            // The shared deadline still has time left: expiry, rather than timeout,
            // must suppress the result after a real PostgreSQL rollback boundary.
            assertThat(elapsed).isBetween(Duration.ofSeconds(3), Duration.ofMillis(4_750));
            assertThat(expired).isNull();
            assertThat(isolated.getHikariPoolMXBean().getActiveConnections()).isZero();
            assertThat(counts(expiring)).isEqualTo(before);

            Fixture healthy = fixture();
            Counts healthyBefore = counts(healthy);
            probe.expiration.set(grantExpiration(healthy));
            probe.injected.set(false);
            probe.liveBeforeRollback.set(false);
            probe.expiredAfterRollback.set(false);
            authorityRead.set(false);
            scopeRead.set(false);
            assertThat(reviewers.resolve(healthy.key(), Duration.ofSeconds(5))).isNotNull();
            assertThat(authorityRead).isTrue();
            assertThat(scopeRead).isTrue();
            assertThat(probe.injected).isTrue();
            assertThat(probe.liveBeforeRollback).isTrue();
            assertThat(probe.expiredAfterRollback).isFalse();
            assertThat(isolated.getHikariPoolMXBean().getActiveConnections()).isZero();
            assertThat(reviewers.resolve(healthy.key(), Duration.ofSeconds(5))).isNotNull();
            assertThat(counts(healthy)).isEqualTo(healthyBefore);
        }
    }

    @ParameterizedTest
    @EnumSource(ResetAt.class)
    void swallowedResetFailureRetiresItsExactLeaseAndAllowsOneFreshHealthyRead(ResetAt reset) throws Exception {
        Fixture fixture = fixture(TestRunMode.BASELINE);
        StoredDigest before = storedDigest();
        ResetFailureProbe probe = new ResetFailureProbe();
        try (HikariDataSource pool = resetFailurePool(reset, probe)) {
            var ownerA = spy(new StoredRunReviewerAuthoritySource(pool, credentials));
            var ownerB = spy(new StoredGatewayPreCallScopeSource(pool, json));
            doAnswer(call -> {
                Object result = call.callRealMethod();
                probe.authorityRead.set(result != null);
                return result;
            }).when(ownerA).resolve(any(InvocationKey.class), any(Duration.class));
            doAnswer(call -> {
                Object result = call.callRealMethod();
                probe.scopeRead.set(result != null);
                return result;
            }).when(ownerB).resolve(any(InvocationKey.class), any(Duration.class));
            var reviewers = new StoredGatewayReviewerContextSource(pool, ownerA, ownerB);
            long started = System.nanoTime();
            var resolution = reviewers.resolve(fixture.key(), Duration.ofSeconds(5));
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(5));
            assertThat(probe.authorityRead).isTrue();
            assertThat(probe.scopeRead).isTrue();
            assertThat(probe.injected).isTrue();
            assertThat(probe.defaults).containsExactly(new ConnectionDefaults(true, false,
                    Connection.TRANSACTION_READ_COMMITTED));
            assertThat(probe.rollbacks).hasSize(1);
            assertThat(resolution).isNotNull();
            assertThat(resolution.key()).isEqualTo(fixture.key());
            assertThat(resolution.reviewer().actorId()).isEqualTo(ACTOR);
            assertThat(resolution.reviewer().workspaceId()).isEqualTo(AgentService.DEMO_WORKSPACE_ID);
            assertThat(resolution.reviewer().role()).isEqualTo("AI_SECURITY_REVIEWER");
            assertThat(resolution.reviewer().sessionId()).isEqualTo(revocations.sessionDigest(fixture.session()));
            assertThat(resolution.reviewer().authenticated()).isTrue();
            assertThat(resolution.reviewer().csrfVerified()).isTrue();
            assertThat(resolution.reviewer().demoMode()).isFalse();
            assertThat(probe.borrowed).hasSize(1);
            assertThat(probe.retired).containsExactly(probe.borrowed.getFirst());

            long cleanupDeadline = awaitDeadlineLeases(pool);
            while (!probe.closedSuccessfully.get() && System.nanoTime() < cleanupDeadline) Thread.sleep(20);
            assertThat(probe.closedSuccessfully).isTrue();
            assertThat(probe.faultedPhysical.get().isClosed()).isTrue();
            assertThat(storedDigest()).isEqualTo(before);
            assertThat(Duration.ofNanos(cleanupDeadline - System.nanoTime())).isGreaterThan(Duration.ofSeconds(1));
            Duration remaining = Duration.ofNanos(Math.min(Duration.ofSeconds(5).toNanos(),
                    cleanupDeadline - System.nanoTime()));
            var healthy = reviewers.resolve(fixture.key(), remaining);
            assertThat(healthy).isNotNull();
            assertThat(healthy.key()).isEqualTo(fixture.key());
            assertThat(healthy.reviewer()).isEqualTo(resolution.reviewer());
            assertThat(System.nanoTime()).isLessThan(cleanupDeadline);
            assertThat(probe.rollbacks).hasSize(2);
            assertThat(probe.rollbacks.getLast()).isNotSameAs(probe.faultedPhysical.get());
            assertThat(probe.borrowed).hasSize(2);
            assertThat(probe.retired).containsExactlyElementsOf(probe.borrowed);
            assertThat(pool.getHikariPoolMXBean().getActiveConnections()).isZero();
            assertThat(deadlineSlots().availablePermits()).isEqualTo(2);
            assertThat(storedDigest()).isEqualTo(before);
        }
    }

    @Test
    void diagnosticsUseOnlyFixedOperationalEventNamesAndTags() throws Exception {
        try (OperationalDiagnostics diagnostics = new OperationalDiagnostics()) {
            assertThat(diagnostics.registry.getMeters()).hasSize(7);
            assertThat(diagnostics.registry.getMeters()).allSatisfy(meter -> {
                assertThat(meter.getId().getName()).isEqualTo(FAILURE_EVENTS);
                assertThat(meter.getId().getTags()).hasSize(1);
                assertThat(meter.getId().getTags().getFirst().getKey()).isEqualTo("reason");
                assertThat(meter.getId().getType()).isEqualTo(io.micrometer.core.instrument.Meter.Type.COUNTER);
            });
            assertThat(diagnostics.registry.getMeters().stream()
                    .map(meter -> meter.getId().getTag("reason")).toList())
                    .containsExactlyInAnyOrder("deadline_capacity", "interrupted", "caller_timeout",
                            "execution_failure", "resolution_failure", "retirement_failure", "abort_failure");
        }
    }

    @Test
    void unavailableDiagnosticRegistrationCannotChangeAuthorityOrPublicFailureSemantics() throws Exception {
        Fixture fixture = fixture(TestRunMode.BASELINE);
        StoredDigest before = storedDigest();
        MeterRegistry unavailable = mock(MeterRegistry.class);
        org.mockito.Mockito.when(unavailable.more())
                .thenThrow(new IllegalArgumentException("private-registry-canary"));
        Method registration = StoredGatewayReviewerContextSource.class
                .getDeclaredMethod("registerDiagnostics", MeterRegistry.class);
        registration.setAccessible(true);
        registration.invoke(null, unavailable);
        var reviewers = source();
        var healthy = reviewers.resolve(fixture.key(), Duration.ofSeconds(5));
        assertThat(healthy).isNotNull();
        assertThat(healthy.key()).isEqualTo(fixture.key());
        assertThat(healthy.reviewer().actorId()).isEqualTo(ACTOR);
        awaitDeadlineLeases(dataSource);
        assertThat(storedDigest()).isEqualTo(before);
        var badKey = new InvocationKey(fixture.key().runId(), fixture.key().caseRunId(),
                fixture.key().traceId(), fixture.key().toolCallId(), OTHER_HASH);
        GatewayProbe gateway = gatewayProbe(reviewers);
        var badInvocation = new ToolInvocation(fixture.invocation().proposal(), badKey.toolCallId(), OTHER_HASH);
        Fixture forged = new Fixture(badKey, fixture.session(), fixture.context(), badInvocation);
        GatewayException failure = assertThrows(GatewayException.class,
                () -> gateway.gateway().invoke(fixture.context(), badInvocation, ACTOR));
        assertPreAdmissionFailure(gateway, forged, failure, FailureCode.AUTHENTICATION_REQUIRED);
        awaitDeadlineLeases(dataSource);
        assertThat(storedDigest()).isEqualTo(before);
        org.mockito.Mockito.verify(unavailable, org.mockito.Mockito.times(7)).more();
    }

    private enum ResetAt { AUTO_COMMIT, ISOLATION, READ_ONLY }
    private record ConnectionDefaults(boolean autoCommit, boolean readOnly, int isolation) { }
    private static final class ResetFailureProbe {
        private final AtomicBoolean authorityRead = new AtomicBoolean();
        private final AtomicBoolean scopeRead = new AtomicBoolean();
        private final AtomicBoolean injected = new AtomicBoolean();
        private final AtomicBoolean closedSuccessfully = new AtomicBoolean();
        private final AtomicReference<Connection> faultedPhysical = new AtomicReference<>();
        private final List<Connection> rollbacks = new CopyOnWriteArrayList<>();
        private final List<Connection> borrowed = new CopyOnWriteArrayList<>();
        private final List<Connection> retired = new CopyOnWriteArrayList<>();
        private final List<ConnectionDefaults> defaults = new CopyOnWriteArrayList<>();
    }

    private HikariDataSource resetFailurePool(ResetAt reset, ResetFailureProbe probe) {
        DataSource physical = new AbstractDataSource() {
            @Override public Connection getConnection() throws SQLException {
                Connection delegate = DriverManager.getConnection(POSTGRES.getJdbcUrl(),
                        POSTGRES.getUsername(), POSTGRES.getPassword());
                AtomicBoolean rolledBack = new AtomicBoolean();
                return (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                        new Class<?>[] {Connection.class}, (proxy, method, arguments) -> {
                            boolean resetting = arguments != null && arguments.length == 1 && switch (reset) {
                                case AUTO_COMMIT -> method.getName().equals("setAutoCommit") && Boolean.TRUE.equals(arguments[0]);
                                case ISOLATION -> method.getName().equals("setTransactionIsolation")
                                        && Integer.valueOf(Connection.TRANSACTION_READ_COMMITTED).equals(arguments[0]);
                                case READ_ONLY -> method.getName().equals("setReadOnly") && Boolean.FALSE.equals(arguments[0]);
                            };
                            if (resetting && rolledBack.get() && probe.authorityRead.get() && probe.scopeRead.get()
                                    && probe.injected.compareAndSet(false, true)) {
                                probe.faultedPhysical.set(delegate);
                                // No fatal SQLState: observe provider retirement, not driver broken-connection eviction.
                                throw new SQLException("private-reset-canary");
                            }
                            Object value = invoke(delegate, method, arguments);
                            if (method.getName().equals("rollback")) {
                                rolledBack.set(true);
                                probe.rollbacks.add(delegate);
                            }
                            if (method.getName().equals("close") && delegate == probe.faultedPhysical.get()
                                    && delegate.isClosed()) probe.closedSuccessfully.set(true);
                            return value;
                        });
            }
            @Override public Connection getConnection(String username, String password) throws SQLException {
                return getConnection();
            }
        };
        HikariConfig config = new HikariConfig();
        config.setDataSource(physical);
        config.setMaximumPoolSize(1);
        config.setMinimumIdle(0);
        config.setConnectionTimeout(1_000);
        return new HikariDataSource(config) {
            @Override public Connection getConnection() throws SQLException {
                Connection connection = super.getConnection();
                probe.borrowed.add(connection);
                probe.defaults.add(new ConnectionDefaults(connection.getAutoCommit(), connection.isReadOnly(),
                        connection.getTransactionIsolation()));
                return connection;
            }
            @Override public void evictConnection(Connection connection) {
                probe.retired.add(connection);
                super.evictConnection(connection);
            }
        };
    }

    private static final class OperationalDiagnostics implements AutoCloseable {
        private final SimpleMeterRegistry registry = new SimpleMeterRegistry();
        private OperationalDiagnostics() throws ClassNotFoundException {
            Class.forName(StoredGatewayReviewerContextSource.class.getName());
            Metrics.addRegistry(registry);
        }
        private double count(String reason) {
            return registry.get(FAILURE_EVENTS).tag("reason", reason).functionCounter().count();
        }
        @Override public void close() {
            Metrics.removeRegistry(registry);
            registry.close();
        }
    }

    private Semaphore deadlineSlots() throws Exception {
        var field = StoredGatewayReviewerContextSource.class.getDeclaredField("DEADLINE_SLOTS");
        field.setAccessible(true);
        return (Semaphore) field.get(null);
    }

    private Instant grantExpiration(Fixture fixture) {
        return db.queryForObject("select authority_expires_at from test_run_reviewer_grants where run_id = ?",
                Timestamp.class, fixture.key().runId()).toInstant();
    }

    private HikariDataSource expiryRollbackPool(RollbackExpiryProbe probe) {
        DataSource physical = new AbstractDataSource() {
            @Override public Connection getConnection() throws SQLException {
                Connection delegate = DriverManager.getConnection(POSTGRES.getJdbcUrl(),
                        POSTGRES.getUsername(), POSTGRES.getPassword());
                return (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                        new Class<?>[] {Connection.class}, (proxy, method, arguments) -> {
                            if (method.getName().equals("rollback") && probe.injected.compareAndSet(false, true)) {
                                probe.liveBeforeRollback.set(Instant.now().isBefore(probe.expiration.get()));
                                try (Statement statement = delegate.createStatement()) {
                                    statement.execute("select pg_sleep(3)");
                                }
                                probe.expiredAfterRollback.set(!Instant.now().isBefore(probe.expiration.get()));
                            }
                            return invoke(delegate, method, arguments);
                        });
            }

            @Override public Connection getConnection(String username, String password) throws SQLException {
                return getConnection();
            }
        };
        HikariConfig config = new HikariConfig();
        config.setDataSource(physical);
        config.setMaximumPoolSize(1);
        config.setMinimumIdle(0);
        config.setConnectionTimeout(1_000);
        return new HikariDataSource(config);
    }

    private static final class RollbackExpiryProbe {
        private final AtomicReference<Instant> expiration = new AtomicReference<>();
        private final AtomicBoolean injected = new AtomicBoolean();
        private final AtomicBoolean liveBeforeRollback = new AtomicBoolean();
        private final AtomicBoolean expiredAfterRollback = new AtomicBoolean();
    }

    @Test
    void mismatchedProposalFieldsAndCrossRunKeysNeverBorrowAuthority() {
        Fixture first = fixture();
        Fixture second = fixture();
        Counts before = counts(first);
        InvocationKey key = first.key();
        for (InvocationKey wrong : List.of(
                new InvocationKey(UUID.randomUUID(), key.caseRunId(), key.traceId(), key.toolCallId(), key.requestDigest()),
                new InvocationKey(key.runId(), UUID.randomUUID(), key.traceId(), key.toolCallId(), key.requestDigest()),
                new InvocationKey(key.runId(), key.caseRunId(), UUID.randomUUID(), key.toolCallId(), key.requestDigest()),
                new InvocationKey(key.runId(), key.caseRunId(), key.traceId(), UUID.randomUUID(), key.requestDigest()),
                new InvocationKey(key.runId(), key.caseRunId(), key.traceId(), key.toolCallId(), OTHER_HASH),
                new InvocationKey(key.runId(), second.key().caseRunId(), key.traceId(),
                        second.key().toolCallId(), second.key().requestDigest()))) {
            assertThat(source().resolve(wrong, Duration.ofSeconds(5))).isNull();
        }
        assertThat(counts(first)).isEqualTo(before);
    }

    @Test
    void bothActualOwnerQueriesShareOneFreshReadOnlyRepeatableReadConnectionAndDecliningBudgets() throws Exception {
        Fixture fixture = fixture();
        List<OwnerRead> reads = new CopyOnWriteArrayList<>();
        try (CountingPool pool = observedPool(reads)) {
            var ownerA = spy(new StoredRunReviewerAuthoritySource(pool, credentials));
            var ownerB = spy(new StoredGatewayPreCallScopeSource(pool, json));
            AtomicReference<Duration> budgetA = new AtomicReference<>(), budgetB = new AtomicReference<>();
            doAnswer(call -> { budgetA.set(call.getArgument(1)); return call.callRealMethod(); })
                    .when(ownerA).resolve(any(InvocationKey.class), any(Duration.class));
            doAnswer(call -> { budgetB.set(call.getArgument(1)); return call.callRealMethod(); })
                    .when(ownerB).resolve(any(InvocationKey.class), any(Duration.class));
            var source = new StoredGatewayReviewerContextSource(pool, ownerA, ownerB);
            StoredDigest before = storedDigest();
            assertThat(source.resolve(fixture.key(), Duration.ofSeconds(5))).isNotNull();
            assertOwnerReads(reads, pool, 1);
            assertThat(budgetA.get()).isLessThan(Duration.ofSeconds(5));
            assertThat(budgetB.get()).isLessThan(budgetA.get()).isGreaterThan(Duration.ofSeconds(1));
            assertThat(storedDigest()).isEqualTo(before);
            OwnerRead first = reads.getFirst();

            db.update("update sandbox_namespaces set state='SEALED' where id=?", fixture.key().runId());
            StoredDigest afterSeal = storedDigest();
            reads.clear();
            assertThat(source.resolve(fixture.key(), Duration.ofSeconds(5))).isNull();
            assertOwnerReads(reads, pool, 2);
            assertThat(reads.getFirst().physical()).isNotSameAs(first.physical());
            assertThat(reads.getFirst().backendPid()).isNotEqualTo(first.backendPid());
            assertThat(storedDigest()).isEqualTo(afterSeal);
            assertThat(TransactionSynchronizationManager.hasResource(pool)).isFalse();
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
        }
    }

    private void assertOwnerReads(List<OwnerRead> reads, CountingPool pool, int borrows) {
        assertThat(pool.borrows).hasValue(borrows);
        assertThat(reads).extracting(OwnerRead::owner).containsExactly("A", "B");
        OwnerRead a = reads.getFirst(), b = reads.getLast();
        assertThat(a.bound()).isNotNull().isSameAs(b.bound());
        assertThat(a.physical()).isSameAs(b.physical());
        assertThat(a.backendPid()).isEqualTo(b.backendPid());
        for (OwnerRead read : reads) {
            assertThat(read.autoCommit()).isFalse();
            assertThat(read.readOnly()).isTrue();
            assertThat(read.isolation()).isEqualTo(Connection.TRANSACTION_REPEATABLE_READ);
            assertThat(read.springActive()).isTrue();
            assertThat(read.springReadOnly()).isTrue();
            assertThat(read.serverReadOnly()).isEqualTo("on");
            assertThat(read.serverIsolation()).isEqualTo("repeatable read");
        }
        assertThat(pool.getHikariPoolMXBean().getActiveConnections()).isZero();
    }

    private CountingPool observedPool(List<OwnerRead> reads) {
        AtomicReference<DataSource> resourceKey = new AtomicReference<>();
        DataSource physical = new AbstractDataSource() {
            @Override public Connection getConnection() throws SQLException {
                Connection connection = DriverManager.getConnection(POSTGRES.getJdbcUrl(),
                        POSTGRES.getUsername(), POSTGRES.getPassword());
                return (Connection) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {Connection.class},
                        (proxy, method, arguments) -> {
                            Object result = invoke(connection, method, arguments);
                            if (method.getName().equals("prepareStatement") && arguments[0] instanceof String sql
                                    && result instanceof PreparedStatement statement) {
                                String owner = sql.contains("join test_run_reviewer_grants") ? "A"
                                        : sql.contains("join sandbox_namespaces") ? "B" : null;
                                if (owner != null) return Proxy.newProxyInstance(getClass().getClassLoader(),
                                        new Class<?>[] {PreparedStatement.class}, (ignored, queryMethod, queryArguments) -> {
                                            if (!queryMethod.getName().equals("executeQuery"))
                                                return invoke(statement, queryMethod, queryArguments);
                                            Object resource = TransactionSynchronizationManager.getResource(resourceKey.get());
                                            Connection bound = resource instanceof ConnectionHolder holder ? holder.getConnection() : null;
                                            OwnerRead observation;
                                            try (Statement metadata = connection.createStatement()) {
                                                metadata.setQueryTimeout(1);
                                                try (ResultSet row = metadata.executeQuery("select pg_backend_pid(), "
                                                        + "current_setting('transaction_read_only'), current_setting('transaction_isolation')")) {
                                                    assertThat(row.next()).isTrue();
                                                    observation = new OwnerRead(owner, connection, bound, row.getInt(1),
                                                            connection.getAutoCommit(), connection.isReadOnly(), connection.getTransactionIsolation(),
                                                            TransactionSynchronizationManager.isActualTransactionActive(),
                                                            TransactionSynchronizationManager.isCurrentTransactionReadOnly(), row.getString(2), row.getString(3));
                                                }
                                            }
                                            Object rows = invoke(statement, queryMethod, queryArguments);
                                            reads.add(observation);
                                            return rows;
                                        });
                            }
                            return result;
                        });
            }
            @Override public Connection getConnection(String username, String password) throws SQLException {
                return getConnection();
            }
        };
        HikariConfig config = new HikariConfig();
        config.setDataSource(physical); config.setMaximumPoolSize(1); config.setMinimumIdle(0);
        config.setConnectionTimeout(1_000);
        CountingPool pool = new CountingPool(config);
        resourceKey.set(pool);
        return pool;
    }

    private record OwnerRead(String owner, Connection physical, Connection bound, int backendPid,
            boolean autoCommit, boolean readOnly, int isolation, boolean springActive,
            boolean springReadOnly, String serverReadOnly, String serverIsolation) { }

    @Test
    void malformedAuthorityIsRejectedBeforeTheSecondOwnerReadWithoutStoredChanges() {
        Fixture fixture = fixture();
        StoredDigest before = storedDigest();
        List<UnaryOperator<StoredRunReviewerAuthoritySource.AuthoritySnapshot>> corruptions = List.of(
                a -> new StoredRunReviewerAuthoritySource.AuthoritySnapshot(null, a.workspaceId(), a.actorId(), a.role(), a.sessionReference(), a.expiresAt()),
                a -> new StoredRunReviewerAuthoritySource.AuthoritySnapshot(a.key(), null, a.actorId(), a.role(), a.sessionReference(), a.expiresAt()),
                a -> new StoredRunReviewerAuthoritySource.AuthoritySnapshot(a.key(), a.workspaceId(), null, a.role(), a.sessionReference(), a.expiresAt()),
                a -> new StoredRunReviewerAuthoritySource.AuthoritySnapshot(a.key(), a.workspaceId(), " padded ", a.role(), a.sessionReference(), a.expiresAt()),
                a -> new StoredRunReviewerAuthoritySource.AuthoritySnapshot(a.key(), a.workspaceId(), "a".repeat(121), a.role(), a.sessionReference(), a.expiresAt()),
                a -> new StoredRunReviewerAuthoritySource.AuthoritySnapshot(a.key(), a.workspaceId(), a.actorId(), "OTHER_ROLE", a.sessionReference(), a.expiresAt()),
                a -> new StoredRunReviewerAuthoritySource.AuthoritySnapshot(a.key(), a.workspaceId(), a.actorId(), a.role(), null, a.expiresAt()),
                a -> new StoredRunReviewerAuthoritySource.AuthoritySnapshot(a.key(), a.workspaceId(), a.actorId(), a.role(), "PRIVATE-CSRF-CANARY", a.expiresAt()),
                a -> new StoredRunReviewerAuthoritySource.AuthoritySnapshot(a.key(), a.workspaceId(), a.actorId(), a.role(), a.sessionReference(), null),
                a -> new StoredRunReviewerAuthoritySource.AuthoritySnapshot(a.key(), a.workspaceId(), a.actorId(), a.role(), a.sessionReference(), Instant.now().minusSeconds(1)));
        for (var corrupt : corruptions) {
            var ownerA = spy(new StoredRunReviewerAuthoritySource(dataSource, credentials));
            var ownerB = mock(StoredGatewayPreCallScopeSource.class);
            doAnswer(call -> corrupt.apply((StoredRunReviewerAuthoritySource.AuthoritySnapshot) call.callRealMethod()))
                    .when(ownerA).resolve(any(InvocationKey.class), any(Duration.class));
            assertThat(new StoredGatewayReviewerContextSource(dataSource, ownerA, ownerB)
                    .resolve(fixture.key(), Duration.ofSeconds(5))).isNull();
            verifyNoInteractions(ownerB);
            assertThat(dataSource.getHikariPoolMXBean().getActiveConnections()).isZero();
            assertThat(storedDigest()).isEqualTo(before);
        }
    }

    @Test
    void lockedAuthorityReadStopsInsideTheSharedBudgetAndRecoversWithoutWrites() throws Exception {
        Fixture fixture = fixture();
        StoredDigest before = storedDigest();
        try (Connection blocker = DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())) {
            blocker.setAutoCommit(false);
            try (Statement lock = blocker.createStatement()) { lock.execute("lock table test_run_reviewer_grants in access exclusive mode"); }
            long started = System.nanoTime();
            assertThat(source().resolve(fixture.key(), Duration.ofSeconds(3))).isNull();
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofMillis(3_750));
            blocker.rollback();
        }
        long cleanupDeadline = System.nanoTime() + Duration.ofSeconds(3).toNanos();
        while (dataSource.getHikariPoolMXBean().getActiveConnections() != 0 && System.nanoTime() < cleanupDeadline) Thread.sleep(20);
        assertThat(dataSource.getHikariPoolMXBean().getActiveConnections()).isZero();
        assertThat(storedDigest()).isEqualTo(before);
        assertThat(source().resolve(fixture.key(), Duration.ofSeconds(5))).isNotNull();
        assertThat(storedDigest()).isEqualTo(before);
    }

    @Test
    void revokedAdmissionAndMissingBCaseScopeFailClosed() {
        Fixture revoked = fixture();
        revocations.revoke(revoked.session());
        Counts afterRevocation = counts(revoked);
        assertThat(source().resolve(revoked.key(), Duration.ofSeconds(5))).isNull();
        assertThat(counts(revoked)).isEqualTo(afterRevocation);

        Fixture missingScope = fixture();
        db.update("update sandbox_namespaces set state = 'SEALED' where id = ?", missingScope.key().runId());
        Counts afterSeal = counts(missingScope);
        assertThat(source().resolve(missingScope.key(), Duration.ofSeconds(5))).isNull();
        assertThat(counts(missingScope)).isEqualTo(afterSeal);
    }

    @ParameterizedTest
    @EnumSource(value = TestRunMode.class, names = {"BASELINE", "SEAL_REPLAY"})
    void matchedModeWrongProposalCannotCallOrChangeStoredEvidence(TestRunMode mode) throws Exception {
        Fixture actual = fixture(mode);
        assertHealthyMatchedFixture(actual, mode);
        InvocationKey wrong = new InvocationKey(actual.key().runId(), actual.key().caseRunId(),
                actual.key().traceId(), actual.key().toolCallId(), OTHER_HASH);
        Fixture forged = new Fixture(wrong, actual.session(), actual.context(),
                new ToolInvocation(actual.invocation().proposal(), actual.key().toolCallId(), OTHER_HASH));
        StoredDigest before = storedDigest();
        assertGatewayStoredFailure(forged, dataSource, source(), FailureCode.AUTHENTICATION_REQUIRED);
        assertNoStoredGatewayWrite(actual, before);
    }

    @ParameterizedTest
    @EnumSource(value = TestRunMode.class, names = {"BASELINE", "SEAL_REPLAY"})
    void matchedModeRevokedGrantCannotCallOrChangeStoredEvidence(TestRunMode mode) throws Exception {
        Fixture fixture = fixture(mode);
        assertHealthyMatchedFixture(fixture, mode);
        revocations.revoke(fixture.session());
        StoredDigest afterRevocation = storedDigest();
        assertGatewayStoredFailure(fixture, dataSource, source(), FailureCode.AUTHENTICATION_REQUIRED);
        assertNoStoredGatewayWrite(fixture, afterRevocation);
    }

    @ParameterizedTest
    @EnumSource(value = TestRunMode.class, names = {"BASELINE", "SEAL_REPLAY"})
    void matchedModeSealedNamespaceCannotCallOrChangeStoredEvidence(TestRunMode mode) throws Exception {
        Fixture fixture = fixture(mode);
        assertHealthyMatchedFixture(fixture, mode);
        db.update("update sandbox_namespaces set state='SEALED' where id=?", fixture.key().runId());
        StoredDigest afterSeal = storedDigest();
        assertGatewayStoredFailure(fixture, dataSource, source(), FailureCode.AUTHENTICATION_REQUIRED);
        assertNoStoredGatewayWrite(fixture, afterSeal);
    }

    @ParameterizedTest
    @EnumSource(value = TestRunMode.class, names = {"BASELINE", "SEAL_REPLAY"})
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void matchedModePgSetupDeadlineCannotCallOrChangeStoredEvidence(TestRunMode mode) throws Exception {
        Fixture fixture = fixture(mode);
        assertHealthyMatchedFixture(fixture, mode);
        StoredDigest before = storedDigest();
        AtomicBoolean injected = new AtomicBoolean();
        try (HikariDataSource pool = stalledPool(DelayAt.READ_ONLY_SETUP, injected)) {
            var stored = new StoredGatewayReviewerContextSource(pool,
                    new StoredRunReviewerAuthoritySource(pool, credentials),
                    new StoredGatewayPreCallScopeSource(pool, json));
            assertGatewayStoredFailure(fixture, pool, stored,
                    FailureCode.AUTHENTICATION_REQUIRED, FailureCode.POLICY_EVALUATION_TIMEOUT);
            assertThat(injected).isTrue();
        }
        assertNoStoredGatewayWrite(fixture, before);
    }

    @Test
    void malformedConsumedScopeIdentityCannotEscapeOrChangeStoredEvidence() throws Exception {
        Fixture fixture = fixture(TestRunMode.BASELINE);
        assertHealthyMatchedFixture(fixture, TestRunMode.BASELINE);
        StoredDigest before = storedDigest();
        List<UnaryOperator<StoredGatewayPreCallScopeSource.ScopeSnapshot>> corruptions = List.of(
                scope -> null,
                scope -> scopeCopy(scope, null, scope.serverContext(), scope.namespace()),
                scope -> scopeCopy(scope, new InvocationKey(scope.key().runId(), scope.key().caseRunId(),
                        scope.key().traceId(), scope.key().toolCallId(), OTHER_HASH), scope.serverContext(), scope.namespace()),
                scope -> scopeCopy(scope, scope.key(), null, scope.namespace()),
                scope -> scopeCopy(scope, scope.key(), scope.serverContext(), null),
                scope -> scopeCopy(scope, scope.key(), contextCopy(scope.serverContext(), UUID.randomUUID(),
                        scope.serverContext().caseRunId(), scope.serverContext().traceId()), scope.namespace()),
                scope -> scopeCopy(scope, scope.key(), contextCopy(scope.serverContext(), scope.serverContext().runId(),
                        UUID.randomUUID(), scope.serverContext().traceId()), scope.namespace()),
                scope -> scopeCopy(scope, scope.key(), contextCopy(scope.serverContext(), scope.serverContext().runId(),
                        scope.serverContext().caseRunId(), UUID.randomUUID()), scope.namespace()),
                scope -> scopeCopy(scope, scope.key(), scope.serverContext(),
                        new GatewayRuntimeObservations.NamespaceObservation(UUID.randomUUID(),
                                scope.namespace().fixtureVersion(), scope.namespace().fixtureDigest(), "ACTIVE")));
        for (var corrupt : corruptions) {
            var ownerB = spy(new StoredGatewayPreCallScopeSource(dataSource, json));
            AtomicInteger realScopeReads = new AtomicInteger();
            doAnswer(call -> {
                var actual = (StoredGatewayPreCallScopeSource.ScopeSnapshot) call.callRealMethod();
                realScopeReads.incrementAndGet();
                return corrupt.apply(actual);
            }).when(ownerB).resolve(any(InvocationKey.class), any(Duration.class));
            var stored = new StoredGatewayReviewerContextSource(dataSource, authorities, ownerB);
            assertGatewayStoredFailure(fixture, dataSource, stored, FailureCode.AUTHENTICATION_REQUIRED);
            assertThat(realScopeReads).hasValue(1);
            assertNoStoredGatewayWrite(fixture, before);
        }
    }

    private StoredGatewayPreCallScopeSource.ScopeSnapshot scopeCopy(
            StoredGatewayPreCallScopeSource.ScopeSnapshot original, InvocationKey key,
            SandboxExecutionContext context, GatewayRuntimeObservations.NamespaceObservation namespace) {
        return new StoredGatewayPreCallScopeSource.ScopeSnapshot(key, context, namespace,
                original.toolName(), original.workflowStage(), original.allowedDocumentIds());
    }

    private SandboxExecutionContext contextCopy(SandboxExecutionContext original, UUID run, UUID caseRun, UUID trace) {
        return new SandboxExecutionContext(run, caseRun, trace, original.mode(),
                original.caseKey(), original.currentApplicantId());
    }

    private void assertGatewayStoredFailure(Fixture fixture, HikariDataSource pool,
            StoredGatewayReviewerContextSource stored, FailureCode... accepted) throws Exception {
        GatewayProbe probe = gatewayProbe(stored);
        long started = System.nanoTime();
        GatewayException failure = assertThrows(GatewayException.class,
                () -> probe.gateway().invoke(fixture.context(), fixture.invocation(), ACTOR));
        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofMillis(5_750));
        assertPreAdmissionFailure(probe, fixture, failure, accepted);
        awaitDeadlineLeases(pool);
        assertThat(dataSource.getHikariPoolMXBean().getActiveConnections()).isZero();
    }

    private void assertHealthyMatchedFixture(Fixture fixture, TestRunMode mode) throws Exception {
        assertThat(fixture.context().mode()).isEqualTo(mode);
        assertThat(db.queryForObject("select mode from test_runs where id=?", String.class, fixture.key().runId()))
                .isEqualTo(mode.name());
        UUID contract = db.queryForObject("select contract_version_id from test_runs where id=?", UUID.class, fixture.key().runId());
        if (mode == TestRunMode.BASELINE) {
            assertThat(contract).isNull();
        } else {
            assertThat(contract).isNotNull();
            assertThat(db.queryForObject("""
                    select count(*) from test_runs run
                    join safety_contract_versions version on version.id=run.contract_version_id and version.state='APPROVED'
                    join safety_contracts contract on contract.id=version.contract_id and contract.release_id=run.release_id
                    where run.id=?
                    """, Integer.class, fixture.key().runId())).isEqualTo(1);
        }
        var healthy = source().resolve(fixture.key(), Duration.ofSeconds(5));
        assertThat(healthy).isNotNull();
        assertThat(healthy.key()).isEqualTo(fixture.key());
        assertThat(healthy.reviewer().actorId()).isEqualTo(ACTOR);
        awaitDeadlineLeases(dataSource);
    }

    @Test
    void optInBeanAndAmbientTransactionAreFailClosed() {
        Fixture fixture = fixture();
        StoredGatewayReviewerContextSource source = source();
        GatewayReviewerContextSource.Resolution ambient =
                new TransactionTemplate(new DataSourceTransactionManager(dataSource))
                        .execute(ignored -> source.resolve(fixture.key(), Duration.ofSeconds(5)));
        assertThat(ambient).isNull();
        assertThat(source.resolve(fixture.key(), Duration.ZERO)).isNull();
        assertThat(source.resolve(fixture.key(), Duration.ofSeconds(6))).isNull();
        assertThat(source.resolve(fixture.key(), Duration.ofMillis(900))).isNull();

        var context = new ApplicationContextRunner()
                .withBean(javax.sql.DataSource.class, () -> {
                    HikariDataSource isolated = new HikariDataSource();
                    isolated.setConnectionTimeout(2_000);
                    return isolated;
                })
                .withBean(StoredRunReviewerAuthoritySource.class, () -> authorities)
                .withBean(StoredGatewayPreCallScopeSource.class, () -> scopes)
                .withUserConfiguration(StoredGatewayReviewerContextSource.class);
        context.run(child -> assertThat(child.getBeanNamesForType(GatewayReviewerContextSource.class)).isEmpty());
        context.withPropertyValues("finsec.policy.gateway.enabled=true",
                        "finsec.policy.gateway.reviewer.stored.enabled=true")
                .run(child -> assertThat(child.getBeanNamesForType(GatewayReviewerContextSource.class))
                        .containsExactly(LoanReviewPolicyGatewayConfiguration.REVIEWER_CONTEXT_BEAN));

        try (HikariDataSource unsafeDefault = new HikariDataSource()) {
            assertThatThrownBy(() -> new StoredGatewayReviewerContextSource(unsafeDefault, authorities, scopes))
                    .isInstanceOf(IllegalStateException.class).hasNoCause();
        }
    }

    @Test
    void exhaustedPoolAndLockedBReadStopInsideFiniteBudget() throws Exception {
        Fixture fixture = fixture();
        Counts before = counts(fixture);
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(POSTGRES.getJdbcUrl());
        config.setUsername(POSTGRES.getUsername());
        config.setPassword(POSTGRES.getPassword());
        config.setMaximumPoolSize(1);
        config.setMinimumIdle(0);
        config.setConnectionTimeout(1_000);
        try (HikariDataSource singleConnection = new HikariDataSource(config);
                Connection held = singleConnection.getConnection()) {
            var bounded = new StoredGatewayReviewerContextSource(singleConnection,
                    new StoredRunReviewerAuthoritySource(singleConnection, credentials),
                    new StoredGatewayPreCallScopeSource(singleConnection, json));
            long started = System.nanoTime();
            assertThat(bounded.resolve(fixture.key(), Duration.ofSeconds(4))).isNull();
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(3));
        }

        try (Connection blocker = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())) {
            blocker.setAutoCommit(false);
            try (Statement lock = blocker.createStatement()) {
                lock.execute("lock table sandbox_loan_cases in access exclusive mode");
            }
            long started = System.nanoTime();
            assertThat(source().resolve(fixture.key(), Duration.ofSeconds(3))).isNull();
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofMillis(3_750));
            blocker.rollback();
        }
        assertThat(counts(fixture)).isEqualTo(before);
        assertThat(source().resolve(fixture.key(), Duration.ofSeconds(5))).isNotNull();
    }

    @Test
    void stalledTransactionSetupAbortsTheRealPgConnectionWithinTheSharedDeadline() throws Exception {
        assertStalledTransactionIsBounded(DelayAt.READ_ONLY_SETUP);
    }

    @Test
    void stalledTransactionRollbackAbortsTheRealPgConnectionWithinTheSharedDeadline() throws Exception {
        assertStalledTransactionIsBounded(DelayAt.ROLLBACK);
    }

    @Test
    void stalledPhysicalAbortDoesNotHoldTheCallerPastItsDeadline() throws Exception {
        Fixture fixture = fixture();
        Counts before = counts(fixture);
        AtomicBoolean sleepingInPostgres = new AtomicBoolean();
        CountDownLatch abortEntered = new CountDownLatch(1);
        CountDownLatch releaseAbort = new CountDownLatch(1);
        try (HikariDataSource stalledPool = stalledPool(
                DelayAt.READ_ONLY_SETUP, sleepingInPostgres, abortEntered, releaseAbort)) {
            var reviewers = new StoredGatewayReviewerContextSource(stalledPool,
                    new StoredRunReviewerAuthoritySource(stalledPool, credentials),
                    new StoredGatewayPreCallScopeSource(stalledPool, json));
            ExecutorService callers = Executors.newSingleThreadExecutor();
            try {
                long started = System.nanoTime();
                Future<GatewayReviewerContextSource.Resolution> result = callers.submit(
                        () -> reviewers.resolve(fixture.key(), Duration.ofSeconds(3)));
                assertThat(abortEntered.await(5, TimeUnit.SECONDS)).isTrue();
                long callerTimeLeft = Duration.ofMillis(3_750).toNanos() - (System.nanoTime() - started);
                assertThat(callerTimeLeft).isPositive();
                // Hold physical abort until after the caller has returned. The current implementation
                // runs this abort in the caller's finally block and must fail this assertion.
                assertThat(result.get(callerTimeLeft, TimeUnit.NANOSECONDS)).isNull();
                assertThat(sleepingInPostgres).isTrue();
            } finally {
                releaseAbort.countDown();
                callers.shutdownNow();
                assertThat(callers.awaitTermination(6, TimeUnit.SECONDS)).isTrue();
            }
            long cleanupDeadline = System.nanoTime() + Duration.ofSeconds(6).toNanos();
            while (stalledPool.getHikariPoolMXBean().getActiveConnections() != 0
                    && System.nanoTime() < cleanupDeadline) {
                Thread.sleep(20);
            }
            assertThat(stalledPool.getHikariPoolMXBean().getActiveConnections()).isZero();
            assertThat(reviewers.resolve(fixture.key(), Duration.ofSeconds(5))).isNotNull();
            assertThat(counts(fixture)).isEqualTo(before);
        }
    }

    @Test
    void failedWorkerEvictionKeepsTheWatchdogArmedForTheSameBorrowedLease() throws Exception {
        Fixture fixture = fixture();
        Counts before = counts(fixture);
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(POSTGRES.getJdbcUrl());
        config.setUsername(POSTGRES.getUsername());
        config.setPassword(POSTGRES.getPassword());
        config.setMaximumPoolSize(1);
        config.setMinimumIdle(0);
        config.setConnectionTimeout(1_000);
        try (OperationalDiagnostics diagnostics = new OperationalDiagnostics();
                FailFirstEvictionPool pool = new FailFirstEvictionPool(config)) {
            var reviewers = new StoredGatewayReviewerContextSource(pool,
                    new StoredRunReviewerAuthoritySource(pool, credentials),
                    new StoredGatewayPreCallScopeSource(pool, json));
            double retirementsBefore = diagnostics.count("retirement_failure");
            long started = System.nanoTime();
            assertThat(reviewers.resolve(fixture.key(), Duration.ofSeconds(3))).isNull();
            assertThat(Duration.ofNanos(System.nanoTime() - started))
                    .isLessThan(Duration.ofMillis(3_750));
            assertThat(pool.firstEvictionThread.get()).startsWith("stored-gateway-reviewer");
            // The worker's injected first eviction fails. The deadline callback must retry
            // retirement of that exact borrowed proxy instead of being disarmed by the caller.
            assertThat(pool.retryEntered.await(5, TimeUnit.SECONDS)).isTrue();
            assertThat(pool.evictions.get()).isEqualTo(2);
            assertThat(pool.retryThread.get()).startsWith("stored-gateway-reviewer-deadline");
            assertThat(pool.sameBorrowedLease.get()).isTrue();
            long cleanupDeadline = System.nanoTime() + Duration.ofSeconds(6).toNanos();
            while (pool.getHikariPoolMXBean().getActiveConnections() != 0
                    && System.nanoTime() < cleanupDeadline) {
                Thread.sleep(20);
            }
            assertThat(pool.getHikariPoolMXBean().getActiveConnections()).isZero();
            while (deadlineSlots().availablePermits() != 2 && System.nanoTime() < cleanupDeadline) Thread.sleep(20);
            assertThat(deadlineSlots().availablePermits()).isEqualTo(2);
            assertThat(diagnostics.count("retirement_failure")).isEqualTo(retirementsBefore + 1);
            assertThat(reviewers.resolve(fixture.key(), Duration.ofSeconds(5))).isNotNull();
            assertThat(counts(fixture)).isEqualTo(before);
        }
    }

    @Test
    void twoBlockedWatchdogsRejectAThirdStoredReviewerBeforeBorrowing() throws Exception {
        Fixture fixture = fixture();
        Counts before = counts(fixture);
        StoredDigest rowsBefore = storedDigest();
        AtomicBoolean firstSleep = new AtomicBoolean();
        AtomicBoolean secondSleep = new AtomicBoolean();
        CountDownLatch firstAbort = new CountDownLatch(1);
        CountDownLatch secondAbort = new CountDownLatch(1);
        CountDownLatch releaseAborts = new CountDownLatch(1);
        AtomicReference<String> firstAbortThread = new AtomicReference<>();
        AtomicReference<String> secondAbortThread = new AtomicReference<>();
        CountingPool thirdPool = countingPool();
        try (OperationalDiagnostics diagnostics = new OperationalDiagnostics();
                HikariDataSource firstPool = stalledPool(DelayAt.READ_ONLY_SETUP, firstSleep,
                firstAbort, releaseAborts, firstAbortThread);
                HikariDataSource secondPool = stalledPool(DelayAt.READ_ONLY_SETUP, secondSleep,
                        secondAbort, releaseAborts, secondAbortThread);
                thirdPool) {
            var first = new StoredGatewayReviewerContextSource(firstPool,
                    new StoredRunReviewerAuthoritySource(firstPool, credentials),
                    new StoredGatewayPreCallScopeSource(firstPool, json));
            var second = new StoredGatewayReviewerContextSource(secondPool,
                    new StoredRunReviewerAuthoritySource(secondPool, credentials),
                    new StoredGatewayPreCallScopeSource(secondPool, json));
            var thirdSource = new StoredGatewayReviewerContextSource(thirdPool,
                    new StoredRunReviewerAuthoritySource(thirdPool, credentials),
                    new StoredGatewayPreCallScopeSource(thirdPool, json));
            double capacityBefore = diagnostics.count("deadline_capacity");
            ExecutorService callers = Executors.newFixedThreadPool(2);
            try {
                Future<TimedResolution> firstCall = callers.submit(
                        () -> timedResolve(first, fixture.key(), Duration.ofSeconds(3)));
                Future<TimedResolution> secondCall = callers.submit(
                        () -> timedResolve(second, fixture.key(), Duration.ofSeconds(3)));
                assertThat(firstAbort.await(5, TimeUnit.SECONDS)).isTrue();
                assertThat(secondAbort.await(5, TimeUnit.SECONDS)).isTrue();
                assertThat(firstSleep).isTrue();
                assertThat(secondSleep).isTrue();
                assertThat(firstAbortThread.get()).startsWith("stored-gateway-reviewer-deadline");
                assertThat(secondAbortThread.get()).startsWith("stored-gateway-reviewer-deadline");

                // Both real deadline callbacks are held inside physical abort. The static
                // admission bound must reject a third valid key before its reader borrows PG.
                int borrowsBeforeThird = thirdPool.borrows.get();
                TimedResolution third = timedResolve(thirdSource, fixture.key(), Duration.ofSeconds(3));
                assertThat(third.resolution()).isNull();
                assertThat(third.elapsed()).isLessThan(Duration.ofMillis(500));
                assertThat(thirdPool.borrows.get()).isEqualTo(borrowsBeforeThird);

                TimedResolution firstResult = firstCall.get(2, TimeUnit.SECONDS);
                TimedResolution secondResult = secondCall.get(2, TimeUnit.SECONDS);
                assertThat(firstResult.resolution()).isNull();
                assertThat(secondResult.resolution()).isNull();
                assertThat(firstResult.elapsed()).isLessThan(Duration.ofMillis(3_750));
                assertThat(secondResult.elapsed()).isLessThan(Duration.ofMillis(3_750));
            } finally {
                releaseAborts.countDown();
                callers.shutdownNow();
                assertThat(callers.awaitTermination(6, TimeUnit.SECONDS)).isTrue();
            }
            long cleanupDeadline = awaitDeadlineLeases(firstPool, secondPool);
            assertThat(diagnostics.count("deadline_capacity")).isEqualTo(capacityBefore + 1);
            assertSingleHealthyRecovery(thirdPool, fixture, cleanupDeadline);
            assertThat(counts(fixture)).isEqualTo(before);
            assertThat(storedDigest()).isEqualTo(rowsBefore);
        }
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void gatewaySetupTimeoutCannotCallTheAdapterOrChangeStoredEvidence() throws Exception {
        Fixture fixture = fixture();
        StoredDigest before = storedDigest();
        AtomicBoolean sleepingInPostgres = new AtomicBoolean();
        try (HikariDataSource stalledPool = stalledPool(DelayAt.READ_ONLY_SETUP, sleepingInPostgres)) {
            var stored = new StoredGatewayReviewerContextSource(stalledPool,
                    new StoredRunReviewerAuthoritySource(stalledPool, credentials),
                    new StoredGatewayPreCallScopeSource(stalledPool, json));
            GatewayProbe probe = gatewayProbe(stored);
            long started = System.nanoTime();
            GatewayException failure = assertThrows(GatewayException.class,
                    () -> probe.gateway().invoke(fixture.context(), fixture.invocation(), ACTOR));
            assertThat(Duration.ofNanos(System.nanoTime() - started))
                    .isLessThan(Duration.ofMillis(5_750));
            assertThat(sleepingInPostgres).isTrue();
            assertPreAdmissionFailure(probe, fixture, failure,
                    FailureCode.AUTHENTICATION_REQUIRED, FailureCode.POLICY_EVALUATION_TIMEOUT);

            long cleanupDeadline = System.nanoTime() + Duration.ofSeconds(6).toNanos();
            while (stalledPool.getHikariPoolMXBean().getActiveConnections() != 0
                    && System.nanoTime() < cleanupDeadline) {
                Thread.sleep(20);
            }
            assertThat(stalledPool.getHikariPoolMXBean().getActiveConnections()).isZero();
            assertThat(source().resolve(fixture.key(), Duration.ofSeconds(5))).isNotNull();
        }
        assertNoStoredGatewayWrite(fixture, before);
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void gatewayRejectsTwoBlockedWatchdogsBeforeAThirdBorrowOrToolCall() throws Exception {
        Fixture fixture = fixture();
        StoredDigest before = storedDigest();
        AtomicBoolean firstSleep = new AtomicBoolean();
        AtomicBoolean secondSleep = new AtomicBoolean();
        CountDownLatch firstAbort = new CountDownLatch(1);
        CountDownLatch secondAbort = new CountDownLatch(1);
        CountDownLatch releaseAborts = new CountDownLatch(1);
        AtomicReference<String> firstAbortThread = new AtomicReference<>();
        AtomicReference<String> secondAbortThread = new AtomicReference<>();
        CountingPool thirdPool = countingPool();
        try (HikariDataSource firstPool = stalledPool(DelayAt.READ_ONLY_SETUP, firstSleep,
                firstAbort, releaseAborts, firstAbortThread);
                HikariDataSource secondPool = stalledPool(DelayAt.READ_ONLY_SETUP, secondSleep,
                        secondAbort, releaseAborts, secondAbortThread);
                thirdPool) {
            var first = new StoredGatewayReviewerContextSource(firstPool,
                    new StoredRunReviewerAuthoritySource(firstPool, credentials),
                    new StoredGatewayPreCallScopeSource(firstPool, json));
            var second = new StoredGatewayReviewerContextSource(secondPool,
                    new StoredRunReviewerAuthoritySource(secondPool, credentials),
                    new StoredGatewayPreCallScopeSource(secondPool, json));
            var third = new StoredGatewayReviewerContextSource(thirdPool,
                    new StoredRunReviewerAuthoritySource(thirdPool, credentials),
                    new StoredGatewayPreCallScopeSource(thirdPool, json));
            ExecutorService callers = Executors.newFixedThreadPool(2);
            try {
                Future<TimedResolution> firstCall = callers.submit(
                        () -> timedResolve(first, fixture.key(), Duration.ofSeconds(3)));
                Future<TimedResolution> secondCall = callers.submit(
                        () -> timedResolve(second, fixture.key(), Duration.ofSeconds(3)));
                assertThat(firstAbort.await(5, TimeUnit.SECONDS)).isTrue();
                assertThat(secondAbort.await(5, TimeUnit.SECONDS)).isTrue();
                assertThat(firstSleep).isTrue();
                assertThat(secondSleep).isTrue();
                assertThat(firstAbortThread.get()).isEqualTo("stored-gateway-reviewer-deadline");
                assertThat(secondAbortThread.get()).isEqualTo("stored-gateway-reviewer-deadline");

                int borrowsBeforeGateway = thirdPool.borrows.get();
                GatewayProbe probe = gatewayProbe(third);
                long started = System.nanoTime();
                GatewayException failure = assertThrows(GatewayException.class,
                        () -> probe.gateway().invoke(fixture.context(), fixture.invocation(), ACTOR));
                assertThat(Duration.ofNanos(System.nanoTime() - started))
                        .isLessThan(Duration.ofMillis(500));
                assertPreAdmissionFailure(probe, fixture, failure, FailureCode.AUTHENTICATION_REQUIRED);
                assertThat(thirdPool.borrows.get()).isEqualTo(borrowsBeforeGateway);

                TimedResolution firstResult = firstCall.get(2, TimeUnit.SECONDS);
                TimedResolution secondResult = secondCall.get(2, TimeUnit.SECONDS);
                assertThat(firstResult.resolution()).isNull();
                assertThat(secondResult.resolution()).isNull();
                assertThat(firstResult.elapsed()).isLessThan(Duration.ofMillis(3_750));
                assertThat(secondResult.elapsed()).isLessThan(Duration.ofMillis(3_750));
            } finally {
                releaseAborts.countDown();
                callers.shutdownNow();
                assertThat(callers.awaitTermination(6, TimeUnit.SECONDS)).isTrue();
            }
            long cleanupDeadline = awaitDeadlineLeases(firstPool, secondPool);
            assertSingleHealthyRecovery(thirdPool, fixture, cleanupDeadline);
        }
        assertNoStoredGatewayWrite(fixture, before);
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void saturatedHikariCloseExecutorCannotHoldTheReviewerCaller() throws Exception {
        Fixture fixture = fixture();
        Counts before = counts(fixture);
        AtomicBoolean blockingArmed = new AtomicBoolean();
        AtomicInteger physicalCloses = new AtomicInteger();
        CountDownLatch firstCloseEntered = new CountDownLatch(1);
        CountDownLatch callerCloseEntered = new CountDownLatch(1);
        CountDownLatch releaseCloses = new CountDownLatch(1);
        AtomicReference<String> firstCloseThread = new AtomicReference<>();
        AtomicReference<String> callerCloseThread = new AtomicReference<>();
        // Hikari may close a probe connection during its constructor. Arm the blocking
        // proxy only after the pool exists, and release the latch before closing the pool.
        HikariDataSource pool = closeBlockingPool(blockingArmed, physicalCloses,
                firstCloseEntered, callerCloseEntered, releaseCloses,
                firstCloseThread, callerCloseThread);
        ExecutorService callers = Executors.newSingleThreadExecutor();
        Connection firstLease = null;
        Connection secondLease = null;
        Connection thirdLease = null;
        boolean firstRetired = false;
        boolean secondRetired = false;
        try {
            blockingArmed.set(true);
            // Hikari maxPool=1 has one close worker and one queue slot. Retire two borrowed
            // leases without closing their already-retired proxies: the first physical close
            // blocks the worker and the second occupies the queue.
            firstLease = pool.getConnection();
            pool.evictConnection(firstLease);
            firstRetired = true;
            assertThat(firstCloseEntered.await(3, TimeUnit.SECONDS)).isTrue();
            assertThat(firstCloseThread.get()).endsWith(":connection-closer");
            secondLease = pool.getConnection();
            pool.evictConnection(secondLease);
            secondRetired = true;
            assertThat(physicalCloses.get()).isEqualTo(1);
            thirdLease = pool.getConnection();
            thirdLease.close();
            thirdLease = null;

            var reviewers = new StoredGatewayReviewerContextSource(pool,
                    new StoredRunReviewerAuthoritySource(pool, credentials),
                    new StoredGatewayPreCallScopeSource(pool, json));
            try {
                Future<TimedResolution> result = callers.submit(
                        () -> timedResolve(reviewers, fixture.key(), Duration.ofSeconds(3)));
                // Queue saturation must force the next physical close on the reviewer worker.
                // A test that never enters this callback cannot claim the CallerRuns case.
                assertThat(callerCloseEntered.await(5, TimeUnit.SECONDS)).isTrue();
                assertThat(physicalCloses.get()).isEqualTo(2);
                assertThat(callerCloseThread.get()).isEqualTo("stored-gateway-reviewer");
                TimedResolution timed = result.get(5, TimeUnit.SECONDS);
                assertThat(timed.resolution()).isNull();
                assertThat(timed.elapsed()).isLessThan(Duration.ofMillis(3_750));
            } finally {
                releaseCloses.countDown();
            }
            long cleanupDeadline = System.nanoTime() + Duration.ofSeconds(6).toNanos();
            while ((physicalCloses.get() < 3
                    || pool.getHikariPoolMXBean().getActiveConnections() != 0)
                    && System.nanoTime() < cleanupDeadline) {
                Thread.sleep(20);
            }
            assertThat(physicalCloses.get()).isGreaterThanOrEqualTo(3);
            assertThat(pool.getHikariPoolMXBean().getActiveConnections()).isZero();
            assertThat(reviewers.resolve(fixture.key(), Duration.ofSeconds(5))).isNotNull();
            assertThat(counts(fixture)).isEqualTo(before);
        } finally {
            releaseCloses.countDown();
            try {
                if (thirdLease != null) thirdLease.close();
                if (secondLease != null && !secondRetired) secondLease.close();
                if (firstLease != null && !firstRetired) firstLease.close();
            } finally {
                callers.shutdownNow();
                try {
                    assertThat(callers.awaitTermination(6, TimeUnit.SECONDS)).isTrue();
                } finally {
                    pool.close();
                }
            }
        }
    }

    private HikariDataSource closeBlockingPool(AtomicBoolean blockingArmed,
            AtomicInteger physicalCloses,
            CountDownLatch firstCloseEntered, CountDownLatch callerCloseEntered,
            CountDownLatch releaseCloses, AtomicReference<String> firstCloseThread,
            AtomicReference<String> callerCloseThread) {
        DataSource delayedDataSource = new AbstractDataSource() {
            @Override public Connection getConnection() throws SQLException {
                return closeBlockingConnection(DriverManager.getConnection(POSTGRES.getJdbcUrl(),
                        POSTGRES.getUsername(), POSTGRES.getPassword()), physicalCloses,
                        blockingArmed, firstCloseEntered, callerCloseEntered, releaseCloses,
                        firstCloseThread, callerCloseThread);
            }

            @Override public Connection getConnection(String username, String password) throws SQLException {
                return closeBlockingConnection(DriverManager.getConnection(POSTGRES.getJdbcUrl(),
                        username, password), physicalCloses,
                        blockingArmed, firstCloseEntered, callerCloseEntered, releaseCloses,
                        firstCloseThread, callerCloseThread);
            }
        };
        HikariConfig config = new HikariConfig();
        config.setDataSource(delayedDataSource);
        config.setMaximumPoolSize(1);
        config.setMinimumIdle(0);
        config.setConnectionTimeout(1_000);
        config.setValidationTimeout(1_000);
        return new HikariDataSource(config);
    }

    private Connection closeBlockingConnection(Connection delegate, AtomicInteger physicalCloses,
            AtomicBoolean blockingArmed,
            CountDownLatch firstCloseEntered, CountDownLatch callerCloseEntered,
            CountDownLatch releaseCloses, AtomicReference<String> firstCloseThread,
            AtomicReference<String> callerCloseThread) {
        return (Connection) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {Connection.class},
                (proxy, method, arguments) -> {
                    if (method.getName().equals("close") && blockingArmed.get()) {
                        int call = physicalCloses.incrementAndGet();
                        if (call == 1) {
                            firstCloseThread.set(Thread.currentThread().getName());
                            firstCloseEntered.countDown();
                        }
                        if (call == 2) {
                            callerCloseThread.set(Thread.currentThread().getName());
                            callerCloseEntered.countDown();
                        }
                        try {
                            releaseCloses.await();
                        } catch (InterruptedException interrupted) {
                            Thread.currentThread().interrupt();
                        }
                    }
                    return invoke(delegate, method, arguments);
                });
    }

    private long awaitDeadlineLeases(HikariDataSource... pools) throws Exception {
        long cleanupDeadline = System.nanoTime() + Duration.ofSeconds(8).toNanos();
        // Eviction can make Hikari report zero before the worker and physical-abort
        // callback finish. Observe the existing lease barrier; never mutate its permits.
        var field = StoredGatewayReviewerContextSource.class.getDeclaredField("DEADLINE_SLOTS");
        field.setAccessible(true);
        Semaphore slots = (Semaphore) field.get(null);
        int initialPermits = slots.availablePermits();
        while ((slots.availablePermits() != 2
                || Arrays.stream(pools).anyMatch(pool -> pool.getHikariPoolMXBean().getActiveConnections() != 0))
                && System.nanoTime() < cleanupDeadline) {
            Thread.sleep(20);
        }
        assertThat(slots.availablePermits()).as("both worker/watchdog leases settled").isEqualTo(2);
        for (HikariDataSource pool : pools) assertThat(pool.getHikariPoolMXBean().getActiveConnections()).isZero();
        System.out.println("deadline cleanup permits: " + initialPermits + " -> " + slots.availablePermits());
        return cleanupDeadline;
    }

    private void assertSingleHealthyRecovery(CountingPool pool, Fixture fixture, long cleanupDeadline) {
        var ownerA = spy(new StoredRunReviewerAuthoritySource(pool, credentials));
        var ownerB = spy(new StoredGatewayPreCallScopeSource(pool, json));
        AtomicInteger aReads = new AtomicInteger(), bReads = new AtomicInteger();
        doAnswer(call -> { aReads.incrementAndGet(); return call.callRealMethod(); })
                .when(ownerA).resolve(any(InvocationKey.class), any(Duration.class));
        doAnswer(call -> { bReads.incrementAndGet(); return call.callRealMethod(); })
                .when(ownerB).resolve(any(InvocationKey.class), any(Duration.class));
        int borrowsBefore = pool.borrows.get();
        long remaining = Math.min(Duration.ofSeconds(5).toNanos(), cleanupDeadline - System.nanoTime());
        assertThat(remaining).as("healthy recovery remains within the eight-second cleanup interval").isPositive();
        var recovered = new StoredGatewayReviewerContextSource(pool, ownerA, ownerB)
                .resolve(fixture.key(), Duration.ofNanos(remaining));
        System.out.println("healthy recovery borrows/owner A/owner B: "
                + (pool.borrows.get() - borrowsBefore) + "/" + aReads.get() + "/" + bReads.get());
        assertThat(pool.borrows).hasValue(borrowsBefore + 1);
        assertThat(aReads).hasValue(1);
        assertThat(bReads).hasValue(1);
        assertThat(recovered).isNotNull();
        assertThat(recovered.key()).isEqualTo(fixture.key());
        assertThat(recovered.reviewer().actorId()).isEqualTo(ACTOR);
        assertThat(pool.getHikariPoolMXBean().getActiveConnections()).isZero();
        assertThat(System.nanoTime()).isLessThan(cleanupDeadline);
    }

    private TimedResolution timedResolve(StoredGatewayReviewerContextSource source,
            InvocationKey key, Duration budget) {
        long started = System.nanoTime();
        var resolution = source.resolve(key, budget);
        return new TimedResolution(resolution, Duration.ofNanos(System.nanoTime() - started));
    }

    private record TimedResolution(GatewayReviewerContextSource.Resolution resolution, Duration elapsed) { }

    private CountingPool countingPool() {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(POSTGRES.getJdbcUrl());
        config.setUsername(POSTGRES.getUsername());
        config.setPassword(POSTGRES.getPassword());
        config.setMaximumPoolSize(1);
        config.setMinimumIdle(0);
        config.setConnectionTimeout(1_000);
        return new CountingPool(config);
    }

    private static final class CountingPool extends HikariDataSource {
        private final AtomicInteger borrows = new AtomicInteger();

        private CountingPool(HikariConfig config) {
            super(config);
        }

        @Override
        public Connection getConnection() throws SQLException {
            borrows.incrementAndGet();
            return super.getConnection();
        }
    }

    private static final class FailFirstEvictionPool extends HikariDataSource {
        private final AtomicInteger evictions = new AtomicInteger();
        private final AtomicReference<Connection> firstBorrowedLease = new AtomicReference<>();
        private final AtomicReference<String> firstEvictionThread = new AtomicReference<>();
        private final AtomicReference<String> retryThread = new AtomicReference<>();
        private final AtomicBoolean sameBorrowedLease = new AtomicBoolean();
        private final CountDownLatch retryEntered = new CountDownLatch(1);

        private FailFirstEvictionPool(HikariConfig config) {
            super(config);
        }

        @Override
        public void evictConnection(Connection connection) {
            int call = evictions.incrementAndGet();
            if (call == 1) {
                firstBorrowedLease.set(connection);
                firstEvictionThread.set(Thread.currentThread().getName());
                throw new IllegalStateException("injected first eviction failure");
            }
            if (call == 2) {
                sameBorrowedLease.set(connection == firstBorrowedLease.get());
                retryThread.set(Thread.currentThread().getName());
                retryEntered.countDown();
            }
            super.evictConnection(connection);
        }
    }

    private void assertStalledTransactionIsBounded(DelayAt stage) throws Exception {
        Fixture fixture = fixture();
        Counts before = counts(fixture);
        AtomicBoolean injected = new AtomicBoolean();
        try (HikariDataSource stalledPool = stalledPool(stage, injected)) {
            var reviewers = new StoredGatewayReviewerContextSource(stalledPool,
                    new StoredRunReviewerAuthoritySource(stalledPool, credentials),
                    new StoredGatewayPreCallScopeSource(stalledPool, json));
            long started = System.nanoTime();
            assertThat(reviewers.resolve(fixture.key(), Duration.ofSeconds(3))).isNull();
            // The real PG sleep must run at the selected transaction boundary. Allow only
            // 750 ms for test-host scheduling beyond the caller's three-second budget.
            assertThat(injected).isTrue();
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofMillis(3_750));
            assertThat(counts(fixture)).isEqualTo(before);

            long cleanupDeadline = System.nanoTime() + Duration.ofSeconds(3).toNanos();
            while (stalledPool.getHikariPoolMXBean().getActiveConnections() != 0
                    && System.nanoTime() < cleanupDeadline) {
                Thread.sleep(20);
            }
            assertThat(stalledPool.getHikariPoolMXBean().getActiveConnections()).isZero();
            assertThat(reviewers.resolve(fixture.key(), Duration.ofSeconds(5))).isNotNull();
            assertThat(counts(fixture)).isEqualTo(before);
        }
    }

    private HikariDataSource stalledPool(DelayAt stage, AtomicBoolean injected) {
        return stalledPool(stage, injected, null, null);
    }

    private HikariDataSource stalledPool(DelayAt stage, AtomicBoolean injected,
            CountDownLatch abortEntered, CountDownLatch releaseAbort) {
        return stalledPool(stage, injected, abortEntered, releaseAbort, null);
    }

    private HikariDataSource stalledPool(DelayAt stage, AtomicBoolean injected,
            CountDownLatch abortEntered, CountDownLatch releaseAbort,
            AtomicReference<String> abortThread) {
        DataSource delayedDataSource = new AbstractDataSource() {
            @Override public Connection getConnection() throws SQLException {
                return delayedConnection(DriverManager.getConnection(POSTGRES.getJdbcUrl(),
                        POSTGRES.getUsername(), POSTGRES.getPassword()), stage, injected,
                        abortEntered, releaseAbort, abortThread);
            }

            @Override public Connection getConnection(String username, String password) throws SQLException {
                return delayedConnection(DriverManager.getConnection(POSTGRES.getJdbcUrl(), username, password),
                        stage, injected, abortEntered, releaseAbort, abortThread);
            }
        };
        HikariConfig config = new HikariConfig();
        config.setDataSource(delayedDataSource);
        config.setMaximumPoolSize(1);
        config.setMinimumIdle(1);
        config.setConnectionTimeout(1_000);
        config.setValidationTimeout(1_000);
        return new HikariDataSource(config);
    }

    private Connection delayedConnection(Connection delegate, DelayAt stage, AtomicBoolean once,
            CountDownLatch abortEntered, CountDownLatch releaseAbort,
            AtomicReference<String> abortThread) {
        return (Connection) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {Connection.class},
                (proxy, method, arguments) -> {
                    if (abortEntered != null && method.getName().equals("setNetworkTimeout")) {
                        // Simulate a driver that does not honor the network deadline. The real
                        // PostgreSQL pg_sleep must then be stopped by the source's watchdog.
                        return null;
                    }
                    if (abortEntered != null && method.getName().equals("abort")) {
                        if (abortThread != null) abortThread.set(Thread.currentThread().getName());
                        abortEntered.countDown();
                        try {
                            releaseAbort.await();
                        } catch (InterruptedException interrupted) {
                            Thread.currentThread().interrupt();
                        }
                    }
                    if (stage == DelayAt.ROLLBACK && method.getName().equals("rollback")
                            && once.compareAndSet(false, true)) {
                        pgSleep(delegate);
                    }
                    Object value = invoke(delegate, method, arguments);
                    if (stage == DelayAt.READ_ONLY_SETUP && method.getName().equals("createStatement")
                            && value instanceof Statement statement) {
                        return Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {Statement.class},
                                (statementProxy, statementMethod, statementArguments) -> {
                                    if (statementMethod.getName().equals("executeUpdate")
                                            && statementArguments != null && statementArguments.length > 0
                                            && "SET TRANSACTION READ ONLY".equals(statementArguments[0])
                                            && once.compareAndSet(false, true)) {
                                        pgSleep(delegate);
                                    }
                                    return invoke(statement, statementMethod, statementArguments);
                                });
                    }
                    return value;
                });
    }

    private static Object invoke(Object receiver, Method method, Object[] arguments) throws Throwable {
        try {
            return method.invoke(receiver, arguments);
        } catch (InvocationTargetException failure) {
            throw failure.getCause();
        }
    }

    private static void pgSleep(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("select pg_sleep(10)");
        }
    }

    private enum DelayAt { READ_ONLY_SETUP, ROLLBACK }

    private StoredGatewayReviewerContextSource source() {
        return new StoredGatewayReviewerContextSource(dataSource, authorities, scopes);
    }

    private GatewayProbe gatewayProbe(GatewayReviewerContextSource stored) {
        AtomicReference<InvocationKey> requestedKey = new AtomicReference<>();
        AtomicReference<Duration> remaining = new AtomicReference<>();
        AtomicInteger reviewerCalls = new AtomicInteger();
        AtomicInteger adapterCalls = new AtomicInteger();
        GatewayReviewerContextSource recording = (key, budget) -> {
            requestedKey.set(key);
            remaining.set(budget);
            reviewerCalls.incrementAndGet();
            return stored.resolve(key, budget);
        };
        PlatformTransactionManager transactions = mock(PlatformTransactionManager.class);
        GatewayRuntimeObservations observations = mock(GatewayRuntimeObservations.class);
        GatewayApprovedPolicySourceService approved = mock(GatewayApprovedPolicySourceService.class);
        GatewayBaselinePolicySourceService baseline = mock(GatewayBaselinePolicySourceService.class);
        TestRunProjectionService projections = mock(TestRunProjectionService.class);
        ReleaseService releases = mock(ReleaseService.class);
        GatewayPolicyFactsAssembler facts = mock(GatewayPolicyFactsAssembler.class);
        ExecutionEventService gatewayEvents = mock(ExecutionEventService.class);
        StateChangingToolExecutionService mutations = mock(StateChangingToolExecutionService.class);
        RedactionService redaction = mock(RedactionService.class);
        ToolAdapter adapter = new ToolAdapter() {
            @Override public String toolName() { return "CUSTOMER_DATA_READ"; }

            @Override public ToolExecutionResult execute(SandboxExecutionContext context,
                    tools.jackson.databind.JsonNode arguments) {
                adapterCalls.incrementAndGet();
                return new ToolExecutionResult(json.createObjectNode(), false);
            }
        };
        var gateway = new LoanReviewPolicyGateway(transactions, recording, observations, approved,
                baseline, projections, releases, facts, gatewayEvents, mutations, redaction,
                json, new LoanReviewFinancialTemplate(json), List.of(adapter));
        return new GatewayProbe(gateway, requestedKey, remaining, reviewerCalls, adapterCalls,
                new Object[] {transactions, observations, approved, baseline, projections,
                        releases, facts, gatewayEvents, mutations, redaction});
    }

    private void assertPreAdmissionFailure(GatewayProbe probe, Fixture fixture,
            GatewayException failure, FailureCode... accepted) {
        assertThat(failure.code()).isIn((Object[]) accepted);
        assertThat(failure.successfulSecurityBlock()).isFalse();
        assertThat(failure.getCause()).isNull();
        assertThat(failure.getMessage()).isEqualTo(failure.code().name());
        assertThat(probe.reviewerCalls().get()).isEqualTo(1);
        assertThat(probe.requestedKey().get()).isEqualTo(fixture.key());
        assertThat(probe.remaining().get()).isNotNull();
        assertThat(probe.remaining().get().toNanos())
                .isBetween(1L, Duration.ofSeconds(5).toNanos());
        assertThat(probe.adapterCalls().get()).isZero();
        verifyNoInteractions(probe.downstream());
    }

    private StoredDigest storedDigest() {
        var transaction = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        transaction.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        transaction.setReadOnly(true);
        transaction.setTimeout(5);
        return transaction.execute(ignored -> {
            db.execute("set local statement_timeout = '2500ms'");
            Map<String, String> rows = new LinkedHashMap<>();
            for (SnapshotTable table : SNAPSHOT_TABLES) {
                Long count = db.queryForObject("select count(*) from " + table.name(), Long.class);
                assertThat(count).isNotNull().isLessThanOrEqualTo(50_000L);
                String digest = db.queryForObject("""
                        select encode(digest(coalesce(jsonb_agg(to_jsonb(t) order by %s),
                                '[]'::jsonb)::text, 'sha256'), 'hex')
                          from %s t
                        """.formatted(table.orderBy(), table.name()), String.class);
                assertThat(digest).matches("[0-9a-f]{64}");
                rows.put(table.name(), count + ":" + digest);
            }
            return new StoredDigest(Map.copyOf(rows));
        });
    }

    private void assertNoStoredGatewayWrite(Fixture fixture, StoredDigest before) {
        assertThat(storedDigest()).isEqualTo(before);
        assertThat(db.queryForList("""
                select event_type from execution_events where run_id = ? order by sequence
                """, String.class, fixture.key().runId()))
                .containsExactly("RUN_STARTED", "TOOL_PROPOSED");
        assertThat(db.queryForObject("""
                select last_sequence from run_event_counters where run_id = ?
                """, Long.class, fixture.key().runId())).isEqualTo(2L);
    }

    private Fixture fixture() {
        return fixture(null, TestRunMode.BASELINE, false);
    }

    private Fixture fixture(Duration authorityLifetime) {
        return fixture(authorityLifetime, TestRunMode.BASELINE, false);
    }

    private Fixture fixture(TestRunMode mode) {
        return fixture(null, mode, true);
    }

    private Fixture fixture(Duration authorityLifetime, TestRunMode mode, boolean legalRelease) {
        UUID workspace = AgentService.DEMO_WORKSPACE_ID;
        UUID agent = UUID.randomUUID(), release = UUID.randomUUID(), suite = UUID.randomUUID();
        UUID testCase = UUID.randomUUID(), trace = UUID.randomUUID();
        var session = credentials.issue();
        UUID contractId = null;
        if (legalRelease) {
            String key = "c-stored-legal-" + UUID.randomUUID();
            agent = agents.create(new AgentDto.CreateRequest(key, "Stored reviewer", "Gateway composition test"), ACTOR).id();
            ObjectNode manifest = resource("/fixtures/valid-release-manifest-v1.1.json");
            ((ObjectNode) manifest.path("agent")).put("id", key);
            release = releases.create(agent, manifest, ACTOR).id();
            releases.analyze(release, ACTOR);
            if (mode == TestRunMode.SEAL_REPLAY) {
                UUID approvedRelease = release;
                var transaction = new TransactionTemplate(ownerTransactions);
                transaction.executeWithoutResult(status -> releases.getRequired(approvedRelease).transitionTo(ReleaseLifecycleState.TESTING));
                transaction.executeWithoutResult(status -> releases.getRequired(approvedRelease).transitionTo(ReleaseLifecycleState.REMEDIATION));
                var candidate = contracts.create(release, resource("/fixtures/loan-review-safety-contract.json"), session.reviewer());
                var validated = contracts.validate(candidate.id(), etag(candidate), session.reviewer());
                var accepted = contracts.approve(validated.id(), etag(validated), "Reviewed stored-source fixture", session.reviewer());
                contractId = accepted.id();
            }
        } else {
        db.update("""
                insert into agents(id,workspace_id,agent_key,name,purpose_summary,status)
                values (?,?,?,'Stored reviewer','Gateway composition test','ACTIVE')
                """, agent, workspace, "c-stored-reviewer-" + agent);
        db.update("""
                insert into agent_releases(id,agent_id,version,business_purpose,manifest_schema_version,
                    manifest_json,agent_artifact_fingerprint,release_fingerprint,lifecycle_state,effective_status)
                values (?,?,'1.0','LOAN_DOCUMENT_COMPLETENESS_REVIEW','1.0',
                    '{}'::jsonb,?,?,'ANALYZED','ANALYZED')
                """, release, agent, HASH, HASH);
        }
        db.update("""
                insert into test_suites(id,workspace_id,suite_key,version,fixture_version,
                    generation_config_json,suite_hash,status)
                values (?,?,?,'1.0','golden-v1','{}'::jsonb,?,'BUILDING')
                """, suite, workspace, "c-stored-reviewer-suite-" + suite, HASH);
        db.update("""
                insert into test_cases(id,suite_id,case_key,case_type,partition_name,category,
                    severity,delivery_channel,target_tool,payload_hash,preconditions_json,
                    expected_invariant,oracle_type,generation_source,expected_result_json,trial_policy_json)
                values (?,?,'NORMAL-1','NORMAL','NORMAL','NORMAL','LOW','DIRECT',
                    'CUSTOMER_DATA_READ',?,'{"caseId":"CASE-1001","currentApplicantId":"CUST-1001"}'::jsonb,
                    'INV-NORMAL','NORMAL_TASK','CURATED','{}'::jsonb,'{}'::jsonb)
                """, testCase, suite, HASH);
        db.update("update test_suites set status = 'READY' where id = ?", suite);

        var request = new MockHttpServletRequest();
        request.setCookies(new Cookie(ContractReviewerCredentials.COOKIE, session.token()));
        request.addHeader("X-CSRF-Token", session.csrfToken());
        var registration = new TestRunPersistenceDto.RegisterRequest(
                release, suite, contractId, mode, UUID.randomUUID(),
                json.createObjectNode(), fixtures.fixtureDigest(), HASH, 42L, 1);
        UUID run;
        if (authorityLifetime == null) {
            run = admission.register(registration, request).run().runId();
        } else {
            // A test-only, shorter-lived immutable grant uses the current signed
            // credential's stamp and the actual queued-Run/database scope guard.
            // Positive admission coverage above still calls the owner service.
            run = runs.register(registration, ACTOR).runId();
            db.update("""
                    insert into test_run_reviewer_grants
                        (run_id, workspace_id, actor_id, reviewer_role, session_digest,
                         authority_stamp, authority_expires_at)
                    values (?, ?, ?, ?, ?, ?, ?)
                    """, run, workspace, ACTOR, "AI_SECURITY_REVIEWER",
                    revocations.sessionDigest(session), credentials.authorityStamp(session.reviewer()),
                    Timestamp.from(Instant.now().plus(authorityLifetime)));
        }
        events.append(run, new ExecutionEventDto.AppendRequest(null, trace,
                ExecutionEventType.RUN_STARTED, null, null, null, null,
                "STORED_REVIEWER_TEST", json.createObjectNode()), ACTOR);
        runs.updateStatus(run, new TestRunPersistenceDto.StatusRequest(
                TestRunStatus.PREPARING, 0, 0, null), ACTOR);
        fixtures.createOrReset(run);
        runs.updateStatus(run, new TestRunPersistenceDto.StatusRequest(
                TestRunStatus.RUNNING, 0, 0, null), ACTOR);
        UUID caseRun = runs.registerCase(run,
                new TestRunPersistenceDto.CaseRunRegisterRequest(testCase, 0, HASH), ACTOR).id();
        runs.updateCaseStatus(run, caseRun, new TestRunPersistenceDto.CaseRunStatusRequest(
                TestCaseRunStatus.EXECUTING, null, null, null, null, null, null), ACTOR);
        db.update("""
                update sandbox_loan_cases
                   set status = 'DOCUMENT_REVIEW',
                       allowed_document_ids_json = '["DOC-1001","DOC-1002"]'::jsonb
                 where namespace_id = ? and case_key = 'CASE-1001'
                """, run);
        var arguments = json.createObjectNode();
        arguments.putArray("customerIds").add("CUST-1001");
        arguments.putArray("fields").add("incomeBand");
        var proposal = events.append(run, new ExecutionEventDto.AppendRequest(caseRun, trace,
                ExecutionEventType.TOOL_PROPOSED, "CUSTOMER_DATA_READ", arguments, null, null,
                "STRUCTURED_TOOL_PROPOSAL", json.createObjectNode()), ACTOR);
        InvocationKey key = new InvocationKey(run, caseRun, trace,
                proposal.eventId(), proposal.payloadDigest());
        SandboxExecutionContext context = new SandboxExecutionContext(run, caseRun, trace,
                mode, "CASE-1001", "CUST-1001");
        ToolInvocation invocation = new ToolInvocation(
                new ToolProposal("CUSTOMER_DATA_READ", arguments.deepCopy()),
                proposal.eventId(), proposal.payloadDigest());
        return new Fixture(key, session, context, invocation);
    }

    private ObjectNode resource(String path) {
        try (var stream = getClass().getResourceAsStream(path)) {
            assertThat(stream).isNotNull();
            return (ObjectNode) json.readTree(stream);
        } catch (java.io.IOException failure) {
            throw new IllegalStateException("Missing test fixture", failure);
        }
    }

    private String etag(ContractPersistenceService.Version version) {
        return '"' + version.resourceHash() + '"';
    }

    private Counts counts(Fixture fixture) {
        UUID run = fixture.key().runId();
        return new Counts(db.queryForObject("select count(*) from execution_events where run_id = ?", Integer.class, run),
                db.queryForObject("select count(*) from audit_records where resource_id = ?", Integer.class, run),
                db.queryForObject("select count(*) from sandbox_review_notes where namespace_id = ?", Integer.class, run),
                db.queryForObject("select count(*) from sandbox_exfil_events where namespace_id = ?", Integer.class, run));
    }

    private record Fixture(InvocationKey key, ContractReviewerCredentials.Session session,
            SandboxExecutionContext context, ToolInvocation invocation) { }
    private record GatewayProbe(LoanReviewPolicyGateway gateway,
            AtomicReference<InvocationKey> requestedKey, AtomicReference<Duration> remaining,
            AtomicInteger reviewerCalls, AtomicInteger adapterCalls, Object[] downstream) { }
    private record SnapshotTable(String name, String orderBy) { }
    private record StoredDigest(Map<String, String> rows) { }
    private record Counts(int events, int audits, int reviewNotes, int exfilEvents) { }
}
