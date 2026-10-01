package com.finsecseal.policy;

import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.contract.SafetyContractLifecyclePolicy;
import com.finsecseal.evidence.StoredRunReviewerAuthoritySource;
import com.finsecseal.policy.GatewayRuntimeObservations.InvocationKey;
import com.finsecseal.sandbox.tool.StoredGatewayPreCallScopeSource;
import com.zaxxer.hikari.HikariDataSource;
import io.micrometer.core.instrument.FunctionCounter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Metrics;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import javax.sql.DataSource;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.jdbc.datasource.ConnectionHolder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.DefaultTransactionStatus;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Combines existing owner facts for one proposal; it does not create reviewer authority. */
@Component(LoanReviewPolicyGatewayConfiguration.REVIEWER_CONTEXT_BEAN)
@ConditionalOnProperty(name = {
        "finsec.policy.gateway.enabled", "finsec.policy.gateway.reviewer.stored.enabled"
}, havingValue = "true")
public final class StoredGatewayReviewerContextSource implements GatewayReviewerContextSource {
    private static final String FAILURE_EVENTS = "finsec.policy.gateway.reviewer.failure.events";
    private static final Duration MAX_BUDGET = Duration.ofSeconds(5);
    private static final long MIN_READER_NANOS = TimeUnit.SECONDS.toNanos(1);
    private static final ThreadPoolExecutor READERS = new ThreadPoolExecutor(4, 4, 0,
            TimeUnit.MILLISECONDS, new SynchronousQueue<>(), runnable -> {
                Thread thread = new Thread(runnable, "stored-gateway-reviewer");
                thread.setDaemon(true);
                return thread;
            }, new ThreadPoolExecutor.AbortPolicy());
    private static final ScheduledThreadPoolExecutor DEADLINES = new ScheduledThreadPoolExecutor(2,
            runnable -> {
                Thread thread = new Thread(runnable, "stored-gateway-reviewer-deadline");
                thread.setDaemon(true);
                return thread;
            });
    // A scheduled timeout must own a slot until both its callback and reader really finish.
    // Otherwise two blocked aborts could strand every deadline thread behind queued work.
    private static final Semaphore DEADLINE_SLOTS = new Semaphore(2);
    static {
        DEADLINES.setRemoveOnCancelPolicy(true);
        registerDiagnostics(Metrics.globalRegistry);
    }

    private enum OperationalFailure {
        DEADLINE_CAPACITY("deadline_capacity"), INTERRUPTED("interrupted"),
        CALLER_TIMEOUT("caller_timeout"), EXECUTION_FAILURE("execution_failure"),
        RESOLUTION_FAILURE("resolution_failure"), RETIREMENT_FAILURE("retirement_failure"),
        ABORT_FAILURE("abort_failure");

        private final String category;
        private final AtomicLong events = new AtomicLong();

        OperationalFailure(String category) {
            this.category = category;
        }
    }

    private static void registerDiagnostics(MeterRegistry registry) {
        // Registration is startup-only. Failure paths never call a registry or exporter.
        for (OperationalFailure failure : OperationalFailure.values()) {
            try {
                FunctionCounter.builder(FAILURE_EVENTS, failure.events, AtomicLong::doubleValue)
                        .tag("reason", failure.category)
                        .description("Stored reviewer operational failure events; not security blocks")
                        .register(registry);
            } catch (RuntimeException unavailable) {
                // Unavailable diagnostics must not alter authority or public error behavior.
            }
        }
    }

    private static void recordFailure(OperationalFailure failure) {
        failure.events.incrementAndGet();
    }

    private final DataSource dataSource;
    private final HikariDataSource pool;
    private final StoredRunReviewerAuthoritySource authorities;
    private final StoredGatewayPreCallScopeSource scopes;

    public StoredGatewayReviewerContextSource(DataSource dataSource,
            StoredRunReviewerAuthoritySource authorities, StoredGatewayPreCallScopeSource scopes) {
        if (!(dataSource instanceof HikariDataSource hikari) || !boundedPool(hikari)) {
            throw new IllegalStateException("Stored Gateway reviewer requires a connection timeout below five seconds");
        }
        this.dataSource = dataSource;
        this.pool = hikari;
        this.authorities = authorities;
        this.scopes = scopes;
    }

    @Override
    public Resolution resolve(InvocationKey key, Duration remaining) {
        if (key == null || remaining == null || remaining.isNegative() || remaining.isZero()
                || remaining.compareTo(MAX_BUDGET) > 0 || !boundedPool(pool)
                || TransactionSynchronizationManager.isActualTransactionActive()
                || TransactionSynchronizationManager.hasResource(dataSource)
                || TransactionSynchronizationManager.isSynchronizationActive()) {
            return null;
        }
        long budget = remaining.toNanos();
        // A and B each need at least a second for their finite JDBC statement timeout.
        if (budget <= Math.max(MIN_READER_NANOS, TimeUnit.MILLISECONDS.toNanos(pool.getConnectionTimeout()))) {
            return null;
        }
        if (!DEADLINE_SLOTS.tryAcquire()) {
            recordFailure(OperationalFailure.DEADLINE_CAPACITY);
            return null;
        }
        long deadline = System.nanoTime() + budget;
        DeadlineLease lease = new DeadlineLease(pool);
        ScheduledFuture<?> watchdog = null;
        Future<ReviewedSnapshot> worker = null;
        ReviewedSnapshot snapshot = null;
        try {
            watchdog = DEADLINES.schedule(() -> {
                if (!lease.startWatchdog()) return;
                try {
                    lease.expire();
                } finally {
                    lease.finishWatchdog();
                }
            }, timeRemaining(deadline), TimeUnit.NANOSECONDS);
            worker = READERS.submit(() -> {
                if (!lease.startWorker()) return null;
                try {
                    return resolveWithBoundConnection(key, deadline, lease);
                } finally {
                    lease.finishWorker();
                }
            });
            snapshot = worker.get(timeRemaining(deadline), TimeUnit.NANOSECONDS);
        } catch (InterruptedException failure) {
            recordFailure(OperationalFailure.INTERRUPTED);
            Thread.currentThread().interrupt();
        } catch (TimeoutException failure) {
            recordFailure(OperationalFailure.CALLER_TIMEOUT);
        } catch (ExecutionException | RuntimeException failure) {
            recordFailure(OperationalFailure.EXECUTION_FAILURE);
            // Neither SQL nor A/B operational errors may escape into Gateway error classification.
        } finally {
            if (!lease.workerSettled()) {
                // Do not run JDBC eviction or driver abort on the deadline caller. Future.cancel
                // marks the Future done before a running JDBC thread has actually exited.
                lease.markExpired();
                lease.cancelUnstartedWorker();
                if (worker != null) worker.cancel(true);
            }
            if (lease.workerSettled() && !lease.retirementFailed()
                    && lease.disarmUnstartedWatchdog()
                    && watchdog != null) {
                watchdog.cancel(false);
            }
        }
        // Transaction cleanup and retirement can outlive the authority checked by the reader.
        // Keep its original expiration until all caller-side finalization has also completed.
        return snapshot != null && !lease.expired.get() && System.nanoTime() < deadline
                && Instant.now().isBefore(snapshot.authorityExpiresAt())
                ? snapshot.resolution() : null;
    }

    private record ReviewedSnapshot(Resolution resolution, Instant authorityExpiresAt) { }

    private ReviewedSnapshot resolveWithBoundConnection(InvocationKey key, long deadline, DeadlineLease lease) {
        Connection connection = null;
        boolean bound = false;
        ReviewedSnapshot result = null;
        boolean completed = false;
        try {
            connection = pool.getConnection();
            lease.attach(connection);
            if (lease.expired.get() || System.nanoTime() >= deadline) return null;
            tightenNetworkTimeout(connection, deadline);
            TransactionSynchronizationManager.bindResource(dataSource, new ConnectionHolder(connection));
            bound = true;

            TransactionTemplate transaction = new TransactionTemplate(
                    new DeadlineTransactionManager(dataSource, deadline));
            transaction.setReadOnly(true);
            transaction.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
            transaction.setTimeout((int) Math.max(1, TimeUnit.NANOSECONDS.toSeconds(timeRemaining(deadline))));
            result = transaction.execute(status -> {
                try {
                    return readBoundSnapshot(key, deadline);
                } finally {
                    status.setRollbackOnly();
                }
            });
            completed = true;
        } catch (SQLException | RuntimeException failure) {
            recordFailure(OperationalFailure.RESOLUTION_FAILURE);
            // A propagated setup, owner-read, rollback, or cleanup failure grants no authority.
            return null;
        } finally {
            if (bound) TransactionSynchronizationManager.unbindResourceIfPossible(dataSource);
            if (connection != null) {
                // Evict the still-borrowed proxy before disarming the watchdog. Hikari must not
                // lend its physical connection to another caller while a late abort can race.
                // Closing the proxy after eviction would reset already-retired pool state.
                try {
                    lease.retire(connection);
                    lease.clear(connection);
                } catch (RuntimeException failure) {
                    recordFailure(OperationalFailure.RETIREMENT_FAILURE);
                    completed = false;
                    lease.markRetirementFailed();
                    // Keep the borrowed reference so an armed watchdog can retry retirement.
                }
            }
        }
        return completed && !lease.expired.get() && System.nanoTime() < deadline ? result : null;
    }

    private ReviewedSnapshot readBoundSnapshot(InvocationKey key, long deadline) {
        Connection connection = DataSourceUtils.getConnection(dataSource);
        try {
            tightenNetworkTimeout(connection, deadline);
            if (connection.getAutoCommit() || !connection.isReadOnly()
                    || connection.getTransactionIsolation() != Connection.TRANSACTION_REPEATABLE_READ) {
                return null;
            }
            var authority = authorities.resolve(key, timeLeft(deadline));
            if (authority == null || !key.equals(authority.key()) || authority.expiresAt() == null
                    || !Instant.now().isBefore(authority.expiresAt())) return null;
            // Validate C's reviewer contract; the unchanged A reader verifies credentials/stamps.
            ReviewerContext reviewer = new ReviewerContext(authority.workspaceId(), authority.actorId(),
                    authority.role(), authority.sessionReference(), true, true, false);
            SafetyContractLifecyclePolicy.requireReviewerContext(reviewer, authority.workspaceId());
            if (!reviewer.sessionId().matches("sha256:[0-9a-f]{64}")) return null;
            tightenNetworkTimeout(connection, deadline);
            var scope = scopes.resolve(key, timeLeft(deadline));
            if (scope == null || !key.equals(scope.key()) || !key.runId().equals(scope.namespace().namespaceId())
                    || !key.runId().equals(scope.serverContext().runId())
                    || !key.caseRunId().equals(scope.serverContext().caseRunId())
                    || !key.traceId().equals(scope.serverContext().traceId())
                    || !Instant.now().isBefore(authority.expiresAt())
                    || !sameBoundConnection(connection)
                    || System.nanoTime() >= deadline) {
                return null;
            }
            // A verified this opaque digest at Run admission, not by a fresh browser CSRF exchange.
            return new ReviewedSnapshot(new Resolution(key, reviewer), authority.expiresAt());
        } catch (SQLException failure) {
            return null;
        } finally {
            DataSourceUtils.releaseConnection(connection, dataSource);
        }
    }

    private static Duration timeLeft(long deadline) {
        long nanos = deadline - System.nanoTime();
        if (nanos < MIN_READER_NANOS) {
            throw new IllegalStateException("Stored Gateway reviewer deadline exhausted");
        }
        return Duration.ofNanos(nanos);
    }

    private static long timeRemaining(long deadline) {
        long nanos = deadline - System.nanoTime();
        if (nanos <= 0) throw new IllegalStateException("Stored Gateway reviewer deadline exhausted");
        return nanos;
    }

    private static void tightenNetworkTimeout(Connection connection, long deadline) throws SQLException {
        long millis = TimeUnit.NANOSECONDS.toMillis(timeRemaining(deadline));
        connection.setNetworkTimeout(Runnable::run, (int) Math.max(1, Math.min(millis, Integer.MAX_VALUE)));
    }

    private static final class DeadlineLease {
        private static final int ARMED = 0;
        private static final int RUNNING = 1;
        private static final int SETTLED = 2;

        private final HikariDataSource pool;
        private final AtomicBoolean expired = new AtomicBoolean();
        private final AtomicBoolean retirementFailed = new AtomicBoolean();
        private final AtomicReference<Connection> connection = new AtomicReference<>();
        private final AtomicInteger workerState = new AtomicInteger(ARMED);
        private final AtomicInteger watchdogState = new AtomicInteger(ARMED);
        private final AtomicBoolean slotReleased = new AtomicBoolean();

        private DeadlineLease(HikariDataSource pool) {
            this.pool = pool;
        }

        private void attach(Connection borrowed) {
            connection.set(borrowed);
            if (expired.get()) retireAndAbort(borrowed);
        }

        private void markExpired() {
            expired.set(true);
        }

        private void markRetirementFailed() {
            retirementFailed.set(true);
            markExpired();
        }

        private boolean retirementFailed() {
            return retirementFailed.get();
        }

        private void expire() {
            markExpired();
            Connection borrowed = connection.get();
            if (borrowed != null) retireAndAbort(borrowed);
        }

        private boolean startWorker() {
            return workerState.compareAndSet(ARMED, RUNNING);
        }

        private void finishWorker() {
            workerState.set(SETTLED);
            releaseSlotIfSettled();
        }

        private void cancelUnstartedWorker() {
            if (workerState.compareAndSet(ARMED, SETTLED)) releaseSlotIfSettled();
        }

        private boolean workerSettled() {
            return workerState.get() == SETTLED;
        }

        private boolean startWatchdog() {
            return watchdogState.compareAndSet(ARMED, RUNNING);
        }

        private void finishWatchdog() {
            watchdogState.set(SETTLED);
            releaseSlotIfSettled();
        }

        private boolean disarmUnstartedWatchdog() {
            if (!watchdogState.compareAndSet(ARMED, SETTLED)) return false;
            releaseSlotIfSettled();
            return true;
        }

        private void releaseSlotIfSettled() {
            if (workerState.get() == SETTLED && watchdogState.get() == SETTLED
                    && slotReleased.compareAndSet(false, true)) {
                DEADLINE_SLOTS.release();
            }
        }

        private void clear(Connection borrowed) {
            connection.compareAndSet(borrowed, null);
        }

        private void retire(Connection borrowed) {
            pool.evictConnection(borrowed);
        }

        private void retireAndAbort(Connection borrowed) {
            try {
                retire(borrowed);
            } catch (RuntimeException ignored) {
                recordFailure(OperationalFailure.RETIREMENT_FAILURE);
                // The worker also retires the lease; an uncertain pool state never grants authority.
            }
            abort(borrowed);
        }

        private static void abort(Connection borrowed) {
            try {
                borrowed.abort(Runnable::run);
            } catch (SQLException | RuntimeException ignored) {
                recordFailure(OperationalFailure.ABORT_FAILURE);
                // The worker also retires the borrowed lease; a failed abort never grants authority.
            }
        }
    }

    private static final class DeadlineTransactionManager extends DataSourceTransactionManager {
        private final DataSource dataSource;
        private final long deadline;

        private DeadlineTransactionManager(DataSource dataSource, long deadline) {
            super(dataSource);
            this.dataSource = dataSource;
            this.deadline = deadline;
            setEnforceReadOnly(true);
        }

        @Override
        protected void prepareTransactionalConnection(Connection connection,
                TransactionDefinition definition) throws SQLException {
            if (!definition.isReadOnly()) throw new SQLException("Reviewer transaction must be read-only");
            tightenNetworkTimeout(connection, deadline);
            long seconds = TimeUnit.NANOSECONDS.toSeconds(timeRemaining(deadline));
            if (seconds < 1) throw new SQLException("Reviewer setup deadline exhausted");
            try (Statement statement = connection.createStatement()) {
                statement.setQueryTimeout((int) Math.min(seconds, 5));
                statement.executeUpdate("SET TRANSACTION READ ONLY");
            }
        }

        @Override
        protected void doRollback(DefaultTransactionStatus status) {
            Connection connection = DataSourceUtils.getConnection(dataSource);
            try {
                tightenNetworkTimeout(connection, deadline);
                super.doRollback(status);
            } catch (SQLException failure) {
                throw new IllegalStateException("Reviewer rollback deadline unavailable");
            } finally {
                DataSourceUtils.releaseConnection(connection, dataSource);
            }
        }

        @Override
        protected void doCommit(DefaultTransactionStatus status) {
            throw new IllegalStateException("Reviewer transaction must roll back");
        }

        @Override
        protected void doCleanupAfterCompletion(Object transaction) {
            Connection connection = DataSourceUtils.getConnection(dataSource);
            try {
                tightenNetworkTimeout(connection, deadline);
                super.doCleanupAfterCompletion(transaction);
            } catch (SQLException failure) {
                throw new IllegalStateException("Reviewer cleanup deadline unavailable");
            } finally {
                DataSourceUtils.releaseConnection(connection, dataSource);
            }
        }
    }

    private boolean sameBoundConnection(Connection expected) {
        Connection current = DataSourceUtils.getConnection(dataSource);
        try {
            return current == expected;
        } finally {
            DataSourceUtils.releaseConnection(current, dataSource);
        }
    }

    private static boolean boundedPool(HikariDataSource pool) {
        return pool.getConnectionTimeout() > 0 && pool.getConnectionTimeout() < 5_000;
    }
}
