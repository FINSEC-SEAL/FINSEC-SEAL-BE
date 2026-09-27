package com.finsecseal.sandbox.tool;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.policy.GatewayRuntimeObservations.InvocationKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import javax.sql.DataSource;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * B-owned, read-only comparison of committed sandbox rows before and after one Tool call.
 *
 * <p>This is deliberately not a Gateway observations provider or a Spring bean. Equal snapshots
 * do not prove that no intermediate write occurred or attribute a change to this Tool call.
 */
public final class ReadOnlySandboxNetStateSnapshotService {

    static final int MAX_SLOTS = 16;
    static final int MAX_ROWS = 10_000;
    static final long MAX_BYTES = 8L * 1024 * 1024;
    static final int MAX_ROW_BYTES = 1024 * 1024;
    static final long TTL_NANOS = Duration.ofSeconds(5).toNanos();
    private static final Duration MAX_REMAINING = Duration.ofSeconds(5);
    private static final String FAILURE_MESSAGE = "Sandbox net-state observation is incomplete";
    private static final String DIGEST_PATTERN = "[0-9a-f]{64}";

    // Fixed, exhaustive V3 sandbox state allowlist. Each row digest includes every stored column.
    // The namespace table additionally guards its fixture binding, state and expiry metadata.
    private static final List<Table> TABLES = List.of(
            new Table("sandbox_namespaces", "id", "id", null),
            new Table("sandbox_customers", "namespace_id", "customer_key", null),
            new Table("sandbox_loan_cases", "namespace_id", "case_key", null),
            new Table("sandbox_documents", "namespace_id", "document_key", null),
            new Table("sandbox_loan_policies", "namespace_id", "policy_key", "version"),
            new Table("sandbox_review_notes", "namespace_id", "note_key", null),
            new Table("sandbox_loan_decisions", "namespace_id", "case_key", null),
            new Table("sandbox_exfil_events", "namespace_id", "event_key", null));

    private final DataSource dataSource;
    private final PlatformTransactionManager transactions;
    private final StoredGatewayPreCallScopeSource scopeSource;
    private final LongSupplier nanoTime;
    private final Map<InvocationKey, Slot> slots = new HashMap<>();

    public ReadOnlySandboxNetStateSnapshotService(DataSource dataSource,
            PlatformTransactionManager transactions, StoredGatewayPreCallScopeSource scopeSource) {
        this(dataSource, transactions, scopeSource, System::nanoTime);
    }

    ReadOnlySandboxNetStateSnapshotService(DataSource dataSource,
            PlatformTransactionManager transactions, StoredGatewayPreCallScopeSource scopeSource,
            LongSupplier nanoTime) {
        this.dataSource = Objects.requireNonNull(dataSource);
        this.transactions = Objects.requireNonNull(transactions);
        this.scopeSource = Objects.requireNonNull(scopeSource);
        this.nanoTime = Objects.requireNonNull(nanoTime);
    }

    /** Captures the global persisted net state, including namespaces other than the requested one. */
    public CaptureReceipt captureBefore(InvocationKey key, Duration remaining) {
        requireOutsideTransaction(key, remaining);
        Slot slot = reserve(key);
        try {
            Snapshot snapshot = snapshot(key, remaining);
            synchronized (slots) {
                expire(nanoTime.getAsLong());
                if (slots.get(key) != slot || slot.state != State.RESERVED) throw incomplete();
                slot.namespaceId = snapshot.namespaceId;
                slot.fingerprint = snapshot.fingerprint;
                slot.state = State.READY;
                return new CaptureReceipt(key, slot.captureId, snapshot.namespaceId,
                        snapshot.fingerprint);
            }
        } catch (RuntimeException failure) {
            fail(key, slot);
            throw incomplete();
        }
    }

    /** Accepts only an identical committed after-snapshot; no row or change attribution escapes. */
    public NetUnchangedReceipt compareAfter(InvocationKey key, CaptureReceipt before,
            Duration remaining) {
        requireOutsideTransaction(key, remaining);
        Slot slot = beginComparison(key, before);
        try {
            Snapshot after = snapshot(key, remaining);
            synchronized (slots) {
                expire(nanoTime.getAsLong());
                if (slots.get(key) != slot || slot.state != State.COMPARING
                        || !slot.namespaceId.equals(after.namespaceId)
                        || !slot.fingerprint.equals(after.fingerprint)) {
                    throw incomplete();
                }
                String fingerprint = slot.fingerprint;
                slot.fingerprint = null;
                slot.state = State.CONSUMED;
                return new NetUnchangedReceipt(key, slot.captureId, after.namespaceId,
                        fingerprint);
            }
        } catch (RuntimeException failure) {
            fail(key, slot);
            throw incomplete();
        }
    }

    private Slot reserve(InvocationKey key) {
        synchronized (slots) {
            long now = nanoTime.getAsLong();
            expire(now);
            if (slots.containsKey(key) || slots.size() >= MAX_SLOTS) throw incomplete();
            Slot slot = new Slot(UUID.randomUUID(), now);
            slots.put(key, slot);
            return slot;
        }
    }

    private Slot beginComparison(InvocationKey key, CaptureReceipt receipt) {
        synchronized (slots) {
            expire(nanoTime.getAsLong());
            Slot slot = slots.get(key);
            if (receipt == null || slot == null || slot.state != State.READY
                    || !key.equals(receipt.key()) || !slot.captureId.equals(receipt.captureId())
                    || !slot.namespaceId.equals(receipt.namespaceId())
                    || !slot.fingerprint.equals(receipt.fingerprint())) {
                throw incomplete();
            }
            slot.state = State.COMPARING;
            return slot;
        }
    }

    private void fail(InvocationKey key, Slot slot) {
        synchronized (slots) {
            expire(nanoTime.getAsLong());
            if (slots.get(key) == slot && slot.state != State.CONSUMED) {
                slot.namespaceId = null;
                slot.fingerprint = null;
                slot.state = State.FAILED;
            }
        }
    }

    private void expire(long now) {
        // Subtraction works across nanoTime wrap for intervals shorter than 2^63 ns.
        slots.values().removeIf(slot -> now - slot.reservedAt >= TTL_NANOS);
    }

    private Snapshot snapshot(InvocationKey key, Duration remaining) {
        long deadline = nanoTime.getAsLong() + remaining.toNanos();
        TransactionTemplate transaction = new TransactionTemplate(transactions);
        transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        transaction.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        transaction.setReadOnly(true);
        transaction.setTimeout(queryTimeoutSeconds(deadline));
        try {
            Snapshot snapshot = transaction.execute(status -> {
                if (!TransactionSynchronizationManager.isActualTransactionActive()
                        || !TransactionSynchronizationManager.hasResource(dataSource)
                        || !TransactionSynchronizationManager.isCurrentTransactionReadOnly()
                        || !Objects.equals(TransactionSynchronizationManager.getCurrentTransactionIsolationLevel(),
                                Connection.TRANSACTION_REPEATABLE_READ)) {
                    throw incomplete();
                }
                Connection connection = null;
                try {
                    connection = DataSourceUtils.getConnection(dataSource);
                    setTransactionReadOnly(connection, deadline);
                    String previousTimeout = currentTimeout(connection, deadline);
                    setLocalTimeout(connection, deadline, remainingMillis(deadline) + "ms");
                    var scope = scopeSource.resolve(key, remainingDuration(deadline));
                    if (!key.equals(scope.key()) || !key.runId().equals(scope.namespace().namespaceId())) {
                        throw incomplete();
                    }
                    String fingerprint = fingerprint(connection, deadline);
                    setLocalTimeout(connection, deadline, previousTimeout);
                    return new Snapshot(scope.namespace().namespaceId(), fingerprint);
                } catch (SQLException | RuntimeException failure) {
                    status.setRollbackOnly();
                    throw incomplete();
                } finally {
                    if (connection != null) DataSourceUtils.releaseConnection(connection, dataSource);
                }
            });
            if (snapshot == null || deadline - nanoTime.getAsLong() <= 0) throw incomplete();
            return snapshot;
        } catch (RuntimeException failure) {
            // No SQL/driver cause or stored row may cross the public failure boundary.
            throw incomplete();
        }
    }

    private String fingerprint(Connection connection, long deadline) throws SQLException {
        MessageDigest digest = sha256();
        update(digest, "finsec:sandbox-net-state:v1");
        Budget budget = new Budget();
        for (Table table : TABLES) {
            update(digest, "table:start");
            update(digest, table.name);
            int tableRows = scanTable(connection, deadline, table, digest, budget);
            update(digest, "table:end");
            update(digest, Integer.toString(tableRows));
        }
        update(digest, "all:end");
        update(digest, Integer.toString(budget.rows));
        return "sha256:" + java.util.HexFormat.of().formatHex(digest.digest());
    }

    private int scanTable(Connection connection, long deadline, Table table, MessageDigest digest,
            Budget budget) throws SQLException {
        int tableRows = 0;
        try (PreparedStatement statement = connection.prepareStatement(table.sql())) {
            statement.setQueryTimeout(queryTimeoutSeconds(deadline));
            statement.setFetchSize(64);
            statement.setInt(1, MAX_ROW_BYTES);
            statement.setInt(2, MAX_ROWS + 1);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    if (deadline - nanoTime.getAsLong() <= 0) throw incomplete();
                    long bytes = rows.getLong("row_bytes");
                    if (rows.wasNull()) throw incomplete();
                    String rowDigest = rows.getString("row_digest");
                    if (rowDigest == null || !rowDigest.matches(DIGEST_PATTERN)) throw incomplete();
                    budget.add(bytes);
                    tableRows++;
                    update(digest, "row");
                    update(digest, Long.toString(bytes));
                    update(digest, rowDigest);
                }
            }
        }
        return tableRows;
    }

    private void setTransactionReadOnly(Connection connection, long deadline) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("set transaction read only")) {
            statement.setQueryTimeout(queryTimeoutSeconds(deadline));
            statement.execute();
        }
    }

    private String currentTimeout(Connection connection, long deadline) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("show statement_timeout")) {
            statement.setQueryTimeout(queryTimeoutSeconds(deadline));
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) throw incomplete();
                String timeout = rows.getString(1);
                if (timeout == null || timeout.isBlank() || rows.next()) throw incomplete();
                return timeout;
            }
        }
    }

    private void setLocalTimeout(Connection connection, long deadline, String value) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "select set_config('statement_timeout', ?, true)")) {
            statement.setQueryTimeout(queryTimeoutSeconds(deadline));
            statement.setString(1, value);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next() || rows.getString(1) == null || rows.next()) throw incomplete();
            }
        }
    }

    private int queryTimeoutSeconds(long deadline) {
        long seconds = TimeUnit.NANOSECONDS.toSeconds(deadline - nanoTime.getAsLong());
        if (seconds < 1) throw incomplete();
        return (int) Math.min(seconds, 5);
    }

    private long remainingMillis(long deadline) {
        long millis = TimeUnit.NANOSECONDS.toMillis(deadline - nanoTime.getAsLong());
        if (millis < 1_000) throw incomplete();
        return millis;
    }

    private Duration remainingDuration(long deadline) {
        long nanos = deadline - nanoTime.getAsLong();
        if (nanos < TimeUnit.SECONDS.toNanos(1)) throw incomplete();
        return Duration.ofNanos(nanos);
    }

    private static void requireOutsideTransaction(InvocationKey key, Duration remaining) {
        if (key == null || remaining == null || remaining.isNegative() || remaining.isZero()
                || remaining.compareTo(MAX_REMAINING) > 0
                || TransactionSynchronizationManager.isActualTransactionActive()
                || TransactionSynchronizationManager.isSynchronizationActive()) {
            throw incomplete();
        }
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException failure) {
            throw incomplete();
        }
    }

    private static void update(MessageDigest digest, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        digest.update(ByteBuffer.allocate(4).putInt(bytes.length).array());
        digest.update(bytes);
    }

    private static BusinessException incomplete() {
        return new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, FAILURE_MESSAGE);
    }

    private record Snapshot(UUID namespaceId, String fingerprint) { }

    private static final class Budget {
        private int rows;
        private long bytes;

        private void add(long rowBytes) {
            if (rowBytes < 1 || rowBytes > MAX_ROW_BYTES || rows >= MAX_ROWS
                    || bytes > MAX_BYTES - rowBytes) throw incomplete();
            rows++;
            bytes += rowBytes;
        }
    }

    private enum State { RESERVED, READY, COMPARING, CONSUMED, FAILED }

    private static final class Slot {
        private final UUID captureId;
        private final long reservedAt;
        private State state = State.RESERVED;
        private UUID namespaceId;
        private String fingerprint;

        private Slot(UUID captureId, long reservedAt) {
            this.captureId = captureId;
            this.reservedAt = reservedAt;
        }
    }

    private record Table(String name, String namespaceColumn, String firstKey, String secondKey) {
        private String sql() {
            String pk2 = secondKey == null ? "null::text" : "t." + secondKey + "::text";
            String order = "t." + namespaceColumn + ", t." + firstKey
                    + (secondKey == null ? "" : ", t." + secondKey);
            return """
                    select octet_length(convert_to(r.body, 'UTF8')) row_bytes,
                           case when octet_length(convert_to(r.body, 'UTF8')) <= ?
                                then encode(digest(convert_to(r.body, 'UTF8'), 'sha256'), 'hex')
                           end row_digest
                      from (
                          select t.%s::text namespace_id, t.%s::text pk1,
                                 %s pk2, to_jsonb(t)::text body
                            from %s t
                           order by %s
                           limit ?
                      ) r
                     order by r.namespace_id, r.pk1, r.pk2
                    """.formatted(namespaceColumn, firstKey, pk2, name, order);
        }
    }

    public record CaptureReceipt(InvocationKey key, UUID captureId, UUID namespaceId,
            String fingerprint) {
        @Override public String toString() { return "SandboxNetStateCapture[" + captureId + "]"; }
    }

    public record NetUnchangedReceipt(InvocationKey key, UUID captureId, UUID namespaceId,
            String fingerprint) {
        @Override public String toString() { return "SandboxNetStateUnchanged[" + captureId + "]"; }
    }
}
