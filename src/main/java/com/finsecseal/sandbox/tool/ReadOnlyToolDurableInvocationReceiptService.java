package com.finsecseal.sandbox.tool;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.policy.GatewayRuntimeObservations.InvocationKey;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
 * Durable read-only Tool admission and redacted completion receipt using the existing V13 table.
 *
 * <p>This class is intentionally not registered as a bean or connected to the Gateway. It does not
 * replay a stored response or establish a raw-output, classification, or state-change observation.
 */
public final class ReadOnlyToolDurableInvocationReceiptService {

    private static final String FAILURE_MESSAGE = "Read-only Tool invocation receipt is incomplete";
    private static final Duration MAX_REMAINING = Duration.ofSeconds(5);

    private static final String CLAIM_SQL = """
            insert into sandbox_tool_idempotency_records
                (id, test_case_run_id, tool_call_id, tool_name, request_digest, state)
            select ?, case_run.id, proposed.id, proposed.tool_name, proposed.payload_digest,
                   'PROCESSING'
              from test_runs run
              join test_case_runs case_run on case_run.test_run_id = run.id
              join sandbox_namespaces namespace on namespace.id = run.id
                   and namespace.state = 'ACTIVE' and namespace.expires_at > now()
              join execution_events proposed on proposed.id = ?
                   and proposed.run_id = run.id
                   and proposed.test_case_run_id = case_run.id
                   and proposed.trace_id = ?
                   and proposed.event_type = 'TOOL_PROPOSED'
                   and proposed.payload_digest = ?
              join execution_events policy on policy.id = ?
                   and policy.run_id = run.id
                   and policy.test_case_run_id = case_run.id
                   and policy.trace_id = proposed.trace_id
                   and policy.event_type = 'POLICY_EVALUATED'
                   and policy.tool_name = proposed.tool_name
                   and policy.sequence > proposed.sequence
                   and policy.metadata_json ->> 'toolCallId' = proposed.id::text
                   and policy.policy_decision_json -> 'allowed' = 'true'::jsonb
                   and policy.policy_decision_json ->> 'decisionType' = 'ALLOW'
                   and policy.policy_decision_json ->> 'evaluationMode' =
                       case when run.mode = 'BASELINE' then 'BASELINE' else 'ENFORCE' end
             where run.id = ? and case_run.id = ?
               and run.status = 'RUNNING' and case_run.status = 'EXECUTING'
               and run.mode in ('BASELINE', 'SEAL_REPLAY', 'HELD_OUT', 'REGRESSION')
               and proposed.tool_name is not null
               and not exists (
                   select 1 from execution_events prior
                    where prior.run_id = run.id
                      and prior.test_case_run_id = case_run.id
                      and prior.metadata_json ->> 'toolCallId' = proposed.id::text
                      and prior.event_type in
                          ('TOOL_REQUEST', 'TOOL_RESPONSE', 'SANDBOX_STATE_CHANGED')
               )
            on conflict (test_case_run_id, tool_call_id) do nothing
            returning id, tool_name
            """;

    private static final String COMPLETE_SQL = """
            update sandbox_tool_idempotency_records receipt
               set state = 'COMPLETED',
                   response_json = response.output_redacted,
                   state_changed = false,
                   request_event_id = request.id,
                   response_event_id = response.id,
                   state_event_id = null,
                   completed_at = now()
              from test_case_runs case_run,
                   test_runs run,
                   execution_events proposed,
                   execution_events policy,
                   execution_events request,
                   execution_events response
             where receipt.id = ?
               and receipt.state = 'PROCESSING'
               and receipt.test_case_run_id = ?
               and receipt.tool_call_id = ?
               and receipt.request_digest = ?
               and receipt.tool_name = ?
               and case_run.id = receipt.test_case_run_id
               and run.id = case_run.test_run_id and run.id = ?
               and proposed.id = receipt.tool_call_id
               and proposed.run_id = run.id and proposed.test_case_run_id = case_run.id
               and proposed.trace_id = ? and proposed.event_type = 'TOOL_PROPOSED'
               and proposed.payload_digest = receipt.request_digest
               and proposed.tool_name = receipt.tool_name
               and policy.id = ? and policy.run_id = run.id
               and policy.test_case_run_id = case_run.id and policy.trace_id = proposed.trace_id
               and policy.event_type = 'POLICY_EVALUATED'
               and policy.tool_name = receipt.tool_name
               and policy.metadata_json ->> 'toolCallId' = proposed.id::text
               and policy.policy_decision_json -> 'allowed' = 'true'::jsonb
               and policy.policy_decision_json ->> 'decisionType' = 'ALLOW'
               and policy.policy_decision_json ->> 'evaluationMode' =
                   case when run.mode = 'BASELINE' then 'BASELINE' else 'ENFORCE' end
               and policy.sequence > proposed.sequence
               and request.id = ? and request.run_id = run.id
               and request.test_case_run_id = case_run.id and request.trace_id = proposed.trace_id
               and request.event_type = 'TOOL_REQUEST' and request.tool_name = receipt.tool_name
               and request.metadata_json ->> 'toolCallId' = proposed.id::text
               and request.input_redacted is not null and request.output_redacted is null
               and request.sequence > policy.sequence
               and response.id = ? and response.run_id = run.id
               and response.test_case_run_id = case_run.id and response.trace_id = proposed.trace_id
               and response.event_type = 'TOOL_RESPONSE' and response.tool_name = receipt.tool_name
               and response.metadata_json ->> 'toolCallId' = proposed.id::text
               and response.metadata_json ->> 'deliveredToAgent' = 'false'
               and response.metadata_json ->> 'deliveryState' = 'PENDING'
               and response.metadata_json ->> 'stateChanged' = 'false'
               and response.input_redacted is null and response.output_redacted is not null
               and response.sequence > request.sequence
            returning receipt.id
            """;

    private final DataSource dataSource;
    private final PlatformTransactionManager transactions;
    private final Map<String, ToolAdapter> adapters;
    private final LongSupplier nanoTime;

    public ReadOnlyToolDurableInvocationReceiptService(DataSource dataSource,
            PlatformTransactionManager transactions, List<ToolAdapter> adapters) {
        this(dataSource, transactions, adapters, System::nanoTime);
    }

    ReadOnlyToolDurableInvocationReceiptService(DataSource dataSource,
            PlatformTransactionManager transactions, List<ToolAdapter> adapters,
            LongSupplier nanoTime) {
        if (dataSource == null || transactions == null || adapters == null) {
            throw new IllegalArgumentException("Read-only Tool receipt dependencies are incomplete");
        }
        this.dataSource = dataSource;
        this.transactions = transactions;
        this.nanoTime = java.util.Objects.requireNonNull(nanoTime);
        Map<String, ToolAdapter> byName = new HashMap<>();
        for (ToolAdapter adapter : adapters) {
            if (adapter == null || adapter.toolName() == null || adapter.toolName().isBlank()
                    || byName.putIfAbsent(adapter.toolName(), adapter) != null) {
                throw new IllegalArgumentException("Read-only Tool adapter registry is invalid");
            }
        }
        this.adapters = Map.copyOf(byName);
    }

    /** The claim transaction commits before the caller may enter the read-only adapter. */
    public ClaimReceipt claim(InvocationKey key, UUID policyEventId, Duration remaining) {
        requireOutsideTransaction(key, remaining);
        if (policyEventId == null) throw incomplete();
        return transact(remaining, (connection, deadline) -> {
            UUID id = UUID.randomUUID();
            try (PreparedStatement statement = connection.prepareStatement(CLAIM_SQL)) {
                statement.setQueryTimeout(queryTimeoutSeconds(deadline));
                statement.setObject(1, id);
                statement.setObject(2, key.toolCallId());
                statement.setObject(3, key.traceId());
                statement.setString(4, key.requestDigest());
                statement.setObject(5, policyEventId);
                statement.setObject(6, key.runId());
                statement.setObject(7, key.caseRunId());
                try (ResultSet rows = statement.executeQuery()) {
                    if (!rows.next()) throw incomplete();
                    UUID storedId = rows.getObject("id", UUID.class);
                    String toolName = rows.getString("tool_name");
                    if (storedId == null || !storedId.equals(id) || toolName == null || rows.next()) {
                        throw incomplete();
                    }
                    ToolAdapter adapter = adapters.get(toolName);
                    if (adapter == null || adapter.effect() != ToolEffect.READ_ONLY) {
                        throw incomplete();
                    }
                    return new ClaimReceipt(id, key, policyEventId, toolName);
                }
            }
        });
    }

    /** Copies only the committed redacted response event into the V13 completion receipt. */
    public CompletionReceipt complete(ClaimReceipt claim, UUID requestEventId,
            UUID responseEventId, Duration remaining) {
        requireOutsideTransaction(claim == null ? null : claim.key(), remaining);
        if (claim == null || claim.id() == null || claim.policyEventId() == null
                || claim.toolName() == null || requestEventId == null || responseEventId == null) {
            throw incomplete();
        }
        return transact(remaining, (connection, deadline) -> {
            try (PreparedStatement statement = connection.prepareStatement(COMPLETE_SQL)) {
                statement.setQueryTimeout(queryTimeoutSeconds(deadline));
                statement.setObject(1, claim.id());
                statement.setObject(2, claim.key().caseRunId());
                statement.setObject(3, claim.key().toolCallId());
                statement.setString(4, claim.key().requestDigest());
                statement.setString(5, claim.toolName());
                statement.setObject(6, claim.key().runId());
                statement.setObject(7, claim.key().traceId());
                statement.setObject(8, claim.policyEventId());
                statement.setObject(9, requestEventId);
                statement.setObject(10, responseEventId);
                try (ResultSet rows = statement.executeQuery()) {
                    if (!rows.next() || !claim.id().equals(rows.getObject(1, UUID.class))
                            || rows.next()) {
                        throw incomplete();
                    }
                }
            }
            return new CompletionReceipt(claim.id(), claim.key(), requestEventId, responseEventId);
        });
    }

    private void requireOutsideTransaction(InvocationKey key, Duration remaining) {
        if (key == null || remaining == null || remaining.isNegative() || remaining.isZero()
                || remaining.compareTo(MAX_REMAINING) > 0
                || TransactionSynchronizationManager.isActualTransactionActive()
                || TransactionSynchronizationManager.isSynchronizationActive()) {
            throw incomplete();
        }
    }

    private <T> T transact(Duration remaining, SqlOperation<T> operation) {
        long deadline = nanoTime.getAsLong() + remaining.toNanos();
        TransactionTemplate transaction = new TransactionTemplate(transactions);
        transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        transaction.setTimeout(queryTimeoutSeconds(deadline));
        try {
            T result = transaction.execute(status -> {
                if (!TransactionSynchronizationManager.isActualTransactionActive()
                        || !TransactionSynchronizationManager.hasResource(dataSource)) {
                    throw incomplete();
                }
                Connection connection = null;
                try {
                    connection = DataSourceUtils.getConnection(dataSource);
                    String previousTimeout = currentTimeout(connection, deadline);
                    setLocalTimeout(connection, deadline, remainingMillis(deadline) + "ms");
                    T value = operation.apply(connection, deadline);
                    setLocalTimeout(connection, deadline, previousTimeout);
                    return value;
                } catch (SQLException | RuntimeException exception) {
                    status.setRollbackOnly();
                    throw incomplete();
                } finally {
                    if (connection != null) DataSourceUtils.releaseConnection(connection, dataSource);
                }
            });
            if (result == null) throw incomplete();
            // A driver/commit can outlast the budget after the final SQL. The committed claim
            // remains a durable fence, but no expired success receipt may be handed to a caller.
            if (deadline - nanoTime.getAsLong() <= 0) throw incomplete();
            return result;
        } catch (RuntimeException exception) {
            // Neither SQL/driver text nor stored response data may escape as a cause.
            throw incomplete();
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

    private static BusinessException incomplete() {
        return new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, FAILURE_MESSAGE);
    }

    @FunctionalInterface
    private interface SqlOperation<T> {
        T apply(Connection connection, long deadline) throws SQLException;
    }

    public record ClaimReceipt(UUID id, InvocationKey key, UUID policyEventId, String toolName) {
        @Override public String toString() { return "ReadOnlyToolClaim[" + id + "]"; }
    }

    public record CompletionReceipt(UUID id, InvocationKey key, UUID requestEventId,
            UUID responseEventId) {
        @Override public String toString() { return "ReadOnlyToolCompletion[" + id + "]"; }
    }
}
