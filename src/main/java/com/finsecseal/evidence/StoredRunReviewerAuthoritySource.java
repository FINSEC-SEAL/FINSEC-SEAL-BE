package com.finsecseal.evidence;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.platform.contract.ContractReviewerCredentials;
import com.finsecseal.policy.GatewayRuntimeObservations.InvocationKey;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Current authority facts for one server-stored Tool proposal. This is not a Gateway reviewer bean.
 * The V17 grant is trusted application admission evidence, not a cryptographic proof against DB admins.
 * Its session digest represents admission-time CSRF, never a fresh browser session or CSRF check.
 */
@Component
public final class StoredRunReviewerAuthoritySource {
    private static final String AUTHORITY_SQL = """
            select grant_row.workspace_id, grant_row.actor_id, grant_row.reviewer_role,
                   grant_row.session_digest, grant_row.authority_stamp,
                   grant_row.authority_expires_at
              from execution_events proposed
              join test_case_runs case_run on case_run.id = proposed.test_case_run_id
                   and case_run.test_run_id = proposed.run_id
              join test_runs run on run.id = case_run.test_run_id
              join test_cases test_case on test_case.id = case_run.test_case_id
                   and test_case.suite_id = run.suite_id
              join agent_releases release on release.id = run.release_id
              join agents agent on agent.id = release.agent_id
              join test_run_reviewer_grants grant_row on grant_row.run_id = run.id
                   and grant_row.workspace_id = agent.workspace_id
                   and grant_row.workspace_id = proposed.workspace_id
             where proposed.id = ? and proposed.run_id = ?
               and case_run.id = ? and proposed.trace_id = ?
               and proposed.payload_digest = ? and proposed.event_type = 'TOOL_PROPOSED'
               and run.status = 'RUNNING' and case_run.status = 'EXECUTING'
               and proposed.created_at >= grant_row.created_at
               and grant_row.reviewer_role = 'AI_SECURITY_REVIEWER'
               and grant_row.authority_expires_at > clock_timestamp()
               and not exists (
                   select 1 from reviewer_session_revocations revoked
                    where revoked.session_digest = grant_row.session_digest
               )
             limit 2
            """;

    private final DataSource dataSource;
    private final ContractReviewerCredentials credentials;

    public StoredRunReviewerAuthoritySource(DataSource dataSource, ContractReviewerCredentials credentials) {
        this.dataSource = dataSource;
        this.credentials = credentials;
    }

    /** Caller must have already acquired a bound read-only repeatable-read connection within its deadline. */
    public AuthoritySnapshot resolve(InvocationKey key, Duration remaining) {
        if (key == null || remaining == null || remaining.isNegative() || remaining.isZero()
                || remaining.compareTo(Duration.ofSeconds(5)) > 0
                || !TransactionSynchronizationManager.isActualTransactionActive()
                || !TransactionSynchronizationManager.isCurrentTransactionReadOnly()
                || !Integer.valueOf(Connection.TRANSACTION_REPEATABLE_READ).equals(
                        TransactionSynchronizationManager.getCurrentTransactionIsolationLevel())
                || !TransactionSynchronizationManager.hasResource(dataSource)) {
            throw unavailable();
        }

        long deadline = System.nanoTime() + remaining.toNanos();
        Connection connection = null;
        try {
            // hasResource above prevents an unbounded new pool acquisition in this reader.
            connection = DataSourceUtils.getConnection(dataSource);
            if (connection.getAutoCommit() || !connection.isReadOnly()
                    || connection.getTransactionIsolation() != Connection.TRANSACTION_REPEATABLE_READ) {
                throw unavailable();
            }
            String originalTimeout = currentTimeout(connection, deadline);
            setLocalTimeout(connection, deadline, remainingMillis(deadline) + "ms");
            AuthoritySnapshot authority = readAuthority(connection, deadline, key);
            setLocalTimeout(connection, deadline, originalTimeout);
            if (!Instant.now().isBefore(authority.expiresAt()) || System.nanoTime() >= deadline) {
                throw unavailable();
            }
            return authority;
        } catch (SQLException | RuntimeException failure) {
            // Never attach SQL, stored values, credentials or driver causes to the public error.
            throw unavailable();
        } finally {
            if (connection != null) DataSourceUtils.releaseConnection(connection, dataSource);
        }
    }

    private AuthoritySnapshot readAuthority(Connection connection, long deadline, InvocationKey key)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(AUTHORITY_SQL)) {
            statement.setQueryTimeout(queryTimeoutSeconds(deadline));
            statement.setObject(1, key.toolCallId());
            statement.setObject(2, key.runId());
            statement.setObject(3, key.caseRunId());
            statement.setObject(4, key.traceId());
            statement.setString(5, key.requestDigest());
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) throw unavailable();
                UUID workspace = rows.getObject("workspace_id", UUID.class);
                String actor = rows.getString("actor_id");
                String role = rows.getString("reviewer_role");
                String sessionReference = rows.getString("session_digest");
                String stamp = rows.getString("authority_stamp");
                var expiration = rows.getTimestamp("authority_expires_at");
                if (rows.next() || workspace == null || actor == null || actor.isBlank()
                        || !actor.equals(actor.strip()) || actor.length() > 120
                        || !"AI_SECURITY_REVIEWER".equals(role)
                        || sessionReference == null
                        || !sessionReference.matches("sha256:[0-9a-f]{64}")
                        || expiration == null
                        || !credentials.matchesCurrentAuthorityStamp(workspace, actor, role, stamp)) {
                    throw unavailable();
                }
                Instant expiresAt = expiration.toInstant();
                if (!Instant.now().isBefore(expiresAt)) throw unavailable();
                return new AuthoritySnapshot(key, workspace, actor, role, sessionReference, expiresAt);
            }
        }
    }

    private String currentTimeout(Connection connection, long deadline) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("show statement_timeout")) {
            statement.setQueryTimeout(queryTimeoutSeconds(deadline));
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) throw unavailable();
                String timeout = rows.getString(1);
                if (timeout == null || timeout.isBlank() || rows.next()) throw unavailable();
                return timeout;
            }
        }
    }

    private void setLocalTimeout(Connection connection, long deadline, String value) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "select set_config('statement_timeout', ?, true)")) {
            statement.setQueryTimeout(queryTimeoutSeconds(deadline));
            statement.setString(1, value);
            try (ResultSet ignored = statement.executeQuery()) {
                if (!ignored.next()) throw unavailable();
            }
        }
    }

    private int queryTimeoutSeconds(long deadline) {
        long seconds = TimeUnit.NANOSECONDS.toSeconds(deadline - System.nanoTime());
        if (seconds < 1) throw unavailable();
        return (int) Math.min(seconds, 5);
    }

    private long remainingMillis(long deadline) {
        long millis = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
        if (millis < 1_000) throw unavailable();
        return millis;
    }

    private static BusinessException unavailable() {
        return new BusinessException(ErrorCode.OPERATOR_AUTH_REQUIRED,
                "Current Run reviewer authority is unavailable");
    }

    /** One-way opaque admission reference; it is not a signed cookie or a current CSRF token. */
    public record AuthoritySnapshot(InvocationKey key, UUID workspaceId, String actorId,
            String role, String sessionReference, Instant expiresAt) {
        @Override public String toString() {
            return "RunReviewerAuthority[toolCallId=" + key.toolCallId() + "]";
        }
    }
}
