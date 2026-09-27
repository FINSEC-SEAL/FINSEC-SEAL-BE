package com.finsecseal.sandbox.tool;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.policy.GatewayRuntimeObservations.InvocationKey;
import com.finsecseal.policy.GatewayRuntimeObservations.RegistryObservation;
import com.finsecseal.policy.PolicyToolTrustFacts.ToolRegistryEntry;
import com.finsecseal.policy.PolicyToolTrustFacts.TrustLevel;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/** Actual stored release registry for one proposed call; not a complete C observation provider. */
@Component
public final class StoredGatewayRegistrySource {

    private static final int MAX_TOOLS = 50;
    private static final String REGISTRY_SQL = """
            select release.release_fingerprint, proposed.tool_name requested_tool,
                   link.enabled, definition.tool_key, definition.version,
                   definition.trust_level, definition.schema_hash,
                   definition.description_hash
              from test_runs run
              join test_case_runs case_run on case_run.test_run_id = run.id
              join test_cases test_case on test_case.id = case_run.test_case_id
                   and test_case.suite_id = run.suite_id
              join sandbox_namespaces namespace on namespace.id = run.id
                   and namespace.fixture_version = run.fixture_version
                   and namespace.fixture_digest = run.fixture_digest
              join execution_events proposed on proposed.id = ? and proposed.run_id = run.id
                   and proposed.test_case_run_id = case_run.id
                   and proposed.trace_id = ? and proposed.payload_digest = ?
                   and proposed.event_type = 'TOOL_PROPOSED'
              join agent_releases release on release.id = run.release_id
              left join release_tools link on link.release_id = release.id
              left join tool_definitions definition on definition.id = link.tool_definition_id
             where run.id = ? and case_run.id = ?
               and run.status = 'RUNNING' and case_run.status = 'EXECUTING'
               and namespace.state = 'ACTIVE' and namespace.expires_at > now()
             order by link.ordinal nulls last, definition.tool_key, definition.version
             limit ?
            """;

    private final DataSource dataSource;
    private final StoredGatewayPreCallScopeSource scopeSource;
    private final List<ToolAdapter> adapters;

    public StoredGatewayRegistrySource(DataSource dataSource,
                                       StoredGatewayPreCallScopeSource scopeSource,
                                       List<ToolAdapter> adapters) {
        this.dataSource = Objects.requireNonNull(dataSource);
        this.scopeSource = Objects.requireNonNull(scopeSource);
        this.adapters = List.copyOf(adapters);
    }

    public RegistryObservation observe(InvocationKey key, Duration remaining) {
        if (key == null || remaining == null || remaining.isNegative() || remaining.isZero()
                || remaining.compareTo(Duration.ofSeconds(5)) > 0
                || !TransactionSynchronizationManager.isActualTransactionActive()
                || !TransactionSynchronizationManager.hasResource(dataSource)) {
            throw incomplete();
        }
        long deadline = System.nanoTime() + remaining.toNanos();
        Connection connection = null;
        try {
            var scope = scopeSource.resolve(key, remainingDuration(deadline));
            if (!key.equals(scope.key()) || adapterCount(scope.toolName()) != 1) {
                throw incomplete();
            }
            connection = DataSourceUtils.getConnection(dataSource);
            String priorTimeout = currentTimeout(connection, deadline);
            setLocalTimeout(connection, deadline, remainingMillis(deadline) + "ms");
            try {
                return readRegistry(connection, deadline, key, scope.toolName());
            } finally {
                setLocalTimeout(connection, deadline, priorTimeout);
            }
        } catch (SQLException | RuntimeException failure) {
            // No SQL, driver or stored-value cause crosses the observation boundary.
            throw incomplete();
        } finally {
            if (connection != null) {
                DataSourceUtils.releaseConnection(connection, dataSource);
            }
        }
    }

    private long adapterCount(String toolName) {
        long matches = 0;
        for (ToolAdapter adapter : adapters) {
            if (toolName.equals(adapter.toolName())) {
                matches++;
            }
        }
        return matches;
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

    private void setLocalTimeout(Connection connection, long deadline, String timeout) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "select set_config('statement_timeout', ?, true)")) {
            statement.setQueryTimeout(queryTimeoutSeconds(deadline));
            statement.setString(1, timeout);
            statement.executeQuery().close();
        }
    }

    private RegistryObservation readRegistry(Connection connection, long deadline,
                                             InvocationKey key, String requestedTool) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(REGISTRY_SQL)) {
            statement.setQueryTimeout(queryTimeoutSeconds(deadline));
            statement.setObject(1, key.toolCallId());
            statement.setObject(2, key.traceId());
            statement.setString(3, key.requestDigest());
            statement.setObject(4, key.runId());
            statement.setObject(5, key.caseRunId());
            statement.setInt(6, MAX_TOOLS + 1);
            try (ResultSet rows = statement.executeQuery()) {
                String fingerprint = null;
                List<ToolRegistryEntry> entries = new ArrayList<>();
                Set<ToolIdentity> identities = new HashSet<>();
                boolean requestedLinked = false;
                while (rows.next()) {
                    String observedFingerprint = rows.getString("release_fingerprint");
                    if (fingerprint == null) fingerprint = observedFingerprint;
                    if (!Objects.equals(fingerprint, observedFingerprint)
                            || !requestedTool.equals(rows.getString("requested_tool"))
                            || rows.getString("tool_key") == null) {
                        throw incomplete();
                    }
                    String name = rows.getString("tool_key");
                    String version = rows.getString("version");
                    if (!identities.add(new ToolIdentity(name, version))) throw incomplete();
                    ToolRegistryEntry entry = new ToolRegistryEntry(name, version,
                            TrustLevel.valueOf(rows.getString("trust_level")),
                            rows.getString("schema_hash"), rows.getString("description_hash"));
                    entries.add(entry);
                    if (requestedTool.equals(name)) requestedLinked = true;
                    if (entries.size() > MAX_TOOLS) throw incomplete();
                }
                if (fingerprint == null || !requestedLinked) throw incomplete();
                return new RegistryObservation(key, fingerprint, entries);
            }
        }
    }

    private Duration remainingDuration(long deadline) {
        long nanos = deadline - System.nanoTime();
        if (nanos < TimeUnit.SECONDS.toNanos(1)) throw incomplete();
        return Duration.ofNanos(nanos);
    }

    private int queryTimeoutSeconds(long deadline) {
        long seconds = TimeUnit.NANOSECONDS.toSeconds(deadline - System.nanoTime());
        if (seconds < 1) throw incomplete();
        return (int) Math.min(seconds, 5);
    }

    private long remainingMillis(long deadline) {
        long millis = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
        if (millis < 1_000) throw incomplete();
        return millis;
    }

    private static BusinessException incomplete() {
        return new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE,
                "Stored Gateway Tool registry is incomplete");
    }

    private record ToolIdentity(String name, String version) { }
}
