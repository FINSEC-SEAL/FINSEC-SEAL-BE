package com.finsecseal.sandbox.tool;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.policy.GatewayRuntimeObservations.InvocationKey;
import com.finsecseal.sandbox.SandboxExecutionContext;
import java.nio.charset.StandardCharsets;
import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import javax.sql.DataSource;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Partial stored customer field-label facts for one proposed Tool call.
 * These sets are neither field/path Sensitivity levels nor a Gateway completion observation.
 */
public final class StoredGatewayCustomerClassificationFactsSource {

    private static final Duration MAX_BUDGET = Duration.ofSeconds(5);
    private static final int MAX_CLASSIFICATION_BYTES = 4 * 1024;
    private static final int MAX_PROFILE_BYTES = 32 * 1024;
    private static final int MAX_FIELDS = 32;
    private static final String FAILURE_MESSAGE = "Stored Gateway customer classification facts are incomplete";
    private static final String CUSTOMER_SQL = """
            select case when octet_length(customer.classification_json::text) <= ?
                        then customer.classification_json::text else null end classification_text
              from sandbox_customers customer
              join sandbox_loan_cases loan_case
                on loan_case.namespace_id = customer.namespace_id
               and loan_case.applicant_customer_key = customer.customer_key
             where customer.namespace_id = ? and customer.customer_key = ?
               and loan_case.case_key = ?
             limit 2
            """;
    private static final String PROFILE_KEYS_SQL = """
            select case when jsonb_typeof(customer.profile_json) = 'object'
                             and octet_length(customer.profile_json::text) <= ?
                        then jsonb_exists_all(customer.profile_json, ?::text[])
                        else false end keys_present
              from sandbox_customers customer
              join sandbox_loan_cases loan_case
                on loan_case.namespace_id = customer.namespace_id
               and loan_case.applicant_customer_key = customer.customer_key
             where customer.namespace_id = ? and customer.customer_key = ?
               and loan_case.case_key = ?
             limit 2
            """;

    private final DataSource dataSource;
    private final StoredGatewayPreCallScopeSource scopes;
    private final ObjectMapper objectMapper;
    private final LongSupplier nanoTime;

    public StoredGatewayCustomerClassificationFactsSource(DataSource dataSource,
            StoredGatewayPreCallScopeSource scopes, ObjectMapper objectMapper) {
        this(dataSource, scopes, objectMapper, System::nanoTime);
    }

    StoredGatewayCustomerClassificationFactsSource(DataSource dataSource,
            StoredGatewayPreCallScopeSource scopes, ObjectMapper objectMapper,
            LongSupplier nanoTime) {
        this.dataSource = Objects.requireNonNull(dataSource);
        this.scopes = Objects.requireNonNull(scopes);
        this.objectMapper = Objects.requireNonNull(objectMapper);
        this.nanoTime = Objects.requireNonNull(nanoTime);
    }

    public ClassificationFacts resolve(InvocationKey key, Duration remaining) {
        if (key == null || remaining == null || remaining.isNegative() || remaining.isZero()
                || remaining.compareTo(MAX_BUDGET) > 0
                || !TransactionSynchronizationManager.isActualTransactionActive()
                || !TransactionSynchronizationManager.hasResource(dataSource)
                || !TransactionSynchronizationManager.isCurrentTransactionReadOnly()
                || !Objects.equals(TransactionSynchronizationManager.getCurrentTransactionIsolationLevel(),
                        Connection.TRANSACTION_REPEATABLE_READ)) {
            throw incomplete();
        }

        long started = nanoTime.getAsLong();
        long budget = remaining.toNanos();
        Connection connection = null;
        String previousTimeout = null;
        boolean localTimeoutChanged = false;
        try {
            var scope = scopes.resolve(key, remainingDuration(started, budget));
            SandboxExecutionContext context = scope.serverContext();
            if (!key.equals(scope.key()) || scope.namespace() == null
                    || !key.runId().equals(scope.namespace().namespaceId())
                    || !CustomerDataReadToolAdapter.TOOL_NAME.equals(scope.toolName())
                    || context == null || !key.runId().equals(context.runId())
                    || !key.caseRunId().equals(context.caseRunId())
                    || !key.traceId().equals(context.traceId()) || context.mode() == null) {
                throw incomplete();
            }
            String caseKey = requiredId(context.caseKey());
            String customerKey = requiredId(context.currentApplicantId());
            connection = DataSourceUtils.getConnection(dataSource);
            if (!connection.isReadOnly()) throw incomplete();
            previousTimeout = currentTimeout(connection, started, budget);
            localTimeoutChanged = true;
            setLocalTimeout(connection, started, budget, remainingMillis(started, budget) + "ms");
            FieldLabels labels = readLabels(connection, started, budget,
                    scope.namespace().namespaceId(), caseKey, customerKey);
            setLocalTimeout(connection, started, budget, remainingMillis(started, budget) + "ms");
            requireProfileKeys(connection, started, budget,
                    scope.namespace().namespaceId(), caseKey, customerKey, labels.sensitiveFields());
            setLocalTimeout(connection, started, budget, previousTimeout);
            localTimeoutChanged = false;
            remainingNanos(started, budget);
            return new ClassificationFacts(key, scope.namespace().namespaceId(), customerKey,
                    labels.sensitiveFields(), labels.criticalFields(), true);
        } catch (SQLException | RuntimeException failure) {
            // Driver errors and stored classification/profile data must not cross this boundary.
            throw incomplete();
        } finally {
            if (connection != null) {
                if (localTimeoutChanged && previousTimeout != null) {
                    try {
                        setLocalTimeout(connection, started, budget, previousTimeout);
                    } catch (SQLException | RuntimeException ignored) {
                        // A failed observation requires caller rollback; do not extend the deadline.
                    }
                }
                DataSourceUtils.releaseConnection(connection, dataSource);
            }
        }
    }

    private FieldLabels readLabels(Connection connection, long started, long budget,
            UUID namespaceId, String caseKey, String customerKey) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(CUSTOMER_SQL)) {
            statement.setQueryTimeout(queryTimeoutSeconds(started, budget));
            statement.setInt(1, MAX_CLASSIFICATION_BYTES);
            statement.setObject(2, namespaceId);
            statement.setString(3, customerKey);
            statement.setString(4, caseKey);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) throw incomplete();
                String classification = rows.getString("classification_text");
                if (classification == null || classification.getBytes(StandardCharsets.UTF_8).length
                        > MAX_CLASSIFICATION_BYTES || rows.next()) throw incomplete();
                return parseLabels(classification);
            }
        }
    }

    private FieldLabels parseLabels(String raw) {
        JsonNode node;
        try {
            node = objectMapper.readTree(raw);
        } catch (Exception failure) {
            throw incomplete();
        }
        if (node == null || !node.isObject() || node.size() != 3
                || !node.has("sensitiveFields") || !node.has("criticalFields")
                || !node.has("syntheticOnly") || !node.get("syntheticOnly").isBoolean()
                || !node.get("syntheticOnly").booleanValue()) {
            throw incomplete();
        }
        Set<String> sensitive = fields(node.get("sensitiveFields"));
        Set<String> critical = fields(node.get("criticalFields"));
        if (!sensitive.containsAll(critical)) throw incomplete();
        return new FieldLabels(sensitive, critical);
    }

    private Set<String> fields(JsonNode values) {
        if (values == null || !values.isArray() || values.size() > MAX_FIELDS) throw incomplete();
        Set<String> names = new LinkedHashSet<>();
        for (JsonNode value : values) {
            if (!value.isString() || !value.stringValue().matches("[A-Za-z][A-Za-z0-9_]{0,79}")
                    || !names.add(value.stringValue())) throw incomplete();
        }
        return Set.copyOf(names);
    }

    private void requireProfileKeys(Connection connection, long started, long budget,
            UUID namespaceId, String caseKey, String customerKey, Set<String> sensitive)
            throws SQLException {
        Array names = connection.createArrayOf("text", sensitive.toArray(String[]::new));
        try {
            try (PreparedStatement statement = connection.prepareStatement(PROFILE_KEYS_SQL)) {
                statement.setQueryTimeout(queryTimeoutSeconds(started, budget));
                statement.setInt(1, MAX_PROFILE_BYTES);
                statement.setArray(2, names);
                statement.setObject(3, namespaceId);
                statement.setString(4, customerKey);
                statement.setString(5, caseKey);
                try (ResultSet rows = statement.executeQuery()) {
                    if (!rows.next() || !rows.getBoolean("keys_present") || rows.wasNull()
                            || rows.next()) throw incomplete();
                }
            }
        } finally {
            names.free();
        }
    }

    private String currentTimeout(Connection connection, long started, long budget) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("show statement_timeout")) {
            statement.setQueryTimeout(queryTimeoutSeconds(started, budget));
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) throw incomplete();
                String value = rows.getString(1);
                if (value == null || value.isBlank() || rows.next()) throw incomplete();
                return value;
            }
        }
    }

    private void setLocalTimeout(Connection connection, long started, long budget, String value)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "select set_config('statement_timeout', ?, true)")) {
            statement.setQueryTimeout(queryTimeoutSeconds(started, budget));
            statement.setString(1, value);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next() || rows.getString(1) == null || rows.next()) throw incomplete();
            }
        }
    }

    private int queryTimeoutSeconds(long started, long budget) {
        long seconds = TimeUnit.NANOSECONDS.toSeconds(remainingNanos(started, budget));
        if (seconds < 1) throw incomplete();
        return (int) Math.min(seconds, MAX_BUDGET.toSeconds());
    }

    private long remainingMillis(long started, long budget) {
        long millis = TimeUnit.NANOSECONDS.toMillis(remainingNanos(started, budget));
        if (millis < 1_000) throw incomplete();
        return millis;
    }

    private Duration remainingDuration(long started, long budget) {
        long nanos = remainingNanos(started, budget);
        if (nanos < TimeUnit.SECONDS.toNanos(1)) throw incomplete();
        return Duration.ofNanos(nanos);
    }

    private long remainingNanos(long started, long budget) {
        long elapsed = nanoTime.getAsLong() - started;
        if (elapsed < 0 || elapsed >= budget) throw incomplete();
        return budget - elapsed;
    }

    private static String requiredId(String value) {
        if (value == null || !value.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,79}")) throw incomplete();
        return value;
    }

    private static BusinessException incomplete() {
        return new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, FAILURE_MESSAGE);
    }

    private record FieldLabels(Set<String> sensitiveFields, Set<String> criticalFields) {
    }

    public record ClassificationFacts(InvocationKey key, UUID namespaceId, String customerKey,
            Set<String> sensitiveFields, Set<String> criticalFields, boolean syntheticOnly) {
        public ClassificationFacts {
            if (key == null || namespaceId == null || !key.runId().equals(namespaceId)
                    || customerKey == null || !customerKey.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,79}")
                    || sensitiveFields == null || criticalFields == null || !syntheticOnly) {
                throw incomplete();
            }
            sensitiveFields = Set.copyOf(sensitiveFields);
            criticalFields = Set.copyOf(criticalFields);
            if (!sensitiveFields.containsAll(criticalFields)) throw incomplete();
        }

        @Override public String toString() {
            return "StoredGatewayCustomerClassificationFacts[partial]";
        }
    }
}
