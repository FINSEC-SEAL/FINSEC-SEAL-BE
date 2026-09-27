package com.finsecseal.sandbox.tool;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.sandbox.SandboxExecutionContext;
import java.nio.charset.StandardCharsets;
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
import java.util.function.LongSupplier;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

@Component
public final class CustomerDataReadToolAdapter implements FixedOperationToolAdapter {

    public static final String TOOL_NAME = "CUSTOMER_DATA_READ";
    private static final String FIXED_OPERATION = "READ";
    private static final int MAX_CUSTOMERS = 20;
    private static final int MAX_FIELDS = 20;
    private static final int MAX_PROFILE_BYTES = 32 * 1024;
    private static final int MAX_OUTPUT_BYTES = 1024 * 1024;
    private static final Duration MAX_BUDGET = Duration.ofSeconds(5);
    private static final Set<String> ALLOWED_ARGUMENTS = Set.of("customerIds", "fields");
    private static final String CUSTOMER_SQL = """
            select customer_key,
                   case when octet_length(profile_json::text) <= ?
                        then profile_json::text else null end profile_text,
                   octet_length(profile_json::text) profile_bytes
              from sandbox_customers
             where namespace_id = ? and customer_key = ?
            """;

    private final DataSource dataSource;
    private final PlatformTransactionManager transactions;
    private final ObjectMapper objectMapper;
    private final LongSupplier nanoTime;

    /** Retained for validator-only callers that never perform adapter I/O. */
    public CustomerDataReadToolAdapter(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this(null, objectMapper, null, System::nanoTime);
    }

    @Autowired
    public CustomerDataReadToolAdapter(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper,
            PlatformTransactionManager transactions) {
        this(Objects.requireNonNull(jdbcTemplate).getDataSource(), objectMapper,
                transactions, System::nanoTime);
    }

    CustomerDataReadToolAdapter(DataSource dataSource, ObjectMapper objectMapper,
            PlatformTransactionManager transactions, LongSupplier nanoTime) {
        this.dataSource = dataSource;
        this.transactions = transactions;
        this.objectMapper = Objects.requireNonNull(objectMapper);
        this.nanoTime = Objects.requireNonNull(nanoTime);
    }

    @Override
    public String toolName() {
        return TOOL_NAME;
    }

    @Override
    public String fixedOperation() {
        return FIXED_OPERATION;
    }

    @Override
    public void validateArguments(JsonNode arguments) {
        if (arguments == null || !arguments.isObject()) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "CUSTOMER_DATA_READ arguments must be an object");
        }
        Set<String> actualFields = new HashSet<>();
        arguments.properties().forEach(entry -> actualFields.add(entry.getKey()));
        if (!ALLOWED_ARGUMENTS.containsAll(actualFields)) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "CUSTOMER_DATA_READ contains unknown arguments");
        }
        requireTextArray(arguments, "customerIds", MAX_CUSTOMERS);
        requireTextArray(arguments, "fields", MAX_FIELDS);
    }

    @Override
    public ToolExecutionResult execute(SandboxExecutionContext context, JsonNode arguments) {
        return executeWithin(context, arguments, MAX_BUDGET);
    }

    /** B-local finite JDBC budget; C does not yet pass its remaining Gateway deadline here. */
    public ToolExecutionResult executeWithin(SandboxExecutionContext context, JsonNode arguments,
            Duration remaining) {
        if (remaining == null || remaining.isZero() || remaining.isNegative()
                || remaining.compareTo(MAX_BUDGET) > 0 || context == null
                || context.runId() == null || context.caseRunId() == null
                || context.traceId() == null || context.mode() == null
                || dataSource == null || transactions == null
                || TransactionSynchronizationManager.isActualTransactionActive()
                || TransactionSynchronizationManager.isSynchronizationActive()) {
            throw incomplete();
        }
        long startedAt = nanoTime.getAsLong();
        long budgetNanos = remaining.toNanos();
        validateArguments(arguments);
        List<String> customerIds = requireTextArray(arguments, "customerIds", MAX_CUSTOMERS);
        List<String> fields = requireTextArray(arguments, "fields", MAX_FIELDS);
        TransactionTemplate transaction = new TransactionTemplate(transactions);
        transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        transaction.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        transaction.setReadOnly(true);
        transaction.setTimeout(queryTimeoutSeconds(startedAt, budgetNanos));
        try {
            ToolExecutionResult result = transaction.execute(status -> {
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
                    setTransactionReadOnly(connection, startedAt, budgetNanos);
                    String previousTimeout = currentTimeout(connection, startedAt, budgetNanos);
                    setLocalTimeout(connection, startedAt, budgetNanos,
                            remainingMillis(startedAt, budgetNanos) + "ms");
                    ToolExecutionResult execution = readCustomers(connection, context, customerIds,
                            fields, startedAt, budgetNanos);
                    setLocalTimeout(connection, startedAt, budgetNanos, previousTimeout);
                    return execution;
                } catch (SQLException | RuntimeException failure) {
                    status.setRollbackOnly();
                    throw incomplete();
                } finally {
                    if (connection != null) DataSourceUtils.releaseConnection(connection, dataSource);
                }
            });
            if (result == null) throw incomplete();
            leftNanos(startedAt, budgetNanos); // Commit time is part of the attempt.
            return result;
        } catch (RuntimeException failure) {
            // Driver and stored profile details must not appear in the public exception or cause.
            throw incomplete();
        }
    }

    private ToolExecutionResult readCustomers(Connection connection, SandboxExecutionContext context,
            List<String> customerIds, List<String> fields, long startedAt, long budgetNanos)
            throws SQLException {
        ObjectNode output = objectMapper.createObjectNode();
        output.put("status", 200);
        ArrayNode rows = output.putArray("rows");
        for (String customerId : customerIds) {
            setLocalTimeout(connection, startedAt, budgetNanos,
                    remainingMillis(startedAt, budgetNanos) + "ms");
            CustomerSnapshot customer = readCustomer(connection, context, customerId,
                    startedAt, budgetNanos);
            if (customer == null) continue;
            ObjectNode row = rows.addObject();
            row.put("customerId", customer.customerId());
            ObjectNode projectedFields = row.putObject("fields");
            for (String field : fields) {
                JsonNode value = customer.profile().get(field);
                if (value != null) projectedFields.set(field, value.deepCopy());
            }
            leftNanos(startedAt, budgetNanos);
        }
        if (objectMapper.writeValueAsString(output).getBytes(StandardCharsets.UTF_8).length
                > MAX_OUTPUT_BYTES) {
            throw incomplete();
        }
        leftNanos(startedAt, budgetNanos);
        return new ToolExecutionResult(output, false);
    }

    private CustomerSnapshot readCustomer(Connection connection, SandboxExecutionContext context,
            String customerId, long startedAt, long budgetNanos) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(CUSTOMER_SQL)) {
            statement.setQueryTimeout(queryTimeoutSeconds(startedAt, budgetNanos));
            statement.setInt(1, MAX_PROFILE_BYTES);
            statement.setObject(2, context.namespaceId());
            statement.setString(3, customerId);
            try (ResultSet results = statement.executeQuery()) {
                if (!results.next()) return null;
                String storedId = results.getString("customer_key");
                long bytes = results.getLong("profile_bytes");
                if (results.wasNull() || bytes < 0 || bytes > MAX_PROFILE_BYTES
                        || !customerId.equals(storedId)) {
                    throw incomplete();
                }
                String profileText = results.getString("profile_text");
                if (profileText == null || results.next()) throw incomplete();
                return new CustomerSnapshot(storedId, parseJson(profileText));
            }
        }
    }

    private void setTransactionReadOnly(Connection connection, long startedAt, long budgetNanos)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("set transaction read only")) {
            statement.setQueryTimeout(queryTimeoutSeconds(startedAt, budgetNanos));
            statement.execute();
        }
    }

    private String currentTimeout(Connection connection, long startedAt, long budgetNanos)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("show statement_timeout")) {
            statement.setQueryTimeout(queryTimeoutSeconds(startedAt, budgetNanos));
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) throw incomplete();
                String value = rows.getString(1);
                if (value == null || value.isBlank() || rows.next()) throw incomplete();
                return value;
            }
        }
    }

    private void setLocalTimeout(Connection connection, long startedAt, long budgetNanos, String value)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "select set_config('statement_timeout', ?, true)")) {
            statement.setQueryTimeout(queryTimeoutSeconds(startedAt, budgetNanos));
            statement.setString(1, value);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next() || rows.getString(1) == null || rows.next()) throw incomplete();
            }
        }
    }

    private int queryTimeoutSeconds(long startedAt, long budgetNanos) {
        long seconds = TimeUnit.NANOSECONDS.toSeconds(leftNanos(startedAt, budgetNanos));
        if (seconds < 1) throw incomplete();
        return (int) Math.min(seconds, MAX_BUDGET.toSeconds());
    }

    private long remainingMillis(long startedAt, long budgetNanos) {
        long millis = TimeUnit.NANOSECONDS.toMillis(leftNanos(startedAt, budgetNanos));
        if (millis < 1_000) throw incomplete();
        return millis;
    }

    private long leftNanos(long startedAt, long budgetNanos) {
        long elapsed = nanoTime.getAsLong() - startedAt;
        // nanoTime subtraction is wrap-safe for these short intervals; a backwards test clock fails closed.
        if (elapsed < 0 || elapsed >= budgetNanos) throw incomplete();
        return budgetNanos - elapsed;
    }

    private List<String> requireTextArray(JsonNode arguments, String field, int maximumSize) {
        if (arguments == null || !arguments.isObject() || !arguments.path(field).isArray()) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, field + " must be an array");
        }
        ArrayNode array = (ArrayNode) arguments.path(field);
        if (array.isEmpty() || array.size() > maximumSize) {
            throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    field + " must contain between 1 and " + maximumSize + " items"
            );
        }
        List<String> values = new ArrayList<>();
        array.forEach(node -> {
            if (!node.isString() || node.asString().isBlank() || node.asString().length() > 80) {
                throw new BusinessException(ErrorCode.VALIDATION_ERROR, field + " contains an invalid value");
            }
            values.add(node.asString());
        });
        return List.copyOf(values);
    }

    private JsonNode parseJson(String value) {
        try {
            return objectMapper.readTree(value);
        } catch (Exception exception) {
            throw incomplete();
        }
    }

    private static BusinessException incomplete() {
        return new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE,
                "CUSTOMER_DATA_READ execution is incomplete");
    }

    private record CustomerSnapshot(String customerId, JsonNode profile) {
    }
}
