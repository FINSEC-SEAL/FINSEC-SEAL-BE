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
import java.util.HashSet;
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
import tools.jackson.databind.node.ObjectNode;

/** Returns only a bounded stored case projection under a finite local PostgreSQL budget. */
@Component
public final class CaseContextReadToolAdapter implements ToolAdapter {

    public static final String TOOL_NAME = "CASE_CONTEXT_READ";
    private static final Duration MAX_BUDGET = Duration.ofSeconds(5);
    private static final int MAX_DOCUMENTS = 100;
    private static final int MAX_DOCUMENTS_BYTES = 16 * 1024;
    private static final int MAX_OUTPUT_BYTES = 32 * 1024;
    private static final String CASE_SQL = """
            select loan_case.case_key, loan_case.applicant_customer_key,
                   loan_case.status,
                   case when octet_length(loan_case.allowed_document_ids_json::text) <= ?
                        then loan_case.allowed_document_ids_json::text else null end allowed_documents,
                   octet_length(loan_case.allowed_document_ids_json::text) allowed_bytes
              from test_runs run
              join test_case_runs case_run on case_run.test_run_id = run.id
              join test_cases test_case on test_case.id = case_run.test_case_id
                   and test_case.suite_id = run.suite_id
              join sandbox_namespaces namespace on namespace.id = run.id
                   and namespace.fixture_version = run.fixture_version
                   and namespace.fixture_digest = run.fixture_digest
              join sandbox_loan_cases loan_case on loan_case.namespace_id = namespace.id
                   and loan_case.case_key = test_case.preconditions_json ->> 'caseId'
             where run.id = ? and case_run.id = ? and run.mode = ?
               and run.status = 'RUNNING' and case_run.status = 'EXECUTING'
               and namespace.state = 'ACTIVE' and namespace.expires_at > now()
               and loan_case.case_key = ? and loan_case.applicant_customer_key = ?
               and loan_case.applicant_customer_key = test_case.preconditions_json ->> 'currentApplicantId'
            """;

    private final DataSource dataSource;
    private final PlatformTransactionManager transactions;
    private final ObjectMapper objectMapper;
    private final LongSupplier nanoTime;

    /** Retained for callers that construct this adapter only to validate Tool arguments. */
    public CaseContextReadToolAdapter(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this(null, objectMapper, null, System::nanoTime);
    }

    @Autowired
    public CaseContextReadToolAdapter(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper,
            PlatformTransactionManager transactions) {
        this(Objects.requireNonNull(jdbcTemplate).getDataSource(), objectMapper,
                transactions, System::nanoTime);
    }

    CaseContextReadToolAdapter(DataSource dataSource, ObjectMapper objectMapper,
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
    public void validateArguments(JsonNode arguments) {
        if (arguments == null || !arguments.isObject() || arguments.size() != 1
                || !validIdentifier(arguments.path("caseId"))) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR,
                    "CASE_CONTEXT_READ requires only a non-blank caseId of at most 80 characters");
        }
    }

    @Override
    public ToolExecutionResult execute(SandboxExecutionContext context, JsonNode arguments) {
        return executeWithin(context, arguments, MAX_BUDGET);
    }

    /** B-local SQL budget; the C Gateway does not yet propagate its remaining deadline. */
    public ToolExecutionResult executeWithin(SandboxExecutionContext context, JsonNode arguments,
            Duration remaining) {
        if (remaining == null || remaining.isZero() || remaining.isNegative()
                || remaining.compareTo(MAX_BUDGET) > 0) throw incomplete();
        long startedAt = nanoTime.getAsLong();
        long budgetNanos = remaining.toNanos();
        validateArguments(arguments); // Preserve malformed-argument errors before context checks.
        if (context == null || context.runId() == null || context.caseRunId() == null
                || context.traceId() == null || context.mode() == null
                || context.caseKey() == null || context.currentApplicantId() == null
                || !arguments.path("caseId").stringValue().equals(context.caseKey())
                || dataSource == null || transactions == null
                || TransactionSynchronizationManager.isActualTransactionActive()
                || TransactionSynchronizationManager.isSynchronizationActive()) {
            throw incomplete();
        }

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
                    ToolExecutionResult execution = readCase(connection, context,
                            startedAt, budgetNanos);
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
            leftNanos(startedAt, budgetNanos); // Includes transaction completion.
            return result;
        } catch (RuntimeException failure) {
            // Stored identifiers and SQL/driver causes must not cross this boundary.
            throw incomplete();
        }
    }

    private ToolExecutionResult readCase(Connection connection, SandboxExecutionContext context,
            long startedAt, long budgetNanos) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(CASE_SQL)) {
            statement.setQueryTimeout(queryTimeoutSeconds(startedAt, budgetNanos));
            statement.setInt(1, MAX_DOCUMENTS_BYTES);
            statement.setObject(2, context.runId());
            statement.setObject(3, context.caseRunId());
            statement.setString(4, context.mode().name());
            statement.setString(5, context.caseKey());
            statement.setString(6, context.currentApplicantId());
            try (ResultSet results = statement.executeQuery()) {
                if (!results.next()) throw incomplete();
                String caseId = results.getString("case_key");
                String applicantId = results.getString("applicant_customer_key");
                String workflowStage = results.getString("status");
                long allowedBytes = results.getLong("allowed_bytes");
                if (results.wasNull() || allowedBytes < 0 || allowedBytes > MAX_DOCUMENTS_BYTES
                        || !context.caseKey().equals(caseId)
                        || !context.currentApplicantId().equals(applicantId)
                        || workflowStage == null || workflowStage.isBlank()) {
                    throw incomplete();
                }
                String allowedJson = results.getString("allowed_documents");
                if (allowedJson == null || results.next()) throw incomplete();
                JsonNode documents;
                try {
                    documents = objectMapper.readTree(allowedJson);
                } catch (RuntimeException failure) {
                    throw incomplete();
                }
                if (documents == null || !documents.isArray() || documents.size() > MAX_DOCUMENTS) {
                    throw incomplete();
                }
                Set<String> uniqueIds = new HashSet<>();
                for (JsonNode document : documents) {
                    if (!validIdentifier(document) || !uniqueIds.add(document.stringValue())) {
                        throw incomplete();
                    }
                }
                ObjectNode output = objectMapper.createObjectNode();
                output.put("caseId", caseId);
                output.put("currentApplicantId", applicantId);
                output.put("workflowStage", workflowStage);
                output.set("allowedDocumentIds", documents.deepCopy());
                if (objectMapper.writeValueAsString(output).getBytes(StandardCharsets.UTF_8).length
                        > MAX_OUTPUT_BYTES) {
                    throw incomplete();
                }
                leftNanos(startedAt, budgetNanos);
                return new ToolExecutionResult(output, false);
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
        if (elapsed < 0 || elapsed >= budgetNanos) throw incomplete();
        return budgetNanos - elapsed;
    }

    private static boolean validIdentifier(JsonNode value) {
        return value.isString() && !value.stringValue().isBlank()
                && value.stringValue().length() <= 80
                && value.stringValue().equals(value.stringValue().strip());
    }

    private static BusinessException incomplete() {
        return new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE,
                "CASE_CONTEXT_READ requires a complete active server-owned case context");
    }

}
