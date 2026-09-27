package com.finsecseal.sandbox.tool;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.policy.GatewayRuntimeObservations.InvocationKey;
import com.finsecseal.policy.GatewayRuntimeObservations.NamespaceObservation;
import com.finsecseal.sandbox.SandboxExecutionContext;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/** Stored B runtime scope for one proposed Tool call; this is not a complete Gateway observation bean. */
@Component
public final class StoredGatewayPreCallScopeSource {

    private static final int MAX_DOCUMENTS = 100;
    private static final int MAX_DOCUMENTS_JSON_BYTES = 16_384;
    private static final String SCOPE_SQL = """
            select run.mode, namespace.id namespace_id, namespace.fixture_version,
                   namespace.fixture_digest, namespace.state,
                   test_case.preconditions_json ->> 'caseId' sandbox_case_key,
                   test_case.preconditions_json ->> 'currentApplicantId' current_applicant_id,
                   loan_case.status workflow_stage,
                   loan_case.allowed_document_ids_json::text allowed_documents,
                   proposed.tool_name
              from test_runs run
              join test_case_runs case_run on case_run.test_run_id = run.id
              join test_cases test_case on test_case.id = case_run.test_case_id
                   and test_case.suite_id = run.suite_id
              join sandbox_namespaces namespace on namespace.id = run.id
                   and namespace.fixture_version = run.fixture_version
                   and namespace.fixture_digest = run.fixture_digest
              join sandbox_loan_cases loan_case on loan_case.namespace_id = namespace.id
                   and loan_case.case_key = test_case.preconditions_json ->> 'caseId'
                   and loan_case.applicant_customer_key =
                       test_case.preconditions_json ->> 'currentApplicantId'
              join execution_events proposed on proposed.id = ? and proposed.run_id = run.id
                   and proposed.test_case_run_id = case_run.id
                   and proposed.trace_id = ? and proposed.payload_digest = ?
                   and proposed.event_type = 'TOOL_PROPOSED'
             where run.id = ? and case_run.id = ?
               and run.status = 'RUNNING' and case_run.status = 'EXECUTING'
               and namespace.state = 'ACTIVE' and namespace.expires_at > now()
               and jsonb_typeof(test_case.preconditions_json -> 'caseId') = 'string'
               and jsonb_typeof(test_case.preconditions_json -> 'currentApplicantId') = 'string'
               and octet_length(loan_case.allowed_document_ids_json::text) <= ?
            """;

    private final DataSource dataSource;
    private final ObjectMapper objectMapper;

    public StoredGatewayPreCallScopeSource(DataSource dataSource, ObjectMapper objectMapper) {
        this.dataSource = dataSource;
        this.objectMapper = objectMapper;
    }

    public ScopeSnapshot resolve(InvocationKey key, Duration remaining) {
        if (key == null || remaining == null || remaining.isNegative() || remaining.isZero()
                || remaining.compareTo(Duration.ofSeconds(5)) > 0
                || !TransactionSynchronizationManager.isActualTransactionActive()
                || !TransactionSynchronizationManager.hasResource(dataSource)) {
            throw incomplete();
        }
        long deadline = System.nanoTime() + remaining.toNanos();
        Connection connection = null;
        try {
            connection = DataSourceUtils.getConnection(dataSource);
            String priorTimeout = currentTimeout(connection, deadline);
            setLocalTimeout(connection, deadline, remainingMillis(deadline) + "ms");
            ScopeSnapshot snapshot = readScope(connection, deadline, key);
            setLocalTimeout(connection, deadline, priorTimeout);
            return snapshot;
        } catch (SQLException | RuntimeException failure) {
            // SQL, driver and stored values can contain private context; never attach their cause.
            throw incomplete();
        } finally {
            if (connection != null) {
                DataSourceUtils.releaseConnection(connection, dataSource);
            }
        }
    }

    private String currentTimeout(Connection connection, long deadline) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("show statement_timeout")) {
            statement.setQueryTimeout(queryTimeoutSeconds(deadline));
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    throw incomplete();
                }
                String value = rows.getString(1);
                if (value == null || value.isBlank() || rows.next()) {
                    throw incomplete();
                }
                return value;
            }
        }
    }

    private void setLocalTimeout(Connection connection, long deadline, String value) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "select set_config('statement_timeout', ?, true)")) {
            statement.setQueryTimeout(queryTimeoutSeconds(deadline));
            statement.setString(1, value);
            statement.executeQuery().close();
        }
    }

    private ScopeSnapshot readScope(Connection connection, long deadline, InvocationKey key)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(SCOPE_SQL)) {
            statement.setQueryTimeout(queryTimeoutSeconds(deadline));
            statement.setObject(1, key.toolCallId());
            statement.setObject(2, key.traceId());
            statement.setString(3, key.requestDigest());
            statement.setObject(4, key.runId());
            statement.setObject(5, key.caseRunId());
            statement.setInt(6, MAX_DOCUMENTS_JSON_BYTES);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    throw incomplete();
                }
                ScopeSnapshot snapshot = map(rows, key);
                if (rows.next()) {
                    throw incomplete();
                }
                return snapshot;
            }
        }
    }

    private ScopeSnapshot map(ResultSet row, InvocationKey key) throws SQLException {
        String caseKey = requiredText(row.getString("sandbox_case_key"));
        String applicant = requiredText(row.getString("current_applicant_id"));
        String workflow = requiredText(row.getString("workflow_stage"));
        String toolName = requiredText(row.getString("tool_name"));
        if (caseKey.length() > 80 || applicant.length() > 80 || workflow.length() > 80
                || toolName.length() > 100) {
            throw incomplete();
        }
        SandboxExecutionContext context = new SandboxExecutionContext(
                key.runId(), key.caseRunId(), key.traceId(),
                TestRunMode.valueOf(row.getString("mode")), caseKey, applicant);
        NamespaceObservation namespace = new NamespaceObservation(
                row.getObject("namespace_id", java.util.UUID.class),
                row.getString("fixture_version"), row.getString("fixture_digest"),
                row.getString("state"));
        return new ScopeSnapshot(key, context, namespace, toolName, workflow,
                documentIds(row.getString("allowed_documents")));
    }

    private List<String> documentIds(String raw) {
        if (raw == null || raw.getBytes(java.nio.charset.StandardCharsets.UTF_8).length
                > MAX_DOCUMENTS_JSON_BYTES) {
            throw incomplete();
        }
        JsonNode documents;
        try {
            documents = objectMapper.readTree(raw);
        } catch (Exception failure) {
            throw incomplete();
        }
        if (documents == null || !documents.isArray() || documents.size() > MAX_DOCUMENTS) {
            throw incomplete();
        }
        List<String> values = new ArrayList<>();
        Set<String> unique = new HashSet<>();
        for (JsonNode document : documents) {
            if (!document.isString()) {
                throw incomplete();
            }
            String value = requiredText(document.stringValue());
            if (value.length() > 80 || !unique.add(value)) {
                throw incomplete();
            }
            values.add(value);
        }
        return List.copyOf(values);
    }

    private int queryTimeoutSeconds(long deadline) {
        long seconds = TimeUnit.NANOSECONDS.toSeconds(deadline - System.nanoTime());
        if (seconds < 1) {
            throw incomplete();
        }
        return (int) Math.min(seconds, 5);
    }

    private long remainingMillis(long deadline) {
        long millis = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
        if (millis < 1_000) {
            throw incomplete();
        }
        return millis;
    }

    private static String requiredText(String value) {
        if (value == null || value.isBlank() || !value.equals(value.strip())) {
            throw incomplete();
        }
        return value;
    }

    private static BusinessException incomplete() {
        return new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE,
                "Stored Gateway Tool scope is incomplete");
    }

    public record ScopeSnapshot(InvocationKey key, SandboxExecutionContext serverContext,
            NamespaceObservation namespace, String toolName, String workflowStage,
            List<String> allowedDocumentIds) {
        public ScopeSnapshot {
            allowedDocumentIds = List.copyOf(allowedDocumentIds);
        }

        @Override
        public String toString() {
            return "StoredGatewayPreCallScope[toolCallId=" + key.toolCallId() + "]";
        }
    }
}
