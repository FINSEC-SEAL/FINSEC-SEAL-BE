package com.finsecseal.sandbox.tool;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.policy.GatewayRuntimeObservations.InvocationKey;
import com.finsecseal.policy.NonCustomerResponseSemanticsEvaluator.DocumentSource;
import com.finsecseal.policy.PolicyObjectScopeFacts.DocumentOwnership;
import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import javax.sql.DataSource;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Stored ownership and source trust for one DOCUMENT_READER proposal's allowed documents.
 * This is a partial B fact source, not a GatewayRuntimeObservations implementation or bean.
 */
public final class StoredGatewayDocumentScopeSource {

    private static final Duration MAX_BUDGET = Duration.ofSeconds(5);
    private static final int MAX_DOCUMENTS = 100;
    private static final int MAX_ID_LENGTH = 80;
    private static final Set<String> TRUST_LEVELS = Set.of(
            "UNTRUSTED_APPLICANT", "TRUSTED_INTERNAL");
    private static final String DOCUMENT_SQL = """
            select document_key, case_key, owner_customer_key, trust_level
              from sandbox_documents
             where namespace_id = ? and document_key = any (?)
             order by document_key
             limit ?
            """;

    private final DataSource dataSource;
    private final StoredGatewayPreCallScopeSource scopes;
    private final LongSupplier nanoTime;

    public StoredGatewayDocumentScopeSource(DataSource dataSource,
            StoredGatewayPreCallScopeSource scopes) {
        this(dataSource, scopes, System::nanoTime);
    }

    StoredGatewayDocumentScopeSource(DataSource dataSource,
            StoredGatewayPreCallScopeSource scopes, LongSupplier nanoTime) {
        this.dataSource = Objects.requireNonNull(dataSource);
        this.scopes = Objects.requireNonNull(scopes);
        this.nanoTime = Objects.requireNonNull(nanoTime);
    }

    /**
     * requestedDocumentId selects an independently stored row; it supplies no ownership or trust.
     * An unallowlisted selector produces no source while valid stored allowlist facts remain visible.
     */
    public DocumentFacts resolve(InvocationKey key, String requestedDocumentId, Duration remaining) {
        if (key == null || remaining == null || remaining.isNegative() || remaining.isZero()
                || remaining.compareTo(MAX_BUDGET) > 0
                || !TransactionSynchronizationManager.isActualTransactionActive()
                || !TransactionSynchronizationManager.hasResource(dataSource)
                || !Objects.equals(TransactionSynchronizationManager.getCurrentTransactionIsolationLevel(),
                        Connection.TRANSACTION_REPEATABLE_READ)) {
            throw incomplete();
        }
        long deadline = nanoTime.getAsLong() + remaining.toNanos();
        Connection connection = null;
        String previousTimeout = null;
        boolean localTimeoutChanged = false;
        try {
            var scope = scopes.resolve(key, remainingDuration(deadline));
            if (!key.equals(scope.key()) || !key.runId().equals(scope.namespace().namespaceId())
                    || !DocumentReaderToolAdapter.TOOL_NAME.equals(scope.toolName())
                    || scope.serverContext() == null || scope.serverContext().caseKey() == null
                    || scope.serverContext().currentApplicantId() == null) {
                throw incomplete();
            }
            List<String> allowed = requireAllowed(scope.allowedDocumentIds());
            connection = DataSourceUtils.getConnection(dataSource);
            previousTimeout = currentTimeout(connection, deadline);
            setLocalTimeout(connection, deadline, remainingMillis(deadline) + "ms");
            localTimeoutChanged = true;
            DocumentFacts facts = readDocuments(connection, deadline, key,
                    scope.namespace().namespaceId(), scope.serverContext().caseKey(),
                    scope.serverContext().currentApplicantId(), allowed, requestedDocumentId);
            setLocalTimeout(connection, deadline, previousTimeout);
            localTimeoutChanged = false;
            remainingNanos(deadline);
            return facts;
        } catch (SQLException | RuntimeException failure) {
            // Database, driver, document and selector details must not cross this boundary.
            throw incomplete();
        } finally {
            if (connection != null) {
                if (localTimeoutChanged) {
                    try {
                        setLocalTimeout(connection, deadline, previousTimeout);
                    } catch (SQLException | RuntimeException ignored) {
                        // The caller must roll back a failed observation; never extend the deadline.
                    }
                }
                DataSourceUtils.releaseConnection(connection, dataSource);
            }
        }
    }

    private DocumentFacts readDocuments(Connection connection, long deadline, InvocationKey key,
            UUID namespaceId, String caseKey, String applicantId, List<String> allowed,
            String requestedDocumentId) throws SQLException {
        Map<String, DocumentSource> stored = new LinkedHashMap<>();
        if (!allowed.isEmpty()) {
            Array ids = connection.createArrayOf("text", allowed.toArray(String[]::new));
            try {
                try (PreparedStatement statement = connection.prepareStatement(DOCUMENT_SQL)) {
                    statement.setQueryTimeout(queryTimeoutSeconds(deadline));
                    statement.setObject(1, namespaceId);
                    statement.setArray(2, ids);
                    statement.setInt(3, MAX_DOCUMENTS + 1);
                    try (ResultSet rows = statement.executeQuery()) {
                        while (rows.next()) {
                            remainingNanos(deadline);
                            String documentId = requiredId(rows.getString("document_key"));
                            String ownerCase = requiredId(rows.getString("case_key"));
                            String ownerCustomer = requiredId(rows.getString("owner_customer_key"));
                            String trust = rows.getString("trust_level");
                            if (!allowed.contains(documentId) || !caseKey.equals(ownerCase)
                                    || !applicantId.equals(ownerCustomer) || !TRUST_LEVELS.contains(trust)
                                    || stored.size() >= MAX_DOCUMENTS) {
                                throw incomplete();
                            }
                            DocumentOwnership ownership = new DocumentOwnership(documentId, ownerCase);
                            if (stored.putIfAbsent(documentId, new DocumentSource(ownership, trust)) != null) {
                                throw incomplete();
                            }
                        }
                    }
                }
            } finally {
                ids.free();
            }
        }
        if (stored.size() != allowed.size() || !stored.keySet().containsAll(allowed)) {
            throw incomplete();
        }
        List<DocumentOwnership> ownerships = new ArrayList<>(stored.size());
        stored.values().forEach(source -> ownerships.add(source.ownership()));
        DocumentSource selected = requestedDocumentId == null || requestedDocumentId.length() > MAX_ID_LENGTH
                ? null : stored.get(requestedDocumentId);
        return new DocumentFacts(key, namespaceId, ownerships, Optional.ofNullable(selected));
    }

    private List<String> requireAllowed(List<String> allowed) {
        if (allowed == null || allowed.size() > MAX_DOCUMENTS) throw incomplete();
        Set<String> unique = new HashSet<>();
        for (String value : allowed) {
            requiredId(value);
            if (!unique.add(value)) throw incomplete();
        }
        return List.copyOf(allowed);
    }

    private String currentTimeout(Connection connection, long deadline) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("show statement_timeout")) {
            statement.setQueryTimeout(queryTimeoutSeconds(deadline));
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) throw incomplete();
                String value = rows.getString(1);
                if (value == null || value.isBlank() || rows.next()) throw incomplete();
                return value;
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
        long seconds = TimeUnit.NANOSECONDS.toSeconds(remainingNanos(deadline));
        if (seconds < 1) throw incomplete();
        return (int) Math.min(seconds, MAX_BUDGET.toSeconds());
    }

    private long remainingMillis(long deadline) {
        long millis = TimeUnit.NANOSECONDS.toMillis(remainingNanos(deadline));
        if (millis < 1_000) throw incomplete();
        return millis;
    }

    private Duration remainingDuration(long deadline) {
        long nanos = remainingNanos(deadline);
        if (nanos < TimeUnit.SECONDS.toNanos(1)) throw incomplete();
        return Duration.ofNanos(nanos);
    }

    private long remainingNanos(long deadline) {
        long nanos = deadline - nanoTime.getAsLong();
        if (nanos <= 0) throw incomplete();
        return nanos;
    }

    private static String requiredId(String value) {
        if (value == null || value.isBlank() || value.length() > MAX_ID_LENGTH
                || !value.equals(value.strip())) throw incomplete();
        return value;
    }

    private static BusinessException incomplete() {
        return new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE,
                "Stored Gateway document facts are incomplete");
    }

    public record DocumentFacts(InvocationKey key, UUID namespaceId,
            List<DocumentOwnership> ownerships, Optional<DocumentSource> requestedSource) {
        public DocumentFacts {
            if (key == null || namespaceId == null || ownerships == null || requestedSource == null) {
                throw incomplete();
            }
            ownerships = List.copyOf(ownerships);
        }

        @Override public String toString() {
            return "StoredGatewayDocumentFacts[toolCallId=" + key.toolCallId() + "]";
        }
    }
}
