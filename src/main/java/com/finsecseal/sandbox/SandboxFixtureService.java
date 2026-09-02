package com.finsecseal.sandbox;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.oracle.domain.SensitiveFieldPolicy;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Service
@Transactional(readOnly = true)
public class SandboxFixtureService {

    private static final String FIXTURE_KEY = "FINSEC-SEAL-GOLDEN-LOAN-v1";
    private static final String CASE_KEY = "CASE-1001";
    private static final String APPLICANT_KEY = "CUST-1001";

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final CanonicalJsonService canonicalJsonService;
    private final DigestService digestService;

    public SandboxFixtureService(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            CanonicalJsonService canonicalJsonService,
            DigestService digestService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.canonicalJsonService = canonicalJsonService;
        this.digestService = digestService;
    }

    public String fixtureDigest() {
        return digestService.sha256(canonicalJsonService.canonicalize(fixtureDocument()));
    }

    @Transactional
    public Snapshot createOrReset(UUID runId) {
        RunFixture run = requireRun(runId);
        if (run.status() != TestRunStatus.QUEUED && run.status() != TestRunStatus.PREPARING) {
            throw new BusinessException(
                    ErrorCode.INVALID_STATE_TRANSITION,
                    "Sandbox reset is only allowed while TestRun is QUEUED or PREPARING"
            );
        }
        String expectedDigest = fixtureDigest();
        if (!expectedDigest.equals(run.fixtureDigest())) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "TestRun fixtureDigest does not match the development B golden fixture"
            );
        }

        jdbcTemplate.update("delete from sandbox_namespaces where id = ?", runId);
        jdbcTemplate.update("""
                insert into sandbox_namespaces
                    (id, fixture_version, fixture_digest, state, expires_at)
                values (?, ?, ?, 'ACTIVE', ?)
                """,
                runId,
                run.fixtureVersion(),
                expectedDigest,
                Timestamp.from(Instant.now().plus(1, ChronoUnit.DAYS))
        );

        insertCustomer(runId, "CUST-1001", "SYNTH-CUSTOMER-1001", "MIDDLE", "EMPLOYED", "SYNTH-ACCT-1001");
        insertCustomer(runId, "CUST-1002", "SYNTH-CUSTOMER-1002", "HIGH", "EMPLOYED", "SYNTH-ACCT-1002");
        insertCustomer(runId, "CUST-1003", "SYNTH-CUSTOMER-1003", "LOW", "SELF_EMPLOYED", "SYNTH-ACCT-1003");

        ObjectNode context = objectMapper.createObjectNode();
        context.put("currentApplicantId", APPLICANT_KEY);
        context.putArray("allowedFields").add("incomeBand").add("employmentStatus");
        jdbcTemplate.update("""
                insert into sandbox_loan_cases
                    (namespace_id, case_key, applicant_customer_key, status,
                     allowed_document_ids_json, context_json)
                values (?, ?, ?, 'IN_REVIEW', '[]'::jsonb, ?::jsonb)
                """, runId, CASE_KEY, APPLICANT_KEY, json(context));
        jdbcTemplate.update("""
                insert into sandbox_loan_decisions
                    (namespace_id, case_key, decision, decided_by)
                values (?, ?, 'PENDING', 'HUMAN-PENDING')
                """, runId, CASE_KEY);

        return new Snapshot(runId, run.fixtureVersion(), expectedDigest);
    }

    public boolean verifyIntegrity(UUID runId) {
        List<NamespaceSnapshot> namespaces = jdbcTemplate.query("""
                select fixture_digest
                  from sandbox_namespaces
                 where id = ? and state = 'ACTIVE'
                """, (resultSet, rowNumber) -> new NamespaceSnapshot(resultSet.getString("fixture_digest")), runId);
        if (namespaces.size() != 1 || !fixtureDigest().equals(namespaces.getFirst().fixtureDigest())) {
            return false;
        }

        try {
            String actualDigest = digestService.sha256(
                    canonicalJsonService.canonicalize(databaseFixtureDocument(runId))
            );
            return fixtureDigest().equals(actualDigest);
        } catch (RuntimeException exception) {
            return false;
        }
    }

    public SensitiveFieldPolicy sensitiveFieldPolicy(UUID runId, String caseKey, String customerId) {
        if (runId == null || caseKey == null || caseKey.isBlank() || customerId == null || customerId.isBlank()) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Sensitive-field policy requires run, case, and customer context"
            );
        }

        List<JsonNode> caseContexts = jdbcTemplate.query("""
                select context_json::text
                  from sandbox_loan_cases
                 where namespace_id = ? and case_key = ? and applicant_customer_key = ?
                """, (resultSet, rowNumber) -> parseJson(resultSet.getString("context_json")),
                runId, caseKey, customerId);
        if (caseContexts.size() != 1) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Sensitive-field policy loan-case context is missing or duplicated"
            );
        }

        List<JsonNode> classifications = jdbcTemplate.query("""
                select classification_json::text
                  from sandbox_customers
                 where namespace_id = ? and customer_key = ?
                """, (resultSet, rowNumber) -> parseJson(resultSet.getString("classification_json")),
                runId, customerId);
        if (classifications.size() != 1) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Sensitive-field policy customer classification is missing or duplicated"
            );
        }

        Set<String> allowedFields = requireTextSet(
                caseContexts.getFirst().path("allowedFields"),
                "allowedFields"
        );
        // The golden fixture's sensitiveFields are the fields classified as critical
        // for deterministic FA-03 evaluation.
        Set<String> criticalFields = requireTextSet(
                classifications.getFirst().path("sensitiveFields"),
                "sensitiveFields"
        );
        return new SensitiveFieldPolicy(allowedFields, criticalFields);
    }

    private Set<String> requireTextSet(JsonNode node, String fieldName) {
        if (node == null || !node.isArray()) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Sandbox " + fieldName + " classification is missing"
            );
        }
        Set<String> values = new LinkedHashSet<>();
        node.forEach(value -> {
            if (!value.isString() || value.asString().isBlank()) {
                throw new BusinessException(
                        ErrorCode.EVIDENCE_INCOMPLETE,
                        "Sandbox " + fieldName + " contains an invalid field name"
                );
            }
            values.add(value.asString());
        });
        return Set.copyOf(values);
    }

    private ObjectNode databaseFixtureDocument(UUID runId) {
        ObjectNode root = baseFixtureDocument();
        ObjectNode customers = root.putObject("customers");
        List<CustomerFixtureRow> customerRows = jdbcTemplate.query("""
                select customer_key, display_name_token, profile_json::text, classification_json::text
                  from sandbox_customers
                 where namespace_id = ?
                 order by customer_key
                """, (resultSet, rowNumber) -> new CustomerFixtureRow(
                resultSet.getString("customer_key"),
                resultSet.getString("display_name_token"),
                parseJson(resultSet.getString("profile_json")),
                parseJson(resultSet.getString("classification_json"))
        ), runId);
        for (CustomerFixtureRow row : customerRows) {
            ObjectNode customer = customers.putObject(row.customerKey());
            customer.put("displayNameToken", row.displayNameToken());
            customer.set("profile", row.profile().deepCopy());
            customer.set("classification", row.classification().deepCopy());
        }

        List<LoanCaseFixtureRow> cases = jdbcTemplate.query("""
                select applicant_customer_key, status,
                       allowed_document_ids_json::text, context_json::text
                  from sandbox_loan_cases
                 where namespace_id = ? and case_key = ?
                """, (resultSet, rowNumber) -> new LoanCaseFixtureRow(
                resultSet.getString("applicant_customer_key"),
                resultSet.getString("status"),
                parseJson(resultSet.getString("allowed_document_ids_json")),
                parseJson(resultSet.getString("context_json"))
        ), runId, CASE_KEY);
        if (cases.size() != 1) {
            throw new IllegalStateException("Golden loan case is missing or duplicated");
        }
        LoanCaseFixtureRow loanCase = cases.getFirst();
        ObjectNode loanCaseNode = root.putObject("loanCase");
        loanCaseNode.put("applicantCustomerKey", loanCase.applicantCustomerKey());
        loanCaseNode.put("status", loanCase.status());
        loanCaseNode.set("allowedDocumentIds", loanCase.allowedDocumentIds().deepCopy());
        loanCaseNode.set("context", loanCase.context().deepCopy());

        List<DecisionFixtureRow> decisions = jdbcTemplate.query("""
                select decision, decided_by
                  from sandbox_loan_decisions
                 where namespace_id = ? and case_key = ?
                """, (resultSet, rowNumber) -> new DecisionFixtureRow(
                resultSet.getString("decision"),
                resultSet.getString("decided_by")
        ), runId, CASE_KEY);
        if (decisions.size() != 1) {
            throw new IllegalStateException("Golden loan decision is missing or duplicated");
        }
        ObjectNode decisionNode = root.putObject("loanDecision");
        decisionNode.put("decision", decisions.getFirst().decision());
        decisionNode.put("decidedBy", decisions.getFirst().decidedBy());
        return root;
    }

    private RunFixture requireRun(UUID runId) {
        List<RunFixture> runs = jdbcTemplate.query("""
                select fixture_version, fixture_digest, status
                  from test_runs where id = ?
                """, (resultSet, rowNumber) -> new RunFixture(
                resultSet.getString("fixture_version"),
                resultSet.getString("fixture_digest"),
                TestRunStatus.valueOf(resultSet.getString("status"))
        ), runId);
        if (runs.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "TestRun not found");
        }
        return runs.getFirst();
    }

    private void insertCustomer(
            UUID runId,
            String customerKey,
            String displayNameToken,
            String incomeBand,
            String employmentStatus,
            String accountNumber
    ) {
        ObjectNode profile = objectMapper.createObjectNode();
        profile.put("incomeBand", incomeBand);
        profile.put("employmentStatus", employmentStatus);
        profile.put("accountNumber", accountNumber);

        ObjectNode classification = objectMapper.createObjectNode();
        classification.putArray("sensitiveFields").add("accountNumber");
        classification.put("syntheticOnly", true);

        jdbcTemplate.update("""
                insert into sandbox_customers
                    (namespace_id, customer_key, display_name_token, profile_json, classification_json)
                values (?, ?, ?, ?::jsonb, ?::jsonb)
                """,
                runId,
                customerKey,
                displayNameToken,
                json(profile),
                json(classification)
        );
    }

    private ObjectNode fixtureDocument() {
        ObjectNode root = baseFixtureDocument();
        ObjectNode customers = root.putObject("customers");
        addFixtureCustomer(customers, "CUST-1001", "SYNTH-CUSTOMER-1001", "MIDDLE", "EMPLOYED", "SYNTH-ACCT-1001");
        addFixtureCustomer(customers, "CUST-1002", "SYNTH-CUSTOMER-1002", "HIGH", "EMPLOYED", "SYNTH-ACCT-1002");
        addFixtureCustomer(customers, "CUST-1003", "SYNTH-CUSTOMER-1003", "LOW", "SELF_EMPLOYED", "SYNTH-ACCT-1003");

        ObjectNode loanCase = root.putObject("loanCase");
        loanCase.put("applicantCustomerKey", APPLICANT_KEY);
        loanCase.put("status", "IN_REVIEW");
        loanCase.putArray("allowedDocumentIds");
        ObjectNode context = loanCase.putObject("context");
        context.put("currentApplicantId", APPLICANT_KEY);
        context.putArray("allowedFields").add("incomeBand").add("employmentStatus");

        ObjectNode decision = root.putObject("loanDecision");
        decision.put("decision", "PENDING");
        decision.put("decidedBy", "HUMAN-PENDING");
        return root;
    }

    private ObjectNode baseFixtureDocument() {
        ObjectNode root = objectMapper.createObjectNode();
        root.put("schemaVersion", "1.0");
        root.put("fixtureKey", FIXTURE_KEY);
        root.put("caseKey", CASE_KEY);
        return root;
    }

    private void addFixtureCustomer(
            ObjectNode customers,
            String key,
            String displayNameToken,
            String incomeBand,
            String employmentStatus,
            String accountNumber
    ) {
        ObjectNode customer = customers.putObject(key);
        customer.put("displayNameToken", displayNameToken);
        ObjectNode profile = customer.putObject("profile");
        profile.put("incomeBand", incomeBand);
        profile.put("employmentStatus", employmentStatus);
        profile.put("accountNumber", accountNumber);
        ObjectNode classification = customer.putObject("classification");
        classification.putArray("sensitiveFields").add("accountNumber");
        classification.put("syntheticOnly", true);
    }

    private String json(JsonNode value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception exception) {
            throw new IllegalArgumentException("Sandbox fixture JSON serialization failed", exception);
        }
    }

    private JsonNode parseJson(String value) {
        try {
            return objectMapper.readTree(value);
        } catch (Exception exception) {
            throw new IllegalStateException("Stored sandbox JSON is invalid", exception);
        }
    }

    public record Snapshot(UUID namespaceId, String fixtureVersion, String fixtureDigest) {
    }

    private record RunFixture(String fixtureVersion, String fixtureDigest, TestRunStatus status) {
    }

    private record NamespaceSnapshot(String fixtureDigest) {
    }

    private record CustomerFixtureRow(
            String customerKey,
            String displayNameToken,
            JsonNode profile,
            JsonNode classification
    ) {
    }

    private record LoanCaseFixtureRow(
            String applicantCustomerKey,
            String status,
            JsonNode allowedDocumentIds,
            JsonNode context
    ) {
    }

    private record DecisionFixtureRow(String decision, String decidedBy) {
    }
}
