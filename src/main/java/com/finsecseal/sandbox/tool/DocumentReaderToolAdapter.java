package com.finsecseal.sandbox.tool;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.EncryptionService;
import com.finsecseal.sandbox.SandboxExecutionContext;
import java.sql.Timestamp;
import java.util.List;
import java.util.Set;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/** Reads only a server-owned, current-case document; its content remains untrusted data. */
@Component
public final class DocumentReaderToolAdapter implements ToolAdapter {

    public static final String TOOL_NAME = "DOCUMENT_READER";
    private static final Set<String> DOCUMENT_TYPES = Set.of(
            "INCOME_STATEMENT", "EMPLOYMENT_CERTIFICATE", "ID_COPY", "OTHER");
    private static final Set<String> SOURCE_TRUST_LEVELS = Set.of(
            "UNTRUSTED_APPLICANT", "TRUSTED_INTERNAL");

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final EncryptionService encryptionService;
    private final DigestService digestService;

    public DocumentReaderToolAdapter(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper,
                                     EncryptionService encryptionService, DigestService digestService) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.encryptionService = encryptionService;
        this.digestService = digestService;
    }

    @Override
    public String toolName() {
        return TOOL_NAME;
    }

    @Override
    public void validateArguments(JsonNode arguments) {
        if (arguments == null || !arguments.isObject() || arguments.size() != 2
                || !validIdentifier(arguments.path("caseId"))
                || !validIdentifier(arguments.path("documentId"))) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR,
                    "DOCUMENT_READER requires only caseId and documentId of at most 80 characters");
        }
    }

    @Override
    public ToolExecutionResult execute(SandboxExecutionContext context, JsonNode arguments) {
        validateArguments(arguments);
        if (context == null || context.runId() == null || context.caseRunId() == null
                || context.traceId() == null || context.mode() == null
                || !validText(context.caseKey()) || !validText(context.currentApplicantId())
                || !arguments.path("caseId").stringValue().equals(context.caseKey())) {
            throw incomplete();
        }

        List<StoredDocument> matches = jdbcTemplate.query("""
                select loan_case.allowed_document_ids_json::text, document.document_key,
                       document.case_key, document.owner_customer_key, document.document_type,
                       document.content_encrypted, document.content_digest, document.trust_level,
                       document.classification_json::text, document.created_at
                  from test_runs run
                  join test_case_runs case_run on case_run.test_run_id = run.id
                  join test_cases test_case on test_case.id = case_run.test_case_id
                       and test_case.suite_id = run.suite_id
                  join sandbox_namespaces namespace on namespace.id = run.id
                  join sandbox_loan_cases loan_case on loan_case.namespace_id = namespace.id
                       and loan_case.case_key = test_case.preconditions_json ->> 'caseId'
                  join sandbox_documents document on document.namespace_id = namespace.id
                       and document.case_key = loan_case.case_key
                       and document.document_key = ?
                 where run.id = ? and case_run.id = ? and run.mode = ?
                   and run.status = 'RUNNING' and case_run.status = 'EXECUTING'
                   and namespace.state = 'ACTIVE' and namespace.expires_at > now()
                   and namespace.fixture_version = run.fixture_version
                   and namespace.fixture_digest = run.fixture_digest
                   and loan_case.case_key = ? and loan_case.applicant_customer_key = ?
                   and loan_case.applicant_customer_key = test_case.preconditions_json ->> 'currentApplicantId'
                   and loan_case.status = 'DOCUMENT_REVIEW'
                   and document.owner_customer_key = loan_case.applicant_customer_key
                """, (resultSet, rowNumber) -> new StoredDocument(
                resultSet.getString("allowed_document_ids_json"), resultSet.getString("document_key"),
                resultSet.getString("case_key"), resultSet.getString("owner_customer_key"),
                resultSet.getString("document_type"), resultSet.getString("content_encrypted"),
                resultSet.getString("content_digest"), resultSet.getString("trust_level"),
                resultSet.getString("classification_json"), resultSet.getTimestamp("created_at")
        ), arguments.path("documentId").stringValue(), context.runId(), context.caseRunId(),
                context.mode().name(), context.caseKey(), context.currentApplicantId());
        if (matches.size() != 1) throw incomplete();

        StoredDocument document = matches.getFirst();
        if (!allowed(document.allowedDocumentIds(), document.documentId())
                || !DOCUMENT_TYPES.contains(document.type())
                || !SOURCE_TRUST_LEVELS.contains(document.sourceTrustLevel())
                || document.createdAt() == null || !validText(document.encryptedContent())) {
            throw incomplete();
        }
        JsonNode classification = parse(document.classificationJson());
        if (!classification.isObject() || !classification.path("syntheticOnly").asBoolean(false)) {
            throw incomplete();
        }

        String content;
        try {
            content = encryptionService.decrypt(document.encryptedContent());
        } catch (RuntimeException failure) {
            throw incomplete();
        }
        if (!validText(content) || !digestService.sha256(content).equals(document.contentDigest())) {
            throw incomplete();
        }

        ObjectNode output = objectMapper.createObjectNode();
        output.put("caseId", document.caseId());
        output.put("documentId", document.documentId());
        output.put("ownerCustomerId", document.ownerCustomerId());
        output.put("documentType", document.type());
        output.put("content", content);
        output.put("sourceTrustLevel", document.sourceTrustLevel());
        output.put("createdAt", document.createdAt().toInstant().toString());
        return new ToolExecutionResult(output, false);
    }

    private boolean allowed(String json, String id) {
        JsonNode ids = parse(json);
        if (!ids.isArray() || ids.isEmpty() || ids.size() > 100) return false;
        Set<String> unique = new java.util.HashSet<>();
        for (JsonNode value : ids) {
            if (!validIdentifier(value) || !unique.add(value.stringValue())) return false;
        }
        return unique.contains(id);
    }

    private JsonNode parse(String json) {
        try {
            return objectMapper.readTree(json);
        } catch (RuntimeException failure) {
            throw incomplete();
        }
    }

    private static boolean validIdentifier(JsonNode value) {
        return value.isString() && validText(value.stringValue()) && value.stringValue().length() <= 80
                && value.stringValue().equals(value.stringValue().strip());
    }

    private static boolean validText(String value) {
        return value != null && !value.isBlank();
    }

    private static BusinessException incomplete() {
        return new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE,
                "DOCUMENT_READER requires an active current-case document with complete source evidence");
    }

    private record StoredDocument(String allowedDocumentIds, String documentId, String caseId,
                                  String ownerCustomerId, String type, String encryptedContent,
                                  String contentDigest, String sourceTrustLevel,
                                  String classificationJson, Timestamp createdAt) {
    }
}
