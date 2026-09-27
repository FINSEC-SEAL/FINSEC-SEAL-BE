package com.finsecseal.sandbox.tool;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.sandbox.SandboxExecutionContext;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/** Returns the stored case projection; caller-supplied context never supplies response facts. */
@Component
public final class CaseContextReadToolAdapter implements ToolAdapter {

    public static final String TOOL_NAME = "CASE_CONTEXT_READ";
    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public CaseContextReadToolAdapter(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
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
        validateArguments(arguments);
        if (context == null || context.runId() == null || context.caseRunId() == null
                || context.traceId() == null || context.mode() == null
                || context.caseKey() == null || context.currentApplicantId() == null
                || !arguments.path("caseId").stringValue().equals(context.caseKey())) {
            throw incomplete();
        }

        List<StoredCase> matches = jdbcTemplate.query("""
                select loan_case.case_key, loan_case.applicant_customer_key,
                       loan_case.status, loan_case.allowed_document_ids_json::text
                  from test_runs run
                  join test_case_runs case_run on case_run.test_run_id = run.id
                  join test_cases test_case on test_case.id = case_run.test_case_id
                       and test_case.suite_id = run.suite_id
                  join sandbox_namespaces namespace on namespace.id = run.id
                  join sandbox_loan_cases loan_case on loan_case.namespace_id = namespace.id
                       and loan_case.case_key = test_case.preconditions_json ->> 'caseId'
                 where run.id = ? and case_run.id = ? and run.mode = ?
                   and run.status = 'RUNNING' and case_run.status = 'EXECUTING'
                   and namespace.state = 'ACTIVE' and namespace.expires_at > now()
                   and loan_case.case_key = ? and loan_case.applicant_customer_key = ?
                   and loan_case.applicant_customer_key = test_case.preconditions_json ->> 'currentApplicantId'
                """, (resultSet, rowNumber) -> new StoredCase(
                resultSet.getString("case_key"), resultSet.getString("applicant_customer_key"),
                resultSet.getString("status"), resultSet.getString("allowed_document_ids_json")
        ), context.runId(), context.caseRunId(), context.mode().name(),
                context.caseKey(), context.currentApplicantId());
        if (matches.size() != 1) throw incomplete();

        StoredCase stored = matches.getFirst();
        if (stored.workflowStage() == null || stored.workflowStage().isBlank()) throw incomplete();
        JsonNode documents;
        try {
            documents = objectMapper.readTree(stored.allowedDocumentsJson());
        } catch (RuntimeException exception) {
            throw incomplete();
        }
        if (documents == null || !documents.isArray() || documents.size() > 100) throw incomplete();
        Set<String> uniqueIds = new HashSet<>();
        for (JsonNode document : documents) {
            if (!validIdentifier(document) || !uniqueIds.add(document.stringValue())) throw incomplete();
        }

        ObjectNode output = objectMapper.createObjectNode();
        output.put("caseId", stored.caseId());
        output.put("currentApplicantId", stored.applicantId());
        output.put("workflowStage", stored.workflowStage());
        output.set("allowedDocumentIds", documents.deepCopy());
        return new ToolExecutionResult(output, false);
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

    private record StoredCase(String caseId, String applicantId, String workflowStage,
                              String allowedDocumentsJson) {
    }
}
