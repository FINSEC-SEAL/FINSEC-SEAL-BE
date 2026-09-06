package com.finsecseal.sandbox.tool;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.sandbox.SandboxExecutionContext;
import java.util.HashSet;
import java.util.Set;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Component
public final class LoanDecisionUpdateMockToolAdapter implements ToolAdapter {

    public static final String TOOL_NAME = "LOAN_DECISION_UPDATE";

    private static final Set<String> ALLOWED_ARGUMENTS =
            Set.of("caseId", "decision");
    private static final Set<String> ALLOWED_DECISIONS =
            Set.of("APPROVED", "REJECTED");

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public LoanDecisionUpdateMockToolAdapter(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    @Override
    public String toolName() {
        return TOOL_NAME;
    }

    @Override
    public void validateArguments(JsonNode arguments) {
        if (arguments == null || !arguments.isObject()) {
            throw validation(
                    "LOAN_DECISION_UPDATE arguments must be an object"
            );
        }

        Set<String> actualFields = new HashSet<>();
        arguments.properties().forEach(
                entry -> actualFields.add(entry.getKey())
        );
        if (!ALLOWED_ARGUMENTS.equals(actualFields)) {
            throw validation(
                    "LOAN_DECISION_UPDATE accepts only caseId and decision"
            );
        }

        JsonNode caseIdNode = arguments.get("caseId");
        if (caseIdNode == null
                || !caseIdNode.isString()
                || caseIdNode.asString().isBlank()
                || caseIdNode.asString().length() > 80) {
            throw validation(
                    "LOAN_DECISION_UPDATE caseId must be a non-blank string"
            );
        }

        JsonNode decisionNode = arguments.get("decision");
        if (decisionNode == null
                || !decisionNode.isString()
                || !ALLOWED_DECISIONS.contains(
                        decisionNode.asString()
                )) {
            throw validation(
                    "LOAN_DECISION_UPDATE decision must be APPROVED or REJECTED"
            );
        }
    }

    @Override
    public ToolExecutionResult execute(
            SandboxExecutionContext context,
            JsonNode arguments
    ) {
        validateArguments(arguments);
        requireExecutionContext(context);

        String caseId = arguments.path("caseId").asString();
        String decision = arguments.path("decision").asString();
        String decidedBy = "AGENT:" + context.caseRunId();

        int updated = jdbcTemplate.update("""
                update sandbox_loan_decisions
                   set decision = ?,
                       decided_by = ?,
                       row_version = row_version + 1,
                       updated_at = now()
                 where namespace_id = ?
                   and case_key = ?
                """,
                decision,
                decidedBy,
                context.namespaceId(),
                caseId
        );

        if (updated != 1) {
            throw new BusinessException(
                    ErrorCode.RESOURCE_NOT_FOUND,
                    "Loan decision not found in the current sandbox namespace"
            );
        }

        Long rowVersion = jdbcTemplate.queryForObject("""
                select row_version
                  from sandbox_loan_decisions
                 where namespace_id = ?
                   and case_key = ?
                """,
                Long.class,
                context.namespaceId(),
                caseId
        );

        ObjectNode output = objectMapper.createObjectNode();
        output.put("status", 200);
        output.put("caseId", caseId);
        output.put("decision", decision);
        output.put("rowVersion", rowVersion == null ? 0L : rowVersion);

        return new ToolExecutionResult(output, true);
    }

    private void requireExecutionContext(
            SandboxExecutionContext context
    ) {
        if (context == null
                || context.namespaceId() == null
                || context.caseRunId() == null) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "LOAN_DECISION_UPDATE requires namespace and case-run provenance"
            );
        }
    }

    private BusinessException validation(String message) {
        return new BusinessException(
                ErrorCode.VALIDATION_ERROR,
                message
        );
    }
}
