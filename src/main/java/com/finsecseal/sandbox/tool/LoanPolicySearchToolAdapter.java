package com.finsecseal.sandbox.tool;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.release.DigestService;
import com.finsecseal.sandbox.SandboxExecutionContext;
import com.finsecseal.sandbox.SandboxFixtureService;
import java.util.List;
import java.util.Locale;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/** Searches only the server-seeded, integrity-checked policy in the active case namespace. */
@Component
public final class LoanPolicySearchToolAdapter implements ToolAdapter {

    public static final String TOOL_NAME = "LOAN_POLICY_SEARCH";
    private static final String PRODUCT_TYPE = "PERSONAL_CREDIT_LOAN";

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final DigestService digestService;
    private final SandboxFixtureService fixtureService;

    public LoanPolicySearchToolAdapter(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper,
                                       DigestService digestService, SandboxFixtureService fixtureService) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.digestService = digestService;
        this.fixtureService = fixtureService;
    }

    @Override
    public String toolName() {
        return TOOL_NAME;
    }

    @Override
    public void validateArguments(JsonNode arguments) {
        if (arguments == null || !arguments.isObject() || arguments.size() != 1
                || !arguments.path("query").isString()
                || !validQuery(arguments.path("query").stringValue())) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR,
                    "LOAN_POLICY_SEARCH requires only a nonblank query of at most 200 characters");
        }
    }

    @Override
    public ToolExecutionResult execute(SandboxExecutionContext context, JsonNode arguments) {
        validateArguments(arguments);
        if (context == null || context.runId() == null || context.caseRunId() == null
                || context.traceId() == null || context.mode() == null
                || !validText(context.caseKey()) || !validText(context.currentApplicantId())) {
            throw incomplete();
        }

        List<StoredPolicy> stored = jdbcTemplate.query("""
                select policy.policy_key, policy.version, policy.rule_code,
                       policy.requirement_json::text, policy.content_digest
                  from test_runs run
                  join test_case_runs case_run on case_run.test_run_id = run.id
                  join test_cases test_case on test_case.id = case_run.test_case_id
                       and test_case.suite_id = run.suite_id
                  join sandbox_namespaces namespace on namespace.id = run.id
                  join sandbox_loan_cases loan_case on loan_case.namespace_id = namespace.id
                       and loan_case.case_key = test_case.preconditions_json ->> 'caseId'
                  join sandbox_loan_policies policy on policy.namespace_id = namespace.id
                 where run.id = ? and case_run.id = ? and run.mode = ?
                   and run.status = 'RUNNING' and case_run.status = 'EXECUTING'
                   and namespace.state = 'ACTIVE' and namespace.expires_at > now()
                   and namespace.fixture_version = run.fixture_version
                   and namespace.fixture_digest = run.fixture_digest
                   and loan_case.case_key = ? and loan_case.applicant_customer_key = ?
                   and loan_case.applicant_customer_key = test_case.preconditions_json ->> 'currentApplicantId'
                   and loan_case.status = 'DOCUMENT_REVIEW'
                 order by policy.policy_key, policy.version
                """, (resultSet, rowNumber) -> new StoredPolicy(
                resultSet.getString("policy_key"), resultSet.getString("version"),
                resultSet.getString("rule_code"), resultSet.getString("requirement_json"),
                resultSet.getString("content_digest")), context.runId(), context.caseRunId(),
                context.mode().name(), context.caseKey(), context.currentApplicantId());
        if (stored.isEmpty() || !fixtureService.verifyIntegrity(context.runId())) throw incomplete();

        String query = arguments.path("query").stringValue().strip().toLowerCase(Locale.ROOT);
        ArrayNode policies = objectMapper.createArrayNode();
        for (StoredPolicy policy : stored) {
            JsonNode requirement;
            try {
                requirement = objectMapper.readTree(policy.requirementJson());
            } catch (RuntimeException invalid) {
                throw incomplete();
            }
            if (!validText(policy.id()) || !validText(policy.version()) || !validText(policy.ruleCode())
                    || !requirement.isObject() || requirement.size() != 2
                    || !requirement.path("productType").isString()
                    || !PRODUCT_TYPE.equals(requirement.path("productType").stringValue())
                    || !requirement.path("text").isString()
                    || !validText(requirement.path("text").stringValue())
                    || !digestService.sha256(requirement.path("text").stringValue()).equals(policy.contentDigest())) {
                throw incomplete();
            }
            String text = requirement.path("text").stringValue();
            String searchable = (policy.id() + " " + policy.ruleCode() + " " + PRODUCT_TYPE + " " + text)
                    .toLowerCase(Locale.ROOT);
            if (searchable.contains(query)) {
                ObjectNode result = policies.addObject();
                result.put("policyId", policy.id());
                result.put("version", policy.version());
                result.put("productType", PRODUCT_TYPE);
                result.put("ruleCode", policy.ruleCode());
                result.put("requirement", text);
                result.put("sourceTrustLevel", "TRUSTED_INTERNAL");
            }
        }
        ObjectNode output = objectMapper.createObjectNode();
        output.set("policies", policies);
        return new ToolExecutionResult(output, false);
    }

    private static boolean validQuery(String value) {
        if (!validText(value) || value.length() > 200) return false;
        for (int index = 0; index < value.length(); index++) {
            if (Character.isISOControl(value.charAt(index))) return false;
        }
        return true;
    }

    private static boolean validText(String value) {
        return value != null && !value.isBlank();
    }

    private static BusinessException incomplete() {
        return new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE,
                "LOAN_POLICY_SEARCH requires an active current-case trusted policy with complete source evidence");
    }

    private record StoredPolicy(String id, String version, String ruleCode, String requirementJson,
                                String contentDigest) {
    }
}
