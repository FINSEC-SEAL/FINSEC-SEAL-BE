package com.finsecseal.sandbox.tool;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.sandbox.SandboxExecutionContext;
import com.finsecseal.sandbox.SandboxFixtureService;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/** Creates one structured review note for the executing case-run, never a loan decision. */
@Component
public final class ReviewNoteWriteToolAdapter implements ToolAdapter {

    public static final String TOOL_NAME = "REVIEW_NOTE_WRITE";
    private static final Set<String> ARGUMENT_FIELDS = Set.of("caseId", "reviewResult");
    private static final Set<String> RESULT_FIELDS = Set.of("reviewStatus", "missingDocuments", "evidence");
    private static final Set<String> EVIDENCE_FIELDS = Set.of("rule", "reason");
    private static final Set<String> STATUSES = Set.of("READY_FOR_HUMAN_REVIEW", "NEEDS_MORE_DOCUMENTS");

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final SandboxFixtureService fixtureService;

    public ReviewNoteWriteToolAdapter(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper,
                                      SandboxFixtureService fixtureService) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.fixtureService = fixtureService;
    }

    @Override
    public String toolName() {
        return TOOL_NAME;
    }

    @Override
    public ToolEffect effect() {
        return ToolEffect.STATE_CHANGING;
    }

    @Override
    public void validateArguments(JsonNode arguments) {
        if (!hasFields(arguments, ARGUMENT_FIELDS)
                || !validText(arguments.path("caseId"), 80)) {
            throw validation();
        }
        JsonNode review = arguments.path("reviewResult");
        if (!hasFields(review, RESULT_FIELDS)
                || !review.path("reviewStatus").isString()
                || !STATUSES.contains(review.path("reviewStatus").stringValue())) {
            throw validation();
        }
        JsonNode missing = review.path("missingDocuments");
        JsonNode evidence = review.path("evidence");
        if (!missing.isArray() || missing.size() > 20 || !evidence.isArray() || evidence.size() > 20) {
            throw validation();
        }
        for (int index = 0; index < missing.size(); index++) {
            if (!validText(missing.get(index), 200)) throw validation();
        }
        for (int index = 0; index < evidence.size(); index++) {
            JsonNode item = evidence.get(index);
            if (!hasFields(item, EVIDENCE_FIELDS)
                    || !validText(item.path("rule"), 120)
                    || !validText(item.path("reason"), 1000)) {
                throw validation();
            }
        }
    }

    @Override
    public ToolExecutionResult execute(SandboxExecutionContext context, JsonNode arguments) {
        validateArguments(arguments);
        if (context == null || context.runId() == null || context.caseRunId() == null
                || context.traceId() == null || context.mode() == null
                || !validText(context.caseKey(), 80)
                || !validText(context.currentApplicantId(), 80)
                || !context.caseKey().equals(arguments.path("caseId").stringValue())) {
            throw incomplete();
        }

        List<String> agents = jdbcTemplate.queryForList("""
                select agent.agent_key
                  from test_runs run
                  join agent_releases release on release.id = run.release_id
                  join agents agent on agent.id = release.agent_id
                  join test_case_runs case_run on case_run.test_run_id = run.id
                  join test_cases test_case on test_case.id = case_run.test_case_id
                       and test_case.suite_id = run.suite_id
                  join sandbox_namespaces namespace on namespace.id = run.id
                  join sandbox_loan_cases loan_case on loan_case.namespace_id = namespace.id
                       and loan_case.case_key = test_case.preconditions_json ->> 'caseId'
                 where run.id = ? and case_run.id = ? and run.mode = ?
                   and run.status = 'RUNNING' and case_run.status = 'EXECUTING'
                   and namespace.state = 'ACTIVE' and namespace.expires_at > now()
                   and namespace.fixture_version = ? and namespace.fixture_version = run.fixture_version
                   and namespace.fixture_digest = run.fixture_digest
                   and loan_case.case_key = ? and loan_case.applicant_customer_key = ?
                   and loan_case.applicant_customer_key = test_case.preconditions_json ->> 'currentApplicantId'
                   and loan_case.status = 'DOCUMENT_REVIEW'
                """, String.class, context.runId(), context.caseRunId(), context.mode().name(),
                SandboxFixtureService.NORMAL_FIXTURE_VERSION, context.caseKey(), context.currentApplicantId());
        if (agents.size() != 1 || !fixtureService.verifyIntegrity(context.runId())) throw incomplete();

        String noteKey = "NOTE-" + context.caseRunId();
        int inserted = jdbcTemplate.update("""
                insert into sandbox_review_notes
                    (namespace_id, note_key, case_key, review_result_json, created_by_agent)
                select namespace.id, ?, loan_case.case_key, ?::jsonb, agent.agent_key
                  from test_runs run
                  join agent_releases release on release.id = run.release_id
                  join agents agent on agent.id = release.agent_id
                  join test_case_runs case_run on case_run.test_run_id = run.id
                  join test_cases test_case on test_case.id = case_run.test_case_id
                       and test_case.suite_id = run.suite_id
                  join sandbox_namespaces namespace on namespace.id = run.id
                  join sandbox_loan_cases loan_case on loan_case.namespace_id = namespace.id
                       and loan_case.case_key = test_case.preconditions_json ->> 'caseId'
                 where run.id = ? and case_run.id = ? and run.mode = ?
                   and run.status = 'RUNNING' and case_run.status = 'EXECUTING'
                   and namespace.state = 'ACTIVE' and namespace.expires_at > now()
                   and namespace.fixture_version = ? and namespace.fixture_version = run.fixture_version
                   and namespace.fixture_digest = run.fixture_digest
                   and loan_case.case_key = ? and loan_case.applicant_customer_key = ?
                   and loan_case.applicant_customer_key = test_case.preconditions_json ->> 'currentApplicantId'
                   and loan_case.status = 'DOCUMENT_REVIEW'
                on conflict (namespace_id, note_key) do nothing
                """, noteKey, arguments.path("reviewResult").toString(), context.runId(),
                context.caseRunId(), context.mode().name(), SandboxFixtureService.NORMAL_FIXTURE_VERSION,
                context.caseKey(), context.currentApplicantId());
        if (inserted != 1) {
            throw new BusinessException(ErrorCode.RESOURCE_CONFLICT,
                    "REVIEW_NOTE_WRITE already has a note for this case-run or its context changed");
        }

        JsonNode review = arguments.path("reviewResult");
        ObjectNode output = objectMapper.createObjectNode();
        output.put("caseId", context.caseKey());
        output.put("reviewStatus", review.path("reviewStatus").stringValue());
        output.set("missingDocuments", review.path("missingDocuments").deepCopy());
        output.set("evidence", review.path("evidence").deepCopy());
        return new ToolExecutionResult(output, true);
    }

    private static boolean hasFields(JsonNode value, Set<String> expected) {
        if (value == null || !value.isObject() || value.size() != expected.size()) return false;
        Set<String> actual = new HashSet<>();
        value.properties().forEach(entry -> actual.add(entry.getKey()));
        return actual.equals(expected);
    }

    private static boolean validText(JsonNode value, int maximum) {
        return value != null && value.isString() && validText(value.stringValue(), maximum);
    }

    private static boolean validText(String value, int maximum) {
        if (value == null || value.isBlank() || value.length() > maximum) return false;
        for (int index = 0; index < value.length(); index++) {
            if (Character.isISOControl(value.charAt(index))) return false;
        }
        return true;
    }

    private static BusinessException validation() {
        return new BusinessException(ErrorCode.VALIDATION_ERROR,
                "REVIEW_NOTE_WRITE requires bounded catalog-shaped review arguments");
    }

    private static BusinessException incomplete() {
        return new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE,
                "REVIEW_NOTE_WRITE requires an active, intact current-case document review context");
    }
}
