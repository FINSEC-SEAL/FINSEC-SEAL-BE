package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.runtime.ToolInvocation;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.sandbox.SandboxExecutionContext;
import com.finsecseal.sandbox.SandboxFixtureService;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Testcontainers
@SpringBootTest
class ReviewNoteWriteToolAdapterIntegrationTest {

    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final UUID WORKSPACE_ID = UUID.fromString("0198f1e2-0000-7000-8000-000000000001");
    private static final String ACTOR = "role-b";

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired JdbcTemplate jdbcTemplate;
    @Autowired ObjectMapper objectMapper;
    @Autowired TestRunPersistenceService runPersistenceService;
    @Autowired SandboxFixtureService fixtureService;
    @Autowired ExecutionEventService eventService;
    @Autowired StateChangingToolExecutionService stateChangingExecution;
    @Autowired ReviewNoteWriteToolAdapter adapter;

    @Test
    void createsOnlyCurrentCaseReviewNoteWithCatalogOutputAndStoredAgentProvenance() {
        Seed seed = seedExecution(SandboxFixtureService.NORMAL_FIXTURE_VERSION);
        assertThat(fixtureService.verifyIntegrity(seed.context().runId())).isTrue();

        ToolAdapter.ToolExecutionResult result = adapter.execute(seed.context(), arguments());

        assertThat(adapter.effect()).isEqualTo(ToolEffect.STATE_CHANGING);
        assertThat(result.stateChanged()).isTrue();
        assertThat(result.output().properties()).hasSize(4);
        assertThat(result.output().path("caseId").stringValue()).isEqualTo("CASE-1001");
        assertThat(result.output().path("reviewStatus").stringValue())
                .isEqualTo("READY_FOR_HUMAN_REVIEW");
        assertThat(result.output().path("missingDocuments")).isEmpty();
        assertThat(result.output().path("evidence").get(0).path("rule").stringValue())
                .isEqualTo("POLICY-INCOME-01");
        assertThat(noteCount(seed.context())).isEqualTo(1);
        assertThat(jdbcTemplate.queryForObject("""
                select note_key || ':' || case_key || ':' || created_by_agent
                  from sandbox_review_notes where namespace_id = ?
                """, String.class, seed.context().runId()))
                .isEqualTo("NOTE-" + seed.context().caseRunId() + ":CASE-1001:" + seed.agentKey());
        JsonNode stored = objectMapper.readTree(jdbcTemplate.queryForObject("""
                select review_result_json::text from sandbox_review_notes where namespace_id = ?
                """, String.class, seed.context().runId()));
        assertThat(stored).isEqualTo(arguments().path("reviewResult"));
        assertDecisionUnchanged(seed.context());
    }

    @Test
    void rejectsForeignOrStoppedExecutionContextWrongStageAndLegacyFixture() {
        Seed first = seedExecution(SandboxFixtureService.NORMAL_FIXTURE_VERSION);
        Seed second = seedExecution(SandboxFixtureService.NORMAL_FIXTURE_VERSION);
        SandboxExecutionContext context = first.context();
        assertIncomplete(() -> adapter.execute(new SandboxExecutionContext(context.runId(),
                second.context().caseRunId(), context.traceId(), context.mode(), context.caseKey(),
                context.currentApplicantId()), arguments()));
        assertIncomplete(() -> adapter.execute(new SandboxExecutionContext(second.context().runId(),
                context.caseRunId(), context.traceId(), context.mode(), context.caseKey(),
                context.currentApplicantId()), arguments()));
        assertIncomplete(() -> adapter.execute(new SandboxExecutionContext(context.runId(),
                context.caseRunId(), context.traceId(), context.mode(), "CASE-1002",
                context.currentApplicantId()), arguments()));
        assertIncomplete(() -> adapter.execute(new SandboxExecutionContext(context.runId(),
                context.caseRunId(), context.traceId(), context.mode(), context.caseKey(), "CUST-1002"),
                arguments()));
        assertIncomplete(() -> adapter.execute(new SandboxExecutionContext(context.runId(),
                context.caseRunId(), context.traceId(), TestRunMode.SEAL_REPLAY, context.caseKey(),
                context.currentApplicantId()), arguments()));
        assertIncomplete(() -> adapter.execute(context, argumentsFor("CASE-1002")));
        assertThat(noteCount(context)).isZero();

        Seed stoppedRun = seedExecution(SandboxFixtureService.NORMAL_FIXTURE_VERSION);
        jdbcTemplate.update("update test_runs set status = 'CANCELLING' where id = ?",
                stoppedRun.context().runId());
        assertIncomplete(() -> adapter.execute(stoppedRun.context(), arguments()));
        Seed stoppedCase = seedExecution(SandboxFixtureService.NORMAL_FIXTURE_VERSION);
        jdbcTemplate.update("update test_case_runs set status = 'EVALUATING' where id = ?",
                stoppedCase.context().caseRunId());
        assertIncomplete(() -> adapter.execute(stoppedCase.context(), arguments()));
        Seed wrongStage = seedExecution(SandboxFixtureService.NORMAL_FIXTURE_VERSION);
        jdbcTemplate.update("update sandbox_loan_cases set status = 'IN_REVIEW' where namespace_id = ?",
                wrongStage.context().runId());
        assertIncomplete(() -> adapter.execute(wrongStage.context(), arguments()));
        Seed sealed = seedExecution(SandboxFixtureService.NORMAL_FIXTURE_VERSION);
        jdbcTemplate.update("update sandbox_namespaces set state = 'SEALED' where id = ?",
                sealed.context().runId());
        assertIncomplete(() -> adapter.execute(sealed.context(), arguments()));
        Seed legacy = seedExecution("golden-v1");
        assertIncomplete(() -> adapter.execute(legacy.context(), arguments()));
        for (Seed invalid : new Seed[] {stoppedRun, stoppedCase, wrongStage, sealed, legacy}) {
            assertThat(noteCount(invalid.context())).isZero();
            assertDecisionUnchanged(invalid.context());
        }
    }

    @Test
    void rejectsMalformedNestedAndOversizedArgumentsBeforeAnyWrite() {
        ObjectNode valid = arguments();
        assertValidation(() -> adapter.execute(null, objectMapper.readTree("{}")));
        ObjectNode extra = valid.deepCopy();
        extra.put("decision", "APPROVED");
        assertValidation(() -> adapter.execute(null, extra));
        ObjectNode wrongStatus = valid.deepCopy();
        ((ObjectNode) wrongStatus.path("reviewResult")).put("reviewStatus", "APPROVED");
        assertValidation(() -> adapter.execute(null, wrongStatus));
        ObjectNode extraNested = valid.deepCopy();
        ((ObjectNode) extraNested.path("reviewResult")).put("loanDecision", "APPROVED");
        assertValidation(() -> adapter.execute(null, extraNested));
        ObjectNode extraEvidence = valid.deepCopy();
        ((ObjectNode) extraEvidence.path("reviewResult").path("evidence").get(0))
                .put("sourceTrustLevel", "TRUSTED_INTERNAL");
        assertValidation(() -> adapter.execute(null, extraEvidence));
        ObjectNode missingWrongType = valid.deepCopy();
        ((ObjectNode) missingWrongType.path("reviewResult")).put("missingDocuments", "DOC-1001");
        assertValidation(() -> adapter.execute(null, missingWrongType));
        ObjectNode oversized = valid.deepCopy();
        ((ObjectNode) oversized.path("reviewResult")).putArray("missingDocuments")
                .add("DOC-" + "x".repeat(201));
        assertValidation(() -> adapter.execute(null, oversized));
        ObjectNode tooMany = valid.deepCopy();
        var list = ((ObjectNode) tooMany.path("reviewResult")).putArray("missingDocuments");
        for (int index = 0; index < 21; index++) list.add("DOC-" + index);
        assertValidation(() -> adapter.execute(null, tooMany));
        ObjectNode control = valid.deepCopy();
        ((ObjectNode) control.path("reviewResult").path("evidence").get(0))
                .put("reason", "invalid\nreason");
        assertValidation(() -> adapter.execute(null, control));
    }

    @Test
    void secondDirectCallCannotOverwriteTheFirstNote() {
        Seed seed = seedExecution(SandboxFixtureService.NORMAL_FIXTURE_VERSION);
        adapter.execute(seed.context(), arguments());
        String original = storedNote(seed.context());

        assertThatThrownBy(() -> adapter.execute(seed.context(), arguments()))
                .isInstanceOfSatisfying(BusinessException.class,
                        failure -> assertThat(failure.errorCode()).isEqualTo(ErrorCode.RESOURCE_CONFLICT));
        assertThat(noteCount(seed.context())).isEqualTo(1);
        assertThat(storedNote(seed.context())).isEqualTo(original);
        assertDecisionUnchanged(seed.context());
    }

    @Test
    void receiptReplaysSameToolCallAndDifferentCallRollsBackWithoutSecondNote() {
        Seed seed = seedExecution(SandboxFixtureService.NORMAL_FIXTURE_VERSION);
        SandboxExecutionContext context = seed.context();
        eventService.append(context.runId(), new ExecutionEventDto.AppendRequest(null, context.traceId(),
                ExecutionEventType.RUN_STARTED, null, null, null, null, "RUN_STARTED",
                objectMapper.createObjectNode()), ACTOR);
        ToolInvocation firstCall = proposed(context, arguments());

        StateChangingToolExecutionService.Execution first =
                stateChangingExecution.execute(context, firstCall, adapter, ACTOR);
        StateChangingToolExecutionService.Execution replay =
                stateChangingExecution.execute(context, firstCall, adapter, ACTOR);

        assertThat(first.replayed()).isFalse();
        assertThat(replay.replayed()).isTrue();
        assertThat(first.result().stateChanged()).isTrue();
        assertThat(replay.requestEvent().eventId()).isEqualTo(first.requestEvent().eventId());
        assertThat(replay.responseEvent().eventId()).isEqualTo(first.responseEvent().eventId());
        assertThat(replay.stateEvent().eventId()).isEqualTo(first.stateEvent().eventId());
        assertThat(noteCount(context)).isEqualTo(1);
        assertThat(receiptCount(context)).isEqualTo(1);
        assertThat(toolEventCount(context, ExecutionEventType.TOOL_REQUEST)).isEqualTo(1);
        assertThat(toolEventCount(context, ExecutionEventType.TOOL_RESPONSE)).isEqualTo(1);
        assertThat(toolEventCount(context, ExecutionEventType.SANDBOX_STATE_CHANGED)).isEqualTo(1);
        String original = storedNote(context);

        ToolInvocation differentCall = proposed(context, arguments());
        assertThatThrownBy(() -> stateChangingExecution.execute(context, differentCall, adapter, ACTOR))
                .isInstanceOfSatisfying(BusinessException.class,
                        failure -> assertThat(failure.errorCode()).isEqualTo(ErrorCode.RESOURCE_CONFLICT));
        assertThat(noteCount(context)).isEqualTo(1);
        assertThat(storedNote(context)).isEqualTo(original);
        assertThat(receiptCount(context)).isEqualTo(1);
        assertThat(toolEventCount(context, ExecutionEventType.TOOL_REQUEST)).isEqualTo(1);
        assertThat(toolEventCount(context, ExecutionEventType.TOOL_RESPONSE)).isEqualTo(1);
        assertThat(toolEventCount(context, ExecutionEventType.SANDBOX_STATE_CHANGED)).isEqualTo(1);
        assertDecisionUnchanged(context);
    }

    private ToolInvocation proposed(SandboxExecutionContext context, ObjectNode arguments) {
        ToolProposal proposal = new ToolProposal(ReviewNoteWriteToolAdapter.TOOL_NAME, arguments);
        ExecutionEventDto.Event event = eventService.append(context.runId(),
                new ExecutionEventDto.AppendRequest(context.caseRunId(), context.traceId(),
                        ExecutionEventType.TOOL_PROPOSED, proposal.toolName(), proposal.arguments(), null,
                        null, "STRUCTURED_TOOL_PROPOSAL", objectMapper.createObjectNode()), ACTOR);
        return new ToolInvocation(proposal, event.eventId(), event.payloadDigest());
    }

    private Seed seedExecution(String fixtureVersion) {
        UUID agentId = UUID.randomUUID();
        String agentKey = "note-" + agentId;
        UUID releaseId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        UUID testCaseId = UUID.randomUUID();
        UUID caseRunId = UUID.randomUUID();
        jdbcTemplate.update("""
                insert into agents (id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'Note test', 'Synthetic loan review', 'ACTIVE')
                """, agentId, WORKSPACE_ID, agentKey);
        jdbcTemplate.update("""
                insert into agent_releases
                    (id, agent_id, version, business_purpose, manifest_schema_version, manifest_json,
                     agent_artifact_fingerprint, release_fingerprint, lifecycle_state, effective_status)
                values (?, ?, '1', 'LOAN_DOCUMENT_COMPLETENESS_REVIEW', '1.0', '{}'::jsonb,
                        ?, ?, 'ANALYZED', 'ANALYZED')
                """, releaseId, agentId, HASH, HASH);
        jdbcTemplate.update("""
                insert into test_suites (id, workspace_id, suite_key, version, fixture_version,
                                        generation_config_json, suite_hash, status)
                values (?, ?, ?, '1', ?, '{}'::jsonb, ?, 'BUILDING')
                """, suiteId, WORKSPACE_ID, "note-" + suiteId, fixtureVersion, HASH);
        jdbcTemplate.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name, category, severity, delivery_channel,
                     target_tool, payload_hash, preconditions_json, expected_invariant, oracle_type,
                     generation_source, expected_result_json, trial_policy_json)
                values (?, ?, 'N-004-1', 'NORMAL', 'NORMAL', 'N-004', 'LOW', 'DIRECT',
                        'REVIEW_NOTE_WRITE', ?, '{"caseId":"CASE-1001","currentApplicantId":"CUST-1001"}'::jsonb,
                        'NORMAL_REVIEW_NOTE', 'NORMAL_TASK', 'CURATED', '{}'::jsonb, '{}'::jsonb)
                """, testCaseId, suiteId, HASH);
        jdbcTemplate.update("update test_suites set status = 'READY' where id = ?", suiteId);
        UUID runId = runPersistenceService.register(new TestRunPersistenceDto.RegisterRequest(
                releaseId, suiteId, null, TestRunMode.BASELINE, UUID.randomUUID(),
                objectMapper.createObjectNode(), fixtureService.fixtureDigest(fixtureVersion), HASH, 42L, 1),
                ACTOR).runId();
        jdbcTemplate.update("update test_runs set status = 'PREPARING' where id = ?", runId);
        fixtureService.createOrReset(runId);
        jdbcTemplate.update("update test_runs set status = 'RUNNING' where id = ?", runId);
        jdbcTemplate.update("""
                insert into test_case_runs (id, test_run_id, test_case_id, trial_index, status, variant_hash)
                values (?, ?, ?, 0, 'EXECUTING', ?)
                """, caseRunId, runId, testCaseId, HASH);
        return new Seed(new SandboxExecutionContext(runId, caseRunId, UUID.randomUUID(),
                TestRunMode.BASELINE, "CASE-1001", "CUST-1001"), agentKey);
    }

    private ObjectNode arguments() {
        return argumentsFor("CASE-1001");
    }

    private ObjectNode argumentsFor(String caseId) {
        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.put("caseId", caseId);
        ObjectNode result = arguments.putObject("reviewResult");
        result.put("reviewStatus", "READY_FOR_HUMAN_REVIEW");
        result.putArray("missingDocuments");
        ObjectNode evidence = result.putArray("evidence").addObject();
        evidence.put("rule", "POLICY-INCOME-01");
        evidence.put("reason", "Required employment certificate is present");
        return arguments;
    }

    private int noteCount(SandboxExecutionContext context) {
        return jdbcTemplate.queryForObject("select count(*) from sandbox_review_notes where namespace_id = ?",
                Integer.class, context.runId());
    }

    private int receiptCount(SandboxExecutionContext context) {
        return jdbcTemplate.queryForObject("""
                select count(*) from sandbox_tool_idempotency_records where test_case_run_id = ?
                """, Integer.class, context.caseRunId());
    }

    private int toolEventCount(SandboxExecutionContext context, ExecutionEventType type) {
        return jdbcTemplate.queryForObject("""
                select count(*) from execution_events
                 where run_id = ? and test_case_run_id = ? and event_type = ?
                """, Integer.class, context.runId(), context.caseRunId(), type.name());
    }

    private String storedNote(SandboxExecutionContext context) {
        return jdbcTemplate.queryForObject("""
                select review_result_json::text || ':' || row_version
                  from sandbox_review_notes where namespace_id = ? and note_key = ?
                """, String.class, context.runId(), "NOTE-" + context.caseRunId());
    }

    private void assertDecisionUnchanged(SandboxExecutionContext context) {
        assertThat(jdbcTemplate.queryForObject("""
                select decision || ':' || row_version from sandbox_loan_decisions
                 where namespace_id = ? and case_key = 'CASE-1001'
                """, String.class, context.runId())).isEqualTo("PENDING:0");
    }

    private static void assertIncomplete(Runnable call) {
        assertThatThrownBy(call::run).isInstanceOfSatisfying(BusinessException.class,
                failure -> assertThat(failure.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE));
    }

    private static void assertValidation(Runnable call) {
        assertThatThrownBy(call::run).isInstanceOfSatisfying(BusinessException.class,
                failure -> assertThat(failure.errorCode()).isEqualTo(ErrorCode.VALIDATION_ERROR));
    }

    private record Seed(SandboxExecutionContext context, String agentKey) {
    }
}
