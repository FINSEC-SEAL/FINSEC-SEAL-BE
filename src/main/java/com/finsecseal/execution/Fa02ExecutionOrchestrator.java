package com.finsecseal.execution;

import com.finsecseal.attack.AttackSeed;
import com.finsecseal.attack.AttackSeedCatalog;
import com.finsecseal.attack.AttackVariant;
import com.finsecseal.attack.AttackVariantFactory;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.oracle.application.OracleAssessmentService;
import com.finsecseal.oracle.domain.CustomerDataRow;
import com.finsecseal.oracle.domain.CustomerResponseEvidence;
import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleResult;
import com.finsecseal.oracle.evaluator.CrossCustomerOracle;
import com.finsecseal.runtime.AgentRuntimeService;
import com.finsecseal.sandbox.SandboxExecutionContext;
import com.finsecseal.sandbox.SandboxFixtureService;
import com.finsecseal.sandbox.tool.ToolDispatcher;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Service
public class Fa02ExecutionOrchestrator {

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final AttackSeedCatalog attackSeedCatalog;
    private final AttackVariantFactory attackVariantFactory;
    private final TestRunPersistenceService runPersistenceService;
    private final AgentRuntimeService runtimeService;
    private final ToolDispatcher toolDispatcher;
    private final SandboxFixtureService fixtureService;
    private final OracleAssessmentService oracleAssessmentService;
    private final RunExecutionLifecycleService lifecycleService;

    public Fa02ExecutionOrchestrator(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            AttackSeedCatalog attackSeedCatalog,
            AttackVariantFactory attackVariantFactory,
            TestRunPersistenceService runPersistenceService,
            AgentRuntimeService runtimeService,
            ToolDispatcher toolDispatcher,
            SandboxFixtureService fixtureService,
            OracleAssessmentService oracleAssessmentService,
            RunExecutionLifecycleService lifecycleService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.attackSeedCatalog = attackSeedCatalog;
        this.attackVariantFactory = attackVariantFactory;
        this.runPersistenceService = runPersistenceService;
        this.runtimeService = runtimeService;
        this.toolDispatcher = toolDispatcher;
        this.fixtureService = fixtureService;
        this.oracleAssessmentService = oracleAssessmentService;
        this.lifecycleService = lifecycleService;
    }

    public Result execute(UUID runId, UUID testCaseId, String actorId) {
        String normalizedActor = actorId == null || actorId.isBlank() ? "orchestrator-b" : actorId;
        ExecutionTarget target = requireTarget(runId, testCaseId);
        if (target.mode() != TestRunMode.BASELINE) {
            throw new BusinessException(ErrorCode.INVALID_STATE_TRANSITION, "FA-02 first slice only supports BASELINE");
        }
        if (target.status() != TestRunStatus.QUEUED && target.status() != TestRunStatus.RUNNING) {
            throw new BusinessException(
                    ErrorCode.INVALID_STATE_TRANSITION,
                    "FA-02 execution requires a QUEUED or RUNNING TestRun"
            );
        }
        if (!"FA-02".equals(target.category())) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "TestCase is not FA-02");
        }

        AttackSeed seed = attackSeedCatalog.requireSeed(target.category());
        AttackVariant variant = attackVariantFactory.fromSeed(seed);
        validateVariantAgainstTestCase(variant, target);
        UUID traceId = UUID.randomUUID();
        UUID caseRunId = null;

        try {
            lifecycleService.ensureRunning(runId, traceId, target.category(), normalizedActor);

            TestRunPersistenceDto.CaseRun caseRun = runPersistenceService.registerCase(
                    runId,
                    new TestRunPersistenceDto.CaseRunRegisterRequest(testCaseId, 0, variant.variantHash()),
                    normalizedActor
            );
            caseRunId = caseRun.id();
            runPersistenceService.updateCaseStatus(
                    runId,
                    caseRun.id(),
                    new TestRunPersistenceDto.CaseRunStatusRequest(
                            TestCaseRunStatus.EXECUTING, null, null, null, null, null, null
                    ),
                    normalizedActor
            );

            SandboxExecutionContext context = new SandboxExecutionContext(
                    runId,
                    caseRun.id(),
                    traceId,
                    target.mode(),
                    target.sandboxCaseKey(),
                    target.currentApplicantId()
            );
            AgentRuntimeService.RuntimeTurn turn = runtimeService.proposeTool(context, variant, normalizedActor);
            ToolDispatcher.DispatchResult dispatch = toolDispatcher.dispatch(
                    context,
                    turn.aiResponse().proposal(),
                    normalizedActor
            );

            AgentRuntimeService.DeliveryReceipt delivery = AgentRuntimeService.DeliveryReceipt.notDelivered();
            if (dispatch.toolInvoked()) {
                delivery = runtimeService.deliverToolResult(
                        context,
                        variant,
                        turn.aiResponse().proposal().toolName(),
                        dispatch.execution().output(),
                        dispatch.responseEvent().eventId(),
                        dispatch.responseEvent().sequence(),
                        normalizedActor
                );
            }

            runPersistenceService.updateCaseStatus(
                    runId,
                    caseRun.id(),
                    new TestRunPersistenceDto.CaseRunStatusRequest(
                            TestCaseRunStatus.EVALUATING, null, null, null, null, null, null
                    ),
                    normalizedActor
            );

            boolean integrityValid = fixtureService.verifyIntegrity(runId);
            if (!integrityValid) {
                throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, "Golden Fixture integrity validation failed");
            }
            CustomerResponseEvidence evidence = materializeEvidence(context, dispatch, delivery, integrityValid);
            OracleResult oracleResult = new CrossCustomerOracle().evaluate(evidence);
            ExecutionEventDto.Event sourceEvent = dispatch.toolInvoked()
                    ? dispatch.responseEvent()
                    : dispatch.policyEvent();
            OracleAssessmentService.Assessment assessment = oracleAssessmentService.record(
                    runId,
                    caseRun.id(),
                    traceId,
                    sourceEvent.eventId(),
                    oracleResult,
                    normalizedActor
            );

            TestCaseRunStatus terminalCaseStatus = caseStatus(oracleResult.outcome());
            String errorCode = oracleResult.outcome() == OracleOutcome.INCONCLUSIVE
                    ? oracleResult.reasonCode().name()
                    : null;
            ObjectNode caseResult = objectMapper.createObjectNode();
            caseResult.put("oracleOutcome", oracleResult.outcome().name());
            caseResult.put("reasonCode", oracleResult.reasonCode().name());
            caseResult.put("oracleResultId", assessment.oracleResult().id().toString());
            caseResult.put("variantHash", variant.variantHash());
            caseResult.put("deliveredToAgent", delivery.deliveredToAgent());
            if (delivery.deliveryEventId() != null) {
                caseResult.put("deliveryEventId", delivery.deliveryEventId().toString());
            }
            if (assessment.finding() != null) {
                caseResult.put("findingId", assessment.finding().id().toString());
            }
            runPersistenceService.updateCaseStatus(
                    runId,
                    caseRun.id(),
                    new TestRunPersistenceDto.CaseRunStatusRequest(
                            terminalCaseStatus,
                            oracleResult.outcome().name(),
                            "NOT_EVALUATED",
                            turn.aiResponse().latencyMs() + delivery.latencyMs(),
                            objectMapper.createObjectNode(),
                            errorCode,
                            caseResult
                    ),
                    normalizedActor
            );

            lifecycleService.completeIfReady(
                    runId,
                    caseRun.id(),
                    traceId,
                    target.category(),
                    oracleResult.outcome().name(),
                    oracleResult.reasonCode().name(),
                    normalizedActor
            );

            return new Result(
                    runId,
                    caseRun.id(),
                    traceId,
                    oracleResult.outcome().name(),
                    oracleResult.reasonCode().name(),
                    assessment.oracleResult().id(),
                    assessment.finding() == null ? null : assessment.finding().id(),
                    variant.variantHash(),
                    delivery.deliveredToAgent()
            );
        } catch (RuntimeException exception) {
            lifecycleService.sealFailure(runId, caseRunId, traceId, exception, normalizedActor);
            throw exception;
        }
    }

    private ExecutionTarget requireTarget(UUID runId, UUID testCaseId) {
        List<ExecutionTarget> targets = jdbcTemplate.query("""
                select run.mode, run.status, test_case.case_key, test_case.category,
                       test_case.severity, test_case.target_tool, test_case.payload_hash,
                       test_case.expected_invariant, test_case.oracle_type,
                       test_case.preconditions_json::text
                  from test_runs run
                  join test_cases test_case on test_case.suite_id = run.suite_id
                 where run.id = ? and test_case.id = ?
                """, (resultSet, rowNumber) -> {
            JsonNode preconditions = parseJson(resultSet.getString("preconditions_json"));
            return new ExecutionTarget(
                    TestRunMode.valueOf(resultSet.getString("mode")),
                    TestRunStatus.valueOf(resultSet.getString("status")),
                    resultSet.getString("case_key"),
                    resultSet.getString("category"),
                    resultSet.getString("severity"),
                    resultSet.getString("target_tool"),
                    resultSet.getString("payload_hash"),
                    resultSet.getString("expected_invariant"),
                    resultSet.getString("oracle_type"),
                    preconditions.path("caseId").asString(null),
                    preconditions.path("currentApplicantId").asString(null)
            );
        }, runId, testCaseId);
        if (targets.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "TestRun/TestCase pair not found");
        }
        ExecutionTarget target = targets.getFirst();
        if (target.sandboxCaseKey() == null || target.currentApplicantId() == null) {
            throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, "FA-02 preconditions are incomplete");
        }
        return target;
    }

    private void validateVariantAgainstTestCase(AttackVariant variant, ExecutionTarget target) {
        if (!variant.category().equals(target.category())
                || !variant.severity().equals(target.severity())
                || !variant.targetTool().equals(target.targetTool())
                || !variant.invariantId().equals(target.expectedInvariant())
                || !variant.oracleType().equals(target.oracleType())) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Curated attack variant identity does not match TestCase identity"
            );
        }
        if (!variant.variantHash().equals(target.payloadHash())) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Executed attack variant hash does not match TestCase payload_hash"
            );
        }
    }

    private CustomerResponseEvidence materializeEvidence(
            SandboxExecutionContext context,
            ToolDispatcher.DispatchResult dispatch,
            AgentRuntimeService.DeliveryReceipt delivery,
            boolean integrityValid
    ) {
        if (!dispatch.toolInvoked()) {
            return new CustomerResponseEvidence(
                    context.currentApplicantId(),
                    false,
                    false,
                    !dispatch.policyDecision().allowed(),
                    integrityValid,
                    null,
                    List.of()
            );
        }

        List<CustomerDataRow> rows = new ArrayList<>();
        JsonNode responseRows = dispatch.execution().output().path("rows");
        if (!responseRows.isArray()) {
            throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, "CUSTOMER_DATA_READ response rows are missing");
        }
        responseRows.forEach(row -> {
            String customerId = row.path("customerId").asString(null);
            if (customerId == null) {
                throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, "CUSTOMER_DATA_READ row customerId is missing");
            }
            Map<String, Object> fields = new LinkedHashMap<>();
            JsonNode fieldNode = row.path("fields");
            if (fieldNode.isObject()) {
                fieldNode.properties().forEach(entry -> fields.put(entry.getKey(), scalar(entry.getValue())));
            }
            rows.add(new CustomerDataRow(customerId, fields));
        });
        return new CustomerResponseEvidence(
                context.currentApplicantId(),
                true,
                delivery.deliveredToAgent(),
                false,
                integrityValid,
                dispatch.responseEvent().sequence(),
                rows
        );
    }

    private Object scalar(JsonNode value) {
        if (value == null || value.isNull()) {
            return null;
        }
        if (value.isBoolean()) {
            return value.asBoolean();
        }
        if (value.isIntegralNumber()) {
            return value.asLong();
        }
        if (value.isFloatingPointNumber()) {
            return value.asDouble();
        }
        return value.asString();
    }

    private TestCaseRunStatus caseStatus(OracleOutcome outcome) {
        return switch (outcome) {
            case ATTACK_SUCCESS -> TestCaseRunStatus.FAILED_SECURITY;
            case ATTACK_BLOCKED -> TestCaseRunStatus.PASSED;
            case INCONCLUSIVE -> TestCaseRunStatus.ERROR;
            case NORMAL_SUCCESS -> TestCaseRunStatus.PASSED;
            case NORMAL_FAILURE -> TestCaseRunStatus.FAILED_FUNCTIONAL;
        };
    }

    private JsonNode parseJson(String value) {
        try {
            return objectMapper.readTree(value);
        } catch (Exception exception) {
            throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, "TestCase preconditions JSON is invalid");
        }
    }

    public record Result(
            UUID runId,
            UUID caseRunId,
            UUID traceId,
            String oracleOutcome,
            String reasonCode,
            UUID oracleResultId,
            UUID findingId,
            String variantHash,
            boolean deliveredToAgent
    ) {
    }

    private record ExecutionTarget(
            TestRunMode mode,
            TestRunStatus status,
            String caseKey,
            String category,
            String severity,
            String targetTool,
            String payloadHash,
            String expectedInvariant,
            String oracleType,
            String sandboxCaseKey,
            String currentApplicantId
    ) {
    }
}
