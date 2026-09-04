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
import com.finsecseal.oracle.domain.SensitiveFieldPolicy;
import com.finsecseal.oracle.evaluator.SensitiveFieldOracle;
import com.finsecseal.runtime.AgentToolLoopService;
import com.finsecseal.sandbox.SandboxExecutionContext;
import com.finsecseal.sandbox.SandboxFixtureService;
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
public class Fa03ExecutionOrchestrator {

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final AttackSeedCatalog attackSeedCatalog;
    private final AttackVariantFactory attackVariantFactory;
    private final TestRunPersistenceService runPersistenceService;
    private final AgentToolLoopService agentToolLoopService;
    private final SandboxFixtureService fixtureService;
    private final OracleAssessmentService oracleAssessmentService;
    private final RunExecutionLifecycleService lifecycleService;

    public Fa03ExecutionOrchestrator(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            AttackSeedCatalog attackSeedCatalog,
            AttackVariantFactory attackVariantFactory,
            TestRunPersistenceService runPersistenceService,
            AgentToolLoopService agentToolLoopService,
            SandboxFixtureService fixtureService,
            OracleAssessmentService oracleAssessmentService,
            RunExecutionLifecycleService lifecycleService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.attackSeedCatalog = attackSeedCatalog;
        this.attackVariantFactory = attackVariantFactory;
        this.runPersistenceService = runPersistenceService;
        this.agentToolLoopService = agentToolLoopService;
        this.fixtureService = fixtureService;
        this.oracleAssessmentService = oracleAssessmentService;
        this.lifecycleService = lifecycleService;
    }

    public Result execute(UUID runId, UUID testCaseId, String actorId) {
        String normalizedActor = actorId == null || actorId.isBlank() ? "orchestrator-b" : actorId;
        ExecutionTarget target = requireTarget(runId, testCaseId);
        if (target.mode() != TestRunMode.BASELINE) {
            throw new BusinessException(ErrorCode.INVALID_STATE_TRANSITION, "FA-03 only supports BASELINE");
        }
        if (target.status() != TestRunStatus.QUEUED && target.status() != TestRunStatus.RUNNING) {
            throw new BusinessException(
                    ErrorCode.INVALID_STATE_TRANSITION,
                    "FA-03 execution requires a QUEUED or RUNNING TestRun"
            );
        }
        if (!"FA-03".equals(target.category())) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "TestCase is not FA-03");
        }

        AttackSeed seed = attackSeedCatalog.requireSeed(target.category());
        AttackVariant variant = attackVariantFactory.fromSeed(seed);
        validateVariantAgainstTestCase(variant, target);
        UUID traceId = UUID.randomUUID();
        UUID caseRunId = null;

        try {
            lifecycleService.ensureRunning(runId, traceId, target.category(), normalizedActor);

            RunExecutionLifecycleService.CaseExecutionClaim claim = lifecycleService.claimCase(
                    runId, testCaseId, 0, variant.variantHash(), normalizedActor
            );
            TestRunPersistenceDto.CaseRun caseRun = claim.caseRun();
            caseRunId = caseRun.id();

            if (!claim.created()) {
                if (!isReplayableTerminal(caseRun.status())) {
                    throw new BusinessException(
                            ErrorCode.IDEMPOTENCY_IN_PROGRESS,
                            "The same TestCase execution is already in progress"
                    );
                }
                Result existing = existingResult(runId, caseRun);
                lifecycleService.completeIfReady(
                        runId,
                        caseRun.id(),
                        existing.traceId(),
                        target.category(),
                        existing.oracleOutcome(),
                        existing.reasonCode(),
                        normalizedActor
                );
                return existing;
            }

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
            AgentToolLoopService.LoopResult loop = agentToolLoopService.execute(
                    context,
                    variant,
                    normalizedActor
            );
            AgentToolLoopService.ToolStep oracleStep = loop.toolSteps().getFirst();

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
            CustomerResponseEvidence evidence = materializeEvidence(context, oracleStep, integrityValid);
            OracleResult oracleResult = new SensitiveFieldOracle(
                    fixtureService.sensitiveFieldPolicy(
                            runId,
                            target.sandboxCaseKey(),
                            target.currentApplicantId()
                    )
            ).evaluate(evidence);

            ExecutionEventDto.Event sourceEvent = oracleStep.dispatch().toolInvoked()
                    ? oracleStep.dispatch().responseEvent()
                    : oracleStep.dispatch().policyEvent();
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
            caseResult.put("deliveredToAgent", oracleStep.delivery().deliveredToAgent());
            if (oracleStep.delivery().status() != null) {
                caseResult.put("deliveryStatus", oracleStep.delivery().status().name());
            }
            if (oracleStep.delivery().deliveryEventId() != null) {
                caseResult.put("deliveryEventId", oracleStep.delivery().deliveryEventId().toString());
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
                            loop.latencyMs(),
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
                    oracleStep.delivery().deliveredToAgent()
            );
        } catch (BusinessException exception) {
            if (exception.errorCode() == ErrorCode.IDEMPOTENCY_IN_PROGRESS) {
                throw exception;
            }
            lifecycleService.sealFailure(runId, caseRunId, traceId, exception, normalizedActor);
            throw exception;
        } catch (RuntimeException exception) {
            lifecycleService.sealFailure(runId, caseRunId, traceId, exception, normalizedActor);
            throw exception;
        }
    }

    private Result existingResult(UUID runId, TestRunPersistenceDto.CaseRun caseRun) {
        JsonNode stored = caseRun.result();
        String oracleOutcome = stored.path("oracleOutcome").asString(caseRun.securityOutcome());
        String reasonCode = stored.path("reasonCode").asString(null);
        UUID oracleResultId = parseRequiredUuid(stored.path("oracleResultId").asString(null), "oracleResultId");
        UUID findingId = parseOptionalUuid(stored.path("findingId").asString(null));
        boolean deliveredToAgent = stored.path("deliveredToAgent").asBoolean();

        if (oracleOutcome == null || reasonCode == null) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Terminal TestCaseRun is missing persisted Oracle outcome evidence"
            );
        }
        return new Result(
                runId,
                caseRun.id(),
                existingTraceId(caseRun.id()),
                oracleOutcome,
                reasonCode,
                oracleResultId,
                findingId,
                caseRun.variantHash(),
                deliveredToAgent
        );
    }

    private UUID existingTraceId(UUID caseRunId) {
        List<UUID> traceIds = jdbcTemplate.query(
                """
                select trace_id
                  from execution_events
                 where test_case_run_id = ?
                 order by sequence
                 limit 1
                """,
                (resultSet, rowNumber) -> resultSet.getObject("trace_id", UUID.class),
                caseRunId
        );
        if (traceIds.isEmpty()) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Terminal TestCaseRun is missing its execution trace"
            );
        }
        return traceIds.getFirst();
    }

    private boolean isReplayableTerminal(TestCaseRunStatus status) {
        return status == TestCaseRunStatus.PASSED
                || status == TestCaseRunStatus.FAILED_SECURITY
                || status == TestCaseRunStatus.FAILED_FUNCTIONAL;
    }

    private UUID parseRequiredUuid(String value, String fieldName) {
        UUID parsed = parseOptionalUuid(value);
        if (parsed == null) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Terminal TestCaseRun is missing " + fieldName
            );
        }
        return parsed;
    }

    private UUID parseOptionalUuid(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException exception) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Terminal TestCaseRun contains an invalid evidence identifier"
            );
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
            throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, "FA-03 preconditions are incomplete");
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
            AgentToolLoopService.ToolStep oracleStep,
            boolean integrityValid
    ) {
        var dispatch = oracleStep.dispatch();
        var delivery = oracleStep.delivery();
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
        if (value == null || value.isNull()) return null;
        if (value.isBoolean()) return value.asBoolean();
        if (value.isIntegralNumber()) return value.asLong();
        if (value.isFloatingPointNumber()) return value.asDouble();
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
