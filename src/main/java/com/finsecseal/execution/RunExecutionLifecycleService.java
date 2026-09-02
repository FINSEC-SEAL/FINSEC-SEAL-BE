package com.finsecseal.execution;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.sandbox.SandboxFixtureService;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Service
public class RunExecutionLifecycleService {

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final SandboxFixtureService fixtureService;
    private final ExecutionEventService eventService;
    private final TestRunPersistenceService runPersistenceService;

    public RunExecutionLifecycleService(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            SandboxFixtureService fixtureService,
            ExecutionEventService eventService,
            TestRunPersistenceService runPersistenceService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.fixtureService = fixtureService;
        this.eventService = eventService;
        this.runPersistenceService = runPersistenceService;
    }

    public void ensureRunning(UUID runId, UUID traceId, String category, String actorId) {
        TestRunStatus status = runStatus(runId);
        if (status == TestRunStatus.RUNNING) {
            if (!fixtureService.verifyIntegrity(runId)) {
                throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, "Golden Fixture integrity validation failed");
            }
            return;
        }
        if (status != TestRunStatus.QUEUED) {
            throw new BusinessException(
                    ErrorCode.INVALID_STATE_TRANSITION,
                    "Execution requires a QUEUED or RUNNING TestRun"
            );
        }

        eventService.append(
                runId,
                new ExecutionEventDto.AppendRequest(
                        null,
                        traceId,
                        ExecutionEventType.RUN_STARTED,
                        null,
                        null,
                        null,
                        null,
                        "BASELINE",
                        objectMapper.createObjectNode().put("category", category)
                ),
                actorId
        );
        runPersistenceService.updateStatus(
                runId,
                new TestRunPersistenceDto.StatusRequest(TestRunStatus.PREPARING, 0, 0, null),
                actorId
        );
        fixtureService.createOrReset(runId);
        if (!fixtureService.verifyIntegrity(runId)) {
            throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, "Golden Fixture integrity validation failed");
        }
        runPersistenceService.updateStatus(
                runId,
                new TestRunPersistenceDto.StatusRequest(TestRunStatus.RUNNING, 0, 0, null),
                actorId
        );
    }

    @Transactional
    public boolean completeIfReady(
            UUID runId,
            UUID caseRunId,
            UUID traceId,
            String category,
            String oracleOutcome,
            String reasonCode,
            String actorId
    ) {
        TestRunStatus status = lockRunStatus(runId);
        if (status != TestRunStatus.RUNNING) {
            return false;
        }
        RunCounts counts = readRunCounts(runId);
        if (counts.materializedCases() != counts.totalCases()
                || counts.terminalCases() != counts.totalCases()) {
            return false;
        }

        ObjectNode summary = objectMapper.createObjectNode();
        summary.put("category", category);
        summary.put("oracleOutcome", oracleOutcome);
        summary.put("reasonCode", reasonCode);
        summary.put("completedCases", counts.terminalCases());
        summary.put("operationalErrorCount", counts.errorCases());
        eventService.append(
                runId,
                new ExecutionEventDto.AppendRequest(
                        caseRunId,
                        traceId,
                        ExecutionEventType.RUN_COMPLETED,
                        null,
                        null,
                        null,
                        null,
                        "RUN_COMPLETED",
                        summary
                ),
                actorId
        );
        runPersistenceService.updateStatus(
                runId,
                new TestRunPersistenceDto.StatusRequest(
                        TestRunStatus.COMPLETED,
                        counts.terminalCases(),
                        counts.errorCases(),
                        summary
                ),
                actorId
        );
        return true;
    }

    @Transactional
    public void sealFailure(
            UUID runId,
            UUID caseRunId,
            UUID traceId,
            RuntimeException failure,
            String actorId
    ) {
        TestRunStatus status = lockRunStatus(runId);
        if (status.isTerminal()) {
            return;
        }

        if (caseRunId != null) {
            TestCaseRunStatus caseStatus = caseStatus(runId, caseRunId);
            if (caseStatus != null && !isTerminal(caseStatus)) {
                ObjectNode result = objectMapper.createObjectNode();
                result.put("failureType", failure.getClass().getSimpleName());
                result.put("message", safeMessage(failure.getMessage()));
                runPersistenceService.updateCaseStatus(
                        runId,
                        caseRunId,
                        new TestRunPersistenceDto.CaseRunStatusRequest(
                                TestCaseRunStatus.ERROR,
                                null,
                                "NOT_EVALUATED",
                                null,
                                objectMapper.createObjectNode(),
                                "RUNTIME_EXECUTION_ERROR",
                                result
                        ),
                        actorId
                );
            }
        }

        RunCounts counts = readRunCounts(runId);
        ensureRunStartedForFailure(runId, traceId, actorId);
        ObjectNode metadata = objectMapper.createObjectNode();
        metadata.put("failureType", failure.getClass().getSimpleName());
        metadata.put("message", safeMessage(failure.getMessage()));
        metadata.put("completedCases", counts.terminalCases());
        metadata.put("operationalErrorCount", counts.errorCases());
        eventService.append(
                runId,
                new ExecutionEventDto.AppendRequest(
                        caseRunId,
                        traceId,
                        ExecutionEventType.RUN_FAILED,
                        null,
                        null,
                        null,
                        null,
                        "RUNTIME_EXECUTION_ERROR",
                        metadata
                ),
                actorId
        );
        runPersistenceService.updateStatus(
                runId,
                new TestRunPersistenceDto.StatusRequest(
                        TestRunStatus.FAILED,
                        counts.terminalCases(),
                        counts.errorCases(),
                        metadata
                ),
                actorId
        );
    }

    private void ensureRunStartedForFailure(UUID runId, UUID traceId, String actorId) {
        Integer count = jdbcTemplate.queryForObject(
                "select count(*) from execution_events where run_id = ?",
                Integer.class,
                runId
        );
        if (Integer.valueOf(0).equals(count)) {
            eventService.append(
                    runId,
                    new ExecutionEventDto.AppendRequest(
                            null,
                            traceId,
                            ExecutionEventType.RUN_STARTED,
                            null,
                            null,
                            null,
                            null,
                            "RECOVERY_START",
                            objectMapper.createObjectNode().put("failureRecovery", true)
                    ),
                    actorId
            );
        }
    }

    private RunCounts readRunCounts(UUID runId) {
        List<RunCounts> rows = jdbcTemplate.query("""
                select run.status, run.total_cases,
                       count(case_run.id)::integer materialized_cases,
                       count(case_run.id) filter (where case_run.status in (
                           'PASSED', 'FAILED_SECURITY', 'FAILED_FUNCTIONAL', 'ERROR', 'CANCELLED'
                       ))::integer terminal_cases,
                       count(case_run.id) filter (where case_run.status = 'ERROR')::integer error_cases
                  from test_runs run
                  left join test_case_runs case_run on case_run.test_run_id = run.id
                 where run.id = ?
                 group by run.id, run.status, run.total_cases
                """, (resultSet, rowNumber) -> new RunCounts(
                TestRunStatus.valueOf(resultSet.getString("status")),
                resultSet.getInt("total_cases"),
                resultSet.getInt("materialized_cases"),
                resultSet.getInt("terminal_cases"),
                resultSet.getInt("error_cases")
        ), runId);
        if (rows.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "TestRun not found");
        }
        return rows.getFirst();
    }

    private TestRunStatus runStatus(UUID runId) {
        List<TestRunStatus> statuses = jdbcTemplate.query(
                "select status from test_runs where id = ?",
                (resultSet, rowNumber) -> TestRunStatus.valueOf(resultSet.getString("status")),
                runId
        );
        if (statuses.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "TestRun not found");
        }
        return statuses.getFirst();
    }

    private TestRunStatus lockRunStatus(UUID runId) {
        List<TestRunStatus> statuses = jdbcTemplate.query(
                "select status from test_runs where id = ? for update",
                (resultSet, rowNumber) -> TestRunStatus.valueOf(resultSet.getString("status")),
                runId
        );
        if (statuses.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "TestRun not found");
        }
        return statuses.getFirst();
    }

    private TestCaseRunStatus caseStatus(UUID runId, UUID caseRunId) {
        List<TestCaseRunStatus> statuses = jdbcTemplate.query(
                "select status from test_case_runs where id = ? and test_run_id = ?",
                (resultSet, rowNumber) -> TestCaseRunStatus.valueOf(resultSet.getString("status")),
                caseRunId,
                runId
        );
        return statuses.isEmpty() ? null : statuses.getFirst();
    }

    private boolean isTerminal(TestCaseRunStatus status) {
        return status == TestCaseRunStatus.PASSED
                || status == TestCaseRunStatus.FAILED_SECURITY
                || status == TestCaseRunStatus.FAILED_FUNCTIONAL
                || status == TestCaseRunStatus.ERROR
                || status == TestCaseRunStatus.CANCELLED;
    }

    private String safeMessage(String message) {
        if (message == null || message.isBlank()) {
            return "Execution failed";
        }
        return message.length() <= 400 ? message : message.substring(0, 400);
    }

    private record RunCounts(
            TestRunStatus status,
            int totalCases,
            int materializedCases,
            int terminalCases,
            int errorCases
    ) {
    }
}
