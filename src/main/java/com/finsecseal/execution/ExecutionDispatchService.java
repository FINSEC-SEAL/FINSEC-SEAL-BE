package com.finsecseal.execution;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class ExecutionDispatchService {

    private final JdbcTemplate jdbcTemplate;
    private final Fa02ExecutionOrchestrator fa02;
    private final Fa03ExecutionOrchestrator fa03;
    private final Fa04ExecutionOrchestrator fa04;
    private final Fa05ExecutionOrchestrator fa05;

    public ExecutionDispatchService(
            JdbcTemplate jdbcTemplate,
            Fa02ExecutionOrchestrator fa02,
            Fa03ExecutionOrchestrator fa03,
            Fa04ExecutionOrchestrator fa04,
            Fa05ExecutionOrchestrator fa05
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.fa02 = fa02;
        this.fa03 = fa03;
        this.fa04 = fa04;
        this.fa05 = fa05;
    }

    public Result execute(UUID runId, UUID testCaseId, String actorId) {
        String category = jdbcTemplate.queryForObject("""
                select test_case.category
                  from test_runs run
                  join test_cases test_case on test_case.suite_id = run.suite_id
                 where run.id = ? and test_case.id = ?
                """, String.class, runId, testCaseId);

        if ("FA-02".equals(category)) {
            return from(fa02.execute(runId, testCaseId, actorId));
        }
        if ("FA-03".equals(category)) {
            return from(fa03.execute(runId, testCaseId, actorId));
        }
        if ("FA-04".equals(category)) {
            return from(fa04.execute(runId, testCaseId, actorId));
        }
        if ("FA-05".equals(category)) {
            return from(fa05.execute(runId, testCaseId, actorId));
        }

        throw new BusinessException(
                ErrorCode.VALIDATION_ERROR,
                "Unsupported execution category: " + category
        );
    }

    private Result from(Fa02ExecutionOrchestrator.Result result) {
        return new Result(
                result.runId(),
                result.caseRunId(),
                result.traceId(),
                result.oracleOutcome(),
                result.reasonCode(),
                result.oracleResultId(),
                result.findingId(),
                result.variantHash(),
                result.deliveredToAgent()
        );
    }


    private Result from(Fa03ExecutionOrchestrator.Result result) {
        return new Result(
                result.runId(),
                result.caseRunId(),
                result.traceId(),
                result.oracleOutcome(),
                result.reasonCode(),
                result.oracleResultId(),
                result.findingId(),
                result.variantHash(),
                result.deliveredToAgent()
        );
    }


    private Result from(Fa04ExecutionOrchestrator.Result result) {
        return new Result(
                result.runId(),
                result.caseRunId(),
                result.traceId(),
                result.oracleOutcome(),
                result.reasonCode(),
                result.oracleResultId(),
                result.findingId(),
                result.variantHash(),
                result.deliveredToAgent()
        );
    }

    private Result from(Fa05ExecutionOrchestrator.Result result) {
        return new Result(
                result.runId(),
                result.caseRunId(),
                result.traceId(),
                result.oracleOutcome(),
                result.reasonCode(),
                result.oracleResultId(),
                result.findingId(),
                result.variantHash(),
                result.deliveredToAgent()
        );
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
}
