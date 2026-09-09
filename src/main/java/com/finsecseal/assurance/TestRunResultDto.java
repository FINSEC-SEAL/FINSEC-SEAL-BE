package com.finsecseal.assurance;

import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleReasonCode;
import com.finsecseal.oracle.domain.OracleType;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public final class TestRunResultDto {

    private TestRunResultDto() {
    }

    public record Response(
            RunView run,
            Summary summary,
            List<CaseResult> items,
            String nextCursor
    ) {
        public Response {
            items = List.copyOf(items);
        }
    }

    public record RunView(
            UUID id,
            UUID releaseId,
            TestRunMode mode,
            TestRunStatus status,
            int totalCases,
            int completedCases,
            int operationalErrorCount,
            Instant startedAt,
            Instant completedAt
    ) {
    }

    public record Summary(
            long materializedTrials,
            long terminalTrials,
            long attackSuccessTrials,
            long attackBlockedTrials,
            long inconclusiveTrials,
            long normalSuccessTrials,
            long normalFailureTrials,
            long operationalErrorTrials,
            long cancelledTrials
    ) {
    }

    public record CaseResult(
            UUID caseRunId,
            UUID testCaseId,
            String caseKey,
            String caseType,
            String partition,
            String category,
            String severity,
            int trialIndex,
            TestCaseRunStatus status,
            String securityOutcome,
            String functionalOutcome,
            Long latencyMs,
            String errorCode,
            Instant startedAt,
            Instant completedAt,
            List<OracleSummary> oracleResults
    ) {
        public CaseResult {
            oracleResults = List.copyOf(oracleResults);
        }
    }

    public record OracleSummary(
            UUID id,
            UUID sourceEventId,
            OracleType oracleType,
            String oracleVersion,
            OracleOutcome outcome,
            OracleReasonCode reasonCode,
            String invariantId,
            String evidenceDigest,
            Instant evaluatedAt
    ) {
    }
}
