package com.finsecseal.execution;

import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public final class ExecutionQueryDto {

    private ExecutionQueryDto() {
    }

    public record TestSuiteSummary(
            UUID id,
            UUID releaseId,
            String version,
            String status,
            String suiteHash,
            int caseCount
    ) {
    }

    public record TestSuiteListResponse(List<TestSuiteSummary> items, String nextCursor) {
        public TestSuiteListResponse {
            items = List.copyOf(items);
        }
    }

    public record TestRunSummary(
            UUID id,
            UUID releaseId,
            UUID suiteId,
            TestRunMode mode,
            TestRunStatus status,
            int totalCases,
            int completedCases,
            int operationalErrorCount,
            long latestSequence,
            Instant startedAt,
            Instant completedAt
    ) {
    }

    public record TestRunListResponse(List<TestRunSummary> items, String nextCursor) {
        public TestRunListResponse {
            items = List.copyOf(items);
        }
    }

    public record ReplayComparisonView(
            UUID baselineRunId,
            UUID replayRunId,
            String category,
            boolean comparable,
            List<String> mismatchReasons
    ) {
        public ReplayComparisonView {
            mismatchReasons = List.copyOf(mismatchReasons);
        }
    }

    public record ReplayComparisonListResponse(List<ReplayComparisonView> items, String nextCursor) {
        public ReplayComparisonListResponse {
            items = List.copyOf(items);
        }
    }
}