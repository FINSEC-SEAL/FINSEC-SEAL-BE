package com.finsecseal.execution;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ReleaseExecutionQueryControllerTest {

    @Test
    void returnsReleaseScopedTestSuites() {
        ReleaseExecutionQueryService service = mock(ReleaseExecutionQueryService.class);
        ReleaseExecutionQueryController controller = new ReleaseExecutionQueryController(service);
        UUID releaseId = UUID.randomUUID();
        ExecutionQueryDto.TestSuiteListResponse expected = new ExecutionQueryDto.TestSuiteListResponse(
                List.of(new ExecutionQueryDto.TestSuiteSummary(
                        UUID.randomUUID(), releaseId, "1.0", "READY", "sha256:" + "a".repeat(64), 12
                )),
                null
        );

        when(service.listSuites(releaseId, "READY", 10, null)).thenReturn(expected);

        ApiResponse<ExecutionQueryDto.TestSuiteListResponse> response =
                controller.listSuites(releaseId, "READY", 10, null, "frontend-b");

        assertThat(response.data()).isEqualTo(expected);
        verify(service).listSuites(releaseId, "READY", 10, null);
    }

    @Test
    void returnsReleaseScopedTestRuns() {
        ReleaseExecutionQueryService service = mock(ReleaseExecutionQueryService.class);
        ReleaseExecutionQueryController controller = new ReleaseExecutionQueryController(service);
        UUID releaseId = UUID.randomUUID();
        ExecutionQueryDto.TestRunListResponse expected = new ExecutionQueryDto.TestRunListResponse(
                List.of(new ExecutionQueryDto.TestRunSummary(
                        UUID.randomUUID(),
                        releaseId,
                        UUID.randomUUID(),
                        TestRunMode.HELD_OUT,
                        TestRunStatus.COMPLETED,
                        12,
                        12,
                        0,
                        20,
                        Instant.parse("2026-09-01T00:00:00Z"),
                        Instant.parse("2026-09-01T00:02:00Z")
                )),
                null
        );

        when(service.listRuns(releaseId, TestRunMode.HELD_OUT, "COMPLETED", 10, null)).thenReturn(expected);

        ApiResponse<ExecutionQueryDto.TestRunListResponse> response =
                controller.listRuns(releaseId, TestRunMode.HELD_OUT, "COMPLETED", 10, null, "frontend-b");

        assertThat(response.data()).isEqualTo(expected);
        verify(service).listRuns(releaseId, TestRunMode.HELD_OUT, "COMPLETED", 10, null);
    }

    @Test
    void returnsReleaseScopedReplayComparisons() {
        ReleaseExecutionQueryService service = mock(ReleaseExecutionQueryService.class);
        ReleaseExecutionQueryController controller = new ReleaseExecutionQueryController(service);
        UUID releaseId = UUID.randomUUID();
        ExecutionQueryDto.ReplayComparisonListResponse expected =
                new ExecutionQueryDto.ReplayComparisonListResponse(
                        List.of(new ExecutionQueryDto.ReplayComparisonView(
                                UUID.randomUUID(),
                                UUID.randomUUID(),
                                "FA-02",
                                false,
                                List.of("MODEL_CONFIG_MISMATCH")
                        )),
                        null
                );

        when(service.listReplayComparisons(releaseId, 25, null)).thenReturn(expected);

        ApiResponse<ExecutionQueryDto.ReplayComparisonListResponse> response =
                controller.listReplayComparisons(releaseId, 25, null, "frontend-b");

        assertThat(response.data()).isEqualTo(expected);
        verify(service).listReplayComparisons(releaseId, 25, null);
    }
}