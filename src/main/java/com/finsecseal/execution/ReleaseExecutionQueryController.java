package com.finsecseal.execution;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.TraceIdFilter;
import com.finsecseal.common.domain.TestRunMode;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/releases/{releaseId}")
public class ReleaseExecutionQueryController {

    private final ReleaseExecutionQueryService queryService;

    public ReleaseExecutionQueryController(ReleaseExecutionQueryService queryService) {
        this.queryService = queryService;
    }

    @GetMapping("/test-suites")
    ApiResponse<ExecutionQueryDto.TestSuiteListResponse> listSuites(
            @PathVariable UUID releaseId,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) Integer limit,
            @RequestParam(required = false) String cursor,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        return ApiResponse.success(
                queryService.listSuites(releaseId, status, limit, cursor),
                TraceIdFilter.currentTraceId()
        );
    }

    @GetMapping("/test-runs")
    ApiResponse<ExecutionQueryDto.TestRunListResponse> listRuns(
            @PathVariable UUID releaseId,
            @RequestParam(required = false) TestRunMode mode,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) Integer limit,
            @RequestParam(required = false) String cursor,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        return ApiResponse.success(
                queryService.listRuns(releaseId, mode, status, limit, cursor),
                TraceIdFilter.currentTraceId()
        );
    }

    @GetMapping("/replay-comparisons")
    ApiResponse<ExecutionQueryDto.ReplayComparisonListResponse> listReplayComparisons(
            @PathVariable UUID releaseId,
            @RequestParam(required = false) Integer limit,
            @RequestParam(required = false) String cursor,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        return ApiResponse.success(
                queryService.listReplayComparisons(releaseId, limit, cursor),
                TraceIdFilter.currentTraceId()
        );
    }
}