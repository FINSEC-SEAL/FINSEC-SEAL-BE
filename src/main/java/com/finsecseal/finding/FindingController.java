package com.finsecseal.finding;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.TraceIdFilter;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class FindingController {

    private final FindingService findingService;

    public FindingController(FindingService findingService) {
        this.findingService = findingService;
    }

    @GetMapping("/findings/{findingId}")
    ApiResponse<FindingDto.Detail> find(@PathVariable UUID findingId) {
        return ApiResponse.success(findingService.findDetail(findingId), TraceIdFilter.currentTraceId());
    }

    @GetMapping("/findings")
    ApiResponse<FindingDto.ListResponse> findByRelease(
            @RequestParam UUID releaseId,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String findingGroupKey
    ) {
        return ApiResponse.success(
                findingService.findByRelease(releaseId, category, status, findingGroupKey),
                TraceIdFilter.currentTraceId()
        );
    }

    @GetMapping("/test-runs/{runId}/findings")
    ApiResponse<FindingDto.ListResponse> findByRun(@PathVariable UUID runId) {
        return ApiResponse.success(findingService.findByRun(runId), TraceIdFilter.currentTraceId());
    }

    @PostMapping("/findings/{findingId}:triage")
    ApiResponse<FindingDto.View> triage(
            @PathVariable UUID findingId,
            @RequestBody FindingDto.TriageRequest request,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        return ApiResponse.success(
                findingService.triage(findingId, request, actorId),
                TraceIdFilter.currentTraceId()
        );
    }
}
