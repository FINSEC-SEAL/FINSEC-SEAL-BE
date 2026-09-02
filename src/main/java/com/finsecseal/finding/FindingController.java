package com.finsecseal.finding;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.TraceIdFilter;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class FindingController {

    private final FindingService findingService;

    public FindingController(FindingService findingService) {
        this.findingService = findingService;
    }

    @GetMapping("/findings/{findingId}")
    ApiResponse<FindingDto.View> find(@PathVariable UUID findingId) {
        return ApiResponse.success(findingService.find(findingId), TraceIdFilter.currentTraceId());
    }

    @GetMapping("/test-runs/{runId}/findings")
    ApiResponse<FindingDto.ListResponse> findByRun(@PathVariable UUID runId) {
        return ApiResponse.success(findingService.findByRun(runId), TraceIdFilter.currentTraceId());
    }
}
