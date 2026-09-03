package com.finsecseal.assurance;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.TraceIdFilter;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/releases/{releaseId}")
public class ReleaseAssuranceController {

    private final ReleaseAssuranceService service;

    public ReleaseAssuranceController(ReleaseAssuranceService service) {
        this.service = service;
    }

    @GetMapping("/metrics")
    ApiResponse<ReleaseAssuranceDto.MetricsView> metrics(@PathVariable UUID releaseId) {
        return ApiResponse.success(service.metrics(releaseId), TraceIdFilter.currentTraceId());
    }

    @PostMapping("/decision:evaluate")
    ApiResponse<ReleaseAssuranceDto.DecisionProposal> evaluate(
            @PathVariable UUID releaseId,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        return ApiResponse.success(service.evaluate(releaseId, actorId), TraceIdFilter.currentTraceId());
    }

    @PostMapping("/decision:confirm")
    ApiResponse<ReleaseAssuranceDto.DecisionView> confirm(
            @PathVariable UUID releaseId,
            @RequestHeader("If-Match") String inputDigest,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId,
            @RequestBody ReleaseAssuranceDto.ConfirmRequest request
    ) {
        return ApiResponse.success(
                service.confirm(releaseId, inputDigest, request, actorId),
                TraceIdFilter.currentTraceId()
        );
    }
}
