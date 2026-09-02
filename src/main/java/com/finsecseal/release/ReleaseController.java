package com.finsecseal.release;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.TraceIdFilter;
import java.net.URI;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.JsonNode;

@RestController
@RequestMapping("/api/v1")
public class ReleaseController {

    private final ReleaseService releaseService;

    public ReleaseController(ReleaseService releaseService) {
        this.releaseService = releaseService;
    }

    @PostMapping("/agents/{agentId}/releases")
    ResponseEntity<ApiResponse<ReleaseDto.Response>> create(
            @PathVariable UUID agentId,
            @RequestBody JsonNode manifest,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        ReleaseDto.Response response = releaseService.create(agentId, manifest, actorId);
        return ResponseEntity.created(URI.create("/api/v1/releases/" + response.id()))
                .body(ApiResponse.success(response, TraceIdFilter.currentTraceId()));
    }

    @GetMapping("/agents/{agentId}/releases")
    ApiResponse<List<ReleaseDto.Response>> findByAgent(@PathVariable UUID agentId) {
        return ApiResponse.success(releaseService.findByAgent(agentId), TraceIdFilter.currentTraceId());
    }

    @GetMapping("/releases/{releaseId}")
    ApiResponse<ReleaseDto.Response> find(@PathVariable UUID releaseId) {
        return ApiResponse.success(releaseService.find(releaseId), TraceIdFilter.currentTraceId());
    }

    @PostMapping("/releases/{releaseId}:validate")
    ApiResponse<ReleaseDto.ValidationResponse> validate(
            @PathVariable UUID releaseId,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        return ApiResponse.success(releaseService.validate(releaseId, actorId), TraceIdFilter.currentTraceId());
    }

    @PostMapping("/releases/{releaseId}:analyze")
    ApiResponse<ReleaseDto.Response> analyze(
            @PathVariable UUID releaseId,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        return ApiResponse.success(releaseService.analyze(releaseId, actorId), TraceIdFilter.currentTraceId());
    }

    @GetMapping("/releases/{releaseId}/fingerprint")
    ApiResponse<ReleaseDto.FingerprintResponse> fingerprint(
            @PathVariable UUID releaseId,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        return ApiResponse.success(releaseService.fingerprint(releaseId, actorId), TraceIdFilter.currentTraceId());
    }

    @GetMapping("/releases/{releaseId}/diff")
    ApiResponse<ReleaseDto.DiffResponse> diff(
            @PathVariable UUID releaseId,
            @RequestParam("against") UUID against,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        return ApiResponse.success(releaseService.diff(releaseId, against, actorId), TraceIdFilter.currentTraceId());
    }

    @PostMapping("/releases/{releaseId}:invalidate")
    ApiResponse<ReleaseDto.Response> invalidate(
            @PathVariable UUID releaseId,
            @RequestBody(required = false) JsonNode reason,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        return ApiResponse.success(
                releaseService.invalidate(releaseId, reason, actorId),
                TraceIdFilter.currentTraceId()
        );
    }
}
