package com.finsecseal.evidence;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.TraceIdFilter;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/platform/test-runs")
public class TestRunPersistenceController {

    private final TestRunPersistenceService persistenceService;

    public TestRunPersistenceController(TestRunPersistenceService persistenceService) {
        this.persistenceService = persistenceService;
    }

    @PostMapping
    ResponseEntity<ApiResponse<TestRunPersistenceDto.Registered>> register(
            @Valid @RequestBody TestRunPersistenceDto.RegisterRequest request,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        TestRunPersistenceDto.Registered registered = persistenceService.register(request, actorId);
        return ResponseEntity.accepted()
                .location(URI.create(registered.statusUrl()))
                .body(ApiResponse.success(registered, TraceIdFilter.currentTraceId()));
    }

    @PostMapping("/{runId}:status")
    ApiResponse<TestRunDto.Projection> updateStatus(
            @PathVariable UUID runId,
            @Valid @RequestBody TestRunPersistenceDto.StatusRequest request,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        return ApiResponse.success(
                persistenceService.updateStatus(runId, request, actorId),
                TraceIdFilter.currentTraceId()
        );
    }

    @PostMapping("/{runId}/case-runs")
    ResponseEntity<ApiResponse<TestRunPersistenceDto.CaseRun>> registerCase(
            @PathVariable UUID runId,
            @Valid @RequestBody TestRunPersistenceDto.CaseRunRegisterRequest request,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        TestRunPersistenceDto.CaseRun caseRun = persistenceService.registerCase(runId, request, actorId);
        return ResponseEntity.created(URI.create(
                "/api/v1/platform/test-runs/" + runId + "/case-runs/" + caseRun.id()
        )).body(ApiResponse.success(caseRun, TraceIdFilter.currentTraceId()));
    }

    @PostMapping("/{runId}/case-runs/{caseRunId}:status")
    ApiResponse<TestRunPersistenceDto.CaseRun> updateCaseStatus(
            @PathVariable UUID runId,
            @PathVariable UUID caseRunId,
            @Valid @RequestBody TestRunPersistenceDto.CaseRunStatusRequest request,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        return ApiResponse.success(
                persistenceService.updateCaseStatus(runId, caseRunId, request, actorId),
                TraceIdFilter.currentTraceId()
        );
    }

    @GetMapping("/{runId}/case-runs/{caseRunId}")
    ApiResponse<TestRunPersistenceDto.CaseRun> findCase(
            @PathVariable UUID runId,
            @PathVariable UUID caseRunId
    ) {
        TestRunPersistenceDto.CaseRun caseRun = persistenceService.findCase(caseRunId);
        if (!caseRun.testRunId().equals(runId)) {
            throw new com.finsecseal.common.api.BusinessException(
                    com.finsecseal.common.api.ErrorCode.RESOURCE_NOT_FOUND,
                    "TestCaseRun not found for TestRun"
            );
        }
        return ApiResponse.success(caseRun, TraceIdFilter.currentTraceId());
    }
}
