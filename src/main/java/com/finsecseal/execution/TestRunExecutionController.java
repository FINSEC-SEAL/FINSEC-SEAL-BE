package com.finsecseal.execution;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.TraceIdFilter;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.evidence.TestRunPersistenceDto;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/test-runs")
public class TestRunExecutionController {

    private final TestRunStartService startService;

    public TestRunExecutionController(TestRunStartService startService) {
        this.startService = startService;
    }

    @PostMapping
    public ResponseEntity<ApiResponse<TestRunPersistenceDto.Registered>> start(
            @RequestBody StartRequest request,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        TestRunPersistenceDto.Registered registered = startService.start(
                new TestRunStartService.Request(
                        request.releaseId(),
                        request.suiteId(),
                        request.mode(),
                        request.contractVersionId(),
                        request.caseIds(),
                        request.randomSeed()
                ),
                actorId
        );

        return ResponseEntity.accepted()
                .body(ApiResponse.success(registered, TraceIdFilter.currentTraceId()));
    }

    public record StartRequest(
            UUID releaseId,
            UUID suiteId,
            TestRunMode mode,
            UUID contractVersionId,
            List<UUID> caseIds,
            Long randomSeed
    ) {
    }
}
