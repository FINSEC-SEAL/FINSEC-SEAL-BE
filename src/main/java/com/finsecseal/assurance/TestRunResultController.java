package com.finsecseal.assurance;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.TraceIdFilter;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/test-runs")
public class TestRunResultController {

    private final TestRunResultService service;

    public TestRunResultController(TestRunResultService service) {
        this.service = service;
    }

    @GetMapping("/{runId}/results")
    ApiResponse<TestRunResultDto.Response> results(
            @PathVariable UUID runId,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String outcome,
            @RequestParam(required = false) Integer limit,
            @RequestParam(required = false) String cursor
    ) {
        return ApiResponse.success(
                service.find(runId, category, outcome, limit, cursor),
                TraceIdFilter.currentTraceId()
        );
    }
}
