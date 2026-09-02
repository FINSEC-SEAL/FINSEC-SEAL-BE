package com.finsecseal.oracle.application;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.TraceIdFilter;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class OracleResultController {

    private final OracleResultService oracleResultService;

    public OracleResultController(OracleResultService oracleResultService) {
        this.oracleResultService = oracleResultService;
    }

    @GetMapping("/oracle-results/{resultId}")
    ApiResponse<OracleResultDto.View> find(@PathVariable UUID resultId) {
        return ApiResponse.success(oracleResultService.find(resultId), TraceIdFilter.currentTraceId());
    }

    @GetMapping("/test-runs/{runId}/oracle-results")
    ApiResponse<OracleResultDto.ListResponse> findByRun(
            @PathVariable UUID runId,
            @RequestParam(required = false) UUID testCaseRunId
    ) {
        return ApiResponse.success(
                oracleResultService.findByRun(runId, testCaseRunId),
                TraceIdFilter.currentTraceId()
        );
    }
}
