package com.finsecseal.assurance;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.TraceIdFilter;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/replays")
public class ReplayComparisonController {

    private final ReplayComparisonService service;

    public ReplayComparisonController(ReplayComparisonService service) {
        this.service = service;
    }

    @GetMapping("/{replayRunId}/comparison")
    ApiResponse<ReplayComparisonDto.Detail> comparison(@PathVariable UUID replayRunId) {
        return ApiResponse.success(service.find(replayRunId), TraceIdFilter.currentTraceId());
    }
}
