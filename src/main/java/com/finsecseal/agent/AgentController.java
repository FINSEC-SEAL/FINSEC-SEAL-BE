package com.finsecseal.agent;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.TraceIdFilter;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/agents")
public class AgentController {

    private final AgentService agentService;

    public AgentController(AgentService agentService) {
        this.agentService = agentService;
    }

    @PostMapping
    ResponseEntity<ApiResponse<AgentDto.Response>> create(@Valid @RequestBody AgentDto.CreateRequest request) {
        AgentDto.Response response = agentService.create(request);
        return ResponseEntity.created(URI.create("/api/v1/agents/" + response.id()))
                .body(ApiResponse.success(response, TraceIdFilter.currentTraceId()));
    }

    @GetMapping
    ApiResponse<List<AgentDto.Response>> findAll() {
        return ApiResponse.success(agentService.findAll(), TraceIdFilter.currentTraceId());
    }

    @GetMapping("/{agentId}")
    ApiResponse<AgentDto.Response> find(@PathVariable UUID agentId) {
        return ApiResponse.success(agentService.find(agentId), TraceIdFilter.currentTraceId());
    }

    @PutMapping("/{agentId}")
    ApiResponse<AgentDto.Response> update(
            @PathVariable UUID agentId,
            @Valid @RequestBody AgentDto.UpdateRequest request
    ) {
        return ApiResponse.success(agentService.update(agentId, request), TraceIdFilter.currentTraceId());
    }

    @DeleteMapping("/{agentId}")
    ApiResponse<AgentDto.Response> archive(@PathVariable UUID agentId) {
        return ApiResponse.success(agentService.archive(agentId), TraceIdFilter.currentTraceId());
    }
}
