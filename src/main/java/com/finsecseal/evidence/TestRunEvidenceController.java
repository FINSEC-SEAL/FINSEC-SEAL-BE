package com.finsecseal.evidence;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.api.TraceIdFilter;
import jakarta.validation.Valid;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.util.UUID;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@RestController
@RequestMapping("/api/v1/test-runs")
public class TestRunEvidenceController {

    private final TestRunProjectionService runProjectionService;
    private final ExecutionEventService eventService;
    private final ExecutionEventStream eventStream;

    public TestRunEvidenceController(
            TestRunProjectionService runProjectionService,
            ExecutionEventService eventService,
            ExecutionEventStream eventStream
    ) {
        this.runProjectionService = runProjectionService;
        this.eventService = eventService;
        this.eventStream = eventStream;
    }

    @GetMapping("/{runId}")
    ApiResponse<TestRunDto.Projection> find(@PathVariable UUID runId) {
        return ApiResponse.success(runProjectionService.find(runId), TraceIdFilter.currentTraceId());
    }

    @PostMapping("/{runId}/events")
    ResponseEntity<ApiResponse<ExecutionEventDto.Event>> append(
            @PathVariable UUID runId,
            @Valid @RequestBody ExecutionEventDto.AppendRequest request,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        ExecutionEventDto.Event event = eventService.append(runId, request, actorId);
        return ResponseEntity.created(URI.create(
                "/api/v1/test-runs/" + runId + "/event-history?after=" + (event.sequence() - 1)
        )).body(ApiResponse.success(event, TraceIdFilter.currentTraceId()));
    }

    @GetMapping("/{runId}/event-history")
    ApiResponse<ExecutionEventDto.History> history(
            @PathVariable UUID runId,
            @RequestParam(defaultValue = "0") long after,
            @RequestParam(defaultValue = "100") int limit
    ) {
        return ApiResponse.success(eventService.history(runId, after, limit), TraceIdFilter.currentTraceId());
    }

    @GetMapping("/{runId}/events:verify")
    ApiResponse<ExecutionEventDto.ChainVerification> verify(@PathVariable UUID runId) {
        return ApiResponse.success(eventService.verifyChain(runId), TraceIdFilter.currentTraceId());
    }

    @GetMapping(value = "/{runId}/events", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    SseEmitter stream(
            @PathVariable UUID runId,
            @RequestHeader(value = "Last-Event-ID", required = false) String lastEventId,
            HttpServletResponse response
    ) {
        response.setHeader("Cache-Control", "no-cache");
        response.setHeader("X-Accel-Buffering", "no");
        return eventStream.subscribe(runId, parseCursor(lastEventId));
    }

    private long parseCursor(String value) {
        if (value == null || value.isBlank()) {
            return 0;
        }
        try {
            long cursor = Long.parseLong(value);
            if (cursor < 0) {
                throw new NumberFormatException("negative cursor");
            }
            return cursor;
        } catch (NumberFormatException exception) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "Last-Event-ID must be non-negative");
        }
    }
}
