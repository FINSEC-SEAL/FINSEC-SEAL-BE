package com.finsecseal.common.api;

import jakarta.validation.Valid;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/platform/idempotency-recoveries")
public class IdempotencyRecoveryController {

    private final IdempotencyRecoveryService recoveryService;

    public IdempotencyRecoveryController(IdempotencyRecoveryService recoveryService) {
        this.recoveryService = recoveryService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    ApiResponse<IdempotencyRecoveryDto.Response> recover(
            @Valid @RequestBody IdempotencyRecoveryDto.Request request,
            @RequestHeader(value = "X-Operator-Recovery-Key", required = false) String recoveryKey,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId
    ) {
        return ApiResponse.success(
                recoveryService.recover(request, recoveryKey, actorId),
                TraceIdFilter.currentTraceId()
        );
    }

    @GetMapping("/pending")
    ApiResponse<List<IdempotencyRecoveryDto.Pending>> pending(
            @RequestHeader(value = "X-Operator-Recovery-Key", required = false) String recoveryKey,
            @RequestHeader(value = "X-Actor-Id", required = false) String actorId,
            @RequestParam(defaultValue = "50") int limit
    ) {
        return ApiResponse.success(
                recoveryService.findPending(recoveryKey, actorId, limit),
                TraceIdFilter.currentTraceId()
        );
    }
}
