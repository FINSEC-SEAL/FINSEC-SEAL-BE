package com.finsecseal.common.api;

import java.time.Instant;

public record ApiResponse<T>(T data, String traceId, Instant timestamp) {

    public static <T> ApiResponse<T> success(T data, String traceId) {
        return new ApiResponse<>(data, traceId, Instant.now());
    }
}
