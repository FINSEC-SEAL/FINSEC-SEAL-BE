package com.finsecseal.common.api;

import org.springframework.http.HttpStatus;

public enum ErrorCode {
    RESOURCE_NOT_FOUND(HttpStatus.NOT_FOUND, false),
    RESOURCE_CONFLICT(HttpStatus.CONFLICT, false),
    MANIFEST_INVALID(HttpStatus.UNPROCESSABLE_CONTENT, false),
    RELEASE_CHANGED(HttpStatus.CONFLICT, false),
    INVALID_STATE_TRANSITION(HttpStatus.CONFLICT, false),
    EVIDENCE_INCOMPLETE(HttpStatus.CONFLICT, false),
    SECRET_DETECTED(HttpStatus.UNPROCESSABLE_CONTENT, false),
    STREAM_CURSOR_EXPIRED(HttpStatus.GONE, true),
    IDEMPOTENCY_CONFLICT(HttpStatus.CONFLICT, false),
    IDEMPOTENCY_IN_PROGRESS(HttpStatus.CONFLICT, true),
    CONFIGURATION_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, false),
    VALIDATION_ERROR(HttpStatus.BAD_REQUEST, false),
    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, true);

    private final HttpStatus status;
    private final boolean retryable;

    ErrorCode(HttpStatus status, boolean retryable) {
        this.status = status;
        this.retryable = retryable;
    }

    public HttpStatus status() {
        return status;
    }

    public boolean retryable() {
        return retryable;
    }
}
