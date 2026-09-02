package com.finsecseal.common.api;

import jakarta.validation.ConstraintViolationException;
import java.net.URI;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.async.AsyncRequestTimeoutException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(BusinessException.class)
    ProblemDetail handleBusiness(BusinessException exception) {
        return problem(exception.errorCode(), exception.getMessage(), List.of());
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, ConstraintViolationException.class})
    ProblemDetail handleValidation(Exception exception) {
        List<String> errors = exception instanceof MethodArgumentNotValidException validation
                ? validation.getBindingResult().getFieldErrors().stream()
                    .map(error -> error.getField() + ": " + error.getDefaultMessage())
                    .toList()
                : List.of(exception.getMessage());
        return problem(ErrorCode.VALIDATION_ERROR, "Request validation failed", errors);
    }

    @ExceptionHandler(AsyncRequestTimeoutException.class)
    void handleAsyncTimeout() {
        // SSE timeout/closed client is a normal stream lifecycle event; the response may already be committed.
    }

    @ExceptionHandler(Exception.class)
    ProblemDetail handleUnexpected(Exception exception) {
        log.error("Unhandled request failure", exception);
        return problem(ErrorCode.INTERNAL_ERROR, "Unexpected server error", List.of());
    }

    private ProblemDetail problem(ErrorCode code, String detail, List<String> errors) {
        HttpStatus status = code.status();
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setType(URI.create("https://finsec-seal.local/problems/" + code.name().toLowerCase()));
        problem.setTitle(status.getReasonPhrase());
        problem.setProperty("code", code.name());
        problem.setProperty("traceId", TraceIdFilter.currentTraceId());
        problem.setProperty("retryable", code.retryable());
        problem.setProperty("errors", errors);
        return problem;
    }
}
