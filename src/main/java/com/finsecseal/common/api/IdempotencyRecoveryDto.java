package com.finsecseal.common.api;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.UUID;

public final class IdempotencyRecoveryDto {

    private IdempotencyRecoveryDto() {
    }

    public enum Resolution {
        RELEASE,
        COMPLETE
    }

    public record Request(
            @NotBlank @Size(max = 120) String actorId,
            @NotBlank @Pattern(regexp = "POST|PUT|PATCH|DELETE") String httpMethod,
            @NotBlank @Size(max = 1000) @Pattern(regexp = "^/api/v1/.*") String requestPath,
            @NotBlank @Pattern(regexp = "^[A-Za-z0-9._:-]{1,128}$") String idempotencyKey,
            @NotBlank @Pattern(regexp = "^sha256:[0-9a-f]{64}$") String requestDigest,
            @NotNull Resolution resolution,
            @NotBlank @Pattern(regexp = "^[A-Za-z0-9][A-Za-z0-9._:/-]{7,299}$") String verificationReference,
            @Valid Completion completedResponse
    ) {
    }

    public record Completion(
            @NotNull @Min(200) @Max(499) Integer status,
            @Size(max = 200) String contentType,
            @Size(max = 1000) String location,
            @NotNull UUID traceId,
            @NotBlank @Size(max = 1_500_000) String bodyBase64
    ) {
    }

    public record Response(
            UUID id,
            UUID idempotencyRecordId,
            Resolution resolution,
            String stateAfterRecovery,
            String responseDigest,
            String recoveredBy,
            Instant recoveredAt
    ) {
    }

    public record Pending(
            UUID idempotencyRecordId,
            String actorId,
            String httpMethod,
            String requestPath,
            String idempotencyKey,
            String requestDigest,
            Instant expiresAt,
            Instant executionFinishedAt,
            String recoveryReason,
            Instant createdAt
    ) {
    }
}
