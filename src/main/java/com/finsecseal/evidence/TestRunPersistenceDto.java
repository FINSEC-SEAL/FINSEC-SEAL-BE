package com.finsecseal.evidence;

import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

public final class TestRunPersistenceDto {

    private TestRunPersistenceDto() {
    }

    public record RegisterRequest(
            @NotNull UUID releaseId,
            @NotNull UUID suiteId,
            UUID contractVersionId,
            @NotNull TestRunMode mode,
            UUID baselinePairGroupId,
            JsonNode config,
            @NotNull @Pattern(regexp = "sha256:[0-9a-f]{64}") String fixtureDigest,
            @NotNull @Pattern(regexp = "sha256:[0-9a-f]{64}") String modelConfigHash,
            Long randomSeed,
            @Min(1) @Max(10000) int totalCases
    ) {
    }

    public record Registered(
            UUID runId,
            TestRunStatus status,
            String statusUrl,
            String streamUrl
    ) {
    }

    public record StatusRequest(
            @NotNull TestRunStatus status,
            @Min(0) Integer completedCases,
            @Min(0) Integer operationalErrorCount,
            JsonNode summary
    ) {
    }

    public record CaseRunRegisterRequest(
            @NotNull UUID testCaseId,
            @Min(0) int trialIndex,
            @NotNull @Pattern(regexp = "sha256:[0-9a-f]{64}") String variantHash
    ) {
    }

    public record CaseRunStatusRequest(
            @NotNull TestCaseRunStatus status,
            String securityOutcome,
            String functionalOutcome,
            @Min(0) Long latencyMs,
            JsonNode tokenUsage,
            String errorCode,
            JsonNode result
    ) {
    }

    public record CaseRun(
            UUID id,
            UUID testRunId,
            UUID testCaseId,
            int trialIndex,
            TestCaseRunStatus status,
            String securityOutcome,
            String functionalOutcome,
            String variantHash,
            Long latencyMs,
            JsonNode tokenUsage,
            String errorCode,
            JsonNode result
    ) {
    }
}
