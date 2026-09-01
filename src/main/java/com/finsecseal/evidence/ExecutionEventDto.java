package com.finsecseal.evidence;

import com.finsecseal.common.domain.ExecutionEventType;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

public final class ExecutionEventDto {

    private ExecutionEventDto() {
    }

    public record AppendRequest(
            UUID testCaseRunId,
            @NotNull UUID traceId,
            @NotNull ExecutionEventType eventType,
            @Size(max = 100) String toolName,
            JsonNode input,
            JsonNode output,
            JsonNode policyDecision,
            @Size(max = 100) String reasonCode,
            JsonNode metadata
    ) {
    }

    public record Event(
            String schemaVersion,
            UUID eventId,
            UUID traceId,
            UUID runId,
            UUID testCaseRunId,
            long sequence,
            Instant occurredAt,
            ExecutionEventType eventType,
            String toolName,
            JsonNode input,
            JsonNode output,
            String payloadDigest,
            JsonNode policyDecision,
            String reasonCode,
            JsonNode metadata,
            String prevEventHash,
            String eventHash
    ) {
    }

    public record History(List<Event> items, long headSequence, Long nextCursor) {
    }

    public record ChainVerification(
            UUID runId,
            boolean valid,
            long eventCount,
            Long firstInvalidSequence,
            String headHash
    ) {
    }

    record RunHead(UUID workspaceId, String status, long sequence, String hash, ExecutionEventType eventType) {
    }
}
