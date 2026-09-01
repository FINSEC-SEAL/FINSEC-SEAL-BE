package com.finsecseal.audit;

import java.time.Instant;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

public final class AuditDto {

    private AuditDto() {
    }

    public record Record(
            UUID id,
            UUID workspaceId,
            String actorId,
            String action,
            String resourceType,
            UUID resourceId,
            String beforeDigest,
            String afterDigest,
            JsonNode metadata,
            Instant occurredAt
    ) {
    }
}
