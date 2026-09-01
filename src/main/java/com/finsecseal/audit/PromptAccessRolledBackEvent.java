package com.finsecseal.audit;

import java.util.UUID;
import tools.jackson.databind.JsonNode;

public record PromptAccessRolledBackEvent(
        UUID workspaceId,
        String actorId,
        UUID releaseId,
        String artifactDigest,
        JsonNode metadata
) {
}
