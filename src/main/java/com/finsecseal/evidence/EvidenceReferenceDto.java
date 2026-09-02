package com.finsecseal.evidence;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

public final class EvidenceReferenceDto {

    private EvidenceReferenceDto() {
    }

    public record AppendRequest(
            @NotBlank @Pattern(regexp = "[A-Z_]+") @Size(max = 80) String ownerType,
            @NotNull UUID ownerId,
            @NotBlank @Pattern(regexp = "[A-Z0-9._:-]+") @Size(max = 80) String evidenceType,
            UUID sourceEventId,
            @NotNull JsonNode summary,
            Instant testedAt
    ) {
    }

    public record Reference(
            UUID id,
            UUID workspaceId,
            String ownerType,
            UUID ownerId,
            String evidenceType,
            UUID sourceEventId,
            String digest,
            JsonNode redactedSummary,
            Instant testedAt,
            Instant createdAt
    ) {
    }

    public record ListResponse(List<Reference> items) {
    }
}
