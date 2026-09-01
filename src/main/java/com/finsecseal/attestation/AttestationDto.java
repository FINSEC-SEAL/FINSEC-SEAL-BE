package com.finsecseal.attestation;

import java.time.Instant;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

public final class AttestationDto {

    private AttestationDto() {
    }

    public record View(
            UUID id,
            UUID releaseDecisionId,
            JsonNode document,
            String documentHash,
            Instant generatedAt,
            String disclaimerVersion,
            boolean stale,
            JsonNode invalidation
    ) {
    }

    public record Export(
            byte[] content,
            String contentType,
            String fileName,
            String documentHash,
            boolean stale
    ) {
    }
}
