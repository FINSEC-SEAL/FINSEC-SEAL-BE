package com.finsecseal.release;

import tools.jackson.databind.JsonNode;
import com.finsecseal.common.domain.ReleaseLifecycleState;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class ReleaseDto {

    private ReleaseDto() {
    }

    public record Response(
            UUID id,
            UUID agentId,
            String version,
            String businessPurpose,
            String manifestSchemaVersion,
            String agentArtifactFingerprint,
            String releaseFingerprint,
            String safetyContractHash,
            ReleaseLifecycleState lifecycleState,
            ReleaseLifecycleState effectiveStatus,
            JsonNode revalidationReason,
            Instant analyzedAt,
            Instant lastTestedAt,
            Instant createdAt,
            Instant updatedAt
    ) {
        public static Response from(AgentReleaseEntity entity) {
            return new Response(
                    entity.getId(),
                    entity.getAgentId(),
                    entity.getVersion(),
                    entity.getBusinessPurpose(),
                    entity.getManifestSchemaVersion(),
                    entity.getAgentArtifactFingerprint(),
                    entity.getReleaseFingerprint(),
                    entity.getSafetyContractHash(),
                    entity.getLifecycleState(),
                    entity.getEffectiveStatus(),
                    entity.getRevalidationReasonJson(),
                    entity.getAnalyzedAt(),
                    entity.getLastTestedAt(),
                    entity.getCreatedAt(),
                    entity.getUpdatedAt()
            );
        }
    }

    public record FingerprintResponse(
            String canonicalizationVersion,
            String agentArtifactFingerprint,
            String releaseFingerprint,
            String safetyContractHash,
            Map<String, String> components
    ) {
    }

    public record ValidationResponse(boolean valid, List<ManifestValidationService.Issue> issues) {
    }

    public record DiffItem(
            String component,
            List<String> jsonPointers,
            String oldDigest,
            String newDigest,
            boolean changed,
            String redactedSummary
    ) {
    }

    public record DiffResponse(UUID against, UUID releaseId, List<DiffItem> components, boolean meaningfulChange) {
    }
}
