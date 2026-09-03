package com.finsecseal.assurance;

import com.finsecseal.common.domain.DecisionValue;
import java.time.Instant;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

public final class ReleaseAssuranceDto {

    private ReleaseAssuranceDto() {
    }

    public record MetricsView(UUID releaseId, ReleaseMetrics metrics) {
    }

    public record DecisionProposal(
            UUID releaseId,
            DecisionValue proposedDecision,
            String gatePolicyVersion,
            String inputDigest,
            JsonNode inputSnapshot
    ) {
    }

    public record ConfirmRequest(DecisionValue decision, String comment) {
    }

    public record DecisionView(
            UUID id,
            UUID releaseId,
            DecisionValue decision,
            String gatePolicyVersion,
            String inputDigest,
            Instant proposedAt,
            String confirmedBy,
            Instant confirmedAt
    ) {
    }
}
