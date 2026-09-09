package com.finsecseal.assurance;

import com.finsecseal.common.domain.DecisionValue;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

public final class ReleaseAssuranceDto {

    private ReleaseAssuranceDto() {
    }

    public record MetricsView(UUID releaseId, ReleaseMetrics metrics, ReplaySummary replaySummary) {
    }

    public record ReplaySummary(
            int totalCount,
            int comparableCount,
            int nonComparableCount,
            boolean evidenceComplete,
            List<ReplayComparison> items
    ) {
        public ReplaySummary {
            items = List.copyOf(items);
        }
    }

    public record ReplayComparison(
            UUID baselineRunId,
            UUID replayRunId,
            String category,
            boolean comparable,
            List<String> mismatchReasons
    ) {
        public ReplayComparison {
            mismatchReasons = List.copyOf(mismatchReasons);
        }
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

    public record DecisionDetail(
            DecisionView decision,
            JsonNode inputSnapshot,
            boolean invalidated,
            JsonNode invalidation
    ) {
    }
}
