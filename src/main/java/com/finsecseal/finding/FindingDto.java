package com.finsecseal.finding;

import com.finsecseal.oracle.application.OracleResultDto;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

public final class FindingDto {

    private FindingDto() {
    }

    public record View(
            UUID id,
            UUID releaseId,
            UUID sourceOracleResultId,
            String category,
            String severity,
            String title,
            String status,
            String violatedInvariant,
            JsonNode rootCause,
            String findingGroupKey,
            UUID firstSeenRunId,
            UUID latestSeenRunId,
            Instant createdAt,
            Instant updatedAt
    ) {
    }

    public record ListResponse(List<View> items) {
    }

    public record Detail(
            View finding,
            OracleResultDto.View oracleResult,
            List<View> relatedFindings
    ) {
        public Detail {
            relatedFindings = List.copyOf(relatedFindings);
        }
    }

    public record TriageRequest(String comment) {
    }
}
