package com.finsecseal.oracle.application;

import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleReasonCode;
import com.finsecseal.oracle.domain.OracleType;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

public final class OracleResultDto {

    private OracleResultDto() {
    }

    public record View(
            UUID id,
            UUID runId,
            UUID testCaseRunId,
            UUID sourceEventId,
            OracleType oracleType,
            String oracleVersion,
            OracleOutcome outcome,
            OracleReasonCode reasonCode,
            String invariantId,
            JsonNode evidence,
            String evidenceDigest,
            Instant evaluatedAt,
            Instant createdAt
    ) {
    }

    public record ListResponse(List<View> items) {
    }
}
