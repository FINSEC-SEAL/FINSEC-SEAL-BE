package com.finsecseal.assurance;

import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleReasonCode;
import com.finsecseal.oracle.domain.OracleType;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

public final class ReplayComparisonDto {

    private ReplayComparisonDto() {
    }

    public record Detail(
            UUID replayRunId,
            UUID replayLinkId,
            UUID findingId,
            UUID releaseId,
            String category,
            String severity,
            boolean comparable,
            List<String> mismatchReasons,
            Side baseline,
            Side replay,
            Difference difference
    ) {
        public Detail {
            mismatchReasons = List.copyOf(mismatchReasons);
        }
    }

    public record Side(
            UUID runId,
            UUID caseRunId,
            TestRunMode mode,
            TestRunStatus runStatus,
            TestCaseRunStatus caseStatus,
            String securityOutcome,
            String functionalOutcome,
            List<EventEvidence> policyDecisions,
            List<EventEvidence> apiResponses,
            List<EventEvidence> stateChanges,
            List<OracleSummary> oracleResults
    ) {
        public Side {
            policyDecisions = List.copyOf(policyDecisions);
            apiResponses = List.copyOf(apiResponses);
            stateChanges = List.copyOf(stateChanges);
            oracleResults = List.copyOf(oracleResults);
        }
    }

    public record EventEvidence(
            UUID eventId,
            ExecutionEventType eventType,
            String toolName,
            JsonNode value,
            String payloadDigest,
            String reasonCode,
            Instant occurredAt
    ) {
        public EventEvidence {
            value = value.deepCopy();
        }
    }

    public record OracleSummary(
            UUID id,
            UUID sourceEventId,
            OracleType oracleType,
            String oracleVersion,
            OracleOutcome outcome,
            OracleReasonCode reasonCode,
            String invariantId,
            String evidenceDigest,
            Instant evaluatedAt
    ) {
    }

    public record Difference(
            boolean policyDecisionChanged,
            boolean apiResponseChanged,
            boolean stateEffectChanged,
            boolean oracleOutcomeChanged,
            boolean attackMitigated
    ) {
    }
}
