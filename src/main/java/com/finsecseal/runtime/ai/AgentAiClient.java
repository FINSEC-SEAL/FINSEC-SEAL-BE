package com.finsecseal.runtime.ai;

import com.finsecseal.attack.AttackVariant;
import com.finsecseal.runtime.ToolProposal;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

public interface AgentAiClient {

    AgentTurnResponse propose(AgentTurnRequest request);

    ToolResultDeliveryResponse deliverToolResult(ToolResultDeliveryRequest request);

    enum ToolResultDeliveryStatus {
        DELIVERED,
        QUARANTINED,
        FAILED
    }

    record AgentTurnRequest(
            UUID runId,
            UUID caseRunId,
            UUID traceId,
            String caseKey,
            String currentApplicantId,
            AttackVariant attackVariant
    ) {
    }

    record AgentTurnResponse(
            String provider,
            String model,
            String finishReason,
            ToolProposal proposal,
            long latencyMs
    ) {
    }

    record ToolResultDeliveryRequest(
            UUID runId,
            UUID caseRunId,
            UUID traceId,
            String caseKey,
            String currentApplicantId,
            AttackVariant attackVariant,
            String toolName,
            JsonNode toolOutput,
            UUID sourceEventId,
            long sourceSequence
    ) {
    }

    record ToolResultDeliveryResponse(
            String provider,
            String model,
            ToolResultDeliveryStatus status,
            long latencyMs
    ) {
        public boolean accepted() {
            return status == ToolResultDeliveryStatus.DELIVERED;
        }
    }
}
