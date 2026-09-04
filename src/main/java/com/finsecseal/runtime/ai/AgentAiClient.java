package com.finsecseal.runtime.ai;

import com.finsecseal.attack.AttackVariant;
import com.finsecseal.runtime.ToolProposal;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

/**
 * Backend-facing Agent contract.
 *
 * <p>The canonical state-machine is the stateless executeStep contract inherited from
 * StatelessAgentStepClient. The legacy propose/deliver methods remain temporarily for
 * existing FA-02/FA-03 orchestration, but Tool-result delivery must preserve the next
 * Agent action.</p>
 */
public interface AgentAiClient extends StatelessAgentStepClient {

    AgentTurnResponse propose(AgentTurnRequest request);

    ToolResultDeliveryResponse deliverToolResult(ToolResultDeliveryRequest request);

    /**
     * Compatibility bridge for existing test fixtures.
     * Production stateless clients should override executeStep directly.
     */
    @Override
    default AgentStepResponse executeStep(AgentStepRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Agent step request is required");
        }

        if (request.previousToolResult() == null) {
            AgentTurnResponse response = propose(new AgentTurnRequest(
                    request.runId(),
                    request.caseRunId(),
                    request.traceId(),
                    request.caseKey(),
                    request.currentApplicantId(),
                    request.attackVariant()
            ));
            if (response == null || response.proposal() == null) {
                throw new IllegalStateException("Initial Agent step must produce a Tool Proposal");
            }
            return new AgentStepResponse(
                    response.provider(),
                    response.model(),
                    response.finishReason(),
                    new ToolProposalAction(response.proposal()),
                    response.latencyMs()
            );
        }

        PreviousToolResult previous = request.previousToolResult();
        ToolResultDeliveryResponse response = deliverToolResult(new ToolResultDeliveryRequest(
                request.runId(),
                request.caseRunId(),
                request.traceId(),
                request.caseKey(),
                request.currentApplicantId(),
                request.attackVariant(),
                previous.toolName(),
                previous.output(),
                previous.sourceEventId(),
                previous.sourceSequence()
        ));

        if (response == null
                || response.status() != ToolResultDeliveryStatus.DELIVERED
                || response.nextAction() == null) {
            throw new IllegalStateException(
                    "Compatibility executeStep requires a delivered Tool result with a next Agent action"
            );
        }

        String finishReason = response.nextAction() instanceof ToolProposalAction
                ? "tool_call"
                : "stop";

        return new AgentStepResponse(
                response.provider(),
                response.model(),
                finishReason,
                response.nextAction(),
                response.latencyMs()
        );
    }

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
            AgentAction nextAction,
            long latencyMs
    ) {
        /**
         * Source-compatible constructor for quarantine/failure fixtures that intentionally
         * do not produce a next Agent action.
         */
        public ToolResultDeliveryResponse(
                String provider,
                String model,
                ToolResultDeliveryStatus status,
                long latencyMs
        ) {
            this(provider, model, status, null, latencyMs);
        }

        public boolean accepted() {
            return status == ToolResultDeliveryStatus.DELIVERED;
        }
    }
}
