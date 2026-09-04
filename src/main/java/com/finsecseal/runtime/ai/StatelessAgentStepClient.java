package com.finsecseal.runtime.ai;

import com.finsecseal.attack.AttackVariant;
import com.finsecseal.runtime.ToolProposal;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

public interface StatelessAgentStepClient {

    AgentStepResponse executeStep(AgentStepRequest request);

    record AgentStepRequest(
            UUID runId,
            UUID caseRunId,
            UUID traceId,
            String caseKey,
            String currentApplicantId,
            AttackVariant attackVariant,
            PreviousToolResult previousToolResult
    ) {
    }

    record PreviousToolResult(
            String toolName,
            JsonNode output,
            UUID sourceEventId,
            long sourceSequence
    ) {
    }

    sealed interface AgentAction permits ToolProposalAction, FinalResponseAction {
    }

    record ToolProposalAction(ToolProposal proposal) implements AgentAction {
    }

    record FinalResponseAction(String content) implements AgentAction {
    }

    record AgentStepResponse(
            String provider,
            String model,
            String finishReason,
            AgentAction action,
            long latencyMs
    ) {
    }
}
