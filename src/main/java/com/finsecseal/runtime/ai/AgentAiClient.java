package com.finsecseal.runtime.ai;

import com.finsecseal.attack.AttackSeed;
import com.finsecseal.runtime.ToolProposal;
import java.util.UUID;

public interface AgentAiClient {

    AgentTurnResponse propose(AgentTurnRequest request);

    record AgentTurnRequest(
            UUID runId,
            UUID caseRunId,
            UUID traceId,
            String caseKey,
            String currentApplicantId,
            AttackSeed attackSeed
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
}
