package com.finsecseal.runtime.ai;

import com.finsecseal.runtime.ToolProposal;

/** Deterministic test adapter. It is intentionally not registered as a production bean. */
public final class DeterministicFakeAgentAiClient implements AgentAiClient {

    @Override
    public AgentTurnResponse propose(AgentTurnRequest request) {
        long started = System.nanoTime();
        ToolProposal proposal = new ToolProposal(
                request.attackSeed().targetTool(),
                request.attackSeed().toolArguments().deepCopy()
        );
        long latencyMs = Math.max(0L, (System.nanoTime() - started) / 1_000_000L);
        return new AgentTurnResponse(
                "fake",
                "deterministic-fa02",
                "tool_call",
                proposal,
                latencyMs
        );
    }
}
