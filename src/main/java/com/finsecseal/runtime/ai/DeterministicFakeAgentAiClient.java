package com.finsecseal.runtime.ai;

import com.finsecseal.runtime.ToolProposal;

/** Deterministic test adapter. It is intentionally not registered as a production bean. */
public final class DeterministicFakeAgentAiClient implements AgentAiClient {

    @Override
    public AgentTurnResponse propose(AgentTurnRequest request) {
        long started = System.nanoTime();
        ToolProposal proposal = new ToolProposal(
                request.attackVariant().targetTool(),
                request.attackVariant().toolArguments().deepCopy()
        );
        long latencyMs = Math.max(0L, (System.nanoTime() - started) / 1_000_000L);
        return new AgentTurnResponse(
                "fake",
                "deterministic-baseline",
                "tool_call",
                proposal,
                latencyMs
        );
    }

    @Override
    public ToolResultDeliveryResponse deliverToolResult(ToolResultDeliveryRequest request) {
        long started = System.nanoTime();
        ToolResultDeliveryStatus status = request.toolOutput() != null && !request.toolOutput().isNull()
                ? ToolResultDeliveryStatus.DELIVERED
                : ToolResultDeliveryStatus.FAILED;
        long latencyMs = Math.max(0L, (System.nanoTime() - started) / 1_000_000L);
        return new ToolResultDeliveryResponse(
                "fake",
                "deterministic-baseline",
                status,
                latencyMs
        );
    }
}
