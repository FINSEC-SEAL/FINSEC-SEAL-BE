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
        return new AgentTurnResponse(
                "fake",
                "deterministic-baseline",
                "tool_call",
                proposal,
                elapsedMs(started)
        );
    }

    @Override
    public ToolResultDeliveryResponse deliverToolResult(ToolResultDeliveryRequest request) {
        long started = System.nanoTime();
        boolean delivered = request.toolOutput() != null && !request.toolOutput().isNull();
        ToolResultDeliveryStatus status = delivered
                ? ToolResultDeliveryStatus.DELIVERED
                : ToolResultDeliveryStatus.FAILED;
        AgentAction nextAction = delivered
                ? new FinalResponseAction("Tool result received; agent step completed.")
                : null;

        return new ToolResultDeliveryResponse(
                "fake",
                "deterministic-baseline",
                status,
                nextAction,
                elapsedMs(started)
        );
    }

    @Override
    public AgentStepResponse executeStep(AgentStepRequest request) {
        long started = System.nanoTime();

        if (request.previousToolResult() == null) {
            ToolProposal proposal = new ToolProposal(
                    request.attackVariant().targetTool(),
                    request.attackVariant().toolArguments().deepCopy()
            );
            return new AgentStepResponse(
                    "fake",
                    "deterministic-baseline",
                    "tool_call",
                    new ToolProposalAction(proposal),
                    elapsedMs(started)
            );
        }

        return new AgentStepResponse(
                "fake",
                "deterministic-baseline",
                "stop",
                new FinalResponseAction("Tool result received; agent step completed."),
                elapsedMs(started)
        );
    }

    private long elapsedMs(long started) {
        return Math.max(0L, (System.nanoTime() - started) / 1_000_000L);
    }
}
