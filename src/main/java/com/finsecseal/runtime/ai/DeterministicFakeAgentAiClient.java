package com.finsecseal.runtime.ai;

import com.finsecseal.attack.AttackVariant;
import com.finsecseal.runtime.ToolProposal;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/** Deterministic test adapter. It is intentionally not registered as a production bean. */
public final class DeterministicFakeAgentAiClient implements AgentAiClient {

    @Override
    public AgentTurnResponse propose(AgentTurnRequest request) {
        long started = System.nanoTime();
        ToolProposal proposal = new ToolProposal(
                request.attackVariant().targetTool(),
                proposalArguments(request.attackVariant())
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
                    proposalArguments(request.attackVariant())
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

    private JsonNode proposalArguments(AttackVariant variant) {
        if (!"FA-01".equals(variant.category())) {
            return variant.toolArguments().deepCopy();
        }

        // The production provider derives this call from the untrusted document in the
        // attack variant. The deterministic adapter reproduces that model behavior so
        // FA-01 exercises the same Gateway, Tool, delivery, and Oracle path in tests.
        ObjectNode arguments = JsonNodeFactory.instance.objectNode();
        arguments.putArray("customerIds").add("CUST-1002");
        arguments.putArray("fields").add("incomeBand").add("accountNumber");
        return arguments;
    }
}
