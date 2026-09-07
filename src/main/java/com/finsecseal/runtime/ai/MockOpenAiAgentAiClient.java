package com.finsecseal.runtime.ai;

import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.attack.AttackVariant;
import com.finsecseal.runtime.ToolProposal;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import java.util.UUID;

/**
 * Lightweight mock Agent client that simulates an OpenAI-backed agent.
 * Appends simple ExecutionEvents for MODEL/TOOL proposals and responses.
 */
public class MockOpenAiAgentAiClient implements AgentAiClient {

    private final ObjectMapper objectMapper;
    private final ExecutionEventService eventService; // may be null in test fixtures

    public MockOpenAiAgentAiClient(ObjectMapper objectMapper, ExecutionEventService eventService) {
        this.objectMapper = objectMapper;
        this.eventService = eventService;
    }

    @Override
    public AgentTurnResponse propose(AgentTurnRequest request) {
        ObjectNode args = objectMapper.createObjectNode();
        args.put("note", "mock-proposal");
        args.set("attackVariant", objectMapper.valueToTree(request.attackVariant()));

        // Record a TOOL_PROPOSED execution event for traceability
        ExecutionEventDto.AppendRequest append = new ExecutionEventDto.AppendRequest(
                request.caseRunId(), request.traceId(), ExecutionEventType.TOOL_PROPOSED,
                "mock-tool", args, null, null, null, objectMapper.createObjectNode()
        );
        try {
            if (eventService != null) {
                eventService.append(request.runId(), append, "mock-agent");
            }
        } catch (Exception ignored) {
            // best-effort in test/mock scenarios
        }

        ToolProposal proposal = new ToolProposal("mock-tool", args);
        return new AgentTurnResponse("mock", "mock-model", "tool_call", proposal, 5L);
    }

    @Override
    public ToolResultDeliveryResponse deliverToolResult(ToolResultDeliveryRequest request) {
        // Append a TOOL_RESPONSE event with the supplied output
        ExecutionEventDto.AppendRequest append = new ExecutionEventDto.AppendRequest(
                request.caseRunId(), request.traceId(), ExecutionEventType.TOOL_RESPONSE,
                request.toolName(), null, request.toolOutput(), null, null, objectMapper.createObjectNode()
        );
        try {
            if (eventService != null) {
                eventService.append(request.runId(), append, "mock-agent");
            }
        } catch (Exception ignored) {
        }

        // Return a delivered response with a final action to finish the agent turn
        StatelessAgentStepClient.FinalResponseAction finalAction = new StatelessAgentStepClient.FinalResponseAction("done");
        return new ToolResultDeliveryResponse("mock", "mock-model", ToolResultDeliveryStatus.DELIVERED, finalAction, 10L);
    }
}
