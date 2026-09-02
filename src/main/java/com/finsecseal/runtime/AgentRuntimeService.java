package com.finsecseal.runtime;

import com.finsecseal.attack.AttackSeed;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.runtime.ai.AgentAiClient;
import com.finsecseal.sandbox.SandboxExecutionContext;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Service
public class AgentRuntimeService {

    private final ObjectProvider<AgentAiClient> aiClientProvider;
    private final ExecutionEventService eventService;
    private final ObjectMapper objectMapper;

    public AgentRuntimeService(
            ObjectProvider<AgentAiClient> aiClientProvider,
            ExecutionEventService eventService,
            ObjectMapper objectMapper
    ) {
        this.aiClientProvider = aiClientProvider;
        this.eventService = eventService;
        this.objectMapper = objectMapper;
    }

    public RuntimeTurn proposeTool(
            SandboxExecutionContext context,
            AttackSeed attackSeed,
            String actorId
    ) {
        AgentAiClient aiClient = aiClientProvider.getIfAvailable();
        if (aiClient == null) {
            throw new BusinessException(ErrorCode.CONFIGURATION_ERROR, "Agent AI client is not configured");
        }

        ObjectNode requestMetadata = objectMapper.createObjectNode();
        requestMetadata.put("attackCategory", attackSeed.category());
        requestMetadata.put("caseKey", context.caseKey());
        requestMetadata.put("currentApplicantId", context.currentApplicantId());
        requestMetadata.put("targetTool", attackSeed.targetTool());
        eventService.append(
                context.runId(),
                new ExecutionEventDto.AppendRequest(
                        context.caseRunId(),
                        context.traceId(),
                        ExecutionEventType.MODEL_REQUEST,
                        null,
                        null,
                        null,
                        null,
                        "AGENT_TURN_REQUESTED",
                        requestMetadata
                ),
                actorId
        );

        AgentAiClient.AgentTurnResponse response = aiClient.propose(new AgentAiClient.AgentTurnRequest(
                context.runId(),
                context.caseRunId(),
                context.traceId(),
                context.caseKey(),
                context.currentApplicantId(),
                attackSeed
        ));
        if (response == null || response.proposal() == null
                || response.proposal().toolName() == null || response.proposal().arguments() == null) {
            throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, "AI client returned an invalid Tool Proposal");
        }

        ObjectNode modelResponse = objectMapper.createObjectNode();
        modelResponse.put("provider", response.provider());
        modelResponse.put("model", response.model());
        modelResponse.put("finishReason", response.finishReason());
        modelResponse.put("latencyMs", response.latencyMs());
        modelResponse.put("toolName", response.proposal().toolName());
        eventService.append(
                context.runId(),
                new ExecutionEventDto.AppendRequest(
                        context.caseRunId(),
                        context.traceId(),
                        ExecutionEventType.MODEL_RESPONSE,
                        null,
                        null,
                        modelResponse,
                        null,
                        "AGENT_TURN_COMPLETED",
                        objectMapper.createObjectNode()
                ),
                actorId
        );

        ExecutionEventDto.Event proposalEvent = eventService.append(
                context.runId(),
                new ExecutionEventDto.AppendRequest(
                        context.caseRunId(),
                        context.traceId(),
                        ExecutionEventType.TOOL_PROPOSED,
                        response.proposal().toolName(),
                        response.proposal().arguments(),
                        null,
                        null,
                        "STRUCTURED_TOOL_PROPOSAL",
                        objectMapper.createObjectNode()
                                .put("provider", response.provider())
                                .put("model", response.model())
                ),
                actorId
        );
        return new RuntimeTurn(response, proposalEvent);
    }

    public record RuntimeTurn(
            AgentAiClient.AgentTurnResponse aiResponse,
            ExecutionEventDto.Event proposalEvent
    ) {
    }
}
