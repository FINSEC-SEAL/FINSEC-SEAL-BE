package com.finsecseal.runtime;

import com.finsecseal.attack.AttackVariant;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.runtime.ai.AgentAiClient;
import com.finsecseal.runtime.ai.AgentAiClient.ToolResultDeliveryStatus;
import com.finsecseal.runtime.ai.StatelessAgentStepClient.AgentAction;
import com.finsecseal.runtime.ai.StatelessAgentStepClient.FinalResponseAction;
import com.finsecseal.runtime.ai.StatelessAgentStepClient.ToolProposalAction;
import com.finsecseal.sandbox.SandboxExecutionContext;
import java.util.UUID;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Service
public class AgentRuntimeService {

    private final ObjectProvider<AgentAiClient> aiClientProvider;
    private final ExecutionEventService eventService;
    private final ObjectMapper objectMapper;
    private final ToolProposalValidator proposalValidator;

    public AgentRuntimeService(
            ObjectProvider<AgentAiClient> aiClientProvider,
            ExecutionEventService eventService,
            ObjectMapper objectMapper,
            ToolProposalValidator proposalValidator
    ) {
        this.aiClientProvider = aiClientProvider;
        this.eventService = eventService;
        this.objectMapper = objectMapper;
        this.proposalValidator = proposalValidator;
    }

    public RuntimeTurn proposeTool(
            SandboxExecutionContext context,
            AttackVariant attackVariant,
            String actorId
    ) {
        AgentAiClient aiClient = requireClient();

        ObjectNode requestMetadata = objectMapper.createObjectNode();
        requestMetadata.put("turnType", "TOOL_PROPOSAL");
        requestMetadata.put("attackCategory", attackVariant.category());
        requestMetadata.put("variantHash", attackVariant.variantHash());
        requestMetadata.put("caseKey", context.caseKey());
        requestMetadata.put("currentApplicantId", context.currentApplicantId());
        requestMetadata.put("targetTool", attackVariant.targetTool());
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
                attackVariant
        ));
        if (response == null) {
            throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, "AI client returned an empty response");
        }
        ToolProposal proposal = proposalValidator.validate(response.proposal());

        ObjectNode modelResponse = objectMapper.createObjectNode();
        modelResponse.put("provider", response.provider());
        modelResponse.put("model", response.model());
        modelResponse.put("finishReason", response.finishReason());
        modelResponse.put("latencyMs", response.latencyMs());
        modelResponse.put("toolName", proposal.toolName());
        modelResponse.put("variantHash", attackVariant.variantHash());
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
                        objectMapper.createObjectNode().put("turnType", "TOOL_PROPOSAL")
                ),
                actorId
        );

        ExecutionEventDto.Event proposalEvent = eventService.append(
                context.runId(),
                new ExecutionEventDto.AppendRequest(
                        context.caseRunId(),
                        context.traceId(),
                        ExecutionEventType.TOOL_PROPOSED,
                        proposal.toolName(),
                        proposal.arguments(),
                        null,
                        null,
                        "STRUCTURED_TOOL_PROPOSAL",
                        objectMapper.createObjectNode()
                                .put("provider", response.provider())
                                .put("model", response.model())
                                .put("variantHash", attackVariant.variantHash())
                ),
                actorId
        );
        return new RuntimeTurn(
                new AgentAiClient.AgentTurnResponse(
                        response.provider(),
                        response.model(),
                        response.finishReason(),
                        proposal,
                        response.latencyMs()
                ),
                proposalEvent
        );
    }

    public ToolProposal recordFollowUpToolProposal(
            SandboxExecutionContext context,
            AttackVariant attackVariant,
            ToolProposal proposal,
            UUID sourceModelResponseEventId,
            long sourceModelResponseSequence,
            String actorId
    ) {
        if (sourceModelResponseEventId == null || sourceModelResponseSequence <= 0) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Follow-up Tool Proposal is missing its source MODEL_RESPONSE evidence"
            );
        }

        ToolProposal validatedProposal = proposalValidator.validate(proposal);

        eventService.append(
                context.runId(),
                new ExecutionEventDto.AppendRequest(
                        context.caseRunId(),
                        context.traceId(),
                        ExecutionEventType.TOOL_PROPOSED,
                        validatedProposal.toolName(),
                        validatedProposal.arguments(),
                        null,
                        null,
                        "STRUCTURED_TOOL_PROPOSAL",
                        objectMapper.createObjectNode()
                                .put("turnType", "TOOL_RESULT_DELIVERY")
                                .put("variantHash", attackVariant.variantHash())
                                .put("sourceModelResponseEventId", sourceModelResponseEventId.toString())
                                .put("sourceModelResponseSequence", sourceModelResponseSequence)
                ),
                actorId
        );

        return validatedProposal;
    }

    public DeliveryReceipt deliverToolResult(
            SandboxExecutionContext context,
            AttackVariant attackVariant,
            String toolName,
            JsonNode toolOutput,
            UUID sourceEventId,
            long sourceSequence,
            String actorId
    ) {
        AgentAiClient aiClient = requireClient();

        ObjectNode requestMetadata = objectMapper.createObjectNode();
        requestMetadata.put("turnType", "TOOL_RESULT_DELIVERY");
        requestMetadata.put("sourceEventId", sourceEventId.toString());
        requestMetadata.put("sourceSequence", sourceSequence);
        requestMetadata.put("variantHash", attackVariant.variantHash());
        eventService.append(
                context.runId(),
                new ExecutionEventDto.AppendRequest(
                        context.caseRunId(),
                        context.traceId(),
                        ExecutionEventType.MODEL_REQUEST,
                        toolName,
                        toolOutput,
                        null,
                        null,
                        "AGENT_TOOL_RESULT_DELIVERY_REQUESTED",
                        requestMetadata
                ),
                actorId
        );

        AgentAiClient.ToolResultDeliveryResponse response = aiClient.deliverToolResult(
                new AgentAiClient.ToolResultDeliveryRequest(
                        context.runId(),
                        context.caseRunId(),
                        context.traceId(),
                        context.caseKey(),
                        context.currentApplicantId(),
                        attackVariant,
                        toolName,
                        toolOutput.deepCopy(),
                        sourceEventId,
                        sourceSequence
                )
        );

        if (response == null || response.status() == null) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Agent Tool Response delivery returned an invalid result"
            );
        }
        if (response.status() == ToolResultDeliveryStatus.FAILED) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Agent Tool Response delivery failed"
            );
        }
        if (response.status() == ToolResultDeliveryStatus.DELIVERED && response.nextAction() == null) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Delivered Agent Tool Response is missing the next Agent action"
            );
        }

        boolean delivered = response.status() == ToolResultDeliveryStatus.DELIVERED;
        ObjectNode output = objectMapper.createObjectNode();
        output.put("provider", response.provider());
        output.put("model", response.model());
        output.put("accepted", delivered);
        output.put("deliveryStatus", response.status().name());
        output.put("latencyMs", response.latencyMs());
        output.put("sourceEventId", sourceEventId.toString());
        output.put("sourceSequence", sourceSequence);

        if (response.nextAction() instanceof ToolProposalAction) {
            output.put("nextActionType", "TOOL_PROPOSAL");
        } else if (response.nextAction() instanceof FinalResponseAction) {
            output.put("nextActionType", "FINAL_RESPONSE");
        }

        String reasonCode = delivered
                ? "AGENT_TOOL_RESULT_DELIVERED"
                : "AGENT_TOOL_RESULT_QUARANTINED";
        ExecutionEventDto.Event deliveryEvent = eventService.append(
                context.runId(),
                new ExecutionEventDto.AppendRequest(
                        context.caseRunId(),
                        context.traceId(),
                        ExecutionEventType.MODEL_RESPONSE,
                        toolName,
                        null,
                        output,
                        null,
                        reasonCode,
                        objectMapper.createObjectNode()
                                .put("turnType", "TOOL_RESULT_DELIVERY")
                                .put("variantHash", attackVariant.variantHash())
                ),
                actorId
        );

        return new DeliveryReceipt(
                delivered,
                response.status(),
                deliveryEvent.eventId(),
                deliveryEvent.sequence(),
                response.nextAction(),
                response.latencyMs()
        );
    }

    private AgentAiClient requireClient() {
        AgentAiClient aiClient = aiClientProvider.getIfAvailable();
        if (aiClient == null) {
            throw new BusinessException(ErrorCode.CONFIGURATION_ERROR, "Agent AI client is not configured");
        }
        return aiClient;
    }

    public record RuntimeTurn(
            AgentAiClient.AgentTurnResponse aiResponse,
            ExecutionEventDto.Event proposalEvent
    ) {
    }

    public record DeliveryReceipt(
            boolean deliveredToAgent,
            ToolResultDeliveryStatus status,
            UUID deliveryEventId,
            long deliveryEventSequence,
            AgentAction nextAction,
            long latencyMs
    ) {
        /** Source-compatible constructor for existing callers. */
        public DeliveryReceipt(
                boolean deliveredToAgent,
                ToolResultDeliveryStatus status,
                UUID deliveryEventId,
                long deliveryEventSequence,
                long latencyMs
        ) {
            this(
                    deliveredToAgent,
                    status,
                    deliveryEventId,
                    deliveryEventSequence,
                    null,
                    latencyMs
            );
        }

        public static DeliveryReceipt notDelivered() {
            return new DeliveryReceipt(false, null, null, 0L, null, 0L);
        }
    }
}
