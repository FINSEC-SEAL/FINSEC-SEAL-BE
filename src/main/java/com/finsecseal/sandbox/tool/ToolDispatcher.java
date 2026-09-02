package com.finsecseal.sandbox.tool;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.runtime.ToolProposalValidator;
import com.finsecseal.sandbox.SandboxExecutionContext;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Service
public class ToolDispatcher {

    private final Map<String, ToolAdapter> adapters;
    private final List<ToolExecutionPolicy> policies;
    private final ExecutionEventService eventService;
    private final ObjectMapper objectMapper;
    private final ToolProposalValidator proposalValidator;

    public ToolDispatcher(
            List<ToolAdapter> adapters,
            List<ToolExecutionPolicy> policies,
            ExecutionEventService eventService,
            ObjectMapper objectMapper,
            ToolProposalValidator proposalValidator
    ) {
        this.adapters = indexAdapters(adapters);
        this.policies = List.copyOf(policies);
        this.eventService = eventService;
        this.objectMapper = objectMapper;
        this.proposalValidator = proposalValidator;
    }

    public DispatchResult dispatch(
            SandboxExecutionContext context,
            ToolProposal proposal,
            String actorId
    ) {
        ToolProposal validated = proposalValidator.validate(proposal);
        ToolAdapter adapter = requireAdapter(validated.toolName());
        ToolExecutionPolicy policy = requirePolicy(context);
        ToolExecutionPolicy.PolicyDecision decision = policy.evaluate(context, validated);

        ObjectNode policyJson = objectMapper.createObjectNode();
        policyJson.put("allowed", decision.allowed());
        policyJson.put("reasonCode", decision.reasonCode());
        ExecutionEventDto.Event policyEvent = eventService.append(
                context.runId(),
                new ExecutionEventDto.AppendRequest(
                        context.caseRunId(),
                        context.traceId(),
                        ExecutionEventType.POLICY_EVALUATED,
                        validated.toolName(),
                        null,
                        null,
                        policyJson,
                        decision.reasonCode(),
                        objectMapper.createObjectNode().put("mode", context.mode().name())
                ),
                actorId
        );

        if (!decision.allowed()) {
            return new DispatchResult(decision, policyEvent, null, null, null);
        }

        ExecutionEventDto.Event requestEvent = eventService.append(
                context.runId(),
                new ExecutionEventDto.AppendRequest(
                        context.caseRunId(),
                        context.traceId(),
                        ExecutionEventType.TOOL_REQUEST,
                        validated.toolName(),
                        validated.arguments(),
                        null,
                        null,
                        null,
                        objectMapper.createObjectNode()
                ),
                actorId
        );

        ToolAdapter.ToolExecutionResult execution = adapter.execute(context, validated.arguments());
        ObjectNode responseMetadata = objectMapper.createObjectNode();
        responseMetadata.put("deliveredToAgent", false);
        responseMetadata.put("deliveryState", "PENDING");
        responseMetadata.put("stateChanged", execution.stateChanged());
        ExecutionEventDto.Event responseEvent = eventService.append(
                context.runId(),
                new ExecutionEventDto.AppendRequest(
                        context.caseRunId(),
                        context.traceId(),
                        ExecutionEventType.TOOL_RESPONSE,
                        validated.toolName(),
                        null,
                        execution.output(),
                        null,
                        "TOOL_EXECUTED",
                        responseMetadata
                ),
                actorId
        );
        return new DispatchResult(decision, policyEvent, requestEvent, responseEvent, execution);
    }

    private ToolAdapter requireAdapter(String toolName) {
        ToolAdapter adapter = adapters.get(toolName);
        if (adapter == null) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "Unknown tool proposal: " + toolName);
        }
        return adapter;
    }

    private ToolExecutionPolicy requirePolicy(SandboxExecutionContext context) {
        List<ToolExecutionPolicy> matches = policies.stream()
                .filter(policy -> policy.supports(context.mode()))
                .toList();
        if (matches.size() != 1) {
            throw new BusinessException(
                    ErrorCode.CONFIGURATION_ERROR,
                    "Exactly one ToolExecutionPolicy must support mode " + context.mode()
            );
        }
        return matches.getFirst();
    }

    private Map<String, ToolAdapter> indexAdapters(List<ToolAdapter> adapters) {
        Map<String, ToolAdapter> indexed = new HashMap<>();
        for (ToolAdapter adapter : adapters) {
            ToolAdapter previous = indexed.put(adapter.toolName(), adapter);
            if (previous != null) {
                throw new IllegalStateException("Duplicate ToolAdapter for " + adapter.toolName());
            }
        }
        return Map.copyOf(indexed);
    }

    public record DispatchResult(
            ToolExecutionPolicy.PolicyDecision policyDecision,
            ExecutionEventDto.Event policyEvent,
            ExecutionEventDto.Event requestEvent,
            ExecutionEventDto.Event responseEvent,
            ToolAdapter.ToolExecutionResult execution
    ) {
        public boolean toolInvoked() {
            return responseEvent != null;
        }
    }
}
