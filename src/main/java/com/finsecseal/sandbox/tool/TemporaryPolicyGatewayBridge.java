package com.finsecseal.sandbox.tool;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.runtime.ToolInvocation;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.sandbox.SandboxExecutionContext;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Component
public final class TemporaryPolicyGatewayBridge implements PolicyGateway {

    private final Map<String, ToolAdapter> adapters;
    private final List<ToolExecutionPolicy> policies;
    private final ExecutionEventService eventService;
    private final ObjectMapper objectMapper;
    private final StateChangingToolExecutionService stateChangingToolExecutionService;

    public TemporaryPolicyGatewayBridge(
            List<ToolAdapter> adapters,
            List<ToolExecutionPolicy> policies,
            ExecutionEventService eventService,
            ObjectMapper objectMapper
    ) {
        this(
                adapters,
                policies,
                eventService,
                objectMapper,
                null
        );
    }

    @Autowired
    public TemporaryPolicyGatewayBridge(
            List<ToolAdapter> adapters,
            List<ToolExecutionPolicy> policies,
            ExecutionEventService eventService,
            ObjectMapper objectMapper,
            StateChangingToolExecutionService stateChangingToolExecutionService
    ) {
        this.adapters = indexAdapters(adapters);
        this.policies = List.copyOf(policies);
        this.eventService = eventService;
        this.objectMapper = objectMapper;
        this.stateChangingToolExecutionService =
                stateChangingToolExecutionService;
    }

    @Override
    public GatewayResult invoke(
            SandboxExecutionContext context,
            ToolInvocation invocation,
            String actorId
    ) {
        if (invocation == null) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Policy Gateway requires Spring-owned Tool invocation identity"
            );
        }
        return invokeInternal(
                context,
                invocation.proposal(),
                invocation,
                actorId
        );
    }

    @Override
    public GatewayResult invoke(
            SandboxExecutionContext context,
            ToolProposal proposal,
            String actorId
    ) {
        return invokeInternal(
                context,
                proposal,
                null,
                actorId
        );
    }

    private GatewayResult invokeInternal(
            SandboxExecutionContext context,
            ToolProposal proposal,
            ToolInvocation invocation,
            String actorId
    ) {
        requireBaselineMode(context);

        ToolAdapter adapter = requireAdapter(proposal.toolName());

        if (adapter.effect() == ToolEffect.STATE_CHANGING
                && invocation == null) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "State-changing Tool requires Spring-owned invocation identity"
            );
        }

        ToolExecutionPolicy policy = requirePolicy(context);
        ToolExecutionPolicy.PolicyDecision legacyDecision =
                policy.evaluate(context, proposal);

        PolicyDecision decision = new PolicyDecision(
                legacyDecision.allowed(),
                legacyDecision.reasonCode()
        );

        ObjectNode policyJson = objectMapper.createObjectNode();
        policyJson.put("allowed", decision.allowed());
        policyJson.put("reasonCode", decision.reasonCode());

        ExecutionEventDto.Event policyEvent = eventService.append(
                context.runId(),
                new ExecutionEventDto.AppendRequest(
                        context.caseRunId(),
                        context.traceId(),
                        ExecutionEventType.POLICY_EVALUATED,
                        proposal.toolName(),
                        null,
                        null,
                        policyJson,
                        decision.reasonCode(),
                        objectMapper.createObjectNode()
                                .put("mode", context.mode().name())
                ),
                actorId
        );

        if (!decision.allowed()) {
            return new GatewayResult(
                    decision,
                    policyEvent,
                    null,
                    null,
                    null
            );
        }

        if (invocation != null
                && adapter.effect() == ToolEffect.STATE_CHANGING) {
            if (stateChangingToolExecutionService == null) {
                throw new BusinessException(
                        ErrorCode.CONFIGURATION_ERROR,
                        "State-changing Tool invocation requires the common idempotent executor"
                );
            }

            StateChangingToolExecutionService.Execution execution =
                    stateChangingToolExecutionService.execute(
                            context,
                            invocation,
                            adapter,
                            actorId
                    );

            return new GatewayResult(
                    decision,
                    policyEvent,
                    execution.requestEvent(),
                    execution.responseEvent(),
                    execution.result()
            );
        }

        ExecutionEventDto.Event requestEvent = eventService.append(
                context.runId(),
                new ExecutionEventDto.AppendRequest(
                        context.caseRunId(),
                        context.traceId(),
                        ExecutionEventType.TOOL_REQUEST,
                        proposal.toolName(),
                        proposal.arguments(),
                        null,
                        null,
                        null,
                        objectMapper.createObjectNode()
                ),
                actorId
        );

        ToolAdapter.ToolExecutionResult execution =
                adapter.execute(context, proposal.arguments());

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
                        proposal.toolName(),
                        null,
                        execution.output(),
                        null,
                        "TOOL_EXECUTED",
                        responseMetadata
                ),
                actorId
        );

        if (execution.stateChanged()) {
            ObjectNode stateMetadata = objectMapper.createObjectNode();
            stateMetadata.put("stateChanged", true);
            stateMetadata.put(
                    "sourceToolResponseEventId",
                    responseEvent.eventId().toString()
            );

            eventService.append(
                    context.runId(),
                    new ExecutionEventDto.AppendRequest(
                            context.caseRunId(),
                            context.traceId(),
                            ExecutionEventType.SANDBOX_STATE_CHANGED,
                            proposal.toolName(),
                            null,
                            null,
                            null,
                            "SANDBOX_STATE_CHANGED",
                            stateMetadata
                    ),
                    actorId
            );
        }

        return new GatewayResult(
                decision,
                policyEvent,
                requestEvent,
                responseEvent,
                execution
        );
    }

    private void requireBaselineMode(SandboxExecutionContext context) {
        if (context.mode() != TestRunMode.BASELINE) {
            throw new BusinessException(
                    ErrorCode.CONFIGURATION_ERROR,
                    "Temporary Policy Gateway only supports BASELINE"
            );
        }
    }

    private ToolAdapter requireAdapter(String toolName) {
        ToolAdapter adapter = adapters.get(toolName);
        if (adapter == null) {
            throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    "Unknown tool proposal: " + toolName
            );
        }
        return adapter;
    }

    private ToolExecutionPolicy requirePolicy(
            SandboxExecutionContext context
    ) {
        List<ToolExecutionPolicy> matches = policies.stream()
                .filter(policy -> policy.supports(context.mode()))
                .toList();

        if (matches.size() != 1) {
            throw new BusinessException(
                    ErrorCode.CONFIGURATION_ERROR,
                    "Exactly one ToolExecutionPolicy must support mode "
                            + context.mode()
            );
        }

        return matches.getFirst();
    }

    private Map<String, ToolAdapter> indexAdapters(
            List<ToolAdapter> adapters
    ) {
        Map<String, ToolAdapter> indexed = new HashMap<>();

        for (ToolAdapter adapter : adapters) {
            ToolAdapter previous =
                    indexed.put(adapter.toolName(), adapter);

            if (previous != null) {
                throw new IllegalStateException(
                        "Duplicate ToolAdapter for " + adapter.toolName()
                );
            }
        }

        return Map.copyOf(indexed);
    }
}
