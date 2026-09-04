package com.finsecseal.runtime;

import com.finsecseal.attack.AttackVariant;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.runtime.ai.AgentAiClient.ToolResultDeliveryStatus;
import com.finsecseal.runtime.ai.StatelessAgentStepClient.AgentAction;
import com.finsecseal.runtime.ai.StatelessAgentStepClient.FinalResponseAction;
import com.finsecseal.runtime.ai.StatelessAgentStepClient.ToolProposalAction;
import com.finsecseal.sandbox.SandboxExecutionContext;
import com.finsecseal.sandbox.tool.ToolDispatcher;
import java.util.ArrayList;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class AgentToolLoopService {

    private final AgentRuntimeService runtimeService;
    private final ToolDispatcher toolDispatcher;
    private final int maxSteps;

    public AgentToolLoopService(
            AgentRuntimeService runtimeService,
            ToolDispatcher toolDispatcher,
            @Value("${finsec.ai.max-steps:8}") int maxSteps
    ) {
        if (maxSteps < 1) {
            throw new IllegalArgumentException("finsec.ai.max-steps must be at least 1");
        }
        this.runtimeService = runtimeService;
        this.toolDispatcher = toolDispatcher;
        this.maxSteps = maxSteps;
    }

    public LoopResult execute(
            SandboxExecutionContext context,
            AttackVariant attackVariant,
            String actorId
    ) {
        AgentRuntimeService.RuntimeTurn initialTurn = runtimeService.proposeTool(
                context,
                attackVariant,
                actorId
        );
        ToolProposal currentProposal = initialTurn.aiResponse().proposal();
        List<ToolStep> steps = new ArrayList<>();
        long totalLatencyMs = initialTurn.aiResponse().latencyMs();

        while (true) {
            if (steps.size() >= maxSteps) {
                throw new BusinessException(
                        ErrorCode.EVIDENCE_INCOMPLETE,
                        "Agent tool loop exceeded max step limit: " + maxSteps
                );
            }

            ToolDispatcher.DispatchResult dispatch = toolDispatcher.dispatch(
                    context,
                    currentProposal,
                    actorId
            );

            if (!dispatch.toolInvoked()) {
                steps.add(new ToolStep(
                        currentProposal,
                        dispatch,
                        AgentRuntimeService.DeliveryReceipt.notDelivered()
                ));
                return new LoopResult(
                        List.copyOf(steps),
                        null,
                        TerminationReason.POLICY_DENIED,
                        totalLatencyMs
                );
            }

            AgentRuntimeService.DeliveryReceipt delivery = runtimeService.deliverToolResult(
                    context,
                    attackVariant,
                    currentProposal.toolName(),
                    dispatch.execution().output(),
                    dispatch.responseEvent().eventId(),
                    dispatch.responseEvent().sequence(),
                    actorId
            );
            totalLatencyMs += delivery.latencyMs();
            steps.add(new ToolStep(currentProposal, dispatch, delivery));

            if (delivery.status() == ToolResultDeliveryStatus.QUARANTINED) {
                return new LoopResult(
                        List.copyOf(steps),
                        null,
                        TerminationReason.QUARANTINED,
                        totalLatencyMs
                );
            }

            if (!delivery.deliveredToAgent()) {
                throw new BusinessException(
                        ErrorCode.EVIDENCE_INCOMPLETE,
                        "Agent Tool Result was not delivered"
                );
            }

            AgentAction nextAction = delivery.nextAction();
            if (nextAction instanceof FinalResponseAction finalResponse) {
                return new LoopResult(
                        List.copyOf(steps),
                        finalResponse,
                        TerminationReason.FINAL_RESPONSE,
                        totalLatencyMs
                );
            }

            if (nextAction instanceof ToolProposalAction toolProposalAction) {
                currentProposal = toolProposalAction.proposal();
                continue;
            }

            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Delivered Agent Tool Result has an unsupported next action"
            );
        }
    }

    public record ToolStep(
            ToolProposal proposal,
            ToolDispatcher.DispatchResult dispatch,
            AgentRuntimeService.DeliveryReceipt delivery
    ) {
    }

    public record LoopResult(
            List<ToolStep> toolSteps,
            FinalResponseAction finalResponse,
            TerminationReason terminationReason,
            long latencyMs
    ) {
        public ToolStep lastToolStep() {
            return toolSteps.isEmpty() ? null : toolSteps.getLast();
        }
    }

    public enum TerminationReason {
        FINAL_RESPONSE,
        POLICY_DENIED,
        QUARANTINED
    }
}
