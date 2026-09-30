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
import java.util.UUID;
import java.util.function.Consumer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class AgentToolLoopService {

    private final AgentRuntimeService runtimeService;
    private final ToolDispatcher toolDispatcher;
    private final int maxSteps;
    private final Consumer<UUID> cancellationCheck;

    @Autowired
    public AgentToolLoopService(
            AgentRuntimeService runtimeService,
            ToolDispatcher toolDispatcher,
            @Value("${finsec.ai.max-steps:8}") int maxSteps,
            RunCancellationProbe cancellationProbe
    ) {
        this(runtimeService, toolDispatcher, maxSteps, cancellationProbe::throwIfCancellationRequested);
    }

    /** Source-compatible constructor for focused tests that do not own persisted Run state. */
    public AgentToolLoopService(
            AgentRuntimeService runtimeService,
            ToolDispatcher toolDispatcher,
            int maxSteps
    ) {
        this(runtimeService, toolDispatcher, maxSteps, runId -> { });
    }

    private AgentToolLoopService(
            AgentRuntimeService runtimeService,
            ToolDispatcher toolDispatcher,
            int maxSteps,
            Consumer<UUID> cancellationCheck
    ) {
        if (maxSteps < 1) {
            throw new IllegalArgumentException("finsec.ai.max-steps must be at least 1");
        }
        this.runtimeService = runtimeService;
        this.toolDispatcher = toolDispatcher;
        this.maxSteps = maxSteps;
        this.cancellationCheck = cancellationCheck;
    }

    public LoopResult execute(
            SandboxExecutionContext context,
            AttackVariant attackVariant,
            String actorId
    ) {
        cancellationCheck.accept(context.runId());
        AgentRuntimeService.RuntimeTurn initialTurn = runtimeService.proposeTool(
                context,
                attackVariant,
                actorId
        );
        ToolInvocation currentInvocation = new ToolInvocation(
                initialTurn.aiResponse().proposal(),
                initialTurn.proposalEvent().eventId(),
                initialTurn.proposalEvent().payloadDigest()
        );
        List<ToolStep> steps = new ArrayList<>();
        long totalLatencyMs = initialTurn.aiResponse().latencyMs();

        while (true) {
            cancellationCheck.accept(context.runId());
            if (steps.size() >= maxSteps) {
                throw new BusinessException(
                        ErrorCode.EVIDENCE_INCOMPLETE,
                        "Agent tool loop exceeded max step limit: " + maxSteps
                );
            }

            ToolDispatcher.DispatchResult dispatch = toolDispatcher.dispatch(
                    context,
                    currentInvocation,
                    actorId
            );

            if (dispatch.policyDecision() == null) {
                throw new BusinessException(
                        ErrorCode.EVIDENCE_INCOMPLETE,
                        "Tool dispatch is missing a Policy Gateway decision"
                );
            }

            if (!dispatch.policyDecision().allowed()) {
                steps.add(new ToolStep(
                        currentInvocation.proposal(),
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

            if (!dispatch.toolInvoked()
                    || dispatch.execution() == null
                    || dispatch.responseEvent() == null) {
                throw new BusinessException(
                        ErrorCode.EVIDENCE_INCOMPLETE,
                        "Allowed Tool dispatch is missing execution evidence"
                );
            }

            cancellationCheck.accept(context.runId());
            AgentRuntimeService.DeliveryReceipt delivery = runtimeService.deliverToolResult(
                    context,
                    attackVariant,
                    currentInvocation.proposal().toolName(),
                    dispatch.execution().output(),
                    dispatch.responseEvent().eventId(),
                    dispatch.responseEvent().sequence(),
                    actorId
            );
            totalLatencyMs += delivery.latencyMs();
            steps.add(new ToolStep(
                    currentInvocation.proposal(),
                    dispatch,
                    delivery
            ));

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
                cancellationCheck.accept(context.runId());
                currentInvocation = runtimeService.recordFollowUpToolProposal(
                        context,
                        attackVariant,
                        toolProposalAction.proposal(),
                        delivery.deliveryEventId(),
                        delivery.deliveryEventSequence(),
                        actorId
                );
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
