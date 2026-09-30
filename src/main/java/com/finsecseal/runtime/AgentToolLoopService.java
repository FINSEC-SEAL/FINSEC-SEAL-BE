package com.finsecseal.runtime;

import com.finsecseal.attack.AttackVariant;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.runtime.ai.AgentAiClient.ToolResultDeliveryStatus;
import com.finsecseal.runtime.ai.ModelTokenUsage;
import com.finsecseal.runtime.ai.StatelessAgentStepClient.AgentAction;
import com.finsecseal.runtime.ai.StatelessAgentStepClient.FinalResponseAction;
import com.finsecseal.runtime.ai.StatelessAgentStepClient.ToolProposalAction;
import com.finsecseal.sandbox.SandboxExecutionContext;
import com.finsecseal.sandbox.tool.ToolDispatcher;
import java.util.ArrayList;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class AgentToolLoopService {

    private final AgentRuntimeService runtimeService;
    private final ToolDispatcher toolDispatcher;
    private final int maxSteps;
    private final long maxTotalTokens;
    private final long executionTimeoutNanos;
    private final Consumer<UUID> cancellationCheck;
    private final LongSupplier nanoTime;

    @Autowired
    public AgentToolLoopService(
            AgentRuntimeService runtimeService,
            ToolDispatcher toolDispatcher,
            @Value("${finsec.ai.max-steps:8}") int maxSteps,
            @Value("${finsec.ai.max-total-tokens:8192}") long maxTotalTokens,
            @Value("${finsec.ai.execution-timeout:30s}") Duration executionTimeout,
            RunCancellationProbe cancellationProbe
    ) {
        this(runtimeService, toolDispatcher, maxSteps, maxTotalTokens, executionTimeout,
                cancellationProbe::throwIfCancellationRequested, System::nanoTime);
    }

    /** Source-compatible constructor for focused tests that do not own persisted Run state. */
    public AgentToolLoopService(
            AgentRuntimeService runtimeService,
            ToolDispatcher toolDispatcher,
            int maxSteps
    ) {
        this(runtimeService, toolDispatcher, maxSteps, 8_192L, Duration.ofSeconds(30),
                runId -> { }, System::nanoTime);
    }

    /** Source-compatible constructor for cancellation-focused tests. */
    AgentToolLoopService(
            AgentRuntimeService runtimeService,
            ToolDispatcher toolDispatcher,
            int maxSteps,
            RunCancellationProbe cancellationProbe
    ) {
        this(runtimeService, toolDispatcher, maxSteps, 8_192L, Duration.ofSeconds(30),
                cancellationProbe::throwIfCancellationRequested, System::nanoTime);
    }

    AgentToolLoopService(
            AgentRuntimeService runtimeService,
            ToolDispatcher toolDispatcher,
            int maxSteps,
            long maxTotalTokens,
            Duration executionTimeout,
            Consumer<UUID> cancellationCheck,
            LongSupplier nanoTime
    ) {
        if (maxSteps < 1) {
            throw new IllegalArgumentException("finsec.ai.max-steps must be at least 1");
        }
        if (maxTotalTokens < 1) {
            throw new IllegalArgumentException("finsec.ai.max-total-tokens must be at least 1");
        }
        if (executionTimeout == null || executionTimeout.isZero() || executionTimeout.isNegative()) {
            throw new IllegalArgumentException("finsec.ai.execution-timeout must be positive");
        }
        this.runtimeService = runtimeService;
        this.toolDispatcher = toolDispatcher;
        this.maxSteps = maxSteps;
        this.maxTotalTokens = maxTotalTokens;
        try {
            this.executionTimeoutNanos = executionTimeout.toNanos();
        } catch (ArithmeticException exception) {
            throw new IllegalArgumentException("finsec.ai.execution-timeout is too large", exception);
        }
        this.cancellationCheck = cancellationCheck;
        this.nanoTime = nanoTime;
    }

    public LoopResult execute(
            SandboxExecutionContext context,
            AttackVariant attackVariant,
            String actorId
    ) {
        long startedNanos = nanoTime.getAsLong();
        cancellationCheck.accept(context.runId());
        enforceTimeBudget(startedNanos);
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
        ModelTokenUsage totalTokenUsage = requireTokenUsage(initialTurn.aiResponse().tokenUsage());
        enforceBudgets(startedNanos, totalTokenUsage);

        while (true) {
            cancellationCheck.accept(context.runId());
            enforceBudgets(startedNanos, totalTokenUsage);
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
            enforceTimeBudget(startedNanos);

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
                        totalLatencyMs,
                        totalTokenUsage
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
            enforceTimeBudget(startedNanos);
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
            totalTokenUsage = totalTokenUsage.plus(requireTokenUsage(delivery.tokenUsage()));
            enforceBudgets(startedNanos, totalTokenUsage);
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
                        totalLatencyMs,
                        totalTokenUsage
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
                        totalLatencyMs,
                        totalTokenUsage
                );
            }

            if (nextAction instanceof ToolProposalAction toolProposalAction) {
                cancellationCheck.accept(context.runId());
                enforceBudgets(startedNanos, totalTokenUsage);
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

    private ModelTokenUsage requireTokenUsage(ModelTokenUsage usage) {
        if (usage == null) {
            throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, "AI response is missing token usage");
        }
        return usage;
    }

    private void enforceBudgets(long startedNanos, ModelTokenUsage usage) {
        enforceTimeBudget(startedNanos);
        if (usage.totalTokens() > maxTotalTokens) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Agent tool loop exceeded total token limit: " + maxTotalTokens
            );
        }
    }

    private void enforceTimeBudget(long startedNanos) {
        long elapsedNanos = nanoTime.getAsLong() - startedNanos;
        if (elapsedNanos < 0 || elapsedNanos > executionTimeoutNanos) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Agent tool loop exceeded execution timeout"
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
            long latencyMs,
            ModelTokenUsage tokenUsage
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
