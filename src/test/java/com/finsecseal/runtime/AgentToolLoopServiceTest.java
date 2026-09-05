package com.finsecseal.runtime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.finsecseal.attack.AttackVariant;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.runtime.AgentRuntimeService.DeliveryReceipt;
import com.finsecseal.runtime.AgentRuntimeService.RuntimeTurn;
import com.finsecseal.runtime.ai.AgentAiClient.AgentTurnResponse;
import com.finsecseal.runtime.ai.AgentAiClient.ToolResultDeliveryStatus;
import com.finsecseal.runtime.ai.StatelessAgentStepClient.FinalResponseAction;
import com.finsecseal.runtime.ai.StatelessAgentStepClient.ToolProposalAction;
import com.finsecseal.sandbox.SandboxExecutionContext;
import com.finsecseal.sandbox.tool.ToolAdapter;
import com.finsecseal.sandbox.tool.ToolDispatcher;
import com.finsecseal.sandbox.tool.PolicyGateway;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

class AgentToolLoopServiceTest {

    private static final String ACTOR = "orchestrator-b";

    private final ObjectMapper objectMapper = new ObjectMapper();

    private AgentRuntimeService runtimeService;
    private ToolDispatcher toolDispatcher;
    private SandboxExecutionContext context;
    private AttackVariant variant;

    @BeforeEach
    void setUp() {
        runtimeService = mock(AgentRuntimeService.class);
        toolDispatcher = mock(ToolDispatcher.class);

        context = new SandboxExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                TestRunMode.BASELINE,
                "FA-02",
                "applicant-current"
        );
        variant = new AttackVariant(
                "FA-02",
                "HIGH",
                "customer_data_read",
                "INV-CUSTOMER-BOUNDARY",
                "CROSS_CUSTOMER",
                objectMapper.createObjectNode().put("customerId", "customer-other"),
                "sha256:" + "a".repeat(64)
        );
    }

    @Test
    void proposalToolProposalToolFinalIsExecutedAsABoundedSpringLoop() {
        ToolProposal first = proposal("customer_data_read", "customer-other");
        ToolProposal second = proposal("customer_data_read", "customer-third");

        RuntimeTurn initialTurn = initialTurn(first);
        ToolDispatcher.DispatchResult firstDispatch = allowedDispatch(first, 11L);
        ToolDispatcher.DispatchResult secondDispatch = allowedDispatch(second, 21L);

        when(runtimeService.proposeTool(context, variant, ACTOR)).thenReturn(initialTurn);
        when(runtimeService.recordFollowUpToolProposal(
                eq(context), eq(variant), eq(second), any(), anyLong(), eq(ACTOR)
        )).thenReturn(second);
        when(toolDispatcher.dispatch(context, first, ACTOR)).thenReturn(firstDispatch);
        when(toolDispatcher.dispatch(context, second, ACTOR)).thenReturn(secondDispatch);
        when(runtimeService.deliverToolResult(
                eq(context), eq(variant), eq(first.toolName()), any(),
                eq(firstDispatch.responseEvent().eventId()), eq(firstDispatch.responseEvent().sequence()), eq(ACTOR)
        )).thenReturn(deliveredWith(new ToolProposalAction(second), 2L));
        when(runtimeService.deliverToolResult(
                eq(context), eq(variant), eq(second.toolName()), any(),
                eq(secondDispatch.responseEvent().eventId()), eq(secondDispatch.responseEvent().sequence()), eq(ACTOR)
        )).thenReturn(deliveredWith(new FinalResponseAction("done"), 3L));

        Object service = newService(8);
        Object result = execute(service);

        assertThat(result).isNotNull();
        verify(toolDispatcher, times(2)).dispatch(any(), any(), eq(ACTOR));
        verify(runtimeService, times(2)).deliverToolResult(any(), any(), any(), any(), any(), any(Long.class), eq(ACTOR));
    }

    @Test
    void maxStepsExceededFailsClosedBeforeAnAdditionalProposalIsDispatched() {
        ToolProposal first = proposal("customer_data_read", "customer-1");
        ToolProposal second = proposal("customer_data_read", "customer-2");
        ToolProposal third = proposal("customer_data_read", "customer-3");

        ToolDispatcher.DispatchResult firstDispatch = allowedDispatch(first, 31L);
        ToolDispatcher.DispatchResult secondDispatch = allowedDispatch(second, 41L);

        when(runtimeService.proposeTool(context, variant, ACTOR)).thenReturn(initialTurn(first));
        when(runtimeService.recordFollowUpToolProposal(
                eq(context), eq(variant), eq(second), any(), anyLong(), eq(ACTOR)
        )).thenReturn(second);
        when(runtimeService.recordFollowUpToolProposal(
                eq(context), eq(variant), eq(third), any(), anyLong(), eq(ACTOR)
        )).thenReturn(third);
        when(toolDispatcher.dispatch(context, first, ACTOR)).thenReturn(firstDispatch);
        when(toolDispatcher.dispatch(context, second, ACTOR)).thenReturn(secondDispatch);
        when(runtimeService.deliverToolResult(
                eq(context), eq(variant), eq(first.toolName()), any(),
                eq(firstDispatch.responseEvent().eventId()), eq(firstDispatch.responseEvent().sequence()), eq(ACTOR)
        )).thenReturn(deliveredWith(new ToolProposalAction(second), 1L));
        when(runtimeService.deliverToolResult(
                eq(context), eq(variant), eq(second.toolName()), any(),
                eq(secondDispatch.responseEvent().eventId()), eq(secondDispatch.responseEvent().sequence()), eq(ACTOR)
        )).thenReturn(deliveredWith(new ToolProposalAction(third), 1L));

        Object service = newService(2);

        assertThatThrownBy(() -> execute(service))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("step");

        verify(toolDispatcher, times(2)).dispatch(any(), any(), eq(ACTOR));
        verify(toolDispatcher, never()).dispatch(context, third, ACTOR);
    }

    @Test
    void everyToolProposalPassesThroughToolDispatcherInOrder() {
        ToolProposal first = proposal("customer_data_read", "customer-a");
        ToolProposal second = proposal("customer_data_read", "customer-b");

        ToolDispatcher.DispatchResult firstDispatch = allowedDispatch(first, 51L);
        ToolDispatcher.DispatchResult secondDispatch = allowedDispatch(second, 61L);

        when(runtimeService.proposeTool(context, variant, ACTOR)).thenReturn(initialTurn(first));
        when(runtimeService.recordFollowUpToolProposal(
                eq(context), eq(variant), eq(second), any(), anyLong(), eq(ACTOR)
        )).thenReturn(second);
        when(toolDispatcher.dispatch(context, first, ACTOR)).thenReturn(firstDispatch);
        when(toolDispatcher.dispatch(context, second, ACTOR)).thenReturn(secondDispatch);
        when(runtimeService.deliverToolResult(
                eq(context), eq(variant), eq(first.toolName()), any(),
                eq(firstDispatch.responseEvent().eventId()), eq(firstDispatch.responseEvent().sequence()), eq(ACTOR)
        )).thenReturn(deliveredWith(new ToolProposalAction(second), 1L));
        when(runtimeService.deliverToolResult(
                eq(context), eq(variant), eq(second.toolName()), any(),
                eq(secondDispatch.responseEvent().eventId()), eq(secondDispatch.responseEvent().sequence()), eq(ACTOR)
        )).thenReturn(deliveredWith(new FinalResponseAction("finished"), 1L));

        execute(newService(8));

        InOrder order = inOrder(runtimeService, toolDispatcher);
        order.verify(runtimeService).proposeTool(context, variant, ACTOR);
        order.verify(toolDispatcher).dispatch(context, first, ACTOR);
        order.verify(runtimeService).deliverToolResult(
                eq(context), eq(variant), eq(first.toolName()), any(),
                eq(firstDispatch.responseEvent().eventId()), eq(firstDispatch.responseEvent().sequence()), eq(ACTOR)
        );
        order.verify(runtimeService).recordFollowUpToolProposal(
                eq(context), eq(variant), eq(second), any(), anyLong(), eq(ACTOR)
        );
        order.verify(toolDispatcher).dispatch(context, second, ACTOR);
        order.verify(runtimeService).deliverToolResult(
                eq(context), eq(variant), eq(second.toolName()), any(),
                eq(secondDispatch.responseEvent().eventId()), eq(secondDispatch.responseEvent().sequence()), eq(ACTOR)
        );
    }

    @Test
    void finalResponseTerminatesTheLoopWithoutAnotherDispatch() {
        ToolProposal first = proposal("customer_data_read", "customer-only");
        ToolDispatcher.DispatchResult dispatch = allowedDispatch(first, 71L);

        when(runtimeService.proposeTool(context, variant, ACTOR)).thenReturn(initialTurn(first));
        when(toolDispatcher.dispatch(context, first, ACTOR)).thenReturn(dispatch);
        when(runtimeService.deliverToolResult(
                eq(context), eq(variant), eq(first.toolName()), any(),
                eq(dispatch.responseEvent().eventId()), eq(dispatch.responseEvent().sequence()), eq(ACTOR)
        )).thenReturn(deliveredWith(new FinalResponseAction("final"), 1L));

        Object result = execute(newService(8));

        assertThat(result).isNotNull();
        verify(toolDispatcher, times(1)).dispatch(any(), any(), eq(ACTOR));
        verify(runtimeService, times(1)).deliverToolResult(any(), any(), any(), any(), any(), any(Long.class), eq(ACTOR));
    }

    @Test
    void deniedAndQuarantinedPathsTerminateWithoutBreakingExistingSemantics() {
        ToolProposal deniedProposal = proposal("customer_data_read", "customer-denied");
        when(runtimeService.proposeTool(context, variant, ACTOR)).thenReturn(initialTurn(deniedProposal));
        when(toolDispatcher.dispatch(context, deniedProposal, ACTOR)).thenReturn(deniedDispatch());

        Object deniedResult = execute(newService(8));
        assertThat(deniedResult).isNotNull();
        verify(runtimeService, never()).deliverToolResult(any(), any(), any(), any(), any(), any(Long.class), any());

        runtimeService = mock(AgentRuntimeService.class);
        toolDispatcher = mock(ToolDispatcher.class);

        ToolProposal quarantinedProposal = proposal("customer_data_read", "customer-quarantined");
        ToolDispatcher.DispatchResult quarantinedDispatch = allowedDispatch(quarantinedProposal, 81L);
        when(runtimeService.proposeTool(context, variant, ACTOR)).thenReturn(initialTurn(quarantinedProposal));
        when(toolDispatcher.dispatch(context, quarantinedProposal, ACTOR)).thenReturn(quarantinedDispatch);
        when(runtimeService.deliverToolResult(
                eq(context), eq(variant), eq(quarantinedProposal.toolName()), any(),
                eq(quarantinedDispatch.responseEvent().eventId()),
                eq(quarantinedDispatch.responseEvent().sequence()),
                eq(ACTOR)
        )).thenReturn(new DeliveryReceipt(
                false,
                ToolResultDeliveryStatus.QUARANTINED,
                UUID.randomUUID(),
                82L,
                null,
                1L
        ));

        Object quarantinedResult = execute(newService(8));
        assertThat(quarantinedResult).isNotNull();
        verify(toolDispatcher, times(1)).dispatch(context, quarantinedProposal, ACTOR);
        verify(runtimeService, times(1)).deliverToolResult(
                eq(context), eq(variant), eq(quarantinedProposal.toolName()), any(),
                eq(quarantinedDispatch.responseEvent().eventId()),
                eq(quarantinedDispatch.responseEvent().sequence()),
                eq(ACTOR)
        );
    }

    private ToolProposal proposal(String toolName, String customerId) {
        return new ToolProposal(
                toolName,
                objectMapper.createObjectNode().put("customerId", customerId)
        );
    }

    private RuntimeTurn initialTurn(ToolProposal proposal) {
        return new RuntimeTurn(
                new AgentTurnResponse(
                        "fake",
                        "multi-step-test",
                        "tool_call",
                        proposal,
                        1L
                ),
                null
        );
    }

    private DeliveryReceipt deliveredWith(Object nextAction, long latencyMs) {
        return new DeliveryReceipt(
                true,
                ToolResultDeliveryStatus.DELIVERED,
                UUID.randomUUID(),
                100L,
                (com.finsecseal.runtime.ai.StatelessAgentStepClient.AgentAction) nextAction,
                latencyMs
        );
    }

    private ToolDispatcher.DispatchResult allowedDispatch(ToolProposal proposal, long sequence) {
        ObjectNode output = objectMapper.createObjectNode()
                .put("tool", proposal.toolName())
                .put("sequence", sequence);
        ExecutionEventDto.Event responseEvent = event(sequence, proposal.toolName(), output);
        return new ToolDispatcher.DispatchResult(
                new PolicyGateway.PolicyDecision(true, "ALLOW"),
                null,
                null,
                responseEvent,
                new ToolAdapter.ToolExecutionResult(output, false)
        );
    }

    private ToolDispatcher.DispatchResult deniedDispatch() {
        return new ToolDispatcher.DispatchResult(
                new PolicyGateway.PolicyDecision(false, "DENY"),
                null,
                null,
                null,
                null
        );
    }

    private ExecutionEventDto.Event event(long sequence, String toolName, ObjectNode output) {
        return new ExecutionEventDto.Event(
                "1.0",
                UUID.randomUUID(),
                context.traceId(),
                context.runId(),
                context.caseRunId(),
                sequence,
                Instant.now(),
                ExecutionEventType.TOOL_RESPONSE,
                toolName,
                null,
                output,
                "payload-digest",
                null,
                "TOOL_EXECUTED",
                objectMapper.createObjectNode(),
                "prev-hash",
                "event-hash"
        );
    }

    private Object newService(int maxSteps) {
        Class<?> serviceType = requireServiceType();
        try {
            Constructor<?> constructor = serviceType.getDeclaredConstructor(
                    AgentRuntimeService.class,
                    ToolDispatcher.class,
                    int.class
            );
            constructor.setAccessible(true);
            return constructor.newInstance(runtimeService, toolDispatcher, maxSteps);
        } catch (NoSuchMethodException exception) {
            throw new AssertionError(
                    "AgentToolLoopService must have constructor (AgentRuntimeService, ToolDispatcher, int maxSteps)",
                    exception
            );
        } catch (ReflectiveOperationException exception) {
            throw new AssertionError("Could not construct AgentToolLoopService", exception);
        }
    }

    private Object execute(Object service) {
        try {
            Method execute = service.getClass().getDeclaredMethod(
                    "execute",
                    SandboxExecutionContext.class,
                    AttackVariant.class,
                    String.class
            );
            execute.setAccessible(true);
            return execute.invoke(service, context, variant, ACTOR);
        } catch (InvocationTargetException exception) {
            Throwable cause = exception.getCause();
            if (cause instanceof RuntimeException runtimeException) {
                throw runtimeException;
            }
            if (cause instanceof Error error) {
                throw error;
            }
            throw new RuntimeException(cause);
        } catch (NoSuchMethodException exception) {
            throw new AssertionError(
                    "AgentToolLoopService must expose execute(SandboxExecutionContext, AttackVariant, String)",
                    exception
            );
        } catch (IllegalAccessException exception) {
            throw new AssertionError("Could not invoke AgentToolLoopService.execute", exception);
        }
    }

    private Class<?> requireServiceType() {
        try {
            return Class.forName("com.finsecseal.runtime.AgentToolLoopService");
        } catch (ClassNotFoundException exception) {
            throw new AssertionError(
                    "AgentToolLoopService does not exist yet; this is the expected RED reason",
                    exception
            );
        }
    }
}
