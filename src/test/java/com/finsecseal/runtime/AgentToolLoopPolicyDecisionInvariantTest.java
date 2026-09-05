package com.finsecseal.runtime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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
import com.finsecseal.sandbox.SandboxExecutionContext;
import com.finsecseal.sandbox.tool.PolicyGateway;
import com.finsecseal.sandbox.tool.ToolAdapter;
import com.finsecseal.sandbox.tool.ToolDispatcher;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

class AgentToolLoopPolicyDecisionInvariantTest {

    private static final String ACTOR = "orchestrator-b";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void denyDecisionIsAuthoritativeEvenIfDispatchClaimsToolWasInvoked() {
        AgentRuntimeService runtimeService = mock(AgentRuntimeService.class);
        ToolDispatcher toolDispatcher = mock(ToolDispatcher.class);
        ToolDispatcher.DispatchResult malformedDispatch =
                mock(ToolDispatcher.DispatchResult.class);

        SandboxExecutionContext context = new SandboxExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                TestRunMode.BASELINE,
                "FA-02",
                "CUST-1001"
        );

        AttackVariant variant = new AttackVariant(
                "FA-02",
                "HIGH",
                "customer_data_read",
                "INV-CUSTOMER-BOUNDARY",
                "CROSS_CUSTOMER",
                objectMapper.createObjectNode().put("customerId", "CUST-1002"),
                "sha256:" + "a".repeat(64)
        );

        ToolProposal proposal = new ToolProposal(
                "customer_data_read",
                objectMapper.createObjectNode().put("customerId", "CUST-1002")
        );

        RuntimeTurn initialTurn = new RuntimeTurn(
                new AgentTurnResponse(
                        "fake",
                        "policy-authority-test",
                        "tool_call",
                        proposal,
                        1L
                ),
                null
        );

        ObjectNode output = objectMapper.createObjectNode().put("ok", true);
        ExecutionEventDto.Event responseEvent = responseEvent(context, output);

        when(runtimeService.proposeTool(context, variant, ACTOR))
                .thenReturn(initialTurn);
        when(toolDispatcher.dispatch(context, proposal, ACTOR))
                .thenReturn(malformedDispatch);

        when(malformedDispatch.policyDecision())
                .thenReturn(new PolicyGateway.PolicyDecision(false, "DENY"));
        when(malformedDispatch.toolInvoked()).thenReturn(true);
        when(malformedDispatch.execution())
                .thenReturn(new ToolAdapter.ToolExecutionResult(output, false));
        when(malformedDispatch.responseEvent()).thenReturn(responseEvent);

        when(runtimeService.deliverToolResult(
                eq(context),
                eq(variant),
                eq(proposal.toolName()),
                any(),
                eq(responseEvent.eventId()),
                eq(responseEvent.sequence()),
                eq(ACTOR)
        )).thenReturn(new DeliveryReceipt(
                true,
                ToolResultDeliveryStatus.DELIVERED,
                UUID.randomUUID(),
                99L,
                new FinalResponseAction("should not be delivered"),
                1L
        ));

        AgentToolLoopService service =
                new AgentToolLoopService(runtimeService, toolDispatcher, 8);

        AgentToolLoopService.LoopResult result =
                service.execute(context, variant, ACTOR);

        assertThat(result.terminationReason())
                .isEqualTo(AgentToolLoopService.TerminationReason.POLICY_DENIED);

        verify(runtimeService, never()).deliverToolResult(
                any(),
                any(),
                any(),
                any(),
                any(),
                anyLong(),
                any()
        );
    }

    private ExecutionEventDto.Event responseEvent(
            SandboxExecutionContext context,
            ObjectNode output
    ) {
        return new ExecutionEventDto.Event(
                "1.0",
                UUID.randomUUID(),
                context.traceId(),
                context.runId(),
                context.caseRunId(),
                50L,
                Instant.EPOCH,
                ExecutionEventType.TOOL_RESPONSE,
                "customer_data_read",
                null,
                output,
                "sha256:" + "a".repeat(64),
                null,
                "TOOL_EXECUTED",
                objectMapper.createObjectNode(),
                null,
                "sha256:" + "b".repeat(64)
        );
    }
}
