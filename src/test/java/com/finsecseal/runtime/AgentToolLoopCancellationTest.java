package com.finsecseal.runtime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.finsecseal.attack.AttackVariant;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.runtime.ai.AgentAiClient;
import com.finsecseal.sandbox.SandboxExecutionContext;
import com.finsecseal.sandbox.tool.ToolDispatcher;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.node.JsonNodeFactory;

class AgentToolLoopCancellationTest {

    @Test
    void stopsBeforeToolDispatchWhenCancellationArrivesAfterInitialModelTurn() {
        AgentRuntimeService runtimeService = mock(AgentRuntimeService.class);
        ToolDispatcher dispatcher = mock(ToolDispatcher.class);
        RunCancellationProbe cancellation = mock(RunCancellationProbe.class);
        UUID runId = UUID.randomUUID();
        SandboxExecutionContext context = new SandboxExecutionContext(
                runId,
                UUID.randomUUID(),
                UUID.randomUUID(),
                TestRunMode.BASELINE,
                "CASE-1001",
                "CUST-1001"
        );
        AttackVariant variant = new AttackVariant(
                "FA-02",
                "HIGH",
                "customer_isolation",
                "CROSS_CUSTOMER",
                "CUSTOMER_DATA_READ",
                JsonNodeFactory.instance.objectNode(),
                "sha256:" + "a".repeat(64)
        );
        ToolProposal proposal = new ToolProposal(
                "CUSTOMER_DATA_READ",
                JsonNodeFactory.instance.objectNode()
        );
        AgentAiClient.AgentTurnResponse aiResponse = mock(AgentAiClient.AgentTurnResponse.class);
        ExecutionEventDto.Event proposalEvent = mock(ExecutionEventDto.Event.class);
        when(aiResponse.proposal()).thenReturn(proposal);
        when(proposalEvent.eventId()).thenReturn(UUID.randomUUID());
        when(proposalEvent.payloadDigest()).thenReturn("sha256:" + "b".repeat(64));
        when(runtimeService.proposeTool(any(), any(), anyString())).thenReturn(
                new AgentRuntimeService.RuntimeTurn(aiResponse, proposalEvent));
        BusinessException cancelled = new BusinessException(
                ErrorCode.INVALID_STATE_TRANSITION,
                "TestRun cancellation was requested"
        );
        doNothing().doThrow(cancelled)
                .when(cancellation).throwIfCancellationRequested(runId);

        AgentToolLoopService service = new AgentToolLoopService(
                runtimeService,
                dispatcher,
                8,
                cancellation
        );

        assertThatThrownBy(() -> service.execute(context, variant, "orchestrator-b"))
                .isSameAs(cancelled)
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.INVALID_STATE_TRANSITION));
        verifyNoInteractions(dispatcher);
    }
}
