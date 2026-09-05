package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.sandbox.SandboxExecutionContext;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

class TemporaryPolicyGatewayBridgeModeInvariantTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @ParameterizedTest
    @EnumSource(
            value = TestRunMode.class,
            names = {"SEAL_REPLAY", "HELD_OUT", "REGRESSION"}
    )
    void temporaryBridgeFailsClosedOutsideBaselineEvenWhenLegacyPolicySupportsMode(
            TestRunMode mode
    ) {
        ExecutionEventService eventService = mock(ExecutionEventService.class);
        ToolAdapter adapter = mock(ToolAdapter.class);
        when(adapter.toolName()).thenReturn("customer_data_read");
        when(adapter.execute(any(), any())).thenReturn(
                new ToolAdapter.ToolExecutionResult(
                        objectMapper.createObjectNode().put("ok", true),
                        false
                )
        );

        when(eventService.append(any(), any(), any())).thenReturn(
                event(10L, ExecutionEventType.POLICY_EVALUATED),
                event(11L, ExecutionEventType.TOOL_REQUEST),
                event(12L, ExecutionEventType.TOOL_RESPONSE)
        );

        ToolExecutionPolicy permissiveNonBaselinePolicy = new ToolExecutionPolicy() {
            @Override
            public boolean supports(TestRunMode candidate) {
                return candidate == mode;
            }

            @Override
            public PolicyDecision evaluate(
                    SandboxExecutionContext context,
                    ToolProposal proposal
            ) {
                return new PolicyDecision(true, "SHOULD_NEVER_BE_USED");
            }
        };

        TemporaryPolicyGatewayBridge bridge = new TemporaryPolicyGatewayBridge(
                List.of(adapter),
                List.of(permissiveNonBaselinePolicy),
                eventService,
                objectMapper
        );

        SandboxExecutionContext context = new SandboxExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                mode,
                "FA-02",
                "CUST-1001"
        );

        ToolProposal proposal = new ToolProposal(
                "customer_data_read",
                objectMapper.createObjectNode().put("customerId", "CUST-1002")
        );

        assertThatThrownBy(() -> bridge.invoke(context, proposal, "orchestrator-b"))
                .isInstanceOfSatisfying(BusinessException.class, exception -> {
                    assertThat(exception.errorCode()).isEqualTo(ErrorCode.CONFIGURATION_ERROR);
                    assertThat(exception.getMessage()).contains("only supports BASELINE");
                });

        verify(adapter, never()).execute(any(), any());
        verifyNoInteractions(eventService);
    }

    private ExecutionEventDto.Event event(long sequence, ExecutionEventType eventType) {
        ObjectNode empty = objectMapper.createObjectNode();
        return new ExecutionEventDto.Event(
                "1.0",
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                sequence,
                Instant.EPOCH,
                eventType,
                "customer_data_read",
                empty,
                empty,
                "sha256:" + "a".repeat(64),
                empty,
                null,
                empty,
                null,
                "sha256:" + "b".repeat(64)
        );
    }
}
