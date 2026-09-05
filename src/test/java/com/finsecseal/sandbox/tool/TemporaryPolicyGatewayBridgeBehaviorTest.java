package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

class TemporaryPolicyGatewayBridgeBehaviorTest {

    private static final String ACTOR = "orchestrator-b";

    private final ObjectMapper objectMapper = new ObjectMapper();

    private ExecutionEventService eventService;
    private ToolAdapter adapter;
    private SandboxExecutionContext baselineContext;
    private ToolProposal proposal;

    @BeforeEach
    void setUp() {
        eventService = mock(ExecutionEventService.class);
        adapter = mock(ToolAdapter.class);
        when(adapter.toolName()).thenReturn("customer_data_read");

        baselineContext = context(TestRunMode.BASELINE);
        proposal = new ToolProposal(
                "customer_data_read",
                objectMapper.createObjectNode().put("customerId", "CUST-1002")
        );
    }

    @Test
    void baselineAllowInvokesRegisteredAdapterExactlyOnceThroughGateway() {
        ToolAdapter.ToolExecutionResult execution =
                new ToolAdapter.ToolExecutionResult(
                        objectMapper.createObjectNode().put("ok", true),
                        false
                );

        when(adapter.execute(baselineContext, proposal.arguments()))
                .thenReturn(execution);

        when(eventService.append(
                eq(baselineContext.runId()),
                any(ExecutionEventDto.AppendRequest.class),
                eq(ACTOR)
        )).thenReturn(
                event(baselineContext, 10L, ExecutionEventType.POLICY_EVALUATED),
                event(baselineContext, 11L, ExecutionEventType.TOOL_REQUEST),
                event(baselineContext, 12L, ExecutionEventType.TOOL_RESPONSE)
        );

        TemporaryPolicyGatewayBridge bridge = new TemporaryPolicyGatewayBridge(
                List.of(adapter),
                List.of(new BaselineToolExecutionPolicy()),
                eventService,
                objectMapper
        );

        PolicyGateway.GatewayResult result =
                bridge.invoke(baselineContext, proposal, ACTOR);

        assertThat(result.policyDecision().allowed()).isTrue();
        assertThat(result.policyDecision().reasonCode()).isEqualTo("BASELINE_ALLOW");
        assertThat(result.execution()).isSameAs(execution);
        assertThat(result.requestEvent().eventType()).isEqualTo(ExecutionEventType.TOOL_REQUEST);
        assertThat(result.responseEvent().eventType()).isEqualTo(ExecutionEventType.TOOL_RESPONSE);

        verify(adapter, times(1))
                .execute(baselineContext, proposal.arguments());

        ArgumentCaptor<ExecutionEventDto.AppendRequest> requestCaptor =
                ArgumentCaptor.forClass(ExecutionEventDto.AppendRequest.class);

        verify(eventService, times(3)).append(
                eq(baselineContext.runId()),
                requestCaptor.capture(),
                eq(ACTOR)
        );

        assertThat(requestCaptor.getAllValues())
                .extracting(ExecutionEventDto.AppendRequest::eventType)
                .containsExactly(
                        ExecutionEventType.POLICY_EVALUATED,
                        ExecutionEventType.TOOL_REQUEST,
                        ExecutionEventType.TOOL_RESPONSE
                );
    }

    @Test
    void unsupportedEnforcementModeFailsClosedBeforeAnyEvidenceOrAdapterInvocation() {
        SandboxExecutionContext sealReplay = context(TestRunMode.SEAL_REPLAY);

        TemporaryPolicyGatewayBridge bridge = new TemporaryPolicyGatewayBridge(
                List.of(adapter),
                List.of(new BaselineToolExecutionPolicy()),
                eventService,
                objectMapper
        );

        assertThatThrownBy(() -> bridge.invoke(sealReplay, proposal, ACTOR))
                .isInstanceOfSatisfying(BusinessException.class, exception -> {
                    assertThat(exception.errorCode()).isEqualTo(ErrorCode.CONFIGURATION_ERROR);
                    assertThat(exception.getMessage())
                            .contains("Exactly one ToolExecutionPolicy must support mode SEAL_REPLAY");
                });

        verify(adapter, never()).execute(any(), any());
        verifyNoInteractions(eventService);
    }

    @Test
    void denyCreatesOnlyPolicyEvidenceAndNeverInvokesAdapter() {
        ToolExecutionPolicy denyPolicy = new ToolExecutionPolicy() {
            @Override
            public boolean supports(TestRunMode mode) {
                return mode == TestRunMode.BASELINE;
            }

            @Override
            public PolicyDecision evaluate(
                    SandboxExecutionContext context,
                    ToolProposal proposal
            ) {
                return new PolicyDecision(false, "TEST_DENY");
            }
        };

        when(eventService.append(
                eq(baselineContext.runId()),
                any(ExecutionEventDto.AppendRequest.class),
                eq(ACTOR)
        )).thenReturn(
                event(baselineContext, 20L, ExecutionEventType.POLICY_EVALUATED)
        );

        TemporaryPolicyGatewayBridge bridge = new TemporaryPolicyGatewayBridge(
                List.of(adapter),
                List.of(denyPolicy),
                eventService,
                objectMapper
        );

        PolicyGateway.GatewayResult result =
                bridge.invoke(baselineContext, proposal, ACTOR);

        assertThat(result.policyDecision().allowed()).isFalse();
        assertThat(result.policyDecision().reasonCode()).isEqualTo("TEST_DENY");
        assertThat(result.requestEvent()).isNull();
        assertThat(result.responseEvent()).isNull();
        assertThat(result.execution()).isNull();

        verify(adapter, never()).execute(any(), any());

        ArgumentCaptor<ExecutionEventDto.AppendRequest> requestCaptor =
                ArgumentCaptor.forClass(ExecutionEventDto.AppendRequest.class);

        verify(eventService, times(1)).append(
                eq(baselineContext.runId()),
                requestCaptor.capture(),
                eq(ACTOR)
        );

        assertThat(requestCaptor.getValue().eventType())
                .isEqualTo(ExecutionEventType.POLICY_EVALUATED);
        assertThat(requestCaptor.getValue().reasonCode())
                .isEqualTo("TEST_DENY");
    }

    private SandboxExecutionContext context(TestRunMode mode) {
        return new SandboxExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                mode,
                "FA-02",
                "CUST-1001"
        );
    }

    private ExecutionEventDto.Event event(
            SandboxExecutionContext context,
            long sequence,
            ExecutionEventType eventType
    ) {
        ObjectNode empty = objectMapper.createObjectNode();
        return new ExecutionEventDto.Event(
                "1.0",
                UUID.randomUUID(),
                context.traceId(),
                context.runId(),
                context.caseRunId(),
                sequence,
                Instant.EPOCH,
                eventType,
                proposal.toolName(),
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
