package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.evidence.ExecutionEventDto;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

class PolicyGatewayResultInvariantTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void denyCannotCarryToolExecutionEvidence() {
        ExecutionEventDto.Event policyEvent = event(1L, ExecutionEventType.POLICY_EVALUATED);
        ExecutionEventDto.Event requestEvent = event(2L, ExecutionEventType.TOOL_REQUEST);
        ExecutionEventDto.Event responseEvent = event(3L, ExecutionEventType.TOOL_RESPONSE);
        ToolAdapter.ToolExecutionResult execution = new ToolAdapter.ToolExecutionResult(
                objectMapper.createObjectNode().put("ok", true),
                false
        );

        assertEvidenceIncomplete(() -> new PolicyGateway.GatewayResult(
                new PolicyGateway.PolicyDecision(false, "DENY"),
                policyEvent,
                requestEvent,
                responseEvent,
                execution
        ));
    }

    @Test
    void allowRequiresCompleteToolExecutionEvidence() {
        ExecutionEventDto.Event policyEvent = event(1L, ExecutionEventType.POLICY_EVALUATED);

        assertEvidenceIncomplete(() -> new PolicyGateway.GatewayResult(
                new PolicyGateway.PolicyDecision(true, "ALLOW"),
                policyEvent,
                null,
                null,
                null
        ));
    }

    @Test
    void policyDecisionIsRequired() {
        ExecutionEventDto.Event policyEvent = event(1L, ExecutionEventType.POLICY_EVALUATED);

        assertEvidenceIncomplete(() -> new PolicyGateway.GatewayResult(
                null,
                policyEvent,
                null,
                null,
                null
        ));
    }

    @Test
    void policyEventIsRequired() {
        assertEvidenceIncomplete(() -> new PolicyGateway.GatewayResult(
                new PolicyGateway.PolicyDecision(false, "DENY"),
                null,
                null,
                null,
                null
        ));
    }

    @Test
    void dispatchResultRejectsContradictoryDecisionAndExecutionEvidence() {
        ExecutionEventDto.Event policyEvent = event(1L, ExecutionEventType.POLICY_EVALUATED);
        ExecutionEventDto.Event requestEvent = event(2L, ExecutionEventType.TOOL_REQUEST);
        ExecutionEventDto.Event responseEvent = event(3L, ExecutionEventType.TOOL_RESPONSE);
        ToolAdapter.ToolExecutionResult execution = new ToolAdapter.ToolExecutionResult(
                objectMapper.createObjectNode().put("ok", true),
                false
        );

        assertEvidenceIncomplete(() -> new ToolDispatcher.DispatchResult(
                new PolicyGateway.PolicyDecision(false, "DENY"),
                policyEvent,
                requestEvent,
                responseEvent,
                execution
        ));
    }

    private void assertEvidenceIncomplete(ThrowingAction action) {
        assertThatThrownBy(action::run)
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE)
                );
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
                "CUSTOMER_DATA_READ",
                empty,
                empty,
                "sha256:" + "a".repeat(64),
                empty,
                eventType == ExecutionEventType.POLICY_EVALUATED ? "TEST" : null,
                empty,
                null,
                "sha256:" + "b".repeat(64)
        );
    }

    @FunctionalInterface
    private interface ThrowingAction {
        void run();
    }
}
