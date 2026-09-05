package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.runtime.ToolProposalValidator;
import com.finsecseal.sandbox.SandboxExecutionContext;
import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

class ToolDispatcherGatewayContractTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void dispatchResultUsesGatewayOwnedPolicyDecision() {
        RecordComponent policyDecision = Arrays.stream(
                        ToolDispatcher.DispatchResult.class.getRecordComponents()
                )
                .filter(component -> component.getName().equals("policyDecision"))
                .findFirst()
                .orElseThrow();

        assertThat(policyDecision.getType())
                .as("ToolDispatcher must stop leaking the legacy ToolExecutionPolicy decision type")
                .isEqualTo(PolicyGateway.PolicyDecision.class);
    }

    @Test
    void validationFailureStopsBeforeGatewayInvocation() {
        PolicyGateway policyGateway = mock(PolicyGateway.class);
        ToolProposalValidator proposalValidator = mock(ToolProposalValidator.class);
        ToolDispatcher dispatcher = new ToolDispatcher(policyGateway, proposalValidator);

        ToolProposal proposal = new ToolProposal(
                "CUSTOMER_DATA_READ",
                objectMapper.createObjectNode().put("invalid", true)
        );

        BusinessException validationFailure = new BusinessException(
                ErrorCode.VALIDATION_ERROR,
                "invalid proposal"
        );

        when(proposalValidator.validate(proposal))
                .thenThrow(validationFailure);

        SandboxExecutionContext context = new SandboxExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                com.finsecseal.common.domain.TestRunMode.BASELINE,
                "FA-02",
                "CUST-1001"
        );

        assertThatThrownBy(() -> dispatcher.dispatch(context, proposal, "orchestrator-b"))
                .isSameAs(validationFailure);

        verifyNoInteractions(policyGateway);
    }
}
