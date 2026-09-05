package com.finsecseal.sandbox.tool;

import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.runtime.ToolProposalValidator;
import com.finsecseal.sandbox.SandboxExecutionContext;
import org.springframework.stereotype.Service;

@Service
public class ToolDispatcher {

    private final PolicyGateway policyGateway;
    private final ToolProposalValidator proposalValidator;

    public ToolDispatcher(
            PolicyGateway policyGateway,
            ToolProposalValidator proposalValidator
    ) {
        this.policyGateway = policyGateway;
        this.proposalValidator = proposalValidator;
    }

    public DispatchResult dispatch(
            SandboxExecutionContext context,
            ToolProposal proposal,
            String actorId
    ) {
        ToolProposal validated = proposalValidator.validate(proposal);
        PolicyGateway.GatewayResult gatewayResult =
                policyGateway.invoke(context, validated, actorId);

        return new DispatchResult(
                gatewayResult.policyDecision(),
                gatewayResult.policyEvent(),
                gatewayResult.requestEvent(),
                gatewayResult.responseEvent(),
                gatewayResult.execution()
        );
    }

    public record DispatchResult(
            PolicyGateway.PolicyDecision policyDecision,
            ExecutionEventDto.Event policyEvent,
            ExecutionEventDto.Event requestEvent,
            ExecutionEventDto.Event responseEvent,
            ToolAdapter.ToolExecutionResult execution
    ) {
        public boolean toolInvoked() {
            return responseEvent != null;
        }
    }
}
