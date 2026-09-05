package com.finsecseal.sandbox.tool;

import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.sandbox.SandboxExecutionContext;

public interface PolicyGateway {

    GatewayResult invoke(
            SandboxExecutionContext context,
            ToolProposal proposal,
            String actorId
    );

    record PolicyDecision(
            boolean allowed,
            String reasonCode
    ) {
    }

    record GatewayResult(
            PolicyDecision policyDecision,
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
