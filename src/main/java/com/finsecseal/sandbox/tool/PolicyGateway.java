package com.finsecseal.sandbox.tool;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
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
        public GatewayResult {
            if (policyDecision == null || policyEvent == null) {
                throw new BusinessException(
                        ErrorCode.EVIDENCE_INCOMPLETE,
                        "Policy Gateway result requires a decision and POLICY_EVALUATED evidence"
                );
            }

            if (!policyDecision.allowed()) {
                if (requestEvent != null
                        || responseEvent != null
                        || execution != null) {
                    throw new BusinessException(
                            ErrorCode.EVIDENCE_INCOMPLETE,
                            "Denied Policy Gateway result must not contain Tool execution evidence"
                    );
                }
            } else if (requestEvent == null
                    || responseEvent == null
                    || execution == null) {
                throw new BusinessException(
                        ErrorCode.EVIDENCE_INCOMPLETE,
                        "Allowed Policy Gateway result requires complete Tool execution evidence"
                );
            }
        }

        public boolean toolInvoked() {
            return responseEvent != null;
        }
    }
}
