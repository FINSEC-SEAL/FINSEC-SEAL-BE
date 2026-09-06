package com.finsecseal.runtime;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import java.util.UUID;

public record ToolInvocation(
        ToolProposal proposal,
        UUID toolCallId,
        String requestDigest
) {
    public ToolInvocation {
        if (proposal == null
                || toolCallId == null
                || requestDigest == null
                || !requestDigest.matches("sha256:[0-9a-f]{64}")) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Tool invocation requires proposal, toolCallId, and SHA-256 request digest"
            );
        }
    }
}
