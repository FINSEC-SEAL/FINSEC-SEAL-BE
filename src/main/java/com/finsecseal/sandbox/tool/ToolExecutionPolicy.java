package com.finsecseal.sandbox.tool;

import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.sandbox.SandboxExecutionContext;

public interface ToolExecutionPolicy {

    boolean supports(TestRunMode mode);

    PolicyDecision evaluate(SandboxExecutionContext context, ToolProposal proposal);

    record PolicyDecision(boolean allowed, String reasonCode) {
    }
}
