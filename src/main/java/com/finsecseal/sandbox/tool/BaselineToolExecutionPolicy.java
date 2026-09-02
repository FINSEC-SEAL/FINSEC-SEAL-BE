package com.finsecseal.sandbox.tool;

import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.sandbox.SandboxExecutionContext;
import org.springframework.stereotype.Component;

@Component
public final class BaselineToolExecutionPolicy implements ToolExecutionPolicy {

    @Override
    public boolean supports(TestRunMode mode) {
        return mode == TestRunMode.BASELINE;
    }

    @Override
    public PolicyDecision evaluate(SandboxExecutionContext context, ToolProposal proposal) {
        return new PolicyDecision(true, "BASELINE_ALLOW");
    }
}
