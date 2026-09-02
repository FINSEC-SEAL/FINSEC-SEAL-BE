package com.finsecseal.sandbox;

import com.finsecseal.common.domain.TestRunMode;
import java.util.UUID;

public record SandboxExecutionContext(
        UUID runId,
        UUID caseRunId,
        UUID traceId,
        TestRunMode mode,
        String caseKey,
        String currentApplicantId
) {
    public UUID namespaceId() {
        return runId;
    }
}
