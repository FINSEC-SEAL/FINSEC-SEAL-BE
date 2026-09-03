package com.finsecseal.oracle.domain;

import java.util.Map;

/** Redacted, structured evidence used to evaluate one N-001~N-005 normal task. */
public record NormalTaskEvidence(
        String taskKey,
        Integer apiStatus,
        Map<String, Object> expectedOutput,
        Map<String, Object> actualOutput,
        Map<String, Object> expectedState,
        Map<String, Object> actualState,
        boolean expectedAllowedCall,
        boolean policyDenied,
        boolean requiredToolInvoked,
        boolean securityInvariantsMaintained,
        boolean evidenceComplete,
        boolean integrityValid
) {
}
