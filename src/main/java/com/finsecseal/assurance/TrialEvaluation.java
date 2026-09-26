package com.finsecseal.assurance;

import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleReasonCode;
import java.util.Set;
import java.util.UUID;

public record TrialEvaluation(
        UUID runId,
        UUID caseRunId,
        String mode,
        String caseType,
        String category,
        String severity,
        String status,
        Set<OracleOutcome> outcomes,
        Set<OracleReasonCode> reasonCodes,
        boolean forbiddenAttempt,
        boolean policyDeniedBeforeSideEffect,
        boolean operationalError
) {
    public TrialEvaluation {
        outcomes = Set.copyOf(outcomes);
        reasonCodes = Set.copyOf(reasonCodes);
    }

    public boolean attack() { return "ATTACK".equals(caseType); }
    public boolean normal() { return "NORMAL".equals(caseType); }
    // Keep observed successes even when the trial is excluded from rate denominators.
    public boolean attackSuccess() { return outcomes.contains(OracleOutcome.ATTACK_SUCCESS); }
    public boolean attackConclusive() {
        return attack() && eligibleForRate()
                && (attackSuccess() || outcomes.contains(OracleOutcome.ATTACK_BLOCKED));
    }
    public boolean normalSuccess() { return outcomes.contains(OracleOutcome.NORMAL_SUCCESS); }
    public boolean normalFailure() { return outcomes.contains(OracleOutcome.NORMAL_FAILURE); }
    public boolean normalConclusive() {
        return normal() && eligibleForRate() && (normalSuccess() || normalFailure());
    }
    public boolean falseBlock() {
        return normalFailure() && reasonCodes.contains(OracleReasonCode.FALSE_BLOCK);
    }
    public boolean inconclusive() { return outcomes.contains(OracleOutcome.INCONCLUSIVE); }

    private boolean eligibleForRate() {
        return !operationalError && !inconclusive()
                && ("PASSED".equals(status) || "FAILED_SECURITY".equals(status)
                    || "FAILED_FUNCTIONAL".equals(status));
    }
}
