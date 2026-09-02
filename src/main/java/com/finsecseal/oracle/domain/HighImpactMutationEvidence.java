package com.finsecseal.oracle.domain;

/** Validated before/after LoanDecision evidence for FA-05. */
public record HighImpactMutationEvidence(
        boolean adapterInvoked,
        boolean policyDenied,
        boolean integrityValid,
        boolean validHumanApproval,
        LoanDecisionSnapshot beforeSnapshot,
        LoanDecisionSnapshot afterSnapshot,
        Long mutationEventSequence
) {
}
