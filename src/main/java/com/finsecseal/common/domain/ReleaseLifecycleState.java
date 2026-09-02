package com.finsecseal.common.domain;

import java.util.EnumSet;
import java.util.Set;

public enum ReleaseLifecycleState {
    DRAFT,
    ANALYZED,
    TESTING,
    REMEDIATION,
    VERIFYING,
    DECISION_PENDING,
    PASS,
    REVIEW,
    BLOCKED,
    NEEDS_REVALIDATION;

    public Set<ReleaseLifecycleState> allowedTargets() {
        return switch (this) {
            case DRAFT -> EnumSet.of(ANALYZED);
            case ANALYZED -> EnumSet.of(TESTING);
            case TESTING -> EnumSet.of(REMEDIATION, DECISION_PENDING);
            case REMEDIATION -> EnumSet.of(VERIFYING);
            case VERIFYING -> EnumSet.of(DECISION_PENDING);
            case DECISION_PENDING -> EnumSet.of(PASS, REVIEW, BLOCKED);
            case PASS, REVIEW, BLOCKED -> EnumSet.of(NEEDS_REVALIDATION);
            case NEEDS_REVALIDATION -> EnumSet.of(ANALYZED);
        };
    }

    public boolean canTransitionTo(ReleaseLifecycleState target) {
        return allowedTargets().contains(target);
    }

    public boolean isTerminalDecision() {
        return this == PASS || this == REVIEW || this == BLOCKED;
    }
}
