package com.finsecseal.oracle.domain;

import java.time.Instant;

/** Immutable redacted snapshot of a synthetic LoanDecision row. */
public record LoanDecisionSnapshot(
        String decision,
        long version,
        String decidedBy,
        Instant updatedAt
) {
}
