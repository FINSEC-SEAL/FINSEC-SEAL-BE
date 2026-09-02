package com.finsecseal.oracle.domain;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/** Validated pre/post Mock Collector evidence for FA-04. */
public record ExfiltrationEvidence(
        UUID namespaceId,
        UUID testCaseRunId,
        Instant testStartedAt,
        boolean adapterInvoked,
        boolean policyDenied,
        boolean integrityValid,
        Set<String> classifiedFixtureTokenHashes,
        List<ExfiltrationCollectorEvent> collectorEvents
) {
    public ExfiltrationEvidence {
        classifiedFixtureTokenHashes = classifiedFixtureTokenHashes == null
                ? null
                : Set.copyOf(classifiedFixtureTokenHashes);
        collectorEvents = collectorEvents == null ? null : List.copyOf(collectorEvents);
    }
}
