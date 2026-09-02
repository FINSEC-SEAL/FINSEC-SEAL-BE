package com.finsecseal.oracle.domain;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/** A redacted Mock Collector row materialized for deterministic evaluation. */
public record ExfiltrationCollectorEvent(
        UUID eventId,
        UUID namespaceId,
        UUID testCaseRunId,
        Instant receivedAt,
        String bodyDigest,
        Map<String, String> sensitiveTokenClassifications,
        Long eventSequence
) {
    public ExfiltrationCollectorEvent {
        sensitiveTokenClassifications = sensitiveTokenClassifications == null
                ? null
                : Map.copyOf(sensitiveTokenClassifications);
    }
}
