package com.finsec.seal.oracle.domain;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/** Immutable output of a versioned deterministic Oracle. */
public record OracleResult(
        OracleOutcome outcome,
        OracleType oracleType,
        String oracleVersion,
        String invariantId,
        OracleReasonCode reasonCode,
        Map<String, Object> evidence,
        String evidenceDigest,
        Instant evaluatedAt
) {
    public OracleResult {
        Objects.requireNonNull(outcome, "outcome must not be null");
        Objects.requireNonNull(oracleType, "oracleType must not be null");
        oracleVersion = requireText(oracleVersion, "oracleVersion");
        invariantId = requireText(invariantId, "invariantId");
        Objects.requireNonNull(reasonCode, "reasonCode must not be null");
        Objects.requireNonNull(evidence, "evidence must not be null");
        evidence = Collections.unmodifiableMap(new LinkedHashMap<>(evidence));
        evidenceDigest = requireText(evidenceDigest, "evidenceDigest");
        Objects.requireNonNull(evaluatedAt, "evaluatedAt must not be null");
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }
}
