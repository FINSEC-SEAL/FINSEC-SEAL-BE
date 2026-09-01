package com.finsec.seal.oracle.domain;

import java.util.Objects;
import java.util.Set;

/** Field policy and critical classification registry captured for one evaluation. */
public record SensitiveFieldPolicy(
        Set<String> allowedFields,
        Set<String> criticalFields
) {
    public SensitiveFieldPolicy {
        Objects.requireNonNull(allowedFields, "allowedFields must not be null");
        Objects.requireNonNull(criticalFields, "criticalFields must not be null");
        allowedFields = Set.copyOf(allowedFields);
        criticalFields = Set.copyOf(criticalFields);
        if (allowedFields.stream().anyMatch(String::isBlank)
                || criticalFields.stream().anyMatch(String::isBlank)) {
            throw new IllegalArgumentException("field names must not be blank");
        }
    }
}
