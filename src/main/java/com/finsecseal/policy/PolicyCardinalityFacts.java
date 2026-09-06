package com.finsecseal.policy;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Immutable, prevalidated facts required by the pre-call Cardinality policy stage.
 */
public record PolicyCardinalityFacts(
        String requestedTool,
        int normalizedRequestedRecordCount,
        List<String> catalogTools,
        List<CardinalityPolicy> cardinalityPolicies
) {

    public PolicyCardinalityFacts {
        requestedTool = requireNonBlank(requestedTool, "requestedTool");
        if (normalizedRequestedRecordCount < 0) {
            throw new IllegalArgumentException(
                    "normalizedRequestedRecordCount must not be negative"
            );
        }
        catalogTools = copyUniqueCatalogTools(catalogTools);
        cardinalityPolicies = copyUniquePolicies(cardinalityPolicies);
        validateCatalogReferences(catalogTools, cardinalityPolicies);
    }

    public boolean isRequestedToolCatalogKnown() {
        return catalogTools.contains(requestedTool);
    }

    public Optional<CardinalityPolicy> requestedCardinalityPolicy() {
        return cardinalityPolicies.stream()
                .filter(policy -> policy.toolName().equals(requestedTool))
                .findFirst();
    }

    private static List<String> copyUniqueCatalogTools(List<String> values) {
        if (values == null) {
            throw new IllegalArgumentException("catalogTools must not be null");
        }

        Set<String> unique = new HashSet<>();
        for (int index = 0; index < values.size(); index++) {
            String value = requireNonBlank(values.get(index), "catalogTools[" + index + "]");
            if (!unique.add(value)) {
                throw new IllegalArgumentException(
                        "catalogTools must not contain duplicate tool names"
                );
            }
        }
        return List.copyOf(values);
    }

    private static List<CardinalityPolicy> copyUniquePolicies(
            List<CardinalityPolicy> values
    ) {
        if (values == null) {
            throw new IllegalArgumentException("cardinalityPolicies must not be null");
        }

        Set<String> unique = new HashSet<>();
        for (CardinalityPolicy policy : values) {
            if (policy == null) {
                throw new IllegalArgumentException(
                        "cardinalityPolicies must not contain null entries"
                );
            }
            if (!unique.add(policy.toolName())) {
                throw new IllegalArgumentException(
                        "cardinalityPolicies must not contain duplicate tool names"
                );
            }
        }
        return List.copyOf(values);
    }

    private static void validateCatalogReferences(
            List<String> catalogTools,
            List<CardinalityPolicy> policies
    ) {
        Set<String> catalogNames = Set.copyOf(catalogTools);
        for (CardinalityPolicy policy : policies) {
            if (!catalogNames.contains(policy.toolName())) {
                throw new IllegalArgumentException(
                        "cardinalityPolicies must reference catalog tools"
                );
            }
        }
    }

    private static String requireNonBlank(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }

    public record CardinalityPolicy(String toolName, int maxRequestedRecords) {

        public CardinalityPolicy {
            toolName = requireNonBlank(toolName, "cardinality policy tool name");
            if (maxRequestedRecords <= 0) {
                throw new IllegalArgumentException(
                        "maxRequestedRecords must be greater than zero"
                );
            }
        }
    }
}
