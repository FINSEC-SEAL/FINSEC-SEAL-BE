package com.finsecseal.policy;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Immutable, prevalidated contract facts required by the Egress policy stage.
 */
public record PolicyEgressFacts(
        String requestedTool,
        List<CatalogTool> catalogTools,
        boolean externalEgressAllowed,
        List<String> allowedDestinations
) {

    public PolicyEgressFacts {
        requestedTool = requireNonBlank(requestedTool, "requestedTool");
        catalogTools = copyUniqueCatalogTools(catalogTools);
        allowedDestinations = copyUniqueDestinations(allowedDestinations);

        if (externalEgressAllowed) {
            throw new IllegalArgumentException("P0 external egress must remain disabled");
        }
        if (!allowedDestinations.isEmpty()) {
            throw new IllegalArgumentException("P0 destination exceptions are not supported");
        }
    }

    public Optional<CatalogTool> requestedCatalogTool() {
        return catalogTools.stream()
                .filter(tool -> tool.name().equals(requestedTool))
                .findFirst();
    }

    private static List<CatalogTool> copyUniqueCatalogTools(List<CatalogTool> values) {
        if (values == null) {
            throw new IllegalArgumentException("catalogTools must not be null");
        }

        Set<String> names = new HashSet<>();
        for (CatalogTool tool : values) {
            if (tool == null) {
                throw new IllegalArgumentException("catalogTools must not contain null entries");
            }
            if (!names.add(tool.name())) {
                throw new IllegalArgumentException(
                        "catalogTools must not contain duplicate tool names"
                );
            }
        }
        return List.copyOf(values);
    }

    private static List<String> copyUniqueDestinations(List<String> values) {
        if (values == null) {
            throw new IllegalArgumentException("allowedDestinations must not be null");
        }

        Set<String> unique = new HashSet<>();
        for (int index = 0; index < values.size(); index++) {
            String value = requireNonBlank(
                    values.get(index),
                    "allowedDestinations[" + index + "]"
            );
            if (!unique.add(value)) {
                throw new IllegalArgumentException(
                        "allowedDestinations must not contain duplicate values"
                );
            }
        }
        return List.copyOf(values);
    }

    private static String requireNonBlank(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }

    public record CatalogTool(String name, EgressClassification egressClassification) {

        public CatalogTool {
            name = requireNonBlank(name, "catalog tool name");
            if (egressClassification == null) {
                throw new IllegalArgumentException(
                        "catalog egress classification must not be null"
                );
            }
        }
    }

    public enum EgressClassification {
        INTERNAL,
        EXTERNAL
    }
}
