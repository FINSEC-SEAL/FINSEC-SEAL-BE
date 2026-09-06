package com.finsecseal.policy;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Immutable, prevalidated facts used by the Tool and Operation policy stages.
 */
public record PolicyToolAuthorizationFacts(
        String requestedTool,
        String requestedOperation,
        List<CatalogTool> catalogTools,
        List<String> allowedTools,
        boolean externalEgressExplicitlyDenied,
        List<String> humanOnlyTools
) {

    public PolicyToolAuthorizationFacts {
        requestedTool = requireNonBlank(requestedTool, "requestedTool");
        requestedOperation = requireNonBlank(requestedOperation, "requestedOperation");
        catalogTools = copyUniqueCatalogTools(catalogTools);
        allowedTools = copyUniqueTextValues(allowedTools, "allowedTools");
        humanOnlyTools = copyUniqueTextValues(humanOnlyTools, "humanOnlyTools");
    }

    public Optional<CatalogTool> requestedCatalogTool() {
        return catalogTools.stream()
                .filter(tool -> tool.name().equals(requestedTool))
                .findFirst();
    }

    public boolean isRequestedToolAllowed() {
        return allowedTools.contains(requestedTool);
    }

    public boolean isRequestedToolHumanOnly() {
        return humanOnlyTools.contains(requestedTool);
    }

    private static List<CatalogTool> copyUniqueCatalogTools(List<CatalogTool> values) {
        if (values == null) {
            throw new IllegalArgumentException("catalogTools must not be null");
        }

        Set<String> names = new HashSet<>();
        for (int index = 0; index < values.size(); index++) {
            CatalogTool tool = values.get(index);
            if (tool == null) {
                throw new IllegalArgumentException("catalogTools must not contain null entries");
            }
            if (!names.add(tool.name())) {
                throw new IllegalArgumentException("catalogTools must not contain duplicate tool names");
            }
        }
        return List.copyOf(values);
    }

    private static List<String> copyUniqueTextValues(List<String> values, String field) {
        if (values == null) {
            throw new IllegalArgumentException(field + " must not be null");
        }

        Set<String> unique = new HashSet<>();
        for (int index = 0; index < values.size(); index++) {
            String value = requireNonBlank(values.get(index), field + "[" + index + "]");
            if (!unique.add(value)) {
                throw new IllegalArgumentException(field + " must not contain duplicate values");
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

    public record CatalogTool(
            String name,
            String operation,
            boolean externalEgressTool
    ) {

        public CatalogTool {
            name = requireNonBlank(name, "catalog tool name");
            operation = requireNonBlank(operation, "catalog tool operation");
        }
    }
}
