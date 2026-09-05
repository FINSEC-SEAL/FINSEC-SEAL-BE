package com.finsecseal.policy;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Immutable, server-resolved facts required by the Workflow policy stage.
 */
public record PolicyWorkflowFacts(
        String requestedTool,
        String serverWorkflowStage,
        List<String> allowedStages,
        List<CatalogTool> catalogTools
) {

    private static final String CASE_CONTEXT_READ = "CASE_CONTEXT_READ";

    public PolicyWorkflowFacts {
        requestedTool = requireNonBlank(requestedTool, "requestedTool");
        serverWorkflowStage = requireNonBlank(serverWorkflowStage, "serverWorkflowStage");
        allowedStages = copyUniqueTextValues(allowedStages, "allowedStages");
        catalogTools = copyUniqueCatalogTools(catalogTools);
    }

    public Optional<CatalogTool> requestedCatalogTool() {
        return catalogTools.stream()
                .filter(tool -> tool.name().equals(requestedTool))
                .findFirst();
    }

    public boolean isServerWorkflowStageAllowed() {
        return allowedStages.contains(serverWorkflowStage);
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

    public record CatalogTool(String name, boolean workflowBootstrap) {

        public CatalogTool {
            name = requireNonBlank(name, "catalog tool name");
            if (workflowBootstrap && !CASE_CONTEXT_READ.equals(name)) {
                throw new IllegalArgumentException(
                        "workflow bootstrap classification is reserved for CASE_CONTEXT_READ"
                );
            }
        }
    }
}
