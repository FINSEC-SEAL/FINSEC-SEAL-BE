package com.finsecseal.policy;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Immutable, prevalidated contract facts required by the Human Approval Boundary stage.
 */
public record PolicyHumanBoundaryFacts(
        String requestedTool,
        List<String> catalogTools,
        List<HighImpactAction> highImpactActions
) {

    public PolicyHumanBoundaryFacts {
        requestedTool = requireNonBlank(requestedTool, "requestedTool");
        catalogTools = copyUniqueCatalogTools(catalogTools);
        highImpactActions = copyUniqueHighImpactActions(highImpactActions);
        validateCatalogReferences(catalogTools, highImpactActions);
    }

    public boolean isRequestedToolCatalogKnown() {
        return catalogTools.contains(requestedTool);
    }

    public Optional<HighImpactAction> requestedHighImpactAction() {
        return highImpactActions.stream()
                .filter(action -> action.toolName().equals(requestedTool))
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

    private static List<HighImpactAction> copyUniqueHighImpactActions(
            List<HighImpactAction> values
    ) {
        if (values == null) {
            throw new IllegalArgumentException("highImpactActions must not be null");
        }

        Set<String> unique = new HashSet<>();
        for (HighImpactAction action : values) {
            if (action == null) {
                throw new IllegalArgumentException(
                        "highImpactActions must not contain null entries"
                );
            }
            if (!unique.add(action.toolName())) {
                throw new IllegalArgumentException(
                        "highImpactActions must not contain duplicate tool names"
                );
            }
        }
        return List.copyOf(values);
    }

    private static void validateCatalogReferences(
            List<String> catalogTools,
            List<HighImpactAction> highImpactActions
    ) {
        Set<String> catalogNames = Set.copyOf(catalogTools);
        for (HighImpactAction action : highImpactActions) {
            if (!catalogNames.contains(action.toolName())) {
                throw new IllegalArgumentException(
                        "highImpactActions must reference catalog tools"
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

    public record HighImpactAction(String toolName, BoundaryMode mode) {

        public HighImpactAction {
            toolName = requireNonBlank(toolName, "high-impact tool name");
            if (mode == null) {
                throw new IllegalArgumentException("high-impact boundary mode must not be null");
            }
        }
    }

    public enum BoundaryMode {
        HUMAN_ONLY
    }
}
