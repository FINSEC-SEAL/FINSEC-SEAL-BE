package com.finsecseal.policy;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Immutable, prevalidated request and trusted policy facts for Field Scope.
 */
public record PolicyFieldScopeFacts(
        String requestedTool,
        Optional<List<String>> requestedFields,
        List<ToolOutputSchema> catalogSchemas,
        List<FieldPolicy> fieldPolicies
) {

    public PolicyFieldScopeFacts {
        requestedTool = requireConfigurationText(requestedTool, "requestedTool");
        requestedFields = copyRequestedFields(requestedFields);
        catalogSchemas = copyUniqueSchemas(catalogSchemas);
        fieldPolicies = copyUniquePolicies(fieldPolicies);
        validatePolicyCrossReferences(catalogSchemas, fieldPolicies);

        if (findPolicy(fieldPolicies, requestedTool).isPresent()) {
            List<String> fields = requestedFields.orElseThrow(() ->
                    invalidRequest(
                            "requestedFields is required by the active field policy"
                    ));
            if (fields.isEmpty()) {
                throw invalidRequest(
                        "requestedFields must not be empty for the active field policy"
                );
            }
        }
    }

    public boolean isRequestedToolCatalogKnown() {
        return catalogSchemas.stream()
                .anyMatch(schema -> schema.toolName().equals(requestedTool));
    }

    public Optional<FieldPolicy> requestedFieldPolicy() {
        return findPolicy(fieldPolicies, requestedTool);
    }

    private static Optional<List<String>> copyRequestedFields(
            Optional<List<String>> value
    ) {
        if (value == null) {
            throw invalidRequest("requestedFields must not be null");
        }
        if (value.isEmpty()) {
            return Optional.empty();
        }

        List<String> source = value.orElseThrow();
        List<String> snapshot = new ArrayList<>(source);
        Set<String> unique = new HashSet<>();
        for (int index = 0; index < snapshot.size(); index++) {
            String field = snapshot.get(index);
            if (field == null || field.isBlank()) {
                throw invalidRequest(
                        "requestedFields[" + index + "] must not be blank"
                );
            }
            if (!unique.add(field)) {
                throw invalidRequest("requestedFields must not contain duplicates");
            }
        }
        return Optional.of(List.copyOf(snapshot));
    }

    private static List<ToolOutputSchema> copyUniqueSchemas(
            List<ToolOutputSchema> values
    ) {
        if (values == null) {
            throw new IllegalArgumentException("catalogSchemas must not be null");
        }

        Set<String> unique = new HashSet<>();
        for (ToolOutputSchema schema : values) {
            if (schema == null) {
                throw new IllegalArgumentException(
                        "catalogSchemas must not contain null entries"
                );
            }
            if (!unique.add(schema.toolName())) {
                throw new IllegalArgumentException(
                        "catalogSchemas must not contain duplicate tool names"
                );
            }
        }
        return List.copyOf(values);
    }

    private static List<FieldPolicy> copyUniquePolicies(
            List<FieldPolicy> values
    ) {
        if (values == null) {
            throw new IllegalArgumentException("fieldPolicies must not be null");
        }

        Set<String> unique = new HashSet<>();
        for (FieldPolicy policy : values) {
            if (policy == null) {
                throw new IllegalArgumentException(
                        "fieldPolicies must not contain null entries"
                );
            }
            if (!unique.add(policy.toolName())) {
                throw new IllegalArgumentException(
                        "fieldPolicies must not contain duplicate tool names"
                );
            }
        }
        return List.copyOf(values);
    }

    private static void validatePolicyCrossReferences(
            List<ToolOutputSchema> schemas,
            List<FieldPolicy> policies
    ) {
        for (FieldPolicy policy : policies) {
            ToolOutputSchema schema = schemas.stream()
                    .filter(candidate -> candidate.toolName()
                            .equals(policy.toolName()))
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException(
                            "fieldPolicies must reference catalog tools"
                    ));
            if (!schema.outputFields().containsAll(policy.allowedFields())) {
                throw new IllegalArgumentException(
                        "fieldPolicies may allow only declared Tool output fields"
                );
            }
        }
    }

    private static Optional<FieldPolicy> findPolicy(
            List<FieldPolicy> policies,
            String toolName
    ) {
        return policies.stream()
                .filter(policy -> policy.toolName().equals(toolName))
                .findFirst();
    }

    private static List<String> copyUniqueConfigurationFields(
            List<String> values,
            String field
    ) {
        if (values == null) {
            throw new IllegalArgumentException(field + " must not be null");
        }

        List<String> snapshot = new ArrayList<>(values);
        Set<String> unique = new HashSet<>();
        for (int index = 0; index < snapshot.size(); index++) {
            String value = requireConfigurationText(
                    snapshot.get(index),
                    field + "[" + index + "]"
            );
            if (!unique.add(value)) {
                throw new IllegalArgumentException(
                        field + " must not contain duplicates"
                );
            }
        }
        return List.copyOf(snapshot);
    }

    private static String requireConfigurationText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }

    private static InvalidPolicyScopeRequestException invalidRequest(
            String message
    ) {
        return new InvalidPolicyScopeRequestException(message);
    }

    public record ToolOutputSchema(String toolName, List<String> outputFields) {

        public ToolOutputSchema {
            toolName = requireConfigurationText(
                    toolName,
                    "catalog schema tool name"
            );
            outputFields = copyUniqueConfigurationFields(
                    outputFields,
                    "catalog outputFields"
            );
        }
    }

    public record FieldPolicy(
            String toolName,
            List<String> allowedFields,
            boolean denyUnknown
    ) {

        public FieldPolicy {
            toolName = requireConfigurationText(
                    toolName,
                    "field policy tool name"
            );
            allowedFields = copyUniqueConfigurationFields(
                    allowedFields,
                    "policy allowedFields"
            );
            if (!denyUnknown) {
                throw new IllegalArgumentException(
                        "P0 field policy requires denyUnknown=true"
                );
            }
        }
    }
}
