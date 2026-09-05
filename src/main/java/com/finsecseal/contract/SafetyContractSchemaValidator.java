package com.finsecseal.contract;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;

@Component
public class SafetyContractSchemaValidator {

    private static final String SCHEMA_VERSION = "1.0";
    private static final Set<String> ROOT_FIELDS = Set.of(
            "schemaVersion", "contractId", "version", "purpose", "allowedTools", "resourcePolicies",
            "customerScope", "fieldPolicy", "cardinality", "externalEgress", "workflow",
            "highImpactActions", "toolTrust", "outputPolicy", "metadata"
    );
    private static final Set<String> RESOURCE_POLICY_FIELDS = Set.of("caseScope", "documentScope");
    private static final Set<String> CUSTOMER_SCOPE_FIELDS = Set.of("type");
    private static final Set<String> FIELD_POLICY_FIELDS = Set.of("allowed", "denyUnknown");
    private static final Set<String> CARDINALITY_FIELDS = Set.of("maxRequestedRecords", "maxReturnedRecords");
    private static final Set<String> EGRESS_FIELDS = Set.of("allowed", "allowedDestinations");
    private static final Set<String> WORKFLOW_FIELDS = Set.of("allowedStages");
    private static final Set<String> TOOL_TRUST_FIELDS = Set.of("requireTrustedTool", "allowedTrustLevels");
    private static final Set<String> OUTPUT_POLICY_FIELDS = Set.of("reviewStatusAllowed");
    private static final Set<String> METADATA_FIELDS = Set.of("templateVersion", "validatorVersion");

    public ValidationResult validate(JsonNode contract) {
        List<Issue> issues = new ArrayList<>();
        if (contract == null || !contract.isObject()) {
            return new ValidationResult(false, List.of(issue("/", "TYPE", "Safety Contract must be a JSON object")));
        }

        rejectUnknown(contract, "", ROOT_FIELDS, issues);
        validateSchemaVersion(contract.path("schemaVersion"), issues);
        validateOptionalText(contract, "contractId", "/contractId", issues);
        validateOptionalInteger(contract, "version", "/version", issues);
        validateOptionalText(contract, "purpose", "/purpose", issues);
        validateStringSet(contract.path("allowedTools"), "/allowedTools", contract.has("allowedTools"), issues);

        validateDynamicObject(
                contract.path("resourcePolicies"),
                "/resourcePolicies",
                contract.has("resourcePolicies"),
                RESOURCE_POLICY_FIELDS,
                (value, path) -> {
                    validateOptionalText(value, "caseScope", path + "/caseScope", issues);
                    validateOptionalText(value, "documentScope", path + "/documentScope", issues);
                },
                issues
        );
        validateFixedObject(
                contract.path("customerScope"),
                "/customerScope",
                contract.has("customerScope"),
                CUSTOMER_SCOPE_FIELDS,
                value -> validateOptionalText(value, "type", "/customerScope/type", issues),
                issues
        );
        validateDynamicObject(
                contract.path("fieldPolicy"),
                "/fieldPolicy",
                contract.has("fieldPolicy"),
                FIELD_POLICY_FIELDS,
                (value, path) -> {
                    validateStringSet(value.path("allowed"), path + "/allowed", value.has("allowed"), issues);
                    validateOptionalBoolean(value, "denyUnknown", path + "/denyUnknown", issues);
                },
                issues
        );
        validateDynamicObject(
                contract.path("cardinality"),
                "/cardinality",
                contract.has("cardinality"),
                CARDINALITY_FIELDS,
                (value, path) -> {
                    validateOptionalInteger(value, "maxRequestedRecords", path + "/maxRequestedRecords", issues);
                    validateOptionalInteger(value, "maxReturnedRecords", path + "/maxReturnedRecords", issues);
                },
                issues
        );
        validateFixedObject(
                contract.path("externalEgress"),
                "/externalEgress",
                contract.has("externalEgress"),
                EGRESS_FIELDS,
                value -> {
                    validateOptionalBoolean(value, "allowed", "/externalEgress/allowed", issues);
                    validateStringSet(
                            value.path("allowedDestinations"),
                            "/externalEgress/allowedDestinations",
                            value.has("allowedDestinations"),
                            issues
                    );
                },
                issues
        );
        validateFixedObject(
                contract.path("workflow"),
                "/workflow",
                contract.has("workflow"),
                WORKFLOW_FIELDS,
                value -> validateStringSet(
                        value.path("allowedStages"),
                        "/workflow/allowedStages",
                        value.has("allowedStages"),
                        issues
                ),
                issues
        );
        validateStringMap(
                contract.path("highImpactActions"),
                "/highImpactActions",
                contract.has("highImpactActions"),
                issues
        );
        validateFixedObject(
                contract.path("toolTrust"),
                "/toolTrust",
                contract.has("toolTrust"),
                TOOL_TRUST_FIELDS,
                value -> {
                    validateOptionalBoolean(value, "requireTrustedTool", "/toolTrust/requireTrustedTool", issues);
                    validateStringSet(
                            value.path("allowedTrustLevels"),
                            "/toolTrust/allowedTrustLevels",
                            value.has("allowedTrustLevels"),
                            issues
                    );
                },
                issues
        );
        validateFixedObject(
                contract.path("outputPolicy"),
                "/outputPolicy",
                contract.has("outputPolicy"),
                OUTPUT_POLICY_FIELDS,
                value -> validateStringSet(
                        value.path("reviewStatusAllowed"),
                        "/outputPolicy/reviewStatusAllowed",
                        value.has("reviewStatusAllowed"),
                        issues
                ),
                issues
        );
        validateFixedObject(
                contract.path("metadata"),
                "/metadata",
                contract.has("metadata"),
                METADATA_FIELDS,
                value -> {
                    validateOptionalText(value, "templateVersion", "/metadata/templateVersion", issues);
                    validateOptionalText(value, "validatorVersion", "/metadata/validatorVersion", issues);
                },
                issues
        );

        return new ValidationResult(issues.isEmpty(), issues);
    }

    private void validateSchemaVersion(JsonNode value, List<Issue> issues) {
        if (!value.isString()) {
            issues.add(issue("/schemaVersion", "TYPE", "schemaVersion must be the string 1.0"));
        } else if (!SCHEMA_VERSION.equals(value.stringValue())) {
            issues.add(issue("/schemaVersion", "UNSUPPORTED_SCHEMA_VERSION", "Only Safety Contract schemaVersion 1.0 is supported"));
        }
    }

    private void validateFixedObject(
            JsonNode value,
            String path,
            boolean present,
            Set<String> allowedFields,
            java.util.function.Consumer<JsonNode> validator,
            List<Issue> issues
    ) {
        if (!present) {
            return;
        }
        if (!value.isObject()) {
            issues.add(issue(path, "TYPE", path + " must be a JSON object"));
            return;
        }
        rejectUnknown(value, path, allowedFields, issues);
        validator.accept(value);
    }

    private void validateDynamicObject(
            JsonNode value,
            String path,
            boolean present,
            Set<String> valueFields,
            DynamicValueValidator validator,
            List<Issue> issues
    ) {
        if (!present) {
            return;
        }
        if (!value.isObject()) {
            issues.add(issue(path, "TYPE", path + " must be a JSON object"));
            return;
        }
        sortedFieldNames(value).forEach(key -> {
            String entryPath = path + "/" + escapePointerToken(key);
            JsonNode entry = value.path(key);
            if (!entry.isObject()) {
                issues.add(issue(entryPath, "TYPE", entryPath + " must be a JSON object"));
                return;
            }
            rejectUnknown(entry, entryPath, valueFields, issues);
            validator.validate(entry, entryPath);
        });
    }

    private void validateStringMap(JsonNode value, String path, boolean present, List<Issue> issues) {
        if (!present) {
            return;
        }
        if (!value.isObject()) {
            issues.add(issue(path, "TYPE", path + " must be a JSON object"));
            return;
        }
        sortedFieldNames(value).forEach(key -> {
            JsonNode entry = value.path(key);
            if (!entry.isString()) {
                String entryPath = path + "/" + escapePointerToken(key);
                issues.add(issue(entryPath, "TYPE", entryPath + " must be a string"));
            }
        });
    }

    private void validateStringSet(JsonNode value, String path, boolean present, List<Issue> issues) {
        if (!present) {
            return;
        }
        if (!value.isArray()) {
            issues.add(issue(path, "TYPE", path + " must be an array"));
            return;
        }
        Set<String> normalizedValues = new HashSet<>();
        for (int index = 0; index < value.size(); index++) {
            JsonNode item = value.get(index);
            String itemPath = path + "/" + index;
            if (!item.isString()) {
                issues.add(issue(itemPath, "TYPE", "Set-valued array entries must be strings"));
                continue;
            }
            String normalized = SafetyContractTextNormalizer.normalize(item.stringValue());
            if (!normalizedValues.add(normalized)) {
                issues.add(issue(itemPath, "DUPLICATE_VALUE", "Set-valued arrays must not contain duplicates"));
            }
        }
    }

    private void validateOptionalText(JsonNode parent, String field, String path, List<Issue> issues) {
        if (parent.has(field) && !parent.path(field).isString()) {
            issues.add(issue(path, "TYPE", path + " must be a string"));
        }
    }

    private void validateOptionalInteger(JsonNode parent, String field, String path, List<Issue> issues) {
        if (parent.has(field) && !parent.path(field).isIntegralNumber()) {
            issues.add(issue(path, "TYPE", path + " must be an integer"));
        }
    }

    private void validateOptionalBoolean(JsonNode parent, String field, String path, List<Issue> issues) {
        if (parent.has(field) && !parent.path(field).isBoolean()) {
            issues.add(issue(path, "TYPE", path + " must be a boolean"));
        }
    }

    private void rejectUnknown(JsonNode value, String path, Set<String> allowed, List<Issue> issues) {
        if (!value.isObject()) {
            return;
        }
        sortedFieldNames(value).stream()
                .filter(field -> !allowed.contains(field))
                .forEach(field -> issues.add(issue(
                        path + "/" + escapePointerToken(field),
                        "UNKNOWN_FIELD",
                        "Unknown Safety Contract field"
                )));
    }

    private List<String> sortedFieldNames(JsonNode object) {
        List<String> names = new ArrayList<>();
        object.properties().forEach(entry -> names.add(entry.getKey()));
        names.sort(String::compareTo);
        return names;
    }

    private String escapePointerToken(String value) {
        return value.replace("~", "~0").replace("/", "~1");
    }

    private Issue issue(String path, String code, String message) {
        return new Issue(path.isEmpty() ? "/" : path, code, message);
    }

    @FunctionalInterface
    private interface DynamicValueValidator {
        void validate(JsonNode value, String path);
    }

    public record Issue(String jsonPointer, String code, String message) {
        public Issue {
            Objects.requireNonNull(jsonPointer);
            Objects.requireNonNull(code);
            Objects.requireNonNull(message);
        }
    }

    public record ValidationResult(boolean valid, List<Issue> issues) {
        public ValidationResult {
            issues = List.copyOf(issues);
            if (valid != issues.isEmpty()) {
                throw new IllegalArgumentException("Validation status must match issue presence");
            }
        }
    }
}
