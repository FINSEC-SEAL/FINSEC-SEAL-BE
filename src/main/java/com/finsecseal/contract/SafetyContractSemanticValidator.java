package com.finsecseal.contract;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;

/**
 * Applies the deterministic {@code loan-review/1} semantic rules after schema validation.
 *
 * <p>A {@link ValidationStatus#VALID} result is valid only relative to the caller-supplied
 * {@link ContractValidationCatalog}. It is not evidence that a contract is approved, deployable,
 * enforceable, or reconciled with the authoritative release registry.</p>
 */
@Component
public class SafetyContractSemanticValidator {

    private static final String EXPECTED_PURPOSE = "LOAN_DOCUMENT_COMPLETENESS_REVIEW";
    private static final String EXPECTED_TEMPLATE_VERSION = "loan-review/1";
    private static final String EXPECTED_VALIDATOR_VERSION = "1.0";
    private static final String CUSTOMER_DATA_READ = "CUSTOMER_DATA_READ";
    private static final String DOCUMENT_READER = "DOCUMENT_READER";
    private static final String REVIEW_NOTE_WRITE = "REVIEW_NOTE_WRITE";
    private static final String LOAN_DECISION_UPDATE = "LOAN_DECISION_UPDATE";

    private static final List<String> REQUIRED_TOOLS = List.of(
            "CASE_CONTEXT_READ",
            DOCUMENT_READER,
            CUSTOMER_DATA_READ,
            "LOAN_POLICY_SEARCH",
            REVIEW_NOTE_WRITE
    );
    private static final Set<String> REQUIRED_CUSTOMER_FIELDS = Set.of(
            "incomeBand",
            "employmentStatus"
    );
    private static final Set<String> REQUIRED_REVIEW_STATUSES = Set.of(
            "READY_FOR_HUMAN_REVIEW",
            "NEEDS_MORE_DOCUMENTS"
    );
    private static final Set<String> REQUIRED_WORKFLOW_STAGES = Set.of("DOCUMENT_REVIEW");
    private static final Set<String> REQUIRED_TRUST_LEVELS = Set.of("TRUSTED_INTERNAL");

    private static final Comparator<Issue> ISSUE_ORDER = Comparator
            .comparing(Issue::jsonPointer)
            .thenComparing(Issue::code)
            .thenComparing(issue -> issue.severity().name())
            .thenComparing(Issue::message);

    private final SafetyContractSchemaValidator schemaValidator;

    public SafetyContractSemanticValidator(SafetyContractSchemaValidator schemaValidator) {
        this.schemaValidator = Objects.requireNonNull(schemaValidator, "schemaValidator");
    }

    public ValidationResult validate(JsonNode contract, ContractValidationCatalog catalog) {
        SafetyContractSchemaValidator.ValidationResult schemaResult = schemaValidator.validate(contract);
        if (!schemaResult.valid()) {
            List<Issue> schemaIssues = schemaResult.issues().stream()
                    .map(issue -> new Issue(
                            issue.jsonPointer(),
                            issue.code(),
                            IssueSeverity.ERROR,
                            issue.message()
                    ))
                    .sorted(ISSUE_ORDER)
                    .toList();
            return ValidationResult.fromIssues(schemaIssues);
        }

        Objects.requireNonNull(catalog, "catalog");
        List<Issue> issues = new ArrayList<>();

        validateIdentity(contract, issues);
        validateAllowedTools(contract, catalog, issues);
        validateResourcePolicies(contract, catalog, issues);
        validateCustomerScope(contract, issues);
        validateFieldPolicies(contract, catalog, issues);
        validateCardinality(contract, catalog, issues);
        validateEgress(contract, issues);
        validateWorkflow(contract, issues);
        validateHighImpactActions(contract, catalog, issues);
        validateToolTrust(contract, issues);
        validateOutputPolicy(contract, issues);

        issues.sort(ISSUE_ORDER);
        return ValidationResult.fromIssues(issues);
    }

    private void validateIdentity(JsonNode contract, List<Issue> issues) {
        requireNonBlankText(contract.path("contractId"), "/contractId", "CONTRACT_ID_REQUIRED", issues);

        JsonNode version = contract.path("version");
        if (!version.isIntegralNumber()) {
            add(issues, "/version", "CONTRACT_VERSION_REQUIRED", "Contract version is required");
        } else if (version.bigIntegerValue().signum() <= 0) {
            add(issues, "/version", "CONTRACT_VERSION_INVALID", "Contract version must be positive");
        }

        requireExactText(
                contract.path("purpose"),
                "/purpose",
                EXPECTED_PURPOSE,
                "PURPOSE_REQUIRED",
                "PURPOSE_MISMATCH",
                issues
        );
        requireExactText(
                contract.at("/metadata/templateVersion"),
                "/metadata/templateVersion",
                EXPECTED_TEMPLATE_VERSION,
                "TEMPLATE_VERSION_REQUIRED",
                "TEMPLATE_VERSION_MISMATCH",
                issues
        );
        requireExactText(
                contract.at("/metadata/validatorVersion"),
                "/metadata/validatorVersion",
                EXPECTED_VALIDATOR_VERSION,
                "VALIDATOR_VERSION_REQUIRED",
                "VALIDATOR_VERSION_MISMATCH",
                issues
        );
    }

    private void validateAllowedTools(
            JsonNode contract,
            ContractValidationCatalog catalog,
            List<Issue> issues
    ) {
        JsonNode allowedTools = contract.path("allowedTools");
        Set<String> allowed = stringSet(allowedTools);

        REQUIRED_TOOLS.stream()
                .filter(tool -> !allowed.contains(tool))
                .forEach(tool -> add(
                        issues,
                        "/allowedTools",
                        "REQUIRED_TOOL_MISSING",
                        "Required loan-review Tool is missing: " + tool
                ));

        for (int index = 0; index < allowedTools.size(); index++) {
            String tool = allowedTools.get(index).stringValue();
            String pointer = "/allowedTools/" + index;
            if (!catalog.hasEnabledTool(tool)) {
                add(issues, pointer, "TOOL_NOT_IN_RELEASE_CATALOG", "Allowed Tool is not in the supplied release catalog: " + tool);
            }
            if (catalog.hasHighImpactTool(tool)) {
                add(issues, pointer, "HUMAN_ONLY_TOOL_ALLOWED", "HUMAN_ONLY Tool must not be allowed for Agent execution: " + tool);
            }
        }
    }

    private void validateResourcePolicies(
            JsonNode contract,
            ContractValidationCatalog catalog,
            List<Issue> issues
    ) {
        JsonNode policies = contract.path("resourcePolicies");
        validatePolicyToolReferences(policies, "/resourcePolicies", catalog, issues);

        requireExactText(
                policies.at("/" + DOCUMENT_READER + "/caseScope"),
                "/resourcePolicies/" + DOCUMENT_READER + "/caseScope",
                "CURRENT_CASE_ONLY",
                "CASE_SCOPE_REQUIRED",
                "CASE_SCOPE_EXCEEDS_TEMPLATE",
                issues
        );
        requireExactText(
                policies.at("/" + DOCUMENT_READER + "/documentScope"),
                "/resourcePolicies/" + DOCUMENT_READER + "/documentScope",
                "ALLOWED_DOCUMENTS_ONLY",
                "DOCUMENT_SCOPE_REQUIRED",
                "DOCUMENT_SCOPE_EXCEEDS_TEMPLATE",
                issues
        );
        requireExactText(
                policies.at("/" + REVIEW_NOTE_WRITE + "/caseScope"),
                "/resourcePolicies/" + REVIEW_NOTE_WRITE + "/caseScope",
                "CURRENT_CASE_ONLY",
                "CASE_SCOPE_REQUIRED",
                "CASE_SCOPE_EXCEEDS_TEMPLATE",
                issues
        );
    }

    private void validateCustomerScope(JsonNode contract, List<Issue> issues) {
        requireExactText(
                contract.at("/customerScope/type"),
                "/customerScope/type",
                "CURRENT_APPLICANT_ONLY",
                "CUSTOMER_SCOPE_REQUIRED",
                "CUSTOMER_SCOPE_EXCEEDS_TEMPLATE",
                issues
        );
    }

    private void validateFieldPolicies(
            JsonNode contract,
            ContractValidationCatalog catalog,
            List<Issue> issues
    ) {
        JsonNode policies = contract.path("fieldPolicy");
        validatePolicyToolReferences(policies, "/fieldPolicy", catalog, issues);

        sortedFieldNames(policies).forEach(tool -> {
            JsonNode allowedFields = policies.path(tool).path("allowed");
            for (int index = 0; index < allowedFields.size(); index++) {
                String field = allowedFields.get(index).stringValue();
                if (!catalog.hasOutputField(tool, field)) {
                    add(
                            issues,
                            "/fieldPolicy/" + escapePointerToken(tool) + "/allowed/" + index,
                            "FIELD_NOT_IN_TOOL_OUTPUT",
                            "Field is not present in the supplied Tool output schema: " + field
                    );
                }
            }
        });

        JsonNode customerPolicy = policies.path(CUSTOMER_DATA_READ);
        JsonNode allowedFields = customerPolicy.path("allowed");
        Set<String> actualFields = stringSet(allowedFields);
        REQUIRED_CUSTOMER_FIELDS.stream()
                .filter(field -> !actualFields.contains(field))
                .forEach(field -> add(
                        issues,
                        "/fieldPolicy/" + CUSTOMER_DATA_READ + "/allowed",
                        "REQUIRED_FIELD_MISSING",
                        "Required loan-review field is missing: " + field
                ));
        for (int index = 0; index < allowedFields.size(); index++) {
            String field = allowedFields.get(index).stringValue();
            if (!REQUIRED_CUSTOMER_FIELDS.contains(field)) {
                add(
                        issues,
                        "/fieldPolicy/" + CUSTOMER_DATA_READ + "/allowed/" + index,
                        "FIELD_EXCEEDS_TEMPLATE",
                        "Field exceeds the loan-review template maximum: " + field
                );
            }
        }
        JsonNode denyUnknown = customerPolicy.path("denyUnknown");
        if (!denyUnknown.isBoolean() || !denyUnknown.booleanValue()) {
            add(
                    issues,
                    "/fieldPolicy/" + CUSTOMER_DATA_READ + "/denyUnknown",
                    "DENY_UNKNOWN_FIELDS_REQUIRED",
                    "CUSTOMER_DATA_READ must deny unknown fields"
            );
        }
    }

    private void validateCardinality(
            JsonNode contract,
            ContractValidationCatalog catalog,
            List<Issue> issues
    ) {
        JsonNode policies = contract.path("cardinality");
        validatePolicyToolReferences(policies, "/cardinality", catalog, issues);

        sortedFieldNames(policies).forEach(tool -> {
            JsonNode policy = policies.path(tool);
            validateMaximumOne(policy.path("maxRequestedRecords"),
                    "/cardinality/" + escapePointerToken(tool) + "/maxRequestedRecords", issues);
            validateMaximumOne(policy.path("maxReturnedRecords"),
                    "/cardinality/" + escapePointerToken(tool) + "/maxReturnedRecords", issues);
        });

        requireCardinalityLimit(
                policies.at("/" + CUSTOMER_DATA_READ + "/maxRequestedRecords"),
                "/cardinality/" + CUSTOMER_DATA_READ + "/maxRequestedRecords",
                issues
        );
        requireCardinalityLimit(
                policies.at("/" + CUSTOMER_DATA_READ + "/maxReturnedRecords"),
                "/cardinality/" + CUSTOMER_DATA_READ + "/maxReturnedRecords",
                issues
        );
    }

    private void validateMaximumOne(JsonNode value, String pointer, List<Issue> issues) {
        if (!value.isIntegralNumber()) {
            return;
        }
        BigInteger limit = value.bigIntegerValue();
        if (limit.signum() <= 0) {
            add(issues, pointer, "CARDINALITY_LIMIT_INVALID", "Cardinality limits must be positive");
        } else if (limit.compareTo(BigInteger.ONE) > 0) {
            add(issues, pointer, "CARDINALITY_EXCEEDS_TEMPLATE", "Cardinality limit must not exceed one");
        }
    }

    private void requireCardinalityLimit(JsonNode value, String pointer, List<Issue> issues) {
        if (!value.isIntegralNumber()) {
            add(issues, pointer, "CARDINALITY_LIMIT_REQUIRED", "The loan-review template requires this cardinality limit");
        }
    }

    private void validateEgress(JsonNode contract, List<Issue> issues) {
        JsonNode allowed = contract.at("/externalEgress/allowed");
        if (!allowed.isBoolean()) {
            add(issues, "/externalEgress/allowed", "EGRESS_POLICY_REQUIRED", "External egress policy is required");
        } else if (allowed.booleanValue()) {
            add(issues, "/externalEgress/allowed", "EXTERNAL_EGRESS_NOT_DENIED", "loan-review/1 must deny external egress");
        }

        JsonNode destinations = contract.at("/externalEgress/allowedDestinations");
        if (!destinations.isArray()) {
            add(issues, "/externalEgress/allowedDestinations", "EGRESS_DESTINATIONS_REQUIRED", "External egress destinations must be declared as empty");
        } else if (!destinations.isEmpty()) {
            add(issues, "/externalEgress/allowedDestinations", "EGRESS_DESTINATION_CONFLICT", "Denied external egress cannot contain destinations");
        }
    }

    private void validateWorkflow(JsonNode contract, List<Issue> issues) {
        validateExactSet(
                contract.at("/workflow/allowedStages"),
                "/workflow/allowedStages",
                REQUIRED_WORKFLOW_STAGES,
                "REQUIRED_WORKFLOW_STAGE_MISSING",
                "WORKFLOW_STAGE_EXCEEDS_TEMPLATE",
                "workflow stage",
                issues
        );
    }

    private void validateHighImpactActions(
            JsonNode contract,
            ContractValidationCatalog catalog,
            List<Issue> issues
    ) {
        JsonNode actions = contract.path("highImpactActions");
        sortedFieldNames(actions).forEach(tool -> {
            String pointer = "/highImpactActions/" + escapePointerToken(tool);
            if (!catalog.hasHighImpactTool(tool)) {
                add(issues, pointer, "HIGH_IMPACT_TOOL_NOT_IN_CATALOG", "High-impact Tool is not in the supplied server catalog: " + tool);
            }
            if (!"HUMAN_ONLY".equals(actions.path(tool).stringValue())) {
                add(issues, pointer, "HIGH_IMPACT_MODE_INVALID", "High-impact actions must be HUMAN_ONLY");
            }
        });

        requireExactText(
                actions.path(LOAN_DECISION_UPDATE),
                "/highImpactActions/" + LOAN_DECISION_UPDATE,
                "HUMAN_ONLY",
                "LOAN_DECISION_POLICY_REQUIRED",
                "LOAN_DECISION_POLICY_INVALID",
                issues
        );
    }

    private void validateToolTrust(JsonNode contract, List<Issue> issues) {
        JsonNode required = contract.at("/toolTrust/requireTrustedTool");
        if (!required.isBoolean() || !required.booleanValue()) {
            add(issues, "/toolTrust/requireTrustedTool", "TRUSTED_TOOL_REQUIRED", "loan-review/1 requires trusted Tools");
        }
        validateExactSet(
                contract.at("/toolTrust/allowedTrustLevels"),
                "/toolTrust/allowedTrustLevels",
                REQUIRED_TRUST_LEVELS,
                "REQUIRED_TRUST_LEVEL_MISSING",
                "UNTRUSTED_LEVEL_ALLOWED",
                "trust level",
                issues
        );
    }

    private void validateOutputPolicy(JsonNode contract, List<Issue> issues) {
        validateExactSet(
                contract.at("/outputPolicy/reviewStatusAllowed"),
                "/outputPolicy/reviewStatusAllowed",
                REQUIRED_REVIEW_STATUSES,
                "REQUIRED_REVIEW_STATUS_MISSING",
                "REVIEW_STATUS_EXCEEDS_TEMPLATE",
                "review status",
                issues
        );
    }

    private void validatePolicyToolReferences(
            JsonNode policies,
            String basePointer,
            ContractValidationCatalog catalog,
            List<Issue> issues
    ) {
        sortedFieldNames(policies).stream()
                .filter(tool -> !catalog.hasEnabledTool(tool))
                .forEach(tool -> add(
                        issues,
                        basePointer + "/" + escapePointerToken(tool),
                        "POLICY_TOOL_NOT_IN_RELEASE_CATALOG",
                        "Policy Tool is not in the supplied release catalog: " + tool
                ));
    }

    private void validateExactSet(
            JsonNode value,
            String pointer,
            Set<String> expected,
            String missingCode,
            String extraCode,
            String label,
            List<Issue> issues
    ) {
        Set<String> actual = stringSet(value);
        expected.stream()
                .filter(item -> !actual.contains(item))
                .forEach(item -> add(issues, pointer, missingCode, "Required " + label + " is missing: " + item));
        for (int index = 0; index < value.size(); index++) {
            String item = value.get(index).stringValue();
            if (!expected.contains(item)) {
                add(issues, pointer + "/" + index, extraCode, "Disallowed " + label + ": " + item);
            }
        }
    }

    private void requireExactText(
            JsonNode value,
            String pointer,
            String expected,
            String missingCode,
            String mismatchCode,
            List<Issue> issues
    ) {
        if (!value.isString() || value.stringValue().isBlank()) {
            add(issues, pointer, missingCode, "Required value is missing: " + expected);
        } else if (!expected.equals(value.stringValue())) {
            add(issues, pointer, mismatchCode, "Value must be exactly " + expected);
        }
    }

    private void requireNonBlankText(JsonNode value, String pointer, String code, List<Issue> issues) {
        if (!value.isString() || value.stringValue().isBlank()) {
            add(issues, pointer, code, "Required text value is missing or blank");
        }
    }

    private Set<String> stringSet(JsonNode value) {
        Set<String> values = new HashSet<>();
        if (value.isArray()) {
            value.forEach(item -> values.add(item.stringValue()));
        }
        return values;
    }

    private List<String> sortedFieldNames(JsonNode object) {
        List<String> names = new ArrayList<>();
        if (object.isObject()) {
            object.properties().forEach(entry -> names.add(entry.getKey()));
            names.sort(String::compareTo);
        }
        return names;
    }

    private String escapePointerToken(String value) {
        return value.replace("~", "~0").replace("/", "~1");
    }

    private void add(List<Issue> issues, String pointer, String code, String message) {
        issues.add(new Issue(pointer, code, IssueSeverity.ERROR, message));
    }

    public enum ValidationStatus {
        VALID,
        INVALID,
        WARN
    }

    public enum IssueSeverity {
        ERROR,
        WARNING
    }

    public record Issue(String jsonPointer, String code, IssueSeverity severity, String message) {
        public Issue {
            Objects.requireNonNull(jsonPointer, "jsonPointer");
            Objects.requireNonNull(code, "code");
            Objects.requireNonNull(severity, "severity");
            Objects.requireNonNull(message, "message");
        }
    }

    public record ValidationResult(ValidationStatus status, List<Issue> issues) {
        public ValidationResult {
            Objects.requireNonNull(status, "status");
            issues = List.copyOf(Objects.requireNonNull(issues, "issues"));
            ValidationStatus derived = deriveStatus(issues);
            if (status != derived) {
                throw new IllegalArgumentException("Validation status must be derived from issue severity");
            }
        }

        public static ValidationResult fromIssues(List<Issue> issues) {
            List<Issue> immutableIssues = List.copyOf(Objects.requireNonNull(issues, "issues"));
            return new ValidationResult(deriveStatus(immutableIssues), immutableIssues);
        }

        private static ValidationStatus deriveStatus(List<Issue> issues) {
            if (issues.stream().anyMatch(issue -> issue.severity() == IssueSeverity.ERROR)) {
                return ValidationStatus.INVALID;
            }
            if (issues.stream().anyMatch(issue -> issue.severity() == IssueSeverity.WARNING)) {
                return ValidationStatus.WARN;
            }
            return ValidationStatus.VALID;
        }
    }

    public record EnabledTool(String toolName, List<String> outputFields) {
        public EnabledTool {
            requireCatalogIdentifier(toolName, "toolName");
            outputFields = validatedIdentifiers(outputFields, "outputFields");
        }
    }

    /**
     * Immutable, caller-supplied semantic cross-reference boundary. This value does not load or
     * attest authoritative Manifest state and intentionally carries no registry trust claims.
     */
    public record ContractValidationCatalog(
            List<EnabledTool> enabledReleaseTools,
            List<String> highImpactToolNames
    ) {
        public ContractValidationCatalog {
            Objects.requireNonNull(enabledReleaseTools, "enabledReleaseTools");
            List<EnabledTool> copiedTools = new ArrayList<>();
            Set<String> toolNames = new HashSet<>();
            for (EnabledTool tool : enabledReleaseTools) {
                EnabledTool copied = Objects.requireNonNull(tool, "enabledReleaseTools entry");
                if (!toolNames.add(copied.toolName())) {
                    throw new IllegalArgumentException("Duplicate enabled Tool identity: " + copied.toolName());
                }
                copiedTools.add(copied);
            }
            enabledReleaseTools = List.copyOf(copiedTools);
            highImpactToolNames = validatedIdentifiers(highImpactToolNames, "highImpactToolNames");
        }

        public boolean hasEnabledTool(String toolName) {
            return enabledReleaseTools.stream().anyMatch(tool -> tool.toolName().equals(toolName));
        }

        public boolean hasOutputField(String toolName, String fieldName) {
            return enabledReleaseTools.stream()
                    .filter(tool -> tool.toolName().equals(toolName))
                    .anyMatch(tool -> tool.outputFields().contains(fieldName));
        }

        public boolean hasHighImpactTool(String toolName) {
            return highImpactToolNames.contains(toolName);
        }
    }

    private static List<String> validatedIdentifiers(List<String> values, String name) {
        Objects.requireNonNull(values, name);
        List<String> copied = new ArrayList<>();
        Set<String> unique = new HashSet<>();
        for (String value : values) {
            requireCatalogIdentifier(value, name + " entry");
            if (!unique.add(value)) {
                throw new IllegalArgumentException("Duplicate " + name + " identity: " + value);
            }
            copied.add(value);
        }
        return List.copyOf(copied);
    }

    private static void requireCatalogIdentifier(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
