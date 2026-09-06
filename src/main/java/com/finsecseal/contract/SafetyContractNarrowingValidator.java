package com.finsecseal.contract;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.BooleanNode;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.MissingNode;
import tools.jackson.databind.node.ObjectNode;
import tools.jackson.databind.node.StringNode;

import com.finsecseal.contract.SafetyContractPatchOperation.AddConstraint;
import com.finsecseal.contract.SafetyContractPatchOperation.ConstraintKind;
import com.finsecseal.contract.SafetyContractPatchOperation.DenyTool;
import com.finsecseal.contract.SafetyContractPatchOperation.LimitKind;
import com.finsecseal.contract.SafetyContractPatchOperation.LowerLimit;
import com.finsecseal.contract.SafetyContractPatchOperation.NarrowSet;
import com.finsecseal.contract.SafetyContractPatchOperation.SetHumanOnly;
import com.finsecseal.contract.SafetyContractPatchOperation.SetKind;

/**
 * Validates that a typed policy diff produces exactly one narrower contract snapshot.
 */
@Component
public class SafetyContractNarrowingValidator {

    private static final BigInteger ONE = BigInteger.ONE;
    private static final String HUMAN_ONLY = "HUMAN_ONLY";
    private static final Comparator<SafetyContractPatchOperation> OPERATION_ORDER =
            Comparator.comparing(SafetyContractPatchOperation::logicalTarget)
                    .thenComparing(operation -> operation.type().name());
    private static final Comparator<Issue> ISSUE_ORDER = Comparator
            .comparing(Issue::jsonPointer)
            .thenComparing(Issue::code)
            .thenComparing(Issue::message);

    private final SafetyContractSchemaValidator schemaValidator;
    private final SafetyContractCanonicalizer canonicalizer;

    public SafetyContractNarrowingValidator(
            SafetyContractSchemaValidator schemaValidator,
            SafetyContractCanonicalizer canonicalizer
    ) {
        this.schemaValidator = Objects.requireNonNull(schemaValidator);
        this.canonicalizer = Objects.requireNonNull(canonicalizer);
    }

    public ValidationResult validate(
            JsonNode baseContract,
            JsonNode resultContract,
            List<SafetyContractPatchOperation> operations
    ) {
        JsonNode baseSnapshot = baseContract == null ? null : baseContract.deepCopy();
        JsonNode resultSnapshot = resultContract == null ? null : resultContract.deepCopy();
        List<SafetyContractPatchOperation> operationSnapshot = operations == null
                ? null
                : Collections.unmodifiableList(new ArrayList<>(operations));

        List<Issue> issues = new ArrayList<>();
        appendStructuralIssues("base", schemaValidator.validate(baseSnapshot), issues);
        appendStructuralIssues("result", schemaValidator.validate(resultSnapshot), issues);
        if (!issues.isEmpty()) {
            return invalid(issues);
        }

        ObjectNode base = (ObjectNode) baseSnapshot;
        ObjectNode result = (ObjectNode) resultSnapshot;
        validateIdentity(base, result, issues);
        Optional<BigInteger> resultVersion = validateVersion(base, result, issues);

        List<SafetyContractPatchOperation> sortedOperations = normalizeOperations(
                operationSnapshot,
                issues
        );
        validateOperationTargets(sortedOperations, issues);
        if (!issues.isEmpty()) {
            return invalid(issues);
        }

        ObjectNode expected = base.deepCopy();
        expected.put("version", resultVersion.orElseThrow());
        for (SafetyContractPatchOperation operation : sortedOperations) {
            applyAndValidate(base, result, expected, operation, issues);
        }
        if (!issues.isEmpty()) {
            return invalid(issues);
        }

        try {
            SafetyContractCanonicalizer.CanonicalPolicy basePolicy =
                    canonicalizer.canonicalizeAndHash(base);
            SafetyContractCanonicalizer.CanonicalPolicy expectedPolicy =
                    canonicalizer.canonicalizeAndHash(expected);
            SafetyContractCanonicalizer.CanonicalPolicy resultPolicy =
                    canonicalizer.canonicalizeAndHash(result);

            if (!expectedPolicy.canonicalJson().equals(resultPolicy.canonicalJson())) {
                issues.add(issue(
                        "/",
                        "UNDECLARED_POLICY_CHANGE",
                        "Result must equal base plus version increment and declared operations"
                ));
                return invalid(issues);
            }

            return valid(new ValidatedPatch(
                    sortedOperations,
                    basePolicy.policyHash(),
                    resultPolicy.policyHash()
            ));
        } catch (RuntimeException exception) {
            issues.add(issue(
                    "/",
                    "CANONICALIZATION_FAILURE",
                    "Patch snapshots could not be canonicalized"
            ));
            return invalid(issues);
        }
    }

    private void appendStructuralIssues(
            String snapshot,
            SafetyContractSchemaValidator.ValidationResult validation,
            List<Issue> issues
    ) {
        validation.issues().forEach(source -> {
            String suffix = "/".equals(source.jsonPointer()) ? "" : source.jsonPointer();
            issues.add(issue(
                    "/" + snapshot + suffix,
                    snapshot.toUpperCase() + "_" + source.code(),
                    source.message()
            ));
        });
    }

    private void validateIdentity(ObjectNode base, ObjectNode result, List<Issue> issues) {
        Optional<String> baseId = requiredNormalizedText(
                base.path("contractId"),
                "/base/contractId",
                issues
        );
        Optional<String> resultId = requiredNormalizedText(
                result.path("contractId"),
                "/result/contractId",
                issues
        );
        if (baseId.isPresent() && resultId.isPresent() && !baseId.equals(resultId)) {
            issues.add(issue(
                    "/result/contractId",
                    "CONTRACT_IDENTITY_CHANGED",
                    "Patch result must retain the base contractId"
            ));
        }
    }

    private Optional<String> requiredNormalizedText(
            JsonNode value,
            String pointer,
            List<Issue> issues
    ) {
        if (!value.isString() || value.stringValue().isBlank()) {
            issues.add(issue(
                    pointer,
                    "REQUIRED_IDENTITY",
                    "contractId must be a nonblank string"
            ));
            return Optional.empty();
        }
        return Optional.of(SafetyContractTextNormalizer.normalize(value.stringValue()));
    }

    private Optional<BigInteger> validateVersion(
            ObjectNode base,
            ObjectNode result,
            List<Issue> issues
    ) {
        Optional<BigInteger> baseVersion = positiveInteger(
                base.path("version"),
                "/base/version",
                issues
        );
        Optional<BigInteger> resultVersion = positiveInteger(
                result.path("version"),
                "/result/version",
                issues
        );
        if (baseVersion.isPresent()
                && resultVersion.isPresent()
                && !resultVersion.get().equals(baseVersion.get().add(ONE))) {
            issues.add(issue(
                    "/result/version",
                    "INVALID_VERSION_INCREMENT",
                    "Patch result version must equal base version plus one"
            ));
        }
        return resultVersion;
    }

    private Optional<BigInteger> positiveInteger(
            JsonNode value,
            String pointer,
            List<Issue> issues
    ) {
        if (!value.isIntegralNumber() || value.bigIntegerValue().signum() <= 0) {
            issues.add(issue(
                    pointer,
                    "REQUIRED_POSITIVE_VERSION",
                    "Patch snapshots require a positive integer version"
            ));
            return Optional.empty();
        }
        return Optional.of(value.bigIntegerValue());
    }

    private List<SafetyContractPatchOperation> normalizeOperations(
            List<SafetyContractPatchOperation> operations,
            List<Issue> issues
    ) {
        if (operations == null || operations.isEmpty()) {
            issues.add(issue(
                    "/operations",
                    "EMPTY_PATCH",
                    "Patch must contain at least one typed operation"
            ));
            return List.of();
        }

        List<SafetyContractPatchOperation> normalized = new ArrayList<>();
        for (int index = 0; index < operations.size(); index++) {
            SafetyContractPatchOperation operation = operations.get(index);
            if (operation == null) {
                issues.add(issue(
                        "/operations/" + index,
                        "NULL_OPERATION",
                        "Patch operations must not be null"
                ));
            } else {
                normalized.add(operation);
            }
        }
        normalized.sort(OPERATION_ORDER);
        return List.copyOf(normalized);
    }

    private void validateOperationTargets(
            List<SafetyContractPatchOperation> operations,
            List<Issue> issues
    ) {
        Set<String> targets = new HashSet<>();
        for (SafetyContractPatchOperation operation : operations) {
            if (!targets.add(operation.logicalTarget())) {
                issues.add(issue(
                        operation.jsonPointer(),
                        "DUPLICATE_OPERATION_TARGET",
                        "Only one operation may write a logical policy target"
                ));
            }
        }

        for (int left = 0; left < operations.size(); left++) {
            String leftTarget = operations.get(left).logicalTarget();
            for (int right = left + 1; right < operations.size(); right++) {
                String rightTarget = operations.get(right).logicalTarget();
                if (!leftTarget.equals(rightTarget) && targetsOverlap(leftTarget, rightTarget)) {
                    issues.add(issue(
                            rightTarget,
                            "CONFLICTING_OPERATION_TARGET",
                            "Operations must not write ancestor and descendant targets"
                    ));
                }
            }
        }
    }

    private boolean targetsOverlap(String left, String right) {
        return left.startsWith(right + "/") || right.startsWith(left + "/");
    }

    private void applyAndValidate(
            ObjectNode base,
            ObjectNode result,
            ObjectNode expected,
            SafetyContractPatchOperation operation,
            List<Issue> issues
    ) {
        switch (operation) {
            case AddConstraint addConstraint -> applyConstraint(
                    base,
                    result,
                    expected,
                    addConstraint,
                    issues
            );
            case NarrowSet narrowSet -> applyNarrowSet(
                    base,
                    result,
                    expected,
                    narrowSet,
                    issues
            );
            case LowerLimit lowerLimit -> applyLowerLimit(
                    base,
                    result,
                    expected,
                    lowerLimit,
                    issues
            );
            case DenyTool denyTool -> applyDenyTool(
                    base,
                    result,
                    expected,
                    denyTool,
                    issues
            );
            case SetHumanOnly setHumanOnly -> applyHumanOnly(
                    base,
                    result,
                    expected,
                    setHumanOnly,
                    issues
            );
        }
    }

    private void applyConstraint(
            ObjectNode base,
            ObjectNode result,
            ObjectNode expected,
            AddConstraint operation,
            List<Issue> issues
    ) {
        JsonNode baseValue = constraintValue(base, operation);
        JsonNode restrictedValue = restrictedValue(operation.constraintKind());
        if (!validConstraintTransition(baseValue, restrictedValue, operation.constraintKind())) {
            issues.add(issue(
                    operation.jsonPointer(),
                    "NOT_A_NEW_CONSTRAINT",
                    "ADD_CONSTRAINT must introduce a stricter documented value"
            ));
            return;
        }
        if (!restrictedValue.equals(constraintValue(result, operation))) {
            issues.add(issue(
                    operation.jsonPointer(),
                    "RESULT_VALUE_MISMATCH",
                    "Patch result does not contain the declared constraint"
            ));
            return;
        }
        putConstraint(expected, operation, restrictedValue);
    }

    private boolean validConstraintTransition(
            JsonNode baseValue,
            JsonNode restrictedValue,
            ConstraintKind kind
    ) {
        if (baseValue.isMissingNode()) {
            return true;
        }
        return switch (kind) {
            case DENY_UNKNOWN_FIELDS, REQUIRE_TRUSTED_TOOL ->
                    baseValue.isBoolean() && !baseValue.booleanValue();
            case DISABLE_EXTERNAL_EGRESS ->
                    baseValue.isBoolean() && baseValue.booleanValue();
            case CURRENT_APPLICANT_ONLY, CURRENT_CASE_ONLY, ALLOWED_DOCUMENTS_ONLY -> false;
        } && !baseValue.equals(restrictedValue);
    }

    private JsonNode restrictedValue(ConstraintKind kind) {
        return switch (kind) {
            case CURRENT_APPLICANT_ONLY -> StringNode.valueOf("CURRENT_APPLICANT_ONLY");
            case CURRENT_CASE_ONLY -> StringNode.valueOf("CURRENT_CASE_ONLY");
            case ALLOWED_DOCUMENTS_ONLY -> StringNode.valueOf("ALLOWED_DOCUMENTS_ONLY");
            case DENY_UNKNOWN_FIELDS, REQUIRE_TRUSTED_TOOL -> BooleanNode.TRUE;
            case DISABLE_EXTERNAL_EGRESS -> BooleanNode.FALSE;
        };
    }

    private JsonNode constraintValue(ObjectNode root, AddConstraint operation) {
        return switch (operation.constraintKind()) {
            case CURRENT_APPLICANT_ONLY -> nestedValue(root, "customerScope", "type");
            case CURRENT_CASE_ONLY -> dynamicValue(
                    root,
                    "resourcePolicies",
                    operation.toolName().orElseThrow(),
                    "caseScope"
            );
            case ALLOWED_DOCUMENTS_ONLY -> dynamicValue(
                    root,
                    "resourcePolicies",
                    operation.toolName().orElseThrow(),
                    "documentScope"
            );
            case DENY_UNKNOWN_FIELDS -> dynamicValue(
                    root,
                    "fieldPolicy",
                    operation.toolName().orElseThrow(),
                    "denyUnknown"
            );
            case REQUIRE_TRUSTED_TOOL -> nestedValue(
                    root,
                    "toolTrust",
                    "requireTrustedTool"
            );
            case DISABLE_EXTERNAL_EGRESS -> nestedValue(
                    root,
                    "externalEgress",
                    "allowed"
            );
        };
    }

    private void putConstraint(
            ObjectNode root,
            AddConstraint operation,
            JsonNode value
    ) {
        switch (operation.constraintKind()) {
            case CURRENT_APPLICANT_ONLY -> object(root, "customerScope").set("type", value);
            case CURRENT_CASE_ONLY -> dynamicObject(
                    root,
                    "resourcePolicies",
                    operation.toolName().orElseThrow()
            ).set("caseScope", value);
            case ALLOWED_DOCUMENTS_ONLY -> dynamicObject(
                    root,
                    "resourcePolicies",
                    operation.toolName().orElseThrow()
            ).set("documentScope", value);
            case DENY_UNKNOWN_FIELDS -> dynamicObject(
                    root,
                    "fieldPolicy",
                    operation.toolName().orElseThrow()
            ).set("denyUnknown", value);
            case REQUIRE_TRUSTED_TOOL -> object(root, "toolTrust")
                    .set("requireTrustedTool", value);
            case DISABLE_EXTERNAL_EGRESS -> object(root, "externalEgress")
                    .set("allowed", value);
        }
    }

    private void applyNarrowSet(
            ObjectNode base,
            ObjectNode result,
            ObjectNode expected,
            NarrowSet operation,
            List<Issue> issues
    ) {
        Optional<Set<String>> baseValues = textSet(setValue(base, operation));
        Optional<Set<String>> resultValues = textSet(setValue(result, operation));
        Set<String> retainedValues = new TreeSet<>(operation.retainedValues());

        if (retainedValues.size() != operation.retainedValues().size()) {
            issues.add(issue(
                    operation.jsonPointer(),
                    "DUPLICATE_SET_VALUE",
                    "NARROW_SET values must be unique after normalization"
            ));
            return;
        }
        if (baseValues.isEmpty()) {
            issues.add(issue(
                    operation.jsonPointer(),
                    "MISSING_BASE_SET",
                    "NARROW_SET requires an existing base set"
            ));
            return;
        }
        if (!baseValues.get().containsAll(retainedValues)
                || retainedValues.size() >= baseValues.get().size()) {
            issues.add(issue(
                    operation.jsonPointer(),
                    "SET_NOT_STRICTLY_NARROWER",
                    "NARROW_SET must retain a strict subset of base values"
            ));
            return;
        }
        if (resultValues.isEmpty() || !resultValues.get().equals(retainedValues)) {
            issues.add(issue(
                    operation.jsonPointer(),
                    "RESULT_VALUE_MISMATCH",
                    "Patch result set must equal the declared retained values"
            ));
            return;
        }
        putSetValue(expected, operation, operation.retainedValues());
    }

    private JsonNode setValue(ObjectNode root, NarrowSet operation) {
        return switch (operation.setKind()) {
            case ALLOWED_FIELDS -> dynamicValue(
                    root,
                    "fieldPolicy",
                    operation.toolName().orElseThrow(),
                    "allowed"
            );
            case ALLOWED_DESTINATIONS -> nestedValue(
                    root,
                    "externalEgress",
                    "allowedDestinations"
            );
            case WORKFLOW_STAGES -> nestedValue(root, "workflow", "allowedStages");
            case ALLOWED_TRUST_LEVELS -> nestedValue(
                    root,
                    "toolTrust",
                    "allowedTrustLevels"
            );
            case REVIEW_STATUSES -> nestedValue(
                    root,
                    "outputPolicy",
                    "reviewStatusAllowed"
            );
        };
    }

    private void putSetValue(
            ObjectNode root,
            NarrowSet operation,
            List<String> values
    ) {
        ObjectNode parent = switch (operation.setKind()) {
            case ALLOWED_FIELDS -> dynamicObject(
                    root,
                    "fieldPolicy",
                    operation.toolName().orElseThrow()
            );
            case ALLOWED_DESTINATIONS -> object(root, "externalEgress");
            case WORKFLOW_STAGES -> object(root, "workflow");
            case ALLOWED_TRUST_LEVELS -> object(root, "toolTrust");
            case REVIEW_STATUSES -> object(root, "outputPolicy");
        };
        String field = switch (operation.setKind()) {
            case ALLOWED_FIELDS -> "allowed";
            case ALLOWED_DESTINATIONS -> "allowedDestinations";
            case WORKFLOW_STAGES -> "allowedStages";
            case ALLOWED_TRUST_LEVELS -> "allowedTrustLevels";
            case REVIEW_STATUSES -> "reviewStatusAllowed";
        };
        ArrayNode array = JsonNodeFactory.instance.arrayNode();
        values.forEach(array::add);
        parent.set(field, array);
    }

    private void applyLowerLimit(
            ObjectNode base,
            ObjectNode result,
            ObjectNode expected,
            LowerLimit operation,
            List<Issue> issues
    ) {
        if (operation.newLimit().signum() < 0) {
            issues.add(issue(
                    operation.jsonPointer(),
                    "INVALID_LIMIT",
                    "Cardinality limit must be nonnegative"
            ));
            return;
        }

        JsonNode baseValue = limitValue(base, operation);
        if (!baseValue.isMissingNode()) {
            BigInteger oldLimit = baseValue.bigIntegerValue();
            if (oldLimit.signum() < 0 || operation.newLimit().compareTo(oldLimit) >= 0) {
                issues.add(issue(
                        operation.jsonPointer(),
                        "LIMIT_NOT_LOWERED",
                        "LOWER_LIMIT must strictly reduce a nonnegative base limit"
                ));
                return;
            }
        }

        JsonNode resultValue = limitValue(result, operation);
        if (!resultValue.isIntegralNumber()
                || !resultValue.bigIntegerValue().equals(operation.newLimit())) {
            issues.add(issue(
                    operation.jsonPointer(),
                    "RESULT_VALUE_MISMATCH",
                    "Patch result limit must equal the declared new limit"
            ));
            return;
        }

        dynamicObject(expected, "cardinality", operation.toolName())
                .put(operation.limitKind().fieldName(), operation.newLimit());
    }

    private JsonNode limitValue(ObjectNode root, LowerLimit operation) {
        return dynamicValue(
                root,
                "cardinality",
                operation.toolName(),
                operation.limitKind().fieldName()
        );
    }

    private void applyDenyTool(
            ObjectNode base,
            ObjectNode result,
            ObjectNode expected,
            DenyTool operation,
            List<Issue> issues
    ) {
        Optional<Set<String>> baseTools = textSet(base.path("allowedTools"));
        Optional<Set<String>> resultTools = textSet(result.path("allowedTools"));
        if (baseTools.isEmpty() || !baseTools.get().contains(operation.toolName())) {
            issues.add(issue(
                    operation.jsonPointer(),
                    "TOOL_NOT_ALLOWED_IN_BASE",
                    "DENY_TOOL requires a tool allowed by the base contract"
            ));
            return;
        }
        if (resultTools.isEmpty() || resultTools.get().contains(operation.toolName())) {
            issues.add(issue(
                    operation.jsonPointer(),
                    "RESULT_VALUE_MISMATCH",
                    "Patch result must remove the denied tool"
            ));
            return;
        }

        ArrayNode tools = (ArrayNode) expected.path("allowedTools");
        for (int index = tools.size() - 1; index >= 0; index--) {
            if (normalizeText(tools.get(index)).equals(operation.toolName())) {
                tools.remove(index);
            }
        }
    }

    private void applyHumanOnly(
            ObjectNode base,
            ObjectNode result,
            ObjectNode expected,
            SetHumanOnly operation,
            List<Issue> issues
    ) {
        JsonNode baseValue = dynamicMapValue(base, "highImpactActions", operation.toolName());
        if (baseValue.isString() && HUMAN_ONLY.equals(normalizeText(baseValue))) {
            issues.add(issue(
                    operation.jsonPointer(),
                    "HUMAN_ONLY_ALREADY_SET",
                    "SET_HUMAN_ONLY must introduce a stricter boundary"
            ));
            return;
        }

        JsonNode resultValue = dynamicMapValue(result, "highImpactActions", operation.toolName());
        if (!resultValue.isString() || !HUMAN_ONLY.equals(normalizeText(resultValue))) {
            issues.add(issue(
                    operation.jsonPointer(),
                    "RESULT_VALUE_MISMATCH",
                    "Patch result must set the action to HUMAN_ONLY"
            ));
            return;
        }

        Optional<Set<String>> resultTools = textSet(result.path("allowedTools"));
        if (resultTools.isPresent() && resultTools.get().contains(operation.toolName())) {
            issues.add(issue(
                    operation.jsonPointer(),
                    "HUMAN_ONLY_TOOL_STILL_ALLOWED",
                    "A HUMAN_ONLY action must not remain in allowedTools"
            ));
            return;
        }

        object(expected, "highImpactActions").put(operation.toolName(), HUMAN_ONLY);
    }

    private Optional<Set<String>> textSet(JsonNode value) {
        if (!value.isArray()) {
            return Optional.empty();
        }
        Set<String> values = new TreeSet<>();
        value.forEach(item -> values.add(normalizeText(item)));
        return Optional.of(Set.copyOf(values));
    }

    private String normalizeText(JsonNode value) {
        return SafetyContractTextNormalizer.normalize(value.stringValue());
    }

    private JsonNode nestedValue(ObjectNode root, String objectName, String fieldName) {
        JsonNode object = root.path(objectName);
        return object.isObject() ? object.path(fieldName) : MissingNode.getInstance();
    }

    private JsonNode dynamicValue(
            ObjectNode root,
            String objectName,
            String normalizedKey,
            String fieldName
    ) {
        JsonNode dynamic = root.path(objectName);
        if (!(dynamic instanceof ObjectNode dynamicObject)) {
            return MissingNode.getInstance();
        }
        String actualKey = normalizedFieldName(dynamicObject, normalizedKey);
        if (actualKey == null || !(dynamicObject.path(actualKey) instanceof ObjectNode value)) {
            return MissingNode.getInstance();
        }
        return value.path(fieldName);
    }

    private JsonNode dynamicMapValue(
            ObjectNode root,
            String objectName,
            String normalizedKey
    ) {
        JsonNode dynamic = root.path(objectName);
        if (!(dynamic instanceof ObjectNode dynamicObject)) {
            return MissingNode.getInstance();
        }
        String actualKey = normalizedFieldName(dynamicObject, normalizedKey);
        return actualKey == null ? MissingNode.getInstance() : dynamicObject.path(actualKey);
    }

    private ObjectNode dynamicObject(
            ObjectNode root,
            String objectName,
            String normalizedKey
    ) {
        ObjectNode dynamic = object(root, objectName);
        String actualKey = normalizedFieldName(dynamic, normalizedKey);
        if (actualKey == null) {
            ObjectNode created = JsonNodeFactory.instance.objectNode();
            dynamic.set(normalizedKey, created);
            return created;
        }
        return (ObjectNode) dynamic.path(actualKey);
    }

    private ObjectNode object(ObjectNode root, String fieldName) {
        JsonNode current = root.path(fieldName);
        if (current instanceof ObjectNode object) {
            return object;
        }
        ObjectNode created = JsonNodeFactory.instance.objectNode();
        root.set(fieldName, created);
        return created;
    }

    private String normalizedFieldName(ObjectNode object, String normalizedKey) {
        return object.properties().stream()
                .map(java.util.Map.Entry::getKey)
                .filter(key -> SafetyContractTextNormalizer.normalize(key).equals(normalizedKey))
                .sorted()
                .findFirst()
                .orElse(null);
    }

    private static Issue issue(String pointer, String code, String message) {
        return new Issue(pointer, code, message);
    }

    private static ValidationResult valid(ValidatedPatch patch) {
        return new ValidationResult(true, List.of(), Optional.of(patch));
    }

    private static ValidationResult invalid(List<Issue> issues) {
        List<Issue> sorted = issues.stream().sorted(ISSUE_ORDER).toList();
        return new ValidationResult(false, sorted, Optional.empty());
    }

    public record Issue(String jsonPointer, String code, String message) {
        public Issue {
            Objects.requireNonNull(jsonPointer);
            Objects.requireNonNull(code);
            Objects.requireNonNull(message);
        }
    }

    public record ValidatedPatch(
            List<SafetyContractPatchOperation> operations,
            String basePolicyHash,
            String resultPolicyHash
    ) {
        public ValidatedPatch {
            operations = List.copyOf(Objects.requireNonNull(operations));
            Objects.requireNonNull(basePolicyHash);
            Objects.requireNonNull(resultPolicyHash);
        }
    }

    public record ValidationResult(
            boolean valid,
            List<Issue> issues,
            Optional<ValidatedPatch> validatedPatch
    ) {
        public ValidationResult {
            issues = List.copyOf(Objects.requireNonNull(issues));
            Objects.requireNonNull(validatedPatch);
            if (valid != issues.isEmpty() || valid != validatedPatch.isPresent()) {
                throw new IllegalArgumentException(
                        "Validation status, issues, and proof must agree"
                );
            }
        }
    }
}
