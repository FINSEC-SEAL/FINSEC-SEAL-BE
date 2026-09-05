package com.finsecseal.contract;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Closed, typed policy-diff operations accepted by the narrowing validator.
 */
public sealed interface SafetyContractPatchOperation permits
        SafetyContractPatchOperation.AddConstraint,
        SafetyContractPatchOperation.NarrowSet,
        SafetyContractPatchOperation.LowerLimit,
        SafetyContractPatchOperation.DenyTool,
        SafetyContractPatchOperation.SetHumanOnly {

    OperationType type();

    String jsonPointer();

    default String logicalTarget() {
        return jsonPointer();
    }

    enum OperationType {
        ADD_CONSTRAINT,
        NARROW_SET,
        LOWER_LIMIT,
        DENY_TOOL,
        SET_HUMAN_ONLY
    }

    enum ConstraintKind {
        CURRENT_APPLICANT_ONLY(false),
        CURRENT_CASE_ONLY(true),
        ALLOWED_DOCUMENTS_ONLY(true),
        DENY_UNKNOWN_FIELDS(true),
        REQUIRE_TRUSTED_TOOL(false),
        DISABLE_EXTERNAL_EGRESS(false);

        private final boolean toolRequired;

        ConstraintKind(boolean toolRequired) {
            this.toolRequired = toolRequired;
        }

        boolean toolRequired() {
            return toolRequired;
        }
    }

    enum SetKind {
        ALLOWED_FIELDS(true),
        ALLOWED_DESTINATIONS(false),
        WORKFLOW_STAGES(false),
        ALLOWED_TRUST_LEVELS(false),
        REVIEW_STATUSES(false);

        private final boolean toolRequired;

        SetKind(boolean toolRequired) {
            this.toolRequired = toolRequired;
        }

        boolean toolRequired() {
            return toolRequired;
        }
    }

    enum LimitKind {
        MAX_REQUESTED_RECORDS("maxRequestedRecords"),
        MAX_RETURNED_RECORDS("maxReturnedRecords");

        private final String fieldName;

        LimitKind(String fieldName) {
            this.fieldName = fieldName;
        }

        String fieldName() {
            return fieldName;
        }
    }

    record AddConstraint(
            ConstraintKind constraintKind,
            Optional<String> toolName
    ) implements SafetyContractPatchOperation {

        public AddConstraint {
            Objects.requireNonNull(constraintKind, "constraintKind must not be null");
            Objects.requireNonNull(toolName, "toolName must not be null");
            toolName = toolName.map(SafetyContractPatchOperation::normalizeIdentifier);
            if (constraintKind.toolRequired() != toolName.isPresent()) {
                throw new IllegalArgumentException(
                        "toolName presence must match the constraint target"
                );
            }
        }

        public AddConstraint(ConstraintKind constraintKind) {
            this(constraintKind, Optional.empty());
        }

        public AddConstraint(ConstraintKind constraintKind, String toolName) {
            this(constraintKind, Optional.ofNullable(toolName));
        }

        @Override
        public OperationType type() {
            return OperationType.ADD_CONSTRAINT;
        }

        @Override
        public String jsonPointer() {
            return switch (constraintKind) {
                case CURRENT_APPLICANT_ONLY -> "/customerScope/type";
                case CURRENT_CASE_ONLY -> dynamicPointer("resourcePolicies", "caseScope");
                case ALLOWED_DOCUMENTS_ONLY -> dynamicPointer(
                        "resourcePolicies",
                        "documentScope"
                );
                case DENY_UNKNOWN_FIELDS -> dynamicPointer("fieldPolicy", "denyUnknown");
                case REQUIRE_TRUSTED_TOOL -> "/toolTrust/requireTrustedTool";
                case DISABLE_EXTERNAL_EGRESS -> "/externalEgress/allowed";
            };
        }

        private String dynamicPointer(String objectName, String fieldName) {
            return "/" + objectName + "/" + escapePointerToken(toolName.orElseThrow())
                    + "/" + fieldName;
        }
    }

    record NarrowSet(
            SetKind setKind,
            Optional<String> toolName,
            List<String> retainedValues
    ) implements SafetyContractPatchOperation {

        public NarrowSet {
            Objects.requireNonNull(setKind, "setKind must not be null");
            Objects.requireNonNull(toolName, "toolName must not be null");
            Objects.requireNonNull(retainedValues, "retainedValues must not be null");
            toolName = toolName.map(SafetyContractPatchOperation::normalizeIdentifier);
            if (setKind.toolRequired() != toolName.isPresent()) {
                throw new IllegalArgumentException("toolName presence must match the set target");
            }
            retainedValues = retainedValues.stream()
                    .map(value -> SafetyContractTextNormalizer.normalize(
                            Objects.requireNonNull(value, "retained value must not be null")
                    ))
                    .sorted()
                    .toList();
        }

        public NarrowSet(SetKind setKind, List<String> retainedValues) {
            this(setKind, Optional.empty(), retainedValues);
        }

        public NarrowSet(SetKind setKind, String toolName, List<String> retainedValues) {
            this(setKind, Optional.ofNullable(toolName), retainedValues);
        }

        @Override
        public OperationType type() {
            return OperationType.NARROW_SET;
        }

        @Override
        public String jsonPointer() {
            return switch (setKind) {
                case ALLOWED_FIELDS -> "/fieldPolicy/"
                        + escapePointerToken(toolName.orElseThrow()) + "/allowed";
                case ALLOWED_DESTINATIONS -> "/externalEgress/allowedDestinations";
                case WORKFLOW_STAGES -> "/workflow/allowedStages";
                case ALLOWED_TRUST_LEVELS -> "/toolTrust/allowedTrustLevels";
                case REVIEW_STATUSES -> "/outputPolicy/reviewStatusAllowed";
            };
        }
    }

    record LowerLimit(
            LimitKind limitKind,
            String toolName,
            BigInteger newLimit
    ) implements SafetyContractPatchOperation {

        public LowerLimit {
            Objects.requireNonNull(limitKind, "limitKind must not be null");
            toolName = normalizeIdentifier(toolName);
            Objects.requireNonNull(newLimit, "newLimit must not be null");
        }

        public LowerLimit(LimitKind limitKind, String toolName, long newLimit) {
            this(limitKind, toolName, BigInteger.valueOf(newLimit));
        }

        @Override
        public OperationType type() {
            return OperationType.LOWER_LIMIT;
        }

        @Override
        public String jsonPointer() {
            return "/cardinality/" + escapePointerToken(toolName) + "/"
                    + limitKind.fieldName();
        }
    }

    record DenyTool(String toolName) implements SafetyContractPatchOperation {

        public DenyTool {
            toolName = normalizeIdentifier(toolName);
        }

        @Override
        public OperationType type() {
            return OperationType.DENY_TOOL;
        }

        @Override
        public String jsonPointer() {
            return "/allowedTools/" + escapePointerToken(toolName);
        }
    }

    record SetHumanOnly(String toolName) implements SafetyContractPatchOperation {

        public SetHumanOnly {
            toolName = normalizeIdentifier(toolName);
        }

        @Override
        public OperationType type() {
            return OperationType.SET_HUMAN_ONLY;
        }

        @Override
        public String jsonPointer() {
            return "/highImpactActions/" + escapePointerToken(toolName);
        }
    }

    private static String normalizeIdentifier(String value) {
        String normalized = SafetyContractTextNormalizer.normalize(
                Objects.requireNonNull(value, "identifier must not be null")
        );
        if (normalized.isBlank()) {
            throw new IllegalArgumentException("identifier must not be blank");
        }
        return normalized;
    }

    private static String escapePointerToken(String value) {
        return value.replace("~", "~0").replace("/", "~1");
    }
}
