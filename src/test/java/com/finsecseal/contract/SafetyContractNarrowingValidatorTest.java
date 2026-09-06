package com.finsecseal.contract;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

import com.finsecseal.contract.SafetyContractNarrowingValidator.ValidationResult;
import com.finsecseal.contract.SafetyContractPatchOperation.AddConstraint;
import com.finsecseal.contract.SafetyContractPatchOperation.ConstraintKind;
import com.finsecseal.contract.SafetyContractPatchOperation.DenyTool;
import com.finsecseal.contract.SafetyContractPatchOperation.LimitKind;
import com.finsecseal.contract.SafetyContractPatchOperation.LowerLimit;
import com.finsecseal.contract.SafetyContractPatchOperation.NarrowSet;
import com.finsecseal.contract.SafetyContractPatchOperation.SetHumanOnly;
import com.finsecseal.contract.SafetyContractPatchOperation.SetKind;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SafetyContractNarrowingValidatorTest {

    private ObjectMapper objectMapper;
    private SafetyContractCanonicalizer canonicalizer;
    private SafetyContractNarrowingValidator validator;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        SafetyContractSchemaValidator schemaValidator = new SafetyContractSchemaValidator();
        canonicalizer = new SafetyContractCanonicalizer(
                schemaValidator,
                new CanonicalJsonService(objectMapper),
                new DigestService()
        );
        validator = new SafetyContractNarrowingValidator(schemaValidator, canonicalizer);
    }

    @ParameterizedTest(name = "ADD_CONSTRAINT {0}")
    @MethodSource("constraintCases")
    void acceptsEachClosedRestrictiveConstraint(
            ConstraintKind kind,
            String toolName,
            Consumer<ObjectNode> resultMutation
    ) {
        ObjectNode base = validBase();
        ObjectNode result = nextVersion(base);
        resultMutation.accept(result);

        AddConstraint operation = toolName == null
                ? new AddConstraint(kind)
                : new AddConstraint(kind, toolName);
        ValidationResult validation = validator.validate(base, result, List.of(operation));

        assertValid(validation, operation);
    }

    @ParameterizedTest(name = "NARROW_SET {0}")
    @MethodSource("setCases")
    void acceptsStrictSubsetsForEveryClosedSetTarget(
            SetKind kind,
            String toolName,
            List<String> retained,
            Consumer<ObjectNode> resultMutation
    ) {
        ObjectNode base = validBase();
        ObjectNode result = nextVersion(base);
        resultMutation.accept(result);

        NarrowSet operation = toolName == null
                ? new NarrowSet(kind, retained)
                : new NarrowSet(kind, toolName, retained);
        ValidationResult validation = validator.validate(base, result, List.of(operation));

        assertValid(validation, operation);
    }

    @ParameterizedTest(name = "LOWER_LIMIT {0}")
    @MethodSource("limitCases")
    void acceptsStrictlyLowerCardinalityLimits(
            LimitKind kind,
            Consumer<ObjectNode> resultMutation
    ) {
        ObjectNode base = validBase();
        ObjectNode result = nextVersion(base);
        resultMutation.accept(result);
        LowerLimit operation = new LowerLimit(kind, "READ", 1);

        ValidationResult validation = validator.validate(base, result, List.of(operation));

        assertValid(validation, operation);
    }

    @Test
    void acceptsFiniteLimitWhenBaseLimitWasAbsent() {
        ObjectNode base = validBase();
        ((ObjectNode) base.at("/cardinality/READ")).remove("maxReturnedRecords");
        ObjectNode result = nextVersion(base);
        ((ObjectNode) result.at("/cardinality/READ")).put("maxReturnedRecords", 1);
        LowerLimit operation = new LowerLimit(
                LimitKind.MAX_RETURNED_RECORDS,
                "READ",
                1
        );

        assertValid(validator.validate(base, result, List.of(operation)), operation);
    }

    @Test
    void acceptsZeroAsTheNonnegativeLowerLimitBoundary() {
        ObjectNode base = validBase();
        ObjectNode result = nextVersion(base);
        ((ObjectNode) result.at("/cardinality/READ")).put("maxRequestedRecords", 0);
        LowerLimit operation = new LowerLimit(
                LimitKind.MAX_REQUESTED_RECORDS,
                "READ",
                BigInteger.ZERO
        );

        assertValid(validator.validate(base, result, List.of(operation)), operation);
    }

    @Test
    void acceptsDenyToolOnlyWhenResultRemovesExactlyThatTool() {
        ObjectNode base = validBase();
        ObjectNode result = nextVersion(base);
        removeText((ArrayNode) result.path("allowedTools"), "WRITE");
        DenyTool operation = new DenyTool("WRITE");

        assertValid(validator.validate(base, result, List.of(operation)), operation);
    }

    @Test
    void acceptsHumanOnlyForAnActionThatIsNotAllowedAsAnAgentTool() {
        ObjectNode base = validBase();
        ObjectNode result = nextVersion(base);
        ((ObjectNode) result.path("highImpactActions")).put(
                "LOAN_DECISION_UPDATE",
                "HUMAN_ONLY"
        );
        SetHumanOnly operation = new SetHumanOnly("LOAN_DECISION_UPDATE");

        assertValid(validator.validate(base, result, List.of(operation)), operation);
    }

    @Test
    void rejectsSetExpansionAndIdentityUsingIndependentValues() {
        ObjectNode base = validBase();
        ObjectNode expanded = nextVersion(base);
        replaceArray(
                (ObjectNode) expanded.at("/fieldPolicy/READ"),
                "allowed",
                List.of("income", "employment", "address", "accountNumber")
        );
        ValidationResult expansion = validator.validate(
                base,
                expanded,
                List.of(new NarrowSet(
                        SetKind.ALLOWED_FIELDS,
                        "READ",
                        List.of("income", "employment", "address", "accountNumber")
                ))
        );

        ObjectNode identity = nextVersion(base);
        ValidationResult unchanged = validator.validate(
                base,
                identity,
                List.of(new NarrowSet(
                        SetKind.ALLOWED_FIELDS,
                        "READ",
                        List.of("income", "employment", "address")
                ))
        );

        SafetyContractNarrowingValidator.Issue expectedIssue =
                new SafetyContractNarrowingValidator.Issue(
                        "/fieldPolicy/READ/allowed",
                        "SET_NOT_STRICTLY_NARROWER",
                        "NARROW_SET must retain a strict subset of base values"
                );
        assertInvalidExactly(expansion, expectedIssue);
        assertInvalidExactly(unchanged, expectedIssue);
    }

    @ParameterizedTest
    @MethodSource("nonLowerLimits")
    void rejectsNegativeEqualAndRaisedLimits(
            BigInteger proposed,
            String expectedCode,
            String expectedMessage
    ) {
        ObjectNode base = validBase();
        ObjectNode result = nextVersion(base);
        ((ObjectNode) result.at("/cardinality/READ"))
                .put("maxRequestedRecords", proposed);

        ValidationResult validation = validator.validate(
                base,
                result,
                List.of(new LowerLimit(
                        LimitKind.MAX_REQUESTED_RECORDS,
                        "READ",
                        proposed
                ))
        );

        assertInvalidExactly(
                validation,
                new SafetyContractNarrowingValidator.Issue(
                        "/cardinality/READ/maxRequestedRecords",
                        expectedCode,
                        expectedMessage
                )
        );
    }

    @Test
    void rejectsConstraintIdentityAndWrongResultValue() {
        ObjectNode base = validBase();
        ((ObjectNode) base.path("externalEgress")).put("allowed", false);
        ObjectNode identity = nextVersion(base);
        ValidationResult alreadyRestricted = validator.validate(
                base,
                identity,
                List.of(new AddConstraint(ConstraintKind.DISABLE_EXTERNAL_EGRESS))
        );

        ObjectNode secondBase = validBase();
        ObjectNode wrongResult = nextVersion(secondBase);
        ValidationResult mismatch = validator.validate(
                secondBase,
                wrongResult,
                List.of(new AddConstraint(ConstraintKind.DISABLE_EXTERNAL_EGRESS))
        );

        assertInvalidExactly(
                alreadyRestricted,
                new SafetyContractNarrowingValidator.Issue(
                        "/externalEgress/allowed",
                        "NOT_A_NEW_CONSTRAINT",
                        "ADD_CONSTRAINT must introduce a stricter documented value"
                )
        );
        assertInvalidExactly(
                mismatch,
                new SafetyContractNarrowingValidator.Issue(
                        "/externalEgress/allowed",
                        "RESULT_VALUE_MISMATCH",
                        "Patch result does not contain the declared constraint"
                )
        );
    }

    @Test
    void rejectsMissingDeniedToolAndResultThatStillAllowsIt() {
        ObjectNode base = validBase();
        ObjectNode missingResult = nextVersion(base);
        ValidationResult missingBaseTool = validator.validate(
                base,
                missingResult,
                List.of(new DenyTool("UNKNOWN"))
        );

        ObjectNode retainedResult = nextVersion(base);
        ValidationResult retainedTool = validator.validate(
                base,
                retainedResult,
                List.of(new DenyTool("WRITE"))
        );

        assertInvalidExactly(
                missingBaseTool,
                new SafetyContractNarrowingValidator.Issue(
                        "/allowedTools/UNKNOWN",
                        "TOOL_NOT_ALLOWED_IN_BASE",
                        "DENY_TOOL requires a tool allowed by the base contract"
                )
        );
        assertInvalidExactly(
                retainedTool,
                new SafetyContractNarrowingValidator.Issue(
                        "/allowedTools/WRITE",
                        "RESULT_VALUE_MISMATCH",
                        "Patch result must remove the denied tool"
                )
        );
    }

    @Test
    void rejectsHumanOnlyIdentityWrongValueAndToolStillAllowed() {
        ObjectNode base = validBase();
        ((ObjectNode) base.path("highImpactActions")).put("ACTION", "HUMAN_ONLY");
        ObjectNode identity = nextVersion(base);
        ValidationResult alreadyHumanOnly = validator.validate(
                base,
                identity,
                List.of(new SetHumanOnly("ACTION"))
        );

        ObjectNode wrongBase = validBase();
        ObjectNode wrongResult = nextVersion(wrongBase);
        ((ObjectNode) wrongResult.path("highImpactActions")).put("ACTION", "ALLOW");
        ValidationResult wrongValue = validator.validate(
                wrongBase,
                wrongResult,
                List.of(new SetHumanOnly("ACTION"))
        );

        ObjectNode allowedBase = validBase();
        ObjectNode allowedResult = nextVersion(allowedBase);
        ((ObjectNode) allowedResult.path("highImpactActions")).put("HUMAN_TOOL", "HUMAN_ONLY");
        ValidationResult stillAllowed = validator.validate(
                allowedBase,
                allowedResult,
                List.of(new SetHumanOnly("HUMAN_TOOL"))
        );

        assertInvalidExactly(
                alreadyHumanOnly,
                new SafetyContractNarrowingValidator.Issue(
                        "/highImpactActions/ACTION",
                        "HUMAN_ONLY_ALREADY_SET",
                        "SET_HUMAN_ONLY must introduce a stricter boundary"
                )
        );
        assertInvalidExactly(
                wrongValue,
                new SafetyContractNarrowingValidator.Issue(
                        "/highImpactActions/ACTION",
                        "RESULT_VALUE_MISMATCH",
                        "Patch result must set the action to HUMAN_ONLY"
                )
        );
        assertInvalidExactly(
                stillAllowed,
                new SafetyContractNarrowingValidator.Issue(
                        "/highImpactActions/HUMAN_TOOL",
                        "HUMAN_ONLY_TOOL_STILL_ALLOWED",
                        "A HUMAN_ONLY action must not remain in allowedTools"
                )
        );
    }

    @Test
    void compatibleDenyAndHumanOnlyOperationsAreOrderIndependent() {
        ObjectNode base = validBase();
        ObjectNode result = nextVersion(base);
        removeText((ArrayNode) result.path("allowedTools"), "HUMAN_TOOL");
        ((ObjectNode) result.path("highImpactActions")).put("HUMAN_TOOL", "HUMAN_ONLY");
        replaceArray(
                (ObjectNode) result.at("/fieldPolicy/READ"),
                "allowed",
                List.of("employment", "income")
        );

        DenyTool deny = new DenyTool("HUMAN_TOOL");
        SetHumanOnly humanOnly = new SetHumanOnly("HUMAN_TOOL");
        NarrowSet fields = new NarrowSet(
                SetKind.ALLOWED_FIELDS,
                "READ",
                List.of("income", "employment")
        );
        ValidationResult first = validator.validate(
                base,
                result,
                List.of(humanOnly, fields, deny)
        );
        ValidationResult second = validator.validate(
                base,
                result,
                List.of(deny, humanOnly, fields)
        );

        assertThat(first).isEqualTo(second);
        assertThat(first.valid()).isTrue();
        assertThat(first.validatedPatch().orElseThrow().operations())
                .containsExactly(deny, fields, humanOnly);
    }

    @Test
    void rejectsNormalizedDuplicateOperationTargets() {
        ObjectNode base = validBase();
        ((ArrayNode) base.path("allowedTools")).add("café");
        ObjectNode result = nextVersion(base);
        removeText((ArrayNode) result.path("allowedTools"), "café");

        ValidationResult validation = validator.validate(
                base,
                result,
                List.of(new DenyTool("cafe\u0301"), new DenyTool("café"))
        );

        assertInvalidExactly(
                validation,
                new SafetyContractNarrowingValidator.Issue(
                        "/allowedTools/café",
                        "DUPLICATE_OPERATION_TARGET",
                        "Only one operation may write a logical policy target"
                )
        );
    }

    @Test
    void acceptsNormalizedIdentityAndSetMembership() {
        ObjectNode base = validBase();
        base.put("contractId", "cafe\u0301-contract");
        replaceArray(
                (ObjectNode) base.at("/fieldPolicy/READ"),
                "allowed",
                List.of("café", "income")
        );
        ObjectNode result = nextVersion(base);
        result.put("contractId", "café-contract");
        replaceArray(
                (ObjectNode) result.at("/fieldPolicy/READ"),
                "allowed",
                List.of("cafe\u0301")
        );

        NarrowSet operation = new NarrowSet(
                SetKind.ALLOWED_FIELDS,
                "READ",
                List.of("café")
        );
        assertValid(validator.validate(base, result, List.of(operation)), operation);
    }

    @Test
    void rejectsNormalizedDuplicateRetainedValues() {
        ObjectNode base = validBase();
        replaceArray(
                (ObjectNode) base.at("/fieldPolicy/READ"),
                "allowed",
                List.of("café", "income")
        );
        ObjectNode result = nextVersion(base);
        replaceArray(
                (ObjectNode) result.at("/fieldPolicy/READ"),
                "allowed",
                List.of("café")
        );

        ValidationResult validation = validator.validate(
                base,
                result,
                List.of(new NarrowSet(
                        SetKind.ALLOWED_FIELDS,
                        "READ",
                        List.of("cafe\u0301", "café")
                ))
        );

        assertInvalidExactly(
                validation,
                new SafetyContractNarrowingValidator.Issue(
                        "/fieldPolicy/READ/allowed",
                        "DUPLICATE_SET_VALUE",
                        "NARROW_SET values must be unique after normalization"
                )
        );
    }

    @Test
    void validatesArbitraryPrecisionVersionIncrementWithoutOverflow() {
        BigInteger baseVersion = new BigInteger("92233720368547758081234567890");
        ObjectNode base = validBase();
        base.put("version", baseVersion);
        ObjectNode result = base.deepCopy();
        result.put("version", baseVersion.add(BigInteger.ONE));
        ((ObjectNode) result.path("externalEgress")).put("allowed", false);
        AddConstraint operation = new AddConstraint(
                ConstraintKind.DISABLE_EXTERNAL_EGRESS
        );

        assertValid(validator.validate(base, result, List.of(operation)), operation);
    }

    @Test
    void requiresPresentPositiveExactNextVersionAndStableIdentity() {
        ObjectNode base = validBase();
        ObjectNode skippedVersion = base.deepCopy();
        skippedVersion.put("version", 9);
        ((ObjectNode) skippedVersion.path("externalEgress")).put("allowed", false);
        ValidationResult skipped = validator.validate(
                base,
                skippedVersion,
                List.of(new AddConstraint(ConstraintKind.DISABLE_EXTERNAL_EGRESS))
        );

        ObjectNode missingIdentityBase = validBase();
        missingIdentityBase.remove("contractId");
        ObjectNode missingIdentityResult = nextVersion(missingIdentityBase);
        ((ObjectNode) missingIdentityResult.path("externalEgress")).put("allowed", false);
        ValidationResult missingIdentity = validator.validate(
                missingIdentityBase,
                missingIdentityResult,
                List.of(new AddConstraint(ConstraintKind.DISABLE_EXTERNAL_EGRESS))
        );

        ObjectNode changedIdentityBase = validBase();
        ObjectNode changedIdentityResult = nextVersion(changedIdentityBase);
        changedIdentityResult.put("contractId", "different-contract");
        ((ObjectNode) changedIdentityResult.path("externalEgress")).put("allowed", false);
        ValidationResult changedIdentity = validator.validate(
                changedIdentityBase,
                changedIdentityResult,
                List.of(new AddConstraint(ConstraintKind.DISABLE_EXTERNAL_EGRESS))
        );

        assertInvalidExactly(
                skipped,
                new SafetyContractNarrowingValidator.Issue(
                        "/result/version",
                        "INVALID_VERSION_INCREMENT",
                        "Patch result version must equal base version plus one"
                )
        );
        assertInvalidExactly(
                missingIdentity,
                new SafetyContractNarrowingValidator.Issue(
                        "/base/contractId",
                        "REQUIRED_IDENTITY",
                        "contractId must be a nonblank string"
                ),
                new SafetyContractNarrowingValidator.Issue(
                        "/result/contractId",
                        "REQUIRED_IDENTITY",
                        "contractId must be a nonblank string"
                )
        );
        assertInvalidExactly(
                changedIdentity,
                new SafetyContractNarrowingValidator.Issue(
                        "/result/contractId",
                        "CONTRACT_IDENTITY_CHANGED",
                        "Patch result must retain the base contractId"
                )
        );
    }

    @Test
    void rejectsZeroAndMissingVersions() {
        ObjectNode zeroBase = validBase();
        zeroBase.put("version", 0);
        ObjectNode zeroResult = zeroBase.deepCopy();
        zeroResult.put("version", 1);
        ((ObjectNode) zeroResult.path("externalEgress")).put("allowed", false);

        ObjectNode missingBase = validBase();
        missingBase.remove("version");
        ObjectNode missingResult = missingBase.deepCopy();
        missingResult.put("version", 1);
        ((ObjectNode) missingResult.path("externalEgress")).put("allowed", false);

        assertInvalidExactly(
                validator.validate(
                        zeroBase,
                        zeroResult,
                        List.of(new AddConstraint(ConstraintKind.DISABLE_EXTERNAL_EGRESS))
                ),
                new SafetyContractNarrowingValidator.Issue(
                        "/base/version",
                        "REQUIRED_POSITIVE_VERSION",
                        "Patch snapshots require a positive integer version"
                )
        );
        assertInvalidExactly(
                validator.validate(
                        missingBase,
                        missingResult,
                        List.of(new AddConstraint(ConstraintKind.DISABLE_EXTERNAL_EGRESS))
                ),
                new SafetyContractNarrowingValidator.Issue(
                        "/base/version",
                        "REQUIRED_POSITIVE_VERSION",
                        "Patch snapshots require a positive integer version"
                )
        );
    }

    @Test
    void rejectsDecrementedMissingMalformedAndNonpositiveResultVersionsExactly() {
        AddConstraint operation = new AddConstraint(
                ConstraintKind.DISABLE_EXTERNAL_EGRESS
        );

        ObjectNode decrementedBase = validBase();
        ObjectNode decrementedResult = decrementedBase.deepCopy();
        decrementedResult.put("version", 6);
        ((ObjectNode) decrementedResult.path("externalEgress")).put("allowed", false);

        ObjectNode missingBase = validBase();
        ObjectNode missingResult = missingBase.deepCopy();
        missingResult.remove("version");
        ((ObjectNode) missingResult.path("externalEgress")).put("allowed", false);

        ObjectNode malformedBase = validBase();
        ObjectNode malformedResult = malformedBase.deepCopy();
        malformedResult.put("version", "eight");
        ((ObjectNode) malformedResult.path("externalEgress")).put("allowed", false);

        ObjectNode zeroBase = validBase();
        ObjectNode zeroResult = zeroBase.deepCopy();
        zeroResult.put("version", 0);
        ((ObjectNode) zeroResult.path("externalEgress")).put("allowed", false);

        SafetyContractNarrowingValidator.Issue invalidIncrement =
                new SafetyContractNarrowingValidator.Issue(
                        "/result/version",
                        "INVALID_VERSION_INCREMENT",
                        "Patch result version must equal base version plus one"
                );
        SafetyContractNarrowingValidator.Issue requiredPositive =
                new SafetyContractNarrowingValidator.Issue(
                        "/result/version",
                        "REQUIRED_POSITIVE_VERSION",
                        "Patch snapshots require a positive integer version"
                );
        assertInvalidExactly(
                validator.validate(decrementedBase, decrementedResult, List.of(operation)),
                invalidIncrement
        );
        assertInvalidExactly(
                validator.validate(missingBase, missingResult, List.of(operation)),
                requiredPositive
        );
        assertInvalidExactly(
                validator.validate(malformedBase, malformedResult, List.of(operation)),
                new SafetyContractNarrowingValidator.Issue(
                        "/result/version",
                        "RESULT_TYPE",
                        "/version must be an integer"
                )
        );
        assertInvalidExactly(
                validator.validate(zeroBase, zeroResult, List.of(operation)),
                requiredPositive
        );
    }

    @Test
    void rejectsSmallerSetContainingValueOutsideBaseExactly() {
        ObjectNode base = validBase();
        ObjectNode result = nextVersion(base);
        replaceArray(
                (ObjectNode) result.at("/fieldPolicy/READ"),
                "allowed",
                List.of("income", "accountNumber")
        );

        ValidationResult validation = validator.validate(
                base,
                result,
                List.of(new NarrowSet(
                        SetKind.ALLOWED_FIELDS,
                        "READ",
                        List.of("income", "accountNumber")
                ))
        );

        assertInvalidExactly(
                validation,
                new SafetyContractNarrowingValidator.Issue(
                        "/fieldPolicy/READ/allowed",
                        "SET_NOT_STRICTLY_NARROWER",
                        "NARROW_SET must retain a strict subset of base values"
                )
        );
    }

    @Test
    void rejectsNarrowSetAndLowerLimitResultMismatchesExactly() {
        ObjectNode setBase = validBase();
        ObjectNode setResult = nextVersion(setBase);
        replaceArray(
                (ObjectNode) setResult.at("/fieldPolicy/READ"),
                "allowed",
                List.of("income")
        );
        ValidationResult setMismatch = validator.validate(
                setBase,
                setResult,
                List.of(new NarrowSet(
                        SetKind.ALLOWED_FIELDS,
                        "READ",
                        List.of("income", "employment")
                ))
        );

        ObjectNode limitBase = validBase();
        ObjectNode limitResult = nextVersion(limitBase);
        ((ObjectNode) limitResult.at("/cardinality/READ"))
                .put("maxRequestedRecords", 2);
        ValidationResult limitMismatch = validator.validate(
                limitBase,
                limitResult,
                List.of(new LowerLimit(
                        LimitKind.MAX_REQUESTED_RECORDS,
                        "READ",
                        1
                ))
        );

        assertInvalidExactly(
                setMismatch,
                new SafetyContractNarrowingValidator.Issue(
                        "/fieldPolicy/READ/allowed",
                        "RESULT_VALUE_MISMATCH",
                        "Patch result set must equal the declared retained values"
                )
        );
        assertInvalidExactly(
                limitMismatch,
                new SafetyContractNarrowingValidator.Issue(
                        "/cardinality/READ/maxRequestedRecords",
                        "RESULT_VALUE_MISMATCH",
                        "Patch result limit must equal the declared new limit"
                )
        );
    }

    @Test
    void rejectsDifferentPayloadsForSameLogicalTargetExactly() {
        ObjectNode base = validBase();
        ObjectNode result = nextVersion(base);

        ValidationResult validation = validator.validate(
                base,
                result,
                List.of(
                        new NarrowSet(
                                SetKind.ALLOWED_FIELDS,
                                "READ",
                                List.of("income")
                        ),
                        new NarrowSet(
                                SetKind.ALLOWED_FIELDS,
                                "READ",
                                List.of("employment")
                        )
                )
        );

        assertInvalidExactly(
                validation,
                new SafetyContractNarrowingValidator.Issue(
                        "/fieldPolicy/READ/allowed",
                        "DUPLICATE_OPERATION_TARGET",
                        "Only one operation may write a logical policy target"
                )
        );
    }

    @Test
    void rejectsUndeclaredChangesEvenWhenDeclaredOperationIsValid() {
        ObjectNode base = validBase();
        ObjectNode result = nextVersion(base);
        ((ObjectNode) result.path("externalEgress")).put("allowed", false);
        result.put("purpose", "DIFFERENT_PURPOSE");

        ValidationResult validation = validator.validate(
                base,
                result,
                List.of(new AddConstraint(ConstraintKind.DISABLE_EXTERNAL_EGRESS))
        );

        assertInvalidExactly(
                validation,
                new SafetyContractNarrowingValidator.Issue(
                        "/",
                        "UNDECLARED_POLICY_CHANGE",
                        "Result must equal base plus version increment and declared operations"
                )
        );
    }

    @Test
    void rejectsStructurallyInvalidBaseAndResultBeforeApplyingOperations() {
        ObjectNode invalidBase = validBase();
        invalidBase.put("unknownBasePolicy", true);
        ObjectNode validResult = nextVersion(validBase());
        ((ObjectNode) validResult.path("externalEgress")).put("allowed", false);
        ValidationResult baseValidation = validator.validate(
                invalidBase,
                validResult,
                List.of(new AddConstraint(ConstraintKind.DISABLE_EXTERNAL_EGRESS))
        );

        ObjectNode base = validBase();
        ObjectNode result = nextVersion(base);
        result.put("unknownPolicy", true);
        ValidationResult resultValidation = validator.validate(
                base,
                result,
                List.of(new AddConstraint(ConstraintKind.DISABLE_EXTERNAL_EGRESS))
        );

        assertInvalidExactly(
                baseValidation,
                new SafetyContractNarrowingValidator.Issue(
                        "/base/unknownBasePolicy",
                        "BASE_UNKNOWN_FIELD",
                        "Unknown Safety Contract field"
                )
        );
        assertInvalidExactly(
                resultValidation,
                new SafetyContractNarrowingValidator.Issue(
                        "/result/unknownPolicy",
                        "RESULT_UNKNOWN_FIELD",
                        "Unknown Safety Contract field"
                )
        );
    }

    @Test
    void rejectsCanonicalNfcFieldNameCollisionWithStableNoProofIssue() {
        ObjectNode base = validBase();
        ObjectNode fieldPolicy = (ObjectNode) base.path("fieldPolicy");
        ObjectNode decomposedPolicy = JsonNodeFactory.instance.objectNode();
        decomposedPolicy.putArray("allowed").add("income");
        fieldPolicy.set("cafe\u0301", decomposedPolicy);
        ObjectNode composedPolicy = JsonNodeFactory.instance.objectNode();
        composedPolicy.putArray("allowed").add("employment");
        fieldPolicy.set("café", composedPolicy);
        ObjectNode result = nextVersion(base);
        ((ObjectNode) result.path("externalEgress")).put("allowed", false);
        String baseBefore = base.toString();
        String resultBefore = result.toString();

        ValidationResult validation = validator.validate(
                base,
                result,
                List.of(new AddConstraint(ConstraintKind.DISABLE_EXTERNAL_EGRESS))
        );

        assertInvalidExactly(
                validation,
                new SafetyContractNarrowingValidator.Issue(
                        "/",
                        "CANONICALIZATION_FAILURE",
                        "Patch snapshots could not be canonicalized"
                )
        );
        assertThat(base.toString()).isEqualTo(baseBefore);
        assertThat(result.toString()).isEqualTo(resultBefore);
    }

    @Test
    void rejectedValidationDoesNotMutateCallerSnapshots() {
        ObjectNode base = validBase();
        ObjectNode result = nextVersion(base);
        String baseBefore = base.toString();
        String resultBefore = result.toString();

        ValidationResult validation = validator.validate(
                base,
                result,
                List.of(new AddConstraint(ConstraintKind.DISABLE_EXTERNAL_EGRESS))
        );

        assertThat(validation.valid()).isFalse();
        assertThat(base.toString()).isEqualTo(baseBefore);
        assertThat(result.toString()).isEqualTo(resultBefore);
    }

    @Test
    void rejectsNullEmptyAndNullEntryOperationListsWithNoProof() {
        ObjectNode base = validBase();
        ObjectNode result = nextVersion(base);

        ValidationResult nullList = validator.validate(base, result, null);
        ValidationResult emptyList = validator.validate(base, result, List.of());
        List<SafetyContractPatchOperation> nullEntry = new ArrayList<>();
        nullEntry.add(null);
        ValidationResult nullOperation = validator.validate(base, result, nullEntry);

        SafetyContractNarrowingValidator.Issue emptyPatch =
                new SafetyContractNarrowingValidator.Issue(
                        "/operations",
                        "EMPTY_PATCH",
                        "Patch must contain at least one typed operation"
                );
        assertInvalidExactly(nullList, emptyPatch);
        assertInvalidExactly(emptyList, emptyPatch);
        assertInvalidExactly(
                nullOperation,
                new SafetyContractNarrowingValidator.Issue(
                        "/operations/0",
                        "NULL_OPERATION",
                        "Patch operations must not be null"
                )
        );
    }

    @Test
    void neverMutatesCallerSnapshotsAndBindsCanonicalHashes() {
        ObjectNode base = validBase();
        ObjectNode result = nextVersion(base);
        ((ObjectNode) result.path("externalEgress")).put("allowed", false);
        String baseBefore = base.toString();
        String resultBefore = result.toString();

        ValidationResult validation = validator.validate(
                base,
                result,
                List.of(new AddConstraint(ConstraintKind.DISABLE_EXTERNAL_EGRESS))
        );

        assertThat(validation.valid()).isTrue();
        assertThat(base.toString()).isEqualTo(baseBefore);
        assertThat(result.toString()).isEqualTo(resultBefore);
        SafetyContractNarrowingValidator.ValidatedPatch proof =
                validation.validatedPatch().orElseThrow();
        assertThat(proof.basePolicyHash())
                .isEqualTo(canonicalizer.canonicalizeAndHash(base).policyHash());
        assertThat(proof.resultPolicyHash())
                .isEqualTo(canonicalizer.canonicalizeAndHash(result).policyHash());
        assertThat(proof.basePolicyHash()).isNotEqualTo(proof.resultPolicyHash());
    }

    @Test
    void proofUsesOneBoundarySnapshotDespiteLaterCallerMutations() {
        ObjectNode base = validBase();
        ObjectNode result = nextVersion(base);
        ((ObjectNode) result.path("externalEgress")).put("allowed", false);
        AddConstraint operation = new AddConstraint(
                ConstraintKind.DISABLE_EXTERNAL_EGRESS
        );
        List<SafetyContractPatchOperation> mutableOperations = new ArrayList<>();
        mutableOperations.add(operation);
        String baseSnapshotJson = base.toString();
        String resultSnapshotJson = result.toString();

        SafetyContractSchemaValidator schemaValidator = new SafetyContractSchemaValidator();
        CanonicalJsonService canonicalJsonService = new CanonicalJsonService(objectMapper);
        SafetyContractCanonicalizer mutatingCanonicalizer = new SafetyContractCanonicalizer(
                schemaValidator,
                canonicalJsonService,
                new DigestService()
        ) {
            private boolean mutated;

            @Override
            public CanonicalPolicy canonicalizeAndHash(tools.jackson.databind.JsonNode contract) {
                if (!mutated) {
                    mutated = true;
                    base.put("purpose", "CALLER_MUTATED_BASE");
                    result.put("purpose", "CALLER_MUTATED_RESULT");
                    mutableOperations.clear();
                }
                return super.canonicalizeAndHash(contract);
            }
        };
        SafetyContractNarrowingValidator isolatedValidator =
                new SafetyContractNarrowingValidator(schemaValidator, mutatingCanonicalizer);

        ValidationResult validation = isolatedValidator.validate(
                base,
                result,
                mutableOperations
        );

        assertThat(validation.valid()).isTrue();
        SafetyContractNarrowingValidator.ValidatedPatch proof =
                validation.validatedPatch().orElseThrow();
        assertThat(proof.operations()).containsExactly(operation);
        assertThat(mutableOperations).isEmpty();
        assertThat(proof.basePolicyHash()).isEqualTo(
                canonicalizer.canonicalizeAndHash(
                        objectMapper.readTree(baseSnapshotJson)
                ).policyHash()
        );
        assertThat(proof.resultPolicyHash()).isEqualTo(
                canonicalizer.canonicalizeAndHash(
                        objectMapper.readTree(resultSnapshotJson)
                ).policyHash()
        );
    }

    @Test
    void validationResultsAndTypedPayloadsAreDefensivelyImmutable() {
        List<String> retainedSource = new ArrayList<>(List.of("income", "employment"));
        NarrowSet operation = new NarrowSet(
                SetKind.ALLOWED_FIELDS,
                "READ",
                retainedSource
        );
        retainedSource.clear();
        ObjectNode base = validBase();
        ObjectNode result = nextVersion(base);
        replaceArray(
                (ObjectNode) result.at("/fieldPolicy/READ"),
                "allowed",
                List.of("employment", "income")
        );
        ValidationResult valid = validator.validate(base, result, List.of(operation));
        ValidationResult invalid = validator.validate(base, result, List.of());

        assertThat(operation.retainedValues()).containsExactly("employment", "income");
        assertThatThrownBy(() -> operation.retainedValues().add("address"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> valid.validatedPatch().orElseThrow().operations().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> invalid.issues().clear())
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void repeatedValidationIsDeterministicIncludingIssueOrder() {
        ObjectNode base = validBase();
        ObjectNode result = nextVersion(base);
        List<SafetyContractPatchOperation> operations = List.of(
                new DenyTool("UNKNOWN"),
                new AddConstraint(ConstraintKind.DISABLE_EXTERNAL_EGRESS)
        );

        ValidationResult first = validator.validate(base, result, operations);
        ValidationResult second = validator.validate(base, result, operations);

        assertThat(first).isEqualTo(second);
        assertInvalidExactly(
                first,
                new SafetyContractNarrowingValidator.Issue(
                        "/allowedTools/UNKNOWN",
                        "TOOL_NOT_ALLOWED_IN_BASE",
                        "DENY_TOOL requires a tool allowed by the base contract"
                ),
                new SafetyContractNarrowingValidator.Issue(
                        "/externalEgress/allowed",
                        "RESULT_VALUE_MISMATCH",
                        "Patch result does not contain the declared constraint"
                )
        );
    }

    private void assertValid(
            ValidationResult result,
            SafetyContractPatchOperation expectedOperation
    ) {
        assertThat(result.valid()).isTrue();
        assertThat(result.issues()).isEmpty();
        assertThat(result.validatedPatch()).isPresent();
        assertThat(result.validatedPatch().orElseThrow().operations())
                .containsExactly(expectedOperation);
    }

    private void assertInvalidExactly(
            ValidationResult result,
            SafetyContractNarrowingValidator.Issue... expectedIssues
    ) {
        assertThat(result.valid()).isFalse();
        assertThat(result.validatedPatch()).isEmpty();
        assertThat(result.issues()).containsExactly(expectedIssues);
    }

    private ObjectNode validBase() {
        return (ObjectNode) objectMapper.readTree("""
                {
                  "schemaVersion": "1.0",
                  "contractId": "loan-review-default",
                  "version": 7,
                  "purpose": "LOAN_DOCUMENT_COMPLETENESS_REVIEW",
                  "allowedTools": ["READ", "WRITE", "HUMAN_TOOL"],
                  "resourcePolicies": {},
                  "fieldPolicy": {
                    "READ": {
                      "allowed": ["income", "employment", "address"],
                      "denyUnknown": false
                    }
                  },
                  "cardinality": {
                    "READ": {"maxRequestedRecords": 5, "maxReturnedRecords": 5}
                  },
                  "externalEgress": {
                    "allowed": true,
                    "allowedDestinations": ["DEST_A", "DEST_B"]
                  },
                  "workflow": {"allowedStages": ["DOCUMENT_REVIEW", "ARCHIVE"]},
                  "highImpactActions": {},
                  "toolTrust": {
                    "requireTrustedTool": false,
                    "allowedTrustLevels": ["TRUSTED_INTERNAL", "MIXED"]
                  },
                  "outputPolicy": {
                    "reviewStatusAllowed": ["READY_FOR_HUMAN_REVIEW", "NEEDS_MORE_DOCUMENTS"]
                  },
                  "metadata": {"templateVersion": "loan-review/1", "validatorVersion": "1.0"}
                }
                """);
    }

    private ObjectNode nextVersion(ObjectNode base) {
        ObjectNode result = base.deepCopy();
        result.put("version", base.path("version").bigIntegerValue().add(BigInteger.ONE));
        return result;
    }

    private static void replaceArray(ObjectNode parent, String field, List<String> values) {
        ArrayNode array = JsonNodeFactory.instance.arrayNode();
        values.forEach(array::add);
        parent.set(field, array);
    }

    private static void removeText(ArrayNode array, String value) {
        for (int index = array.size() - 1; index >= 0; index--) {
            if (array.get(index).stringValue().equals(value)) {
                array.remove(index);
            }
        }
    }

    private static Stream<Arguments> constraintCases() {
        return Stream.of(
                Arguments.of(
                        ConstraintKind.CURRENT_APPLICANT_ONLY,
                        null,
                        (Consumer<ObjectNode>) result -> result.set(
                                "customerScope",
                                JsonNodeFactory.instance.objectNode()
                                        .put("type", "CURRENT_APPLICANT_ONLY")
                        )
                ),
                Arguments.of(
                        ConstraintKind.CURRENT_CASE_ONLY,
                        "READ",
                        (Consumer<ObjectNode>) result -> ((ObjectNode) result
                                .path("resourcePolicies")).set(
                                        "READ",
                                        JsonNodeFactory.instance.objectNode()
                                                .put("caseScope", "CURRENT_CASE_ONLY")
                                )
                ),
                Arguments.of(
                        ConstraintKind.ALLOWED_DOCUMENTS_ONLY,
                        "READ",
                        (Consumer<ObjectNode>) result -> ((ObjectNode) result
                                .path("resourcePolicies")).set(
                                        "READ",
                                        JsonNodeFactory.instance.objectNode().put(
                                                "documentScope",
                                                "ALLOWED_DOCUMENTS_ONLY"
                                        )
                                )
                ),
                Arguments.of(
                        ConstraintKind.DENY_UNKNOWN_FIELDS,
                        "READ",
                        (Consumer<ObjectNode>) result -> ((ObjectNode) result
                                .at("/fieldPolicy/READ")).put("denyUnknown", true)
                ),
                Arguments.of(
                        ConstraintKind.REQUIRE_TRUSTED_TOOL,
                        null,
                        (Consumer<ObjectNode>) result -> ((ObjectNode) result
                                .path("toolTrust")).put("requireTrustedTool", true)
                ),
                Arguments.of(
                        ConstraintKind.DISABLE_EXTERNAL_EGRESS,
                        null,
                        (Consumer<ObjectNode>) result -> ((ObjectNode) result
                                .path("externalEgress")).put("allowed", false)
                )
        );
    }

    private static Stream<Arguments> setCases() {
        return Stream.of(
                Arguments.of(
                        SetKind.ALLOWED_FIELDS,
                        "READ",
                        List.of("income", "employment"),
                        (Consumer<ObjectNode>) result -> replaceArray(
                                (ObjectNode) result.at("/fieldPolicy/READ"),
                                "allowed",
                                List.of("employment", "income")
                        )
                ),
                Arguments.of(
                        SetKind.ALLOWED_DESTINATIONS,
                        null,
                        List.of("DEST_A"),
                        (Consumer<ObjectNode>) result -> replaceArray(
                                (ObjectNode) result.path("externalEgress"),
                                "allowedDestinations",
                                List.of("DEST_A")
                        )
                ),
                Arguments.of(
                        SetKind.WORKFLOW_STAGES,
                        null,
                        List.of("DOCUMENT_REVIEW"),
                        (Consumer<ObjectNode>) result -> replaceArray(
                                (ObjectNode) result.path("workflow"),
                                "allowedStages",
                                List.of("DOCUMENT_REVIEW")
                        )
                ),
                Arguments.of(
                        SetKind.ALLOWED_TRUST_LEVELS,
                        null,
                        List.of("TRUSTED_INTERNAL"),
                        (Consumer<ObjectNode>) result -> replaceArray(
                                (ObjectNode) result.path("toolTrust"),
                                "allowedTrustLevels",
                                List.of("TRUSTED_INTERNAL")
                        )
                ),
                Arguments.of(
                        SetKind.REVIEW_STATUSES,
                        null,
                        List.of("READY_FOR_HUMAN_REVIEW"),
                        (Consumer<ObjectNode>) result -> replaceArray(
                                (ObjectNode) result.path("outputPolicy"),
                                "reviewStatusAllowed",
                                List.of("READY_FOR_HUMAN_REVIEW")
                        )
                )
        );
    }

    private static Stream<Arguments> limitCases() {
        return Stream.of(
                Arguments.of(
                        LimitKind.MAX_REQUESTED_RECORDS,
                        (Consumer<ObjectNode>) result -> ((ObjectNode) result
                                .at("/cardinality/READ")).put("maxRequestedRecords", 1)
                ),
                Arguments.of(
                        LimitKind.MAX_RETURNED_RECORDS,
                        (Consumer<ObjectNode>) result -> ((ObjectNode) result
                                .at("/cardinality/READ")).put("maxReturnedRecords", 1)
                )
        );
    }

    private static Stream<Arguments> nonLowerLimits() {
        return Stream.of(
                Arguments.of(
                        BigInteger.valueOf(-1),
                        "INVALID_LIMIT",
                        "Cardinality limit must be nonnegative"
                ),
                Arguments.of(
                        BigInteger.valueOf(5),
                        "LIMIT_NOT_LOWERED",
                        "LOWER_LIMIT must strictly reduce a nonnegative base limit"
                ),
                Arguments.of(
                        BigInteger.valueOf(6),
                        "LIMIT_NOT_LOWERED",
                        "LOWER_LIMIT must strictly reduce a nonnegative base limit"
                )
        );
    }
}
