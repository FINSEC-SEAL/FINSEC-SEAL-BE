package com.finsecseal.contract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.contract.SafetyContractSemanticValidator.ContractValidationCatalog;
import com.finsecseal.contract.SafetyContractSemanticValidator.EnabledTool;
import com.finsecseal.contract.SafetyContractSemanticValidator.Issue;
import com.finsecseal.contract.SafetyContractSemanticValidator.IssueSeverity;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationResult;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationStatus;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

class SafetyContractSemanticValidatorTest {

    private ObjectMapper objectMapper;
    private SafetyContractSemanticValidator validator;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        validator = new SafetyContractSemanticValidator(new SafetyContractSchemaValidator());
    }

    @Test
    void acceptsLoanReviewTemplateRelativeToSuppliedCatalogWithoutMutatingInputs() {
        ObjectNode contract = validContract();
        ObjectNode original = contract.deepCopy();
        ContractValidationCatalog catalog = validCatalog();

        ValidationResult result = validator.validate(contract, catalog);

        assertThat(result.status()).isEqualTo(ValidationStatus.VALID);
        assertThat(result.issues()).isEmpty();
        assertThat(contract).isEqualTo(original);
        assertThat(catalog).isEqualTo(validCatalog());
    }

    @Test
    void schemaFailureShortCircuitsSemanticsAndDoesNotAccessNullCatalog() {
        ObjectNode contract = validContract();
        contract.put("unexpected", true);
        contract.remove("allowedTools");

        ValidationResult result = validator.validate(contract, null);

        assertThat(result.status()).isEqualTo(ValidationStatus.INVALID);
        assertThat(result.issues()).containsExactly(new Issue(
                "/unexpected",
                "UNKNOWN_FIELD",
                IssueSeverity.ERROR,
                "Unknown Safety Contract field"
        ));
    }

    @Test
    void rejectsAllDenyContractWhenNormalToolsAreMissing() {
        ObjectNode contract = validContract();
        ((ArrayNode) contract.path("allowedTools")).removeAll();

        ValidationResult result = validator.validate(contract, validCatalog());

        assertThat(result.status()).isEqualTo(ValidationStatus.INVALID);
        assertThat(result.issues())
                .filteredOn(issue -> issue.code().equals("REQUIRED_TOOL_MISSING"))
                .extracting(Issue::message)
                .containsExactly(
                        "Required loan-review Tool is missing: CASE_CONTEXT_READ",
                        "Required loan-review Tool is missing: CUSTOMER_DATA_READ",
                        "Required loan-review Tool is missing: DOCUMENT_READER",
                        "Required loan-review Tool is missing: LOAN_POLICY_SEARCH",
                        "Required loan-review Tool is missing: REVIEW_NOTE_WRITE"
                );
    }

    @Test
    void rejectsHumanOnlyToolInAgentAllowlistEvenWhenCatalogedAsEnabled() {
        ObjectNode contract = validContract();
        ((ArrayNode) contract.path("allowedTools")).add("LOAN_DECISION_UPDATE");
        List<EnabledTool> enabled = new ArrayList<>(validCatalog().enabledReleaseTools());
        enabled.add(new EnabledTool("LOAN_DECISION_UPDATE", List.of()));
        ContractValidationCatalog catalog = new ContractValidationCatalog(
                enabled,
                List.of("LOAN_DECISION_UPDATE")
        );

        ValidationResult result = validator.validate(contract, catalog);

        assertIssue(result, "/allowedTools/5", "HUMAN_ONLY_TOOL_ALLOWED");
        assertThat(result.issues()).noneMatch(issue -> issue.code().equals("TOOL_NOT_IN_RELEASE_CATALOG"));
    }

    @Test
    void rejectsCustomerFieldBeyondTemplateEvenWhenToolOutputContainsIt() {
        ObjectNode contract = validContract();
        ((ArrayNode) contract.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed")).add("accountNumber");

        ValidationResult result = validator.validate(contract, validCatalog());

        assertIssue(
                result,
                "/fieldPolicy/CUSTOMER_DATA_READ/allowed/2",
                "FIELD_EXCEEDS_TEMPLATE"
        );
        assertThat(result.issues()).noneMatch(issue -> issue.code().equals("FIELD_NOT_IN_TOOL_OUTPUT"));
    }

    @Test
    void rejectsFieldAbsentFromExactToolOutputSchema() {
        ObjectNode contract = validContract();
        ((ArrayNode) contract.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed")).add("notInOutput");

        ValidationResult result = validator.validate(contract, validCatalog());

        assertIssue(
                result,
                "/fieldPolicy/CUSTOMER_DATA_READ/allowed/2",
                "FIELD_NOT_IN_TOOL_OUTPUT"
        );
        assertIssue(
                result,
                "/fieldPolicy/CUSTOMER_DATA_READ/allowed/2",
                "FIELD_EXCEEDS_TEMPLATE"
        );
    }

    @Test
    void rejectsMissingRequiredFieldAndPermissiveUnknownFieldPolicy() {
        ObjectNode contract = validContract();
        ArrayNode fields = (ArrayNode) contract.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed");
        fields.removeAll().add("incomeBand");
        ((ObjectNode) contract.at("/fieldPolicy/CUSTOMER_DATA_READ")).put("denyUnknown", false);

        ValidationResult result = validator.validate(contract, validCatalog());

        assertIssue(result, "/fieldPolicy/CUSTOMER_DATA_READ/allowed", "REQUIRED_FIELD_MISSING");
        assertIssue(result, "/fieldPolicy/CUSTOMER_DATA_READ/denyUnknown", "DENY_UNKNOWN_FIELDS_REQUIRED");
    }

    @Test
    void rejectsMissingOrMismatchedContractIdentityAndTemplateVersions() {
        ObjectNode contract = validContract();
        contract.put("contractId", " ");
        contract.put("version", 0);
        contract.put("purpose", "loan_document_completeness_review");
        ((ObjectNode) contract.path("metadata"))
                .put("templateVersion", "loan-review/2")
                .remove("validatorVersion");

        ValidationResult result = validator.validate(contract, validCatalog());

        assertCodes(result,
                "CONTRACT_ID_REQUIRED",
                "CONTRACT_VERSION_INVALID",
                "PURPOSE_MISMATCH",
                "TEMPLATE_VERSION_MISMATCH",
                "VALIDATOR_VERSION_REQUIRED"
        );
    }

    @Test
    void rejectsResourceAndCustomerScopeExpansion() {
        ObjectNode contract = validContract();
        ((ObjectNode) contract.at("/resourcePolicies/DOCUMENT_READER"))
                .put("caseScope", "ANY_CASE")
                .put("documentScope", "ANY_DOCUMENT");
        ((ObjectNode) contract.path("customerScope")).put("type", "ANY_CUSTOMER");
        ((ObjectNode) contract.at("/resourcePolicies/REVIEW_NOTE_WRITE")).remove("caseScope");

        ValidationResult result = validator.validate(contract, validCatalog());

        assertCodes(result,
                "CASE_SCOPE_EXCEEDS_TEMPLATE",
                "DOCUMENT_SCOPE_EXCEEDS_TEMPLATE",
                "CUSTOMER_SCOPE_EXCEEDS_TEMPLATE",
                "CASE_SCOPE_REQUIRED"
        );
    }

    @Test
    void rejectsMissingNonPositiveAndExpandedCardinalityLimits() {
        ObjectNode contract = validContract();
        ObjectNode policy = (ObjectNode) contract.at("/cardinality/CUSTOMER_DATA_READ");
        policy.put("maxRequestedRecords", 2);
        policy.remove("maxReturnedRecords");
        ((ObjectNode) contract.path("cardinality")).set(
                "DOCUMENT_READER",
                objectMapper.createObjectNode().put("maxRequestedRecords", 0)
        );

        ValidationResult result = validator.validate(contract, validCatalog());

        assertIssue(result, "/cardinality/CUSTOMER_DATA_READ/maxRequestedRecords", "CARDINALITY_EXCEEDS_TEMPLATE");
        assertIssue(result, "/cardinality/CUSTOMER_DATA_READ/maxReturnedRecords", "CARDINALITY_LIMIT_REQUIRED");
        assertIssue(result, "/cardinality/DOCUMENT_READER/maxRequestedRecords", "CARDINALITY_LIMIT_INVALID");
    }

    @Test
    void rejectsCardinalityLargerThanIntegerRangeWithoutOverflowBypass() {
        ObjectNode contract = validContract();
        ((ObjectNode) contract.at("/cardinality/CUSTOMER_DATA_READ"))
                .put("maxRequestedRecords", new BigInteger("4294967297"));

        ValidationResult result = validator.validate(contract, validCatalog());

        assertIssue(
                result,
                "/cardinality/CUSTOMER_DATA_READ/maxRequestedRecords",
                "CARDINALITY_EXCEEDS_TEMPLATE"
        );
    }

    @Test
    void rejectsAnyEgressAndDeniedEgressDestinationConflict() {
        ObjectNode contract = validContract();
        ((ObjectNode) contract.path("externalEgress")).put("allowed", true);
        ((ArrayNode) contract.at("/externalEgress/allowedDestinations")).add("mock://collector");

        ValidationResult result = validator.validate(contract, validCatalog());

        assertIssue(result, "/externalEgress/allowed", "EXTERNAL_EGRESS_NOT_DENIED");
        assertIssue(result, "/externalEgress/allowedDestinations", "EGRESS_DESTINATION_CONFLICT");
    }

    @Test
    void rejectsMissingRequiredWorkflowAndAdditionalStage() {
        ObjectNode contract = validContract();
        ArrayNode stages = (ArrayNode) contract.at("/workflow/allowedStages");
        stages.removeAll().add("ARCHIVE");

        ValidationResult result = validator.validate(contract, validCatalog());

        assertIssue(result, "/workflow/allowedStages", "REQUIRED_WORKFLOW_STAGE_MISSING");
        assertIssue(result, "/workflow/allowedStages/0", "WORKFLOW_STAGE_EXCEEDS_TEMPLATE");
    }

    @Test
    void rejectsInvalidOrUncatalogedHighImpactPolicy() {
        ObjectNode contract = validContract();
        ((ObjectNode) contract.path("highImpactActions"))
                .put("LOAN_DECISION_UPDATE", "AGENT_ALLOWED")
                .put("UNKNOWN_ACTION", "HUMAN_ONLY");

        ValidationResult result = validator.validate(contract, validCatalog());

        assertIssue(result, "/highImpactActions/LOAN_DECISION_UPDATE", "HIGH_IMPACT_MODE_INVALID");
        assertIssue(result, "/highImpactActions/LOAN_DECISION_UPDATE", "LOAN_DECISION_POLICY_INVALID");
        assertIssue(result, "/highImpactActions/UNKNOWN_ACTION", "HIGH_IMPACT_TOOL_NOT_IN_CATALOG");
    }

    @Test
    void rejectsHighImpactPolicyWhenServerCatalogOmitsIdentity() {
        ContractValidationCatalog catalog = new ContractValidationCatalog(
                validCatalog().enabledReleaseTools(),
                List.of()
        );

        ValidationResult result = validator.validate(validContract(), catalog);

        assertIssue(
                result,
                "/highImpactActions/LOAN_DECISION_UPDATE",
                "HIGH_IMPACT_TOOL_NOT_IN_CATALOG"
        );
    }

    @Test
    void rejectsPermissiveToolTrustPolicy() {
        ObjectNode contract = validContract();
        ((ObjectNode) contract.path("toolTrust")).put("requireTrustedTool", false);
        ((ArrayNode) contract.at("/toolTrust/allowedTrustLevels")).add("MIXED");

        ValidationResult result = validator.validate(contract, validCatalog());

        assertIssue(result, "/toolTrust/requireTrustedTool", "TRUSTED_TOOL_REQUIRED");
        assertIssue(result, "/toolTrust/allowedTrustLevels/1", "UNTRUSTED_LEVEL_ALLOWED");
    }

    @Test
    void rejectsMissingRequiredReviewStatusAndUnknownStatus() {
        ObjectNode contract = validContract();
        ArrayNode statuses = (ArrayNode) contract.at("/outputPolicy/reviewStatusAllowed");
        statuses.removeAll().add("READY_FOR_HUMAN_REVIEW").add("AUTO_APPROVED");

        ValidationResult result = validator.validate(contract, validCatalog());

        assertIssue(result, "/outputPolicy/reviewStatusAllowed", "REQUIRED_REVIEW_STATUS_MISSING");
        assertIssue(result, "/outputPolicy/reviewStatusAllowed/1", "REVIEW_STATUS_EXCEEDS_TEMPLATE");
    }

    @Test
    void crossReferencesEveryPolicyToolAgainstExactReleaseCatalogIdentity() {
        ObjectNode contract = validContract();
        ((ObjectNode) contract.path("resourcePolicies")).set(
                "document_reader",
                objectMapper.createObjectNode().put("caseScope", "CURRENT_CASE_ONLY")
        );
        ObjectNode fieldPolicy = objectMapper.createObjectNode();
        fieldPolicy.putArray("allowed").add("value");
        ((ObjectNode) contract.path("fieldPolicy")).set("UNKNOWN/FIELD~TOOL", fieldPolicy);
        ((ObjectNode) contract.path("cardinality")).set(
                "UNKNOWN_CARDINALITY_TOOL",
                objectMapper.createObjectNode().put("maxRequestedRecords", 1)
        );

        ValidationResult result = validator.validate(contract, validCatalog());

        assertIssue(result, "/resourcePolicies/document_reader", "POLICY_TOOL_NOT_IN_RELEASE_CATALOG");
        assertIssue(result, "/fieldPolicy/UNKNOWN~1FIELD~0TOOL", "POLICY_TOOL_NOT_IN_RELEASE_CATALOG");
        assertIssue(result, "/cardinality/UNKNOWN_CARDINALITY_TOOL", "POLICY_TOOL_NOT_IN_RELEASE_CATALOG");
    }

    @Test
    void allowedToolCrossReferenceIsExactAndCaseSensitive() {
        ObjectNode contract = validContract();
        ArrayNode tools = (ArrayNode) contract.path("allowedTools");
        tools.set(0, "case_context_read");

        ValidationResult result = validator.validate(contract, validCatalog());

        assertIssue(result, "/allowedTools", "REQUIRED_TOOL_MISSING");
        assertIssue(result, "/allowedTools/0", "TOOL_NOT_IN_RELEASE_CATALOG");
    }

    @Test
    void validationIssuesAreStableAndDeterministicallyOrdered() {
        ObjectNode contract = validContract();
        contract.put("purpose", "WRONG");
        ((ArrayNode) contract.path("allowedTools")).removeAll();
        ((ObjectNode) contract.path("externalEgress")).put("allowed", true);

        ValidationResult first = validator.validate(contract, validCatalog());
        ValidationResult second = validator.validate(contract.deepCopy(), validCatalog());

        assertThat(first).isEqualTo(second);
        assertThat(first.issues()).isSortedAccordingTo(
                java.util.Comparator.comparing(Issue::jsonPointer)
                        .thenComparing(Issue::code)
                        .thenComparing(issue -> issue.severity().name())
                        .thenComparing(Issue::message)
        );
    }

    @Test
    void derivesValidWarnAndInvalidOnlyFromImmutableIssueSeverity() {
        Issue warning = new Issue("/future", "FUTURE_WARNING", IssueSeverity.WARNING, "warning");
        Issue error = new Issue("/failure", "FAILURE", IssueSeverity.ERROR, "error");

        ValidationResult valid = ValidationResult.fromIssues(List.of());
        ValidationResult warn = ValidationResult.fromIssues(List.of(warning));
        ValidationResult invalid = ValidationResult.fromIssues(List.of(warning, error));

        assertThat(valid.status()).isEqualTo(ValidationStatus.VALID);
        assertThat(warn.status()).isEqualTo(ValidationStatus.WARN);
        assertThat(invalid.status()).isEqualTo(ValidationStatus.INVALID);
        assertThatThrownBy(() -> warn.issues().add(error)).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> new ValidationResult(ValidationStatus.VALID, List.of(error)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void catalogDefensivelyCopiesEveryNestedCollection() {
        List<String> outputFields = new ArrayList<>(List.of("field"));
        EnabledTool tool = new EnabledTool("TOOL", outputFields);
        List<EnabledTool> enabledTools = new ArrayList<>(List.of(tool));
        List<String> highImpact = new ArrayList<>(List.of("HIGH"));

        ContractValidationCatalog catalog = new ContractValidationCatalog(enabledTools, highImpact);
        outputFields.add("mutatedField");
        enabledTools.add(new EnabledTool("MUTATED_TOOL", List.of()));
        highImpact.add("MUTATED_HIGH");

        assertThat(catalog.enabledReleaseTools()).containsExactly(new EnabledTool("TOOL", List.of("field")));
        assertThat(catalog.highImpactToolNames()).containsExactly("HIGH");
        assertThat(catalog.hasOutputField("TOOL", "mutatedField")).isFalse();
        assertThatThrownBy(() -> catalog.enabledReleaseTools().add(tool))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> catalog.enabledReleaseTools().getFirst().outputFields().add("x"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> catalog.highImpactToolNames().add("x"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void rejectsNullBlankAndExactDuplicateCatalogEntries() {
        assertThatThrownBy(() -> new EnabledTool(" ", List.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new EnabledTool("TOOL", Arrays.asList("field", null)))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new EnabledTool("TOOL", List.of("field", "field")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ContractValidationCatalog(
                List.of(new EnabledTool("TOOL", List.of()), new EnabledTool("TOOL", List.of())),
                List.of()
        )).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ContractValidationCatalog(
                Arrays.asList(new EnabledTool("TOOL", List.of()), null),
                List.of()
        )).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new ContractValidationCatalog(
                List.of(),
                List.of("HIGH", "HIGH")
        )).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ContractValidationCatalog(null, List.of()))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void validSchemaRequiresCatalogBeforeSemanticValidation() {
        assertThatThrownBy(() -> validator.validate(validContract(), null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("catalog");
    }

    private void assertIssue(ValidationResult result, String pointer, String code) {
        assertThat(result.status()).isEqualTo(ValidationStatus.INVALID);
        assertThat(result.issues()).anyMatch(issue ->
                issue.jsonPointer().equals(pointer) && issue.code().equals(code));
    }

    private void assertCodes(ValidationResult result, String... codes) {
        assertThat(result.status()).isEqualTo(ValidationStatus.INVALID);
        assertThat(result.issues()).extracting(Issue::code).contains(codes);
    }

    private ContractValidationCatalog validCatalog() {
        return new ContractValidationCatalog(
                List.of(
                        new EnabledTool("CASE_CONTEXT_READ", List.of()),
                        new EnabledTool("DOCUMENT_READER", List.of()),
                        new EnabledTool(
                                "CUSTOMER_DATA_READ",
                                List.of("incomeBand", "employmentStatus", "accountNumber")
                        ),
                        new EnabledTool("LOAN_POLICY_SEARCH", List.of()),
                        new EnabledTool("REVIEW_NOTE_WRITE", List.of())
                ),
                List.of("LOAN_DECISION_UPDATE")
        );
    }

    private ObjectNode validContract() {
        return (ObjectNode) objectMapper.readTree("""
                {
                  "schemaVersion": "1.0",
                  "contractId": "loan-review-default",
                  "version": 2,
                  "purpose": "LOAN_DOCUMENT_COMPLETENESS_REVIEW",
                  "allowedTools": [
                    "CASE_CONTEXT_READ",
                    "DOCUMENT_READER",
                    "CUSTOMER_DATA_READ",
                    "LOAN_POLICY_SEARCH",
                    "REVIEW_NOTE_WRITE"
                  ],
                  "resourcePolicies": {
                    "DOCUMENT_READER": {
                      "caseScope": "CURRENT_CASE_ONLY",
                      "documentScope": "ALLOWED_DOCUMENTS_ONLY"
                    },
                    "REVIEW_NOTE_WRITE": {"caseScope": "CURRENT_CASE_ONLY"}
                  },
                  "customerScope": {"type": "CURRENT_APPLICANT_ONLY"},
                  "fieldPolicy": {
                    "CUSTOMER_DATA_READ": {
                      "allowed": ["incomeBand", "employmentStatus"],
                      "denyUnknown": true
                    }
                  },
                  "cardinality": {
                    "CUSTOMER_DATA_READ": {"maxRequestedRecords": 1, "maxReturnedRecords": 1}
                  },
                  "externalEgress": {"allowed": false, "allowedDestinations": []},
                  "workflow": {"allowedStages": ["DOCUMENT_REVIEW"]},
                  "highImpactActions": {"LOAN_DECISION_UPDATE": "HUMAN_ONLY"},
                  "toolTrust": {
                    "requireTrustedTool": true,
                    "allowedTrustLevels": ["TRUSTED_INTERNAL"]
                  },
                  "outputPolicy": {
                    "reviewStatusAllowed": ["READY_FOR_HUMAN_REVIEW", "NEEDS_MORE_DOCUMENTS"]
                  },
                  "metadata": {"templateVersion": "loan-review/1", "validatorVersion": "1.0"}
                }
                """);
    }
}
