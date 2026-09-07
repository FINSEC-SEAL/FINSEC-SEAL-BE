package com.finsecseal.contract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.finsecseal.contract.SafetyContractSemanticValidator.ContractValidationCatalog;
import com.finsecseal.contract.SafetyContractSemanticValidator.Issue;
import com.finsecseal.contract.SafetyContractSemanticValidator.IssueSeverity;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationResult;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationStatus;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.ReleaseDto.ToolCatalogResponse;
import com.finsecseal.release.ReleaseService;
import java.io.IOException;
import java.io.InputStream;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

class LoanReviewFinancialTemplateTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SafetyContractSchemaValidator schemaValidator = new SafetyContractSchemaValidator();
    private final SafetyContractSemanticValidator semanticValidator =
            new SafetyContractSemanticValidator(schemaValidator);
    private final CanonicalJsonService canonicalJsonService = new CanonicalJsonService(objectMapper);
    private final DigestService digestService = new DigestService();
    private final SafetyContractCanonicalizer canonicalizer = new SafetyContractCanonicalizer(
            schemaValidator, canonicalJsonService, digestService
    );
    private final LoanReviewFinancialTemplate template = new LoanReviewFinancialTemplate(objectMapper);
    private ContractValidationCatalog catalog;

    @BeforeEach
    void loadRealFixtureThroughProductionCatalogAdapter() throws IOException {
        ObjectNode manifest = fixture("valid-release-manifest-v1.1.json");
        UUID releaseId = UUID.fromString("12345678-1234-4abc-8def-1234567890ab");
        ReleaseService releases = mock(ReleaseService.class);
        // The A source boundary is mocked here; transaction/integrity evidence is integration-owned.
        when(releases.toolCatalog(releaseId, "template-test")).thenReturn(new ToolCatalogResponse(
                releaseId,
                "1.1",
                "sha256:" + "a".repeat(64),
                "sha256:" + "b".repeat(64),
                "sha256:8d720bd3b28a0392d1e45a3ff9cf2a75c59db1baee86a37208dc9ba28642938e",
                manifest.path("tools"),
                manifest.path("serverToolCatalog")
        ));
        catalog = new ReleaseToolCatalogContractAdapter(
                releases, canonicalJsonService, digestService, objectMapper
        ).load(releaseId, "template-test").semanticCatalog();
    }

    @Test
    void matchesPublishedPolicyAndPassesRealValidatorsWithTestOnlyIdentity() throws IOException {
        ObjectNode published = fixture("loan-review-safety-contract.json");
        published.remove("contractId");
        published.remove("version");

        assertThat(template.policyRules()).isEqualTo(published);
        assertThat(template.policyRules().path("purpose").stringValue())
                .isEqualTo(LoanReviewFinancialTemplate.PURPOSE);
        assertThat(template.policyRules().at("/metadata/templateVersion").stringValue())
                .isEqualTo(LoanReviewFinancialTemplate.KEY);

        ObjectNode candidate = testCandidate();
        published.put("contractId", "test-only-contract");
        published.put("version", 7);
        assertThat(schemaValidator.validate(candidate).issues()).isEmpty();
        ValidationResult result = semanticValidator.validate(candidate, catalog);
        assertThat(result.status()).isEqualTo(ValidationStatus.VALID);
        assertThat(result.issues()).isEmpty();
        assertThat(canonicalizer.canonicalizeAndHash(candidate))
                .isEqualTo(canonicalizer.canonicalizeAndHash(published));
    }

    @Test
    void doesNotAllocateIdentityOrYieldACompleteCandidateWithoutRoleAIdentity() {
        JsonNode rules = template.policyRules();

        assertThat(rules.has("contractId")).isFalse();
        assertThat(rules.has("version")).isFalse();
        assertThat(rules.has("approval")).isFalse();
        ValidationResult result = semanticValidator.validate(rules, catalog);
        assertThat(result.status()).isEqualTo(ValidationStatus.INVALID);
        assertThat(result.issues()).extracting(Issue::jsonPointer, Issue::code, Issue::severity)
                .containsExactly(
                        tuple("/contractId", "CONTRACT_ID_REQUIRED", IssueSeverity.ERROR),
                        tuple("/version", "CONTRACT_VERSION_REQUIRED", IssueSeverity.ERROR)
                );
    }

    @Test
    void isolatesCallerMutationsAtEveryNestedContainer() {
        ObjectNode original = (ObjectNode) template.policyRules();
        ObjectNode returned = (ObjectNode) template.policyRules();
        returned.put("contractId", "caller-owned");
        ((ArrayNode) returned.path("allowedTools")).removeAll();
        ((ObjectNode) returned.at("/fieldPolicy/CUSTOMER_DATA_READ")).put("denyUnknown", false);
        ((ArrayNode) returned.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed")).add("accountNumber");
        ((ObjectNode) returned.path("metadata")).put("templateVersion", "altered");

        assertThat(template.policyRules()).isEqualTo(original).isNotSameAs(original);
        assertThat(original.has("contractId")).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "CASE_CONTEXT_READ", "DOCUMENT_READER", "CUSTOMER_DATA_READ",
            "LOAN_POLICY_SEARCH", "REVIEW_NOTE_WRITE"
    })
    void rejectsLossOfEachRequiredBusinessTool(String missingTool) {
        ObjectNode candidate = testCandidate();
        ArrayNode tools = (ArrayNode) candidate.path("allowedTools");
        for (int index = tools.size() - 1; index >= 0; index--) {
            if (missingTool.equals(tools.get(index).stringValue())) {
                tools.remove(index);
            }
        }

        ValidationResult result = semanticValidator.validate(candidate, catalog);

        assertThat(result.status()).isEqualTo(ValidationStatus.INVALID);
        assertThat(result.issues()).containsExactly(new Issue(
                "/allowedTools", "REQUIRED_TOOL_MISSING", IssueSeverity.ERROR,
                "Required loan-review Tool is missing: " + missingTool
        ));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', textBlock = """
            /unexpected | true | /unexpected | UNKNOWN_FIELD
            /metadata/generator | "untrusted" | /metadata/generator | UNKNOWN_FIELD
            /allowedTools | ["CASE_CONTEXT_READ","CASE_CONTEXT_READ","DOCUMENT_READER","CUSTOMER_DATA_READ","LOAN_POLICY_SEARCH","REVIEW_NOTE_WRITE"] | /allowedTools/1 | DUPLICATE_VALUE
            /fieldPolicy/CUSTOMER_DATA_READ/allowed | ["incomeBand"] | /fieldPolicy/CUSTOMER_DATA_READ/allowed | REQUIRED_FIELD_MISSING
            /fieldPolicy/CUSTOMER_DATA_READ/allowed | ["employmentStatus"] | /fieldPolicy/CUSTOMER_DATA_READ/allowed | REQUIRED_FIELD_MISSING
            /fieldPolicy/CUSTOMER_DATA_READ/allowed | ["incomeBand","employmentStatus","accountNumber"] | /fieldPolicy/CUSTOMER_DATA_READ/allowed/2 | FIELD_EXCEEDS_TEMPLATE
            /fieldPolicy/CUSTOMER_DATA_READ/denyUnknown | false | /fieldPolicy/CUSTOMER_DATA_READ/denyUnknown | DENY_UNKNOWN_FIELDS_REQUIRED
            /resourcePolicies/DOCUMENT_READER/caseScope | "ANY_CASE" | /resourcePolicies/DOCUMENT_READER/caseScope | CASE_SCOPE_EXCEEDS_TEMPLATE
            /resourcePolicies/DOCUMENT_READER/documentScope | "ANY_DOCUMENT" | /resourcePolicies/DOCUMENT_READER/documentScope | DOCUMENT_SCOPE_EXCEEDS_TEMPLATE
            /resourcePolicies/REVIEW_NOTE_WRITE/caseScope | "ANY_CASE" | /resourcePolicies/REVIEW_NOTE_WRITE/caseScope | CASE_SCOPE_EXCEEDS_TEMPLATE
            /customerScope/type | "ANY_CUSTOMER" | /customerScope/type | CUSTOMER_SCOPE_EXCEEDS_TEMPLATE
            /cardinality/CUSTOMER_DATA_READ/maxRequestedRecords | 0 | /cardinality/CUSTOMER_DATA_READ/maxRequestedRecords | CARDINALITY_LIMIT_INVALID
            /cardinality/CUSTOMER_DATA_READ/maxRequestedRecords | 2 | /cardinality/CUSTOMER_DATA_READ/maxRequestedRecords | CARDINALITY_EXCEEDS_TEMPLATE
            /cardinality/CUSTOMER_DATA_READ/maxReturnedRecords | 0 | /cardinality/CUSTOMER_DATA_READ/maxReturnedRecords | CARDINALITY_LIMIT_INVALID
            /cardinality/CUSTOMER_DATA_READ/maxReturnedRecords | 2 | /cardinality/CUSTOMER_DATA_READ/maxReturnedRecords | CARDINALITY_EXCEEDS_TEMPLATE
            /externalEgress/allowed | true | /externalEgress/allowed | EXTERNAL_EGRESS_NOT_DENIED
            /externalEgress/allowedDestinations | ["mock://collector"] | /externalEgress/allowedDestinations | EGRESS_DESTINATION_CONFLICT
            /workflow/allowedStages | [] | /workflow/allowedStages | REQUIRED_WORKFLOW_STAGE_MISSING
            /workflow/allowedStages | ["DOCUMENT_REVIEW","ARCHIVE"] | /workflow/allowedStages/1 | WORKFLOW_STAGE_EXCEEDS_TEMPLATE
            /highImpactActions/LOAN_DECISION_UPDATE | "AGENT_ALLOWED" | /highImpactActions/LOAN_DECISION_UPDATE | LOAN_DECISION_POLICY_INVALID
            /allowedTools | ["CASE_CONTEXT_READ","DOCUMENT_READER","CUSTOMER_DATA_READ","LOAN_POLICY_SEARCH","REVIEW_NOTE_WRITE","LOAN_DECISION_UPDATE"] | /allowedTools/5 | HUMAN_ONLY_TOOL_ALLOWED
            /toolTrust/requireTrustedTool | false | /toolTrust/requireTrustedTool | TRUSTED_TOOL_REQUIRED
            /toolTrust/allowedTrustLevels | ["TRUSTED_INTERNAL","MIXED"] | /toolTrust/allowedTrustLevels/1 | UNTRUSTED_LEVEL_ALLOWED
            /outputPolicy/reviewStatusAllowed | ["READY_FOR_HUMAN_REVIEW"] | /outputPolicy/reviewStatusAllowed | REQUIRED_REVIEW_STATUS_MISSING
            /outputPolicy/reviewStatusAllowed | ["NEEDS_MORE_DOCUMENTS"] | /outputPolicy/reviewStatusAllowed | REQUIRED_REVIEW_STATUS_MISSING
            /outputPolicy/reviewStatusAllowed | ["READY_FOR_HUMAN_REVIEW","NEEDS_MORE_DOCUMENTS","AUTO_APPROVED"] | /outputPolicy/reviewStatusAllowed/2 | REVIEW_STATUS_EXCEEDS_TEMPLATE
            """)
    void rejectsDeparturesFromFinancialMinimumsAndMaximums(
            String changedPointer, String replacementJson, String issuePointer, String issueCode
    ) {
        ObjectNode candidate = testCandidate();
        int separator = changedPointer.lastIndexOf('/');
        ObjectNode parent = (ObjectNode) candidate.at(changedPointer.substring(0, separator));
        parent.set(changedPointer.substring(separator + 1), objectMapper.readTree(replacementJson));

        ValidationResult result = semanticValidator.validate(candidate, catalog);

        assertThat(result.status()).isEqualTo(ValidationStatus.INVALID);
        assertThat(result.issues()).extracting(Issue::jsonPointer, Issue::code, Issue::severity)
                .contains(tuple(issuePointer, issueCode, IssueSeverity.ERROR));
    }

    private ObjectNode testCandidate() {
        ObjectNode candidate = (ObjectNode) template.policyRules();
        candidate.put("contractId", "test-only-contract");
        candidate.put("version", 7);
        return candidate;
    }

    private ObjectNode fixture(String name) throws IOException {
        try (InputStream input = getClass().getResourceAsStream("/fixtures/" + name)) {
            if (input == null) {
                throw new IOException("Fixture is missing");
            }
            return (ObjectNode) objectMapper.readTree(input);
        }
    }
}
