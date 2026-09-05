package com.finsecseal.contract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

class SafetyContractSchemaTest {

    private ObjectMapper objectMapper;
    private SafetyContractSchemaValidator validator;
    private SafetyContractCanonicalizer canonicalizer;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        CanonicalJsonService canonicalJsonService = new CanonicalJsonService(objectMapper);
        validator = new SafetyContractSchemaValidator();
        canonicalizer = new SafetyContractCanonicalizer(
                validator,
                canonicalJsonService,
                new DigestService()
        );
    }

    @Test
    void acceptsCompleteV1DocumentAndSchemaDefinedDynamicToolKeys() {
        ObjectNode contract = validContract();
        ((ObjectNode) contract.path("resourcePolicies")).set(
                "FUTURE_TOOL",
                objectMapper.createObjectNode().put("caseScope", "CURRENT_CASE_ONLY")
        );
        ObjectNode futureFieldPolicy = objectMapper.createObjectNode();
        futureFieldPolicy.putArray("allowed").add("futureField");
        ((ObjectNode) contract.path("fieldPolicy")).set("FUTURE_TOOL", futureFieldPolicy);
        ((ObjectNode) contract.path("cardinality")).set(
                "FUTURE_TOOL",
                objectMapper.createObjectNode().put("maxRequestedRecords", 1)
        );
        ((ObjectNode) contract.path("highImpactActions")).put("FUTURE_ACTION", "HUMAN_ONLY");

        assertThat(validator.validate(contract).valid()).isTrue();
        assertThat(validator.validate(contract).issues()).isEmpty();
    }

    @ParameterizedTest
    @MethodSource("fixedObjectPaths")
    void rejectsUnknownFieldsAtEveryFixedObject(String objectPointer) {
        ObjectNode contract = validContract();
        ObjectNode target = objectPointer.isEmpty()
                ? contract
                : (ObjectNode) contract.at(objectPointer);
        target.put("unexpected", true);

        SafetyContractSchemaValidator.ValidationResult result = validator.validate(contract);

        String expectedPointer = objectPointer + "/unexpected";
        assertThat(result.valid()).isFalse();
        assertThat(result.issues())
                .contains(new SafetyContractSchemaValidator.Issue(
                        expectedPointer,
                        "UNKNOWN_FIELD",
                        "Unknown Safety Contract field"
                ));
    }

    @ParameterizedTest
    @MethodSource("setArrayPaths")
    void rejectsDuplicatesInEverySetValuedArray(String arrayPointer) {
        ObjectNode contract = validContract();
        ArrayNode array = (ArrayNode) contract.at(arrayPointer);
        array.removeAll().add("DUPLICATE").add("DUPLICATE");

        SafetyContractSchemaValidator.ValidationResult result = validator.validate(contract);

        assertThat(result.valid()).isFalse();
        assertThat(result.issues())
                .extracting(SafetyContractSchemaValidator.Issue::jsonPointer)
                .contains(arrayPointer + "/1");
        assertThat(result.issues())
                .filteredOn(issue -> issue.jsonPointer().equals(arrayPointer + "/1"))
                .extracting(SafetyContractSchemaValidator.Issue::code)
                .containsExactly("DUPLICATE_VALUE");
    }

    @Test
    void rejectsNfcEquivalentDuplicateValues() {
        ObjectNode contract = validContract();
        ((ArrayNode) contract.path("allowedTools")).add("e\u0301").add("é");

        SafetyContractSchemaValidator.ValidationResult result = validator.validate(contract);

        assertThat(result.issues())
                .extracting(SafetyContractSchemaValidator.Issue::jsonPointer)
                .contains("/allowedTools/6");
        assertThat(result.issues())
                .filteredOn(issue -> issue.jsonPointer().equals("/allowedTools/6"))
                .extracting(SafetyContractSchemaValidator.Issue::code)
                .containsExactly("DUPLICATE_VALUE");
    }

    @Test
    void rejectsLineEndingEquivalentDuplicateValues() {
        ObjectNode contract = validContract();
        ((ArrayNode) contract.path("allowedTools"))
                .add("line\r\nbreak")
                .add("line\rbreak")
                .add("line\nbreak");

        SafetyContractSchemaValidator.ValidationResult result = validator.validate(contract);

        assertThat(result.issues())
                .filteredOn(issue -> issue.code().equals("DUPLICATE_VALUE"))
                .extracting(SafetyContractSchemaValidator.Issue::jsonPointer)
                .containsExactly("/allowedTools/6", "/allowedTools/7");
    }

    @Test
    void rejectsMalformedRootUnsupportedVersionAndPresentFieldTypeMismatch() {
        assertThat(validator.validate(objectMapper.createArrayNode()).issues())
                .containsExactly(new SafetyContractSchemaValidator.Issue(
                        "/",
                        "TYPE",
                        "Safety Contract must be a JSON object"
                ));

        ObjectNode contract = validContract();
        contract.put("schemaVersion", "2.0");
        contract.put("version", "two");

        assertThat(validator.validate(contract).issues())
                .extracting(SafetyContractSchemaValidator.Issue::code)
                .contains("UNSUPPORTED_SCHEMA_VERSION", "TYPE");
    }

    @Test
    void reportsUnknownFieldsInStableOrder() {
        ObjectNode contract = validContract();
        contract.put("zUnknown", true);
        contract.put("aUnknown", true);

        List<String> pointers = validator.validate(contract).issues().stream()
                .filter(issue -> issue.code().equals("UNKNOWN_FIELD"))
                .map(SafetyContractSchemaValidator.Issue::jsonPointer)
                .toList();

        assertThat(pointers).containsExactly("/aUnknown", "/zUnknown");
    }

    @Test
    void canonicalizesObjectOrderUnicodeLineEndingsAndEverySetPermutation() {
        ObjectNode first = canonicalRichContract();
        ObjectNode second = first.deepCopy();
        moveFieldToEnd(second, "schemaVersion");
        second.put("purpose", "cafe\u0301\r\nreview");
        reverse((ArrayNode) second.path("allowedTools"));
        reverse((ArrayNode) second.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed"));
        reverse((ArrayNode) second.at("/externalEgress/allowedDestinations"));
        reverse((ArrayNode) second.at("/workflow/allowedStages"));
        reverse((ArrayNode) second.at("/toolTrust/allowedTrustLevels"));
        reverse((ArrayNode) second.at("/outputPolicy/reviewStatusAllowed"));

        SafetyContractCanonicalizer.CanonicalPolicy firstResult = canonicalizer.canonicalizeAndHash(first);
        SafetyContractCanonicalizer.CanonicalPolicy secondResult = canonicalizer.canonicalizeAndHash(second);

        assertThat(secondResult).isEqualTo(firstResult);
    }

    @Test
    void producesFixedCanonicalJsonAndHashVector() {
        JsonNode contract = objectMapper.readTree("""
                {"schemaVersion":"1.0","allowedTools":["Z","A"]}
                """);

        SafetyContractCanonicalizer.CanonicalPolicy result = canonicalizer.canonicalizeAndHash(contract);

        assertThat(result.canonicalJson())
                .isEqualTo("{\"allowedTools\":[\"A\",\"Z\"],\"schemaVersion\":\"1.0\"}");
        assertThat(result.policyHash())
                .isEqualTo("sha256:7aedd654fb6767d6cee0d365da980f9d6e3ca51e91cff9f56a11f3a3ec64639f");
    }

    @Test
    void refusesInvalidInputWithoutMutatingCallerOwnedJson() {
        ObjectNode invalid = validContract();
        ((ArrayNode) invalid.path("allowedTools")).add("CASE_CONTEXT_READ");
        String before = invalid.toString();

        assertThatThrownBy(() -> canonicalizer.canonicalizeAndHash(invalid))
                .isInstanceOf(SafetyContractCanonicalizer.InvalidSafetyContractException.class)
                .satisfies(exception -> assertThat(
                        ((SafetyContractCanonicalizer.InvalidSafetyContractException) exception).issues()
                ).extracting(SafetyContractSchemaValidator.Issue::code)
                        .contains("DUPLICATE_VALUE"));
        assertThat(invalid.toString()).isEqualTo(before);
    }

    @Test
    void hashingIsRepeatableAndChangesForMeaningfulPolicyChanges() {
        ObjectNode original = validContract();
        String before = original.toString();
        SafetyContractCanonicalizer.CanonicalPolicy first = canonicalizer.canonicalizeAndHash(original);
        SafetyContractCanonicalizer.CanonicalPolicy repeated = canonicalizer.canonicalizeAndHash(original);
        ObjectNode changed = original.deepCopy();
        changed.put("contractId", "different-contract");

        assertThat(repeated).isEqualTo(first);
        assertThat(canonicalizer.canonicalizeAndHash(changed).policyHash())
                .isNotEqualTo(first.policyHash());
        assertThat(original.toString()).isEqualTo(before);
    }

    private static Stream<String> fixedObjectPaths() {
        return Stream.of(
                "",
                "/resourcePolicies/DOCUMENT_READER",
                "/customerScope",
                "/fieldPolicy/CUSTOMER_DATA_READ",
                "/cardinality/CUSTOMER_DATA_READ",
                "/externalEgress",
                "/workflow",
                "/toolTrust",
                "/outputPolicy",
                "/metadata"
        );
    }

    private static Stream<String> setArrayPaths() {
        return Stream.of(
                "/allowedTools",
                "/fieldPolicy/CUSTOMER_DATA_READ/allowed",
                "/externalEgress/allowedDestinations",
                "/workflow/allowedStages",
                "/toolTrust/allowedTrustLevels",
                "/outputPolicy/reviewStatusAllowed"
        );
    }

    private ObjectNode canonicalRichContract() {
        ObjectNode contract = validContract();
        contract.put("purpose", "café\nreview");
        ((ArrayNode) contract.at("/externalEgress/allowedDestinations")).add("B").add("A");
        ((ArrayNode) contract.at("/workflow/allowedStages")).add("ARCHIVE");
        ((ArrayNode) contract.at("/toolTrust/allowedTrustLevels")).add("MIXED");
        return contract;
    }

    private void moveFieldToEnd(ObjectNode object, String field) {
        JsonNode value = object.remove(field);
        object.set(field, value);
    }

    private void reverse(ArrayNode array) {
        List<JsonNode> values = new java.util.ArrayList<>();
        array.forEach(values::add);
        java.util.Collections.reverse(values);
        array.removeAll();
        values.forEach(array::add);
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
