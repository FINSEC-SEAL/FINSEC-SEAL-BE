package com.finsecseal.contract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.finsecseal.contract.SafetyContractReviewDiff.Change;
import com.finsecseal.contract.SafetyContractReviewDiff.ChangeKind;
import com.finsecseal.contract.SafetyContractReviewDiff.ComparisonException;
import com.finsecseal.contract.SafetyContractReviewDiff.FailureCode;
import com.finsecseal.contract.SafetyContractReviewDiff.InputSide;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

class SafetyContractReviewDiffTest {
    private static final String SECRET = "REVIEW-POLICY-SECRET-CANARY";
    private ObjectMapper mapper;
    private SafetyContractSchemaValidator schema;
    private SafetyContractCanonicalizer canonicalizer;
    private SafetyContractReviewDiff diff;
    private ObjectNode policy;

    @BeforeEach
    void setup() throws Exception {
        mapper = new ObjectMapper();
        schema = new SafetyContractSchemaValidator();
        canonicalizer = new SafetyContractCanonicalizer(schema, new CanonicalJsonService(mapper), new DigestService());
        diff = new SafetyContractReviewDiff(schema, canonicalizer);
        try (var input = getClass().getResourceAsStream("/fixtures/loan-review-safety-contract.json")) {
            policy = (ObjectNode) mapper.readTree(input);
        }
    }

    @Test
    void absentBaselineProducesOneRootAdditionAndRecomputedHash() {
        var result = diff.compare(Optional.empty(), policy);

        assertThat(result.beforeHash()).isEmpty();
        assertThat(result.afterHash()).isEqualTo(canonicalizer.canonicalizeAndHash(policy).policyHash());
        assertThat(result.changes()).hasSize(1);
        Change change = result.changes().getFirst();
        assertThat(change.pointer()).isEmpty();
        assertThat(change.kind()).isEqualTo(ChangeKind.ADDED);
        assertThat(change.before()).isEmpty();
        assertThat(change.after()).contains(policy);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/allowedTools", "/fieldPolicy/CUSTOMER_DATA_READ/allowed",
            "/fieldPolicy/FUTURE_TOOL/allowed", "/externalEgress/allowedDestinations",
            "/workflow/allowedStages", "/toolTrust/allowedTrustLevels", "/outputPolicy/reviewStatusAllowed"})
    void ignoresOnlyOrderingForEveryPolicyStringSet(String pointer) {
        ObjectNode futureFields = mapper.createObjectNode();
        futureFields.putArray("allowed").add("b").add("a");
        ((ObjectNode) policy.path("fieldPolicy")).set("FUTURE_TOOL", futureFields);
        ((ArrayNode) policy.at("/externalEgress/allowedDestinations")).add("mock://b").add("mock://a");
        ((ArrayNode) policy.at("/workflow/allowedStages")).add("ARCHIVE");
        ((ArrayNode) policy.at("/toolTrust/allowedTrustLevels")).add("MIXED");
        ObjectNode reordered = policy.deepCopy();
        reverse((ArrayNode) reordered.at(pointer));

        var result = diff.compare(Optional.of(policy), reordered);

        assertThat(result.changes()).isEmpty();
        assertThat(result.beforeHash()).contains(result.afterHash());
    }

    @Test
    void displaysNestedAdditionsRemovalsExpansionsAndMissingMinimumPrivilegesInStableOrder() {
        ObjectNode after = policy.deepCopy();
        ((ArrayNode) after.path("allowedTools")).remove(0);
        ((ObjectNode) after.at("/cardinality/CUSTOMER_DATA_READ")).put("maxRequestedRecords", 2);
        after.remove("customerScope");
        ((ObjectNode) after.path("externalEgress")).put("allowed", true);
        ObjectNode fields = mapper.createObjectNode();
        fields.putArray("allowed").add("title");
        ((ObjectNode) after.path("fieldPolicy")).set("LOAN_POLICY_SEARCH", fields);

        var result = diff.compare(Optional.of(policy), after);

        assertThat(result.changes()).extracting(Change::pointer, Change::kind).containsExactly(
                tuple("/allowedTools", ChangeKind.MODIFIED),
                tuple("/cardinality/CUSTOMER_DATA_READ/maxRequestedRecords", ChangeKind.MODIFIED),
                tuple("/customerScope", ChangeKind.REMOVED),
                tuple("/externalEgress/allowed", ChangeKind.MODIFIED),
                tuple("/fieldPolicy/LOAN_POLICY_SEARCH", ChangeKind.ADDED));
        assertThat(result.changes().get(0).after()).contains(after.path("allowedTools"));
        assertThat(result.changes().get(2).before()).contains(policy.path("customerScope"));
        assertThat(result.changes().get(2).after()).isEmpty();
        assertThat(result.changes().get(4).before()).isEmpty();
        assertThat(result.changes().get(4).after()).contains(fields);
        assertThat(result.beforeHash()).contains(canonicalizer.canonicalizeAndHash(policy).policyHash());
        assertThat(result.afterHash()).isEqualTo(canonicalizer.canonicalizeAndHash(after).policyHash());
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', textBlock = """
            /customerScope/type | "ANY_CUSTOMER"
            /resourcePolicies/DOCUMENT_READER/caseScope | "ANY_CASE"
            /resourcePolicies/DOCUMENT_READER/documentScope | "ANY_DOCUMENT"
            /resourcePolicies/REVIEW_NOTE_WRITE/caseScope | "ANY_CASE"
            /fieldPolicy/CUSTOMER_DATA_READ/allowed | ["incomeBand"]
            /fieldPolicy/CUSTOMER_DATA_READ/allowed | ["incomeBand","employmentStatus","accountNumber"]
            /fieldPolicy/CUSTOMER_DATA_READ/denyUnknown | false
            /cardinality/CUSTOMER_DATA_READ/maxReturnedRecords | 2
            /externalEgress/allowedDestinations | ["mock://collector"]
            /workflow/allowedStages | []
            /workflow/allowedStages | ["DOCUMENT_REVIEW","ARCHIVE"]
            /highImpactActions/LOAN_DECISION_UPDATE | "AGENT_ALLOWED"
            /toolTrust/requireTrustedTool | false
            /toolTrust/allowedTrustLevels | ["TRUSTED_INTERNAL","MIXED"]
            /outputPolicy/reviewStatusAllowed | []
            /outputPolicy/reviewStatusAllowed | ["READY_FOR_HUMAN_REVIEW","NEEDS_MORE_DOCUMENTS","AUTO_APPROVED"]
            """)
    void displaysFinancialRuleViolationsInsteadOfTreatingComparisonAsValidation(String pointer, String replacement) {
        ObjectNode after = policy.deepCopy();
        int separator = pointer.lastIndexOf('/');
        ((ObjectNode) after.at(pointer.substring(0, separator)))
                .set(pointer.substring(separator + 1), mapper.readTree(replacement));

        var result = diff.compare(Optional.of(policy), after);

        assertThat(result.changes()).hasSize(1);
        Change change = result.changes().getFirst();
        assertThat(change.pointer()).isEqualTo(pointer);
        assertThat(change.kind()).isEqualTo(ChangeKind.MODIFIED);
        assertThat(change.before()).contains(policy.at(pointer));
        assertThat(change.after()).contains(after.at(pointer));
    }

    @Test
    void showsIdentityPurposeMetadataAndNonadjacentHistoryWithoutApprovalRestrictions() {
        ObjectNode after = policy.deepCopy();
        after.put("contractId", "different-contract");
        after.put("version", 99);
        after.put("purpose", "LOAN_APPROVAL");
        ((ObjectNode) after.path("metadata")).put("templateVersion", "future/1").put("validatorVersion", "2.0");

        var result = diff.compare(Optional.of(policy), after);

        assertThat(result.changes()).extracting(Change::pointer).containsExactly(
                "/contractId", "/metadata/templateVersion", "/metadata/validatorVersion", "/purpose", "/version");
        var reverseHistory = diff.compare(Optional.of(after), policy);
        assertThat(reverseHistory.changes()).extracting(Change::pointer)
                .containsExactlyElementsOf(result.changes().stream().map(Change::pointer).toList());
        assertThat(reverseHistory.beforeHash()).contains(result.afterHash());
        assertThat(result.beforeHash()).contains(reverseHistory.afterHash());
    }

    @ParameterizedTest
    @ValueSource(strings = {"identityNfd", "purposeNfd", "metadataCrlf", "arrayNfd", "arrayCrlf"})
    void rawStringChangesRemainVisibleEvenWhenCanonicalHashesAreEqual(String kind) {
        ObjectNode before = policy.deepCopy();
        ObjectNode after = policy.deepCopy();
        String pointer;
        switch (kind) {
            case "identityNfd" -> {
                before.put("contractId", "cafe\u0301");
                after.put("contractId", "café");
                pointer = "/contractId";
            }
            case "purposeNfd" -> {
                before.put("purpose", "cafe\u0301");
                after.put("purpose", "café");
                pointer = "/purpose";
            }
            case "metadataCrlf" -> {
                ((ObjectNode) before.path("metadata")).put("validatorVersion", "line\r\nversion");
                ((ObjectNode) after.path("metadata")).put("validatorVersion", "line\nversion");
                pointer = "/metadata/validatorVersion";
            }
            case "arrayNfd", "arrayCrlf" -> {
                String raw = kind.equals("arrayNfd") ? "cafe\u0301" : "line\r\nfield";
                String normalized = kind.equals("arrayNfd") ? "café" : "line\nfield";
                pointer = "/fieldPolicy/CUSTOMER_DATA_READ/allowed";
                ((ArrayNode) before.at(pointer)).set(0, raw);
                ((ArrayNode) after.at(pointer)).set(0, normalized);
            }
            default -> throw new AssertionError(kind);
        }

        var result = diff.compare(Optional.of(before), after);

        assertThat(result.beforeHash()).contains(result.afterHash());
        assertThat(result.changes()).hasSize(1);
        Change change = result.changes().getFirst();
        assertThat(change.pointer()).isEqualTo(pointer);
        assertThat(change.kind()).isEqualTo(ChangeKind.MODIFIED);
        assertThat(change.before()).contains(before.at(pointer));
        assertThat(change.after()).contains(after.at(pointer));
    }

    @Test
    void rawObjectKeyDifferencesAndEscapedPointersAreNotHiddenByCanonicalization() {
        ObjectNode before = policy.deepCopy();
        ObjectNode after = policy.deepCopy();
        ObjectNode resource = mapper.createObjectNode().put("caseScope", "CURRENT_CASE_ONLY");
        ((ObjectNode) before.path("resourcePolicies")).set("cafe\u0301/~", resource.deepCopy());
        ((ObjectNode) after.path("resourcePolicies")).set("café/~", resource.deepCopy());

        var result = diff.compare(Optional.of(before), after);

        assertThat(result.beforeHash()).contains(result.afterHash());
        assertThat(result.changes()).extracting(Change::pointer, Change::kind).containsExactly(
                tuple("/resourcePolicies/cafe\u0301~1~0", ChangeKind.REMOVED),
                tuple("/resourcePolicies/café~1~0", ChangeKind.ADDED));
        ((ObjectNode) after.path("resourcePolicies")).set("cafe\u0301/~", resource.deepCopy());
        ((ObjectNode) after.path("resourcePolicies")).remove("café/~");
        ((ObjectNode) after.at("/resourcePolicies/cafe\u0301~1~0")).put("caseScope", "ANY_CASE");
        assertThat(diff.compare(Optional.of(before), after).changes())
                .extracting(Change::pointer).containsExactly("/resourcePolicies/cafe\u0301~1~0/caseScope");
    }

    @Test
    void exactLargeIntegerChangesRemainVisibleDespiteCanonicalNumericRounding() {
        ObjectNode before = policy.deepCopy();
        ObjectNode after = policy.deepCopy();
        String pointer = "/cardinality/CUSTOMER_DATA_READ/maxRequestedRecords";
        BigInteger first = new BigInteger("9007199254740992");
        BigInteger second = first.add(BigInteger.ONE);
        ((ObjectNode) before.at("/cardinality/CUSTOMER_DATA_READ")).put("maxRequestedRecords", first);
        ((ObjectNode) after.at("/cardinality/CUSTOMER_DATA_READ")).put("maxRequestedRecords", second);

        var result = diff.compare(Optional.of(before), after);

        assertThat(result.beforeHash()).contains(result.afterHash());
        assertThat(result.changes()).hasSize(1);
        Change change = result.changes().getFirst();
        assertThat(change.pointer()).isEqualTo(pointer);
        assertThat(change.before().orElseThrow().bigIntegerValue()).isEqualTo(first);
        assertThat(change.after().orElseThrow().bigIntegerValue()).isEqualTo(second);
    }

    @Test
    void integralNodeWidthAloneDoesNotCreateAChange() {
        ObjectNode wider = policy.deepCopy();
        wider.put("version", policy.path("version").longValue());
        ((ObjectNode) wider.at("/cardinality/CUSTOMER_DATA_READ"))
                .put("maxRequestedRecords", BigInteger.ONE).put("maxReturnedRecords", 1L);

        var result = diff.compare(Optional.of(policy), wider);

        assertThat(result.changes()).isEmpty();
        assertThat(result.beforeHash()).contains(result.afterHash());
    }

    @Test
    void objectPropertyInsertionOrderAloneDoesNotCreateAChange() {
        ObjectNode reordered = policy.deepCopy();
        JsonNode first = reordered.remove("schemaVersion");
        reordered.set("schemaVersion", first);

        assertThat(diff.compare(Optional.of(policy), reordered).changes()).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "{}", "[]", "{\"schemaVersion\":\"2.0\"}",
            "{\"schemaVersion\":\"1.0\",\"unexpected\":true}",
            "{\"schemaVersion\":\"1.0\",\"allowedTools\":[\"A\",\"A\"]}"})
    void suppliedMalformedSnapshotNeverMeansMissingBaselineOrEmptySuccessfulDiff(String invalidJson) {
        JsonNode invalid = mapper.readTree(invalidJson);
        expect(diff, FailureCode.INVALID_SNAPSHOT, InputSide.BEFORE, Optional.of(invalid), policy);
        expect(diff, FailureCode.INVALID_SNAPSHOT, InputSide.AFTER, Optional.of(policy), invalid);
    }

    @Test
    void nullOptionalAndNullAfterAreExplicitlyInvalid() {
        var unusedCanonical = mock(SafetyContractCanonicalizer.class);
        var subject = new SafetyContractReviewDiff(schema, unusedCanonical);

        expect(subject, FailureCode.INVALID_REQUEST, InputSide.REQUEST, null, policy);
        expect(subject, FailureCode.INVALID_SNAPSHOT, InputSide.AFTER, Optional.empty(), null);

        verifyNoInteractions(unusedCanonical);
    }

    @Test
    void canonicalKeyCollisionProducesSafeUnavailableInsteadOfPartialRootAddition() {
        ObjectNode resource = mapper.createObjectNode().put("caseScope", "CURRENT_CASE_ONLY");
        ((ObjectNode) policy.path("resourcePolicies")).set("e\u0301", resource.deepCopy());
        ((ObjectNode) policy.path("resourcePolicies")).set("é", resource.deepCopy());
        assertThat(schema.validate(policy).valid()).isTrue();

        expect(diff, FailureCode.COMPARISON_UNAVAILABLE, InputSide.AFTER, Optional.empty(), policy);
    }

    @ParameterizedTest
    @ValueSource(strings = {"beforeThrows", "afterThrows", "nullCanonical", "schemaThrows", "schemaNull"})
    void engineFailuresRemainSafeUnavailableWithoutPartialComparison(String scenario) {
        var engine = mock(SafetyContractCanonicalizer.class);
        var validation = mock(SafetyContractSchemaValidator.class);
        when(validation.validate(any(JsonNode.class))).thenReturn(schema.validate(policy));
        var subject = new SafetyContractReviewDiff(validation, engine);
        Optional<JsonNode> before = Optional.empty();
        InputSide side = InputSide.AFTER;
        switch (scenario) {
            case "beforeThrows" -> {
                before = Optional.of(policy);
                side = InputSide.BEFORE;
                when(engine.canonicalizeAndHash(any(JsonNode.class))).thenThrow(new IllegalStateException(SECRET));
            }
            case "afterThrows" -> when(engine.canonicalizeAndHash(any(JsonNode.class)))
                    .thenThrow(new IllegalStateException(SECRET));
            case "nullCanonical" -> when(engine.canonicalizeAndHash(any(JsonNode.class))).thenReturn(null);
            case "schemaThrows" -> when(validation.validate(any(JsonNode.class)))
                    .thenThrow(new IllegalStateException(SECRET));
            case "schemaNull" -> when(validation.validate(any(JsonNode.class))).thenReturn(null);
            default -> throw new AssertionError(scenario);
        }

        expect(subject, FailureCode.COMPARISON_UNAVAILABLE, side, before, policy);

        if (scenario.startsWith("schema")) {
            verifyNoInteractions(engine);
        }
    }

    @Test
    void retainedChangesAreImmutableAndTheirStringRepresentationDoesNotExposePolicy() {
        policy.put("contractId", SECRET);
        ObjectNode after = policy.deepCopy();
        ((ArrayNode) after.path("allowedTools")).remove(0);
        var result = diff.compare(Optional.of(policy), after);
        Change change = result.changes().getFirst();
        JsonNode originalBefore = change.before().orElseThrow();
        JsonNode originalAfter = change.after().orElseThrow();
        ((ArrayNode) change.before().orElseThrow()).removeAll();
        ((ArrayNode) change.after().orElseThrow()).removeAll();
        policy.removeAll();
        after.removeAll();

        assertThat(change.before()).contains(originalBefore);
        assertThat(change.after()).contains(originalAfter);
        assertThatThrownBy(() -> result.changes().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThat(result.toString()).doesNotContain(SECRET, "allowedTools");
        assertThat(change.toString()).doesNotContain(SECRET, "CASE_CONTEXT_READ");
        ObjectNode addition = mapper.createObjectNode().put("schemaVersion", "1.0").put("contractId", SECRET);
        var creation = diff.compare(Optional.empty(), addition);
        ((ObjectNode) creation.changes().getFirst().after().orElseThrow()).removeAll();
        assertThat(creation.changes().getFirst().after()).contains(addition);
        assertThat(creation.changes().getFirst().toString()).doesNotContain(SECRET);
    }

    private static void reverse(ArrayNode array) {
        List<JsonNode> values = new ArrayList<>();
        array.forEach(values::add);
        Collections.reverse(values);
        array.removeAll();
        values.forEach(array::add);
    }

    private void expect(SafetyContractReviewDiff subject, FailureCode code, InputSide side,
            Optional<JsonNode> before, JsonNode after) {
        assertThatThrownBy(() -> subject.compare(before, after))
                .isInstanceOfSatisfying(ComparisonException.class, exception -> {
                    assertThat(exception.code()).isEqualTo(code);
                    assertThat(exception.side()).isEqualTo(side);
                    assertThat(exception.getCause()).isNull();
                    assertThat(exception.getSuppressed()).isEmpty();
                }).hasMessage("Contract review comparison unavailable: " + code.name() + " (" + side.name() + ")")
                .hasMessageNotContaining(SECRET);
    }
}
