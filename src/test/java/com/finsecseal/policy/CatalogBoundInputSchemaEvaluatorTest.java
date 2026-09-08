package com.finsecseal.policy;

import static com.finsecseal.policy.CatalogBoundInputSchemaEvaluator.FailureCode.INVALID_CATALOG_SCHEMA;
import static com.finsecseal.policy.CatalogBoundInputSchemaEvaluator.FailureCode.INVALID_POLICY_SOURCE;
import static com.finsecseal.policy.CatalogBoundInputSchemaEvaluator.FailureCode.SCHEMA_ENGINE_FAILURE;
import static com.finsecseal.policy.CatalogBoundInputSchemaEvaluator.InputOutcome.INVALID_REQUEST_SCHEMA;
import static com.finsecseal.policy.CatalogBoundInputSchemaEvaluator.InputOutcome.MATCH;
import static com.finsecseal.policy.CatalogBoundInputSchemaEvaluator.InputOutcome.TOOL_NOT_IN_CATALOG;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.SourceBoundCatalog;
import com.finsecseal.contract.SafetyContractSemanticValidator.ContractValidationCatalog;
import com.finsecseal.contract.SafetyContractSemanticValidator.EnabledTool;
import com.finsecseal.policy.CatalogBoundInputSchemaEvaluator.FailureCode;
import com.finsecseal.policy.CatalogBoundInputSchemaEvaluator.InputOutcome;
import com.finsecseal.policy.CatalogBoundInputSchemaEvaluator.InputSchemaException;
import com.finsecseal.policy.GatewayApprovedPolicySourceService.ApprovedPolicySource;
import com.finsecseal.release.LoanReviewToolCatalog;
import com.finsecseal.runtime.ToolProposal;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.BigIntegerNode;
import tools.jackson.databind.node.BinaryNode;
import tools.jackson.databind.node.DecimalNode;
import tools.jackson.databind.node.DoubleNode;
import tools.jackson.databind.node.FloatNode;
import tools.jackson.databind.node.MissingNode;
import tools.jackson.databind.node.ObjectNode;
import tools.jackson.databind.node.POJONode;

/**
 * Actual A versioned input schemas with a mocked approved-source boundary. These unit tests do not
 * establish authorization, stored source provenance, B execution, or overall Gateway permission.
 * Deliberately permissive synthetic schemas isolate C's input size, depth and numeric work limits.
 */
class CatalogBoundInputSchemaEvaluatorTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String CASE = "CASE_CONTEXT_READ";
    private static final String DOCUMENT = "DOCUMENT_READER";
    private static final String CUSTOMER = "CUSTOMER_DATA_READ";
    private static final String SEARCH = "LOAN_POLICY_SEARCH";
    private static final String REVIEW = "REVIEW_NOTE_WRITE";
    private static final String HUMAN = "LOAN_DECISION_UPDATE";
    private static final String PRIVATE = "PRIVATE-INPUT-SENTINEL";
    private static final int BYTE_LIMIT = 32768;
    private static final UUID RELEASE = UUID.fromString("12345678-1234-4abc-8def-1234567890ab");

    private final CatalogBoundInputSchemaEvaluator evaluator = new CatalogBoundInputSchemaEvaluator();

    @ParameterizedTest(name = "actual schema accepts {0}")
    @MethodSource("validRequests")
    void allSixActualSchemasAcceptTheirDeclaredInputs(String tool, JsonNode arguments) {
        assertPreserved(actualSource(), tool, arguments, MATCH);
    }

    static Stream<Arguments> validRequests() {
        return Stream.of(
                Arguments.of(CASE, valid(CASE)),
                Arguments.of(DOCUMENT, valid(DOCUMENT)),
                Arguments.of(CUSTOMER, valid(CUSTOMER)),
                Arguments.of(SEARCH, valid(SEARCH)),
                Arguments.of(REVIEW, valid(REVIEW)),
                Arguments.of(HUMAN, valid(HUMAN)));
    }

    @ParameterizedTest(name = "{0} requires {1}")
    @MethodSource("requiredFields")
    void actualSchemasRejectEachMissingRequiredTopLevelField(String tool, String field) {
        ObjectNode arguments = valid(tool);
        arguments.remove(field);
        assertPreserved(actualSource(), tool, arguments, INVALID_REQUEST_SCHEMA);
    }

    static Stream<Arguments> requiredFields() {
        return Stream.of(Arguments.of(CASE, "caseId"), Arguments.of(DOCUMENT, "caseId"),
                Arguments.of(DOCUMENT, "documentId"), Arguments.of(CUSTOMER, "customerIds"),
                Arguments.of(CUSTOMER, "fields"), Arguments.of(SEARCH, "query"),
                Arguments.of(REVIEW, "caseId"), Arguments.of(REVIEW, "reviewResult"),
                Arguments.of(HUMAN, "caseId"), Arguments.of(HUMAN, "decision"));
    }

    @ParameterizedTest(name = "{0} rejects the wrong type for {1}")
    @MethodSource("requiredFields")
    void actualSchemasRejectWrongRequiredFieldTypes(String tool, String field) {
        ObjectNode arguments = valid(tool);
        arguments.put(field, 7);
        assertPreserved(actualSource(), tool, arguments, INVALID_REQUEST_SCHEMA);
    }

    @ParameterizedTest
    @ValueSource(strings = {CASE, DOCUMENT, CUSTOMER, SEARCH, REVIEW, HUMAN})
    void actualSchemasRejectUnknownTopLevelProperties(String tool) {
        ObjectNode arguments = valid(tool).put("unexpected", PRIVATE);
        assertPreserved(actualSource(), tool, arguments, INVALID_REQUEST_SCHEMA);
    }

    @ParameterizedTest
    @ValueSource(strings = {"customerIds", "fields"})
    void customerArraysUseActualMinMaxAndItemLengthRules(String field) {
        ApprovedPolicySource source = actualSource();
        for (int count : new int[]{0, 1, 20, 21}) {
            ObjectNode arguments = valid(CUSTOMER);
            ArrayNode values = arguments.putArray(field);
            for (int index = 0; index < count; index++) values.add("VALUE-" + index);
            assertPreserved(source, CUSTOMER, arguments,
                    count == 1 || count == 20 ? MATCH : INVALID_REQUEST_SCHEMA);
        }
        for (int length : new int[]{0, 1, 80, 81}) {
            ObjectNode arguments = valid(CUSTOMER);
            arguments.putArray(field).add("x".repeat(length));
            assertPreserved(source, CUSTOMER, arguments,
                    length == 1 || length == 80 ? MATCH : INVALID_REQUEST_SCHEMA);
        }
        ObjectNode nonString = valid(CUSTOMER);
        nonString.putArray(field).add(123);
        assertPreserved(source, CUSTOMER, nonString, INVALID_REQUEST_SCHEMA);
    }

    @Test
    void schemaDoesNotInventCustomerFieldEnumsOrDuplicatePolicyRules() {
        ObjectNode arguments = valid(CUSTOMER);
        arguments.putArray("customerIds").add(" CUST-1 ").add(" CUST-1 ");
        arguments.putArray("fields").add("independent-policy-check").add("independent-policy-check");
        assertPreserved(actualSource(), CUSTOMER, arguments, MATCH);
    }

    @ParameterizedTest
    @ValueSource(strings = {"READY_FOR_HUMAN_REVIEW", "NEEDS_MORE_DOCUMENTS"})
    void reviewAcceptsBothStatusesAndDeclaredEmptyOrMultipleArrays(String status) {
        ObjectNode arguments = valid(REVIEW);
        ObjectNode result = (ObjectNode) arguments.path("reviewResult");
        result.put("reviewStatus", status);
        assertPreserved(actualSource(), REVIEW, arguments, MATCH);
        result.putArray("missingDocuments").add("").add("INCOME_STATEMENT");
        ArrayNode evidence = result.putArray("evidence");
        evidence.addObject().put("rule", "").put("reason", " ");
        evidence.addObject().put("rule", "RULE-2").put("reason", "document required");
        assertPreserved(actualSource(), REVIEW, arguments, MATCH);
    }

    @ParameterizedTest
    @ValueSource(strings = {"reviewStatus", "missingDocuments", "evidence"})
    void reviewRequiresEachNestedFieldAndItsDeclaredType(String field) {
        ObjectNode missing = valid(REVIEW);
        ((ObjectNode) missing.path("reviewResult")).remove(field);
        assertPreserved(actualSource(), REVIEW, missing, INVALID_REQUEST_SCHEMA);
        ObjectNode wrongType = valid(REVIEW);
        ((ObjectNode) wrongType.path("reviewResult")).put(field, 123);
        assertPreserved(actualSource(), REVIEW, wrongType, INVALID_REQUEST_SCHEMA);
    }

    @Test
    void reviewRejectsNestedAdditionalPropertiesAndInvalidArrayItems() {
        ObjectNode extra = valid(REVIEW);
        ((ObjectNode) extra.path("reviewResult")).put("unexpected", PRIVATE);
        assertPreserved(actualSource(), REVIEW, extra, INVALID_REQUEST_SCHEMA);
        ObjectNode missingDocument = valid(REVIEW);
        ((ObjectNode) missingDocument.path("reviewResult")).putArray("missingDocuments").add(7);
        assertPreserved(actualSource(), REVIEW, missingDocument, INVALID_REQUEST_SCHEMA);
        for (String evidence : new String[]{"7", "{}", "{\"rule\":\"R\"}",
                "{\"reason\":\"why\"}", "{\"rule\":7,\"reason\":\"why\"}",
                "{\"rule\":\"R\",\"reason\":7}",
                "{\"rule\":\"R\",\"reason\":\"why\",\"extra\":true}"}) {
            ObjectNode arguments = valid(REVIEW);
            ((ObjectNode) arguments.path("reviewResult")).putArray("evidence").add(json(evidence));
            assertPreserved(actualSource(), REVIEW, arguments, INVALID_REQUEST_SCHEMA);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"APPROVED", "REJECTED"})
    void humanOnlyToolCanMatchItsInputSchemaWithoutGrantingExecution(String decision) {
        for (int length : new int[]{0, 1, 80, 81}) {
            ObjectNode arguments = valid(HUMAN).put("decision", decision).put("caseId", "x".repeat(length));
            assertPreserved(actualSource(), HUMAN, arguments,
                    length == 1 || length == 80 ? MATCH : INVALID_REQUEST_SCHEMA);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"APPROVED ", "approved", "PENDING", ""})
    void humanDecisionEnumIsExactAndNeverNormalized(String decision) {
        assertPreserved(actualSource(), HUMAN, valid(HUMAN).put("decision", decision), INVALID_REQUEST_SCHEMA);
    }

    @ParameterizedTest
    @ValueSource(strings = {"READY_FOR_HUMAN_REVIEW ", "ready_for_human_review", "APPROVED", ""})
    void reviewStatusEnumIsExactAndNeverNormalized(String status) {
        ObjectNode arguments = valid(REVIEW);
        ((ObjectNode) arguments.path("reviewResult")).put("reviewStatus", status);
        assertPreserved(actualSource(), REVIEW, arguments, INVALID_REQUEST_SCHEMA);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "  raw string  "})
    void ordinaryActualStringSchemasRetainEmptyAndWhitespaceValues(String value) {
        assertPreserved(actualSource(), CASE, valid(CASE).put("caseId", value), MATCH);
        assertPreserved(actualSource(), DOCUMENT,
                valid(DOCUMENT).put("caseId", value).put("documentId", value), MATCH);
        assertPreserved(actualSource(), SEARCH, valid(SEARCH).put("query", value), MATCH);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"A", "case_context_read", " CASE_CONTEXT_READ", "CASE_CONTEXT_READ ",
            "CASE_CONTEXT_READ\n", "CASE-CONTEXT-READ", "1CASE", "도구", "_CASE"})
    void invalidRawToolNamesAreRequestFailures(String tool) {
        assertThat(evaluator.evaluate(actualSource(), new ToolProposal(tool, valid(CASE))))
                .isEqualTo(INVALID_REQUEST_SCHEMA);
    }

    @Test
    void toolNameLengthUsesTheExistingCatalogIdentityBoundary() {
        assertThat(evaluator.evaluate(actualSource(), new ToolProposal("AB", json("{}"))))
                .isEqualTo(TOOL_NOT_IN_CATALOG);
        assertThat(evaluator.evaluate(actualSource(), new ToolProposal("A".repeat(100), json("{}"))))
                .isEqualTo(TOOL_NOT_IN_CATALOG);
        assertThat(evaluator.evaluate(actualSource(), new ToolProposal("A".repeat(101), json("{}"))))
                .isEqualTo(INVALID_REQUEST_SCHEMA);
    }

    @ParameterizedTest
    @ValueSource(strings = {"UNKNOWN_TOOL", "EXTERNAL_HTTP"})
    void unknownNamesHaveNoFabricatedCatalogClassificationAndStillReceiveLimits(String tool) {
        assertPreserved(actualSource(), tool, json("{}"), TOOL_NOT_IN_CATALOG);
        assertThat(evaluator.evaluate(actualSource(), new ToolProposal(tool, json("[]"))))
                .isEqualTo(INVALID_REQUEST_SCHEMA);
        assertThat(evaluator.evaluate(actualSource(), new ToolProposal(tool, asciiSized(BYTE_LIMIT + 1))))
                .isEqualTo(INVALID_REQUEST_SCHEMA);
        assertThat(evaluator.evaluate(actualSource(), new ToolProposal(tool, nested(33))))
                .isEqualTo(INVALID_REQUEST_SCHEMA);
    }

    @Test
    void missingProposalIsAnInvalidRequest() {
        assertThat(evaluator.evaluate(actualSource(), null)).isEqualTo(INVALID_REQUEST_SCHEMA);
    }

    @ParameterizedTest
    @MethodSource("nonObjectArguments")
    void argumentsMustBeAJsonObject(JsonNode arguments) {
        assertThat(evaluator.evaluate(actualSource(), new ToolProposal(CASE, arguments)))
                .isEqualTo(INVALID_REQUEST_SCHEMA);
    }

    static Stream<Arguments> nonObjectArguments() {
        return Stream.of(null, json("null"), json("[]"), json("\"text\""), json("7"), json("true"))
                .map(value -> Arguments.of((Object) value));
    }

    @ParameterizedTest
    @ValueSource(ints = {32767, 32768, 32769})
    void exactUtf8ByteBoundaryIsIsolatedFromBusinessSchema(int bytes) {
        ObjectNode arguments = asciiSized(bytes);
        assertThat(utf8Bytes(arguments)).isEqualTo(bytes);
        assertPreserved(permissiveSource(), CASE, arguments, bytes <= BYTE_LIMIT ? MATCH : INVALID_REQUEST_SCHEMA);
    }

    @ParameterizedTest
    @ValueSource(ints = {32767, 32768, 32769})
    void utf8SizeCountsMultibyteAndEscapedCharacters(int bytes) {
        ObjectNode arguments = JSON.createObjectNode().put("한\"", "한\"\\\n".repeat(200));
        int padding = bytes - utf8Bytes(arguments);
        arguments.put("한\"", arguments.path("한\"").asString() + "x".repeat(padding));
        assertThat(utf8Bytes(arguments)).isEqualTo(bytes);
        assertThat(arguments.toString().length()).isLessThan(bytes);
        assertPreserved(permissiveSource(), CASE, arguments, bytes <= BYTE_LIMIT ? MATCH : INVALID_REQUEST_SCHEMA);
    }

    @ParameterizedTest
    @ValueSource(ints = {31, 32, 33})
    void rootIsDepthOneAndDeepestValueHasTheRecordedDepth(int depth) {
        assertPreserved(permissiveSource(), CASE, nested(depth), depth <= 32 ? MATCH : INVALID_REQUEST_SCHEMA);
    }

    @Test
    void cyclesAreRejectedBeforeRecursiveCopyOrSerialization() {
        ObjectNode arguments = JSON.createObjectNode();
        arguments.set("cycle", arguments);
        assertRejectedBeforeCopy(arguments);
    }

    @Test
    void excessivelyWideArrayIsRejectedBeforeRecursiveCopyOrSerialization() {
        ObjectNode arguments = JSON.createObjectNode();
        ArrayNode array = arguments.putArray("values");
        for (int index = 0; index < 20000; index++) array.addNull();
        assertRejectedBeforeCopy(arguments);
    }

    @Test
    void excessivelyWideObjectIsRejectedBeforeRecursiveCopyOrSerialization() {
        ObjectNode arguments = JSON.createObjectNode();
        for (int index = 0; index < 10000; index++) arguments.putNull("key" + index);
        assertRejectedBeforeCopy(arguments);
    }

    @Test
    void excessiveKeyAndTextLengthsAreRejectedBeforeRecursiveCopyOrSerialization() {
        assertRejectedBeforeCopy(JSON.createObjectNode().put("x".repeat(BYTE_LIMIT), ""));
        assertRejectedBeforeCopy(JSON.createObjectNode().put("x", "x".repeat(BYTE_LIMIT)));
        assertRejectedBeforeCopy(nested(33));
    }

    @ParameterizedTest
    @MethodSource("nonJsonValues")
    void nonJsonAndNonFiniteChildrenAreRejectedBeforeCopyOrSerialization(JsonNode value) {
        assertRejectedBeforeCopy(JSON.createObjectNode().set("x", value));
    }

    static Stream<Arguments> nonJsonValues() {
        return Stream.of(MissingNode.getInstance(), BinaryNode.valueOf(new byte[]{1, 2}),
                        new POJONode(PRIVATE), DoubleNode.valueOf(Double.NaN),
                        DoubleNode.valueOf(Double.POSITIVE_INFINITY), DoubleNode.valueOf(Double.NEGATIVE_INFINITY),
                        FloatNode.valueOf(Float.NaN), FloatNode.valueOf(Float.POSITIVE_INFINITY),
                        FloatNode.valueOf(Float.NEGATIVE_INFINITY))
                .map(Arguments::of);
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 1})
    void projectedIntegerDigitBoundaryUsesAnIntegerSchemaAndPreservesDecimalNodes(int sign) {
        ApprovedPolicySource source = integerSource();
        for (int digits : new int[]{32768, 32769}) {
            BigDecimal number = new BigDecimal(BigInteger.valueOf(sign), 1 - digits);
            DecimalNode original = DecimalNode.valueOf(number);
            ObjectNode arguments = JSON.createObjectNode().set("value", original);
            if (digits == 32768) {
                assertPreserved(source, CASE, arguments, MATCH);
            } else {
                assertRejectedBeforeCopy(arguments);
            }
            assertThat(arguments.get("value")).isSameAs(original);
            assertThat(original.decimalValue()).isEqualTo(number);
            assertThat(original.decimalValue().scale()).isEqualTo(1 - digits);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 1})
    void compactHugeExponentsAndExtremeNegativeScaleCannotReachTheEngine(int sign) {
        assertRejectedBeforeCopy(JSON.createObjectNode().set("value",
                DecimalNode.valueOf(new BigDecimal(BigInteger.valueOf(sign), -100000000))));
        assertRejectedBeforeCopy(JSON.createObjectNode().set("value",
                DecimalNode.valueOf(new BigDecimal(BigInteger.valueOf(sign), Integer.MIN_VALUE))));
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 1})
    void decimalPrecisionBoundaryPrecedesTheExactSerializedByteBoundary(int sign) {
        for (int precision : new int[]{32768, 32769}) {
            BigInteger coefficient = new BigInteger("9".repeat(precision)).multiply(BigInteger.valueOf(sign));
            ObjectNode arguments = JSON.createObjectNode().set("value",
                    DecimalNode.valueOf(new BigDecimal(coefficient, precision)));
            if (precision == 32769) {
                assertRejectedBeforeCopy(arguments);
            } else {
                ObjectNode observed = spy(arguments);
                assertThat(evaluator.evaluate(permissiveSource(), new ToolProposal(CASE, observed)))
                        .isEqualTo(INVALID_REQUEST_SCHEMA);
                verify(observed).deepCopy();
                assertThat(utf8Bytes(arguments)).isGreaterThan(BYTE_LIMIT);
            }
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 1})
    void hugeUnscaledDecimalAndIntegerAreRejectedBeforeDecimalSerialization(int sign) {
        BigInteger coefficient = BigInteger.ONE.shiftLeft(131073).multiply(BigInteger.valueOf(sign));
        assertRejectedBeforeCopy(JSON.createObjectNode().set("value", BigIntegerNode.valueOf(coefficient)));
        assertRejectedBeforeCopy(JSON.createObjectNode().set("value",
                DecimalNode.valueOf(new BigDecimal(coefficient, 100000))));
    }

    @Test
    void finiteExponentAndExactIntegerDecimalsRemainSupportedWithoutCoercingInputs() {
        ApprovedPolicySource source = integerSource();
        for (String representation : new String[]{"1E+1000", "-1E+1000", "2.000", "0.000", "9007199254740993.0"}) {
            BigDecimal number = new BigDecimal(representation);
            DecimalNode original = DecimalNode.valueOf(number);
            ObjectNode arguments = JSON.createObjectNode().set("value", original);
            assertPreserved(source, CASE, arguments, MATCH);
            assertThat(arguments.get("value")).isSameAs(original);
            assertThat(original.decimalValue()).isEqualTo(number);
        }
        assertPreserved(source, CASE, JSON.createObjectNode().set("value", DecimalNode.valueOf(new BigDecimal("2.001"))),
                INVALID_REQUEST_SCHEMA);
        assertPreserved(source, CASE, json("{\"value\":\"2\"}"), INVALID_REQUEST_SCHEMA);
    }

    @Test
    void extremeScaleZeroPassesTheWorkGuardWithoutPromisingJsonBridgeAcceptance() {
        for (int scale : new int[]{Integer.MIN_VALUE, Integer.MAX_VALUE}) {
            BigDecimal zero = new BigDecimal(BigInteger.ZERO, scale);
            DecimalNode original = DecimalNode.valueOf(zero);
            ObjectNode arguments = spy(JSON.createObjectNode().set("value", original));
            assertThat(evaluator.evaluate(integerSource(), new ToolProposal(CASE, arguments)))
                    .isIn(MATCH, INVALID_REQUEST_SCHEMA);
            verify(arguments).deepCopy();
            assertThat(original.decimalValue().scale()).isEqualTo(scale);
            assertThat(original.decimalValue().unscaledValue()).isEqualTo(BigInteger.ZERO);
        }
    }

    @Test
    void exactDecimalConstIsComparedWithoutRoundingAndNeitherTreeIsMutated() {
        JsonNode schema = json("""
                {"type":"object","required":["value"],"additionalProperties":false,
                 "properties":{"value":{"type":"number"}}}
                """);
        ((ObjectNode) schema.at("/properties/value")).set("const",
                DecimalNode.valueOf(new BigDecimal("0.123456789012345678901")));
        String before = schema.toString();
        ApprovedPolicySource source = withSchema(schema);
        assertPreserved(source, CASE, JSON.createObjectNode().set("value",
                DecimalNode.valueOf(new BigDecimal("0.123456789012345678901"))), MATCH);
        assertPreserved(source, CASE, JSON.createObjectNode().set("value",
                DecimalNode.valueOf(new BigDecimal("0.123456789012345678902"))), INVALID_REQUEST_SCHEMA);
        assertThat(schema.toString()).isEqualTo(before);
    }

    @Test
    void localReferencesAndWholeSchemaConstraintsAreAppliedWithoutCrossToolReuse() {
        ApprovedPolicySource source = withSchema(json("""
                {"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object",
                 "$defs":{"value":{"type":"integer","minimum":1}},
                 "properties":{"value":{"$ref":"#/$defs/value"}},
                 "required":["value"],"additionalProperties":false}
                """));
        assertPreserved(source, CASE, json("{\"value\":1}"), MATCH);
        assertPreserved(source, CASE, json("{\"value\":0}"), INVALID_REQUEST_SCHEMA);
        assertPreserved(source, CASE, json("{\"value\":\"1\"}"), INVALID_REQUEST_SCHEMA);
        assertPreserved(source, CASE, json("{\"value\":1,\"extra\":true}"), INVALID_REQUEST_SCHEMA);
        assertPreserved(source, DOCUMENT, valid(DOCUMENT), MATCH);
        assertPreserved(source, DOCUMENT, json("{\"value\":1}"), INVALID_REQUEST_SCHEMA);
    }

    @Test
    void booleanFalseSchemaIsAValidCatalogSchemaThatRejectsTheRequest() {
        assertPreserved(withSchema(json("false")), CASE, json("{}"), INVALID_REQUEST_SCHEMA);
    }

    @ParameterizedTest
    @ValueSource(strings = {"{\"type\":42}", "{\"type\":\"invalid-type\"}", "{\"required\":\"x\"}",
            "{\"properties\":{\"x\":{\"type\":\"string\",\"pattern\":\"[\"}}}",
            "{\"$ref\":\"#/missing\"}", "{\"$ref\":\"https://invalid.example/private-schema\"}",
            "{\"$dynamicRef\":\"https://invalid.example/private-schema\"}",
            "{\"$schema\":\"http://json-schema.org/draft-07/schema#\"}",
            "{\"properties\":{\"x\":{\"format\":\"private-unsupported-format\"}}}",
            "[]", "null", "\"private-schema\""})
    void malformedOrUnsupportedKnownSchemaIsAnOperationalCatalogFailure(String schema) {
        assertFailure(INVALID_CATALOG_SCHEMA,
                () -> evaluator.evaluate(withSchema(json(schema)), new ToolProposal(CASE, json("{}"))));
    }

    @Test
    void absentSourceOrCatalogIsAnOperationalSourceFailure() {
        assertFailure(INVALID_POLICY_SOURCE, () -> evaluator.evaluate(null, new ToolProposal(CASE, valid(CASE))));
        assertFailure(INVALID_POLICY_SOURCE,
                () -> evaluator.evaluate(mock(ApprovedPolicySource.class), new ToolProposal(CASE, valid(CASE))));
    }

    @Test
    void ownerAccessFailuresHaveNoRawMessageCauseOrSuppressedException() {
        ApprovedPolicySource source = mock(ApprovedPolicySource.class);
        when(source.catalog()).thenThrow(new IllegalStateException(PRIVATE));
        assertFailure(INVALID_POLICY_SOURCE, () -> evaluator.evaluate(source, new ToolProposal(CASE, valid(CASE))));
        SourceBoundCatalog catalog = mock(SourceBoundCatalog.class);
        when(catalog.semanticCatalog()).thenThrow(new IllegalStateException(PRIVATE));
        ApprovedPolicySource semanticFailure = source(catalog);
        assertFailure(INVALID_POLICY_SOURCE,
                () -> evaluator.evaluate(semanticFailure, new ToolProposal(CASE, valid(CASE))));
        SourceBoundCatalog schemaAccess = mock(SourceBoundCatalog.class);
        when(schemaAccess.semanticCatalog()).thenReturn(semanticCatalog());
        when(schemaAccess.inputSchemas()).thenThrow(new IllegalStateException(PRIVATE));
        ApprovedPolicySource schemaFailure = source(schemaAccess);
        assertFailure(INVALID_POLICY_SOURCE,
                () -> evaluator.evaluate(schemaFailure, new ToolProposal(CASE, valid(CASE))));
    }

    @Test
    void absentSemanticCatalogAndEmptyMembershipAreInvalidPolicySources() {
        for (ContractValidationCatalog semantic : new ContractValidationCatalog[]{null,
                new ContractValidationCatalog(List.of(), List.of())}) {
            SourceBoundCatalog catalog = mock(SourceBoundCatalog.class);
            when(catalog.semanticCatalog()).thenReturn(semantic);
            when(catalog.inputSchemas()).thenReturn(actualSchemas());
            ApprovedPolicySource source = source(catalog);
            assertFailure(INVALID_POLICY_SOURCE, () -> evaluator.evaluate(source, new ToolProposal(CASE, valid(CASE))));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"duplicate-normal", "duplicate-high-impact", "overlap", "invalid-normal", "invalid-high-impact", "null-tool"})
    void corruptSemanticMembershipIsAnInvalidSource(String corruption) {
        ContractValidationCatalog semantic = mock(ContractValidationCatalog.class);
        List<EnabledTool> tools = semanticCatalog().enabledReleaseTools();
        List<String> highImpact = List.of(HUMAN);
        switch (corruption) {
            case "duplicate-normal" -> tools = List.of(new EnabledTool(CASE, List.of()), new EnabledTool(CASE, List.of()));
            case "duplicate-high-impact" -> highImpact = List.of(HUMAN, HUMAN);
            case "overlap" -> highImpact = List.of(CASE);
            case "invalid-normal" -> tools = List.of(new EnabledTool("raw invalid", List.of()));
            case "invalid-high-impact" -> highImpact = List.of("raw invalid");
            case "null-tool" -> { tools = new ArrayList<>(); tools.add(null); }
            default -> throw new AssertionError(corruption);
        }
        when(semantic.enabledReleaseTools()).thenReturn(tools);
        when(semantic.highImpactToolNames()).thenReturn(highImpact);
        SourceBoundCatalog catalog = mock(SourceBoundCatalog.class);
        when(catalog.semanticCatalog()).thenReturn(semantic);
        when(catalog.inputSchemas()).thenReturn(actualSchemas());
        ApprovedPolicySource source = source(catalog);
        assertFailure(INVALID_POLICY_SOURCE, () -> evaluator.evaluate(source, new ToolProposal(CASE, valid(CASE))));
    }

    @ParameterizedTest
    @ValueSource(strings = {CASE, DOCUMENT, CUSTOMER, SEARCH, REVIEW, HUMAN})
    void everyEnabledAndHumanOnlySchemaIsRequiredEvenWhenRequestingAnotherTool(String missing) {
        Map<String, JsonNode> schemas = actualSchemas();
        schemas.remove(missing);
        ApprovedPolicySource source = source(catalog(schemas));
        assertFailure(INVALID_CATALOG_SCHEMA, () -> evaluator.evaluate(source, new ToolProposal(CASE, valid(CASE))));
    }

    @Test
    void extraSchemaIsNotSilentlyPromotedIntoCatalogMembership() {
        Map<String, JsonNode> schemas = actualSchemas();
        schemas.put("EXTERNAL_HTTP", json("true"));
        ApprovedPolicySource source = source(catalog(schemas));
        assertFailure(INVALID_CATALOG_SCHEMA,
                () -> evaluator.evaluate(source, new ToolProposal("EXTERNAL_HTTP", json("{}"))));
    }

    @Test
    void nullSchemaMapOrKnownSchemaValueIsAnOperationalCatalogFailure() {
        Map<String, JsonNode> missingValue = actualSchemas();
        missingValue.put(CASE, null);
        for (Map<String, JsonNode> schemas : java.util.Arrays.asList(null, missingValue)) {
            SourceBoundCatalog catalog = mock(SourceBoundCatalog.class);
            when(catalog.semanticCatalog()).thenReturn(semanticCatalog());
            when(catalog.inputSchemas()).thenReturn(schemas);
            ApprovedPolicySource source = source(catalog);
            assertFailure(INVALID_CATALOG_SCHEMA, () -> evaluator.evaluate(source, new ToolProposal(CASE, valid(CASE))));
        }
    }

    @Test
    void unexpectedEngineFailureIsSanitizedWithoutChangingThePublicConstructor() {
        try (var construction = mockConstruction(CatalogJsonSchemaValidator.class, (engine, context) ->
                when(engine.matches(any(), any())).thenThrow(new IllegalStateException(PRIVATE)))) {
            CatalogBoundInputSchemaEvaluator faulted = new CatalogBoundInputSchemaEvaluator();
            assertFailure(SCHEMA_ENGINE_FAILURE,
                    () -> faulted.evaluate(actualSource(), new ToolProposal(CASE, valid(CASE))));
            assertThat(construction.constructed()).hasSize(1);
        }
    }

    @Test
    void failedRequestSnapshotIsAnInvalidRequestWithoutExposingTheFailure() {
        ObjectNode arguments = spy(valid(CASE));
        doThrow(new IllegalStateException(PRIVATE)).when(arguments).deepCopy();
        assertThat(evaluator.evaluate(actualSource(), new ToolProposal(CASE, arguments)))
                .isEqualTo(INVALID_REQUEST_SCHEMA);
    }

    private void assertRejectedBeforeCopy(ObjectNode arguments) {
        ObjectNode guarded = spy(arguments);
        doThrow(new AssertionError("Unsafe input reached recursive copy")).when(guarded).deepCopy();
        doThrow(new AssertionError("Unsafe input reached serialization")).when(guarded).toString();
        // Do not feed a cycle or explosive exponent into the real engine if a future order regresses.
        try (var construction = mockConstruction(CatalogJsonSchemaValidator.class)) {
            CatalogBoundInputSchemaEvaluator guardedEvaluator = new CatalogBoundInputSchemaEvaluator();
            assertThat(guardedEvaluator.evaluate(permissiveSource(), new ToolProposal(CASE, guarded)))
                    .isEqualTo(INVALID_REQUEST_SCHEMA);
            assertThat(construction.constructed()).hasSize(1);
            verifyNoInteractions(construction.constructed().getFirst());
        }
        verify(guarded, never()).deepCopy();
    }

    private void assertPreserved(ApprovedPolicySource source, String tool, JsonNode arguments, InputOutcome expected) {
        String before = arguments.toString();
        Map<String, JsonNode> schemasBefore = source.catalog().inputSchemas();
        ToolProposal proposal = new ToolProposal(tool, arguments);
        assertThat(evaluator.evaluate(source, proposal)).isEqualTo(expected);
        assertThat(proposal.toolName()).isEqualTo(tool);
        assertThat(proposal.arguments()).isSameAs(arguments);
        assertThat(arguments.toString()).isEqualTo(before);
        assertThat(source.catalog().inputSchemas()).isEqualTo(schemasBefore);
    }

    private static void assertFailure(FailureCode code, Runnable invocation) {
        InputSchemaException failure = catchThrowableOfType(InputSchemaException.class, invocation::run);
        assertThat(failure).isNotNull();
        assertThat(failure.code()).isEqualTo(code);
        assertThat(failure.getMessage()).isEqualTo(code.name()).doesNotContain(PRIVATE);
        assertThat(failure.getCause()).isNull();
        assertThat(failure.getSuppressed()).isEmpty();
    }

    private static ApprovedPolicySource actualSource() { return source(catalog(actualSchemas())); }

    private static ApprovedPolicySource permissiveSource() { return withSchema(json("true")); }

    private static ApprovedPolicySource integerSource() {
        return withSchema(json("""
                {"type":"object","properties":{"value":{"type":"integer"}},
                 "required":["value"],"additionalProperties":false}
                """));
    }

    private static ApprovedPolicySource withSchema(JsonNode schema) {
        Map<String, JsonNode> schemas = actualSchemas();
        schemas.put(CASE, schema);
        return source(catalog(schemas));
    }

    private static ApprovedPolicySource source(SourceBoundCatalog catalog) {
        ApprovedPolicySource source = mock(ApprovedPolicySource.class);
        when(source.catalog()).thenReturn(catalog);
        return source;
    }

    private static SourceBoundCatalog catalog(Map<String, JsonNode> schemas) {
        return new SourceBoundCatalog(RELEASE, "1.1", digest('a'), digest('b'), digest('c'),
                semanticCatalog(), List.of(), List.of(), List.of(), schemas);
    }

    private static ContractValidationCatalog semanticCatalog() {
        List<EnabledTool> tools = new ArrayList<>();
        LoanReviewToolCatalog.normalTools().forEach(tool ->
                tools.add(new EnabledTool(tool.path("name").asString(), List.of())));
        List<String> highImpact = new ArrayList<>();
        LoanReviewToolCatalog.serverToolCatalog().path("tools").forEach(tool ->
                highImpact.add(tool.path("name").asString()));
        return new ContractValidationCatalog(tools, highImpact);
    }

    private static Map<String, JsonNode> actualSchemas() {
        Map<String, JsonNode> schemas = new LinkedHashMap<>();
        LoanReviewToolCatalog.normalTools().forEach(tool ->
                schemas.put(tool.path("name").asString(), tool.path("inputSchema")));
        LoanReviewToolCatalog.serverToolCatalog().path("tools").forEach(tool ->
                schemas.put(tool.path("name").asString(), tool.path("inputSchema")));
        return schemas;
    }

    private static ObjectNode valid(String tool) {
        return (ObjectNode) json(switch (tool) {
            case CASE -> "{\"caseId\":\"CASE-1001\"}";
            case DOCUMENT -> "{\"caseId\":\"CASE-1001\",\"documentId\":\"DOC-1001\"}";
            case CUSTOMER -> "{\"customerIds\":[\"CUST-1001\"],\"fields\":[\"incomeBand\"]}";
            case SEARCH -> "{\"query\":\"income documents\"}";
            case REVIEW -> """
                    {"caseId":"CASE-1001","reviewResult":{"reviewStatus":"READY_FOR_HUMAN_REVIEW",
                     "missingDocuments":[],"evidence":[]}}
                    """;
            case HUMAN -> "{\"caseId\":\"CASE-1001\",\"decision\":\"APPROVED\"}";
            default -> throw new IllegalArgumentException("No fixture for Tool");
        });
    }

    private static ObjectNode asciiSized(int bytes) {
        return JSON.createObjectNode().put("x", "x".repeat(bytes - 8));
    }

    private static ObjectNode nested(int deepestValueDepth) {
        ObjectNode root = JSON.createObjectNode();
        ObjectNode cursor = root;
        for (int depth = 1; depth < deepestValueDepth - 1; depth++) cursor = cursor.putObject("x");
        cursor.putNull("x");
        return root;
    }

    private static int utf8Bytes(JsonNode value) { return value.toString().getBytes(StandardCharsets.UTF_8).length; }

    private static JsonNode json(String value) { return JSON.readTree(value); }

    private static String digest(char value) { return "sha256:" + String.valueOf(value).repeat(64); }
}
