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
import static org.mockito.Mockito.times;
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
    private static final int RESPONSE_BYTE_LIMIT = 1024 * 1024;
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
    void requestInvariantsDoNotInventCustomerScopeFieldEnumsOrNormalization() {
        ApprovedPolicySource source = actualSource();
        ObjectNode arguments = valid(CUSTOMER);
        arguments.putArray("customerIds").add(" CUST-1 ").add("CUST-1").add("CUST-2");
        arguments.putArray("fields").add("independent-policy-check").add("incomeBand").add(" incomeBand ");
        assertPreserved(source, CUSTOMER, arguments, MATCH);
        String before = arguments.toString();
        assertThat(evaluator.evaluateCatalog(source.catalog(), new ToolProposal(CUSTOMER, arguments))).isEqualTo(MATCH);
        assertThat(arguments.toString()).isEqualTo(before);
    }

    @ParameterizedTest
    @MethodSource("invalidCustomerRequestSets")
    void bothEntriesRejectDuplicateAndBlankCustomerRequestValuesBeforePolicy(String field, String value) {
        ApprovedPolicySource source = actualSource();
        ObjectNode arguments = valid(CUSTOMER);
        ArrayNode values = arguments.putArray(field).add(value);
        if (!value.isBlank()) values.add(value);
        String before = arguments.toString();
        Map<String, JsonNode> schemasBefore = source.catalog().inputSchemas();
        assertPreserved(source, CUSTOMER, arguments, INVALID_REQUEST_SCHEMA);
        assertThat(evaluator.evaluateCatalog(source.catalog(), new ToolProposal(CUSTOMER, arguments)))
                .isEqualTo(INVALID_REQUEST_SCHEMA);
        assertThat(arguments.toString()).isEqualTo(before);
        assertThat(source.catalog().inputSchemas()).isEqualTo(schemasBefore);
    }

    static Stream<Arguments> invalidCustomerRequestSets() {
        return Stream.of(Arguments.of("customerIds", "CUST-1002"), Arguments.of("fields", "incomeBand"),
                Arguments.of("customerIds", " \t"), Arguments.of("fields", " \t"));
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
            // At 32768 digits the numeric limit passes, but aggregate JSON bytes already exceed
            // the limit; at 32769 digits the numeric guard rejects first. Neither requires a copy.
            assertRejectedBeforeCopy(arguments);
            assertThat(utf8Bytes(arguments)).isGreaterThan(BYTE_LIMIT);
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
    @ValueSource(strings = {"const", "enum"})
    void formatNamedBusinessValuesStillRequireExactLiteralMatch(String keyword) {
        JsonNode literal = json("{\"format\":\"statement\",\"nested\":[{\"format\":\"receipt\"}]}");
        ObjectNode constraint = JSON.createObjectNode();
        constraint.set(keyword, keyword.equals("enum") ? JSON.createArrayNode().add(literal) : literal);
        ObjectNode schema = (ObjectNode) json("""
                {"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object",
                 "$defs":{},"properties":{"value":{"$ref":"#/$defs/choice"}},
                 "required":["value"],"additionalProperties":false}
                """);
        ((ObjectNode) schema.path("$defs")).set("choice", constraint);
        assertBothSchemaEntries(schema, JSON.createObjectNode().set("value", literal), MATCH);
        assertBothSchemaEntries(schema, json("{\"value\":{\"format\":\"other\"}}"), INVALID_REQUEST_SCHEMA);
    }

    @ParameterizedTest
    @ValueSource(strings = {"default", "examples", "x-business-data", "additionalItems"})
    void annotationsNeverOverrideActualInputConstraints(String keyword) {
        ObjectNode schema = (ObjectNode) json("""
                {"type":"object","properties":{"value":{"type":"string"}},
                 "required":["value"],"additionalProperties":false}
                """);
        JsonNode data = json("{\"format\":\"statement\",\"nested\":[{\"format\":\"receipt\"}]}");
        schema.set(keyword, keyword.equals("examples") ? JSON.createArrayNode().add(data) : data);
        ((ObjectNode) schema.at("/properties/value")).set("default", data.deepCopy());
        ((ObjectNode) schema.at("/properties/value")).set("additionalItems", data.deepCopy());
        assertBothSchemaEntries(schema, JSON.createObjectNode().put("value", PRIVATE), MATCH);
        for (String invalid : new String[]{"{}", "{\"value\":7}", "{\"value\":\"ok\",\"extra\":true}"}) {
            assertBothSchemaEntries(schema, json(invalid), INVALID_REQUEST_SCHEMA);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{\"format\":\"unknown-finsec-format\"}",
            "{\"$defs\":{\"unused\":%s}}", "{\"definitions\":{\"unused\":%s}}",
            "{\"properties\":{\"absent\":%s}}", "{\"patternProperties\":{\"^absent$\":%s}}",
            "{\"dependentSchemas\":{\"absent\":%s}}", "{\"dependencies\":{\"absent\":%s}}",
            "{\"allOf\":[%s]}", "{\"anyOf\":[true,%s]}", "{\"oneOf\":[true,%s]}",
            "{\"prefixItems\":[%s]}", "{\"items\":%s}", "{\"contains\":%s}",
            "{\"additionalProperties\":%s}", "{\"propertyNames\":%s}",
            "{\"unevaluatedProperties\":%s}", "{\"unevaluatedItems\":%s}",
            "{\"not\":%s}", "{\"if\":%s}", "{\"then\":%s}", "{\"else\":%s}",
            "{\"contentSchema\":%s}", "{\"if\":false,\"then\":%s}", "{\"if\":true,\"else\":%s}"
    })
    void unsupportedFormatsRemainCatalogErrorsEvenInUnusedSchemaLocations(String template) {
        assertBothSchemaFailures(json(template.formatted("{\"format\":\"unknown-finsec-format\"}")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"$ref", "$dynamicRef"})
    void aReferencedAnnotationCannotHideAnUnsupportedFormat(String keyword) {
        ObjectNode schema = (ObjectNode) json("""
                {"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object",
                 "default":{"target":{"format":"unknown-finsec-format"}}}
                """);
        assertBothSchemaEntries(schema, json("{}"), MATCH);
        schema.put(keyword, "#/default/target");
        assertBothSchemaFailures(schema);
        schema.remove(keyword);
        schema.set("additionalItems", json("{\"format\":\"unknown-finsec-format\"}"));
        assertBothSchemaEntries(schema, json("{}"), MATCH);
        schema.put(keyword, "#/additionalItems");
        assertBothSchemaFailures(schema);
    }

    @ParameterizedTest
    @ValueSource(strings = {"contentSchema", "then", "else"})
    void resolvedSchemaAnnotationsAndInactiveBranchesUseTheSameFormatGuard(String keyword) {
        JsonNode value = JSON.createObjectNode().put("value", PRIVATE);
        ObjectNode target = JSON.createObjectNode().set(keyword, json("""
                {"properties":{"value":{"format":"unknown-finsec-format"}}}
                """));
        assertBothSchemaFailures(target);
        ObjectNode schema = (ObjectNode) json("""
                {"type":"object","required":["value"],"additionalProperties":false,
                 "properties":{"value":{"type":"string"}},"default":{}}
                """);
        ((ObjectNode) schema.path("default")).set("target", target);
        assertBothSchemaEntries(schema, value, MATCH);
        assertBothSchemaEntries(schema, json("{}"), INVALID_REQUEST_SCHEMA);
        for (String reference : new String[]{"$ref", "$dynamicRef"}) {
            schema.put(reference, "#/default/target");
            assertBothSchemaFailures(schema);
            schema.remove(reference);
        }
        // Supported constraints stay inactive; annotation data is still not a schema.
        target.set(keyword, json("""
                {"type":"string","format":"date-time","default":{"format":"statement"}}
                """));
        schema.put("$ref", "#/default/target");
        assertBothSchemaEntries(schema, value, MATCH);
    }

    @ParameterizedTest
    @ValueSource(strings = {"then", "else"})
    void referencedActiveBranchesStillApplySupportedFormats(String keyword) {
        ObjectNode target = JSON.createObjectNode().put("if", keyword.equals("then"));
        target.set(keyword, json("""
                {"properties":{"value":{"format":"date-time"}},"default":{"format":"statement"}}
                """));
        ObjectNode schema = (ObjectNode) json("{\"$ref\":\"#/default/target\",\"default\":{}}");
        ((ObjectNode) schema.path("default")).set("target", target);
        assertBothSchemaEntries(schema, json("{\"value\":\"2026-09-09T00:00:00Z\"}"), MATCH);
        assertBothSchemaEntries(schema, JSON.createObjectNode().put("value", PRIVATE), INVALID_REQUEST_SCHEMA);
    }

    @Test
    void longReferenceChainsPreserveCatalogFailureInsteadOfBecomingRequestMismatch() {
        ObjectNode schema = (ObjectNode) json("{\"$ref\":\"#/x-chain/0\"}");
        ArrayNode chain = schema.putArray("x-chain");
        for (int index = 0; index < 45; index++) {
            chain.addObject().put("$ref", "#/x-chain/" + (index + 1));
        }
        chain.addObject().put("format", "unknown-finsec-format");
        assertBothSchemaFailures(schema);
    }

    @ParameterizedTest
    @ValueSource(strings = {"{\"if\":false,\"then\":{\"$ref\":\"#/default/target\"}}",
            "{\"if\":true,\"else\":{\"$ref\":\"#/default/target\"}}"})
    void unselectedConditionalReferencesCannotHideUnsupportedFormats(String text) {
        ObjectNode schema = (ObjectNode) json(text);
        schema.set("default", json("{\"target\":{\"format\":\"unknown-finsec-format\"}}"));
        assertBothSchemaFailures(schema);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{\"properties\":{\"value\":{\"$ref\":\"#/x~1data\"}},\"x/data\":{\"format\":\"date-time\"}}",
            "{\"properties\":{\"value\":{\"$ref\":\"#stamp\"}},\"$defs\":{\"stamp\":{\"$anchor\":\"stamp\",\"format\":\"date-time\"}}}",
            "{\"properties\":{\"value\":{\"$dynamicRef\":\"#stamp\"}},\"$defs\":{\"stamp\":{\"$dynamicAnchor\":\"stamp\",\"format\":\"date-time\"}}}"
    })
    void referencedSupportedFormatsStillValidateValues(String text) {
        ObjectNode schema = (ObjectNode) json(text);
        schema.set("default", json("{\"format\":\"statement\"}"));
        assertBothSchemaEntries(schema, json("{\"value\":\"2026-09-09T00:00:00Z\"}"), MATCH);
        assertBothSchemaEntries(schema, json("{\"value\":\"not-a-date\"}"), INVALID_REQUEST_SCHEMA);
    }

    @Test
    void sharedAndRecursiveSchemasDoNotReinterpretAnnotationDataOrLoop() {
        JsonNode schema = json("""
                {"$ref":"#/$defs/node","default":{"format":"statement"},
                 "$defs":{"node":{"type":"object","additionalProperties":false,
                 "properties":{"left":{"$ref":"#/$defs/node"},"right":{"$ref":"#/$defs/node"}}}}}
                """);
        assertBothSchemaEntries(schema, json("{\"left\":{},\"right\":{\"left\":{}}}"), MATCH);
        assertBothSchemaEntries(schema, json("{\"left\":7}"), INVALID_REQUEST_SCHEMA);
    }

    @ParameterizedTest
    @ValueSource(strings = {"date-time", "unknown-finsec-format"})
    void embeddedResourceKeepsItsOwnDialectAndLocalReferenceScope(String format) {
        ObjectNode schema = (ObjectNode) json("""
                {"$ref":"#/$defs/inner","default":{"format":"statement"},
                 "$defs":{"inner":{"$id":"urn:finsec:embedded-format",
                 "$schema":"https://json-schema.org/draft/2020-12/schema",
                 "type":"object","properties":{"value":{"$ref":"#/x-target"}},"x-target":{}}}}
                """);
        ((ObjectNode) schema.at("/$defs/inner/x-target")).put("format", format);
        if (format.equals("unknown-finsec-format")) {
            assertBothSchemaFailures(schema);
        } else {
            assertBothSchemaEntries(schema, json("{\"value\":\"2026-09-09T00:00:00Z\"}"), MATCH);
            assertBothSchemaEntries(schema, json("{\"value\":\"not-a-date\"}"), INVALID_REQUEST_SCHEMA);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{\"default\":{\"$ref\":\"https://invalid.example/schema\"}}",
            "{\"examples\":[{\"$dynamicRef\":\"file:///tmp/private-schema.json\"}]}",
            "{\"x-data\":{\"$schema\":\"http://json-schema.org/draft-07/schema#\"}}"
    })
    void existingReferenceAndDialectRestrictionsAlsoRemainInAnnotations(String schema) {
        assertBothSchemaFailures(json(schema));
    }

    private void assertBothSchemaEntries(JsonNode schema, JsonNode value, InputOutcome expected) {
        String before = schema.toString();
        ApprovedPolicySource source = withSchema(schema);
        assertPreserved(source, CASE, value, expected);
        String valueBefore = value.toString();
        assertThat(evaluator.evaluateCatalog(source.catalog(), new ToolProposal(CASE, value))).isEqualTo(expected);
        assertThat(value.toString()).isEqualTo(valueBefore);
        assertThat(schema.toString()).isEqualTo(before);
    }

    private void assertBothSchemaFailures(JsonNode schema) {
        String before = schema.toString();
        ApprovedPolicySource source = withSchema(schema);
        ToolProposal proposal = new ToolProposal(CASE, JSON.createObjectNode().put("value", PRIVATE));
        String valueBefore = proposal.arguments().toString();
        assertFailure(INVALID_CATALOG_SCHEMA, () -> evaluator.evaluate(source, proposal));
        assertFailure(INVALID_CATALOG_SCHEMA, () -> evaluator.evaluateCatalog(source.catalog(), proposal));
        assertThat(proposal.arguments().toString()).isEqualTo(valueBefore);
        assertThat(schema.toString()).isEqualTo(before);
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

    @ParameterizedTest(name = "catalog-only {0}")
    @MethodSource("catalogEntryRequests")
    void catalogEntryPreservesApprovedEntryOutcomesWithoutReadingTheSourceAgain(
            String name, ToolProposal proposal, InputOutcome expected
    ) {
        SourceBoundCatalog catalog = catalog(actualSchemas());
        ApprovedPolicySource source = source(catalog);
        Map<String, JsonNode> beforeSchemas = catalog.inputSchemas();
        String beforeArguments = proposal == null ? null : proposal.arguments().toString();

        assertThat(evaluator.evaluate(source, proposal)).isEqualTo(expected);
        assertThat(evaluator.evaluateCatalog(catalog, proposal)).isEqualTo(expected);

        verify(source, times(1)).catalog();
        assertThat(catalog.inputSchemas()).isEqualTo(beforeSchemas);
        if (proposal != null) assertThat(proposal.arguments().toString()).isEqualTo(beforeArguments);
    }

    static Stream<Arguments> catalogEntryRequests() {
        return Stream.of(
                Arguments.of("normal", new ToolProposal(CASE, valid(CASE)), MATCH),
                Arguments.of("human schema without permission", new ToolProposal(HUMAN, valid(HUMAN)), MATCH),
                Arguments.of("invalid actual schema", new ToolProposal(CASE, json("{\"caseId\":7}")), INVALID_REQUEST_SCHEMA),
                Arguments.of("unknown tool", new ToolProposal("UNKNOWN_TOOL", json("{}")), TOOL_NOT_IN_CATALOG),
                Arguments.of("missing proposal", null, INVALID_REQUEST_SCHEMA));
    }

    @Test
    void catalogEntryRetainsSourceCoverageAndKnownSchemaFailureCodes() {
        ToolProposal proposal = new ToolProposal(CASE, valid(CASE));
        assertFailure(INVALID_POLICY_SOURCE, () -> evaluator.evaluateCatalog(null, proposal));
        assertFailure(INVALID_POLICY_SOURCE,
                () -> evaluator.evaluateCatalog(mock(SourceBoundCatalog.class), proposal));
        Map<String, JsonNode> missing = actualSchemas();
        missing.remove(HUMAN);
        assertFailure(INVALID_CATALOG_SCHEMA, () -> evaluator.evaluateCatalog(catalog(missing), proposal));
        Map<String, JsonNode> malformed = actualSchemas();
        malformed.put(CASE, json("{\"type\":\"unknown-type\"}"));
        assertFailure(INVALID_CATALOG_SCHEMA, () -> evaluator.evaluateCatalog(catalog(malformed), proposal));
    }

    @Test
    void catalogEntryUsesTheSameSanitizedSchemaEngineFailure() {
        try (var construction = mockConstruction(CatalogJsonSchemaValidator.class, (engine, context) ->
                when(engine.matches(any(), any())).thenThrow(new IllegalStateException(PRIVATE)))) {
            CatalogBoundInputSchemaEvaluator faulted = new CatalogBoundInputSchemaEvaluator();
            assertFailure(SCHEMA_ENGINE_FAILURE,
                    () -> faulted.evaluateCatalog(catalog(actualSchemas()), new ToolProposal(CASE, valid(CASE))));
            assertThat(construction.constructed()).hasSize(1);
            verify(construction.constructed().getFirst(), times(1)).matches(any(), any());
        }
    }

    @Test
    void argumentSnapshotKeepsItsOriginalObjectByteAndDepthLimits() {
        assertThat(CatalogBoundInputSchemaEvaluator.snapshotArguments(asciiSized(BYTE_LIMIT)))
                .isEqualTo(asciiSized(BYTE_LIMIT));
        assertThat(CatalogBoundInputSchemaEvaluator.snapshotArguments(asciiSized(BYTE_LIMIT + 1))).isNull();
        assertThat(CatalogBoundInputSchemaEvaluator.snapshotArguments(nested(32))).isEqualTo(nested(32));
        assertThat(CatalogBoundInputSchemaEvaluator.snapshotArguments(nested(33))).isNull();
        assertThat(CatalogBoundInputSchemaEvaluator.snapshotArguments(null)).isNull();
    }

    @Test
    void responseSnapshotAcceptsEveryNormalJsonRootWithoutRelaxingArgumentRoots() {
        for (String raw : List.of("{}", "[]", "\"plain text\"", "7", "1.25", "true", "null")) {
            JsonNode body = json(raw);
            JsonNode snapshot = CatalogBoundInputSchemaEvaluator.snapshotResponse(body);
            assertThat(snapshot).isNotNull().isEqualTo(body);
            assertThat(body.toString()).isEqualTo(raw);
            if (!body.isObject()) {
                assertThat(CatalogBoundInputSchemaEvaluator.snapshotArguments(body)).isNull();
            }
        }
        assertThat(CatalogBoundInputSchemaEvaluator.snapshotResponse(null)).isNull();
    }

    @ParameterizedTest
    @ValueSource(ints = {1048575, 1048576, 1048577})
    void responseSnapshotHasItsOwnExactUtf8LimitIncludingEscapes(int bytes) {
        ObjectNode response = JSON.createObjectNode().put("한\"", "한\"\\\n".repeat(200));
        int padding = bytes - utf8Bytes(response);
        response.put("한\"", response.path("한\"").asString() + "x".repeat(padding));
        assertThat(utf8Bytes(response)).isEqualTo(bytes);
        assertThat(response.toString().length()).isLessThan(bytes);

        JsonNode snapshot = CatalogBoundInputSchemaEvaluator.snapshotResponse(response);
        if (bytes <= RESPONSE_BYTE_LIMIT) {
            assertThat(snapshot).isEqualTo(response).isNotSameAs(response);
            assertThat(utf8Bytes(snapshot)).isEqualTo(bytes);
        } else {
            assertThat(snapshot).isNull();
        }
        assertThat(CatalogBoundInputSchemaEvaluator.snapshotArguments(response)).isNull();
        assertThat(utf8Bytes(response)).isEqualTo(bytes);
    }

    @ParameterizedTest
    @ValueSource(ints = {64, 65})
    void responseSnapshotCountsTheRootAsDepthOne(int depth) {
        ObjectNode response = nested(depth);
        JsonNode snapshot = CatalogBoundInputSchemaEvaluator.snapshotResponse(response);
        if (depth == 64) {
            assertThat(snapshot).isEqualTo(response).isNotSameAs(response);
        } else {
            assertThat(snapshot).isNull();
        }
        assertThat(CatalogBoundInputSchemaEvaluator.snapshotArguments(response)).isNull();
    }

    @Test
    void argumentAndResponseSnapshotsHaveIndependentNestedOwnership() {
        ObjectNode original = (ObjectNode) json("{\"items\":[{\"value\":\"original\"}]}");
        ObjectNode arguments = (ObjectNode) CatalogBoundInputSchemaEvaluator.snapshotArguments(original);
        ObjectNode response = (ObjectNode) CatalogBoundInputSchemaEvaluator.snapshotResponse(original);
        assertThat(arguments).isNotSameAs(original);
        assertThat(response).isNotSameAs(original).isNotSameAs(arguments);

        ((ObjectNode) original.at("/items/0")).put("value", "owner changed");
        assertThat(arguments.at("/items/0/value").asString()).isEqualTo("original");
        assertThat(response.at("/items/0/value").asString()).isEqualTo("original");
        ((ObjectNode) arguments.at("/items/0")).put("value", "arguments changed");
        assertThat(response.at("/items/0/value").asString()).isEqualTo("original");
        ((ArrayNode) response.path("items")).add("response changed");
        assertThat(arguments.path("items").size()).isEqualTo(1);
        assertThat(original.path("items").size()).isEqualTo(1);
        assertThat(original.at("/items/0/value").asString()).isEqualTo("owner changed");
    }

    @Test
    void bothSnapshotPathsRejectCyclesAndUnsafeValuesBeforeRecursiveWork() {
        ObjectNode cyclic = JSON.createObjectNode();
        cyclic.set("cycle", cyclic);
        assertSnapshotsRejectBeforeCopy(cyclic);
        for (JsonNode value : List.of(new POJONode(PRIVATE), MissingNode.getInstance(),
                BinaryNode.valueOf(new byte[]{1}), DoubleNode.valueOf(Double.NaN),
                DoubleNode.valueOf(Double.POSITIVE_INFINITY))) {
            assertSnapshotsRejectBeforeCopy(JSON.createObjectNode().set("x", value));
            assertThat(CatalogBoundInputSchemaEvaluator.snapshotResponse(value)).isNull();
        }
    }

    @Test
    void largerResponseBudgetKeepsTheSameNumericWorkLimit() {
        DecimalNode boundary = DecimalNode.valueOf(new BigDecimal(BigInteger.ONE, -32767));
        ObjectNode safe = JSON.createObjectNode().set("x", boundary);
        assertThat(CatalogBoundInputSchemaEvaluator.snapshotArguments(safe)).isEqualTo(safe);
        assertThat(CatalogBoundInputSchemaEvaluator.snapshotResponse(safe)).isEqualTo(safe);
        assertThat(safe.path("x")).isSameAs(boundary);
        for (JsonNode value : List.of(
                DecimalNode.valueOf(new BigDecimal(BigInteger.ONE, -32768)),
                DecimalNode.valueOf(new BigDecimal("1E+100000000")),
                DecimalNode.valueOf(new BigDecimal(BigInteger.ONE, Integer.MIN_VALUE)),
                DecimalNode.valueOf(new BigDecimal(BigInteger.TEN.pow(32768), 32768)),
                BigIntegerNode.valueOf(BigInteger.ONE.shiftLeft(131072)))) {
            assertSnapshotsRejectBeforeCopy(JSON.createObjectNode().set("x", value));
        }
    }

    @Test
    void compactExponentsShareAnAggregateWorkBudgetWithoutCountingPunctuationAsNumericWork() {
        DecimalNode number = DecimalNode.valueOf(new BigDecimal(BigInteger.ONE, -32767));
        ObjectNode twoNumbers = JSON.createObjectNode();
        twoNumbers.putArray("values").add(number).add(number);
        assertRejectedBeforeCopy(twoNumbers);
        assertThat(CatalogBoundInputSchemaEvaluator.snapshotResponse(twoNumbers)).isEqualTo(twoNumbers);

        ObjectNode response = JSON.createObjectNode();
        ArrayNode values = response.putArray("values");
        for (int index = 0; index < 32; index++) values.add(number);
        // 32 * 32768 numeric digits equals 1MiB; the compact JSON punctuation has its own byte budget.
        assertThat(CatalogBoundInputSchemaEvaluator.snapshotResponse(response)).isEqualTo(response);
        values.add(number);
        assertSnapshotsRejectBeforeCopy(response);
    }

    @Test
    void serializedIntegerDigitsCountAgainstTheByteBudgetBeforeRecursiveCopy() {
        BigIntegerNode number = BigIntegerNode.valueOf(BigInteger.TEN.pow(32767));
        ObjectNode arguments = JSON.createObjectNode().set("number", number);
        // Numeric work is exactly 32768, but the full JSON is larger than the input byte budget.
        assertRejectedBeforeCopy(arguments);

        ObjectNode response = JSON.createObjectNode();
        ArrayNode values = response.putArray("values");
        for (int index = 0; index < 32; index++) values.add(number);
        // Numeric work equals 1MiB; delimiters and commas make the serialized response too large.
        assertSnapshotsRejectBeforeCopy(response);
    }

    private static void assertSnapshotsRejectBeforeCopy(ObjectNode value) {
        ObjectNode guarded = spy(value);
        doThrow(new AssertionError("Unsafe snapshot reached recursive copy")).when(guarded).deepCopy();
        doThrow(new AssertionError("Unsafe snapshot reached serialization")).when(guarded).toString();
        assertThat(CatalogBoundInputSchemaEvaluator.snapshotArguments(guarded)).isNull();
        assertThat(CatalogBoundInputSchemaEvaluator.snapshotResponse(guarded)).isNull();
        verify(guarded, never()).deepCopy();
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
