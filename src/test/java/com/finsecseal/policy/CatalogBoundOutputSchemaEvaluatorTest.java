package com.finsecseal.policy;

import static com.finsecseal.policy.CatalogBoundOutputSchemaEvaluator.FailureCode.*;
import static com.finsecseal.policy.CatalogBoundOutputSchemaEvaluator.Outcome.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.evidence.TestRunDto;
import com.finsecseal.evidence.TestRunProjectionService;
import com.finsecseal.policy.CatalogBoundOutputSchemaEvaluator.FailureCode;
import com.finsecseal.policy.CatalogBoundOutputSchemaEvaluator.SchemaCheckException;
import com.finsecseal.release.LoanReviewToolCatalog;
import com.finsecseal.release.ReleaseDto.ToolCatalogResponse;
import com.finsecseal.release.ReleaseService;
import com.sun.net.httpserver.HttpServer;
import java.math.BigDecimal;
import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.*;

/** Actual A schemas; non-customer output fixtures are synthetic shapes, not B execution evidence. */
class CatalogBoundOutputSchemaEvaluatorTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final UUID RUN = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID RELEASE = UUID.fromString("00000000-0000-0000-0000-000000000002");
    private static final String ACTOR = "reviewer:test";
    private static final String ARTIFACT = digest('a');
    private static final String RELEASE_HASH = digest('b');
    private static final String CATALOG_HASH = digest('c');
    private static final String CUSTOMER = "CUSTOMER_DATA_READ";
    private static final Map<String, String> OUTPUTS = Map.of(
            "CASE_CONTEXT_READ", """
                {"caseId":"CASE-1001","currentApplicantId":"CUST-1001",
                 "workflowStage":"DOCUMENT_REVIEW","allowedDocumentIds":[]}
                """,
            "DOCUMENT_READER", """
                {"caseId":"CASE-1001","documentId":"DOC-1001","ownerCustomerId":"CUST-1001",
                 "documentType":"INCOME_STATEMENT","content":"Synthetic income statement",
                 "sourceTrustLevel":"UNTRUSTED_APPLICANT","createdAt":"2026-09-07T00:00:00Z"}
                """,
            CUSTOMER, """
                {"status":200,"rows":[{"customerId":"CUST-1002","fields":{"incomeBand":"HIGH"}}]}
                """,
            "LOAN_POLICY_SEARCH", """
                {"policies":[{"policyId":"POL-1001","version":"1.0.0","productType":"PERSONAL_LOAN",
                 "ruleCode":"INCOME_DOCUMENT_REQUIRED","requirement":"Income statement required",
                 "sourceTrustLevel":"TRUSTED_INTERNAL"}]}
                """,
            "REVIEW_NOTE_WRITE", """
                {"caseId":"CASE-1001","reviewStatus":"READY_FOR_HUMAN_REVIEW","missingDocuments":[],
                 "evidence":[{"rule":"INCOME_DOCUMENT_REQUIRED","reason":"Income statement supplied"}]}
                """
    );

    private TestRunProjectionService runs;
    private ReleaseService releases;
    private CatalogBoundOutputSchemaEvaluator evaluator;

    @BeforeEach
    void setUp() {
        runs = mock(TestRunProjectionService.class);
        releases = mock(ReleaseService.class);
        when(runs.find(RUN)).thenReturn(run(RUN, RELEASE, ARTIFACT, RELEASE_HASH));
        when(releases.toolCatalog(RELEASE, ACTOR)).thenReturn(catalog(LoanReviewToolCatalog.normalTools()));
        evaluator = new CatalogBoundOutputSchemaEvaluator(runs, releases);
    }

    @ParameterizedTest
    @MethodSource("validOutputs")
    void appliesEachActualCatalogSchemaAndPreservesSourceBinding(String tool, JsonNode output) {
        var result = evaluator.evaluate(RUN, tool, output, ACTOR);
        assertThat(result.outcome()).isEqualTo(MATCH);
        assertThat(result.source()).isEqualTo(new CatalogBoundOutputSchemaEvaluator.SourceBinding(
                RUN, RELEASE, tool, "1.1", ARTIFACT, RELEASE_HASH, CATALOG_HASH));
        var order = inOrder(runs, releases);
        order.verify(runs).find(RUN);
        order.verify(releases).toolCatalog(RELEASE, ACTOR);
        verifyNoMoreInteractions(runs, releases);
        assertThat(result.toString()).doesNotContain(output.toString());
    }

    static Stream<Arguments> validOutputs() {
        return OUTPUTS.entrySet().stream().map(entry -> Arguments.of(entry.getKey(), json(entry.getValue())));
    }

    @ParameterizedTest
    @MethodSource("invalidOutputs")
    void rejectsActualSchemaViolations(String tool, JsonNode output) {
        assertThat(evaluator.evaluate(RUN, tool, output, ACTOR).outcome()).isEqualTo(ADAPTER_CONTRACT_FAILURE);
    }

    static Stream<Arguments> invalidOutputs() {
        var cases = Stream.<Arguments>builder();
        OUTPUTS.forEach((tool, value) -> {
            ObjectNode extra = (ObjectNode) json(value);
            extra.put("unexpected", "private-output-marker");
            cases.add(Arguments.of(tool, extra));
            cases.add(Arguments.of(tool, json("[]")));
            cases.add(Arguments.of(tool, json("{}")));
        });
        cases.add(Arguments.of("CASE_CONTEXT_READ", changed("CASE_CONTEXT_READ", "allowedDocumentIds", "[42]")));
        cases.add(Arguments.of("CASE_CONTEXT_READ", changed("CASE_CONTEXT_READ", "currentApplicantId", "null")));
        cases.add(Arguments.of("DOCUMENT_READER", changed("DOCUMENT_READER", "documentType", "\"APPROVAL\"")));
        cases.add(Arguments.of("DOCUMENT_READER", changed("DOCUMENT_READER", "sourceTrustLevel", "\"LLM\"")));
        cases.add(Arguments.of("DOCUMENT_READER", changed("DOCUMENT_READER", "content", "{}")));
        for (String date : new String[]{"2026-09-07", "2026-09-07T00:00:00", "2026-02-30T00:00:00Z"}) {
            cases.add(Arguments.of("DOCUMENT_READER", changed("DOCUMENT_READER", "createdAt", JSON.writeValueAsString(date))));
        }
        for (String status : new String[]{"201", "200.5", "\"200\"", "true"}) {
            cases.add(Arguments.of(CUSTOMER, changed(CUSTOMER, "status", status)));
        }
        for (String rows : new String[]{"{}", "[42]", "[{\"customerId\":\"CUST-1001\"}]",
                "[{\"customerId\":\"CUST-1001\",\"fields\":{\"incomeBand\":42}}]",
                "[{\"customerId\":\"CUST-1001\",\"fields\":{\"unknownField\":\"private-output-marker\"}}]"}) {
            cases.add(Arguments.of(CUSTOMER, changed(CUSTOMER, "rows", rows)));
        }
        ObjectNode policy = (ObjectNode) json(OUTPUTS.get("LOAN_POLICY_SEARCH"));
        ((ObjectNode) policy.path("policies").get(0)).put("sourceTrustLevel", "UNTRUSTED_APPLICANT");
        cases.add(Arguments.of("LOAN_POLICY_SEARCH", policy));
        cases.add(Arguments.of("REVIEW_NOTE_WRITE", changed("REVIEW_NOTE_WRITE", "reviewStatus", "\"APPROVED\"")));
        cases.add(Arguments.of("REVIEW_NOTE_WRITE", changed("REVIEW_NOTE_WRITE", "evidence", "[{\"rule\":\"R\"}]")));
        cases.add(Arguments.of("REVIEW_NOTE_WRITE", changed("REVIEW_NOTE_WRITE", "missingDocuments", "[false]")));
        return cases.build();
    }

    @Test
    void preservesJsonSchemaNumericAndEmptyCollectionSemanticsWithoutPolicyPermission() {
        assertThat(evaluator.evaluate(RUN, CUSTOMER, json("{\"status\":200.0,\"rows\":[]}"), ACTOR).outcome()).isEqualTo(MATCH);
        assertThat(evaluator.evaluate(RUN, CUSTOMER, json("{\"status\":200,\"rows\":[{\"customerId\":\"OTHER\",\"fields\":{}}]}"), ACTOR).outcome()).isEqualTo(MATCH);
        assertThat(evaluator.evaluate(RUN, "LOAN_POLICY_SEARCH", json("{\"policies\":[]}"), ACTOR).outcome()).isEqualTo(MATCH);
        useSchema(json("{\"type\":\"number\"}"));
        assertThat(evaluator.evaluate(RUN, CUSTOMER, DecimalNode.valueOf(new BigDecimal("1e1000")), ACTOR).outcome()).isEqualTo(MATCH);
    }

    @ParameterizedTest
    @MethodSource("nonJsonValues")
    void rejectsNonJsonAndNonFiniteNodesEvenWhenSchemaWouldAcceptAnything(JsonNode value) {
        useSchema(json("true"));
        assertThat(evaluator.evaluate(RUN, CUSTOMER, value, ACTOR).outcome()).isEqualTo(ADAPTER_CONTRACT_FAILURE);
        if (value != null) {
            ObjectNode nested = JSON.createObjectNode().set("nested", value);
            assertThat(evaluator.evaluate(RUN, CUSTOMER, nested, ACTOR).outcome()).isEqualTo(ADAPTER_CONTRACT_FAILURE);
        }
    }

    static Stream<Arguments> nonJsonValues() {
        return Stream.of(null, MissingNode.getInstance(), BinaryNode.valueOf(new byte[]{1, 2}),
                        new POJONode("private-output-marker"), DoubleNode.valueOf(Double.NaN),
                        DoubleNode.valueOf(Double.POSITIVE_INFINITY), FloatNode.valueOf(Float.NEGATIVE_INFINITY))
                .map(value -> Arguments.of((Object) value));
    }

    @Test
    void acceptsLocalReferencesAndDoesNotReuseAnotherToolsSchema() {
        useSchema(json("""
                {"$schema":"https://json-schema.org/draft/2020-12/schema",
                 "$defs":{"value":{"type":"integer"}},"$ref":"#/$defs/value"}
                """));
        assertThat(evaluator.evaluate(RUN, CUSTOMER, json("7"), ACTOR).outcome()).isEqualTo(MATCH);
        assertThat(evaluator.evaluate(RUN, CUSTOMER, json("\"7\""), ACTOR).outcome()).isEqualTo(ADAPTER_CONTRACT_FAILURE);
        useSchema(json("{\"type\":\"string\"}"));
        assertThat(evaluator.evaluate(RUN, CUSTOMER, json("7"), ACTOR).outcome()).isEqualTo(ADAPTER_CONTRACT_FAILURE);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{\"type\":42}", "{\"type\":\"invalid-type\"}", "{\"required\":\"value\"}",
            "{\"type\":\"string\",\"pattern\":\"[\"}", "{\"$ref\":\"#/missing\"}",
            "{\"$schema\":\"http://json-schema.org/draft-07/schema#\"}",
            "{\"properties\":{\"value\":{\"$schema\":\"https://invalid.example/schema\"}}}",
            "{\"$ref\":42}", "{\"$dynamicRef\":42}", "[]", "\"not-a-schema\""
    })
    void malformedOrUnsupportedSchemasAreOperationalFailures(String schema) {
        useSchema(json(schema));
        assertFailure(INVALID_SCHEMA, () -> evaluator.evaluate(RUN, CUSTOMER, json("\"private-output-marker\""), ACTOR));
    }

    @Test
    void strictUnknownFormatProducesContractFailureWithoutAcceptingOutput() {
        useSchema(json("{\"type\":\"string\",\"format\":\"unknown-finsec-format\"}"));
        var result = evaluator.evaluate(RUN, CUSTOMER, json("\"private-output-marker\""), ACTOR);
        assertThat(result.outcome()).isEqualTo(ADAPTER_CONTRACT_FAILURE);
        assertThat(result.toString()).doesNotContain("private-output-marker");
    }

    @ParameterizedTest
    @ValueSource(strings = {"file:///tmp/private-output-schema.json", "classpath:release/loan-review-tool-catalog-1.1.json",
            "https://invalid.example/schema", "relative-schema.json"})
    void rejectsNonlocalReferencesIncludingDynamicAndNestedReferences(String location) {
        for (String keyword : new String[]{"$ref", "$dynamicRef"}) {
            ObjectNode reference = JSON.createObjectNode().put(keyword, location);
            useSchema(reference);
            assertFailure(INVALID_SCHEMA, () -> evaluator.evaluate(RUN, CUSTOMER, json("{}"), ACTOR));
            useSchema(JSON.createObjectNode().set("$defs", JSON.createObjectNode().set("unused", reference)));
            assertFailure(INVALID_SCHEMA, () -> evaluator.evaluate(RUN, CUSTOMER, json("{}"), ACTOR));
        }
    }

    @Test
    void neverRequestsHttpReferencedSchema() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/schema", exchange -> {
            requests.incrementAndGet();
            exchange.sendResponseHeaders(200, 4);
            exchange.getResponseBody().write("true".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            exchange.close();
        });
        server.start();
        try {
            String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/schema";
            useSchema(JSON.createObjectNode().put("$ref", url));
            assertFailure(INVALID_SCHEMA, () -> evaluator.evaluate(RUN, CUSTOMER, json("{}"), ACTOR));
            assertThat(requests).hasValue(0);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void absentAndHumanOnlyToolsHaveNoNormalOutputSchema() {
        for (String tool : new String[]{"EXTERNAL_HTTP", "LOAN_DECISION_UPDATE", "UNKNOWN_TOOL"}) {
            assertThat(evaluator.evaluate(RUN, tool, json("{}"), ACTOR).outcome()).isEqualTo(ADAPTER_CONTRACT_FAILURE);
        }
        ArrayNode tools = JSON.createArrayNode().add(JSON.createObjectNode().put("name", CUSTOMER));
        when(releases.toolCatalog(RELEASE, ACTOR)).thenReturn(catalog(tools));
        assertThat(evaluator.evaluate(RUN, CUSTOMER, json("{}"), ACTOR).outcome()).isEqualTo(ADAPTER_CONTRACT_FAILURE);
    }

    @Test
    void rejectsMalformedOrDuplicateCatalogEntries() {
        for (JsonNode tools : new JsonNode[]{null, json("{}"), json("[null]"), json("[{\"name\":42}]"),
                json("[{\"name\":\"CUSTOMER_DATA_READ\",\"outputSchema\":true},{\"name\":\"CUSTOMER_DATA_READ\",\"outputSchema\":true}]")}) {
            when(releases.toolCatalog(RELEASE, ACTOR)).thenReturn(catalog(tools));
            assertFailure(INVALID_CATALOG, () -> evaluator.evaluate(RUN, CUSTOMER, json("{}"), ACTOR));
        }
    }

    @Test
    void sourceFailuresNeverReturnMatchOrExposeCause() {
        when(runs.find(RUN)).thenThrow(new IllegalStateException("private-output-marker"));
        assertFailure(SOURCE_LOAD_FAILURE, () -> evaluator.evaluate(RUN, CUSTOMER, json("{}"), ACTOR));
        verifyNoInteractions(releases);
        doReturn(run(RUN, RELEASE, ARTIFACT, RELEASE_HASH)).when(runs).find(RUN);
        when(releases.toolCatalog(RELEASE, ACTOR)).thenThrow(new IllegalStateException("private-output-marker"));
        assertFailure(SOURCE_LOAD_FAILURE, () -> evaluator.evaluate(RUN, CUSTOMER, json("{}"), ACTOR));
    }

    @Test
    void requiresStoredRunIdentityAndFingerprintsBeforeCatalogRead() {
        for (TestRunDto.Projection run : new TestRunDto.Projection[]{null,
                run(RELEASE, RELEASE, ARTIFACT, RELEASE_HASH), run(RUN, null, ARTIFACT, RELEASE_HASH),
                run(RUN, RELEASE, null, RELEASE_HASH), run(RUN, RELEASE, "invalid", RELEASE_HASH),
                run(RUN, RELEASE, ARTIFACT, null)}) {
            when(runs.find(RUN)).thenReturn(run);
            assertFailure(SOURCE_BINDING_FAILURE, () -> evaluator.evaluate(RUN, CUSTOMER, json("{}"), ACTOR));
        }
        verifyNoInteractions(releases);
    }

    @Test
    void requiresExactReleaseAndCatalogFingerprintBinding() {
        JsonNode tools = LoanReviewToolCatalog.normalTools();
        for (ToolCatalogResponse source : new ToolCatalogResponse[]{null,
                new ToolCatalogResponse(RUN, "1.1", ARTIFACT, RELEASE_HASH, CATALOG_HASH, tools, null),
                new ToolCatalogResponse(RELEASE, "1.0", ARTIFACT, RELEASE_HASH, CATALOG_HASH, tools, null),
                new ToolCatalogResponse(RELEASE, "1.1", digest('d'), RELEASE_HASH, CATALOG_HASH, tools, null),
                new ToolCatalogResponse(RELEASE, "1.1", ARTIFACT, digest('d'), CATALOG_HASH, tools, null),
                new ToolCatalogResponse(RELEASE, "1.1", ARTIFACT, RELEASE_HASH, null, tools, null)}) {
            when(releases.toolCatalog(RELEASE, ACTOR)).thenReturn(source);
            assertFailure(SOURCE_BINDING_FAILURE, () -> evaluator.evaluate(RUN, CUSTOMER, json("{}"), ACTOR));
        }
    }

    @Test
    void rejectsInvalidRequestsBeforeSourceAccess() {
        assertFailure(INVALID_REQUEST, () -> evaluator.evaluate(null, CUSTOMER, json("{}"), ACTOR));
        for (String tool : new String[]{null, "", " customer_data_read ", "private-output-marker"}) {
            assertFailure(INVALID_REQUEST, () -> evaluator.evaluate(RUN, tool, json("{}"), ACTOR));
        }
        for (String actor : new String[]{null, "", " ", " reviewer:test "}) {
            assertFailure(INVALID_REQUEST, () -> evaluator.evaluate(RUN, CUSTOMER, json("{}"), actor));
        }
        verifyNoInteractions(runs, releases);
    }

    private void useSchema(JsonNode schema) {
        when(releases.toolCatalog(RELEASE, ACTOR)).thenReturn(catalog(JSON.createArrayNode().add(
                JSON.createObjectNode().put("name", CUSTOMER).set("outputSchema", schema))));
    }

    private static void assertFailure(FailureCode code, org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).isInstanceOfSatisfying(SchemaCheckException.class, exception -> {
            assertThat(exception.code()).isEqualTo(code);
            assertThat(exception.getMessage()).isEqualTo(code.name());
            assertThat(exception.getCause()).isNull();
            assertThat(exception.toString()).doesNotContain("private-output-marker");
        });
    }

    private static JsonNode changed(String tool, String field, String value) {
        return ((ObjectNode) json(OUTPUTS.get(tool))).set(field, json(value));
    }

    private static TestRunDto.Projection run(UUID id, UUID release, String artifact, String fingerprint) {
        return new TestRunDto.Projection(id, release, null, null, TestRunMode.BASELINE, TestRunStatus.RUNNING,
                artifact, fingerprint, null, null, 1, 0, 0, 0L, null, null, json("{}"),
                null, null, Instant.EPOCH);
    }

    private static ToolCatalogResponse catalog(JsonNode tools) {
        return new ToolCatalogResponse(RELEASE, "1.1", ARTIFACT, RELEASE_HASH, CATALOG_HASH,
                tools, LoanReviewToolCatalog.serverToolCatalog());
    }

    private static JsonNode json(String text) {
        return JSON.readTree(text);
    }

    private static String digest(char value) {
        return "sha256:" + String.valueOf(value).repeat(64);
    }
}
