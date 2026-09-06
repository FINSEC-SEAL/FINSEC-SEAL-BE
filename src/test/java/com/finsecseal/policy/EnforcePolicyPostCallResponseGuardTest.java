package com.finsecseal.policy;

import static com.finsecseal.common.domain.Sensitivity.CREDIT;
import static com.finsecseal.common.domain.Sensitivity.NORMAL;
import static com.finsecseal.policy.EnforcePolicyPostCallDecision.OperationalReason.ADAPTER_CONTRACT_FAILURE;
import static com.finsecseal.policy.EnforcePolicyPostCallDecision.OperationalReason.RESPONSE_CARDINALITY_VIOLATION;
import static com.finsecseal.policy.EnforcePolicyPostCallDecision.Outcome.PASS;
import static com.finsecseal.policy.EnforcePolicyPostCallDecision.Outcome.QUARANTINE;
import static com.finsecseal.policy.EnforcePolicyPostCallDecision.PostCallCheck.CLASSIFICATION;
import static com.finsecseal.policy.EnforcePolicyPostCallDecision.PostCallCheck.FIELD_PROJECTION;
import static com.finsecseal.policy.EnforcePolicyPostCallDecision.PostCallCheck.OBJECT_SCOPE;
import static com.finsecseal.policy.EnforcePolicyPostCallDecision.PostCallCheck.OUTPUT_SCHEMA;
import static com.finsecseal.policy.EnforcePolicyPostCallDecision.PostCallCheck.RETURNED_CARDINALITY;
import static com.finsecseal.policy.EnforcePolicyPostCallDecision.PostCallCheck.STATE_DELTA_PROVENANCE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.policy.EnforcePolicyPostCallDecision.OperationalReason;
import com.finsecseal.policy.EnforcePolicyPostCallDecision.PostCallCheck;
import com.finsecseal.policy.EnforcePolicyPostCallFacts.CatalogOutputField;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

class EnforcePolicyPostCallResponseGuardTest {

    private static final String CUSTOMER_DATA_READ = "CUSTOMER_DATA_READ";
    private static final String CURRENT_APPLICANT = "CUSTOMER-1001";
    private static final String OTHER_CUSTOMER = "CUSTOMER-2002";
    private static final String NAMESPACE_ID = "namespace-run-1001";
    private static final UUID CASE_RUN_ID = UUID.fromString(
            "12345678-1234-4abc-8def-1234567890ab"
    );
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private EnforcePolicyPostCallResponseGuard guard;

    @BeforeEach
    void setUp() {
        guard = new EnforcePolicyPostCallResponseGuard();
    }

    @Test
    void passesExactEmptyResponseAndEvaluatesCompleteOrder() {
        EnforcePolicyPostCallDecision decision = guard.evaluate(facts(
                emptyResponse(),
                exactClassifications(),
                null
        ));

        assertPassed(decision, emptyResponse());
    }

    @Test
    void passesExactSingleRowAtMaximumAndExactOptionalProvenance() {
        ObjectNode response = response(CURRENT_APPLICANT, "name", "Alice");

        EnforcePolicyPostCallDecision decision = guard.evaluate(facts(
                response,
                exactClassifications(),
                exactProvenance()
        ));

        assertPassed(decision, response);
    }

    @Test
    void snapshotsAllInputsAtConstructionAndDeepCopiesPassOutput() {
        ArrayList<String> customerIds = new ArrayList<>(List.of(CURRENT_APPLICANT));
        ArrayList<String> requestedFields = new ArrayList<>(List.of("name"));
        ArrayList<String> approvedProjection = new ArrayList<>(List.of("name"));
        ArrayList<CatalogOutputField> catalog = new ArrayList<>(catalog());
        ObjectNode response = response(CURRENT_APPLICANT, "name", "Alice");
        ObjectNode classifications = exactClassifications();
        ObjectNode provenance = exactProvenance();

        EnforcePolicyPostCallFacts facts = facts(
                CURRENT_APPLICANT,
                customerIds,
                requestedFields,
                approvedProjection,
                catalog,
                1,
                response,
                classifications,
                provenance
        );

        customerIds.add(OTHER_CUSTOMER);
        requestedFields.add("creditScore");
        approvedProjection.clear();
        catalog.clear();
        response.put("status", 500);
        classifications.put("name", "PII");
        provenance.put("namespaceId", "mutated");

        assertThat(facts.requestedCustomerIds()).containsExactly(CURRENT_APPLICANT);
        assertThat(facts.requestedFields()).containsExactly("name");
        assertThat(facts.approvedProjection()).containsExactly("name");
        assertThat(facts.catalogOutputFields()).hasSize(2);
        assertThat(facts.catalogClassifications()).containsEntry("name", NORMAL);
        assertThatThrownBy(() -> facts.catalogClassifications().put("extra", NORMAL))
                .isInstanceOf(UnsupportedOperationException.class);

        JsonNode firstFactsCopy = facts.adapterResponse();
        ((ObjectNode) firstFactsCopy).put("status", 503);
        assertThat(facts.adapterResponse().get("status").asInt()).isEqualTo(200);

        EnforcePolicyPostCallDecision decision = guard.evaluate(facts);
        assertThat(decision.outcome()).isEqualTo(PASS);
        JsonNode firstResultCopy = decision.deliverableOutput().orElseThrow();
        ((ObjectNode) firstResultCopy).put("status", 418);
        ((ObjectNode) firstResultCopy.at("/rows/0/fields")).put("name", "changed");

        JsonNode secondResultCopy = decision.deliverableOutput().orElseThrow();
        assertThat(secondResultCopy.get("status").asInt()).isEqualTo(200);
        assertThat(secondResultCopy.at("/rows/0/fields/name").asString())
                .isEqualTo("Alice");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("malformedResponses")
    void quarantinesMalformedOutputSchema(String ignored, JsonNode response) {
        EnforcePolicyPostCallDecision decision = guard.evaluate(facts(
                response,
                exactClassifications(),
                null
        ));

        assertQuarantined(
                decision,
                OUTPUT_SCHEMA,
                ADAPTER_CONTRACT_FAILURE,
                List.of(OUTPUT_SCHEMA)
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidClassificationMaps")
    void quarantinesMissingOrNonExactClassificationMap(
            String ignored,
            JsonNode classificationMap
    ) {
        EnforcePolicyPostCallDecision decision = guard.evaluate(facts(
                validResponse(),
                classificationMap,
                null
        ));

        assertQuarantined(
                decision,
                CLASSIFICATION,
                ADAPTER_CONTRACT_FAILURE,
                List.of(OUTPUT_SCHEMA, CLASSIFICATION)
        );
    }

    @Test
    void classificationCoverageIsAgainstTheCompleteCatalogEvenForEmptyRows() {
        ObjectNode incomplete = OBJECT_MAPPER.createObjectNode().put("name", "NORMAL");

        EnforcePolicyPostCallDecision decision = guard.evaluate(facts(
                emptyResponse(),
                incomplete,
                null
        ));

        assertQuarantined(
                decision,
                CLASSIFICATION,
                ADAPTER_CONTRACT_FAILURE,
                List.of(OUTPUT_SCHEMA, CLASSIFICATION)
        );
    }

    @Test
    void quarantinesReturnedCustomerThatWasNotRequested() {
        EnforcePolicyPostCallFacts facts = facts(
                CURRENT_APPLICANT,
                List.of(OTHER_CUSTOMER),
                List.of("name"),
                List.of("name"),
                catalog(),
                1,
                response(CURRENT_APPLICANT, "name", "Alice"),
                exactClassifications(),
                null
        );

        assertQuarantined(
                guard.evaluate(facts),
                OBJECT_SCOPE,
                ADAPTER_CONTRACT_FAILURE,
                List.of(OUTPUT_SCHEMA, CLASSIFICATION, OBJECT_SCOPE)
        );
    }

    @Test
    void quarantinesRequestedCustomerThatIsNotTheCurrentApplicant() {
        EnforcePolicyPostCallFacts facts = facts(
                CURRENT_APPLICANT,
                List.of(OTHER_CUSTOMER),
                List.of("name"),
                List.of("name"),
                catalog(),
                1,
                response(OTHER_CUSTOMER, "name", "Mallory"),
                exactClassifications(),
                null
        );

        assertQuarantined(
                guard.evaluate(facts),
                OBJECT_SCOPE,
                ADAPTER_CONTRACT_FAILURE,
                List.of(OUTPUT_SCHEMA, CLASSIFICATION, OBJECT_SCOPE)
        );
    }

    @ParameterizedTest
    @ValueSource(strings = {"customer-1001", "CUSTOMER-1001 ", " CUSTOMER-1001"})
    void customerIdentityComparisonIsExactAndNeverTrimmed(String returnedCustomerId) {
        EnforcePolicyPostCallDecision decision = guard.evaluate(facts(
                response(returnedCustomerId, "name", "Alice"),
                exactClassifications(),
                null
        ));

        assertQuarantined(
                decision,
                OBJECT_SCOPE,
                ADAPTER_CONTRACT_FAILURE,
                List.of(OUTPUT_SCHEMA, CLASSIFICATION, OBJECT_SCOPE)
        );
    }

    @Test
    void quarantinesCatalogFieldThatWasNotRequested() {
        EnforcePolicyPostCallFacts facts = facts(
                CURRENT_APPLICANT,
                List.of(CURRENT_APPLICANT),
                List.of("name"),
                List.of("name", "creditScore"),
                catalog(),
                1,
                response(CURRENT_APPLICANT, "creditScore", 720),
                exactClassifications(),
                null
        );

        assertQuarantined(
                guard.evaluate(facts),
                FIELD_PROJECTION,
                ADAPTER_CONTRACT_FAILURE,
                List.of(OUTPUT_SCHEMA, CLASSIFICATION, OBJECT_SCOPE, FIELD_PROJECTION)
        );
    }

    @Test
    void quarantinesRequestedFieldOutsideApprovedProjection() {
        EnforcePolicyPostCallFacts facts = facts(
                CURRENT_APPLICANT,
                List.of(CURRENT_APPLICANT),
                List.of("name", "creditScore"),
                List.of("name"),
                catalog(),
                1,
                response(CURRENT_APPLICANT, "creditScore", 720),
                exactClassifications(),
                null
        );

        assertQuarantined(
                guard.evaluate(facts),
                FIELD_PROJECTION,
                ADAPTER_CONTRACT_FAILURE,
                List.of(OUTPUT_SCHEMA, CLASSIFICATION, OBJECT_SCOPE, FIELD_PROJECTION)
        );
    }

    @ParameterizedTest
    @ValueSource(strings = {"Name", "name ", " name"})
    void catalogFieldComparisonIsExactAndUnknownVariantFailsAtSchema(String fieldName) {
        EnforcePolicyPostCallDecision decision = guard.evaluate(facts(
                response(CURRENT_APPLICANT, fieldName, "Alice"),
                exactClassifications(),
                null
        ));

        assertQuarantined(
                decision,
                OUTPUT_SCHEMA,
                ADAPTER_CONTRACT_FAILURE,
                List.of(OUTPUT_SCHEMA)
        );
    }

    @Test
    void passesWhenReturnedRowCountEqualsApprovedMaximum() {
        EnforcePolicyPostCallDecision decision = guard.evaluate(facts(
                validResponse(),
                exactClassifications(),
                null
        ));

        assertThat(decision.outcome()).isEqualTo(PASS);
    }

    @Test
    void quarantinesMaximumPlusOneRowsWithDedicatedOperationalReason() {
        EnforcePolicyPostCallFacts facts = facts(
                CURRENT_APPLICANT,
                List.of(CURRENT_APPLICANT),
                List.of("name"),
                List.of("name"),
                catalog(),
                1,
                repeatedValidRows(2),
                exactClassifications(),
                null
        );

        assertQuarantined(
                guard.evaluate(facts),
                RETURNED_CARDINALITY,
                RESPONSE_CARDINALITY_VIOLATION,
                List.of(
                        OUTPUT_SCHEMA,
                        CLASSIFICATION,
                        OBJECT_SCOPE,
                        FIELD_PROJECTION,
                        RETURNED_CARDINALITY
                )
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidProvenanceValues")
    void quarantinesIncompleteOrMismatchedStateDeltaProvenance(
            String ignored,
            JsonNode provenance
    ) {
        EnforcePolicyPostCallDecision decision = guard.evaluate(facts(
                validResponse(),
                exactClassifications(),
                provenance
        ));

        assertQuarantined(
                decision,
                STATE_DELTA_PROVENANCE,
                ADAPTER_CONTRACT_FAILURE,
                PostCallCheck.completeOrder()
        );
    }

    @Test
    void shortCircuitsAtClassificationBeforeLaterViolations() {
        EnforcePolicyPostCallFacts facts = facts(
                CURRENT_APPLICANT,
                List.of(CURRENT_APPLICANT),
                List.of("name"),
                List.of("name"),
                catalog(),
                1,
                repeatedRows(OTHER_CUSTOMER, "creditScore", 720, 2),
                OBJECT_MAPPER.createObjectNode(),
                wrongProvenance()
        );

        assertQuarantined(
                guard.evaluate(facts),
                CLASSIFICATION,
                ADAPTER_CONTRACT_FAILURE,
                List.of(OUTPUT_SCHEMA, CLASSIFICATION)
        );
    }

    @Test
    void shortCircuitsAtObjectScopeBeforeProjectionCardinalityAndProvenance() {
        EnforcePolicyPostCallFacts facts = facts(
                CURRENT_APPLICANT,
                List.of(CURRENT_APPLICANT),
                List.of("name"),
                List.of("name"),
                catalog(),
                1,
                repeatedRows(OTHER_CUSTOMER, "creditScore", 720, 2),
                exactClassifications(),
                wrongProvenance()
        );

        assertQuarantined(
                guard.evaluate(facts),
                OBJECT_SCOPE,
                ADAPTER_CONTRACT_FAILURE,
                List.of(OUTPUT_SCHEMA, CLASSIFICATION, OBJECT_SCOPE)
        );
    }

    @Test
    void shortCircuitsAtProjectionBeforeCardinalityAndProvenance() {
        EnforcePolicyPostCallFacts facts = facts(
                CURRENT_APPLICANT,
                List.of(CURRENT_APPLICANT),
                List.of("name"),
                List.of("name"),
                catalog(),
                1,
                repeatedRows(CURRENT_APPLICANT, "creditScore", 720, 2),
                exactClassifications(),
                wrongProvenance()
        );

        assertQuarantined(
                guard.evaluate(facts),
                FIELD_PROJECTION,
                ADAPTER_CONTRACT_FAILURE,
                List.of(OUTPUT_SCHEMA, CLASSIFICATION, OBJECT_SCOPE, FIELD_PROJECTION)
        );
    }

    @Test
    void shortCircuitsAtCardinalityBeforeProvenance() {
        EnforcePolicyPostCallFacts facts = facts(
                CURRENT_APPLICANT,
                List.of(CURRENT_APPLICANT),
                List.of("name"),
                List.of("name"),
                catalog(),
                1,
                repeatedValidRows(2),
                exactClassifications(),
                wrongProvenance()
        );

        assertQuarantined(
                guard.evaluate(facts),
                RETURNED_CARDINALITY,
                RESPONSE_CARDINALITY_VIOLATION,
                List.of(
                        OUTPUT_SCHEMA,
                        CLASSIFICATION,
                        OBJECT_SCOPE,
                        FIELD_PROJECTION,
                        RETURNED_CARDINALITY
                )
        );
    }

    @Test
    void repeatedEvaluationIsDeterministic() {
        EnforcePolicyPostCallFacts facts = facts(
                validResponse(),
                exactClassifications(),
                exactProvenance()
        );

        assertThat(guard.evaluate(facts)).isEqualTo(guard.evaluate(facts));
    }

    @Test
    void quarantineEvidenceNeverContainsRawAdapterValues() {
        String sensitiveValue = "RAW-SENSITIVE-ACCOUNT-VALUE";
        ObjectNode invalidClassifications = exactClassifications()
                .put("name", "PII");
        EnforcePolicyPostCallDecision decision = guard.evaluate(facts(
                response(CURRENT_APPLICANT, "name", sensitiveValue),
                invalidClassifications,
                null
        ));

        assertThat(decision.outcome()).isEqualTo(QUARANTINE);
        assertThat(decision.deliverableOutput()).isEmpty();
        assertThat(decision.toString()).doesNotContain(sensitiveValue);
    }

    @Test
    void rejectsNullGuardFactsAsCallerMisuse() {
        assertThatThrownBy(() -> guard.evaluate(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("facts must not be null");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "customer_data_read", "CUSTOMER_DATA_READ "})
    void rejectsNonExactSupportedTool(String requestedTool) {
        assertThatThrownBy(() -> new EnforcePolicyPostCallFacts(
                requestedTool,
                CURRENT_APPLICANT,
                List.of(CURRENT_APPLICANT),
                List.of("name"),
                List.of("name"),
                catalog(),
                1,
                NAMESPACE_ID,
                CASE_RUN_ID,
                validResponse(),
                exactClassifications(),
                null
        ))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsMalformedTrustedIdentityAndFieldCollections() {
        assertThatThrownBy(() -> factsWithCurrentApplicant(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("currentApplicantId must not be blank");
        assertThatThrownBy(() -> factsWithCurrentApplicant(" "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("currentApplicantId must not be blank");
        assertThatThrownBy(() -> factsWithCustomerIds(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("requestedCustomerIds must not be null");
        assertThatThrownBy(() -> factsWithCustomerIds(List.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("requestedCustomerIds must not be empty");
        assertThatThrownBy(() -> factsWithCustomerIds(listWithNull()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("requestedCustomerIds[0] must not be blank");
        assertThatThrownBy(() -> factsWithCustomerIds(List.of(" ")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("requestedCustomerIds[0] must not be blank");
        assertThatThrownBy(() -> factsWithCustomerIds(List.of(
                CURRENT_APPLICANT,
                CURRENT_APPLICANT
        )))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("requestedCustomerIds must not contain duplicate values");

        assertThatThrownBy(() -> factsWithRequestedFields(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("requestedFields must not be null");
        assertThatThrownBy(() -> factsWithRequestedFields(List.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("requestedFields must not be empty");
        assertThatThrownBy(() -> factsWithRequestedFields(List.of(" ")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("requestedFields[0] must not be blank");
        assertThatThrownBy(() -> factsWithRequestedFields(List.of("name", "name")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("requestedFields must not contain duplicate values");

        assertThatThrownBy(() -> factsWithApprovedProjection(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("approvedProjection must not be null");
        assertThatThrownBy(() -> factsWithApprovedProjection(List.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("approvedProjection must not be empty");
        assertThatThrownBy(() -> factsWithApprovedProjection(List.of("name", "name")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("approvedProjection must not contain duplicate values");
    }

    @Test
    void rejectsMalformedOrDuplicateTrustedCatalogEntries() {
        assertThatThrownBy(() -> factsWithCatalog(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogOutputFields must not be null");
        assertThatThrownBy(() -> factsWithCatalog(List.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogOutputFields must not be empty");

        ArrayList<CatalogOutputField> withNull = new ArrayList<>();
        withNull.add(null);
        assertThatThrownBy(() -> factsWithCatalog(withNull))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogOutputFields must not contain null entries");
        assertThatThrownBy(() -> factsWithCatalog(List.of(
                new CatalogOutputField("name", NORMAL),
                new CatalogOutputField("name", CREDIT)
        )))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogOutputFields must not contain duplicate field names");
        assertThatThrownBy(() -> new CatalogOutputField(null, NORMAL))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalog output field name must not be blank");
        assertThatThrownBy(() -> new CatalogOutputField(" ", NORMAL))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalog output field name must not be blank");
        assertThatThrownBy(() -> new CatalogOutputField("name", null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("catalog output field classification must not be null");
    }

    @Test
    void rejectsTrustedFieldReferencesOutsideExactCatalog() {
        assertThatThrownBy(() -> factsWithRequestedFields(List.of("Name")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("requestedFields must reference catalog fields");
        assertThatThrownBy(() -> factsWithRequestedFields(List.of("name ")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("requestedFields must reference catalog fields");
        assertThatThrownBy(() -> factsWithApprovedProjection(List.of("unknown")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("approvedProjection must reference catalog fields");
    }

    @Test
    void rejectsMalformedTrustedLimitsAndProvenanceExpectations() {
        assertThatThrownBy(() -> factsWithMaximum(0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("maxReturnedRecords must be greater than zero");
        assertThatThrownBy(() -> factsWithMaximum(-1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("maxReturnedRecords must be greater than zero");
        assertThatThrownBy(() -> factsWithExpectedNamespace(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("expectedNamespaceId must not be blank");
        assertThatThrownBy(() -> factsWithExpectedNamespace(" "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("expectedNamespaceId must not be blank");
        assertThatThrownBy(() -> factsWithExpectedCaseRun(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("expectedTestCaseRunId must not be null");
    }

    @Test
    void decisionInvariantsPreventOutputBearingQuarantineOrInvalidEvidence() {
        assertThatThrownBy(() -> new EnforcePolicyPostCallDecision(
                QUARANTINE,
                Optional.of(ADAPTER_CONTRACT_FAILURE),
                Optional.of(OUTPUT_SCHEMA),
                List.of(OUTPUT_SCHEMA),
                Optional.of(validResponse())
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("QUARANTINE must not contain deliverable output");

        assertThatThrownBy(() -> EnforcePolicyPostCallDecision.quarantine(
                RETURNED_CARDINALITY,
                ADAPTER_CONTRACT_FAILURE,
                List.of(
                        OUTPUT_SCHEMA,
                        CLASSIFICATION,
                        OBJECT_SCOPE,
                        FIELD_PROJECTION,
                        RETURNED_CARDINALITY
                )
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("reason is not valid for the failed check");

        assertThatThrownBy(() -> EnforcePolicyPostCallDecision.quarantine(
                OBJECT_SCOPE,
                ADAPTER_CONTRACT_FAILURE,
                List.of(OUTPUT_SCHEMA, OBJECT_SCOPE)
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("evaluated checks must follow the exact post-call sequence");
    }

    private static Stream<Arguments> malformedResponses() {
        ObjectNode extraEnvelopeField = validResponse().put("debug", true);
        ObjectNode missingStatus = OBJECT_MAPPER.createObjectNode();
        missingStatus.set("rows", OBJECT_MAPPER.createArrayNode());
        ObjectNode wrongStatus = validResponse().put("status", 201);
        ObjectNode floatingStatus = validResponse().put("status", 200.0);
        ObjectNode textualStatus = validResponse().put("status", "200");
        ObjectNode rowsObject = OBJECT_MAPPER.createObjectNode().put("status", 200);
        rowsObject.set("rows", OBJECT_MAPPER.createObjectNode());
        ObjectNode scalarRow = emptyResponse();
        ((ArrayNode) scalarRow.get("rows")).add("invalid");
        ObjectNode missingRowField = emptyResponse();
        ((ArrayNode) missingRowField.get("rows")).add(
                OBJECT_MAPPER.createObjectNode().put("customerId", CURRENT_APPLICANT)
        );
        ObjectNode extraRowField = validResponse();
        ((ObjectNode) extraRowField.at("/rows/0")).put("debug", true);
        ObjectNode blankCustomer = validResponse();
        ((ObjectNode) blankCustomer.at("/rows/0")).put("customerId", " ");
        ObjectNode numericCustomer = validResponse();
        ((ObjectNode) numericCustomer.at("/rows/0")).put("customerId", 1001);
        ObjectNode nonObjectFields = validResponse();
        ((ObjectNode) nonObjectFields.at("/rows/0")).set(
                "fields",
                OBJECT_MAPPER.createArrayNode()
        );
        ObjectNode unknownCatalogField = response(
                CURRENT_APPLICANT,
                "rawAccountNumber",
                "sensitive"
        );

        return Stream.of(
                Arguments.arguments("missing response", (JsonNode) null),
                Arguments.of("non-object response", OBJECT_MAPPER.createArrayNode()),
                Arguments.of("extra envelope field", extraEnvelopeField),
                Arguments.of("missing status", missingStatus),
                Arguments.of("non-success status", wrongStatus),
                Arguments.of("floating status", floatingStatus),
                Arguments.of("textual status", textualStatus),
                Arguments.of("rows is not an array", rowsObject),
                Arguments.of("row is not an object", scalarRow),
                Arguments.of("row field missing", missingRowField),
                Arguments.of("row field extra", extraRowField),
                Arguments.of("blank customer", blankCustomer),
                Arguments.of("non-text customer", numericCustomer),
                Arguments.of("fields is not an object", nonObjectFields),
                Arguments.of("field is absent from catalog", unknownCatalogField)
        );
    }

    private static Stream<Arguments> invalidClassificationMaps() {
        ObjectNode missingField = exactClassifications();
        missingField.remove("creditScore");
        ObjectNode extraField = exactClassifications().put("ssn", "SENSITIVE_PII");
        ObjectNode wrongValue = exactClassifications().put("name", "PII");
        ObjectNode caseVariantValue = exactClassifications().put("name", "normal");
        ObjectNode caseVariantKey = OBJECT_MAPPER.createObjectNode()
                .put("Name", "NORMAL")
                .put("creditScore", "CREDIT");
        ObjectNode nonTextValue = exactClassifications().put("name", 1);

        return Stream.of(
                Arguments.arguments("missing map", (JsonNode) null),
                Arguments.of("non-object map", OBJECT_MAPPER.createArrayNode()),
                Arguments.of("missing catalog field", missingField),
                Arguments.of("extra catalog field", extraField),
                Arguments.of("wrong classification", wrongValue),
                Arguments.of("classification case variant", caseVariantValue),
                Arguments.of("field-name case variant", caseVariantKey),
                Arguments.of("non-text classification", nonTextValue)
        );
    }

    private static Stream<Arguments> invalidProvenanceValues() {
        ObjectNode missingNamespace = OBJECT_MAPPER.createObjectNode()
                .put("testCaseRunId", CASE_RUN_ID.toString());
        ObjectNode missingCaseRun = OBJECT_MAPPER.createObjectNode()
                .put("namespaceId", NAMESPACE_ID);
        ObjectNode extraField = exactProvenance().put("runId", "unexpected");
        ObjectNode blankNamespace = exactProvenance().put("namespaceId", " ");
        ObjectNode blankCaseRun = exactProvenance().put("testCaseRunId", " ");
        ObjectNode wrongNamespace = exactProvenance().put("namespaceId", "other");
        ObjectNode namespaceCaseVariant = exactProvenance()
                .put("namespaceId", NAMESPACE_ID.toUpperCase());
        ObjectNode wrongCaseRun = exactProvenance().put(
                "testCaseRunId",
                "87654321-4321-4abc-8def-ba0987654321"
        );
        ObjectNode caseRunCaseVariant = exactProvenance().put(
                "testCaseRunId",
                CASE_RUN_ID.toString().toUpperCase()
        );
        ObjectNode nonTextNamespace = exactProvenance().put("namespaceId", 1);
        ObjectNode nonTextCaseRun = exactProvenance().put("testCaseRunId", 1);

        return Stream.of(
                Arguments.of("JSON null", OBJECT_MAPPER.nullNode()),
                Arguments.of("empty object", OBJECT_MAPPER.createObjectNode()),
                Arguments.of("missing namespace", missingNamespace),
                Arguments.of("missing case run", missingCaseRun),
                Arguments.of("extra field", extraField),
                Arguments.of("blank namespace", blankNamespace),
                Arguments.of("blank case run", blankCaseRun),
                Arguments.of("wrong namespace", wrongNamespace),
                Arguments.of("namespace case variant", namespaceCaseVariant),
                Arguments.of("wrong case run", wrongCaseRun),
                Arguments.of("case-run case variant", caseRunCaseVariant),
                Arguments.of("non-text namespace", nonTextNamespace),
                Arguments.of("non-text case run", nonTextCaseRun)
        );
    }

    private static EnforcePolicyPostCallFacts facts(
            JsonNode response,
            JsonNode classifications,
            JsonNode provenance
    ) {
        return facts(
                CURRENT_APPLICANT,
                List.of(CURRENT_APPLICANT),
                List.of("name"),
                List.of("name"),
                catalog(),
                1,
                response,
                classifications,
                provenance
        );
    }

    private static EnforcePolicyPostCallFacts facts(
            String currentApplicant,
            List<String> customerIds,
            List<String> requestedFields,
            List<String> approvedProjection,
            List<CatalogOutputField> catalog,
            int maximum,
            JsonNode response,
            JsonNode classifications,
            JsonNode provenance
    ) {
        return new EnforcePolicyPostCallFacts(
                CUSTOMER_DATA_READ,
                currentApplicant,
                customerIds,
                requestedFields,
                approvedProjection,
                catalog,
                maximum,
                NAMESPACE_ID,
                CASE_RUN_ID,
                response,
                classifications,
                provenance
        );
    }

    private static EnforcePolicyPostCallFacts factsWithCurrentApplicant(String value) {
        return facts(
                value,
                List.of(CURRENT_APPLICANT),
                List.of("name"),
                List.of("name"),
                catalog(),
                1,
                validResponse(),
                exactClassifications(),
                null
        );
    }

    private static EnforcePolicyPostCallFacts factsWithCustomerIds(List<String> values) {
        return facts(
                CURRENT_APPLICANT,
                values,
                List.of("name"),
                List.of("name"),
                catalog(),
                1,
                validResponse(),
                exactClassifications(),
                null
        );
    }

    private static EnforcePolicyPostCallFacts factsWithRequestedFields(List<String> values) {
        return facts(
                CURRENT_APPLICANT,
                List.of(CURRENT_APPLICANT),
                values,
                List.of("name"),
                catalog(),
                1,
                validResponse(),
                exactClassifications(),
                null
        );
    }

    private static EnforcePolicyPostCallFacts factsWithApprovedProjection(
            List<String> values
    ) {
        return facts(
                CURRENT_APPLICANT,
                List.of(CURRENT_APPLICANT),
                List.of("name"),
                values,
                catalog(),
                1,
                validResponse(),
                exactClassifications(),
                null
        );
    }

    private static EnforcePolicyPostCallFacts factsWithCatalog(
            List<CatalogOutputField> values
    ) {
        return facts(
                CURRENT_APPLICANT,
                List.of(CURRENT_APPLICANT),
                List.of("name"),
                List.of("name"),
                values,
                1,
                validResponse(),
                exactClassifications(),
                null
        );
    }

    private static EnforcePolicyPostCallFacts factsWithMaximum(int value) {
        return facts(
                CURRENT_APPLICANT,
                List.of(CURRENT_APPLICANT),
                List.of("name"),
                List.of("name"),
                catalog(),
                value,
                validResponse(),
                exactClassifications(),
                null
        );
    }

    private static EnforcePolicyPostCallFacts factsWithExpectedNamespace(String value) {
        return new EnforcePolicyPostCallFacts(
                CUSTOMER_DATA_READ,
                CURRENT_APPLICANT,
                List.of(CURRENT_APPLICANT),
                List.of("name"),
                List.of("name"),
                catalog(),
                1,
                value,
                CASE_RUN_ID,
                validResponse(),
                exactClassifications(),
                null
        );
    }

    private static EnforcePolicyPostCallFacts factsWithExpectedCaseRun(UUID value) {
        return new EnforcePolicyPostCallFacts(
                CUSTOMER_DATA_READ,
                CURRENT_APPLICANT,
                List.of(CURRENT_APPLICANT),
                List.of("name"),
                List.of("name"),
                catalog(),
                1,
                NAMESPACE_ID,
                value,
                validResponse(),
                exactClassifications(),
                null
        );
    }

    private static List<String> listWithNull() {
        ArrayList<String> values = new ArrayList<>();
        values.add(null);
        return values;
    }

    private static List<CatalogOutputField> catalog() {
        return List.of(
                new CatalogOutputField("name", NORMAL),
                new CatalogOutputField("creditScore", CREDIT)
        );
    }

    private static ObjectNode exactClassifications() {
        return OBJECT_MAPPER.createObjectNode()
                .put("name", "NORMAL")
                .put("creditScore", "CREDIT");
    }

    private static ObjectNode exactProvenance() {
        return OBJECT_MAPPER.createObjectNode()
                .put("namespaceId", NAMESPACE_ID)
                .put("testCaseRunId", CASE_RUN_ID.toString());
    }

    private static ObjectNode wrongProvenance() {
        return exactProvenance().put("namespaceId", "other-namespace");
    }

    private static ObjectNode emptyResponse() {
        ObjectNode response = OBJECT_MAPPER.createObjectNode().put("status", 200);
        response.set("rows", OBJECT_MAPPER.createArrayNode());
        return response;
    }

    private static ObjectNode validResponse() {
        return response(CURRENT_APPLICANT, "name", "Alice");
    }

    private static ObjectNode response(
            String customerId,
            String fieldName,
            String value
    ) {
        ObjectNode response = emptyResponse();
        ObjectNode row = ((ArrayNode) response.get("rows")).addObject();
        row.put("customerId", customerId);
        row.putObject("fields").put(fieldName, value);
        return response;
    }

    private static ObjectNode response(
            String customerId,
            String fieldName,
            int value
    ) {
        ObjectNode response = emptyResponse();
        ObjectNode row = ((ArrayNode) response.get("rows")).addObject();
        row.put("customerId", customerId);
        row.putObject("fields").put(fieldName, value);
        return response;
    }

    private static ObjectNode repeatedValidRows(int count) {
        return repeatedRows(CURRENT_APPLICANT, "name", "Alice", count);
    }

    private static ObjectNode repeatedRows(
            String customerId,
            String fieldName,
            String value,
            int count
    ) {
        ObjectNode response = emptyResponse();
        ArrayNode rows = (ArrayNode) response.get("rows");
        for (int index = 0; index < count; index++) {
            ObjectNode row = rows.addObject();
            row.put("customerId", customerId);
            row.putObject("fields").put(fieldName, value);
        }
        return response;
    }

    private static ObjectNode repeatedRows(
            String customerId,
            String fieldName,
            int value,
            int count
    ) {
        ObjectNode response = emptyResponse();
        ArrayNode rows = (ArrayNode) response.get("rows");
        for (int index = 0; index < count; index++) {
            ObjectNode row = rows.addObject();
            row.put("customerId", customerId);
            row.putObject("fields").put(fieldName, value);
        }
        return response;
    }

    private static void assertPassed(
            EnforcePolicyPostCallDecision decision,
            JsonNode expectedOutput
    ) {
        assertThat(decision.outcome()).isEqualTo(PASS);
        assertThat(decision.reason()).isEmpty();
        assertThat(decision.failedCheck()).isEmpty();
        assertThat(decision.evaluatedChecks()).containsExactlyElementsOf(
                PostCallCheck.completeOrder()
        );
        assertThat(decision.deliverableOutput()).contains(expectedOutput);
        assertThat(decision.operationalFailure()).isFalse();
        assertThat(decision.successfulSecurityBlock()).isFalse();
    }

    private static void assertQuarantined(
            EnforcePolicyPostCallDecision decision,
            PostCallCheck failedCheck,
            OperationalReason reason,
            List<PostCallCheck> evaluatedChecks
    ) {
        assertThat(decision.outcome()).isEqualTo(QUARANTINE);
        assertThat(decision.reason()).contains(reason);
        assertThat(decision.failedCheck()).contains(failedCheck);
        assertThat(decision.evaluatedChecks()).containsExactlyElementsOf(evaluatedChecks);
        assertThat(decision.deliverableOutput()).isEmpty();
        assertThat(decision.operationalFailure()).isTrue();
        assertThat(decision.successfulSecurityBlock()).isFalse();
    }
}
