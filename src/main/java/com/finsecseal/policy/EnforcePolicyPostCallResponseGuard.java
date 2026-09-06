package com.finsecseal.policy;

import static com.finsecseal.policy.EnforcePolicyPostCallDecision.OperationalReason.ADAPTER_CONTRACT_FAILURE;
import static com.finsecseal.policy.EnforcePolicyPostCallDecision.OperationalReason.RESPONSE_CARDINALITY_VIOLATION;
import static com.finsecseal.policy.EnforcePolicyPostCallDecision.PostCallCheck.CLASSIFICATION;
import static com.finsecseal.policy.EnforcePolicyPostCallDecision.PostCallCheck.FIELD_PROJECTION;
import static com.finsecseal.policy.EnforcePolicyPostCallDecision.PostCallCheck.OBJECT_SCOPE;
import static com.finsecseal.policy.EnforcePolicyPostCallDecision.PostCallCheck.OUTPUT_SCHEMA;
import static com.finsecseal.policy.EnforcePolicyPostCallDecision.PostCallCheck.RETURNED_CARDINALITY;
import static com.finsecseal.policy.EnforcePolicyPostCallDecision.PostCallCheck.STATE_DELTA_PROVENANCE;

import com.finsecseal.common.domain.Sensitivity;
import com.finsecseal.policy.EnforcePolicyPostCallDecision.OperationalReason;
import com.finsecseal.policy.EnforcePolicyPostCallDecision.PostCallCheck;
import com.finsecseal.policy.EnforcePolicyPostCallFacts.CatalogOutputField;
import com.finsecseal.policy.EnforcePolicyPostCallFacts.OutputValueType;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import tools.jackson.databind.JsonNode;

/**
 * Pure ENFORCE-only post-call guard for CUSTOMER_DATA_READ adapter results.
 *
 * <p>This supporting core does not invoke an adapter, deliver a response, or
 * persist incident evidence. Runtime integration must keep quarantined output
 * away from the Agent.</p>
 */
public final class EnforcePolicyPostCallResponseGuard {

    private static final Set<String> RESPONSE_FIELDS = Set.of("status", "rows");
    private static final Set<String> ROW_FIELDS = Set.of("customerId", "fields");
    private static final Set<String> PROVENANCE_FIELDS = Set.of(
            "namespaceId",
            "testCaseRunId"
    );
    private static final BigInteger SUCCESS_STATUS = BigInteger.valueOf(200);

    public EnforcePolicyPostCallDecision evaluate(EnforcePolicyPostCallFacts facts) {
        Objects.requireNonNull(facts, "facts must not be null");

        JsonNode response = facts.adapterResponse();
        JsonNode classificationMap = facts.adapterClassificationMap();
        Optional<JsonNode> stateDeltaProvenance = facts.adapterStateDeltaProvenance();
        List<PostCallCheck> evaluated = new ArrayList<>();

        evaluated.add(OUTPUT_SCHEMA);
        if (!hasValidOutputSchema(response, facts.catalogOutputFields())) {
            return quarantine(OUTPUT_SCHEMA, ADAPTER_CONTRACT_FAILURE, evaluated);
        }

        evaluated.add(CLASSIFICATION);
        if (!hasExactClassifications(
                classificationMap,
                facts.catalogClassifications()
        )) {
            return quarantine(CLASSIFICATION, ADAPTER_CONTRACT_FAILURE, evaluated);
        }

        evaluated.add(OBJECT_SCOPE);
        if (!hasAllowedCustomers(
                response,
                facts.requestedCustomerIds(),
                facts.currentApplicantId()
        )) {
            return quarantine(OBJECT_SCOPE, ADAPTER_CONTRACT_FAILURE, evaluated);
        }

        evaluated.add(FIELD_PROJECTION);
        if (!hasAllowedProjection(
                response,
                facts.requestedFields(),
                facts.approvedProjection()
        )) {
            return quarantine(FIELD_PROJECTION, ADAPTER_CONTRACT_FAILURE, evaluated);
        }

        evaluated.add(RETURNED_CARDINALITY);
        if (response.get("rows").size() > facts.maxReturnedRecords()) {
            return quarantine(
                    RETURNED_CARDINALITY,
                    RESPONSE_CARDINALITY_VIOLATION,
                    evaluated
            );
        }

        evaluated.add(STATE_DELTA_PROVENANCE);
        if (!hasValidStateDeltaProvenance(stateDeltaProvenance, facts)) {
            return quarantine(
                    STATE_DELTA_PROVENANCE,
                    ADAPTER_CONTRACT_FAILURE,
                    evaluated
            );
        }

        return EnforcePolicyPostCallDecision.pass(response);
    }

    private static boolean hasValidOutputSchema(
            JsonNode response,
            List<CatalogOutputField> catalogFields
    ) {
        if (!hasExactObjectFields(response, RESPONSE_FIELDS)) {
            return false;
        }

        JsonNode status = response.get("status");
        if (status == null
                || !status.isIntegralNumber()
                || !SUCCESS_STATUS.equals(status.bigIntegerValue())) {
            return false;
        }

        JsonNode rows = response.get("rows");
        if (rows == null || !rows.isArray()) {
            return false;
        }

        Map<String, OutputValueType> valueTypes = new HashMap<>();
        for (CatalogOutputField field : catalogFields) {
            valueTypes.put(field.fieldName(), field.valueType());
        }

        for (JsonNode row : rows) {
            if (!hasExactObjectFields(row, ROW_FIELDS)) {
                return false;
            }

            JsonNode customerId = row.get("customerId");
            JsonNode fields = row.get("fields");
            if (customerId == null
                    || !customerId.isString()
                    || customerId.asString().isBlank()
                    || fields == null
                    || !fields.isObject()) {
                return false;
            }

            for (Map.Entry<String, JsonNode> field : fields.properties()) {
                OutputValueType expectedType = valueTypes.get(field.getKey());
                if (expectedType == null || !hasExpectedType(field.getValue(), expectedType)) {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean hasExpectedType(JsonNode value, OutputValueType expectedType) {
        if (value == null) {
            return false;
        }
        return switch (expectedType) {
            case STRING -> value.isString();
            case INTEGER -> value.isIntegralNumber();
        };
    }

    private static boolean hasExactClassifications(
            JsonNode classificationMap,
            Map<String, Sensitivity> expected
    ) {
        if (!hasExactObjectFields(classificationMap, expected.keySet())) {
            return false;
        }

        for (Map.Entry<String, Sensitivity> expectedEntry : expected.entrySet()) {
            JsonNode actualClassification = classificationMap.get(expectedEntry.getKey());
            if (actualClassification == null
                    || !actualClassification.isString()
                    || !expectedEntry.getValue().name().equals(
                            actualClassification.asString()
                    )) {
                return false;
            }
        }
        return true;
    }

    private static boolean hasAllowedCustomers(
            JsonNode response,
            List<String> requestedCustomerIds,
            String currentApplicantId
    ) {
        Set<String> requested = Set.copyOf(requestedCustomerIds);
        for (JsonNode row : response.get("rows")) {
            String returnedCustomerId = row.get("customerId").asString();
            if (!requested.contains(returnedCustomerId)
                    || !currentApplicantId.equals(returnedCustomerId)) {
                return false;
            }
        }
        return true;
    }

    private static boolean hasAllowedProjection(
            JsonNode response,
            List<String> requestedFields,
            List<String> approvedProjection
    ) {
        Set<String> requested = Set.copyOf(requestedFields);
        Set<String> approved = Set.copyOf(approvedProjection);
        for (JsonNode row : response.get("rows")) {
            for (Map.Entry<String, JsonNode> field : row.get("fields").properties()) {
                if (!requested.contains(field.getKey())
                        || !approved.contains(field.getKey())) {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean hasValidStateDeltaProvenance(
            Optional<JsonNode> provenance,
            EnforcePolicyPostCallFacts facts
    ) {
        if (provenance.isEmpty()) {
            return true;
        }

        JsonNode value = provenance.orElseThrow();
        if (!hasExactObjectFields(value, PROVENANCE_FIELDS)) {
            return false;
        }

        JsonNode namespaceId = value.get("namespaceId");
        JsonNode testCaseRunId = value.get("testCaseRunId");
        return namespaceId != null
                && namespaceId.isString()
                && !namespaceId.asString().isBlank()
                && facts.expectedNamespaceId().equals(namespaceId.asString())
                && testCaseRunId != null
                && testCaseRunId.isString()
                && !testCaseRunId.asString().isBlank()
                && facts.expectedTestCaseRunId().toString().equals(
                        testCaseRunId.asString()
                );
    }

    private static boolean hasExactObjectFields(JsonNode node, Set<String> expected) {
        if (node == null || !node.isObject() || node.size() != expected.size()) {
            return false;
        }

        Set<String> actual = new HashSet<>();
        for (Map.Entry<String, JsonNode> entry : node.properties()) {
            actual.add(entry.getKey());
        }
        return actual.equals(expected);
    }

    private static EnforcePolicyPostCallDecision quarantine(
            PostCallCheck failedCheck,
            OperationalReason reason,
            List<PostCallCheck> evaluated
    ) {
        return EnforcePolicyPostCallDecision.quarantine(
                failedCheck,
                reason,
                List.copyOf(evaluated)
        );
    }
}
