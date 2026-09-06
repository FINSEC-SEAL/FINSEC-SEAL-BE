package com.finsecseal.policy;

import com.finsecseal.common.domain.Sensitivity;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

/**
 * Immutable server-constructed facts for the ENFORCE-only CUSTOMER_DATA_READ
 * post-call boundary.
 *
 * <p>The response, classification map, and optional state-delta provenance are
 * untrusted adapter values. They are deliberately accepted as raw JSON so the
 * response guard can quarantine malformed values instead of treating them as
 * trusted construction failures.</p>
 */
public final class EnforcePolicyPostCallFacts {

    public static final String SUPPORTED_TOOL = "CUSTOMER_DATA_READ";

    private final String requestedTool;
    private final String currentApplicantId;
    private final List<String> requestedCustomerIds;
    private final List<String> requestedFields;
    private final List<String> approvedProjection;
    private final List<CatalogOutputField> catalogOutputFields;
    private final Map<String, Sensitivity> catalogClassifications;
    private final int maxReturnedRecords;
    private final String expectedNamespaceId;
    private final UUID expectedTestCaseRunId;
    private final JsonNode adapterResponse;
    private final JsonNode adapterClassificationMap;
    private final JsonNode adapterStateDeltaProvenance;

    public EnforcePolicyPostCallFacts(
            String requestedTool,
            String currentApplicantId,
            List<String> requestedCustomerIds,
            List<String> requestedFields,
            List<String> approvedProjection,
            List<CatalogOutputField> catalogOutputFields,
            int maxReturnedRecords,
            String expectedNamespaceId,
            UUID expectedTestCaseRunId,
            JsonNode adapterResponse,
            JsonNode adapterClassificationMap,
            JsonNode adapterStateDeltaProvenance
    ) {
        this.requestedTool = requireNonBlank(requestedTool, "requestedTool");
        if (!SUPPORTED_TOOL.equals(this.requestedTool)) {
            throw new IllegalArgumentException(
                    "requestedTool must exactly equal " + SUPPORTED_TOOL
            );
        }

        this.currentApplicantId = requireNonBlank(
                currentApplicantId,
                "currentApplicantId"
        );
        this.requestedCustomerIds = copyUniqueNonEmptyStrings(
                requestedCustomerIds,
                "requestedCustomerIds"
        );
        this.requestedFields = copyUniqueNonEmptyStrings(
                requestedFields,
                "requestedFields"
        );
        this.approvedProjection = copyUniqueNonEmptyStrings(
                approvedProjection,
                "approvedProjection"
        );
        this.catalogOutputFields = copyCatalogOutputFields(catalogOutputFields);
        this.catalogClassifications = classificationsByField(this.catalogOutputFields);
        validateCatalogReferences(this.requestedFields, "requestedFields");
        validateCatalogReferences(this.approvedProjection, "approvedProjection");

        if (maxReturnedRecords <= 0) {
            throw new IllegalArgumentException(
                    "maxReturnedRecords must be greater than zero"
            );
        }
        this.maxReturnedRecords = maxReturnedRecords;
        this.expectedNamespaceId = requireNonBlank(
                expectedNamespaceId,
                "expectedNamespaceId"
        );
        this.expectedTestCaseRunId = Objects.requireNonNull(
                expectedTestCaseRunId,
                "expectedTestCaseRunId must not be null"
        );

        this.adapterResponse = snapshot(adapterResponse);
        this.adapterClassificationMap = snapshot(adapterClassificationMap);
        this.adapterStateDeltaProvenance = snapshot(adapterStateDeltaProvenance);
    }

    public String requestedTool() {
        return requestedTool;
    }

    public String currentApplicantId() {
        return currentApplicantId;
    }

    public List<String> requestedCustomerIds() {
        return requestedCustomerIds;
    }

    public List<String> requestedFields() {
        return requestedFields;
    }

    public List<String> approvedProjection() {
        return approvedProjection;
    }

    public List<CatalogOutputField> catalogOutputFields() {
        return catalogOutputFields;
    }

    public Map<String, Sensitivity> catalogClassifications() {
        return catalogClassifications;
    }

    public int maxReturnedRecords() {
        return maxReturnedRecords;
    }

    public String expectedNamespaceId() {
        return expectedNamespaceId;
    }

    public UUID expectedTestCaseRunId() {
        return expectedTestCaseRunId;
    }

    public JsonNode adapterResponse() {
        return snapshot(adapterResponse);
    }

    public JsonNode adapterClassificationMap() {
        return snapshot(adapterClassificationMap);
    }

    public Optional<JsonNode> adapterStateDeltaProvenance() {
        return Optional.ofNullable(snapshot(adapterStateDeltaProvenance));
    }

    private void validateCatalogReferences(List<String> fields, String fieldName) {
        Set<String> catalogNames = catalogClassifications.keySet();
        if (!catalogNames.containsAll(fields)) {
            throw new IllegalArgumentException(fieldName + " must reference catalog fields");
        }
    }

    private static List<String> copyUniqueNonEmptyStrings(
            List<String> values,
            String fieldName
    ) {
        if (values == null) {
            throw new IllegalArgumentException(fieldName + " must not be null");
        }
        if (values.isEmpty()) {
            throw new IllegalArgumentException(fieldName + " must not be empty");
        }

        Set<String> unique = new HashSet<>();
        for (int index = 0; index < values.size(); index++) {
            String value = requireNonBlank(
                    values.get(index),
                    fieldName + "[" + index + "]"
            );
            if (!unique.add(value)) {
                throw new IllegalArgumentException(
                        fieldName + " must not contain duplicate values"
                );
            }
        }
        return List.copyOf(values);
    }

    private static List<CatalogOutputField> copyCatalogOutputFields(
            List<CatalogOutputField> values
    ) {
        if (values == null) {
            throw new IllegalArgumentException("catalogOutputFields must not be null");
        }
        if (values.isEmpty()) {
            throw new IllegalArgumentException("catalogOutputFields must not be empty");
        }

        Set<String> unique = new HashSet<>();
        for (CatalogOutputField value : values) {
            if (value == null) {
                throw new IllegalArgumentException(
                        "catalogOutputFields must not contain null entries"
                );
            }
            if (!unique.add(value.fieldName())) {
                throw new IllegalArgumentException(
                        "catalogOutputFields must not contain duplicate field names"
                );
            }
        }
        return List.copyOf(values);
    }

    private static Map<String, Sensitivity> classificationsByField(
            List<CatalogOutputField> fields
    ) {
        Map<String, Sensitivity> classifications = new LinkedHashMap<>();
        for (CatalogOutputField field : fields) {
            classifications.put(field.fieldName(), field.classification());
        }
        return Collections.unmodifiableMap(classifications);
    }

    private static String requireNonBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }

    private static JsonNode snapshot(JsonNode value) {
        return value == null ? null : value.deepCopy();
    }

    /** Exact scalar type resolved from the authoritative catalog, never inferred from output. */
    public enum OutputValueType {
        STRING,
        INTEGER
    }

    public record CatalogOutputField(
            String fieldName,
            Sensitivity classification,
            OutputValueType valueType
    ) {

        public CatalogOutputField {
            fieldName = requireNonBlank(fieldName, "catalog output field name");
            Objects.requireNonNull(
                    classification,
                    "catalog output field classification must not be null"
            );
            Objects.requireNonNull(valueType, "catalog output field type must not be null");
        }
    }
}
