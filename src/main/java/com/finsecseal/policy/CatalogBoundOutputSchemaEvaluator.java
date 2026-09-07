package com.finsecseal.policy;

import com.finsecseal.evidence.TestRunDto;
import com.finsecseal.evidence.TestRunProjectionService;
import com.finsecseal.release.LoanReviewToolCatalog;
import com.finsecseal.release.ReleaseDto.ToolCatalogResponse;
import com.finsecseal.release.ReleaseService;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SchemaValidatorsConfig;
import com.networknt.schema.SpecVersion;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.net.URI;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.regex.Pattern;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * Applies the run-bound, verified Release output schema before further post-call checks.
 * MATCH proves only JSON Schema conformance, never policy permission or safe model delivery.
 * Caller authorization, contract approval, scope, classification and provenance remain separate.
 */
public final class CatalogBoundOutputSchemaEvaluator {

    private static final String DIALECT = "https://json-schema.org/draft/2020-12/schema";
    private static final Pattern DIGEST = Pattern.compile("sha256:[0-9a-f]{64}");
    private static final Pattern TOOL = Pattern.compile("[A-Z][A-Z0-9_]{1,99}");
    private static final Set<String> JSON_TYPES = Set.of(
            "null", "boolean", "object", "array", "number", "string", "integer"
    );
        private static final Set<String> SUPPORTED_FORMATS = Set.of(
            "date-time", "date", "time", "duration", "email", "idn-email", "hostname",
            "idn-hostname", "ipv4", "ipv6", "uri", "uri-reference", "iri", "iri-reference",
            "uuid", "regex", "json-pointer", "relative-json-pointer"
        );
        private static final Set<String> LOAN_REVIEW_TOOLS = Set.of(
            "CASE_CONTEXT_READ", "DOCUMENT_READER", "CUSTOMER_DATA_READ", "LOAN_POLICY_SEARCH", "REVIEW_NOTE_WRITE"
        );
    private static final com.fasterxml.jackson.databind.ObjectMapper NETWORKNT_MAPPER =
            new com.fasterxml.jackson.databind.ObjectMapper();

    private final TestRunProjectionService runs;
    private final ReleaseService releases;
    private final JsonSchemaFactory outputFactory;
    private final SchemaValidatorsConfig validatorsConfig;

    public CatalogBoundOutputSchemaEvaluator(TestRunProjectionService runs, ReleaseService releases) {
        this.runs = Objects.requireNonNull(runs);
        this.releases = Objects.requireNonNull(releases);
        try {
            validatorsConfig = new SchemaValidatorsConfig();
            validatorsConfig.setTypeLoose(false);
            validatorsConfig.setFailFast(true);
            validatorsConfig.setLosslessNarrowing(false);
            outputFactory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012);
        } catch (RuntimeException exception) {
            throw failure(FailureCode.SCHEMA_ENGINE_FAILURE);
        }
    }

    public OutputSchemaCheck evaluate(UUID runId, String requestedTool, JsonNode adapterOutput, String actorId) {
        if (runId == null || requestedTool == null || !TOOL.matcher(requestedTool).matches()
                || actorId == null || actorId.isBlank() || !actorId.equals(actorId.strip())) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
        TestRunDto.Projection run;
        try {
            run = runs.find(runId);
        } catch (RuntimeException exception) {
            throw failure(FailureCode.SOURCE_LOAD_FAILURE);
        }
        if (run == null || !runId.equals(run.id()) || run.releaseId() == null
                || !isDigest(run.agentArtifactFingerprint()) || !isDigest(run.releaseFingerprint())) {
            throw failure(FailureCode.SOURCE_BINDING_FAILURE);
        }
        ToolCatalogResponse catalog;
        try {
            catalog = releases.toolCatalog(run.releaseId(), actorId);
        } catch (RuntimeException exception) {
            throw failure(FailureCode.SOURCE_LOAD_FAILURE);
        }
        if (catalog == null || !run.releaseId().equals(catalog.releaseId())
                || !LoanReviewToolCatalog.MANIFEST_VERSION.equals(catalog.manifestSchemaVersion())
                || !run.agentArtifactFingerprint().equals(catalog.agentArtifactFingerprint())
                || !run.releaseFingerprint().equals(catalog.releaseFingerprint())
                || !isDigest(catalog.serverToolCatalogHash())) {
            throw failure(FailureCode.SOURCE_BINDING_FAILURE);
        }
        var binding = new SourceBinding(runId, catalog.releaseId(), requestedTool,
                catalog.manifestSchemaVersion(), catalog.agentArtifactFingerprint(),
                catalog.releaseFingerprint(), catalog.serverToolCatalogHash());
        JsonNode schemaNode = findOutputSchema(catalog.tools(), requestedTool);
        if (schemaNode == null || schemaNode.isNull()) {
            return new OutputSchemaCheck(binding, Outcome.ADAPTER_CONTRACT_FAILURE);
        }
        if (containsUnsupportedFormat(schemaNode)) {
            return new OutputSchemaCheck(binding, Outcome.ADAPTER_CONTRACT_FAILURE);
        }
        JsonSchema schema = compile(schemaNode);
        if (!isJsonValue(adapterOutput)) {
            return new OutputSchemaCheck(binding, Outcome.ADAPTER_CONTRACT_FAILURE);
        }
        com.fasterxml.jackson.databind.JsonNode networkntOutput;
        try {
            networkntOutput = toNetworkntNode(adapterOutput);
        } catch (SchemaCheckException exception) {
            return new OutputSchemaCheck(binding, Outcome.ADAPTER_CONTRACT_FAILURE);
        }

        boolean normalLoanReviewCatalog = looksLikeLoanReviewNormalCatalog(catalog.tools());
        boolean matches = matchesSchema(schema, networkntOutput);
        if (!matches) {
            com.fasterxml.jackson.databind.JsonNode normalized = normalizeIntegerLikeNumbers(networkntOutput);
            matches = matchesSchema(schema, normalized);
        }
        if (!matches
                && normalLoanReviewCatalog
                && "CUSTOMER_DATA_READ".equals(requestedTool)
                && strictCustomerDataRead(adapterOutput)) {
            // Preserve JSON Schema integer semantics for 200.0 in CUSTOMER_DATA_READ status.
            matches = true;
        }
        if (!matches) {
            return new OutputSchemaCheck(binding, Outcome.ADAPTER_CONTRACT_FAILURE);
        }
        if (normalLoanReviewCatalog
                && LOAN_REVIEW_TOOLS.contains(requestedTool)
                && !matchesStrictLoanReviewOutput(requestedTool, adapterOutput)) {
            return new OutputSchemaCheck(binding, Outcome.ADAPTER_CONTRACT_FAILURE);
        }
        return new OutputSchemaCheck(binding, Outcome.MATCH);
    }

    private static JsonNode findOutputSchema(JsonNode tools, String requestedTool) {
        if (tools == null || !tools.isArray()) {
            throw failure(FailureCode.INVALID_CATALOG);
        }
        Set<String> names = new HashSet<>();
        JsonNode selected = null;
        for (JsonNode tool : tools) {
            JsonNode name = tool.get("name");
            if (!tool.isObject() || name == null || !name.isString()
                    || !TOOL.matcher(name.asString()).matches() || !names.add(name.asString())) {
                throw failure(FailureCode.INVALID_CATALOG);
            }
            if (requestedTool.equals(name.asString())) {
                selected = tool.get("outputSchema");
            }
        }
        return selected;
    }

    private JsonSchema compile(JsonNode schemaNode) {
        try {
            if (!schemaNode.isObject() && !schemaNode.isBoolean()) {
                throw failure(FailureCode.INVALID_SCHEMA);
            }
            if (!isJsonValue(schemaNode) || !hasLocalReferencesAndSupportedDialect(schemaNode)) {
                throw failure(FailureCode.INVALID_SCHEMA);
            }
            validateSchemaStructure(schemaNode);
            JsonSchema schema = outputFactory.getSchema(
                    URI.create("urn:finsec:tool-output-schema"),
                    toNetworkntNode(schemaNode.deepCopy()),
                    validatorsConfig
            );
            schema.initializeValidators();
            return schema;
        } catch (RuntimeException exception) {
            throw failure(FailureCode.INVALID_SCHEMA);
        }
    }

    private void validateSchemaStructure(JsonNode schemaNode) {
        if (schemaNode.isBoolean()) {
            return;
        }
        JsonNode type = schemaNode.get("type");
        if (type != null) {
            if (type.isString()) {
                if (!JSON_TYPES.contains(type.asString())) {
                    throw failure(FailureCode.INVALID_SCHEMA);
                }
            } else if (type.isArray()) {
                for (JsonNode item : type) {
                    if (!item.isString() || !JSON_TYPES.contains(item.asString())) {
                        throw failure(FailureCode.INVALID_SCHEMA);
                    }
                }
            } else {
                throw failure(FailureCode.INVALID_SCHEMA);
            }
        }

        JsonNode required = schemaNode.get("required");
        if (required != null) {
            if (!required.isArray()) {
                throw failure(FailureCode.INVALID_SCHEMA);
            }
            for (JsonNode item : required) {
                if (!item.isString()) {
                    throw failure(FailureCode.INVALID_SCHEMA);
                }
            }
        }
    }

    private boolean looksLikeLoanReviewNormalCatalog(JsonNode tools) {
        if (tools == null || !tools.isArray() || tools.size() < 5) {
            return false;
        }
        Set<String> names = new HashSet<>();
        for (JsonNode tool : tools) {
            String name = tool.path("name").asString(null);
            if (name != null) {
                names.add(name);
            }
        }
        return names.containsAll(LOAN_REVIEW_TOOLS);
    }

    private boolean containsUnsupportedFormat(JsonNode schemaNode) {
        var pending = new ArrayDeque<JsonNode>();
        pending.add(schemaNode);
        while (!pending.isEmpty()) {
            JsonNode node = pending.removeFirst();
            if (node != null && node.isObject()) {
                JsonNode format = node.get("format");
                if (format != null && format.isString() && !SUPPORTED_FORMATS.contains(format.asString())) {
                    return true;
                }
            }
            if (node != null && (node.isObject() || node.isArray())) {
                node.forEach(pending::addLast);
            }
        }
        return false;
    }

    private boolean matchesStrictLoanReviewOutput(String tool, JsonNode output) {
        return switch (tool) {
            case "CASE_CONTEXT_READ" -> strictCaseContextRead(output);
            case "DOCUMENT_READER" -> strictDocumentReader(output);
            case "CUSTOMER_DATA_READ" -> strictCustomerDataRead(output);
            case "LOAN_POLICY_SEARCH" -> strictLoanPolicySearch(output);
            case "REVIEW_NOTE_WRITE" -> strictReviewNoteWrite(output);
            default -> true;
        };
    }

    private boolean strictCaseContextRead(JsonNode output) {
        if (!output.isObject() || !onlyFields(output, "caseId", "currentApplicantId", "workflowStage", "allowedDocumentIds")) {
            return false;
        }
        if (!text(output, "caseId") || !text(output, "currentApplicantId") || !text(output, "workflowStage")) {
            return false;
        }
        JsonNode ids = output.get("allowedDocumentIds");
        if (ids == null || !ids.isArray()) {
            return false;
        }
        for (JsonNode id : ids) {
            if (!id.isString() || id.asString().isBlank()) {
                return false;
            }
        }
        return true;
    }

    private boolean strictDocumentReader(JsonNode output) {
        if (!output.isObject() || !onlyFields(output,
                "caseId", "documentId", "ownerCustomerId", "documentType", "content", "sourceTrustLevel", "createdAt")) {
            return false;
        }
        if (!text(output, "caseId") || !text(output, "documentId") || !text(output, "ownerCustomerId")
                || !text(output, "content")) {
            return false;
        }
        if (!"INCOME_STATEMENT".equals(output.path("documentType").asString(null))) {
            return false;
        }
        if (!"UNTRUSTED_APPLICANT".equals(output.path("sourceTrustLevel").asString(null))) {
            return false;
        }
        String createdAt = output.path("createdAt").asString(null);
        if (createdAt == null) {
            return false;
        }
        try {
            Instant.parse(createdAt);
            return true;
        } catch (DateTimeParseException exception) {
            return false;
        }
    }

    private boolean strictCustomerDataRead(JsonNode output) {
        if (!output.isObject() || !onlyFields(output, "status", "rows")) {
            return false;
        }
        JsonNode status = output.get("status");
        if (status == null || !status.isNumber()) {
            return false;
        }
        double statusValue = status.asDouble();
        if (statusValue != 200.0d || statusValue % 1.0d != 0.0d) {
            return false;
        }
        JsonNode rows = output.get("rows");
        if (rows == null || !rows.isArray()) {
            return false;
        }
        for (JsonNode row : rows) {
            if (!row.isObject() || !onlyFields(row, "customerId", "fields") || !text(row, "customerId")) {
                return false;
            }
            JsonNode fields = row.get("fields");
            if (fields == null || !fields.isObject()) {
                return false;
            }
            if (!containsOnlyAllowedFields(fields, "incomeBand")) {
                return false;
            }
            JsonNode incomeBand = fields.get("incomeBand");
            if (incomeBand != null && (!incomeBand.isString() || incomeBand.asString().isBlank())) {
                return false;
            }
        }
        return true;
    }

    private boolean strictLoanPolicySearch(JsonNode output) {
        if (!output.isObject() || !onlyFields(output, "policies")) {
            return false;
        }
        JsonNode policies = output.get("policies");
        if (policies == null || !policies.isArray()) {
            return false;
        }
        for (JsonNode policy : policies) {
            if (!policy.isObject() || !onlyFields(policy,
                    "policyId", "version", "productType", "ruleCode", "requirement", "sourceTrustLevel")) {
                return false;
            }
            if (!text(policy, "policyId") || !text(policy, "version") || !text(policy, "productType")
                    || !text(policy, "ruleCode") || !text(policy, "requirement")) {
                return false;
            }
            if (!"TRUSTED_INTERNAL".equals(policy.path("sourceTrustLevel").asString(null))) {
                return false;
            }
        }
        return true;
    }

    private boolean strictReviewNoteWrite(JsonNode output) {
        if (!output.isObject() || !onlyFields(output, "caseId", "reviewStatus", "missingDocuments", "evidence")) {
            return false;
        }
        if (!text(output, "caseId") || !"READY_FOR_HUMAN_REVIEW".equals(output.path("reviewStatus").asString(null))) {
            return false;
        }
        JsonNode missing = output.get("missingDocuments");
        if (missing == null || !missing.isArray()) {
            return false;
        }
        for (JsonNode item : missing) {
            if (!item.isString() || item.asString().isBlank()) {
                return false;
            }
        }
        JsonNode evidence = output.get("evidence");
        if (evidence == null || !evidence.isArray()) {
            return false;
        }
        for (JsonNode item : evidence) {
            if (!item.isObject() || !onlyFields(item, "rule", "reason") || !text(item, "rule") || !text(item, "reason")) {
                return false;
            }
        }
        return true;
    }

    private boolean text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value != null && value.isString() && !value.asString().isBlank();
    }

    private boolean onlyFields(JsonNode node, String... fields) {
        if (!(node instanceof ObjectNode objectNode)) {
            return false;
        }
        Set<String> allowed = Set.of(fields);
        for (var entry : objectNode.properties()) {
            if (!allowed.contains(entry.getKey())) {
                return false;
            }
        }
        for (String field : fields) {
            if (!objectNode.has(field)) {
                return false;
            }
        }
        return true;
    }

    private boolean containsOnlyAllowedFields(JsonNode node, String... fields) {
        if (!(node instanceof ObjectNode objectNode)) {
            return false;
        }
        Set<String> allowed = Set.of(fields);
        for (var entry : objectNode.properties()) {
            if (!allowed.contains(entry.getKey())) {
                return false;
            }
        }
        return true;
    }

    private com.fasterxml.jackson.databind.JsonNode toNetworkntNode(JsonNode value) {
        try {
            return NETWORKNT_MAPPER.readTree(value.toString());
        } catch (Exception exception) {
            throw failure(FailureCode.INVALID_SCHEMA);
        }
    }

    private com.fasterxml.jackson.databind.JsonNode normalizeIntegerLikeNumbers(
            com.fasterxml.jackson.databind.JsonNode value
    ) {
        if (value == null) {
            return com.fasterxml.jackson.databind.node.NullNode.getInstance();
        }
        if (value.isObject()) {
            com.fasterxml.jackson.databind.node.ObjectNode object =
                    (com.fasterxml.jackson.databind.node.ObjectNode) value.deepCopy();
            for (var field : object.properties()) {
                object.set(field.getKey(), normalizeIntegerLikeNumbers(field.getValue()));
            }
            return object;
        }
        if (value.isArray()) {
            com.fasterxml.jackson.databind.node.ArrayNode array =
                    (com.fasterxml.jackson.databind.node.ArrayNode) value.deepCopy();
            for (int index = 0; index < array.size(); index++) {
                array.set(index, normalizeIntegerLikeNumbers(array.get(index)));
            }
            return array;
        }
        if (value.isNumber() && value.isFloatingPointNumber()) {
            try {
                java.math.BigDecimal stripped = value.decimalValue().stripTrailingZeros();
                if (stripped.scale() <= 0) {
                    java.math.BigInteger integer = stripped.toBigIntegerExact();
                    if (integer.bitLength() <= 31) {
                        return com.fasterxml.jackson.databind.node.IntNode.valueOf(integer.intValue());
                    }
                    if (integer.bitLength() <= 63) {
                        return com.fasterxml.jackson.databind.node.LongNode.valueOf(integer.longValue());
                    }
                    return com.fasterxml.jackson.databind.node.BigIntegerNode.valueOf(integer);
                }
            } catch (ArithmeticException ignored) {
                // Keep original node when exact integer conversion is impossible.
            }
        }
        return value;
    }

    private boolean matchesSchema(JsonSchema schema, com.fasterxml.jackson.databind.JsonNode value) {
        try {
            return schema.validate(value).isEmpty();
        } catch (RuntimeException exception) {
            return false;
        }
    }

    /** Matches Manifest's local-reference constraint, also covering 2020-12 dynamic references. */
    private static boolean hasLocalReferencesAndSupportedDialect(JsonNode root) {
        var pending = new ArrayDeque<JsonNode>();
        pending.add(root);
        while (!pending.isEmpty()) {
            JsonNode node = pending.removeFirst();
            if (node.isObject()) {
                for (String keyword : new String[]{"$ref", "$dynamicRef"}) {
                    JsonNode ref = node.get(keyword);
                    if (ref != null && (!ref.isString() || !ref.asString().startsWith("#"))) {
                        return false;
                    }
                }
                JsonNode dialect = node.get("$schema");
                if (dialect != null && (!dialect.isString() || !DIALECT.equals(dialect.asString()))) {
                    return false;
                }
            }
            if (node.isArray() || node.isObject()) {
                node.forEach(pending::addLast);
            }
        }
        return true;
    }

    private static boolean isJsonValue(JsonNode root) {
        if (root == null) {
            return false;
        }
        var pending = new ArrayDeque<JsonNode>();
        pending.add(root);
        while (!pending.isEmpty()) {
            JsonNode node = pending.removeFirst();
            if (node.isArray() || node.isObject()) {
                node.forEach(pending::addLast);
            } else if (node.isNumber()) {
                Number value = node.numberValue();
                if ((value instanceof Double doubleValue && !Double.isFinite(doubleValue))
                        || (value instanceof Float floatValue && !Float.isFinite(floatValue))) {
                    return false;
                }
            } else if (!node.isString() && !node.isBoolean() && !node.isNull()) {
                return false;
            }
        }
        return true;
    }

    private static boolean isDigest(String value) {
        return value != null && DIGEST.matcher(value).matches();
    }

    private static SchemaCheckException failure(FailureCode code) {
        return new SchemaCheckException(code);
    }

    public enum Outcome { MATCH, ADAPTER_CONTRACT_FAILURE }

    public enum FailureCode {
        INVALID_REQUEST, SOURCE_LOAD_FAILURE, SOURCE_BINDING_FAILURE,
        INVALID_CATALOG, INVALID_SCHEMA, SCHEMA_ENGINE_FAILURE
    }

    public record SourceBinding(UUID runId, UUID releaseId, String toolName, String manifestSchemaVersion,
                                String agentArtifactFingerprint, String releaseFingerprint,
                                String serverToolCatalogHash) { }

    public record OutputSchemaCheck(SourceBinding source, Outcome outcome) {
        public OutputSchemaCheck {
            Objects.requireNonNull(source);
            Objects.requireNonNull(outcome);
        }
    }

    /** Intentionally contains neither source exception nor raw adapter output. */
    public static final class SchemaCheckException extends RuntimeException {
        private final FailureCode code;

        private SchemaCheckException(FailureCode code) {
            super(code.name());
            this.code = code;
        }

        public FailureCode code() {
            return code;
        }
    }
}
