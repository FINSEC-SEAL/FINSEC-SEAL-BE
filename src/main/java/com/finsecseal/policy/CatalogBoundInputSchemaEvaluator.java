package com.finsecseal.policy;

import com.finsecseal.policy.GatewayApprovedPolicySourceService.ApprovedPolicySource;
import com.finsecseal.runtime.ToolProposal;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Map;
import java.util.regex.Pattern;
import tools.jackson.databind.JsonNode;

/**
 * Checks request shape against the already approved source snapshot, without owner reads or execution.
 * MATCH is only input-schema conformance; context, permission and the remaining preflight are separate.
 */
public final class CatalogBoundInputSchemaEvaluator {
    private static final int MAX_ARGUMENT_BYTES = 32 * 1024;
    // C resource-limit choices. The specification requires a depth bound but does not fix this number.
    private static final int MAX_DEPTH = 32;
    private static final int MAX_NUMERIC_DIGITS = MAX_ARGUMENT_BYTES;
    private static final Pattern TOOL = Pattern.compile("[A-Z][A-Z0-9_]{1,99}");
    private final CatalogJsonSchemaValidator schemas;

    public CatalogBoundInputSchemaEvaluator() {
        try {
            schemas = new CatalogJsonSchemaValidator();
        } catch (RuntimeException exception) {
            throw failure(FailureCode.SCHEMA_ENGINE_FAILURE);
        }
    }

    public InputOutcome evaluate(ApprovedPolicySource source, ToolProposal proposal) {
        Map<String, JsonNode> catalog = inputSchemas(source);
        if (proposal == null || !validToolName(proposal.toolName())) {
            return InputOutcome.INVALID_REQUEST_SCHEMA;
        }
        JsonNode arguments = snapshotArguments(proposal.arguments());
        if (arguments == null) return InputOutcome.INVALID_REQUEST_SCHEMA;
        JsonNode schema = catalog.get(proposal.toolName());
        if (schema == null) return InputOutcome.TOOL_NOT_IN_CATALOG;
        try {
            return schemas.matches(schema, arguments)
                    ? InputOutcome.MATCH : InputOutcome.INVALID_REQUEST_SCHEMA;
        } catch (CatalogJsonSchemaValidator.ValidationException exception) {
            throw failure(switch (exception.failure()) {
                case INVALID_SCHEMA, UNSUPPORTED_FORMAT -> FailureCode.INVALID_CATALOG_SCHEMA;
                case ENGINE_FAILURE -> FailureCode.SCHEMA_ENGINE_FAILURE;
            });
        } catch (RuntimeException exception) {
            throw failure(FailureCode.SCHEMA_ENGINE_FAILURE);
        }
    }

    private Map<String, JsonNode> inputSchemas(ApprovedPolicySource source) {
        try {
            if (source == null) throw failure(FailureCode.INVALID_POLICY_SOURCE);
            var catalog = source.catalog();
            if (catalog == null) throw failure(FailureCode.INVALID_POLICY_SOURCE);
            var semantic = catalog.semanticCatalog();
            if (semantic == null) throw failure(FailureCode.INVALID_POLICY_SOURCE);
            var expected = new HashSet<String>();
            for (var tool : semantic.enabledReleaseTools()) {
                if (!validToolName(tool.toolName()) || !expected.add(tool.toolName())) {
                    throw failure(FailureCode.INVALID_POLICY_SOURCE);
                }
            }
            for (String tool : semantic.highImpactToolNames()) {
                if (!validToolName(tool) || !expected.add(tool)) throw failure(FailureCode.INVALID_POLICY_SOURCE);
            }
            if (expected.isEmpty()) throw failure(FailureCode.INVALID_POLICY_SOURCE);
            Map<String, JsonNode> inputSchemas = catalog.inputSchemas();
            if (inputSchemas == null || !expected.equals(inputSchemas.keySet())) {
                throw failure(FailureCode.INVALID_CATALOG_SCHEMA);
            }
            for (JsonNode schema : inputSchemas.values()) {
                if (schema == null || (!schema.isObject() && !schema.isBoolean())) {
                    throw failure(FailureCode.INVALID_CATALOG_SCHEMA);
                }
            }
            return inputSchemas;
        } catch (InputSchemaException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw failure(FailureCode.INVALID_POLICY_SOURCE);
        }
    }

    private JsonNode snapshotArguments(JsonNode arguments) {
        try {
            if (arguments == null || !arguments.isObject() || !withinTreeLimits(arguments)) return null;
            JsonNode snapshot = arguments.deepCopy();
            return snapshot.toString().getBytes(StandardCharsets.UTF_8).length <= MAX_ARGUMENT_BYTES
                    ? snapshot : null;
        } catch (RuntimeException exception) {
            return null;
        }
    }

    /** Reject unsafe trees before recursive copying/serialization; callers must not mutate during evaluation. */
    private boolean withinTreeLimits(JsonNode root) {
        var pending = new ArrayDeque<PendingNode>();
        pending.push(new PendingNode(root, 1));
        long minimumBytes = 1;
        while (!pending.isEmpty()) {
            PendingNode current = pending.pop();
            JsonNode node = current.node();
            if (current.depth() > MAX_DEPTH || node == null) return false;
            if (node.isObject()) {
                minimumBytes++; // Replace the queued one-byte lower bound with two delimiters.
                int index = 0;
                for (var property : node.properties()) {
                    // Key quotes, colon, child and (after the first item) comma; escapes can only add bytes.
                    minimumBytes += (long) property.getKey().length() + 4 + (index++ == 0 ? 0 : 1);
                    if (minimumBytes > MAX_ARGUMENT_BYTES) return false;
                    pending.push(new PendingNode(property.getValue(), current.depth() + 1));
                }
            } else if (node.isArray()) {
                minimumBytes++;
                int index = 0;
                for (JsonNode child : node) {
                    minimumBytes += 1 + (index++ == 0 ? 0 : 1);
                    if (minimumBytes > MAX_ARGUMENT_BYTES) return false;
                    pending.push(new PendingNode(child, current.depth() + 1));
                }
            } else if (node.isString()) {
                minimumBytes += (long) node.stringValue().length() + 1;
            } else if (node.isNumber()) {
                if (!withinNumericWorkLimit(node.numberValue())) return false;
            } else if (!node.isBoolean() && !node.isNull()) {
                return false;
            }
            if (minimumBytes > MAX_ARGUMENT_BYTES) return false;
        }
        return true;
    }

    /** Bounds exact-integer fallback expansion without creating an integer or changing the original value. */
    private boolean withinNumericWorkLimit(Number number) {
        if (number == null) return false;
        if (number instanceof Double value) return Double.isFinite(value);
        if (number instanceof Float value) return Float.isFinite(value);
        if (number instanceof BigInteger value) return value.bitLength() <= MAX_NUMERIC_DIGITS * 4;
        if (number instanceof BigDecimal value) {
            if (value.unscaledValue().bitLength() > MAX_NUMERIC_DIGITS * 4) return false;
            int precision = value.precision();
            return precision <= MAX_NUMERIC_DIGITS && (value.signum() == 0
                    || (long) precision - (long) value.scale() <= MAX_NUMERIC_DIGITS);
        }
        return true;
    }

    private static boolean validToolName(String name) {
        return name != null && name.length() <= 100 && TOOL.matcher(name).matches();
    }

    private static InputSchemaException failure(FailureCode code) {
        return new InputSchemaException(code);
    }

    private record PendingNode(JsonNode node, int depth) { }

    public enum InputOutcome { MATCH, INVALID_REQUEST_SCHEMA, TOOL_NOT_IN_CATALOG }

    public enum FailureCode { INVALID_POLICY_SOURCE, INVALID_CATALOG_SCHEMA, SCHEMA_ENGINE_FAILURE }

    /** Contains no raw request, schema, validation issue or owner exception. */
    public static final class InputSchemaException extends RuntimeException {
        private final FailureCode code;

        private InputSchemaException(FailureCode code) {
            super(code.name());
            this.code = code;
        }

        public FailureCode code() { return code; }
    }
}
