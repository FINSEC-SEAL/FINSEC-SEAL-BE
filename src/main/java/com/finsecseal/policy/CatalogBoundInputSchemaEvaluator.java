package com.finsecseal.policy;

import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.SourceBoundCatalog;
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
 * Checks the verified catalog schema and mode-independent request invariants, without owner reads or execution.
 * MATCH grants no context, permission or remaining preflight authority.
 */
public final class CatalogBoundInputSchemaEvaluator {
    private static final int MAX_ARGUMENT_BYTES = 32 * 1024;
    // C resource-limit choices. The specification requires a depth bound but does not fix this number.
    private static final int MAX_DEPTH = 32;
    private static final int MAX_RESPONSE_BYTES = 1024 * 1024;
    private static final int MAX_RESPONSE_DEPTH = 64;
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
        return evaluate(proposal, inputSchemas(source));
    }

    /** Internal use with an already verified catalog; input conformance grants no permission. */
    InputOutcome evaluateCatalog(SourceBoundCatalog catalog, ToolProposal proposal) {
        return evaluate(proposal, inputSchemas(catalog));
    }

    private InputOutcome evaluate(ToolProposal proposal, Map<String, JsonNode> catalog) {
        if (proposal == null || !validToolName(proposal.toolName())) {
            return InputOutcome.INVALID_REQUEST_SCHEMA;
        }
        JsonNode arguments = snapshotArguments(proposal.arguments());
        if (arguments == null) return InputOutcome.INVALID_REQUEST_SCHEMA;
        JsonNode schema = catalog.get(proposal.toolName());
        if (schema == null) return InputOutcome.TOOL_NOT_IN_CATALOG;
        try {
            if (!schemas.matches(schema, arguments)) return InputOutcome.INVALID_REQUEST_SCHEMA;
            // These request invariants precede business rules in both BASELINE and ENFORCE.
            // Never normalize or deduplicate malformed requests into executable ones.
            if ("CUSTOMER_DATA_READ".equals(proposal.toolName())
                    && (!uniqueNonblankStrings(arguments.path("customerIds"))
                            || !uniqueNonblankStrings(arguments.path("fields")))) {
                return InputOutcome.INVALID_REQUEST_SCHEMA;
            }
            return InputOutcome.MATCH;
        } catch (CatalogJsonSchemaValidator.ValidationException exception) {
            throw failure(switch (exception.failure()) {
                case INVALID_SCHEMA, UNSUPPORTED_FORMAT -> FailureCode.INVALID_CATALOG_SCHEMA;
                case ENGINE_FAILURE -> FailureCode.SCHEMA_ENGINE_FAILURE;
            });
        } catch (RuntimeException exception) {
            throw failure(FailureCode.SCHEMA_ENGINE_FAILURE);
        }
    }

    private static boolean uniqueNonblankStrings(JsonNode array) {
        if (!array.isArray() || array.isEmpty()) return false;
        var seen = new HashSet<String>();
        for (JsonNode value : array) {
            if (!value.isString() || value.stringValue().isBlank() || !seen.add(value.stringValue())) return false;
        }
        return true;
    }

    private Map<String, JsonNode> inputSchemas(ApprovedPolicySource source) {
        try {
            if (source == null) throw failure(FailureCode.INVALID_POLICY_SOURCE);
            return inputSchemas(source.catalog());
        } catch (InputSchemaException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw failure(FailureCode.INVALID_POLICY_SOURCE);
        }
    }

    private Map<String, JsonNode> inputSchemas(SourceBoundCatalog catalog) {
        try {
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

    static JsonNode snapshotArguments(JsonNode arguments) {
        try {
            return arguments == null || !arguments.isObject()
                    ? null : snapshot(arguments, MAX_ARGUMENT_BYTES, MAX_DEPTH);
        } catch (RuntimeException exception) {
            return null;
        }
    }

    /** Bounded raw response/classification snapshot, prior to schema or provenance evaluation. */
    static JsonNode snapshotResponse(JsonNode response) {
        return snapshot(response, MAX_RESPONSE_BYTES, MAX_RESPONSE_DEPTH);
    }

    private static JsonNode snapshot(JsonNode value, int maximumBytes, int maximumDepth) {
        try {
            if (value == null || !withinTreeLimits(value, maximumBytes, maximumDepth)) return null;
            JsonNode snapshot = value.deepCopy();
            return snapshot.toString().getBytes(StandardCharsets.UTF_8).length <= maximumBytes
                    ? snapshot : null;
        } catch (RuntimeException exception) {
            return null;
        }
    }

    /** Reject unsafe trees before recursive copying/serialization; callers must not mutate during evaluation. */
    private static boolean withinTreeLimits(JsonNode root, int maximumBytes, int maximumDepth) {
        var pending = new ArrayDeque<PendingNode>();
        pending.push(new PendingNode(root, 1));
        long minimumBytes = 1;
        long numericWork = 0;
        while (!pending.isEmpty()) {
            PendingNode current = pending.pop();
            JsonNode node = current.node();
            if (current.depth() > maximumDepth || node == null) return false;
            if (node.isObject()) {
                minimumBytes++; // Replace the queued one-byte lower bound with two delimiters.
                int index = 0;
                for (var property : node.properties()) {
                    // Key quotes, colon, child and (after the first item) comma; escapes can only add bytes.
                    minimumBytes += (long) property.getKey().length() + 4 + (index++ == 0 ? 0 : 1);
                    if (minimumBytes > maximumBytes) return false;
                    pending.push(new PendingNode(property.getValue(), current.depth() + 1));
                }
            } else if (node.isArray()) {
                minimumBytes++;
                int index = 0;
                for (JsonNode child : node) {
                    minimumBytes += 1 + (index++ == 0 ? 0 : 1);
                    if (minimumBytes > maximumBytes) return false;
                    pending.push(new PendingNode(child, current.depth() + 1));
                }
            } else if (node.isString()) {
                minimumBytes += (long) node.stringValue().length() + 1;
            } else if (node.isNumber()) {
                Number number = node.numberValue();
                if (!withinNumericWorkLimit(number)) return false;
                // Each number is already bounded. Count its representation before copying the
                // whole tree, and separately bound aggregate exact-integer normalization work.
                String encoded = number.toString();
                minimumBytes += encoded.length() - 1L;
                long work = encoded.length();
                BigDecimal decimal = number instanceof BigDecimal value ? value
                        : number instanceof Double || number instanceof Float ? new BigDecimal(encoded) : null;
                if (decimal != null && decimal.signum() != 0) {
                    work = Math.max(work, Math.max(decimal.precision(),
                            (long) decimal.precision() - decimal.scale()));
                }
                numericWork += work;
                if (numericWork > maximumBytes) return false;
            } else if (!node.isBoolean() && !node.isNull()) {
                return false;
            }
            if (minimumBytes > maximumBytes) return false;
        }
        return true;
    }

    /** Bounds exact-integer fallback expansion without creating an integer or changing the original value. */
    private static boolean withinNumericWorkLimit(Number number) {
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

    static boolean validToolName(String name) {
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
