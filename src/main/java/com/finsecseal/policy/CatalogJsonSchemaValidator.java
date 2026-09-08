package com.finsecseal.policy;

import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SchemaValidatorsConfig;
import com.networknt.schema.SpecVersion;
import java.net.URI;
import java.util.ArrayDeque;
import java.util.Set;
import tools.jackson.databind.JsonNode;

/** Shared catalog-schema engine. Source binding and input resource limits belong to its callers. */
final class CatalogJsonSchemaValidator {
    private static final String DIALECT = "https://json-schema.org/draft/2020-12/schema";
    private static final Set<String> JSON_TYPES = Set.of(
            "null", "boolean", "object", "array", "number", "string", "integer"
    );
    private static final Set<String> SUPPORTED_FORMATS = Set.of(
            "date-time", "date", "time", "duration", "email", "idn-email", "hostname",
            "idn-hostname", "ipv4", "ipv6", "uri", "uri-reference", "iri", "iri-reference",
            "uuid", "regex", "json-pointer", "relative-json-pointer"
    );
    // Preserve decimal values in both the schema and output before exact integer normalization.
    private static final com.fasterxml.jackson.databind.ObjectMapper NETWORKNT_MAPPER =
            new com.fasterxml.jackson.databind.ObjectMapper()
                    .enable(com.fasterxml.jackson.databind.DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);

    private final JsonSchemaFactory schemaFactory;
    private final SchemaValidatorsConfig validatorsConfig;

    CatalogJsonSchemaValidator() {
        try {
            validatorsConfig = new SchemaValidatorsConfig();
            validatorsConfig.setTypeLoose(false);
            validatorsConfig.setFailFast(true);
            validatorsConfig.setLosslessNarrowing(false);
            validatorsConfig.setFormatAssertionsEnabled(true);
            schemaFactory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012);
        } catch (RuntimeException exception) {
            throw failure(Failure.ENGINE_FAILURE);
        }
    }

    boolean matches(JsonNode schemaNode, JsonNode value) {
        if (schemaNode == null) throw failure(Failure.INVALID_SCHEMA);
        if (containsUnsupportedFormat(schemaNode)) throw failure(Failure.UNSUPPORTED_FORMAT);
        JsonSchema schema = compile(schemaNode);
        if (!isJsonValue(value)) return false;
        com.fasterxml.jackson.databind.JsonNode instance;
        try {
            instance = toNetworkntNode(value);
        } catch (ValidationException exception) {
            return false;
        }
        return matchesSchema(schema, instance)
                || matchesSchema(schema, normalizeIntegerLikeNumbers(instance));
    }

    private JsonSchema compile(JsonNode schemaNode) {
        try {
            if (!schemaNode.isObject() && !schemaNode.isBoolean()) {
                throw failure(Failure.INVALID_SCHEMA);
            }
            if (!isJsonValue(schemaNode) || !hasLocalReferencesAndSupportedDialect(schemaNode)) {
                throw failure(Failure.INVALID_SCHEMA);
            }
            validateSchemaStructure(schemaNode);
            JsonSchema schema = schemaFactory.getSchema(
                    URI.create("urn:finsec:tool-output-schema"),
                    toNetworkntNode(schemaNode.deepCopy()),
                    validatorsConfig
            );
            schema.initializeValidators();
            return schema;
        } catch (RuntimeException exception) {
            throw failure(Failure.INVALID_SCHEMA);
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
                    throw failure(Failure.INVALID_SCHEMA);
                }
            } else if (type.isArray()) {
                for (JsonNode item : type) {
                    if (!item.isString() || !JSON_TYPES.contains(item.asString())) {
                        throw failure(Failure.INVALID_SCHEMA);
                    }
                }
            } else {
                throw failure(Failure.INVALID_SCHEMA);
            }
        }

        JsonNode required = schemaNode.get("required");
        if (required != null) {
            if (!required.isArray()) {
                throw failure(Failure.INVALID_SCHEMA);
            }
            for (JsonNode item : required) {
                if (!item.isString()) {
                    throw failure(Failure.INVALID_SCHEMA);
                }
            }
        }
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

    private com.fasterxml.jackson.databind.JsonNode toNetworkntNode(JsonNode value) {
        try {
            return NETWORKNT_MAPPER.readTree(value.toString());
        } catch (Exception exception) {
            throw failure(Failure.INVALID_SCHEMA);
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

    private static ValidationException failure(Failure code) {
        return new ValidationException(code);
    }

    enum Failure { INVALID_SCHEMA, UNSUPPORTED_FORMAT, ENGINE_FAILURE }

    /** Never carries a schema, value, engine message or cause. */
    static final class ValidationException extends RuntimeException {
        private final Failure failure;

        private ValidationException(Failure failure) {
            super(failure.name());
            this.failure = failure;
        }

        Failure failure() { return failure; }
    }
}
