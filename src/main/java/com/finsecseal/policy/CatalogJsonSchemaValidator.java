package com.finsecseal.policy;

import com.networknt.schema.FormatKeyword;
import com.networknt.schema.JsonMetaSchema;
import com.networknt.schema.JsonNodePath;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.JsonValidator;
import com.networknt.schema.Keyword;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SchemaValidatorsConfig;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationContext;
import com.networknt.schema.Vocabulary;
import java.net.URI;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.IdentityHashMap;
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
    private static final Set<String> SCHEMA_MAPS = Set.of(
            "$defs", "definitions", "properties", "patternProperties", "dependentSchemas", "dependencies"
    );
    private static final Set<String> SCHEMA_ARRAYS = Set.of("allOf", "anyOf", "oneOf", "prefixItems");
    private static final Set<String> SINGLE_SCHEMAS = Set.of(
            "items", "contains", "additionalProperties", "propertyNames", "unevaluatedProperties",
            "unevaluatedItems", "not", "if", "then", "else", "contentSchema"
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
            JsonMetaSchema dialect = JsonMetaSchema.builder(JsonMetaSchema.getV202012())
                    .vocabularyFactory(CatalogJsonSchemaValidator::guardedVocabulary)
                    .formatKeywordFactory(formats -> new FormatKeyword(formats) {
                        @Override
                        public JsonValidator newValidator(SchemaLocation location, JsonNodePath path,
                                com.fasterxml.jackson.databind.JsonNode format, JsonSchema parent,
                                ValidationContext context) {
                            // Also inspect actual reference targets, using the engine's own URI/scope resolution.
                            if (format.isTextual() && !SUPPORTED_FORMATS.contains(format.asText())) {
                                throw failure(Failure.UNSUPPORTED_FORMAT);
                            }
                            return super.newValidator(location, path, format, parent, context);
                        }
                    }).build();
            schemaFactory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012,
                    builder -> builder.metaSchema(dialect));
        } catch (RuntimeException exception) {
            throw failure(Failure.ENGINE_FAILURE);
        }
    }

    boolean matches(JsonNode schemaNode, JsonNode value) {
        if (schemaNode == null) throw failure(Failure.INVALID_SCHEMA);
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
            if (!isJsonValue(schemaNode)) throw failure(Failure.INVALID_SCHEMA);
            var nativeSchema = toNetworkntNode(schemaNode.deepCopy());
            if (containsUnsupportedFormat(nativeSchema)) throw failure(Failure.UNSUPPORTED_FORMAT);
            if (!hasLocalReferencesAndSupportedDialect(schemaNode)) {
                throw failure(Failure.INVALID_SCHEMA);
            }
            validateSchemaStructure(schemaNode);
            JsonSchema schema = schemaFactory.getSchema(
                    URI.create("urn:finsec:tool-output-schema"),
                    nativeSchema,
                    validatorsConfig
            );
            schema.initializeValidators();
            return schema;
        } catch (RuntimeException exception) {
            rethrowKnownFailure(exception);
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

    private static Vocabulary guardedVocabulary(String iri) {
        Vocabulary original;
        if (Vocabulary.V202012_APPLICATOR.getIri().equals(iri)) {
            original = Vocabulary.V202012_APPLICATOR;
        } else if (Vocabulary.V202012_CONTENT.getIri().equals(iri)) {
            original = Vocabulary.V202012_CONTENT;
        } else {
            return null; // Use the engine's built-in vocabulary fallback.
        }
        return new Vocabulary(original.getIri(), original.getKeywords().stream()
                .map(keyword -> switch (keyword.getValue()) {
                    case "contentSchema", "then", "else" -> guardSchemaKeyword(keyword);
                    default -> keyword;
                }).toArray(Keyword[]::new));
    }

    private static Keyword guardSchemaKeyword(Keyword delegate) {
        return new Keyword() {
            @Override
            public String getValue() {
                return delegate.getValue();
            }

            @Override
            public JsonValidator newValidator(SchemaLocation location, JsonNodePath path,
                    com.fasterxml.jackson.databind.JsonNode schema, JsonSchema parent,
                    ValidationContext context) throws Exception {
                // These keywords need not construct child validators, even in an actual reference target.
                if (containsUnsupportedFormat(schema)) throw failure(Failure.UNSUPPORTED_FORMAT);
                return delegate.newValidator(location, path, schema, parent, context);
            }
        };
    }

    private static boolean containsUnsupportedFormat(com.fasterxml.jackson.databind.JsonNode schemaNode) {
        var pending = new ArrayDeque<com.fasterxml.jackson.databind.JsonNode>();
        pending.add(schemaNode);
        while (!pending.isEmpty()) {
            var node = pending.removeFirst();
            if (node != null && node.isObject()) {
                var format = node.get("format");
                if (format != null && format.isTextual() && !SUPPORTED_FORMATS.contains(format.asText())) {
                    return true;
                }
            }
            if (node != null && node.isObject()) {
                // Keyword values such as const/default/examples are data, not nested schemas.
                // Still inspect unused definitions/branches, which the engine need not evaluate.
                for (String keyword : SCHEMA_MAPS) {
                    var map = node.get(keyword);
                    if (map != null && map.isObject()) map.forEach(pending::addLast);
                }
                for (String keyword : SCHEMA_ARRAYS) {
                    var array = node.get(keyword);
                    if (array != null && array.isArray()) array.forEach(pending::addLast);
                }
                for (String keyword : SINGLE_SCHEMAS) {
                    var child = node.get(keyword);
                    if (child != null) pending.addLast(child);
                }
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
            rethrowKnownFailure(exception);
            return false;
        }
    }

    /** The engine wraps keyword failures, including during lazy reference construction. */
    private static void rethrowKnownFailure(Throwable exception) {
        Set<Throwable> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Throwable cause = exception; cause != null && visited.add(cause); cause = cause.getCause()) {
            if (cause instanceof ValidationException known) throw failure(known.failure());
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
