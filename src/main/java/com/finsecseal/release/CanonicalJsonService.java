package com.finsecseal.release;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;
import tools.jackson.databind.node.StringNode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.Comparator;
import java.util.List;
import org.erdtman.jcs.JsonCanonicalizer;
import org.springframework.stereotype.Component;

@Component
public class CanonicalJsonService {

    public static final String VERSION = "RFC8785+NFC/v1";

    private final ObjectMapper objectMapper;

    public CanonicalJsonService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public byte[] canonicalize(JsonNode value) {
        try {
            byte[] json = objectMapper.writeValueAsBytes(normalizeStrings(value));
            return new JsonCanonicalizer(json).getEncodedUTF8();
        } catch (IOException exception) {
            throw new IllegalArgumentException("JSON canonicalization failed", exception);
        }
    }

    public String canonicalString(JsonNode value) {
        return new String(canonicalize(value), StandardCharsets.UTF_8);
    }

    public JsonNode normalizeManifest(JsonNode manifest) {
        JsonNode normalized = normalizeStrings(manifest);
        if (!(normalized instanceof ObjectNode root)) {
            return normalized;
        }
        if (root.path("tools") instanceof ArrayNode tools) {
            tools.forEach(tool -> {
                if (tool instanceof ObjectNode object) {
                    sortTextArray(object, "dataClassifications");
                }
            });
        }
        if (root.path("humanApprovalBoundaries") instanceof ArrayNode boundaries) {
            boundaries.forEach(boundary -> {
                if (boundary instanceof ObjectNode object) {
                    sortTextArray(object, "operations");
                }
            });
        }
        sortObjectArray(root, "tools", List.of("name", "version"));
        sortObjectArray(root, "ragSources", List.of("sourceId", "version"));
        sortObjectArray(root, "humanApprovalBoundaries", List.of("resource", "mode"));
        sortTextArray(root, "runtimeContextRequirements");
        if (root.path("networkRequirements") instanceof ObjectNode network) {
            sortTextArray(network, "allowedHosts");
        }
        if (root.path("businessWorkflow") instanceof ObjectNode workflow) {
            sortTextArray(workflow, "allowedStages");
        }
        return root;
    }

    private JsonNode normalizeStrings(JsonNode value) {
        if (value == null || value.isNull()) {
            return value;
        }
        if (value.isString()) {
            return StringNode.valueOf(normalizeText(value.stringValue()));
        }
        if (value.isArray()) {
            ArrayNode array = objectMapper.createArrayNode();
            value.forEach(item -> array.add(normalizeStrings(item)));
            return array;
        }
        if (value.isObject()) {
            ObjectNode object = objectMapper.createObjectNode();
            value.properties().forEach(entry -> {
                String normalizedKey = normalizeText(entry.getKey());
                if (object.has(normalizedKey)) {
                    throw new IllegalArgumentException(
                            "JSON object contains field names that collide after NFC normalization"
                    );
                }
                object.set(normalizedKey, normalizeStrings(entry.getValue()));
            });
            return object;
        }
        return value.deepCopy();
    }

    private String normalizeText(String value) {
        String lineNormalized = value.replace("\r\n", "\n").replace('\r', '\n');
        return Normalizer.normalize(lineNormalized, Normalizer.Form.NFC);
    }

    private void sortObjectArray(ObjectNode parent, String fieldName, List<String> stableKeys) {
        if (!(parent.path(fieldName) instanceof ArrayNode array)) {
            return;
        }
        List<JsonNode> values = new java.util.ArrayList<>();
        array.forEach(values::add);
        Comparator<JsonNode> comparator = (left, right) -> 0;
        for (String stableKey : stableKeys) {
            comparator = comparator.thenComparing(node -> node.path(stableKey).asString(""));
        }
        comparator = comparator.thenComparing(this::canonicalString);
        values.sort(comparator);
        array.removeAll();
        values.forEach(array::add);
    }

    private void sortTextArray(ObjectNode parent, String fieldName) {
        if (!(parent.path(fieldName) instanceof ArrayNode array)) {
            return;
        }
        List<String> values = new java.util.ArrayList<>();
        array.forEach(node -> values.add(node.asString("")));
        values.sort(String::compareTo);
        array.removeAll();
        values.forEach(array::add);
    }
}
