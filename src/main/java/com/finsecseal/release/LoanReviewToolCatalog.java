package com.finsecseal.release;

import java.io.InputStream;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/** Versioned server definitions. Catalog membership never grants Agent execution permission. */
public final class LoanReviewToolCatalog {

    public static final String MANIFEST_VERSION = "1.1";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final CanonicalJsonService CANONICAL = new CanonicalJsonService(MAPPER);
    private static final JsonNode DEFINITIONS = load();

    private LoanReviewToolCatalog() {
    }

    public static JsonNode normalTools() {
        return DEFINITIONS.path("normalTools").deepCopy();
    }

    public static JsonNode serverToolCatalog() {
        return DEFINITIONS.path("serverToolCatalog").deepCopy();
    }

    static boolean matchesNormalTool(JsonNode tool) {
        JsonNode normalized = normalizeTool(tool);
        for (JsonNode expected : DEFINITIONS.path("normalTools")) {
            if (expected.path("name").equals(tool.path("name"))) {
                return normalizeTool(expected).equals(normalized);
            }
        }
        return false;
    }

    static boolean matchesServerCatalog(JsonNode catalog) {
        return CANONICAL.normalizeManifest(MAPPER.createObjectNode().set("serverToolCatalog", catalog))
                .path("serverToolCatalog").equals(DEFINITIONS.path("serverToolCatalog"));
    }

    private static JsonNode normalizeTool(JsonNode tool) {
        var wrapper = MAPPER.createObjectNode();
        wrapper.putArray("tools").add(tool);
        return CANONICAL.normalizeManifest(wrapper).path("tools").get(0);
    }

    private static JsonNode load() {
        try (InputStream input = LoanReviewToolCatalog.class.getResourceAsStream(
                "/release/loan-review-tool-catalog-1.1.json")) {
            if (input == null) {
                throw new IllegalStateException("Missing loan-review server Tool catalog");
            }
            return MAPPER.readTree(input);
        } catch (Exception exception) {
            throw new IllegalStateException("Cannot load loan-review server Tool catalog", exception);
        }
    }
}
