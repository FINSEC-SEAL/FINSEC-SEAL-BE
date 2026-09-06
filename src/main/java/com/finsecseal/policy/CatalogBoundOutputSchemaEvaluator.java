package com.finsecseal.policy;

import com.finsecseal.evidence.TestRunDto;
import com.finsecseal.evidence.TestRunProjectionService;
import com.finsecseal.release.LoanReviewToolCatalog;
import com.finsecseal.release.ReleaseDto.ToolCatalogResponse;
import com.finsecseal.release.ReleaseService;
import com.networknt.schema.OutputFormat;
import com.networknt.schema.Schema;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SchemaRegistryConfig;
import com.networknt.schema.dialect.Dialects;
import com.networknt.schema.resource.SchemaLoader;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import tools.jackson.databind.JsonNode;

/**
 * Applies the run-bound, verified Release output schema before further post-call checks.
 * MATCH proves only JSON Schema conformance, never policy permission or safe model delivery.
 * Caller authorization, contract approval, scope, classification and provenance remain separate.
 */
public final class CatalogBoundOutputSchemaEvaluator {

    private static final String DIALECT = "https://json-schema.org/draft/2020-12/schema";
    private static final Set<String> META_RESOURCES = Set.of(
            DIALECT,
            "https://json-schema.org/draft/2020-12/meta/core",
            "https://json-schema.org/draft/2020-12/meta/applicator",
            "https://json-schema.org/draft/2020-12/meta/unevaluated",
            "https://json-schema.org/draft/2020-12/meta/validation",
            "https://json-schema.org/draft/2020-12/meta/meta-data",
            "https://json-schema.org/draft/2020-12/meta/format-annotation",
            "https://json-schema.org/draft/2020-12/meta/content"
    );
    private static final Pattern DIGEST = Pattern.compile("sha256:[0-9a-f]{64}");
    private static final Pattern TOOL = Pattern.compile("[A-Z][A-Z0-9_]{1,99}");

    private final TestRunProjectionService runs;
    private final ReleaseService releases;
    private final SchemaRegistry outputRegistry;
    private final Schema metaSchema;

    public CatalogBoundOutputSchemaEvaluator(TestRunProjectionService runs, ReleaseService releases) {
        this.runs = Objects.requireNonNull(runs);
        this.releases = Objects.requireNonNull(releases);
        try {
            var config = SchemaRegistryConfig.builder()
                    .formatAssertionsEnabled(true).strict("format", true)
                    .failFast(true).typeLoose(false).losslessNarrowing(false)
                    .preloadSchema(false).build();
            outputRegistry = SchemaRegistry.withDialect(Dialects.getDraft202012(), builder -> builder
                    .schemaRegistryConfig(config)
                    .schemaLoader(SchemaLoader.builder().fetchRemoteResources(false)
                            .block(iri -> true).build()));
            var metaRegistry = SchemaRegistry.withDialect(Dialects.getDraft202012(), builder -> builder
                    .schemaRegistryConfig(config)
                    .schemaLoader(SchemaLoader.builder().fetchRemoteResources(false)
                            .allow(iri -> META_RESOURCES.contains(iri.toString())).build()));
            metaSchema = metaRegistry.getSchema(SchemaLocation.of(DIALECT));
            metaSchema.initializeValidators();
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
        Schema schema = compile(schemaNode);
        if (!isJsonValue(adapterOutput)) {
            return new OutputSchemaCheck(binding, Outcome.ADAPTER_CONTRACT_FAILURE);
        }
        try {
            boolean matches = schema.validate(adapterOutput, OutputFormat.BOOLEAN);
            return new OutputSchemaCheck(binding, matches ? Outcome.MATCH : Outcome.ADAPTER_CONTRACT_FAILURE);
        } catch (RuntimeException exception) {
            // Engine diagnostics may embed instance values; expose only a stable operational code.
            throw failure(FailureCode.SCHEMA_ENGINE_FAILURE);
        }
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

    private Schema compile(JsonNode schemaNode) {
        try {
            if (!isJsonValue(schemaNode) || !hasLocalReferencesAndSupportedDialect(schemaNode)
                    || !metaSchema.validate(schemaNode, OutputFormat.BOOLEAN)) {
                throw failure(FailureCode.INVALID_SCHEMA);
            }
            Schema schema = outputRegistry.getSchema(
                    SchemaLocation.of("urn:finsec:tool-output-schema"), schemaNode.deepCopy());
            // Automatic preload suppresses unresolved-reference exceptions; initialize explicitly.
            schema.initializeValidators();
            return schema;
        } catch (RuntimeException exception) {
            throw failure(FailureCode.INVALID_SCHEMA);
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
