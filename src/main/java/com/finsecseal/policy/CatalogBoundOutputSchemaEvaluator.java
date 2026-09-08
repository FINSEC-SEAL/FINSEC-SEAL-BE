package com.finsecseal.policy;

import com.finsecseal.evidence.TestRunDto;
import com.finsecseal.evidence.TestRunProjectionService;
import com.finsecseal.release.LoanReviewToolCatalog;
import com.finsecseal.release.ReleaseDto.ToolCatalogResponse;
import com.finsecseal.release.ReleaseService;
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

    private static final Pattern DIGEST = Pattern.compile("sha256:[0-9a-f]{64}");
    private static final Pattern TOOL = Pattern.compile("[A-Z][A-Z0-9_]{1,99}");
    private final TestRunProjectionService runs;
    private final ReleaseService releases;
    private final CatalogJsonSchemaValidator schemas;

    public CatalogBoundOutputSchemaEvaluator(TestRunProjectionService runs, ReleaseService releases) {
        this.runs = Objects.requireNonNull(runs);
        this.releases = Objects.requireNonNull(releases);
        try {
            schemas = new CatalogJsonSchemaValidator();
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
        try {
            return new OutputSchemaCheck(binding, schemas.matches(schemaNode, adapterOutput)
                    ? Outcome.MATCH : Outcome.ADAPTER_CONTRACT_FAILURE);
        } catch (CatalogJsonSchemaValidator.ValidationException exception) {
            return switch (exception.failure()) {
                case UNSUPPORTED_FORMAT -> new OutputSchemaCheck(binding, Outcome.ADAPTER_CONTRACT_FAILURE);
                case INVALID_SCHEMA -> throw failure(FailureCode.INVALID_SCHEMA);
                case ENGINE_FAILURE -> throw failure(FailureCode.SCHEMA_ENGINE_FAILURE);
            };
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
