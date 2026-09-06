package com.finsecseal.contract;

import com.finsecseal.contract.SafetyContractSemanticValidator.ContractValidationCatalog;
import com.finsecseal.contract.SafetyContractSemanticValidator.EnabledTool;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.ReleaseDto.ToolCatalogResponse;
import com.finsecseal.release.ReleaseService;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Role C boundary that converts Role A's verified Manifest 1.1 Tool catalog into
 * immutable semantic-validation input.
 *
 * <p>A successful conversion proves only source integrity and catalog shape. It
 * does not approve a Safety Contract, pass a Release, authorize deployment, or
 * grant Tool execution permission.</p>
 */
@Component
public final class ReleaseToolCatalogContractAdapter {

    public static final String SUPPORTED_MANIFEST_VERSION = "1.1";
    public static final String SUPPORTED_SERVER_CATALOG_VERSION =
            "loan-review-server/1.0";

    private static final String CUSTOMER_DATA_READ = "CUSTOMER_DATA_READ";
    private static final String CUSTOMER_OUTPUT_FIELDS_POINTER =
            "/outputSchema/properties/rows/items/properties/fields/properties";
    private static final String DEFAULT_OUTPUT_FIELDS_POINTER =
            "/outputSchema/properties";
    private static final Pattern DIGEST = Pattern.compile("^sha256:[0-9a-f]{64}$");
    private static final Pattern TOOL_IDENTIFIER = Pattern.compile(
            "^[A-Z][A-Z0-9_]{1,99}$"
    );

    private final ReleaseService releaseService;
    private final CanonicalJsonService canonicalJsonService;
    private final DigestService digestService;
    private final ObjectMapper objectMapper;

    public ReleaseToolCatalogContractAdapter(
            ReleaseService releaseService,
            CanonicalJsonService canonicalJsonService,
            DigestService digestService,
            ObjectMapper objectMapper
    ) {
        this.releaseService = Objects.requireNonNull(
                releaseService,
                "releaseService must not be null"
        );
        this.canonicalJsonService = Objects.requireNonNull(
                canonicalJsonService,
                "canonicalJsonService must not be null"
        );
        this.digestService = Objects.requireNonNull(
                digestService,
                "digestService must not be null"
        );
        this.objectMapper = Objects.requireNonNull(
                objectMapper,
                "objectMapper must not be null"
        );
    }

    /**
     * Loads exactly one verified source snapshot and converts it without retry
     * or alternate state access.
     */
    public SourceBoundCatalog load(UUID requestedReleaseId, String actorId) {
        if (requestedReleaseId == null || !isExactNonBlank(actorId)) {
            throw failure(FailureCode.INVALID_REQUEST);
        }

        ToolCatalogResponse source;
        try {
            source = releaseService.toolCatalog(requestedReleaseId, actorId);
        } catch (RuntimeException exception) {
            throw failure(FailureCode.SOURCE_LOAD_FAILURE);
        }
        if (source == null) {
            throw failure(FailureCode.SOURCE_UNAVAILABLE);
        }

        JsonNode toolsSnapshot;
        JsonNode serverCatalogSnapshot;
        try {
            toolsSnapshot = snapshot(source.tools());
            serverCatalogSnapshot = snapshot(source.serverToolCatalog());
        } catch (RuntimeException exception) {
            throw failure(FailureCode.SOURCE_SNAPSHOT_FAILURE);
        }

        validateSourceMetadata(requestedReleaseId, source);
        validateServerCatalogHash(serverCatalogSnapshot, source.serverToolCatalogHash());

        List<EnabledTool> enabledTools = extractEnabledTools(toolsSnapshot);
        List<String> highImpactTools = extractHighImpactTools(serverCatalogSnapshot);
        rejectRoleOverlap(enabledTools, highImpactTools);

        return new SourceBoundCatalog(
                source.releaseId(),
                source.manifestSchemaVersion(),
                source.agentArtifactFingerprint(),
                source.releaseFingerprint(),
                source.serverToolCatalogHash(),
                new ContractValidationCatalog(enabledTools, highImpactTools)
        );
    }

    private void validateSourceMetadata(
            UUID requestedReleaseId,
            ToolCatalogResponse source
    ) {
        if (source.releaseId() == null || !requestedReleaseId.equals(source.releaseId())) {
            throw failure(FailureCode.SOURCE_IDENTITY_MISMATCH);
        }
        if (!SUPPORTED_MANIFEST_VERSION.equals(source.manifestSchemaVersion())) {
            throw failure(FailureCode.UNSUPPORTED_MANIFEST_VERSION);
        }
        requireDigest(
                source.agentArtifactFingerprint(),
                FailureCode.INVALID_AGENT_ARTIFACT_FINGERPRINT
        );
        requireDigest(
                source.releaseFingerprint(),
                FailureCode.INVALID_RELEASE_FINGERPRINT
        );
        requireDigest(
                source.serverToolCatalogHash(),
                FailureCode.INVALID_SERVER_CATALOG_HASH
        );
    }

    private void validateServerCatalogHash(JsonNode serverCatalog, String expectedHash) {
        if (serverCatalog == null || !serverCatalog.isObject()) {
            throw failure(FailureCode.INVALID_HIGH_IMPACT_CATALOG);
        }

        String actualHash;
        try {
            ObjectNode wrapper = objectMapper.createObjectNode();
            wrapper.set("serverToolCatalog", serverCatalog.deepCopy());
            JsonNode normalizedCatalog = canonicalJsonService
                    .normalizeManifest(wrapper)
                    .path("serverToolCatalog");
            actualHash = digestService.sha256(
                    canonicalJsonService.canonicalize(normalizedCatalog)
            );
        } catch (RuntimeException exception) {
            throw failure(FailureCode.SERVER_CATALOG_HASH_MISMATCH);
        }

        if (!expectedHash.equals(actualHash)) {
            throw failure(FailureCode.SERVER_CATALOG_HASH_MISMATCH);
        }
    }

    private List<EnabledTool> extractEnabledTools(JsonNode tools) {
        if (tools == null || !tools.isArray() || tools.isEmpty()) {
            throw failure(FailureCode.INVALID_ENABLED_TOOL_CATALOG);
        }

        List<EnabledTool> enabledTools = new ArrayList<>();
        Set<String> toolNames = new HashSet<>();
        for (JsonNode tool : tools) {
            if (tool == null || !tool.isObject()) {
                throw failure(FailureCode.INVALID_ENABLED_TOOL_CATALOG);
            }

            String toolName = requireToolIdentifier(
                    tool.get("name"),
                    FailureCode.INVALID_ENABLED_TOOL_CATALOG
            );
            if (!toolNames.add(toolName)) {
                throw failure(FailureCode.INVALID_ENABLED_TOOL_CATALOG);
            }

            String outputPointer = CUSTOMER_DATA_READ.equals(toolName)
                    ? CUSTOMER_OUTPUT_FIELDS_POINTER
                    : DEFAULT_OUTPUT_FIELDS_POINTER;
            JsonNode properties = tool.at(outputPointer);
            if (!properties.isObject() || properties.isEmpty()) {
                throw failure(FailureCode.INVALID_ENABLED_TOOL_CATALOG);
            }

            List<String> outputFields = new ArrayList<>();
            for (MapEntry field : fieldsOf(properties)) {
                if (!isExactNonBlank(field.name())) {
                    throw failure(FailureCode.INVALID_ENABLED_TOOL_CATALOG);
                }
                outputFields.add(field.name());
            }
            outputFields.sort(String::compareTo);
            enabledTools.add(new EnabledTool(toolName, outputFields));
        }

        enabledTools.sort(Comparator.comparing(EnabledTool::toolName));
        return List.copyOf(enabledTools);
    }

    private List<String> extractHighImpactTools(JsonNode serverCatalog) {
        JsonNode version = serverCatalog.get("version");
        if (version == null
                || !version.isString()
                || !SUPPORTED_SERVER_CATALOG_VERSION.equals(version.stringValue())) {
            throw failure(FailureCode.INVALID_HIGH_IMPACT_CATALOG);
        }

        JsonNode tools = serverCatalog.get("tools");
        if (tools == null || !tools.isArray() || tools.isEmpty()) {
            throw failure(FailureCode.INVALID_HIGH_IMPACT_CATALOG);
        }

        List<String> highImpactTools = new ArrayList<>();
        Set<String> toolNames = new HashSet<>();
        for (JsonNode tool : tools) {
            if (tool == null || !tool.isObject()) {
                throw failure(FailureCode.INVALID_HIGH_IMPACT_CATALOG);
            }

            String toolName = requireToolIdentifier(
                    tool.get("name"),
                    FailureCode.INVALID_HIGH_IMPACT_CATALOG
            );
            if (!toolNames.add(toolName)) {
                throw failure(FailureCode.INVALID_HIGH_IMPACT_CATALOG);
            }

            JsonNode agentExecutable = tool.get("agentExecutable");
            JsonNode executionBoundary = tool.get("executionBoundary");
            if (agentExecutable == null
                    || !agentExecutable.isBoolean()
                    || agentExecutable.booleanValue()
                    || executionBoundary == null
                    || !executionBoundary.isString()
                    || !"HUMAN_ONLY".equals(executionBoundary.stringValue())) {
                throw failure(FailureCode.INVALID_HIGH_IMPACT_CATALOG);
            }
            highImpactTools.add(toolName);
        }

        highImpactTools.sort(String::compareTo);
        return List.copyOf(highImpactTools);
    }

    private void rejectRoleOverlap(
            List<EnabledTool> enabledTools,
            List<String> highImpactTools
    ) {
        Set<String> enabledNames = new HashSet<>();
        enabledTools.forEach(tool -> enabledNames.add(tool.toolName()));
        if (highImpactTools.stream().anyMatch(enabledNames::contains)) {
            throw failure(FailureCode.CATALOG_ROLE_OVERLAP);
        }
    }

    private static String requireToolIdentifier(JsonNode value, FailureCode code) {
        if (value == null || !value.isString()) {
            throw failure(code);
        }
        String identifier = value.stringValue();
        if (!isExactNonBlank(identifier) || !TOOL_IDENTIFIER.matcher(identifier).matches()) {
            throw failure(code);
        }
        return identifier;
    }

    private static void requireDigest(String value, FailureCode code) {
        if (value == null || !DIGEST.matcher(value).matches()) {
            throw failure(code);
        }
    }

    private static boolean isExactNonBlank(String value) {
        return value != null && !value.isBlank() && value.equals(value.strip());
    }

    private static JsonNode snapshot(JsonNode value) {
        return value == null ? null : value.deepCopy();
    }

    private static List<MapEntry> fieldsOf(JsonNode object) {
        List<MapEntry> fields = new ArrayList<>();
        object.properties().forEach(entry -> fields.add(new MapEntry(entry.getKey())));
        return fields;
    }

    private static CatalogAdapterException failure(FailureCode code) {
        return new CatalogAdapterException(code);
    }

    private record MapEntry(String name) {
    }

    /**
     * Immutable source binding for semantic validation. This is not approval evidence.
     */
    public record SourceBoundCatalog(
            UUID releaseId,
            String manifestSchemaVersion,
            String agentArtifactFingerprint,
            String releaseFingerprint,
            String serverToolCatalogHash,
            ContractValidationCatalog semanticCatalog
    ) {

        public SourceBoundCatalog {
            Objects.requireNonNull(releaseId, "releaseId must not be null");
            if (!SUPPORTED_MANIFEST_VERSION.equals(manifestSchemaVersion)) {
                throw new IllegalArgumentException("manifestSchemaVersion is unsupported");
            }
            requireDigest(
                    agentArtifactFingerprint,
                    FailureCode.INVALID_AGENT_ARTIFACT_FINGERPRINT
            );
            requireDigest(
                    releaseFingerprint,
                    FailureCode.INVALID_RELEASE_FINGERPRINT
            );
            requireDigest(
                    serverToolCatalogHash,
                    FailureCode.INVALID_SERVER_CATALOG_HASH
            );
            Objects.requireNonNull(semanticCatalog, "semanticCatalog must not be null");
        }
    }

    public enum FailureCode {
        INVALID_REQUEST("Catalog adapter request is invalid"),
        SOURCE_LOAD_FAILURE("Verified Tool catalog source could not be loaded"),
        SOURCE_UNAVAILABLE("Verified Tool catalog source is unavailable"),
        SOURCE_SNAPSHOT_FAILURE("Verified Tool catalog source could not be snapshotted"),
        SOURCE_IDENTITY_MISMATCH("Verified Tool catalog identity does not match"),
        UNSUPPORTED_MANIFEST_VERSION("Verified Tool catalog version is unsupported"),
        INVALID_AGENT_ARTIFACT_FINGERPRINT("Agent artifact fingerprint is invalid"),
        INVALID_RELEASE_FINGERPRINT("Release fingerprint is invalid"),
        INVALID_SERVER_CATALOG_HASH("Server Tool catalog hash is invalid"),
        SERVER_CATALOG_HASH_MISMATCH("Server Tool catalog integrity check failed"),
        INVALID_ENABLED_TOOL_CATALOG("Enabled Tool catalog is invalid"),
        INVALID_HIGH_IMPACT_CATALOG("High-impact Tool catalog is invalid"),
        CATALOG_ROLE_OVERLAP("Tool catalog roles overlap");

        private final String safeMessage;

        FailureCode(String safeMessage) {
            this.safeMessage = safeMessage;
        }

        public String safeMessage() {
            return safeMessage;
        }
    }

    public static final class CatalogAdapterException extends RuntimeException {

        private final FailureCode code;

        private CatalogAdapterException(FailureCode code) {
            super(Objects.requireNonNull(code, "code must not be null").safeMessage());
            this.code = code;
        }

        public FailureCode code() {
            return code;
        }
    }
}
