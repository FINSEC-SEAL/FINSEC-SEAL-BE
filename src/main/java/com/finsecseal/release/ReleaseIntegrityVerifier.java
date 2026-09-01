package com.finsecseal.release;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ArtifactType;
import com.finsecseal.common.domain.Sensitivity;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

@Component
public class ReleaseIntegrityVerifier {

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final FingerprintService fingerprintService;
    private final DigestService digestService;

    public ReleaseIntegrityVerifier(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            FingerprintService fingerprintService,
            DigestService digestService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.fingerprintService = fingerprintService;
        this.digestService = digestService;
    }

    public void verify(UUID workspaceId, UUID releaseId, JsonNode normalizedManifest) {
        verifyArtifacts(releaseId, normalizedManifest);
        verifyToolCatalog(releaseId, normalizedManifest.path("tools"));
        verifyRagCatalog(workspaceId, releaseId, normalizedManifest.path("ragSources"));
    }

    private void verifyArtifacts(UUID releaseId, JsonNode manifest) {
        Map<ArtifactKey, ExpectedArtifact> expected = expectedArtifacts(manifest);
        List<ArtifactRow> actual = jdbcTemplate.query("""
                select artifact_type, name, content_json::text, content_text_encrypted, sha256,
                       canonicalization_version, sensitivity
                  from release_artifacts
                 where release_id = ?
                 order by artifact_type, name
                """, (resultSet, rowNumber) -> new ArtifactRow(
                        ArtifactType.valueOf(resultSet.getString("artifact_type")),
                        resultSet.getString("name"),
                        parseJson(resultSet.getString("content_json")),
                        resultSet.getString("content_text_encrypted"),
                        resultSet.getString("sha256"),
                        resultSet.getString("canonicalization_version"),
                        Sensitivity.valueOf(resultSet.getString("sensitivity"))
                ), releaseId);
        if (actual.size() != expected.size()) {
            changed("Release artifact count does not match the canonical manifest");
        }
        for (ArtifactRow row : actual) {
            ExpectedArtifact expectedArtifact = expected.remove(new ArtifactKey(row.type(), row.name()));
            if (expectedArtifact == null
                    || !expectedArtifact.content().equals(row.content())
                    || !expectedArtifact.sha256().equals(row.sha256())
                    || !CanonicalJsonService.VERSION.equals(row.canonicalizationVersion())
                    || expectedArtifact.sensitivity() != row.sensitivity()
                    || (expectedArtifact.encrypted()
                        ? row.encryptedText() == null || row.encryptedText().isBlank()
                        : row.encryptedText() != null)) {
                changed("Stored Release artifact differs from the canonical manifest");
            }
        }
        if (!expected.isEmpty()) {
            changed("A canonical Release artifact is missing");
        }
    }

    private Map<ArtifactKey, ExpectedArtifact> expectedArtifacts(JsonNode manifest) {
        Map<ArtifactKey, ExpectedArtifact> expected = new LinkedHashMap<>();
        addJson(expected, ArtifactType.MODEL_CONFIG, "model", manifest.path("model"));
        addJson(expected, ArtifactType.BUSINESS_PURPOSE, "business-purpose", manifest.path("businessPurpose"));
        addJson(expected, ArtifactType.RAG_CONFIG, "rag-sources", manifest.path("ragSources"));
        addJson(expected, ArtifactType.BUSINESS_WORKFLOW, "business-workflow", manifest.path("businessWorkflow"));
        addJson(expected, ArtifactType.HUMAN_BOUNDARY, "human-boundaries", manifest.path("humanApprovalBoundaries"));
        ObjectNode runtime = objectMapper.createObjectNode();
        runtime.set("runtimeContextRequirements", manifest.path("runtimeContextRequirements"));
        runtime.set("networkRequirements", manifest.path("networkRequirements"));
        addJson(expected, ArtifactType.RUNTIME_CONTEXT, "runtime-context", runtime);

        String prompt = manifest.at("/systemPrompt/text").asString();
        ObjectNode promptMetadata = objectMapper.createObjectNode();
        promptMetadata.put("length", prompt.length());
        promptMetadata.put("sha256", digestService.sha256(prompt));
        expected.put(
                new ArtifactKey(ArtifactType.SYSTEM_PROMPT, "system-prompt"),
                new ExpectedArtifact(promptMetadata, digestService.sha256(prompt), Sensitivity.SECRET, true)
        );

        JsonNode tools = manifest.path("tools");
        if (tools instanceof ArrayNode array) {
            array.forEach(tool -> {
                String name = tool.path("name").asString();
                ObjectNode schemas = objectMapper.createObjectNode();
                schemas.set("inputSchema", tool.path("inputSchema"));
                schemas.set("outputSchema", tool.path("outputSchema"));
                schemas.set("metadata", tool.deepCopy());
                schemas.remove("description");
                addJson(expected, ArtifactType.TOOL_SCHEMA, name, schemas);
                ObjectNode description = objectMapper.createObjectNode();
                description.put("description", tool.path("description").asString());
                addJson(expected, ArtifactType.TOOL_DESCRIPTION, name, description);
            });
        }
        return expected;
    }

    private void addJson(
            Map<ArtifactKey, ExpectedArtifact> expected,
            ArtifactType type,
            String name,
            JsonNode content
    ) {
        JsonNode copy = content.deepCopy();
        expected.put(
                new ArtifactKey(type, name),
                new ExpectedArtifact(copy, fingerprintService.hash(copy), Sensitivity.NORMAL, false)
        );
    }

    private void verifyToolCatalog(UUID releaseId, JsonNode tools) {
        List<ToolRow> actual = jdbcTemplate.query("""
                select definition.tool_key, definition.version, definition.operation,
                       definition.input_schema_json::text, definition.output_schema_json::text,
                       definition.description, definition.trust_level, definition.risk_level,
                       definition.data_classifications_json::text, definition.side_effect_type,
                       definition.adapter_key, definition.schema_hash, definition.description_hash,
                       link.enabled, link.ordinal
                  from release_tools link
                  join tool_definitions definition on definition.id = link.tool_definition_id
                 where link.release_id = ?
                 order by link.ordinal
                """, (resultSet, rowNumber) -> new ToolRow(
                        resultSet.getString("tool_key"),
                        resultSet.getString("version"),
                        resultSet.getString("operation"),
                        parseJson(resultSet.getString("input_schema_json")),
                        parseJson(resultSet.getString("output_schema_json")),
                        resultSet.getString("description"),
                        resultSet.getString("trust_level"),
                        resultSet.getString("risk_level"),
                        parseJson(resultSet.getString("data_classifications_json")),
                        resultSet.getString("side_effect_type"),
                        resultSet.getString("adapter_key"),
                        resultSet.getString("schema_hash"),
                        resultSet.getString("description_hash"),
                        resultSet.getBoolean("enabled"),
                        resultSet.getInt("ordinal")
                ), releaseId);
        if (!tools.isArray() || actual.size() != tools.size()) {
            changed("Release Tool catalog count does not match the canonical manifest");
        }
        for (int index = 0; index < actual.size(); index++) {
            ToolRow row = actual.get(index);
            JsonNode tool = tools.get(index);
            ObjectNode schemas = objectMapper.createObjectNode();
            schemas.set("inputSchema", tool.path("inputSchema"));
            schemas.set("outputSchema", tool.path("outputSchema"));
            ObjectNode description = objectMapper.createObjectNode();
            description.put("description", tool.path("description").asString());
            if (row.ordinal() != index || !row.enabled()
                    || !row.toolKey().equals(tool.path("name").asString())
                    || !row.version().equals(tool.path("version").asString())
                    || !row.operation().equals(tool.path("operation").asString())
                    || !row.inputSchema().equals(tool.path("inputSchema"))
                    || !row.outputSchema().equals(tool.path("outputSchema"))
                    || !row.description().equals(tool.path("description").asString())
                    || !row.trustLevel().equals(tool.path("trustLevel").asString())
                    || !row.riskLevel().equals(tool.path("riskLevel").asString())
                    || !row.classifications().equals(tool.path("dataClassifications"))
                    || !row.sideEffectType().equals(tool.path("sideEffectType").asString())
                    || !row.adapterKey().equals(tool.path("adapterKey").asString())
                    || !row.schemaHash().equals(fingerprintService.hash(schemas))
                    || !row.descriptionHash().equals(fingerprintService.hash(description))) {
                changed("Stored Release Tool catalog differs from the canonical manifest");
            }
        }
    }

    private void verifyRagCatalog(UUID workspaceId, UUID releaseId, JsonNode sources) {
        Map<String, RagRow> actual = new LinkedHashMap<>();
        jdbcTemplate.query("""
                select source.workspace_id, source.source_key, source.version, source.trust_level,
                       source.content_digest, source.config_json::text, link.retrieval_config_json::text,
                       link.config_hash
                  from release_rag_sources link
                  join rag_sources source on source.id = link.rag_source_id
                 where link.release_id = ?
                 order by source.source_key, source.version
                """, resultSet -> {
                    while (resultSet.next()) {
                        RagRow row = new RagRow(
                                resultSet.getObject("workspace_id", UUID.class),
                                resultSet.getString("source_key"),
                                resultSet.getString("version"),
                                resultSet.getString("trust_level"),
                                resultSet.getString("content_digest"),
                                parseJson(resultSet.getString("config_json")),
                                parseJson(resultSet.getString("retrieval_config_json")),
                                resultSet.getString("config_hash")
                        );
                        actual.put(row.sourceKey() + "@" + row.version(), row);
                    }
                    return null;
                }, releaseId);
        if (!sources.isArray() || actual.size() != sources.size()) {
            changed("Release RAG catalog count does not match the canonical manifest");
        }
        for (JsonNode source : sources) {
            String key = source.path("sourceId").asString() + "@" + source.path("version").asString();
            RagRow row = actual.remove(key);
            JsonNode retrievalConfig = source.path("retrievalConfig");
            if (row == null || !workspaceId.equals(row.workspaceId())
                    || !row.trustLevel().equals(source.path("trustLevel").asString())
                    || !row.contentDigest().equals(source.path("contentDigest").asString())
                    || !row.sourceConfig().equals(objectMapper.createObjectNode())
                    || !row.retrievalConfig().equals(retrievalConfig)
                    || !row.configHash().equals(fingerprintService.hash(retrievalConfig))) {
                changed("Stored Release RAG catalog differs from the canonical manifest");
            }
        }
        if (!actual.isEmpty()) {
            changed("Unexpected Release RAG catalog link exists");
        }
    }

    private JsonNode parseJson(String value) {
        if (value == null) {
            return objectMapper.nullNode();
        }
        try {
            return objectMapper.readTree(value);
        } catch (Exception exception) {
            throw new IllegalStateException("Stored Release integrity JSON is invalid", exception);
        }
    }

    private void changed(String message) {
        throw new BusinessException(ErrorCode.RELEASE_CHANGED, message);
    }

    private record ArtifactKey(ArtifactType type, String name) {
    }

    private record ExpectedArtifact(JsonNode content, String sha256, Sensitivity sensitivity, boolean encrypted) {
    }

    private record ArtifactRow(
            ArtifactType type,
            String name,
            JsonNode content,
            String encryptedText,
            String sha256,
            String canonicalizationVersion,
            Sensitivity sensitivity
    ) {
    }

    private record ToolRow(
            String toolKey,
            String version,
            String operation,
            JsonNode inputSchema,
            JsonNode outputSchema,
            String description,
            String trustLevel,
            String riskLevel,
            JsonNode classifications,
            String sideEffectType,
            String adapterKey,
            String schemaHash,
            String descriptionHash,
            boolean enabled,
            int ordinal
    ) {
    }

    private record RagRow(
            UUID workspaceId,
            String sourceKey,
            String version,
            String trustLevel,
            String contentDigest,
            JsonNode sourceConfig,
            JsonNode retrievalConfig,
            String configHash
    ) {
    }
}
