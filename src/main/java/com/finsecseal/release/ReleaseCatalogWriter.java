package com.finsecseal.release;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.persistence.UuidV7;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Component
public class ReleaseCatalogWriter {

    private final JdbcTemplate jdbcTemplate;
    private final FingerprintService fingerprintService;
    private final ObjectMapper objectMapper;

    public ReleaseCatalogWriter(
            JdbcTemplate jdbcTemplate,
            FingerprintService fingerprintService,
            ObjectMapper objectMapper
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.fingerprintService = fingerprintService;
        this.objectMapper = objectMapper;
    }

    public void write(UUID workspaceId, UUID releaseId, JsonNode normalizedManifest) {
        writeTools(releaseId, normalizedManifest.path("tools"));
        writeRagSources(workspaceId, releaseId, normalizedManifest.path("ragSources"));
    }

    private void writeTools(UUID releaseId, JsonNode tools) {
        for (int ordinal = 0; ordinal < tools.size(); ordinal++) {
            JsonNode tool = tools.get(ordinal);
            ObjectNode schemas = objectMapper.createObjectNode();
            schemas.set("inputSchema", tool.path("inputSchema"));
            schemas.set("outputSchema", tool.path("outputSchema"));
            ObjectNode description = objectMapper.createObjectNode();
            description.put("description", tool.path("description").asString());

            UUID candidateId = UuidV7.generate();
            jdbcTemplate.update("""
                    insert into tool_definitions
                        (id, tool_key, version, operation, input_schema_json, output_schema_json,
                         description, trust_level, risk_level, data_classifications_json,
                         side_effect_type, adapter_key, schema_hash, description_hash)
                    values
                        (?, ?, ?, ?, cast(? as jsonb), cast(? as jsonb), ?, ?, ?, cast(? as jsonb),
                         ?, ?, ?, ?)
                    on conflict (tool_key, version) do nothing
                    """,
                    candidateId,
                    tool.path("name").asString(),
                    tool.path("version").asString(),
                    tool.path("operation").asString(),
                    tool.path("inputSchema").toString(),
                    tool.path("outputSchema").toString(),
                    tool.path("description").asString(),
                    tool.path("trustLevel").asString(),
                    tool.path("riskLevel").asString(),
                    tool.path("dataClassifications").toString(),
                    tool.path("sideEffectType").asString(),
                    tool.path("adapterKey").asString(),
                    fingerprintService.hash(schemas),
                    fingerprintService.hash(description)
            );

            UUID definitionId = jdbcTemplate.query("""
                    select id from tool_definitions
                     where tool_key = ? and version = ? and operation = ?
                       and input_schema_json = cast(? as jsonb)
                       and output_schema_json = cast(? as jsonb)
                       and description = ? and trust_level = ? and risk_level = ?
                       and data_classifications_json = cast(? as jsonb)
                       and side_effect_type = ? and adapter_key = ?
                       and schema_hash = ? and description_hash = ?
                    """, resultSet -> resultSet.next() ? resultSet.getObject("id", UUID.class) : null,
                    tool.path("name").asString(),
                    tool.path("version").asString(),
                    tool.path("operation").asString(),
                    tool.path("inputSchema").toString(),
                    tool.path("outputSchema").toString(),
                    tool.path("description").asString(),
                    tool.path("trustLevel").asString(),
                    tool.path("riskLevel").asString(),
                    tool.path("dataClassifications").toString(),
                    tool.path("sideEffectType").asString(),
                    tool.path("adapterKey").asString(),
                    fingerprintService.hash(schemas),
                    fingerprintService.hash(description)
            );
            if (definitionId == null) {
                throw new BusinessException(
                        ErrorCode.MANIFEST_INVALID,
                        "Tool name/version conflicts with an immutable catalog definition: "
                                + tool.path("name").asString() + "@" + tool.path("version").asString()
                );
            }
            jdbcTemplate.update("""
                    insert into release_tools (release_id, tool_definition_id, enabled, ordinal)
                    values (?, ?, true, ?)
                    """, releaseId, definitionId, ordinal);
        }
    }

    private void writeRagSources(UUID workspaceId, UUID releaseId, JsonNode sources) {
        for (JsonNode source : sources) {
            UUID candidateId = UuidV7.generate();
            jdbcTemplate.update("""
                    insert into rag_sources
                        (id, workspace_id, source_key, version, trust_level, content_digest, config_json)
                    values (?, ?, ?, ?, ?, ?, '{}'::jsonb)
                    on conflict (workspace_id, source_key, version) do nothing
                    """,
                    candidateId,
                    workspaceId,
                    source.path("sourceId").asString(),
                    source.path("version").asString(),
                    source.path("trustLevel").asString(),
                    source.path("contentDigest").asString()
            );
            UUID sourceId = jdbcTemplate.query("""
                    select id from rag_sources
                     where workspace_id = ? and source_key = ? and version = ?
                       and trust_level = ? and content_digest = ?
                    """, resultSet -> resultSet.next() ? resultSet.getObject("id", UUID.class) : null,
                    workspaceId,
                    source.path("sourceId").asString(),
                    source.path("version").asString(),
                    source.path("trustLevel").asString(),
                    source.path("contentDigest").asString()
            );
            if (sourceId == null) {
                throw new BusinessException(
                        ErrorCode.MANIFEST_INVALID,
                        "RAG source/version conflicts with an immutable catalog definition: "
                                + source.path("sourceId").asString() + "@" + source.path("version").asString()
                );
            }
            JsonNode retrievalConfig = source.path("retrievalConfig");
            jdbcTemplate.update("""
                    insert into release_rag_sources
                        (release_id, rag_source_id, retrieval_config_json, config_hash)
                    values (?, ?, cast(? as jsonb), ?)
                    """, releaseId, sourceId, retrievalConfig.toString(), fingerprintService.hash(retrievalConfig));
        }
    }
}
