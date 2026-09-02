package com.finsecseal.audit;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.persistence.UuidV7;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.annotation.Propagation;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Service
@Transactional(readOnly = true)
public class AuditService {

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public AuditService(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public AuditDto.Record append(
            UUID workspaceId,
            String actorId,
            String action,
            String resourceType,
            UUID resourceId,
            String beforeDigest,
            String afterDigest,
            JsonNode metadata
    ) {
        String safeActor = requireText(actorId, "actorId", 120);
        String safeAction = requireText(action, "action", 100);
        String safeResourceType = requireText(resourceType, "resourceType", 80);
        UUID id = UuidV7.generate();
        Instant occurredAt = Instant.now();
        JsonNode safeMetadata = metadata == null ? objectMapper.createObjectNode() : metadata.deepCopy();
        jdbcTemplate.update("""
                insert into audit_records
                    (id, workspace_id, actor_id, action, resource_type, resource_id,
                     before_digest, after_digest, metadata_json, occurred_at)
                values (?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?)
                """,
                id,
                workspaceId,
                safeActor,
                safeAction,
                safeResourceType,
                resourceId,
                beforeDigest,
                afterDigest,
                json(safeMetadata),
                Timestamp.from(occurredAt)
        );
        return new AuditDto.Record(
                id,
                workspaceId,
                safeActor,
                safeAction,
                safeResourceType,
                resourceId,
                beforeDigest,
                afterDigest,
                safeMetadata,
                occurredAt
        );
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public AuditDto.Record appendRequiresNew(
            UUID workspaceId,
            String actorId,
            String action,
            String resourceType,
            UUID resourceId,
            String beforeDigest,
            String afterDigest,
            JsonNode metadata
    ) {
        return append(
                workspaceId, actorId, action, resourceType, resourceId,
                beforeDigest, afterDigest, metadata
        );
    }

    public List<AuditDto.Record> find(String resourceType, UUID resourceId, int limit) {
        if (limit < 1 || limit > 100) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "limit must be between 1 and 100");
        }
        return jdbcTemplate.query("""
                select id, workspace_id, actor_id, action, resource_type, resource_id,
                       before_digest, after_digest, metadata_json::text, occurred_at
                  from audit_records
                 where resource_type = ? and resource_id = ?
                 order by occurred_at desc, id desc
                 limit ?
                """, (resultSet, rowNumber) -> new AuditDto.Record(
                        resultSet.getObject("id", UUID.class),
                        resultSet.getObject("workspace_id", UUID.class),
                        resultSet.getString("actor_id"),
                        resultSet.getString("action"),
                        resultSet.getString("resource_type"),
                        resultSet.getObject("resource_id", UUID.class),
                        resultSet.getString("before_digest"),
                        resultSet.getString("after_digest"),
                        parseJson(resultSet.getString("metadata_json")),
                        resultSet.getTimestamp("occurred_at").toInstant()
                ), resourceType, resourceId, limit);
    }

    private String requireText(String value, String field, int maxLength) {
        if (value == null || value.isBlank() || value.length() > maxLength) {
            throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    field + " is required and must not exceed " + maxLength + " characters"
            );
        }
        return value;
    }

    private String json(JsonNode value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception exception) {
            throw new IllegalArgumentException("Audit metadata serialization failed", exception);
        }
    }

    private JsonNode parseJson(String value) {
        try {
            return objectMapper.readTree(value);
        } catch (Exception exception) {
            throw new IllegalStateException("Stored audit metadata is invalid", exception);
        }
    }
}
