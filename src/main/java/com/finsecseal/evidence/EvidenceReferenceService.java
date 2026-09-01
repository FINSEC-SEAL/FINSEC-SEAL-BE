package com.finsecseal.evidence;

import com.finsecseal.audit.AuditService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.persistence.UuidV7;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Service
@Transactional(readOnly = true)
public class EvidenceReferenceService {

    private static final Set<String> OWNER_TYPES = Set.of(
            "EXECUTION_EVENT", "ORACLE_RESULT", "FINDING", "RELEASE_DECISION",
            "RELEASE_ATTESTATION", "TEST_RUN", "TEST_CASE_RUN", "CONTRACT_VERSION"
    );

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final RedactionService redactionService;
    private final AuditService auditService;

    public EvidenceReferenceService(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            RedactionService redactionService,
            AuditService auditService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.redactionService = redactionService;
        this.auditService = auditService;
    }

    @Transactional
    public EvidenceReferenceDto.Reference append(EvidenceReferenceDto.AppendRequest request, String actorId) {
        if (request == null || !OWNER_TYPES.contains(request.ownerType())) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "Unsupported evidence ownerType");
        }
        RedactionService.Result summary = redactionService.redact(request.summary());
        UUID workspaceId = jdbcTemplate.queryForObject(
                "select finsec_evidence_owner_workspace(?, ?)",
                UUID.class,
                request.ownerType(),
                request.ownerId()
        );
        UUID id = UuidV7.generate();
        Instant createdAt = Instant.now();
        jdbcTemplate.update("""
                insert into evidence_references
                    (id, workspace_id, owner_type, owner_id, evidence_type, source_event_id,
                     digest, redacted_summary_json, tested_at, created_at)
                values (?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?)
                """,
                id,
                workspaceId,
                request.ownerType(),
                request.ownerId(),
                request.evidenceType(),
                request.sourceEventId(),
                summary.originalDigest(),
                json(summary.redacted()),
                request.testedAt() == null ? null : Timestamp.from(request.testedAt()),
                Timestamp.from(createdAt)
        );

        ObjectNode auditMetadata = objectMapper.createObjectNode();
        auditMetadata.put("schemaVersion", "1.0");
        auditMetadata.put("ownerType", request.ownerType());
        auditMetadata.put("ownerId", request.ownerId().toString());
        auditMetadata.put("evidenceType", request.evidenceType());
        if (request.sourceEventId() != null) {
            auditMetadata.put("sourceEventId", request.sourceEventId().toString());
        }
        auditService.append(
                workspaceId,
                normalizeActor(actorId),
                "EVIDENCE_REFERENCE_APPENDED",
                "EVIDENCE_REFERENCE",
                id,
                null,
                summary.originalDigest(),
                auditMetadata
        );
        return new EvidenceReferenceDto.Reference(
                id,
                workspaceId,
                request.ownerType(),
                request.ownerId(),
                request.evidenceType(),
                request.sourceEventId(),
                summary.originalDigest(),
                summary.redacted(),
                request.testedAt(),
                createdAt
        );
    }

    public EvidenceReferenceDto.ListResponse find(String ownerType, UUID ownerId) {
        if (!OWNER_TYPES.contains(ownerType)) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "Unsupported evidence ownerType");
        }
        jdbcTemplate.queryForObject(
                "select finsec_evidence_owner_workspace(?, ?)",
                UUID.class,
                ownerType,
                ownerId
        );
        List<EvidenceReferenceDto.Reference> items = jdbcTemplate.query("""
                select id, workspace_id, owner_type, owner_id, evidence_type, source_event_id,
                       digest, redacted_summary_json::text, tested_at, created_at
                  from evidence_references
                 where owner_type = ? and owner_id = ?
                 order by created_at, id
                """, (resultSet, rowNumber) -> new EvidenceReferenceDto.Reference(
                        resultSet.getObject("id", UUID.class),
                        resultSet.getObject("workspace_id", UUID.class),
                        resultSet.getString("owner_type"),
                        resultSet.getObject("owner_id", UUID.class),
                        resultSet.getString("evidence_type"),
                        resultSet.getObject("source_event_id", UUID.class),
                        resultSet.getString("digest"),
                        parseJson(resultSet.getString("redacted_summary_json")),
                        resultSet.getTimestamp("tested_at") == null
                                ? null : resultSet.getTimestamp("tested_at").toInstant(),
                        resultSet.getTimestamp("created_at").toInstant()
                ), ownerType, ownerId);
        return new EvidenceReferenceDto.ListResponse(items);
    }

    private String normalizeActor(String actorId) {
        if (actorId == null || actorId.isBlank()) {
            return "system:evidence-producer";
        }
        if (actorId.length() > 120) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "X-Actor-Id exceeds 120 characters");
        }
        return actorId;
    }

    private String json(JsonNode value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception exception) {
            throw new IllegalArgumentException("Evidence JSON serialization failed", exception);
        }
    }

    private JsonNode parseJson(String value) {
        try {
            return objectMapper.readTree(value);
        } catch (Exception exception) {
            throw new IllegalStateException("Stored evidence JSON is invalid", exception);
        }
    }
}
