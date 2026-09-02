package com.finsecseal.finding;

import com.finsecseal.audit.AuditService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.persistence.UuidV7;
import com.finsecseal.oracle.application.OracleResultDto;
import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleReasonCode;
import com.finsecseal.release.DigestService;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Service
@Transactional(readOnly = true)
public class FindingService {

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final DigestService digestService;
    private final AuditService auditService;

    public FindingService(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            DigestService digestService,
            AuditService auditService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.digestService = digestService;
        this.auditService = auditService;
    }

    @Transactional
    public Stored createFromAttackSuccess(
            OracleResultDto.View oracleResult,
            Context context,
            String actorId
    ) {
        if (oracleResult.outcome() != OracleOutcome.ATTACK_SUCCESS) {
            throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    "Finding can only be created from an ATTACK_SUCCESS OracleResult"
            );
        }
        UUID findingId = UuidV7.generate();
        Instant createdAt = Instant.now();
        ObjectNode rootCause = rootCause(oracleResult);
        String groupKey = digestService.sha256(
                context.category() + '|' + oracleResult.invariantId() + '|' + oracleResult.reasonCode().name()
        );

        int inserted = jdbcTemplate.update("""
                insert into findings
                    (id, release_id, source_oracle_result_id, category, severity, title, status,
                     violated_invariant, root_cause_json, finding_group_key, first_seen_run_id,
                     latest_seen_run_id, created_at, updated_at)
                values (?, ?, ?, ?, ?, ?, 'OPEN', ?, ?::jsonb, ?, ?, ?, ?, ?)
                on conflict (source_oracle_result_id) do nothing
                """,
                findingId,
                context.releaseId(),
                oracleResult.id(),
                context.category(),
                context.severity(),
                title(oracleResult.reasonCode()),
                oracleResult.invariantId(),
                json(rootCause),
                groupKey,
                context.runId(),
                context.runId(),
                Timestamp.from(createdAt),
                Timestamp.from(createdAt)
        );

        FindingDto.View stored = findByOracleResult(oracleResult.id());
        if (inserted == 1) {
            ObjectNode auditMetadata = objectMapper.createObjectNode();
            auditMetadata.put("schemaVersion", "1.0");
            auditMetadata.put("runId", context.runId().toString());
            auditMetadata.put("oracleResultId", oracleResult.id().toString());
            auditMetadata.put("category", context.category());
            auditMetadata.put("severity", context.severity());
            auditService.append(
                    context.workspaceId(),
                    normalizeActor(actorId),
                    "FINDING_CREATED",
                    "FINDING",
                    stored.id(),
                    null,
                    oracleResult.evidenceDigest(),
                    auditMetadata
            );
        }
        return new Stored(stored, inserted == 1);
    }

    public FindingDto.View find(UUID findingId) {
        List<FindingDto.View> findings = jdbcTemplate.query(
                selectSql() + " where finding.id = ?",
                this::mapFinding,
                findingId
        );
        if (findings.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "Finding not found");
        }
        return findings.getFirst();
    }

    public FindingDto.ListResponse findByRun(UUID runId) {
        requireRun(runId);
        List<FindingDto.View> items = jdbcTemplate.query(
                selectSql() + """
                         join oracle_results oracle on oracle.id = finding.source_oracle_result_id
                         join test_case_runs case_run on case_run.id = oracle.test_case_run_id
                        where case_run.test_run_id = ?
                        order by finding.created_at, finding.id
                        """,
                this::mapFinding,
                runId
        );
        return new FindingDto.ListResponse(List.copyOf(items));
    }

    private FindingDto.View findByOracleResult(UUID oracleResultId) {
        List<FindingDto.View> findings = jdbcTemplate.query(
                selectSql() + " where finding.source_oracle_result_id = ?",
                this::mapFinding,
                oracleResultId
        );
        if (findings.isEmpty()) {
            throw new BusinessException(ErrorCode.INTERNAL_ERROR, "Finding insert was not materialized");
        }
        return findings.getFirst();
    }

    private ObjectNode rootCause(OracleResultDto.View oracleResult) {
        ObjectNode rootCause = objectMapper.createObjectNode();
        rootCause.put("schemaVersion", "1.0");
        rootCause.put("oracleType", oracleResult.oracleType().name());
        rootCause.put("reasonCode", oracleResult.reasonCode().name());
        rootCause.put("invariantId", oracleResult.invariantId());
        rootCause.put("evidenceDigest", oracleResult.evidenceDigest());
        if (oracleResult.sourceEventId() != null) {
            rootCause.put("sourceEventId", oracleResult.sourceEventId().toString());
        }
        return rootCause;
    }

    private String title(OracleReasonCode reasonCode) {
        return switch (reasonCode) {
            case UNAUTHORIZED_RECORD_RETURNED -> "Unauthorized customer record returned";
            case CRITICAL_FIELD_EXPOSED -> "Critical customer field exposed";
            case SENSITIVE_FIELD_EXPOSED -> "Sensitive customer field exposed";
            case EXFIL_PAYLOAD_RECEIVED -> "Classified data received by external collector";
            case HIGH_IMPACT_STATE_MUTATED -> "Human-only loan decision mutated";
            default -> "Security invariant violation detected";
        };
    }

    private void requireRun(UUID runId) {
        Integer count = jdbcTemplate.queryForObject(
                "select count(*) from test_runs where id = ?",
                Integer.class,
                runId
        );
        if (count == null || count == 0) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "TestRun not found");
        }
    }

    private String selectSql() {
        return """
                select finding.id, finding.release_id, finding.source_oracle_result_id,
                       finding.category, finding.severity, finding.title, finding.status,
                       finding.violated_invariant, finding.root_cause_json::text,
                       finding.finding_group_key, finding.first_seen_run_id,
                       finding.latest_seen_run_id, finding.created_at, finding.updated_at
                  from findings finding
                """;
    }

    private FindingDto.View mapFinding(java.sql.ResultSet resultSet, int rowNumber)
            throws java.sql.SQLException {
        return new FindingDto.View(
                resultSet.getObject("id", UUID.class),
                resultSet.getObject("release_id", UUID.class),
                resultSet.getObject("source_oracle_result_id", UUID.class),
                resultSet.getString("category"),
                resultSet.getString("severity"),
                resultSet.getString("title"),
                resultSet.getString("status"),
                resultSet.getString("violated_invariant"),
                parseJson(resultSet.getString("root_cause_json")),
                resultSet.getString("finding_group_key"),
                resultSet.getObject("first_seen_run_id", UUID.class),
                resultSet.getObject("latest_seen_run_id", UUID.class),
                resultSet.getTimestamp("created_at").toInstant(),
                resultSet.getTimestamp("updated_at").toInstant()
        );
    }

    private String normalizeActor(String actorId) {
        if (actorId == null || actorId.isBlank()) {
            return "system:finding";
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
            throw new IllegalArgumentException("Finding JSON serialization failed", exception);
        }
    }

    private JsonNode parseJson(String value) {
        try {
            return objectMapper.readTree(value);
        } catch (Exception exception) {
            throw new IllegalStateException("Stored Finding JSON is invalid", exception);
        }
    }

    public record Context(
            UUID workspaceId,
            UUID runId,
            UUID releaseId,
            String category,
            String severity
    ) {
    }

    public record Stored(FindingDto.View finding, boolean created) {
    }
}
