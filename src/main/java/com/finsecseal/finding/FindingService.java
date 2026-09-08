package com.finsecseal.finding;

import com.finsecseal.audit.AuditService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.persistence.UuidV7;
import com.finsecseal.evidence.RedactionService;
import com.finsecseal.oracle.application.OracleResultDto;
import com.finsecseal.oracle.application.OracleResultService;
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
    private final RedactionService redactionService;
    private final OracleResultService oracleResultService;

    public FindingService(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            DigestService digestService,
            AuditService auditService,
            RedactionService redactionService,
            OracleResultService oracleResultService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.digestService = digestService;
        this.auditService = auditService;
        this.redactionService = redactionService;
        this.oracleResultService = oracleResultService;
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

    public FindingDto.Detail findDetail(UUID findingId) {
        FindingDto.View finding = find(findingId);
        OracleResultDto.View oracleResult = oracleResultService.find(finding.sourceOracleResultId());
        List<FindingDto.View> related = finding.findingGroupKey() == null
                ? List.of()
                : findByRelease(
                        finding.releaseId(), null, null, finding.findingGroupKey()
                ).items().stream()
                        .filter(candidate -> !candidate.id().equals(finding.id()))
                        .toList();
        return new FindingDto.Detail(finding, oracleResult, related);
    }

    public FindingDto.ListResponse findByRelease(
            UUID releaseId,
            String category,
            String status,
            String findingGroupKey
    ) {
        if (releaseId == null) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "releaseId is required");
        }
        requireRelease(releaseId);
        String normalizedCategory = normalizeOptionalFilter(category, "category", 80);
        String normalizedStatus = normalizeOptionalFilter(status, "status", 30);
        String normalizedGroupKey = normalizeOptionalFilter(findingGroupKey, "findingGroupKey", 100);

        StringBuilder sql = new StringBuilder(selectSql()).append(" where finding.release_id = ?");
        List<Object> arguments = new java.util.ArrayList<>();
        arguments.add(releaseId);
        if (normalizedCategory != null) {
            sql.append(" and finding.category = ?");
            arguments.add(normalizedCategory);
        }
        if (normalizedStatus != null) {
            sql.append(" and finding.status = ?");
            arguments.add(normalizedStatus);
        }
        if (normalizedGroupKey != null) {
            sql.append(" and finding.finding_group_key = ?");
            arguments.add(normalizedGroupKey);
        }
        sql.append(" order by finding.created_at, finding.id");
        List<FindingDto.View> items = jdbcTemplate.query(
                sql.toString(), this::mapFinding, arguments.toArray()
        );
        return new FindingDto.ListResponse(List.copyOf(items));
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

    @Transactional
    public FindingDto.View triage(
            UUID findingId,
            FindingDto.TriageRequest request,
            String actorId
    ) {
        if (findingId == null || request == null) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "Finding and triage request are required");
        }
        String reviewer = requireReviewer(actorId, "triage");
        String comment = requireComment(request.comment(), "Triage");
        FindingDto.View before = findForUpdate(findingId);
        if (!"OPEN".equals(before.status())) {
            throw new BusinessException(
                    ErrorCode.INVALID_STATE_TRANSITION,
                    "Only an OPEN Finding can be triaged"
            );
        }

        Instant updatedAt = Instant.now();
        int updated = jdbcTemplate.update("""
                update findings
                   set status = 'TRIAGED', updated_at = ?
                 where id = ? and status = 'OPEN'
                """, Timestamp.from(updatedAt), findingId);
        if (updated != 1) {
            throw new BusinessException(ErrorCode.RESOURCE_CONFLICT, "Finding was changed concurrently");
        }

        ObjectNode rawMetadata = objectMapper.createObjectNode();
        rawMetadata.put("schemaVersion", "1.0");
        rawMetadata.put("fromStatus", "OPEN");
        rawMetadata.put("toStatus", "TRIAGED");
        rawMetadata.put("comment", comment);
        JsonNode safeMetadata = redactionService.redact(rawMetadata).redacted();
        UUID workspaceId = findWorkspaceId(before.releaseId());
        auditService.append(
                workspaceId,
                reviewer,
                "FINDING_TRIAGED",
                "FINDING",
                findingId,
                digestService.sha256("status=OPEN"),
                digestService.sha256("status=TRIAGED"),
                safeMetadata
        );
        return find(findingId);
    }

    @Transactional
    public FindingDto.View resolveFromReplay(
            UUID findingId,
            FindingDto.ResolveRequest request,
            String actorId
    ) {
        if (findingId == null || request == null || request.replayCaseRunId() == null) {
            throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    "Finding and replayCaseRunId are required"
            );
        }
        String reviewer = requireReviewer(actorId, "finding resolution");
        String comment = requireComment(request.comment(), "Resolution");
        FindingDto.View before = findForUpdate(findingId);
        if (!List.of("OPEN", "TRIAGED").contains(before.status())) {
            throw new BusinessException(
                    ErrorCode.INVALID_STATE_TRANSITION,
                    "Only an OPEN or TRIAGED Finding can be resolved"
            );
        }

        ReplayResolutionEvidence evidence = requireReplayResolutionEvidence(
                findingId,
                request.replayCaseRunId()
        );
        validateReplayResolutionEvidence(evidence);

        Instant updatedAt = Instant.now();
        int updated = jdbcTemplate.update("""
                update findings
                   set status = 'RESOLVED', latest_seen_run_id = ?, updated_at = ?
                 where id = ? and status in ('OPEN', 'TRIAGED')
                """, evidence.replayRunId(), Timestamp.from(updatedAt), findingId);
        if (updated != 1) {
            throw new BusinessException(ErrorCode.RESOURCE_CONFLICT, "Finding was changed concurrently");
        }

        ObjectNode rawMetadata = objectMapper.createObjectNode();
        rawMetadata.put("schemaVersion", "1.0");
        rawMetadata.put("fromStatus", before.status());
        rawMetadata.put("toStatus", "RESOLVED");
        rawMetadata.put("replayLinkId", evidence.replayLinkId().toString());
        rawMetadata.put("replayRunId", evidence.replayRunId().toString());
        rawMetadata.put("replayCaseRunId", request.replayCaseRunId().toString());
        rawMetadata.put("oracleResultId", evidence.replayOracleResultId().toString());
        rawMetadata.put("comment", comment);
        JsonNode safeMetadata = redactionService.redact(rawMetadata).redacted();
        auditService.append(
                findWorkspaceId(before.releaseId()),
                reviewer,
                "FINDING_RESOLVED",
                "FINDING",
                findingId,
                digestService.sha256("status=" + before.status()),
                digestService.sha256(
                        "status=RESOLVED|replayCaseRunId=" + request.replayCaseRunId()
                ),
                safeMetadata
        );
        return find(findingId);
    }

    private ReplayResolutionEvidence requireReplayResolutionEvidence(
            UUID findingId,
            UUID replayCaseRunId
    ) {
        List<ReplayResolutionEvidence> rows = jdbcTemplate.query("""
                select replay_link.id replay_link_id,
                       replay_run.id replay_run_id,
                       replay_run.mode replay_mode,
                       replay_run.status replay_run_status,
                       replay_case.status replay_case_status,
                       replay_case.security_outcome replay_security_outcome,
                       replay_link.same_agent_artifact_fingerprint,
                       replay_link.same_fixture_digest,
                       replay_link.same_model_config,
                       replay_link.same_variant_hash,
                       replay_link.expected_policy_difference,
                       replay_link.comparison_json::text comparison_json,
                       replay_oracle.id replay_oracle_result_id,
                       replay_oracle.outcome replay_outcome
                  from replay_links replay_link
                  join findings finding on finding.id = replay_link.finding_id
                  join oracle_results baseline_oracle
                    on baseline_oracle.id = finding.source_oracle_result_id
                  join test_case_runs replay_case
                    on replay_case.id = replay_link.replay_case_run_id
                  join test_runs replay_run on replay_run.id = replay_case.test_run_id
                  join oracle_results replay_oracle
                    on replay_oracle.test_case_run_id = replay_case.id
                   and replay_oracle.oracle_type = baseline_oracle.oracle_type
                   and replay_oracle.invariant_id = baseline_oracle.invariant_id
                 where replay_link.finding_id = ?
                   and replay_link.replay_case_run_id = ?
                """, (resultSet, rowNumber) -> new ReplayResolutionEvidence(
                resultSet.getObject("replay_link_id", UUID.class),
                resultSet.getObject("replay_run_id", UUID.class),
                resultSet.getString("replay_mode"),
                resultSet.getString("replay_run_status"),
                resultSet.getString("replay_case_status"),
                resultSet.getString("replay_security_outcome"),
                resultSet.getBoolean("same_agent_artifact_fingerprint"),
                resultSet.getBoolean("same_fixture_digest"),
                resultSet.getBoolean("same_model_config"),
                resultSet.getBoolean("same_variant_hash"),
                resultSet.getBoolean("expected_policy_difference"),
                parseJson(resultSet.getString("comparison_json")),
                resultSet.getObject("replay_oracle_result_id", UUID.class),
                OracleOutcome.valueOf(resultSet.getString("replay_outcome"))
        ), findingId, replayCaseRunId);
        if (rows.isEmpty()) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Matching Replay link and Oracle result are required to resolve the Finding"
            );
        }
        if (rows.size() != 1) {
            throw new BusinessException(
                    ErrorCode.RESOURCE_CONFLICT,
                    "Replay evidence is ambiguous for this Finding"
            );
        }
        return rows.getFirst();
    }

    private void validateReplayResolutionEvidence(ReplayResolutionEvidence evidence) {
        if (!"SEAL_REPLAY".equals(evidence.replayMode())
                || !"COMPLETED".equals(evidence.replayRunStatus())
                || !"PASSED".equals(evidence.replayCaseStatus())
                || !"ATTACK_BLOCKED".equals(evidence.replaySecurityOutcome())) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Finding resolution requires a completed, attack-blocking SEAL_REPLAY case"
            );
        }
        boolean flagsComparable = evidence.sameAgentArtifactFingerprint()
                && evidence.sameFixtureDigest()
                && evidence.sameModelConfig()
                && evidence.sameVariantHash()
                && evidence.expectedPolicyDifference();
        if (!flagsComparable || hasReplayMismatch(evidence.comparison())) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Finding resolution requires a comparable Replay result"
            );
        }
        if (evidence.replayOutcome() != OracleOutcome.ATTACK_BLOCKED) {
            throw new BusinessException(
                    ErrorCode.INVALID_STATE_TRANSITION,
                    "Finding can only be resolved when the Replay Oracle outcome is ATTACK_BLOCKED"
            );
        }
    }

    private boolean hasReplayMismatch(JsonNode comparison) {
        if (!comparison.path("comparable").asBoolean(true)) {
            return true;
        }
        for (String field : List.of("mismatchReasons", "mismatches")) {
            JsonNode values = comparison.path(field);
            if (values.isArray() && !values.isEmpty()) {
                return true;
            }
        }
        return false;
    }

    private FindingDto.View findForUpdate(UUID findingId) {
        List<FindingDto.View> findings = jdbcTemplate.query(
                selectSql() + " where finding.id = ? for update",
                this::mapFinding,
                findingId
        );
        if (findings.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "Finding not found");
        }
        return findings.getFirst();
    }

    private UUID findWorkspaceId(UUID releaseId) {
        return jdbcTemplate.queryForObject("""
                select agent.workspace_id
                  from agent_releases release
                  join agents agent on agent.id = release.agent_id
                 where release.id = ?
                """, UUID.class, releaseId);
    }

    private String requireReviewer(String actorId, String operation) {
        if (actorId == null || actorId.isBlank()) {
            throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    "X-Actor-Id is required for " + operation
            );
        }
        return normalizeActor(actorId);
    }

    private String requireComment(String comment, String operation) {
        if (comment == null || comment.isBlank()) {
            throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    operation + " comment must not be blank"
            );
        }
        String normalized = comment.strip();
        if (normalized.length() > 2000) {
            throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    operation + " comment exceeds 2000 characters"
            );
        }
        return normalized;
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

    private void requireRelease(UUID releaseId) {
        Integer count = jdbcTemplate.queryForObject(
                "select count(*) from agent_releases where id = ?",
                Integer.class,
                releaseId
        );
        if (count == null || count == 0) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "Release not found");
        }
    }

    private String normalizeOptionalFilter(String value, String fieldName, int maxLength) {
        if (value == null) {
            return null;
        }
        String normalized = value.strip();
        if (normalized.isEmpty() || normalized.length() > maxLength) {
            throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    fieldName + " must contain between 1 and " + maxLength + " characters"
            );
        }
        return normalized;
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

    private record ReplayResolutionEvidence(
            UUID replayLinkId,
            UUID replayRunId,
            String replayMode,
            String replayRunStatus,
            String replayCaseStatus,
            String replaySecurityOutcome,
            boolean sameAgentArtifactFingerprint,
            boolean sameFixtureDigest,
            boolean sameModelConfig,
            boolean sameVariantHash,
            boolean expectedPolicyDifference,
            JsonNode comparison,
            UUID replayOracleResultId,
            OracleOutcome replayOutcome
    ) {
    }
}
