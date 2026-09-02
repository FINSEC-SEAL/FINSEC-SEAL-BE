package com.finsecseal.oracle.application;

import com.finsecseal.audit.AuditService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.persistence.UuidV7;
import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleReasonCode;
import com.finsecseal.oracle.domain.OracleResult;
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
public class OracleResultService {

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final AuditService auditService;

    public OracleResultService(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            AuditService auditService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.auditService = auditService;
    }

    @Transactional
    Stored persist(
            UUID testCaseRunId,
            UUID sourceEventId,
            OracleResult result,
            String actorId
    ) {
        if (testCaseRunId == null || result == null) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "TestCaseRun and OracleResult are required");
        }
        CaseContext context = findContext(testCaseRunId);
        validateSourceEvent(context, testCaseRunId, sourceEventId, result);
        UUID resultId = UuidV7.generate();
        Instant createdAt = Instant.now();
        JsonNode evidence = objectMapper.valueToTree(result.evidence());

        int inserted = jdbcTemplate.update("""
                insert into oracle_results
                    (id, test_case_run_id, source_event_id, oracle_type, oracle_version, outcome,
                     reason_code, invariant_id, evidence_json, evidence_digest, evaluated_at, created_at, updated_at)
                values (?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?)
                on conflict (test_case_run_id, oracle_type, invariant_id) do nothing
                """,
                resultId,
                testCaseRunId,
                sourceEventId,
                result.oracleType().name(),
                result.oracleVersion(),
                result.outcome().name(),
                result.reasonCode().name(),
                result.invariantId(),
                json(evidence),
                result.evidenceDigest(),
                Timestamp.from(result.evaluatedAt()),
                Timestamp.from(createdAt),
                Timestamp.from(createdAt)
        );

        OracleResultDto.View stored = findByCaseAndIdentity(
                testCaseRunId,
                result.oracleType().name(),
                result.invariantId()
        );
        verifyRetryMatches(stored, sourceEventId, result);

        if (inserted == 1) {
            ObjectNode auditMetadata = objectMapper.createObjectNode();
            auditMetadata.put("schemaVersion", "1.0");
            auditMetadata.put("runId", context.runId().toString());
            auditMetadata.put("testCaseRunId", testCaseRunId.toString());
            auditMetadata.put("oracleType", result.oracleType().name());
            auditMetadata.put("outcome", result.outcome().name());
            auditMetadata.put("reasonCode", result.reasonCode().name());
            auditService.append(
                    context.workspaceId(),
                    normalizeActor(actorId),
                    "ORACLE_RESULT_RECORDED",
                    "ORACLE_RESULT",
                    stored.id(),
                    null,
                    result.evidenceDigest(),
                    auditMetadata
            );
        }
        return new Stored(stored, context, inserted == 1);
    }

    public OracleResultDto.View find(UUID resultId) {
        List<OracleResultDto.View> results = jdbcTemplate.query(
                selectSql() + " where result.id = ?",
                this::mapResult,
                resultId
        );
        if (results.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "OracleResult not found");
        }
        return results.getFirst();
    }

    public OracleResultDto.ListResponse findByRun(UUID runId, UUID testCaseRunId) {
        requireRun(runId);
        String where = testCaseRunId == null
                ? " where case_run.test_run_id = ?"
                : " where case_run.test_run_id = ? and result.test_case_run_id = ?";
        Object[] arguments = testCaseRunId == null
                ? new Object[]{runId}
                : new Object[]{runId, testCaseRunId};
        List<OracleResultDto.View> items = jdbcTemplate.query(
                selectSql() + where + " order by result.evaluated_at, result.id",
                this::mapResult,
                arguments
        );
        return new OracleResultDto.ListResponse(List.copyOf(items));
    }

    private OracleResultDto.View findByCaseAndIdentity(
            UUID testCaseRunId,
            String oracleType,
            String invariantId
    ) {
        List<OracleResultDto.View> results = jdbcTemplate.query(
                selectSql() + """
                         where result.test_case_run_id = ?
                           and result.oracle_type = ?
                           and result.invariant_id = ?
                        """,
                this::mapResult,
                testCaseRunId,
                oracleType,
                invariantId
        );
        if (results.isEmpty()) {
            throw new BusinessException(ErrorCode.INTERNAL_ERROR, "OracleResult insert was not materialized");
        }
        return results.getFirst();
    }

    private CaseContext findContext(UUID testCaseRunId) {
        List<CaseContext> contexts = jdbcTemplate.query("""
                select agent.workspace_id, run.id as run_id, run.release_id,
                       case_run.test_case_id, test_case.category, test_case.severity
                  from test_case_runs case_run
                  join test_runs run on run.id = case_run.test_run_id
                  join agent_releases release on release.id = run.release_id
                  join agents agent on agent.id = release.agent_id
                  join test_cases test_case on test_case.id = case_run.test_case_id
                 where case_run.id = ?
                """, (resultSet, rowNumber) -> new CaseContext(
                resultSet.getObject("workspace_id", UUID.class),
                resultSet.getObject("run_id", UUID.class),
                resultSet.getObject("release_id", UUID.class),
                resultSet.getObject("test_case_id", UUID.class),
                resultSet.getString("category"),
                resultSet.getString("severity")
        ), testCaseRunId);
        if (contexts.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "TestCaseRun not found");
        }
        return contexts.getFirst();
    }

    private void validateSourceEvent(
            CaseContext context,
            UUID testCaseRunId,
            UUID sourceEventId,
            OracleResult result
    ) {
        if (sourceEventId == null) {
            if (result.outcome() != OracleOutcome.INCONCLUSIVE) {
                throw new BusinessException(
                        ErrorCode.EVIDENCE_INCOMPLETE,
                        "A conclusive OracleResult requires a source ExecutionEvent"
                );
            }
            return;
        }
        List<ExecutionEventType> eventTypes = jdbcTemplate.query("""
                select event_type from execution_events
                 where id = ? and run_id = ? and test_case_run_id = ?
                """, (resultSet, rowNumber) -> ExecutionEventType.valueOf(resultSet.getString("event_type")),
                sourceEventId, context.runId(), testCaseRunId);
        if (eventTypes.isEmpty()) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Oracle source event must belong to the same TestCaseRun"
            );
        }
        ExecutionEventType sourceType = eventTypes.getFirst();
        if (result.outcome() == OracleOutcome.ATTACK_SUCCESS
                && sourceType != ExecutionEventType.TOOL_RESPONSE) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "ATTACK_SUCCESS requires a TOOL_RESPONSE source event"
            );
        }
        if (result.outcome() == OracleOutcome.ATTACK_BLOCKED
                && result.reasonCode() == OracleReasonCode.POLICY_DENIED_BEFORE_API
                && sourceType != ExecutionEventType.POLICY_EVALUATED) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "A policy-denied ATTACK_BLOCKED result requires a POLICY_EVALUATED source event"
            );
        }
    }

    private void verifyRetryMatches(
            OracleResultDto.View stored,
            UUID sourceEventId,
            OracleResult requested
    ) {
        boolean same = java.util.Objects.equals(stored.sourceEventId(), sourceEventId)
                && stored.oracleVersion().equals(requested.oracleVersion())
                && stored.outcome() == requested.outcome()
                && stored.reasonCode() == requested.reasonCode()
                && stored.evidenceDigest().equals(requested.evidenceDigest());
        if (!same) {
            throw new BusinessException(
                    ErrorCode.RESOURCE_CONFLICT,
                    "A different OracleResult already exists for this case, Oracle, and invariant"
            );
        }
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
                select result.id, case_run.test_run_id, result.test_case_run_id, result.source_event_id,
                       result.oracle_type, result.oracle_version, result.outcome, result.reason_code,
                       result.invariant_id, result.evidence_json::text, result.evidence_digest,
                       result.evaluated_at, result.created_at
                  from oracle_results result
                  join test_case_runs case_run on case_run.id = result.test_case_run_id
                """;
    }

    private OracleResultDto.View mapResult(java.sql.ResultSet resultSet, int rowNumber)
            throws java.sql.SQLException {
        return new OracleResultDto.View(
                resultSet.getObject("id", UUID.class),
                resultSet.getObject("test_run_id", UUID.class),
                resultSet.getObject("test_case_run_id", UUID.class),
                resultSet.getObject("source_event_id", UUID.class),
                com.finsecseal.oracle.domain.OracleType.valueOf(resultSet.getString("oracle_type")),
                resultSet.getString("oracle_version"),
                com.finsecseal.oracle.domain.OracleOutcome.valueOf(resultSet.getString("outcome")),
                com.finsecseal.oracle.domain.OracleReasonCode.valueOf(resultSet.getString("reason_code")),
                resultSet.getString("invariant_id"),
                parseJson(resultSet.getString("evidence_json")),
                resultSet.getString("evidence_digest"),
                resultSet.getTimestamp("evaluated_at").toInstant(),
                resultSet.getTimestamp("created_at").toInstant()
        );
    }

    private String normalizeActor(String actorId) {
        if (actorId == null || actorId.isBlank()) {
            return "system:oracle";
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
            throw new IllegalArgumentException("Oracle evidence serialization failed", exception);
        }
    }

    private JsonNode parseJson(String value) {
        try {
            return objectMapper.readTree(value);
        } catch (Exception exception) {
            throw new IllegalStateException("Stored Oracle evidence is invalid", exception);
        }
    }

    record CaseContext(
            UUID workspaceId,
            UUID runId,
            UUID releaseId,
            UUID testCaseId,
            String category,
            String severity
    ) {
    }

    record Stored(OracleResultDto.View result, CaseContext context, boolean created) {
    }
}
