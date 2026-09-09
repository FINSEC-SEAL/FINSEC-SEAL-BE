package com.finsecseal.assurance;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleReasonCode;
import com.finsecseal.oracle.domain.OracleType;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Service
@Transactional(readOnly = true)
public class ReplayComparisonService {

    private static final Set<String> TERMINAL_CASE_STATUSES = Set.of(
            "PASSED", "FAILED_SECURITY", "FAILED_FUNCTIONAL", "ERROR", "CANCELLED"
    );

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public ReplayComparisonService(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    public ReplayComparisonDto.Detail find(UUID replayRunId) {
        requireReplayRun(replayRunId);
        List<LinkRow> links = jdbcTemplate.query("""
                select replay_link.id replay_link_id, replay_link.finding_id,
                       finding.release_id, finding.category, finding.severity,
                       replay_link.baseline_case_run_id, replay_link.replay_case_run_id,
                       baseline_case.test_run_id baseline_run_id,
                       replay_case.test_run_id replay_run_id,
                       replay_link.same_agent_artifact_fingerprint,
                       replay_link.same_fixture_digest, replay_link.same_model_config,
                       replay_link.same_variant_hash, replay_link.expected_policy_difference,
                       replay_link.comparison_json::text comparison_json,
                       replay_oracle.id replay_matching_oracle_id
                  from replay_links replay_link
                  join findings finding on finding.id = replay_link.finding_id
                  join oracle_results baseline_oracle
                    on baseline_oracle.id = finding.source_oracle_result_id
                  join test_case_runs baseline_case
                    on baseline_case.id = replay_link.baseline_case_run_id
                  join test_case_runs replay_case
                    on replay_case.id = replay_link.replay_case_run_id
                  left join oracle_results replay_oracle
                    on replay_oracle.test_case_run_id = replay_case.id
                   and replay_oracle.oracle_type = baseline_oracle.oracle_type
                   and replay_oracle.invariant_id = baseline_oracle.invariant_id
                 where replay_case.test_run_id = ?
                """, (resultSet, rowNumber) -> mapLink(resultSet), replayRunId);
        if (links.isEmpty()) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Replay comparison link is not available"
            );
        }
        if (links.size() != 1) {
            throw new BusinessException(
                    ErrorCode.RESOURCE_CONFLICT,
                    "Replay Run must resolve to exactly one comparison pair"
            );
        }

        LinkRow link = links.getFirst();
        ReplayComparisonDto.Side baseline = loadSide(link.baselineRunId(), link.baselineCaseRunId());
        ReplayComparisonDto.Side replay = loadSide(link.replayRunId(), link.replayCaseRunId());
        validateComplete(link, baseline, replay);
        ComparisonStatus status = comparisonStatus(link);

        return new ReplayComparisonDto.Detail(
                replayRunId,
                link.replayLinkId(),
                link.findingId(),
                link.releaseId(),
                link.category(),
                link.severity(),
                status.comparable(),
                status.mismatchReasons(),
                baseline,
                replay,
                difference(baseline, replay)
        );
    }

    private void requireReplayRun(UUID replayRunId) {
        if (replayRunId == null) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "replayRunId is required");
        }
        List<String> modes = jdbcTemplate.queryForList(
                "select mode from test_runs where id = ?",
                String.class,
                replayRunId
        );
        if (modes.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "Replay Run not found");
        }
        if (!"SEAL_REPLAY".equals(modes.getFirst())) {
            throw new BusinessException(ErrorCode.RESOURCE_CONFLICT, "Run is not a SEAL_REPLAY");
        }
    }

    private ReplayComparisonDto.Side loadSide(UUID runId, UUID caseRunId) {
        List<SideRow> rows = jdbcTemplate.query("""
                select run.mode, run.status run_status, case_run.status case_status,
                       case_run.security_outcome, case_run.functional_outcome
                  from test_runs run
                  join test_case_runs case_run on case_run.test_run_id = run.id
                 where run.id = ? and case_run.id = ?
                """, (resultSet, rowNumber) -> new SideRow(
                        TestRunMode.valueOf(resultSet.getString("mode")),
                        TestRunStatus.valueOf(resultSet.getString("run_status")),
                        TestCaseRunStatus.valueOf(resultSet.getString("case_status")),
                        resultSet.getString("security_outcome"),
                        resultSet.getString("functional_outcome")
                ), runId, caseRunId);
        if (rows.isEmpty()) {
            throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, "Replay pair references a missing CaseRun");
        }
        SideRow row = rows.getFirst();
        List<ReplayComparisonDto.EventEvidence> policy = loadEvents(runId, caseRunId, "POLICY_EVALUATED");
        List<ReplayComparisonDto.EventEvidence> responses = loadEvents(runId, caseRunId, "TOOL_RESPONSE");
        List<ReplayComparisonDto.EventEvidence> state = loadEvents(runId, caseRunId, "SANDBOX_STATE_CHANGED");
        List<ReplayComparisonDto.OracleSummary> oracles = loadOracles(caseRunId);
        return new ReplayComparisonDto.Side(
                runId, caseRunId, row.mode(), row.runStatus(), row.caseStatus(),
                row.securityOutcome(), row.functionalOutcome(), policy, responses, state, oracles
        );
    }

    private List<ReplayComparisonDto.EventEvidence> loadEvents(
            UUID runId,
            UUID caseRunId,
            String eventType
    ) {
        return jdbcTemplate.query("""
                select id, event_type, tool_name, output_redacted::text,
                       policy_decision_json::text, metadata_json::text,
                       payload_digest, reason_code, occurred_at
                  from execution_events
                 where run_id = ? and test_case_run_id = ? and event_type = ?
                 order by sequence
                """, (resultSet, rowNumber) -> {
            ExecutionEventType type = ExecutionEventType.valueOf(resultSet.getString("event_type"));
            String value = switch (type) {
                case POLICY_EVALUATED -> resultSet.getString("policy_decision_json");
                case TOOL_RESPONSE -> resultSet.getString("output_redacted");
                case SANDBOX_STATE_CHANGED -> resultSet.getString("metadata_json");
                default -> null;
            };
            return new ReplayComparisonDto.EventEvidence(
                    resultSet.getObject("id", UUID.class),
                    type,
                    resultSet.getString("tool_name"),
                    parseJson(value),
                    resultSet.getString("payload_digest"),
                    resultSet.getString("reason_code"),
                    resultSet.getTimestamp("occurred_at").toInstant()
            );
        }, runId, caseRunId, eventType);
    }

    private List<ReplayComparisonDto.OracleSummary> loadOracles(UUID caseRunId) {
        return jdbcTemplate.query("""
                select id, source_event_id, oracle_type, oracle_version, outcome,
                       reason_code, invariant_id, evidence_digest, evaluated_at
                  from oracle_results
                 where test_case_run_id = ?
                 order by evaluated_at, id
                """, (resultSet, rowNumber) -> new ReplayComparisonDto.OracleSummary(
                        resultSet.getObject("id", UUID.class),
                        resultSet.getObject("source_event_id", UUID.class),
                        OracleType.valueOf(resultSet.getString("oracle_type")),
                        resultSet.getString("oracle_version"),
                        OracleOutcome.valueOf(resultSet.getString("outcome")),
                        OracleReasonCode.valueOf(resultSet.getString("reason_code")),
                        resultSet.getString("invariant_id"),
                        resultSet.getString("evidence_digest"),
                        resultSet.getTimestamp("evaluated_at").toInstant()
                ), caseRunId);
    }

    private void validateComplete(
            LinkRow link,
            ReplayComparisonDto.Side baseline,
            ReplayComparisonDto.Side replay
    ) {
        boolean complete = baseline.runStatus() == TestRunStatus.COMPLETED
                && replay.runStatus() == TestRunStatus.COMPLETED
                && TERMINAL_CASE_STATUSES.contains(baseline.caseStatus().name())
                && TERMINAL_CASE_STATUSES.contains(replay.caseStatus().name())
                && !baseline.oracleResults().isEmpty()
                && link.replayMatchingOracleId() != null;
        if (!complete) {
            throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, "Replay comparison pair is incomplete");
        }
    }

    private ComparisonStatus comparisonStatus(LinkRow link) {
        LinkedHashSet<String> reasons = new LinkedHashSet<>();
        if (!link.sameAgentArtifactFingerprint()) reasons.add("AGENT_ARTIFACT_MISMATCH");
        if (!link.sameFixtureDigest()) reasons.add("FIXTURE_DIGEST_MISMATCH");
        if (!link.sameModelConfig()) reasons.add("MODEL_CONFIG_MISMATCH");
        if (!link.sameVariantHash()) reasons.add("VARIANT_HASH_MISMATCH");
        if (!link.expectedPolicyDifference()) reasons.add("EXPECTED_POLICY_DIFFERENCE_MISSING");
        JsonNode comparison = parseJson(link.comparisonJson());
        for (String field : List.of("mismatchReasons", "mismatches")) {
            JsonNode values = comparison.path(field);
            if (values.isArray()) {
                values.forEach(value -> {
                    if (value.isString() && !value.asString().isBlank()) reasons.add(value.asString());
                    else if (value.path("code").isString()) reasons.add(value.path("code").asString());
                    else if (value.path("reason").isString()) reasons.add(value.path("reason").asString());
                });
            }
        }
        boolean comparable = comparison.path("comparable").asBoolean(reasons.isEmpty()) && reasons.isEmpty();
        if (!comparable && reasons.isEmpty()) {
            reasons.add("REPLAY_NOT_COMPARABLE");
        }
        return new ComparisonStatus(comparable, List.copyOf(reasons));
    }

    private ReplayComparisonDto.Difference difference(
            ReplayComparisonDto.Side baseline,
            ReplayComparisonDto.Side replay
    ) {
        boolean baselineSuccess = hasOutcome(baseline, OracleOutcome.ATTACK_SUCCESS);
        boolean replayBlocked = hasOutcome(replay, OracleOutcome.ATTACK_BLOCKED);
        boolean replaySuccess = hasOutcome(replay, OracleOutcome.ATTACK_SUCCESS);
        return new ReplayComparisonDto.Difference(
                !eventSignature(baseline.policyDecisions()).equals(eventSignature(replay.policyDecisions())),
                !eventSignature(baseline.apiResponses()).equals(eventSignature(replay.apiResponses())),
                !eventSignature(baseline.stateChanges()).equals(eventSignature(replay.stateChanges())),
                !oracleSignature(baseline).equals(oracleSignature(replay)),
                baselineSuccess && replayBlocked && !replaySuccess
        );
    }

    private boolean hasOutcome(ReplayComparisonDto.Side side, OracleOutcome outcome) {
        return side.oracleResults().stream().anyMatch(oracle -> oracle.outcome() == outcome);
    }

    private List<EventSignature> eventSignature(List<ReplayComparisonDto.EventEvidence> events) {
        return events.stream()
                .map(event -> new EventSignature(event.eventType(), event.toolName(), event.value(), event.reasonCode()))
                .toList();
    }

    private List<OracleSignature> oracleSignature(ReplayComparisonDto.Side side) {
        return side.oracleResults().stream()
                .map(oracle -> new OracleSignature(
                        oracle.oracleType(), oracle.outcome(), oracle.reasonCode(), oracle.invariantId()
                ))
                .toList();
    }

    private LinkRow mapLink(ResultSet resultSet) throws SQLException {
        return new LinkRow(
                resultSet.getObject("replay_link_id", UUID.class),
                resultSet.getObject("finding_id", UUID.class),
                resultSet.getObject("release_id", UUID.class),
                resultSet.getString("category"),
                resultSet.getString("severity"),
                resultSet.getObject("baseline_run_id", UUID.class),
                resultSet.getObject("baseline_case_run_id", UUID.class),
                resultSet.getObject("replay_run_id", UUID.class),
                resultSet.getObject("replay_case_run_id", UUID.class),
                resultSet.getBoolean("same_agent_artifact_fingerprint"),
                resultSet.getBoolean("same_fixture_digest"),
                resultSet.getBoolean("same_model_config"),
                resultSet.getBoolean("same_variant_hash"),
                resultSet.getBoolean("expected_policy_difference"),
                resultSet.getString("comparison_json"),
                resultSet.getObject("replay_matching_oracle_id", UUID.class)
        );
    }

    private JsonNode parseJson(String value) {
        if (value == null || value.isBlank()) {
            return objectMapper.createObjectNode();
        }
        try {
            return objectMapper.readTree(value);
        } catch (Exception exception) {
            throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, "Stored Replay evidence is invalid");
        }
    }

    private record SideRow(
            TestRunMode mode,
            TestRunStatus runStatus,
            TestCaseRunStatus caseStatus,
            String securityOutcome,
            String functionalOutcome
    ) {
    }

    private record LinkRow(
            UUID replayLinkId,
            UUID findingId,
            UUID releaseId,
            String category,
            String severity,
            UUID baselineRunId,
            UUID baselineCaseRunId,
            UUID replayRunId,
            UUID replayCaseRunId,
            boolean sameAgentArtifactFingerprint,
            boolean sameFixtureDigest,
            boolean sameModelConfig,
            boolean sameVariantHash,
            boolean expectedPolicyDifference,
            String comparisonJson,
            UUID replayMatchingOracleId
    ) {
    }

    private record ComparisonStatus(boolean comparable, List<String> mismatchReasons) {
    }

    private record EventSignature(
            ExecutionEventType eventType,
            String toolName,
            JsonNode value,
            String reasonCode
    ) {
    }

    private record OracleSignature(
            OracleType oracleType,
            OracleOutcome outcome,
            OracleReasonCode reasonCode,
            String invariantId
    ) {
    }
}
