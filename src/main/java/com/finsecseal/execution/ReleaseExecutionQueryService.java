package com.finsecseal.execution;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Service
@Transactional(readOnly = true)
public class ReleaseExecutionQueryService {

    private static final int DEFAULT_LIMIT = 20;
    private static final int MAX_LIMIT = 100;

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public ReleaseExecutionQueryService(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    public ExecutionQueryDto.TestSuiteListResponse listSuites(
            UUID releaseId,
            String status,
            Integer limit,
            String cursor
    ) {
        ReleaseScope scope = requireReleaseScope(releaseId);
        int pageSize = normalizeLimit(limit);
        PageCursor pageCursor = parseCursor(cursor, "cursor");
        Timestamp cursorTimestamp = pageCursor == null ? null : Timestamp.from(pageCursor.createdAt());
        UUID cursorId = pageCursor == null ? null : pageCursor.id();

        List<SuiteRow> rows = jdbcTemplate.query("""
                select suite.id, suite.version, suite.status, suite.suite_hash,
                       count(test_case.id) case_count, suite.created_at
                  from test_suites suite
                  left join test_cases test_case on test_case.suite_id = suite.id
                 where suite.workspace_id = ?
                                     and (?::varchar is null or suite.status = ?)
                                     and (?::timestamptz is null or suite.created_at < ? or (suite.created_at = ? and suite.id < ?::uuid))
                 group by suite.id, suite.version, suite.status, suite.suite_hash, suite.created_at
                 order by suite.created_at desc, suite.id desc
                 limit ?
                """, (resultSet, rowNumber) -> new SuiteRow(
                        new ExecutionQueryDto.TestSuiteSummary(
                                resultSet.getObject("id", UUID.class),
                                releaseId,
                                resultSet.getString("version"),
                                resultSet.getString("status"),
                                resultSet.getString("suite_hash"),
                                resultSet.getInt("case_count")
                        ),
                        resultSet.getTimestamp("created_at").toInstant()
                ), scope.workspaceId(), status, status, cursorTimestamp, cursorTimestamp, cursorTimestamp, cursorId,
                pageSize + 1);

        String nextCursor = nextCursor(rows, pageSize, SuiteRow::createdAt, row -> row.summary().id());
        List<ExecutionQueryDto.TestSuiteSummary> items = rows.stream()
                .limit(pageSize)
                .map(SuiteRow::summary)
                .toList();
        return new ExecutionQueryDto.TestSuiteListResponse(items, nextCursor);
    }

    public ExecutionQueryDto.TestRunListResponse listRuns(
            UUID releaseId,
            TestRunMode mode,
            String status,
            Integer limit,
            String cursor
    ) {
        requireReleaseScope(releaseId);
        int pageSize = normalizeLimit(limit);
        PageCursor pageCursor = parseCursor(cursor, "cursor");
        Timestamp cursorTimestamp = pageCursor == null ? null : Timestamp.from(pageCursor.createdAt());
        UUID cursorId = pageCursor == null ? null : pageCursor.id();

        List<RunRow> rows = jdbcTemplate.query("""
                select run.id, run.suite_id, run.mode, run.status,
                       run.total_cases, run.completed_cases, run.operational_error_count,
                       coalesce(event.sequence, 0) latest_sequence,
                       run.started_at, run.completed_at, run.created_at
                  from test_runs run
                  left join lateral (
                      select sequence
                        from execution_events
                       where run_id = run.id
                       order by sequence desc
                       limit 1
                  ) event on true
                 where run.release_id = ?
                                     and (?::varchar is null or run.mode = ?)
                                     and (?::varchar is null or run.status = ?)
                                     and (?::timestamptz is null or run.created_at < ? or (run.created_at = ? and run.id < ?::uuid))
                 order by run.created_at desc, run.id desc
                 limit ?
                """, (resultSet, rowNumber) -> new RunRow(
                        new ExecutionQueryDto.TestRunSummary(
                                resultSet.getObject("id", UUID.class),
                                releaseId,
                                resultSet.getObject("suite_id", UUID.class),
                                TestRunMode.valueOf(resultSet.getString("mode")),
                                TestRunStatus.valueOf(resultSet.getString("status")),
                                resultSet.getInt("total_cases"),
                                resultSet.getInt("completed_cases"),
                                resultSet.getInt("operational_error_count"),
                                resultSet.getLong("latest_sequence"),
                                resultSet.getTimestamp("started_at") == null
                                        ? null
                                        : resultSet.getTimestamp("started_at").toInstant(),
                                resultSet.getTimestamp("completed_at") == null
                                        ? null
                                        : resultSet.getTimestamp("completed_at").toInstant()
                        ),
                        resultSet.getTimestamp("created_at").toInstant()
                ), releaseId, mode == null ? null : mode.name(), mode == null ? null : mode.name(), status, status,
                cursorTimestamp, cursorTimestamp, cursorTimestamp, cursorId, pageSize + 1);

        String nextCursor = nextCursor(rows, pageSize, RunRow::createdAt, row -> row.summary().id());
        List<ExecutionQueryDto.TestRunSummary> items = rows.stream()
                .limit(pageSize)
                .map(RunRow::summary)
                .toList();
        return new ExecutionQueryDto.TestRunListResponse(items, nextCursor);
    }

    public ExecutionQueryDto.ReplayComparisonListResponse listReplayComparisons(
            UUID releaseId,
            Integer limit,
            String cursor
    ) {
        requireReleaseScope(releaseId);
        int pageSize = normalizeLimit(limit);
        PageCursor pageCursor = parseCursor(cursor, "cursor");
        Timestamp cursorTimestamp = pageCursor == null ? null : Timestamp.from(pageCursor.createdAt());
        UUID cursorId = pageCursor == null ? null : pageCursor.id();

        List<ReplayRow> rows = jdbcTemplate.query("""
                select replay_link.id,
                       replay_link.created_at,
                       finding.category,
                       baseline_case.test_run_id baseline_run_id,
                       replay_case.test_run_id replay_run_id,
                       replay_link.same_agent_artifact_fingerprint,
                       replay_link.same_fixture_digest,
                       replay_link.same_model_config,
                       replay_link.same_variant_hash,
                       replay_link.expected_policy_difference,
                       replay_link.comparison_json::text comparison_json
                  from replay_links replay_link
                  join findings finding on finding.id = replay_link.finding_id
                  join test_case_runs baseline_case on baseline_case.id = replay_link.baseline_case_run_id
                  join test_case_runs replay_case on replay_case.id = replay_link.replay_case_run_id
                 where finding.release_id = ?
                    and (?::timestamptz is null or replay_link.created_at < ?
                        or (replay_link.created_at = ? and replay_link.id < ?::uuid))
                 order by replay_link.created_at desc, replay_link.id desc
                 limit ?
                """, (resultSet, rowNumber) -> {
                    ReplayComparisonPayload payload = replayComparisonPayload(
                            resultSet.getString("comparison_json"),
                            new ReplayFlags(
                                    resultSet.getBoolean("same_agent_artifact_fingerprint"),
                                    resultSet.getBoolean("same_fixture_digest"),
                                    resultSet.getBoolean("same_model_config"),
                                    resultSet.getBoolean("same_variant_hash"),
                                    resultSet.getBoolean("expected_policy_difference")
                            )
                    );
                    return new ReplayRow(
                            new ExecutionQueryDto.ReplayComparisonView(
                                    resultSet.getObject("baseline_run_id", UUID.class),
                                    resultSet.getObject("replay_run_id", UUID.class),
                                    resultSet.getString("category"),
                                    payload.comparable(),
                                    payload.mismatchReasons()
                            ),
                            resultSet.getTimestamp("created_at").toInstant(),
                            resultSet.getObject("id", UUID.class)
                    );
                }, releaseId, cursorTimestamp, cursorTimestamp, cursorTimestamp, cursorId, pageSize + 1);

        String nextCursor = nextCursor(rows, pageSize, ReplayRow::createdAt, ReplayRow::id);
        List<ExecutionQueryDto.ReplayComparisonView> items = rows.stream()
                .limit(pageSize)
                .map(ReplayRow::summary)
                .toList();
        return new ExecutionQueryDto.ReplayComparisonListResponse(items, nextCursor);
    }

    ReplayComparisonPayload replayComparisonPayload(String comparisonJson, ReplayFlags flags) {
        JsonNode payload = parseJson(comparisonJson);
        LinkedHashSet<String> reasons = new LinkedHashSet<>();

        JsonNode mismatchReasons = payload.path("mismatchReasons");
        if (mismatchReasons.isArray()) {
            mismatchReasons.forEach(node -> {
                if (node.isTextual() && !node.asText().isBlank()) {
                    reasons.add(node.asText());
                }
            });
        }

        JsonNode mismatches = payload.path("mismatches");
        if (mismatches.isArray()) {
            mismatches.forEach(node -> {
                if (node.isTextual() && !node.asText().isBlank()) {
                    reasons.add(node.asText());
                    return;
                }
                String code = text(node, "code");
                if (code != null) {
                    reasons.add(code);
                    return;
                }
                String reason = text(node, "reason");
                if (reason != null) {
                    reasons.add(reason);
                }
            });
        }

        if (!flags.sameAgentArtifactFingerprint()) {
            reasons.add("AGENT_ARTIFACT_MISMATCH");
        }
        if (!flags.sameFixtureDigest()) {
            reasons.add("FIXTURE_DIGEST_MISMATCH");
        }
        if (!flags.sameModelConfig()) {
            reasons.add("MODEL_CONFIG_MISMATCH");
        }
        if (!flags.sameVariantHash()) {
            reasons.add("VARIANT_HASH_MISMATCH");
        }
        if (!flags.expectedPolicyDifference()) {
            reasons.add("EXPECTED_POLICY_DIFFERENCE_MISSING");
        }

        boolean comparable = payload.path("comparable").asBoolean(reasons.isEmpty()) && reasons.isEmpty();
        List<String> mismatchList = new ArrayList<>(reasons);
        if (!comparable && mismatchList.isEmpty()) {
            mismatchList = List.of("REPLAY_NOT_COMPARABLE");
        }
        return new ReplayComparisonPayload(comparable, mismatchList);
    }

    private ReleaseScope requireReleaseScope(UUID releaseId) {
        if (releaseId == null) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "releaseId is required");
        }
        List<ReleaseScope> scopes = jdbcTemplate.query("""
                select agent.workspace_id
                  from agent_releases release
                  join agents agent on agent.id = release.agent_id
                 where release.id = ?
                """, (resultSet, rowNumber) -> new ReleaseScope(
                        resultSet.getObject("workspace_id", UUID.class)
                ), releaseId);
        if (scopes.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "Release not found");
        }
        return scopes.getFirst();
    }

    private int normalizeLimit(Integer limit) {
        if (limit == null) {
            return DEFAULT_LIMIT;
        }
        if (limit < 1 || limit > MAX_LIMIT) {
            throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    "limit must be between 1 and " + MAX_LIMIT
            );
        }
        return limit;
    }

    private PageCursor parseCursor(String cursor, String fieldName) {
        if (cursor == null || cursor.isBlank()) {
            return null;
        }
        String[] parts = cursor.split("\\|", 2);
        if (parts.length != 2) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, fieldName + " must be <timestamp>|<uuid>");
        }
        try {
            return new PageCursor(Instant.parse(parts[0]), UUID.fromString(parts[1]));
        } catch (RuntimeException exception) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, fieldName + " must be <timestamp>|<uuid>");
        }
    }

    private <T> String nextCursor(
            List<T> rows,
            int pageSize,
            java.util.function.Function<T, Instant> createdAt,
            java.util.function.Function<T, UUID> id
    ) {
        if (rows.size() <= pageSize) {
            return null;
        }
        T last = rows.get(pageSize - 1);
        return createdAt.apply(last) + "|" + id.apply(last);
    }

    private JsonNode parseJson(String value) {
        if (value == null || value.isBlank()) {
            return objectMapper.createObjectNode();
        }
        try {
            return objectMapper.readTree(value);
        } catch (Exception exception) {
            throw new IllegalStateException("Stored replay comparison JSON is invalid", exception);
        }
    }

    private String text(JsonNode node, String field) {
        if (node == null) {
            return null;
        }
        JsonNode value = node.path(field);
        if (!value.isTextual() || value.asText().isBlank()) {
            return null;
        }
        return value.asText();
    }

    record ReplayFlags(
            boolean sameAgentArtifactFingerprint,
            boolean sameFixtureDigest,
            boolean sameModelConfig,
            boolean sameVariantHash,
            boolean expectedPolicyDifference
    ) {
    }

    record ReplayComparisonPayload(boolean comparable, List<String> mismatchReasons) {
        ReplayComparisonPayload {
            mismatchReasons = List.copyOf(Objects.requireNonNull(mismatchReasons, "mismatchReasons"));
        }
    }

    private record ReleaseScope(UUID workspaceId) {
    }

    private record PageCursor(Instant createdAt, UUID id) {
    }

    private record SuiteRow(ExecutionQueryDto.TestSuiteSummary summary, Instant createdAt) {
    }

    private record RunRow(ExecutionQueryDto.TestRunSummary summary, Instant createdAt) {
    }

    private record ReplayRow(ExecutionQueryDto.ReplayComparisonView summary, Instant createdAt, UUID id) {
    }
}