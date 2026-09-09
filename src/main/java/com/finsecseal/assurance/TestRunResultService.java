package com.finsecseal.assurance;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleReasonCode;
import com.finsecseal.oracle.domain.OracleType;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class TestRunResultService {

    private static final int DEFAULT_LIMIT = 20;
    private static final int MAX_LIMIT = 100;

    private final JdbcTemplate jdbcTemplate;

    public TestRunResultService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public TestRunResultDto.Response find(
            UUID runId,
            String category,
            String outcome,
            Integer limit,
            String cursor
    ) {
        TestRunResultDto.RunView run = requireRun(runId);
        String normalizedCategory = normalizeCategory(category);
        String normalizedOutcome = normalizeOutcome(outcome);
        int pageSize = normalizeLimit(limit);
        PageCursor pageCursor = parseCursor(cursor);
        Timestamp cursorTimestamp = pageCursor == null ? null : Timestamp.from(pageCursor.createdAt());
        UUID cursorId = pageCursor == null ? null : pageCursor.id();

        List<CaseRow> rows = jdbcTemplate.query("""
                select case_run.id case_run_id, case_run.test_case_id, test_case.case_key,
                       test_case.case_type, test_case.partition_name, test_case.category,
                       test_case.severity, case_run.trial_index, case_run.status,
                       case_run.security_outcome, case_run.functional_outcome, case_run.latency_ms,
                       case_run.error_code, case_run.started_at, case_run.completed_at, case_run.created_at
                  from test_case_runs case_run
                  join test_cases test_case on test_case.id = case_run.test_case_id
                 where case_run.test_run_id = ?
                   and (?::varchar is null or test_case.category = ?)
                   and (?::varchar is null
                        or case_run.security_outcome = ?
                        or case_run.functional_outcome = ?
                        or exists(select 1 from oracle_results oracle
                                   where oracle.test_case_run_id = case_run.id and oracle.outcome = ?))
                   and (?::timestamptz is null or case_run.created_at < ?
                        or (case_run.created_at = ? and case_run.id < ?::uuid))
                 order by case_run.created_at desc, case_run.id desc
                 limit ?
                """, (resultSet, rowNumber) -> new CaseRow(
                        resultSet.getObject("case_run_id", UUID.class),
                        resultSet.getObject("test_case_id", UUID.class),
                        resultSet.getString("case_key"),
                        resultSet.getString("case_type"),
                        resultSet.getString("partition_name"),
                        resultSet.getString("category"),
                        resultSet.getString("severity"),
                        resultSet.getInt("trial_index"),
                        TestCaseRunStatus.valueOf(resultSet.getString("status")),
                        resultSet.getString("security_outcome"),
                        resultSet.getString("functional_outcome"),
                        resultSet.getObject("latency_ms", Long.class),
                        resultSet.getString("error_code"),
                        instant(resultSet.getTimestamp("started_at")),
                        instant(resultSet.getTimestamp("completed_at")),
                        resultSet.getTimestamp("created_at").toInstant()
                ), runId, normalizedCategory, normalizedCategory,
                normalizedOutcome, normalizedOutcome, normalizedOutcome, normalizedOutcome,
                cursorTimestamp, cursorTimestamp, cursorTimestamp, cursorId, pageSize + 1);

        List<CaseRow> page = rows.stream().limit(pageSize).toList();
        Map<UUID, List<TestRunResultDto.OracleSummary>> oracles = loadOracles(
                page.stream().map(CaseRow::caseRunId).toList()
        );
        List<TestRunResultDto.CaseResult> items = page.stream()
                .map(row -> row.toView(oracles.getOrDefault(row.caseRunId(), List.of())))
                .toList();
        String nextCursor = rows.size() <= pageSize
                ? null
                : page.getLast().createdAt() + "|" + page.getLast().caseRunId();

        return new TestRunResultDto.Response(run, summarize(runId), items, nextCursor);
    }

    private TestRunResultDto.RunView requireRun(UUID runId) {
        if (runId == null) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "runId is required");
        }
        List<TestRunResultDto.RunView> runs = jdbcTemplate.query("""
                select id, release_id, mode, status, total_cases, completed_cases,
                       operational_error_count, started_at, completed_at
                  from test_runs where id = ?
                """, (resultSet, rowNumber) -> new TestRunResultDto.RunView(
                        resultSet.getObject("id", UUID.class),
                        resultSet.getObject("release_id", UUID.class),
                        TestRunMode.valueOf(resultSet.getString("mode")),
                        TestRunStatus.valueOf(resultSet.getString("status")),
                        resultSet.getInt("total_cases"),
                        resultSet.getInt("completed_cases"),
                        resultSet.getInt("operational_error_count"),
                        instant(resultSet.getTimestamp("started_at")),
                        instant(resultSet.getTimestamp("completed_at"))
                ), runId);
        if (runs.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "TestRun not found");
        }
        return runs.getFirst();
    }

    private TestRunResultDto.Summary summarize(UUID runId) {
        return jdbcTemplate.queryForObject("""
                select count(*) materialized_trials,
                       count(*) filter (where case_run.status in
                           ('PASSED', 'FAILED_SECURITY', 'FAILED_FUNCTIONAL', 'ERROR', 'CANCELLED')) terminal_trials,
                       count(*) filter (where exists(select 1 from oracle_results oracle
                           where oracle.test_case_run_id = case_run.id and oracle.outcome = 'ATTACK_SUCCESS')) attack_success,
                       count(*) filter (where exists(select 1 from oracle_results oracle
                           where oracle.test_case_run_id = case_run.id and oracle.outcome = 'ATTACK_BLOCKED')) attack_blocked,
                       count(*) filter (where exists(select 1 from oracle_results oracle
                           where oracle.test_case_run_id = case_run.id and oracle.outcome = 'INCONCLUSIVE')) inconclusive,
                       count(*) filter (where exists(select 1 from oracle_results oracle
                           where oracle.test_case_run_id = case_run.id and oracle.outcome = 'NORMAL_SUCCESS')) normal_success,
                       count(*) filter (where exists(select 1 from oracle_results oracle
                           where oracle.test_case_run_id = case_run.id and oracle.outcome = 'NORMAL_FAILURE')) normal_failure,
                       count(*) filter (where case_run.status = 'ERROR') operational_errors,
                       count(*) filter (where case_run.status = 'CANCELLED') cancelled
                  from test_case_runs case_run
                 where case_run.test_run_id = ?
                """, (resultSet, rowNumber) -> new TestRunResultDto.Summary(
                        resultSet.getLong("materialized_trials"),
                        resultSet.getLong("terminal_trials"),
                        resultSet.getLong("attack_success"),
                        resultSet.getLong("attack_blocked"),
                        resultSet.getLong("inconclusive"),
                        resultSet.getLong("normal_success"),
                        resultSet.getLong("normal_failure"),
                        resultSet.getLong("operational_errors"),
                        resultSet.getLong("cancelled")
                ), runId);
    }

    private Map<UUID, List<TestRunResultDto.OracleSummary>> loadOracles(List<UUID> caseRunIds) {
        Map<UUID, List<TestRunResultDto.OracleSummary>> results = new LinkedHashMap<>();
        if (caseRunIds.isEmpty()) {
            return results;
        }
        jdbcTemplate.query("""
                select test_case_run_id, id, source_event_id, oracle_type, oracle_version,
                       outcome, reason_code, invariant_id, evidence_digest, evaluated_at
                  from oracle_results
                 where test_case_run_id = any(?::uuid[])
                 order by evaluated_at, id
                """, resultSet -> {
            while (resultSet.next()) {
                UUID caseRunId = resultSet.getObject("test_case_run_id", UUID.class);
                results.computeIfAbsent(caseRunId, ignored -> new ArrayList<>()).add(
                        new TestRunResultDto.OracleSummary(
                                resultSet.getObject("id", UUID.class),
                                resultSet.getObject("source_event_id", UUID.class),
                                OracleType.valueOf(resultSet.getString("oracle_type")),
                                resultSet.getString("oracle_version"),
                                OracleOutcome.valueOf(resultSet.getString("outcome")),
                                OracleReasonCode.valueOf(resultSet.getString("reason_code")),
                                resultSet.getString("invariant_id"),
                                resultSet.getString("evidence_digest"),
                                resultSet.getTimestamp("evaluated_at").toInstant()
                        )
                );
            }
            return null;
        }, (Object) caseRunIds.toArray(UUID[]::new));
        results.replaceAll((ignored, values) -> List.copyOf(values));
        return results;
    }

    private String normalizeCategory(String category) {
        if (category == null || category.isBlank()) {
            return null;
        }
        String normalized = category.trim().toUpperCase(Locale.ROOT);
        if (normalized.length() > 80) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "category is too long");
        }
        return normalized;
    }

    private String normalizeOutcome(String outcome) {
        if (outcome == null || outcome.isBlank()) {
            return null;
        }
        String normalized = outcome.trim().toUpperCase(Locale.ROOT);
        try {
            OracleOutcome.valueOf(normalized);
            return normalized;
        } catch (IllegalArgumentException exception) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "outcome is not supported");
        }
    }

    private int normalizeLimit(Integer limit) {
        if (limit == null) {
            return DEFAULT_LIMIT;
        }
        if (limit < 1 || limit > MAX_LIMIT) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "limit must be between 1 and " + MAX_LIMIT);
        }
        return limit;
    }

    private PageCursor parseCursor(String cursor) {
        if (cursor == null || cursor.isBlank()) {
            return null;
        }
        String[] parts = cursor.split("\\|", 2);
        if (parts.length != 2) {
            throw invalidCursor();
        }
        try {
            return new PageCursor(Instant.parse(parts[0]), UUID.fromString(parts[1]));
        } catch (RuntimeException exception) {
            throw invalidCursor();
        }
    }

    private BusinessException invalidCursor() {
        return new BusinessException(ErrorCode.VALIDATION_ERROR, "cursor must be <timestamp>|<uuid>");
    }

    private Instant instant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }

    private record PageCursor(Instant createdAt, UUID id) {
    }

    private record CaseRow(
            UUID caseRunId,
            UUID testCaseId,
            String caseKey,
            String caseType,
            String partition,
            String category,
            String severity,
            int trialIndex,
            TestCaseRunStatus status,
            String securityOutcome,
            String functionalOutcome,
            Long latencyMs,
            String errorCode,
            Instant startedAt,
            Instant completedAt,
            Instant createdAt
    ) {
        TestRunResultDto.CaseResult toView(List<TestRunResultDto.OracleSummary> oracleResults) {
            return new TestRunResultDto.CaseResult(
                    caseRunId, testCaseId, caseKey, caseType, partition, category, severity,
                    trialIndex, status, securityOutcome, functionalOutcome, latencyMs, errorCode,
                    startedAt, completedAt, oracleResults
            );
        }
    }
}
