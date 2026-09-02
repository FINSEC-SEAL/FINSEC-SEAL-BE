package com.finsecseal.evidence;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Service
@Transactional(readOnly = true)
public class TestRunProjectionService {

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public TestRunProjectionService(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    public TestRunDto.Projection find(UUID runId) {
        List<TestRunDto.Projection> runs = jdbcTemplate.query("""
                select run.id, run.release_id, run.suite_id, run.contract_version_id,
                       run.mode, run.status, run.agent_artifact_fingerprint,
                       run.release_fingerprint, run.fixture_version, run.fixture_digest,
                       run.total_cases, run.completed_cases, run.operational_error_count,
                       coalesce(event.sequence, 0) latest_sequence, event.event_type latest_event_type,
                       event.event_hash event_head_hash, run.summary_json::text,
                       run.started_at, run.completed_at, run.created_at
                  from test_runs run
                  left join lateral (
                      select sequence, event_type, event_hash
                        from execution_events
                       where run_id = run.id
                       order by sequence desc
                       limit 1
                  ) event on true
                 where run.id = ?
                """, (resultSet, rowNumber) -> new TestRunDto.Projection(
                        resultSet.getObject("id", UUID.class),
                        resultSet.getObject("release_id", UUID.class),
                        resultSet.getObject("suite_id", UUID.class),
                        resultSet.getObject("contract_version_id", UUID.class),
                        TestRunMode.valueOf(resultSet.getString("mode")),
                        TestRunStatus.valueOf(resultSet.getString("status")),
                        resultSet.getString("agent_artifact_fingerprint"),
                        resultSet.getString("release_fingerprint"),
                        resultSet.getString("fixture_version"),
                        resultSet.getString("fixture_digest"),
                        resultSet.getInt("total_cases"),
                        resultSet.getInt("completed_cases"),
                        resultSet.getInt("operational_error_count"),
                        resultSet.getLong("latest_sequence"),
                        resultSet.getString("latest_event_type") == null
                                ? null
                                : ExecutionEventType.valueOf(resultSet.getString("latest_event_type")),
                        resultSet.getString("event_head_hash"),
                        parseJson(resultSet.getString("summary_json")),
                        resultSet.getTimestamp("started_at") == null
                                ? null : resultSet.getTimestamp("started_at").toInstant(),
                        resultSet.getTimestamp("completed_at") == null
                                ? null : resultSet.getTimestamp("completed_at").toInstant(),
                        resultSet.getTimestamp("created_at").toInstant()
                ), runId);
        if (runs.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "TestRun not found");
        }
        return runs.getFirst();
    }

    private JsonNode parseJson(String value) {
        try {
            return objectMapper.readTree(value);
        } catch (Exception exception) {
            throw new IllegalStateException("Stored TestRun summary is invalid", exception);
        }
    }
}
