package com.finsecseal.execution;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.sandbox.SandboxFixtureService;
import java.util.List;
import java.util.UUID;
import java.sql.ResultSet;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import tools.jackson.databind.ObjectMapper;

class RunExecutionLifecycleServiceTest {

    @Test
    @SuppressWarnings("unchecked")
    void recordsSealReplayModeWhenStartingRun() {
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        SandboxFixtureService fixtureService = mock(SandboxFixtureService.class);
        ExecutionEventService eventService = mock(ExecutionEventService.class);
        TestRunPersistenceService persistenceService = mock(TestRunPersistenceService.class);
        UUID runId = UUID.randomUUID();
        UUID traceId = UUID.randomUUID();

        when(jdbcTemplate.query(
                anyString(),
                any(RowMapper.class),
                any(Object[].class)
        )).thenReturn(List.of(TestRunStatus.QUEUED));
        when(fixtureService.verifyIntegrity(runId)).thenReturn(true);

        RunExecutionLifecycleService service = new RunExecutionLifecycleService(
                jdbcTemplate,
                new ObjectMapper(),
                fixtureService,
                eventService,
                persistenceService
        );

        service.ensureRunning(
                runId,
                traceId,
                "FA-02",
                TestRunMode.SEAL_REPLAY,
                "orchestrator-b"
        );

        ArgumentCaptor<ExecutionEventDto.AppendRequest> event =
                ArgumentCaptor.forClass(ExecutionEventDto.AppendRequest.class);
        verify(eventService).append(eq(runId), event.capture(), eq("orchestrator-b"));
        assertThat(event.getValue().eventType()).isEqualTo(ExecutionEventType.RUN_STARTED);
        assertThat(event.getValue().reasonCode()).isEqualTo("SEAL_REPLAY");
        assertThat(event.getValue().metadata().path("mode").asString()).isEqualTo("SEAL_REPLAY");
        assertThat(event.getValue().metadata().path("category").asString()).isEqualTo("FA-02");

        verify(persistenceService).updateStatus(
                eq(runId),
                eq(new TestRunPersistenceDto.StatusRequest(TestRunStatus.PREPARING, 0, 0, null)),
                eq("orchestrator-b")
        );
        verify(fixtureService).createOrReset(runId);
        verify(persistenceService).updateStatus(
                eq(runId),
                eq(new TestRunPersistenceDto.StatusRequest(TestRunStatus.RUNNING, 0, 0, null)),
                eq("orchestrator-b")
        );
    }

    @Test
    @SuppressWarnings("unchecked")
    void sealsActiveCasesAndRunAfterCancellationRequest() throws Exception {
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        SandboxFixtureService fixtureService = mock(SandboxFixtureService.class);
        ExecutionEventService eventService = mock(ExecutionEventService.class);
        TestRunPersistenceService persistenceService = mock(TestRunPersistenceService.class);
        UUID runId = UUID.randomUUID();
        UUID caseRunId = UUID.randomUUID();
        UUID traceId = UUID.randomUUID();

        when(jdbcTemplate.query(anyString(), any(RowMapper.class), any(Object[].class)))
                .thenAnswer(invocation -> {
                    String sql = invocation.getArgument(0);
                    RowMapper<Object> mapper = invocation.getArgument(1);
                    ResultSet resultSet = mock(ResultSet.class);
                    if (sql.contains("select status from test_runs")) {
                        when(resultSet.getString("status")).thenReturn("RUNNING");
                    } else if (sql.contains("materialized_cases")) {
                        when(resultSet.getString("status")).thenReturn("CANCELLING");
                        when(resultSet.getInt("total_cases")).thenReturn(3);
                        when(resultSet.getInt("materialized_cases")).thenReturn(2);
                        when(resultSet.getInt("terminal_cases")).thenReturn(2);
                        when(resultSet.getInt("error_cases")).thenReturn(0);
                        when(resultSet.getInt("security_failed_cases")).thenReturn(1);
                        when(resultSet.getInt("functional_failed_cases")).thenReturn(0);
                    } else {
                        throw new AssertionError("Unexpected query: " + sql);
                    }
                    return List.of(mapper.mapRow(resultSet, 0));
                });
        when(jdbcTemplate.queryForObject(
                contains("execution_events"),
                eq(Integer.class),
                eq(runId)
        )).thenReturn(1);
        when(jdbcTemplate.queryForList(anyString(), eq(UUID.class), eq(runId)))
                .thenReturn(List.of(caseRunId));
        when(jdbcTemplate.queryForObject(
                contains("status = 'CANCELLED'"),
                eq(Integer.class),
                eq(runId)
        )).thenReturn(1);

        RunExecutionLifecycleService service = new RunExecutionLifecycleService(
                jdbcTemplate,
                new ObjectMapper(),
                fixtureService,
                eventService,
                persistenceService
        );

        service.requestCancellation(runId, traceId, "reviewer-b");

        ArgumentCaptor<ExecutionEventDto.AppendRequest> event =
                ArgumentCaptor.forClass(ExecutionEventDto.AppendRequest.class);
        verify(eventService).append(eq(runId), event.capture(), eq("reviewer-b"));
        assertThat(event.getValue().eventType()).isEqualTo(ExecutionEventType.RUN_CANCEL_REQUESTED);
        assertThat(event.getValue().reasonCode()).isEqualTo("OPERATOR_CANCEL_REQUESTED");

        ArgumentCaptor<TestRunPersistenceDto.CaseRunStatusRequest> caseStatus =
                ArgumentCaptor.forClass(TestRunPersistenceDto.CaseRunStatusRequest.class);
        verify(persistenceService).updateCaseStatus(
                eq(runId), eq(caseRunId), caseStatus.capture(), eq("reviewer-b"));
        assertThat(caseStatus.getValue().status()).isEqualTo(
                com.finsecseal.common.domain.TestCaseRunStatus.CANCELLED);

        ArgumentCaptor<TestRunPersistenceDto.StatusRequest> runStatus =
                ArgumentCaptor.forClass(TestRunPersistenceDto.StatusRequest.class);
        verify(persistenceService, times(2)).updateStatus(
                eq(runId), runStatus.capture(), eq("reviewer-b"));
        assertThat(runStatus.getAllValues())
                .extracting(TestRunPersistenceDto.StatusRequest::status)
                .containsExactly(TestRunStatus.CANCELLING, TestRunStatus.CANCELLED);
        assertThat(runStatus.getAllValues().getLast().summary().path("cancelledCases").asInt())
                .isEqualTo(1);
    }
}
