package com.finsecseal.execution;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
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
}
