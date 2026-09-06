package com.finsecseal.execution;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.release.AgentReleaseEntity;
import com.finsecseal.release.AgentReleaseRepository;
import com.finsecseal.release.FingerprintService;
import com.finsecseal.sandbox.SandboxFixtureService;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Executor;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.JsonNode;

class TestRunStartServiceTest {

    @Test
    void registersRunAndDispatchesRequestedCases() {
        AgentReleaseRepository releaseRepository = mock(AgentReleaseRepository.class);
        FingerprintService fingerprintService = mock(FingerprintService.class);
        SandboxFixtureService fixtureService = mock(SandboxFixtureService.class);
        TestRunPersistenceService persistenceService = mock(TestRunPersistenceService.class);
        ExecutionDispatchService dispatchService = mock(ExecutionDispatchService.class);
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        Executor executor = mock(Executor.class);
        AgentReleaseEntity release = mock(AgentReleaseEntity.class);
        JsonNode manifest = mock(JsonNode.class);
        JsonNode model = mock(JsonNode.class);

        UUID releaseId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        UUID firstCaseId = UUID.randomUUID();
        UUID secondCaseId = UUID.randomUUID();
        UUID runId = UUID.randomUUID();
        String actorId = "frontend-b";
        String fixtureDigest = "sha256:" + "a".repeat(64);
        String modelConfigHash = "sha256:" + "b".repeat(64);

        when(releaseRepository.findById(releaseId)).thenReturn(Optional.of(release));
        when(release.getManifestJson()).thenReturn(manifest);
        when(manifest.path("model")).thenReturn(model);
        when(fingerprintService.hash(model)).thenReturn(modelConfigHash);
        when(fixtureService.fixtureDigest()).thenReturn(fixtureDigest);
        when(persistenceService.register(
                any(TestRunPersistenceDto.RegisterRequest.class),
                eq(actorId)
        )).thenReturn(new TestRunPersistenceDto.Registered(
                runId,
                TestRunStatus.QUEUED,
                "/api/v1/test-runs/" + runId,
                "/api/v1/test-runs/" + runId + "/events"
        ));

        TestRunStartService service = new TestRunStartService(
                releaseRepository,
                fingerprintService,
                fixtureService,
                persistenceService,
                dispatchService,
                jdbcTemplate,
                executor
        );

        TestRunPersistenceDto.Registered result = service.start(
                new TestRunStartService.Request(
                        releaseId,
                        suiteId,
                        TestRunMode.BASELINE,
                        null,
                        List.of(firstCaseId, secondCaseId),
                        1234L
                ),
                actorId
        );

        assertThat(result.runId()).isEqualTo(runId);
        assertThat(result.status()).isEqualTo(TestRunStatus.QUEUED);

        ArgumentCaptor<TestRunPersistenceDto.RegisterRequest> requestCaptor =
                ArgumentCaptor.forClass(TestRunPersistenceDto.RegisterRequest.class);
        verify(persistenceService).register(requestCaptor.capture(), eq(actorId));

        TestRunPersistenceDto.RegisterRequest registerRequest = requestCaptor.getValue();
        assertThat(registerRequest.releaseId()).isEqualTo(releaseId);
        assertThat(registerRequest.suiteId()).isEqualTo(suiteId);
        assertThat(registerRequest.mode()).isEqualTo(TestRunMode.BASELINE);
        assertThat(registerRequest.contractVersionId()).isNull();
        assertThat(registerRequest.fixtureDigest()).isEqualTo(fixtureDigest);
        assertThat(registerRequest.modelConfigHash()).isEqualTo(modelConfigHash);
        assertThat(registerRequest.randomSeed()).isEqualTo(1234L);
        assertThat(registerRequest.totalCases()).isEqualTo(2);

        ArgumentCaptor<Runnable> taskCaptor = ArgumentCaptor.forClass(Runnable.class);
        verify(executor).execute(taskCaptor.capture());
        verifyNoInteractions(dispatchService);

        taskCaptor.getValue().run();

        verify(dispatchService).execute(runId, firstCaseId, actorId);
        verify(dispatchService).execute(runId, secondCaseId, actorId);
    }

    @Test
    void loadsAllSuiteCasesWhenCaseIdsAreOmitted() {
        AgentReleaseRepository releaseRepository = mock(AgentReleaseRepository.class);
        FingerprintService fingerprintService = mock(FingerprintService.class);
        SandboxFixtureService fixtureService = mock(SandboxFixtureService.class);
        TestRunPersistenceService persistenceService = mock(TestRunPersistenceService.class);
        ExecutionDispatchService dispatchService = mock(ExecutionDispatchService.class);
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        Executor executor = mock(Executor.class);
        AgentReleaseEntity release = mock(AgentReleaseEntity.class);
        JsonNode manifest = mock(JsonNode.class);
        JsonNode model = mock(JsonNode.class);

        UUID releaseId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        UUID firstCaseId = UUID.randomUUID();
        UUID secondCaseId = UUID.randomUUID();
        UUID runId = UUID.randomUUID();
        String actorId = "frontend-b";

        when(releaseRepository.findById(releaseId)).thenReturn(Optional.of(release));
        when(release.getManifestJson()).thenReturn(manifest);
        when(manifest.path("model")).thenReturn(model);
        when(fingerprintService.hash(model)).thenReturn("model-hash");
        when(fixtureService.fixtureDigest()).thenReturn("fixture-digest");
        when(jdbcTemplate.queryForList(
                "select id from test_cases where suite_id = ? order by case_key",
                UUID.class,
                suiteId
        )).thenReturn(List.of(firstCaseId, secondCaseId));
        when(persistenceService.register(
                any(TestRunPersistenceDto.RegisterRequest.class),
                eq(actorId)
        )).thenReturn(new TestRunPersistenceDto.Registered(
                runId,
                TestRunStatus.QUEUED,
                "/api/v1/test-runs/" + runId,
                "/api/v1/test-runs/" + runId + "/events"
        ));

        TestRunStartService service = new TestRunStartService(
                releaseRepository,
                fingerprintService,
                fixtureService,
                persistenceService,
                dispatchService,
                jdbcTemplate,
                executor
        );

        TestRunPersistenceDto.Registered result = service.start(
                new TestRunStartService.Request(
                        releaseId,
                        suiteId,
                        TestRunMode.BASELINE,
                        null,
                        null,
                        1234L
                ),
                actorId
        );

        assertThat(result.runId()).isEqualTo(runId);

        ArgumentCaptor<TestRunPersistenceDto.RegisterRequest> requestCaptor =
                ArgumentCaptor.forClass(TestRunPersistenceDto.RegisterRequest.class);
        verify(persistenceService).register(requestCaptor.capture(), eq(actorId));
        assertThat(requestCaptor.getValue().totalCases()).isEqualTo(2);

        ArgumentCaptor<Runnable> taskCaptor = ArgumentCaptor.forClass(Runnable.class);
        verify(executor).execute(taskCaptor.capture());
        verifyNoInteractions(dispatchService);

        taskCaptor.getValue().run();

        verify(dispatchService).execute(runId, firstCaseId, actorId);
        verify(dispatchService).execute(runId, secondCaseId, actorId);
    }
}
