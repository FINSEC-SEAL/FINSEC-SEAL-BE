package com.finsecseal.execution;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.evidence.AuthenticatedTestRunRegistrationService;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.release.AgentReleaseEntity;
import com.finsecseal.release.AgentReleaseRepository;
import com.finsecseal.release.FingerprintService;
import com.finsecseal.sandbox.SandboxFixtureService;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.stream.IntStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.ObjectMapper;

class TestRunStartServiceTest {

    private static final String ACTOR = "frontend-b";
    private static final String HASH = "sha256:" + "a".repeat(64);

    @BeforeEach
    void openSynchronization() {
        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
    }

    @AfterEach
    void closeSynchronization() {
        TransactionSynchronizationManager.clearSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(false);
    }

    @Test
    void explicitSelectionPreservesRequestOrderAndDispatchesOnlyAfterCommit() {
        UUID first = UUID.randomUUID(), second = UUID.randomUUID();
        Fixture fixture = new Fixture(List.of(
                new CaseRow(second, "SEED", false), new CaseRow(first, "MUTATION", false)));

        TestRunPersistenceDto.Registered registered = fixture.service.start(
                fixture.request(TestRunMode.BASELINE, List.of(first, second)), fixture.httpRequest);

        assertThat(registered.runId()).isEqualTo(fixture.runId);
        assertThat(fixture.httpRequest.getHeader("X-Actor-Id")).isNotEqualTo(ACTOR);
        ArgumentCaptor<TestRunPersistenceDto.RegisterRequest> registration =
                ArgumentCaptor.forClass(TestRunPersistenceDto.RegisterRequest.class);
        verify(fixture.admission).register(registration.capture(), eq(fixture.httpRequest));
        assertThat(registration.getValue().totalCases()).isEqualTo(2);
        assertThat(fixture.db.caseQueryCount).isEqualTo(2);
        verifyNoInteractions(fixture.executor, fixture.dispatch);
        verifyNoInteractions(fixture.lifecycle);

        Runnable task = afterCommitTask(fixture.executor);
        task.run();
        var ordered = inOrder(fixture.dispatch);
        ordered.verify(fixture.dispatch).execute(fixture.runId, first, ACTOR);
        ordered.verify(fixture.dispatch).execute(fixture.runId, second, ACTOR);
    }

    @Test
    void baselineNormalOnlySuiteAutoSelectsForNullAndEmptyRequests() {
        UUID normal = UUID.randomUUID();
        for (List<UUID> selection : Arrays.<List<UUID>>asList(null, List.of())) {
            Fixture fixture = new Fixture(List.of(new CaseRow(normal, "NORMAL", false)));
            fixture.service.start(fixture.request(TestRunMode.BASELINE, selection), fixture.httpRequest);
            afterCommitTask(fixture.executor).run();
            verify(fixture.dispatch).execute(fixture.runId, normal, ACTOR);
            assertThat(fixture.db.caseQueryCount).isEqualTo(2);
            TransactionSynchronizationManager.clearSynchronization();
            TransactionSynchronizationManager.initSynchronization();
        }
    }

    @Test
    void invalidExplicitInputsFailBeforeRegistrationOrExecutor() {
        Fixture fixture = new Fixture(List.of());
        UUID one = UUID.randomUUID();
        List<List<UUID>> invalid = List.of(
                Arrays.asList(one, null),
                List.of(one, one),
                IntStream.range(0, 10_001).mapToObj(index -> new UUID(0, index)).toList());
        for (List<UUID> selection : invalid) {
            assertInvalid(() -> fixture.service.start(
                    fixture.request(TestRunMode.BASELINE, selection), fixture.httpRequest));
        }
        assertInvalid(() -> fixture.service.start(
                fixture.request(TestRunMode.HELD_OUT, List.of(one)), fixture.httpRequest));
        verifyNoInteractions(fixture.admission, fixture.executor, fixture.dispatch);
        verifyNoInteractions(fixture.lifecycle);
        assertThat(fixture.db.caseQueryCount).isZero();
    }

    @Test
    void hiddenAndForeignCaseSelectionsFailBeforeRegistration() {
        UUID chosen = UUID.randomUUID();
        Fixture hidden = new Fixture(List.of(new CaseRow(chosen, "HELD_OUT", true)));
        assertInvalid(() -> hidden.service.start(
                hidden.request(TestRunMode.BASELINE, List.of(chosen)), hidden.httpRequest));
        verifyNoInteractions(hidden.admission, hidden.executor, hidden.dispatch);
        verifyNoInteractions(hidden.lifecycle);

        Fixture foreign = new Fixture(List.of());
        assertInvalid(() -> foreign.service.start(
                foreign.request(TestRunMode.BASELINE, List.of(chosen)), foreign.httpRequest));
        verifyNoInteractions(foreign.admission, foreign.executor, foreign.dispatch);
        verifyNoInteractions(foreign.lifecycle);
    }

    @Test
    void changedSelectionAfterRegistrationDoesNotScheduleDispatch() {
        UUID chosen = UUID.randomUUID();
        Fixture fixture = new Fixture(List.of(new CaseRow(chosen, "SEED", false)));
        fixture.db.changeOnSecondCaseQuery = true;

        assertInvalid(() -> fixture.service.start(
                fixture.request(TestRunMode.BASELINE, List.of(chosen)), fixture.httpRequest));
        verify(fixture.admission).register(any(), eq(fixture.httpRequest));
        verifyNoInteractions(fixture.executor, fixture.dispatch);
        verifyNoInteractions(fixture.lifecycle);
        assertThat(TransactionSynchronizationManager.getSynchronizations()).isEmpty();
    }

    @Test
    void admissionFailureDoesNotScheduleOrTrustCallerHeader() {
        UUID chosen = UUID.randomUUID();
        Fixture fixture = new Fixture(List.of(new CaseRow(chosen, "NORMAL", false)));
        when(fixture.admission.register(any(), eq(fixture.httpRequest)))
                .thenThrow(new BusinessException(ErrorCode.OPERATOR_AUTH_REQUIRED,
                        "A valid reviewer session is required"));

        assertThatThrownBy(() -> fixture.service.start(
                fixture.request(TestRunMode.BASELINE, List.of(chosen)), fixture.httpRequest))
                .isInstanceOfSatisfying(BusinessException.class,
                        error -> assertThat(error.errorCode()).isEqualTo(ErrorCode.OPERATOR_AUTH_REQUIRED));
        verifyNoInteractions(fixture.executor, fixture.dispatch, fixture.lifecycle);
        assertThat(TransactionSynchronizationManager.getSynchronizations()).isEmpty();
    }

    @Test
    void incompleteAdmissionFailsClosedBeforeScheduling() {
        UUID chosen = UUID.randomUUID();
        Fixture fixture = new Fixture(List.of(new CaseRow(chosen, "NORMAL", false)));
        when(fixture.admission.register(any(), eq(fixture.httpRequest)))
                .thenReturn(new AuthenticatedTestRunRegistrationService.Admission(null, ACTOR));

        assertThatThrownBy(() -> fixture.service.start(
                fixture.request(TestRunMode.BASELINE, List.of(chosen)), fixture.httpRequest))
                .isInstanceOfSatisfying(BusinessException.class,
                        error -> assertThat(error.errorCode()).isEqualTo(ErrorCode.INTERNAL_ERROR))
                .hasMessage("Authenticated TestRun admission was incomplete");
        verifyNoInteractions(fixture.executor, fixture.dispatch, fixture.lifecycle);
        assertThat(TransactionSynchronizationManager.getSynchronizations()).isEmpty();
    }

    @Test
    void executorRejectionAfterCommitFailsExactRegisteredRunWithoutRawMessage() {
        UUID chosen = UUID.randomUUID();
        Fixture fixture = new Fixture(List.of(new CaseRow(chosen, "NORMAL", false)));
        fixture.service.start(fixture.request(TestRunMode.BASELINE, List.of(chosen)), fixture.httpRequest);
        doThrow(new RejectedExecutionException("secret-canary queue full"))
                .when(fixture.executor).execute(any(Runnable.class));

        assertThatThrownBy(() -> TransactionSynchronizationManager.getSynchronizations()
                .forEach(TransactionSynchronization::afterCommit))
                .isInstanceOf(BusinessException.class)
                .satisfies(error -> assertThat(((BusinessException) error).errorCode())
                        .isEqualTo(ErrorCode.INTERNAL_ERROR))
                .hasMessage("TestRun scheduling was rejected")
                .hasMessageNotContaining("secret-canary");
        verify(fixture.admission).register(any(), eq(fixture.httpRequest));
        verify(fixture.lifecycle).rejectScheduling(eq(fixture.runId), any(UUID.class), eq(ACTOR));
        verifyNoInteractions(fixture.dispatch);
    }

    @Test
    void schedulingFailureHandlerErrorIsNotSwallowed() {
        UUID chosen = UUID.randomUUID();
        Fixture fixture = new Fixture(List.of(new CaseRow(chosen, "NORMAL", false)));
        fixture.service.start(fixture.request(TestRunMode.BASELINE, List.of(chosen)), fixture.httpRequest);
        doThrow(new RejectedExecutionException("queue full"))
                .when(fixture.executor).execute(any(Runnable.class));
        IllegalStateException persistenceFailure = new IllegalStateException("write failed");
        doThrow(persistenceFailure).when(fixture.lifecycle)
                .rejectScheduling(eq(fixture.runId), any(UUID.class), eq(ACTOR));

        assertThatThrownBy(() -> TransactionSynchronizationManager.getSynchronizations()
                .forEach(TransactionSynchronization::afterCommit))
                .isSameAs(persistenceFailure);
        verifyNoInteractions(fixture.dispatch);
    }

    private Runnable afterCommitTask(Executor executor) {
        assertThat(TransactionSynchronizationManager.getSynchronizations()).hasSize(1);
        TransactionSynchronizationManager.getSynchronizations()
                .forEach(TransactionSynchronization::afterCommit);
        ArgumentCaptor<Runnable> task = ArgumentCaptor.forClass(Runnable.class);
        verify(executor).execute(task.capture());
        return task.getValue();
    }

    private void assertInvalid(org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).isInstanceOf(BusinessException.class)
                .satisfies(error -> assertThat(((BusinessException) error).errorCode())
                        .isEqualTo(ErrorCode.VALIDATION_ERROR));
    }

    private record CaseRow(UUID id, String partition, boolean hidden) {
    }

    private static final class Fixture {
        final UUID releaseId = UUID.randomUUID();
        final UUID suiteId = UUID.randomUUID();
        final UUID runId = UUID.randomUUID();
        final AgentReleaseRepository releases = mock(AgentReleaseRepository.class);
        final FingerprintService fingerprints = mock(FingerprintService.class);
        final SandboxFixtureService fixtures = mock(SandboxFixtureService.class);
        final AuthenticatedTestRunRegistrationService admission =
                mock(AuthenticatedTestRunRegistrationService.class);
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        final ExecutionDispatchService dispatch = mock(ExecutionDispatchService.class);
        final RunExecutionLifecycleService lifecycle = mock(RunExecutionLifecycleService.class);
        final Executor executor = mock(Executor.class);
        final FakeJdbcTemplate db;
        final TestRunStartService service;

        Fixture(List<CaseRow> rows) {
            db = new FakeJdbcTemplate(rows);
            httpRequest.addHeader("X-Actor-Id", "forged-header-actor");
            AgentReleaseEntity release = mock(AgentReleaseEntity.class);
            when(releases.findById(releaseId)).thenReturn(Optional.of(release));
            when(release.getManifestJson()).thenReturn(new ObjectMapper().createObjectNode());
            when(fingerprints.hash(any())).thenReturn(HASH);
            when(fixtures.fixtureDigest("golden-v1")).thenReturn(HASH);
            when(admission.register(any(), eq(httpRequest))).thenReturn(
                    new AuthenticatedTestRunRegistrationService.Admission(
                            new TestRunPersistenceDto.Registered(runId, TestRunStatus.QUEUED,
                                    "/api/v1/test-runs/" + runId,
                                    "/api/v1/test-runs/" + runId + "/events"), ACTOR));
            service = new TestRunStartService(releases, fingerprints, fixtures,
                    admission, dispatch, lifecycle, db, executor);
        }

        TestRunStartService.Request request(TestRunMode mode, List<UUID> ids) {
            return new TestRunStartService.Request(releaseId, suiteId, mode, null, ids, 42L);
        }
    }

    private static final class FakeJdbcTemplate extends JdbcTemplate {
        private final List<CaseRow> rows;
        int caseQueryCount;
        boolean changeOnSecondCaseQuery;

        FakeJdbcTemplate(List<CaseRow> rows) {
            this.rows = rows;
        }

        @Override
        public <T> List<T> query(String sql, RowMapper<T> mapper, Object... args) {
            if (sql.contains("from agent_releases release")) {
                return List.of(map(mapper, Map.of("fixture_version", "golden-v1", "status", "READY"), 0));
            }
            caseQueryCount++;
            if (changeOnSecondCaseQuery && caseQueryCount == 2) {
                return List.of();
            }
            List<T> mapped = new ArrayList<>();
            for (int index = 0; index < rows.size(); index++) {
                CaseRow row = rows.get(index);
                mapped.add(map(mapper, Map.of("id", row.id(), "partition_name", row.partition(),
                        "hidden_from_patch_generator", row.hidden()), index));
            }
            return mapped;
        }

        private <T> T map(RowMapper<T> mapper, Map<String, Object> values, int index) {
            try {
                ResultSet resultSet = mock(ResultSet.class);
                when(resultSet.getString(anyString()))
                        .thenAnswer(invocation -> values.get(invocation.getArgument(0)));
                when(resultSet.getBoolean(anyString()))
                        .thenAnswer(invocation -> values.get(invocation.getArgument(0)));
                when(resultSet.getObject(anyString(), eq(UUID.class)))
                        .thenAnswer(invocation -> values.get(invocation.getArgument(0)));
                return mapper.mapRow(resultSet, index);
            } catch (SQLException exception) {
                throw new IllegalStateException(exception);
            }
        }
    }
}
