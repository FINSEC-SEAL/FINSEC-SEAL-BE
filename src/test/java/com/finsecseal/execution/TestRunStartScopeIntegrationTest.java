package com.finsecseal.execution;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.core.task.TaskRejectedException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

@Testcontainers
@SpringBootTest
class TestRunStartScopeIntegrationTest {

    private static final String ACTOR = "b-run-scope-test";
    private static final String HASH_A = "sha256:" + "a".repeat(64);
    private static final String HASH_B = "sha256:" + "b".repeat(64);

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired JdbcTemplate db;
    @Autowired TestRunStartService startService;
    @Autowired RunExecutionLifecycleService lifecycleService;

    @MockitoSpyBean
    TestRunPersistenceService runPersistence;

    @MockitoBean(name = "testRunExecutor")
    Executor executor;

    @MockitoBean
    ExecutionDispatchService dispatch;

    @BeforeEach
    void clearExecutionMocks() {
        reset(executor, dispatch, runPersistence);
    }

    @Test
    void baselineNormalOnlySuiteAcceptsNullAndEmptyWithCommittedDispatch() throws Exception {
        for (List<UUID> selection : Arrays.<List<UUID>>asList(null, List.of())) {
            Seed seed = seed();
            UUID normal = addCase(seed.suiteId(), "NORMAL", false, "normal");
            ready(seed.suiteId());
            AtomicInteger independentlyVisibleRuns = new AtomicInteger(-1);
            doAnswer(invocation -> {
                independentlyVisibleRuns.set(committedRunCount(seed.releaseId()));
                return null;
            }).when(executor).execute(any(Runnable.class));

            TestRunPersistenceDto.Registered result = startService.start(
                    request(seed, TestRunMode.BASELINE, null, selection), ACTOR);

            assertThat(result.runId()).isNotNull();
            assertThat(runCount(seed.releaseId())).isEqualTo(1);
            assertThat(auditCount(seed.workspaceId())).isEqualTo(1);
            assertThat(independentlyVisibleRuns.get()).isEqualTo(1);
            assertThat(db.queryForObject("select total_cases from test_runs where id = ?",
                    Integer.class, result.runId())).isEqualTo(1);
            runScheduledTask();
            verify(dispatch).execute(result.runId(), normal, ACTOR);
            reset(executor, dispatch);
        }
    }

    @Test
    void explicitUuidArrayKeepsOrderAndRejectsHiddenOrForeignCasesWithoutWrites() {
        Seed seed = seed();
        UUID first = addCase(seed.suiteId(), "SEED", false, "seed");
        UUID second = addCase(seed.suiteId(), "MUTATION", false, "mutation");
        UUID hidden = addCase(seed.suiteId(), "HELD_OUT", true, "hidden");
        ready(seed.suiteId());
        UUID foreignSuite = newSuite(seed.workspaceId());
        UUID foreign = addCase(foreignSuite, "SEED", false, "foreign");
        ready(foreignSuite);

        assertError(ErrorCode.VALIDATION_ERROR, () -> startService.start(
                request(seed, TestRunMode.BASELINE, null, List.of(hidden)), ACTOR));
        assertError(ErrorCode.VALIDATION_ERROR, () -> startService.start(
                request(seed, TestRunMode.BASELINE, null, List.of(foreign)), ACTOR));
        assertThat(runCount(seed.releaseId())).isZero();
        assertThat(auditCount(seed.workspaceId())).isZero();
        verifyNoInteractions(executor, dispatch);

        TestRunPersistenceDto.Registered result = startService.start(
                request(seed, TestRunMode.BASELINE, null, List.of(second, first)), ACTOR);
        assertThat(db.queryForObject("select total_cases from test_runs where id = ?",
                Integer.class, result.runId())).isEqualTo(2);
        runScheduledTask();
        var ordered = inOrder(dispatch);
        ordered.verify(dispatch).execute(result.runId(), second, ACTOR);
        ordered.verify(dispatch).execute(result.runId(), first, ACTOR);
    }

    @Test
    void heldOutAutoSelectionUsesOnlyHiddenHeldOutAndRejectsClientIds() {
        Seed seed = seed();
        UUID normal = addCase(seed.suiteId(), "NORMAL", false, "normal");
        UUID hidden = addCase(seed.suiteId(), "HELD_OUT", true, "hidden");
        ready(seed.suiteId());
        UUID contract = approvedContract(seed);

        assertError(ErrorCode.VALIDATION_ERROR, () -> startService.start(
                request(seed, TestRunMode.HELD_OUT, contract, List.of(hidden)), ACTOR));
        assertThat(runCount(seed.releaseId())).isZero();
        verifyNoInteractions(executor, dispatch);

        TestRunPersistenceDto.Registered result = startService.start(
                request(seed, TestRunMode.HELD_OUT, contract, List.of()), ACTOR);
        assertThat(db.queryForObject("select total_cases from test_runs where id = ?",
                Integer.class, result.runId())).isEqualTo(1);
        runScheduledTask();
        verify(dispatch).execute(result.runId(), hidden, ACTOR);
        assertThat(normal).isNotEqualTo(hidden);
    }

    @Test
    void invalidSelectionsAndForeignWorkspaceHaveNoRunAuditOrExecutorEffect() {
        Seed seed = seed();
        UUID normal = addCase(seed.suiteId(), "NORMAL", false, "normal");
        ready(seed.suiteId());
        UUID other = UUID.randomUUID();
        List<List<UUID>> invalid = List.of(
                Arrays.asList(normal, null),
                List.of(normal, normal),
                IntStream.range(0, 10_001).mapToObj(index -> new UUID(0, index)).toList(),
                List.of(other));
        for (List<UUID> selection : invalid) {
            assertError(ErrorCode.VALIDATION_ERROR, () -> startService.start(
                    request(seed, TestRunMode.BASELINE, null, selection), ACTOR));
        }

        Seed foreign = seed();
        addCase(foreign.suiteId(), "NORMAL", false, "normal");
        ready(foreign.suiteId());
        assertError(ErrorCode.RESOURCE_NOT_FOUND, () -> startService.start(
                new TestRunStartService.Request(seed.releaseId(), foreign.suiteId(),
                        TestRunMode.BASELINE, null, List.of(), 42L), ACTOR));
        assertThat(runCount(seed.releaseId())).isZero();
        assertThat(auditCount(seed.workspaceId())).isZero();
        verifyNoInteractions(executor, dispatch);
    }

    @Test
    void executorRejectionAfterCommitPersistsFailureAndReleasesActiveSlot() {
        Seed seed = seed();
        addCase(seed.suiteId(), "NORMAL", false, "normal");
        ready(seed.suiteId());
        String canary = "secret-executor-canary";
        doThrow(new TaskRejectedException(canary + " queue full"))
                .when(executor).execute(any(Runnable.class));

        assertThatThrownBy(() -> startService.start(
                request(seed, TestRunMode.BASELINE, null, List.of()), ACTOR))
                .isInstanceOf(BusinessException.class)
                .satisfies(error -> assertThat(((BusinessException) error).errorCode())
                        .isEqualTo(ErrorCode.INTERNAL_ERROR))
                .hasMessage("TestRun scheduling was rejected");
        assertThat(runCount(seed.releaseId())).isEqualTo(1);
        assertThat(auditCount(seed.workspaceId())).isEqualTo(1);
        UUID failedRunId = db.queryForObject(
                "select id from test_runs where release_id = ?", UUID.class, seed.releaseId());
        assertThat(db.queryForObject("select status from test_runs where id = ?",
                String.class, failedRunId)).isEqualTo("FAILED");
        assertThat(db.queryForObject("""
                select completed_cases = 0 and operational_error_count = 0
                  from test_runs where id = ?
                """, Boolean.class, failedRunId)).isTrue();
        assertThat(db.queryForList("""
                select event_type from execution_events where run_id = ? order by sequence
                """, String.class, failedRunId)).containsExactly("RUN_STARTED", "RUN_FAILED");
        assertThat(db.queryForObject("""
                select reason_code from execution_events
                 where run_id = ? and event_type = 'RUN_FAILED'
                """, String.class, failedRunId)).isEqualTo("EXECUTOR_REJECTED");
        assertThat(db.queryForObject("""
                select metadata_json ->> 'dispatchStatus' from execution_events
                 where run_id = ? and event_type = 'RUN_FAILED'
                """, String.class, failedRunId)).isEqualTo("REJECTED");
        assertThat(db.queryForObject("""
                select count(*) from test_case_runs where test_run_id = ?
                """, Integer.class, failedRunId)).isZero();
        assertThat(db.queryForObject("""
                select count(*) from sandbox_namespaces where id = ?
                """, Integer.class, failedRunId)).isZero();
        assertThat(db.queryForList("""
                select action from audit_records where workspace_id = ?
                """, String.class, seed.workspaceId())).containsExactlyInAnyOrder(
                        "TEST_RUN_REGISTERED", "EXECUTION_EVENT_APPENDED",
                        "EXECUTION_EVENT_APPENDED", "TEST_RUN_STATUS_UPDATED");
        assertThat(db.queryForObject("""
                select summary_json::text from test_runs where id = ?
                """, String.class, failedRunId)).doesNotContain(canary);
        assertThat(db.queryForObject("""
                select string_agg(metadata_json::text, ' ') from execution_events where run_id = ?
                """, String.class, failedRunId)).doesNotContain(canary);
        assertThat(db.queryForObject("""
                select string_agg(metadata_json::text, ' ') from audit_records where workspace_id = ?
                """, String.class, seed.workspaceId())).doesNotContain(canary);

        int previousAuditCount = db.queryForObject("""
                select count(*) from audit_records where workspace_id = ?
                """, Integer.class, seed.workspaceId());
        lifecycleService.rejectScheduling(failedRunId, UUID.randomUUID(), ACTOR);
        assertThat(db.queryForObject("""
                select count(*) from execution_events where run_id = ?
                """, Integer.class, failedRunId)).isEqualTo(2);
        assertThat(db.queryForObject("""
                select count(*) from audit_records where workspace_id = ?
                """, Integer.class, seed.workspaceId())).isEqualTo(previousAuditCount);

        reset(executor);
        TestRunPersistenceDto.Registered retry = startService.start(
                request(seed, TestRunMode.BASELINE, null, List.of()), ACTOR);
        assertThat(retry.runId()).isNotEqualTo(failedRunId);
        assertThat(runCount(seed.releaseId())).isEqualTo(2);
        verifyNoInteractions(dispatch);
    }

    @Test
    void schedulingFailureTransactionRollsBackEventsAndAuditWhenStatusWriteFails() {
        Seed seed = seed();
        addCase(seed.suiteId(), "NORMAL", false, "normal");
        ready(seed.suiteId());
        TestRunPersistenceDto.Registered registered = startService.start(
                request(seed, TestRunMode.BASELINE, null, List.of()), ACTOR);
        doThrow(new IllegalStateException("status write failed"))
                .when(runPersistence).updateStatus(eq(registered.runId()),
                        any(TestRunPersistenceDto.StatusRequest.class), eq(ACTOR));

        assertThatThrownBy(() -> lifecycleService.rejectScheduling(
                registered.runId(), UUID.randomUUID(), ACTOR))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("status write failed");
        assertThat(db.queryForObject("select status from test_runs where id = ?",
                String.class, registered.runId())).isEqualTo("QUEUED");
        assertThat(db.queryForObject("""
                select count(*) from execution_events where run_id = ?
                """, Integer.class, registered.runId())).isZero();
        assertThat(db.queryForObject("""
                select count(*) from audit_records where workspace_id = ?
                """, Integer.class, seed.workspaceId())).isEqualTo(1);
        verifyNoInteractions(dispatch);
    }

    private TestRunStartService.Request request(Seed seed, TestRunMode mode,
            UUID contract, List<UUID> ids) {
        return new TestRunStartService.Request(seed.releaseId(), seed.suiteId(),
                mode, contract, ids, 42L);
    }

    private void runScheduledTask() {
        ArgumentCaptor<Runnable> task = ArgumentCaptor.forClass(Runnable.class);
        verify(executor).execute(task.capture());
        task.getValue().run();
    }

    private Seed seed() {
        UUID workspace = UUID.randomUUID(), agent = UUID.randomUUID(), release = UUID.randomUUID();
        db.update("insert into workspaces(id,name,mode) values (?,?,'DEMO')",
                workspace, "B run scope " + workspace);
        db.update("""
                insert into agents(id,workspace_id,agent_key,name,purpose_summary,status)
                values (?,?,?,'B Scope Agent','Run scope test','ACTIVE')
                """, agent, workspace, "b-scope-" + agent);
        db.update("""
                insert into agent_releases(id,agent_id,version,business_purpose,manifest_schema_version,
                    manifest_json,agent_artifact_fingerprint,release_fingerprint,lifecycle_state,effective_status)
                values (?,?,'1.0','LOAN_DOCUMENT_COMPLETENESS_REVIEW','1.0',
                    '{"model":{}}'::jsonb,?,?,'ANALYZED','ANALYZED')
                """, release, agent, HASH_A, HASH_B);
        return new Seed(workspace, release, newSuite(workspace));
    }

    private UUID newSuite(UUID workspace) {
        UUID suite = UUID.randomUUID();
        db.update("""
                insert into test_suites(id,workspace_id,suite_key,version,fixture_version,
                    generation_config_json,suite_hash,status)
                values (?,?,?,'1.0','golden-v1','{}'::jsonb,?,'BUILDING')
                """, suite, workspace, "b-scope-suite-" + suite, HASH_A);
        return suite;
    }

    private UUID addCase(UUID suite, String partition, boolean hidden, String key) {
        UUID id = UUID.randomUUID();
        boolean normal = "NORMAL".equals(partition);
        db.update("""
                insert into test_cases(id,suite_id,case_key,case_type,partition_name,category,
                    severity,delivery_channel,payload_hash,preconditions_json,expected_invariant,
                    oracle_type,generation_source,hidden_from_patch_generator,
                    expected_result_json,trial_policy_json)
                values (?,?,?,?,?,?,?,'DIRECT',?,'{}'::jsonb,?,?,'CURATED',?,'{}'::jsonb,'{}'::jsonb)
                """, id, suite, key, normal ? "NORMAL" : "ATTACK", partition,
                normal ? "NORMAL" : "FA-02", normal ? "LOW" : "HIGH", HASH_A,
                normal ? "INV-NORMAL" : "INV-01", normal ? "NORMAL_TASK" : "CROSS_CUSTOMER", hidden);
        return id;
    }

    private void ready(UUID suite) {
        db.update("update test_suites set status = 'READY' where id = ?", suite);
    }

    private UUID approvedContract(Seed seed) {
        UUID contract = UUID.randomUUID(), version = UUID.randomUUID();
        db.update("""
                insert into safety_contracts(id,workspace_id,release_id,contract_key,status)
                values (?,?,?,?, 'ACTIVE')
                """, contract, seed.workspaceId(), seed.releaseId(), "b-scope-contract");
        db.update("""
                insert into safety_contract_versions(id,contract_id,version,state,policy_json,
                    policy_hash,created_by,approved_by,approved_at)
                values (?,?,1,'APPROVED','{}'::jsonb,?,'b-scope','b-scope',now())
                """, version, contract, HASH_A);
        return version;
    }

    private int runCount(UUID release) {
        return db.queryForObject("select count(*) from test_runs where release_id = ?",
                Integer.class, release);
    }

    private int auditCount(UUID workspace) {
        return db.queryForObject("""
                select count(*) from audit_records
                 where workspace_id = ? and action = 'TEST_RUN_REGISTERED'
                """, Integer.class, workspace);
    }

    private int committedRunCount(UUID release) throws Exception {
        try (Connection connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             PreparedStatement statement = connection.prepareStatement(
                     "select count(*) from test_runs where release_id = ?")) {
            statement.setObject(1, release);
            try (ResultSet result = statement.executeQuery()) {
                result.next();
                return result.getInt(1);
            }
        }
    }

    private void assertError(ErrorCode expected, org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).isInstanceOf(BusinessException.class)
                .satisfies(error -> assertThat(((BusinessException) error).errorCode())
                        .isEqualTo(expected));
    }

    private record Seed(UUID workspaceId, UUID releaseId, UUID suiteId) {
    }
}
