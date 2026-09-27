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
import com.finsecseal.agent.AgentService;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.platform.contract.ContractReviewerCredentials;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import jakarta.servlet.http.Cookie;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.core.task.TaskRejectedException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "finsec.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "finsec.scheduling.enabled=false",
        "finsec.contract-access.key=b-run-scope-reviewer-key-at-least-32-bytes",
        "finsec.contract-access.actor=b-run-scope-reviewer",
        "finsec.contract-access.workspace=0198f1e2-0000-7000-8000-000000000001"
})
class TestRunStartScopeIntegrationTest {

    private static final String ACTOR = "b-run-scope-reviewer";
    private static final String HASH_A = "sha256:" + "a".repeat(64);
    private static final String HASH_B = "sha256:" + "b".repeat(64);

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired JdbcTemplate db;
    @Autowired ObjectMapper json;
    @Autowired ContractReviewerCredentials credentials;
    @Autowired TestRunStartService startService;
    @Autowired RunExecutionLifecycleService lifecycleService;
    @LocalServerPort int port;

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
                    request(seed, TestRunMode.BASELINE, null, selection), reviewerRequest());

            assertThat(result.runId()).isNotNull();
            assertThat(runCount(seed.releaseId())).isEqualTo(1);
            assertThat(registrationAuditCount(seed.releaseId())).isEqualTo(1);
            assertGrant(result.runId());
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
                request(seed, TestRunMode.BASELINE, null, List.of(hidden)), reviewerRequest()));
        assertError(ErrorCode.VALIDATION_ERROR, () -> startService.start(
                request(seed, TestRunMode.BASELINE, null, List.of(foreign)), reviewerRequest()));
        assertThat(runCount(seed.releaseId())).isZero();
        assertThat(registrationAuditCount(seed.releaseId())).isZero();
        verifyNoInteractions(executor, dispatch);

        TestRunPersistenceDto.Registered result = startService.start(
                request(seed, TestRunMode.BASELINE, null, List.of(second, first)), reviewerRequest());
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
                request(seed, TestRunMode.HELD_OUT, contract, List.of(hidden)), reviewerRequest()));
        assertThat(runCount(seed.releaseId())).isZero();
        verifyNoInteractions(executor, dispatch);

        TestRunPersistenceDto.Registered result = startService.start(
                request(seed, TestRunMode.HELD_OUT, contract, List.of()), reviewerRequest());
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
                    request(seed, TestRunMode.BASELINE, null, selection), reviewerRequest()));
        }

        Seed foreign = seed(UUID.randomUUID());
        addCase(foreign.suiteId(), "NORMAL", false, "normal");
        ready(foreign.suiteId());
        assertError(ErrorCode.RESOURCE_NOT_FOUND, () -> startService.start(
                new TestRunStartService.Request(seed.releaseId(), foreign.suiteId(),
                        TestRunMode.BASELINE, null, List.of(), 42L), reviewerRequest()));
        assertThat(runCount(seed.releaseId())).isZero();
        assertThat(registrationAuditCount(seed.releaseId())).isZero();
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
                request(seed, TestRunMode.BASELINE, null, List.of()), reviewerRequest()))
                .isInstanceOf(BusinessException.class)
                .satisfies(error -> assertThat(((BusinessException) error).errorCode())
                        .isEqualTo(ErrorCode.INTERNAL_ERROR))
                .hasMessage("TestRun scheduling was rejected");
        assertThat(runCount(seed.releaseId())).isEqualTo(1);
        assertThat(registrationAuditCount(seed.releaseId())).isEqualTo(1);
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
        assertThat(runAuditActions(failedRunId)).containsExactlyInAnyOrder(
                        "TEST_RUN_REGISTERED", "EXECUTION_EVENT_APPENDED",
                        "EXECUTION_EVENT_APPENDED", "TEST_RUN_STATUS_UPDATED");
        assertThat(db.queryForObject("""
                select summary_json::text from test_runs where id = ?
                """, String.class, failedRunId)).doesNotContain(canary);
        assertThat(db.queryForObject("""
                select string_agg(metadata_json::text, ' ') from execution_events where run_id = ?
                """, String.class, failedRunId)).doesNotContain(canary);
        assertThat(runAuditMetadata(failedRunId)).doesNotContain(canary);

        int previousAuditCount = runAuditCount(failedRunId);
        lifecycleService.rejectScheduling(failedRunId, UUID.randomUUID(), ACTOR);
        assertThat(db.queryForObject("""
                select count(*) from execution_events where run_id = ?
                """, Integer.class, failedRunId)).isEqualTo(2);
        assertThat(runAuditCount(failedRunId)).isEqualTo(previousAuditCount);

        reset(executor);
        TestRunPersistenceDto.Registered retry = startService.start(
                request(seed, TestRunMode.BASELINE, null, List.of()), reviewerRequest());
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
                request(seed, TestRunMode.BASELINE, null, List.of()), reviewerRequest());
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
        assertThat(runAuditCount(registered.runId())).isEqualTo(1);
        verifyNoInteractions(dispatch);
    }

    @Test
    void signedReviewerCannotRegisterForeignWorkspaceAndLeavesNoPartialRunOrDispatch() {
        Seed foreign = seed(UUID.randomUUID());
        addCase(foreign.suiteId(), "NORMAL", false, "normal");
        ready(foreign.suiteId());

        assertError(ErrorCode.OPERATOR_AUTH_REQUIRED, () -> startService.start(
                request(foreign, TestRunMode.BASELINE, null, List.of()), reviewerRequest()));

        assertThat(runCount(foreign.releaseId())).isZero();
        assertThat(grantCount(foreign.releaseId())).isZero();
        assertThat(db.queryForObject("select count(*) from audit_records where workspace_id = ?",
                Integer.class, foreign.workspaceId())).isZero();
        verifyNoInteractions(executor, dispatch);
    }

    @Test
    void publicHttpSignedReviewerAdmitsOnceAndReplaysIdempotentResult() throws Exception {
        Seed seed = seed();
        UUID normal = addCase(seed.suiteId(), "NORMAL", false, "normal");
        ready(seed.suiteId());
        var session = credentials.issue();
        String key = "b-run-signed-" + UUID.randomUUID();

        HttpResponse<String> first = httpStart(seed, session, key, true);
        assertThat(first.statusCode()).isEqualTo(202);
        UUID runId = UUID.fromString(json.readTree(first.body()).path("data").path("runId").asString());
        assertThat(runCount(seed.releaseId())).isEqualTo(1);
        assertThat(registrationAuditCount(seed.releaseId())).isEqualTo(1);
        assertGrant(runId);
        assertThat(db.queryForMap("""
                select actor_id, state, response_status from api_idempotency_records
                 where idempotency_key = ? and request_path = '/api/v1/test-runs'
                """, key)).containsEntry("actor_id", ACTOR)
                .containsEntry("state", "COMPLETED")
                .containsEntry("response_status", 202);

        HttpResponse<String> replay = httpStart(seed, session, key, true);
        assertThat(replay.statusCode()).isEqualTo(202);
        assertThat(replay.body()).isEqualTo(first.body());
        assertThat(runCount(seed.releaseId())).isEqualTo(1);
        assertThat(grantCount(seed.releaseId())).isEqualTo(1);
        runScheduledTask();
        verify(dispatch).execute(runId, normal, ACTOR);
    }

    @Test
    void publicHttpPreAuthenticationFailureCreatesNoReservationOrRun() throws Exception {
        Seed seed = seed();
        addCase(seed.suiteId(), "NORMAL", false, "normal");
        ready(seed.suiteId());
        var session = credentials.issue();
        String absentCookieKey = "b-run-no-cookie-" + UUID.randomUUID();
        String absentCsrfKey = "b-run-no-csrf-" + UUID.randomUUID();

        assertThat(httpStart(seed, null, absentCookieKey, false).statusCode()).isEqualTo(403);
        assertThat(httpStart(seed, session, absentCsrfKey, false).statusCode()).isEqualTo(403);

        assertThat(idempotencyCount(absentCookieKey)).isZero();
        assertThat(idempotencyCount(absentCsrfKey)).isZero();
        assertThat(runCount(seed.releaseId())).isZero();
        assertThat(grantCount(seed.releaseId())).isZero();
        assertThat(registrationAuditCount(seed.releaseId())).isZero();
        verifyNoInteractions(executor, dispatch);
    }

    @Test
    void publicHttpAuthenticatedForeignWorkspaceFailureMayCompleteIdempotencyWithoutRun() throws Exception {
        Seed foreign = seed(UUID.randomUUID());
        addCase(foreign.suiteId(), "NORMAL", false, "normal");
        ready(foreign.suiteId());
        String key = "b-run-foreign-" + UUID.randomUUID();

        HttpResponse<String> response = httpStart(foreign, credentials.issue(), key, true);
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(runCount(foreign.releaseId())).isZero();
        assertThat(grantCount(foreign.releaseId())).isZero();
        assertThat(db.queryForObject("select count(*) from audit_records where workspace_id = ?",
                Integer.class, foreign.workspaceId())).isZero();
        assertThat(db.queryForMap("""
                select actor_id, state, response_status from api_idempotency_records
                 where idempotency_key = ? and request_path = '/api/v1/test-runs'
                """, key)).containsEntry("actor_id", ACTOR)
                .containsEntry("state", "COMPLETED")
                .containsEntry("response_status", 403);
        verifyNoInteractions(executor, dispatch);
    }

    private TestRunStartService.Request request(Seed seed, TestRunMode mode,
            UUID contract, List<UUID> ids) {
        return new TestRunStartService.Request(seed.releaseId(), seed.suiteId(),
                mode, contract, ids, 42L);
    }

    private MockHttpServletRequest reviewerRequest() {
        var session = credentials.issue();
        var request = new MockHttpServletRequest();
        request.setCookies(new Cookie(ContractReviewerCredentials.COOKIE, session.token()));
        request.addHeader("X-CSRF-Token", session.csrfToken());
        return request;
    }

    private HttpResponse<String> httpStart(Seed seed, ContractReviewerCredentials.Session session,
            String key, boolean includeCsrf) throws Exception {
        String body = json.writeValueAsString(Map.of(
                "releaseId", seed.releaseId(), "suiteId", seed.suiteId(),
                "mode", "BASELINE", "caseIds", List.of(), "randomSeed", 42L));
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(
                        "http://localhost:" + port + "/api/v1/test-runs"))
                .header("Content-Type", "application/json")
                .header("Idempotency-Key", key);
        if (session != null) {
            request.header("Cookie", ContractReviewerCredentials.COOKIE + "=" + session.token());
            if (includeCsrf) request.header("X-CSRF-Token", session.csrfToken());
        }
        return HttpClient.newHttpClient().send(request.POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private void runScheduledTask() {
        ArgumentCaptor<Runnable> task = ArgumentCaptor.forClass(Runnable.class);
        verify(executor).execute(task.capture());
        task.getValue().run();
    }

    private Seed seed() {
        return seed(AgentService.DEMO_WORKSPACE_ID);
    }

    private Seed seed(UUID workspace) {
        UUID agent = UUID.randomUUID(), release = UUID.randomUUID();
        if (!AgentService.DEMO_WORKSPACE_ID.equals(workspace)) {
            db.update("insert into workspaces(id,name,mode) values (?,?,'DEMO')",
                    workspace, "B run scope " + workspace);
        }
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

    private int registrationAuditCount(UUID release) {
        return db.queryForObject("""
                select count(*) from audit_records audit
                  join test_runs run on run.id = audit.resource_id
                 where audit.resource_type = 'TEST_RUN'
                   and audit.action = 'TEST_RUN_REGISTERED' and run.release_id = ?
                """, Integer.class, release);
    }

    private int grantCount(UUID release) {
        return db.queryForObject("""
                select count(*) from test_run_reviewer_grants grant_row
                  join test_runs run on run.id = grant_row.run_id
                 where run.release_id = ?
                """, Integer.class, release);
    }

    private void assertGrant(UUID runId) {
        assertThat(db.queryForMap("""
                select workspace_id, actor_id, reviewer_role
                  from test_run_reviewer_grants where run_id = ?
                """, runId)).containsEntry("workspace_id", AgentService.DEMO_WORKSPACE_ID)
                .containsEntry("actor_id", ACTOR)
                .containsEntry("reviewer_role", "AI_SECURITY_REVIEWER");
        assertThat(db.queryForObject("""
                select actor_id from audit_records
                 where resource_type = 'TEST_RUN' and resource_id = ?
                   and action = 'TEST_RUN_REGISTERED'
                """, String.class, runId)).isEqualTo(ACTOR);
    }

    private int idempotencyCount(String key) {
        return db.queryForObject("""
                select count(*) from api_idempotency_records
                 where idempotency_key = ? and request_path = '/api/v1/test-runs'
                """, Integer.class, key);
    }

    private List<String> runAuditActions(UUID runId) {
        return db.queryForList("""
                select action from audit_records
                 where (resource_type = 'TEST_RUN' and resource_id = ?)
                    or (resource_type = 'EXECUTION_EVENT' and resource_id in
                        (select id from execution_events where run_id = ?))
                """, String.class, runId, runId);
    }

    private String runAuditMetadata(UUID runId) {
        return db.queryForObject("""
                select string_agg(metadata_json::text, ' ') from audit_records
                 where (resource_type = 'TEST_RUN' and resource_id = ?)
                    or (resource_type = 'EXECUTION_EVENT' and resource_id in
                        (select id from execution_events where run_id = ?))
                """, String.class, runId, runId);
    }

    private int runAuditCount(UUID runId) {
        return runAuditActions(runId).size();
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
