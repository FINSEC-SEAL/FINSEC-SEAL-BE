package com.finsecseal.evidence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.agent.AgentService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.platform.contract.ContractReviewerCredentials;
import com.finsecseal.platform.contract.ContractReviewerSessionRevocations;
import com.finsecseal.policy.GatewayRuntimeObservations.InvocationKey;
import jakarta.servlet.http.Cookie;
import java.sql.Connection;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;

@Testcontainers
@SpringBootTest(properties = {
        "finsec.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "finsec.scheduling.enabled=false",
        "finsec.contract-access.key=test-reviewer-key-at-least-32-bytes-long",
        "finsec.contract-access.actor=run-grant-reviewer",
        "finsec.contract-access.workspace=0198f1e2-0000-7000-8000-000000000001"
})
class StoredRunReviewerAuthoritySourceIntegrationTest {
    private static final String KEY = "test-reviewer-key-at-least-32-bytes-long";
    private static final String ACTOR = "run-grant-reviewer";
    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final String OTHER_HASH = "sha256:" + "b".repeat(64);

    @Container @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired DataSource dataSource;
    @Autowired JdbcTemplate db;
    @Autowired ObjectMapper json;
    @Autowired ContractReviewerCredentials credentials;
    @Autowired ContractReviewerSessionRevocations revocations;
    @Autowired AuthenticatedTestRunRegistrationService admission;
    @Autowired TestRunPersistenceService runs;
    @Autowired ExecutionEventService events;
    @Autowired StoredRunReviewerAuthoritySource source;

    @Test
    void signedAdmissionAndExactStoredProposalResolveWithoutNewEvidenceOrSecrets() {
        Fixture fixture = authenticatedFixture();
        Counts before = counts();

        var authority = resolve(source, fixture.key(), Duration.ofSeconds(5));

        assertThat(authority.key()).isEqualTo(fixture.key());
        assertThat(authority.workspaceId()).isEqualTo(AgentService.DEMO_WORKSPACE_ID);
        assertThat(authority.actorId()).isEqualTo(ACTOR);
        assertThat(authority.role()).isEqualTo("AI_SECURITY_REVIEWER");
        assertThat(authority.sessionReference()).isEqualTo(revocations.sessionDigest(fixture.session()))
                .matches("sha256:[0-9a-f]{64}");
        assertThat(authority.expiresAt()).isAfter(Instant.now());
        String stamp = db.queryForObject("select authority_stamp from test_run_reviewer_grants where run_id = ?",
                String.class, fixture.key().runId());
        assertThat(authority.toString()).doesNotContain(ACTOR, fixture.session().token(),
                fixture.session().csrfToken(), fixture.session().reviewer().sessionId(),
                authority.sessionReference(), stamp);
        assertThat(counts()).isEqualTo(before);
    }

    @Test
    void everyInvocationKeyFieldAndMissingGrantFailClosedWithoutMutatingEvidence() {
        Fixture fixture = authenticatedFixture();
        Counts before = counts();
        InvocationKey key = fixture.key();
        for (InvocationKey wrong : List.of(
                new InvocationKey(UUID.randomUUID(), key.caseRunId(), key.traceId(), key.toolCallId(), key.requestDigest()),
                new InvocationKey(key.runId(), UUID.randomUUID(), key.traceId(), key.toolCallId(), key.requestDigest()),
                new InvocationKey(key.runId(), key.caseRunId(), UUID.randomUUID(), key.toolCallId(), key.requestDigest()),
                new InvocationKey(key.runId(), key.caseRunId(), key.traceId(), UUID.randomUUID(), key.requestDigest()),
                new InvocationKey(key.runId(), key.caseRunId(), key.traceId(), key.toolCallId(), OTHER_HASH))) {
            assertUnavailable(() -> resolve(source, wrong, Duration.ofSeconds(5)));
        }
        assertThat(counts()).isEqualTo(before);

        Seed legacy = seed(AgentService.DEMO_WORKSPACE_ID);
        UUID legacyRun = runs.register(legacy.request(), "legacy-actor").runId();
        InvocationKey legacyKey = prepareRuntime(legacyRun, legacy.caseId());
        assertUnavailable(() -> resolve(source, legacyKey, Duration.ofSeconds(5)));
    }

    @Test
    void runtimeStatusRevocationAndCredentialRotationInvalidateStoredGrant() {
        Fixture cancelling = authenticatedFixture();
        events.append(cancelling.key().runId(), new ExecutionEventDto.AppendRequest(null,
                cancelling.key().traceId(), ExecutionEventType.RUN_CANCEL_REQUESTED,
                null, null, null, null, null, json.createObjectNode()), ACTOR);
        runs.updateStatus(cancelling.key().runId(),
                new TestRunPersistenceDto.StatusRequest(TestRunStatus.CANCELLING, 0, 0, null), ACTOR);
        assertUnavailable(() -> resolve(source, cancelling.key(), Duration.ofSeconds(5)));

        Fixture evaluating = authenticatedFixture();
        runs.updateCaseStatus(evaluating.key().runId(), evaluating.key().caseRunId(),
                new TestRunPersistenceDto.CaseRunStatusRequest(TestCaseRunStatus.EVALUATING,
                        null, null, null, null, null, null), ACTOR);
        assertUnavailable(() -> resolve(source, evaluating.key(), Duration.ofSeconds(5)));

        Fixture fixture = authenticatedFixture();

        var rotatedKey = new ContractReviewerCredentials(KEY + "-rotated", ACTOR,
                AgentService.DEMO_WORKSPACE_ID.toString(), json);
        var rotatedActor = new ContractReviewerCredentials(KEY, ACTOR + "-rotated",
                AgentService.DEMO_WORKSPACE_ID.toString(), json);
        var rotatedWorkspace = new ContractReviewerCredentials(KEY, ACTOR, UUID.randomUUID().toString(), json);
        for (ContractReviewerCredentials rotated : List.of(rotatedKey, rotatedActor, rotatedWorkspace)) {
            var reader = new StoredRunReviewerAuthoritySource(dataSource, rotated);
            assertUnavailable(() -> resolve(reader, fixture.key(), Duration.ofSeconds(5)));
        }

        revocations.revoke(fixture.session());
        Counts afterRevocation = counts();
        assertUnavailable(() -> resolve(source, fixture.key(), Duration.ofSeconds(5)));
        assertThat(counts()).isEqualTo(afterRevocation);
    }

    @Test
    void expiredOrWrongStampGrantAndForeignWorkspaceCannotBecomeCurrentAuthority() {
        Seed expired = seed(AgentService.DEMO_WORKSPACE_ID);
        UUID expiredRun = runs.register(expired.request(), "legacy-actor").runId();
        insertDirectGrant(expiredRun, AgentService.DEMO_WORKSPACE_ID, HASH, validStamp(),
                "now() - interval '2 days'", "now() - interval '1 day'");
        InvocationKey expiredKey = prepareRuntime(expiredRun, expired.caseId());
        assertUnavailable(() -> resolve(source, expiredKey, Duration.ofSeconds(5)));

        Seed wrongStamp = seed(AgentService.DEMO_WORKSPACE_ID);
        UUID wrongStampRun = runs.register(wrongStamp.request(), "legacy-actor").runId();
        insertDirectGrant(wrongStampRun, AgentService.DEMO_WORKSPACE_ID, OTHER_HASH, "wrong-stamp",
                "now()", "now() + interval '1 hour'");
        InvocationKey wrongStampKey = prepareRuntime(wrongStampRun, wrongStamp.caseId());
        assertUnavailable(() -> resolve(source, wrongStampKey, Duration.ofSeconds(5)));

        UUID foreignWorkspace = UUID.randomUUID();
        db.update("insert into workspaces (id, name, mode) values (?, 'Foreign authority test', 'DEMO')",
                foreignWorkspace);
        Seed foreign = seed(foreignWorkspace);
        UUID foreignRun = runs.register(foreign.request(), "legacy-actor").runId();
        var foreignCredentials = new ContractReviewerCredentials(KEY, ACTOR, foreignWorkspace.toString(), json);
        insertDirectGrant(foreignRun, foreignWorkspace, HASH,
                foreignCredentials.authorityStamp(foreignCredentials.issue().reviewer()),
                "now()", "now() + interval '1 hour'");
        InvocationKey foreignKey = prepareRuntime(foreignRun, foreign.caseId());
        assertUnavailable(() -> resolve(source, foreignKey, Duration.ofSeconds(5)));
    }

    @Test
    void requiresBoundReadOnlyRepeatableReadConnectionAndFiniteDeadline() {
        Fixture fixture = authenticatedFixture();
        assertUnavailable(() -> source.resolve(fixture.key(), Duration.ofSeconds(5)));
        assertUnavailable(() -> transaction(false, TransactionDefinition.ISOLATION_REPEATABLE_READ)
                .execute(ignored -> source.resolve(fixture.key(), Duration.ofSeconds(5))));
        assertUnavailable(() -> transaction(true, TransactionDefinition.ISOLATION_READ_COMMITTED)
                .execute(ignored -> source.resolve(fixture.key(), Duration.ofSeconds(5))));
        for (Duration invalid : List.of(Duration.ZERO, Duration.ofSeconds(-1), Duration.ofSeconds(6))) {
            assertUnavailable(() -> resolve(source, fixture.key(), invalid));
        }
        assertUnavailable(() -> resolve(source, fixture.key(), null));
    }

    @Test
    void databaseLockStopsWithinSuppliedDeadlineWithSafeCauseFreeError() throws Exception {
        Fixture fixture = authenticatedFixture();
        Counts before = counts();
        var executor = Executors.newSingleThreadExecutor();
        try (Connection blocker = dataSource.getConnection()) {
            blocker.setAutoCommit(false);
            try (Statement statement = blocker.createStatement()) {
                statement.execute("lock table test_run_reviewer_grants in access exclusive mode");
            }
            long started = System.nanoTime();
            var attempt = executor.submit(() -> resolve(source, fixture.key(), Duration.ofSeconds(2)));
            try {
                assertThatThrownBy(() -> attempt.get(5, TimeUnit.SECONDS))
                        .isInstanceOf(ExecutionException.class)
                        .satisfies(failure -> assertSafeFailure(failure.getCause()));
                assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(5));
            } finally {
                blocker.rollback();
            }
        } finally {
            executor.shutdownNow();
            assertThat(executor.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
        }
        assertThat(counts()).isEqualTo(before);
    }

    private Fixture authenticatedFixture() {
        Seed seed = seed(AgentService.DEMO_WORKSPACE_ID);
        var session = credentials.issue();
        var request = new MockHttpServletRequest();
        request.setCookies(new Cookie(ContractReviewerCredentials.COOKIE, session.token()));
        request.addHeader("X-CSRF-Token", session.csrfToken());
        UUID runId = admission.register(seed.request(), request).run().runId();
        return new Fixture(prepareRuntime(runId, seed.caseId()), session);
    }

    private InvocationKey prepareRuntime(UUID runId, UUID caseId) {
        UUID traceId = UUID.randomUUID();
        events.append(runId, new ExecutionEventDto.AppendRequest(null, traceId,
                ExecutionEventType.RUN_STARTED, null, null, null, null, null,
                json.createObjectNode()), ACTOR);
        runs.updateStatus(runId, new TestRunPersistenceDto.StatusRequest(TestRunStatus.PREPARING,
                0, 0, null), ACTOR);
        runs.updateStatus(runId, new TestRunPersistenceDto.StatusRequest(TestRunStatus.RUNNING,
                0, 0, null), ACTOR);
        UUID caseRunId = runs.registerCase(runId,
                new TestRunPersistenceDto.CaseRunRegisterRequest(caseId, 0, HASH), ACTOR).id();
        runs.updateCaseStatus(runId, caseRunId,
                new TestRunPersistenceDto.CaseRunStatusRequest(TestCaseRunStatus.EXECUTING,
                        null, null, null, null, null, null), ACTOR);
        var proposal = events.append(runId, new ExecutionEventDto.AppendRequest(caseRunId, traceId,
                ExecutionEventType.TOOL_PROPOSED, "CUSTOMER_DATA_READ", json.createObjectNode(),
                null, null, "STRUCTURED_TOOL_PROPOSAL", json.createObjectNode()), ACTOR);
        return new InvocationKey(runId, caseRunId, traceId, proposal.eventId(), proposal.payloadDigest());
    }

    private Seed seed(UUID workspaceId) {
        UUID agentId = UUID.randomUUID();
        UUID releaseId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        UUID caseId = UUID.randomUUID();
        String suffix = agentId.toString().substring(0, 8);
        db.update("""
                insert into agents (id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'Authority Agent', 'Reviewer source test', 'ACTIVE')
                """, agentId, workspaceId, "authority-agent-" + suffix);
        db.update("""
                insert into agent_releases
                    (id, agent_id, version, business_purpose, manifest_schema_version, manifest_json,
                     agent_artifact_fingerprint, release_fingerprint, lifecycle_state, effective_status)
                values (?, ?, '1.0.0', 'LOAN_DOCUMENT_COMPLETENESS_REVIEW', '1.0', '{}'::jsonb,
                        ?, ?, 'DRAFT', 'DRAFT')
                """, releaseId, agentId, HASH, HASH);
        db.update("update agent_releases set lifecycle_state = 'ANALYZED', effective_status = 'ANALYZED' where id = ?",
                releaseId);
        db.update("""
                insert into test_suites
                    (id, workspace_id, suite_key, version, fixture_version, generation_config_json,
                     suite_hash, status)
                values (?, ?, ?, '1.0.0', 'fixture-v1', '{}'::jsonb, ?, 'BUILDING')
                """, suiteId, workspaceId, "authority-suite-" + suffix, HASH);
        db.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name, category, severity,
                     delivery_channel, payload_hash, preconditions_json, expected_invariant,
                     oracle_type, generation_source, expected_result_json, trial_policy_json)
                values (?, ?, 'case-1', 'NORMAL', 'NORMAL', 'NORMAL', 'LOW', 'DIRECT', ?,
                        '{}'::jsonb, 'INV-NORMAL', 'NORMAL_TASK', 'CURATED', '{}'::jsonb, '{}'::jsonb)
                """, caseId, suiteId, HASH);
        db.update("update test_suites set status = 'READY' where id = ?", suiteId);
        return new Seed(releaseId, suiteId, caseId);
    }

    private void insertDirectGrant(UUID runId, UUID workspace, String sessionDigest,
            String stamp, String createdAtSql, String expiresAtSql) {
        db.update("""
                insert into test_run_reviewer_grants
                    (run_id, workspace_id, actor_id, reviewer_role, session_digest,
                     authority_stamp, created_at, authority_expires_at)
                values (?, ?, ?, 'AI_SECURITY_REVIEWER', ?, ?,
                """ + createdAtSql + ", " + expiresAtSql + ")", runId, workspace, ACTOR,
                sessionDigest, stamp);
    }

    private String validStamp() {
        return credentials.authorityStamp(credentials.issue().reviewer());
    }

    private StoredRunReviewerAuthoritySource.AuthoritySnapshot resolve(
            StoredRunReviewerAuthoritySource reader, InvocationKey key, Duration remaining) {
        return transaction(true, TransactionDefinition.ISOLATION_REPEATABLE_READ)
                .execute(ignored -> reader.resolve(key, remaining));
    }

    private TransactionTemplate transaction(boolean readOnly, int isolation) {
        var template = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        template.setReadOnly(readOnly);
        template.setIsolationLevel(isolation);
        return template;
    }

    private Counts counts() {
        return new Counts(count("test_runs"), count("test_case_runs"), count("execution_events"),
                count("test_run_reviewer_grants"), count("audit_records"));
    }

    private int count(String table) {
        return db.queryForObject("select count(*) from " + table, Integer.class);
    }

    private void assertUnavailable(ThrowingCall call) {
        assertThatThrownBy(call::run).isInstanceOf(BusinessException.class)
                .satisfies(this::assertSafeFailure);
    }

    private void assertSafeFailure(Throwable failure) {
        assertThat(failure).isInstanceOf(BusinessException.class);
        var denied = (BusinessException) failure;
        assertThat(denied.errorCode()).isEqualTo(ErrorCode.OPERATOR_AUTH_REQUIRED);
        assertThat(denied.getMessage()).isEqualTo("Current Run reviewer authority is unavailable");
        assertThat(denied.getCause()).isNull();
    }

    @FunctionalInterface private interface ThrowingCall { void run() throws Exception; }
    private record Seed(UUID releaseId, UUID suiteId, UUID caseId) {
        TestRunPersistenceDto.RegisterRequest request() {
            return new TestRunPersistenceDto.RegisterRequest(releaseId, suiteId, null, TestRunMode.BASELINE,
                    null, null, HASH, HASH, 42L, 1);
        }
    }
    private record Fixture(InvocationKey key, ContractReviewerCredentials.Session session) { }
    private record Counts(int runs, int caseRuns, int events, int grants, int audits) { }
}
