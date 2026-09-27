package com.finsecseal.evidence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.agent.AgentService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.platform.contract.ContractReviewerCredentials;
import com.finsecseal.platform.contract.ContractReviewerSessionRevocations;
import jakarta.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Testcontainers
@SpringBootTest(properties = {
        "finsec.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "finsec.scheduling.enabled=false",
        "finsec.contract-access.key=test-reviewer-key-at-least-32-bytes-long",
        "finsec.contract-access.actor=run-grant-reviewer",
        "finsec.contract-access.workspace=0198f1e2-0000-7000-8000-000000000001"
})
class AuthenticatedTestRunRegistrationIntegrationTest {
    private static final String KEY = "test-reviewer-key-at-least-32-bytes-long";
    private static final String ACTOR = "run-grant-reviewer";
    private static final String HASH = "sha256:" + "a".repeat(64);

    @Container @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired JdbcTemplate db;
    @Autowired ObjectMapper json;
    @Autowired ContractReviewerCredentials credentials;
    @Autowired ContractReviewerSessionRevocations revocations;
    @Autowired AuthenticatedTestRunRegistrationService admission;
    @Autowired TestRunPersistenceService legacyRuns;
    @Autowired ExecutionEventService events;

    @Test
    void signedCookieCommitsOneWorkspaceBoundGrantAndLegacyRegistrationCreatesNone() {
        Seed seed = seed(AgentService.DEMO_WORKSPACE_ID);
        var session = credentials.issue();
        var accepted = admission.register(seed.request(), request(session, session.csrfToken(), null));

        assertThat(accepted.actorId()).isEqualTo(ACTOR);
        assertThat(accepted.run().runId()).isNotNull();
        assertThat(db.queryForObject("select count(*) from test_runs where id = ?", Integer.class,
                accepted.run().runId())).isEqualTo(1);
        assertThat(db.queryForObject("select count(*) from audit_records where resource_type = 'TEST_RUN' "
                + "and resource_id = ? and action = 'TEST_RUN_REGISTERED'", Integer.class,
                accepted.run().runId())).isEqualTo(1);
        Grant grant = db.queryForObject("""
                select workspace_id, actor_id, reviewer_role, session_digest, authority_stamp, authority_expires_at
                  from test_run_reviewer_grants where run_id = ?
                """, (rs, ignored) -> new Grant(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3),
                rs.getString(4), rs.getString(5), rs.getTimestamp(6).toInstant()), accepted.run().runId());
        assertThat(grant).isNotNull();
        assertThat(grant.workspace()).isEqualTo(AgentService.DEMO_WORKSPACE_ID);
        assertThat(grant.actor()).isEqualTo(ACTOR);
        assertThat(grant.role()).isEqualTo("AI_SECURITY_REVIEWER");
        assertThat(grant.sessionDigest()).isEqualTo(revocations.sessionDigest(session))
                .matches("sha256:[0-9a-f]{64}")
                .doesNotContain(session.token(), session.csrfToken(), session.reviewer().sessionId());
        assertThat(grant.authorityStamp()).isEqualTo(credentials.authorityStamp(session.reviewer()))
                .doesNotContain(KEY);
        assertThat(grant.expiresAt()).isEqualTo(Instant.ofEpochSecond(session.expiresAt()));

        Seed legacy = seed(AgentService.DEMO_WORKSPACE_ID);
        UUID legacyRun = legacyRuns.register(legacy.request(), "caller-supplied-actor").runId();
        assertThat(db.queryForObject("select count(*) from test_run_reviewer_grants where run_id = ?",
                Integer.class, legacyRun)).isZero();
    }

    @Test
    void rejectsCookieCsrfKeyOnlyAndActorSpoofBeforeAnyWrite() throws Exception {
        Seed seed = seed(AgentService.DEMO_WORKSPACE_ID);
        var session = credentials.issue();
        assertRejectedWithoutWrites(seed, new MockHttpServletRequest());

        var keyOnly = new MockHttpServletRequest();
        keyOnly.addHeader("X-Contract-Reviewer-Key", KEY);
        keyOnly.addHeader("X-CSRF-Token", session.csrfToken());
        assertRejectedWithoutWrites(seed, keyOnly);

        assertRejectedWithoutWrites(seed, request(session, null, null));
        assertRejectedWithoutWrites(seed, request(session, "wrong", null));
        assertRejectedWithoutWrites(seed, request(session, session.csrfToken(), "forged-actor"));

        var tampered = request(session, session.csrfToken(), null);
        tampered.setCookies(new Cookie(ContractReviewerCredentials.COOKIE, session.token() + "x"));
        assertRejectedWithoutWrites(seed, tampered);
        var duplicate = request(session, session.csrfToken(), null);
        duplicate.setCookies(new Cookie(ContractReviewerCredentials.COOKIE, session.token()),
                new Cookie(ContractReviewerCredentials.COOKIE, session.token()));
        assertRejectedWithoutWrites(seed, duplicate);

        var expired = request(session, session.csrfToken(), null);
        expired.setCookies(new Cookie(ContractReviewerCredentials.COOKIE, expiredToken(session)));
        assertRejectedWithoutWrites(seed, expired);
    }

    @Test
    void revocationAndForeignWorkspaceRejectWithoutRunGrantOrAudit() {
        Seed seed = seed(AgentService.DEMO_WORKSPACE_ID);
        var session = credentials.issue();
        revocations.revoke(session);
        assertRejectedWithoutWrites(seed, request(session, session.csrfToken(), null));

        UUID foreignWorkspace = UUID.randomUUID();
        db.update("insert into workspaces (id, name, mode) values (?, 'Foreign reviewer grant test', 'DEMO')",
                foreignWorkspace);
        Seed foreign = seed(foreignWorkspace);
        var freshSession = credentials.issue();
        // The existing Run registration and its audit happen before this mismatch check.
        assertRejectedWithoutWrites(foreign, request(freshSession, freshSession.csrfToken(), null));
    }

    @Test
    void sqlRejectsForeignDuplicateTerminalAndGrantMutation() {
        Seed seed = seed(AgentService.DEMO_WORKSPACE_ID);
        var session = credentials.issue();
        UUID runId = admission.register(seed.request(), request(session, session.csrfToken(), null)).run().runId();
        UUID foreignWorkspace = UUID.randomUUID();
        db.update("insert into workspaces (id, name, mode) values (?, 'Foreign SQL grant test', 'DEMO')",
                foreignWorkspace);

        assertSqlState("23514", () -> insertGrant(runId, foreignWorkspace));
        assertSqlState("23505", () -> insertGrant(runId, AgentService.DEMO_WORKSPACE_ID));
        assertSqlState("55000", () -> db.update(
                "update test_run_reviewer_grants set actor_id = 'forged' where run_id = ?", runId));
        assertSqlState("55000", () -> db.update("delete from test_run_reviewer_grants where run_id = ?", runId));

        Seed old = seed(AgentService.DEMO_WORKSPACE_ID);
        UUID terminalRun = legacyRuns.register(old.request(), "legacy-actor").runId();
        UUID traceId = UUID.randomUUID();
        events.append(terminalRun, new ExecutionEventDto.AppendRequest(null, traceId,
                ExecutionEventType.RUN_STARTED, null, null, null, null, null, json.createObjectNode()),
                "legacy-actor");
        events.append(terminalRun, new ExecutionEventDto.AppendRequest(null, traceId,
                ExecutionEventType.RUN_FAILED, null, null, null, null, null, json.createObjectNode()),
                "legacy-actor");
        db.update("update test_runs set status = 'FAILED', completed_at = now() where id = ?", terminalRun);
        assertSqlState("23514", () -> insertGrant(terminalRun, AgentService.DEMO_WORKSPACE_ID));
        assertThat(db.queryForObject("select count(*) from test_run_reviewer_grants where run_id = ?",
                Integer.class, terminalRun)).isZero();
    }

    private void assertRejectedWithoutWrites(Seed seed, MockHttpServletRequest request) {
        int auditBefore = auditCount();
        assertThatThrownBy(() -> admission.register(seed.request(), request))
                .isInstanceOf(BusinessException.class)
                .satisfies(error -> assertThat(((BusinessException) error).errorCode())
                        .isEqualTo(ErrorCode.OPERATOR_AUTH_REQUIRED));
        assertThat(db.queryForObject("select count(*) from test_runs where release_id = ?", Integer.class,
                seed.releaseId())).isZero();
        assertThat(db.queryForObject("select count(*) from test_run_reviewer_grants grant_row "
                + "join test_runs run on run.id = grant_row.run_id where run.release_id = ?", Integer.class,
                seed.releaseId())).isZero();
        assertThat(auditCount()).isEqualTo(auditBefore);
    }

    private int auditCount() {
        return db.queryForObject("select count(*) from audit_records where action = 'TEST_RUN_REGISTERED'",
                Integer.class);
    }

    private void insertGrant(UUID runId, UUID workspaceId) {
        db.update("""
                insert into test_run_reviewer_grants
                    (run_id, workspace_id, actor_id, reviewer_role, session_digest,
                     authority_stamp, authority_expires_at)
                values (?, ?, 'sql-reviewer', 'AI_SECURITY_REVIEWER', ?, 'test-stamp', ?)
                """, runId, workspaceId, HASH, Timestamp.from(Instant.now().plusSeconds(600)));
    }

    private void assertSqlState(String expected, Runnable operation) {
        assertThatThrownBy(operation::run)
                .rootCause()
                .isInstanceOf(java.sql.SQLException.class)
                .extracting(error -> ((java.sql.SQLException) error).getSQLState())
                .isEqualTo(expected);
    }

    private Seed seed(UUID workspaceId) {
        UUID agentId = UUID.randomUUID();
        UUID releaseId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        String suffix = agentId.toString().substring(0, 8);
        db.update("""
                insert into agents (id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'Grant Agent', 'Grant registration test', 'ACTIVE')
                """, agentId, workspaceId, "grant-agent-" + suffix);
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
                """, suiteId, workspaceId, "grant-suite-" + suffix, HASH);
        db.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name, category, severity,
                     delivery_channel, payload_hash, preconditions_json, expected_invariant,
                     oracle_type, generation_source, expected_result_json, trial_policy_json)
                values (?, ?, 'case-1', 'NORMAL', 'NORMAL', 'NORMAL', 'LOW', 'DIRECT', ?,
                        '{}'::jsonb, 'INV-NORMAL', 'NORMAL_TASK', 'CURATED', '{}'::jsonb, '{}'::jsonb)
                """, UUID.randomUUID(), suiteId, HASH);
        db.update("update test_suites set status = 'READY' where id = ?", suiteId);
        return new Seed(releaseId, suiteId);
    }

    private MockHttpServletRequest request(ContractReviewerCredentials.Session session, String csrf, String actor) {
        var request = new MockHttpServletRequest();
        request.setCookies(new Cookie(ContractReviewerCredentials.COOKIE, session.token()));
        if (csrf != null) request.addHeader("X-CSRF-Token", csrf);
        if (actor != null) request.addHeader("X-Actor-Id", actor);
        return request;
    }

    private String expiredToken(ContractReviewerCredentials.Session session) throws Exception {
        String encoded = session.token().split("\\.")[0];
        ObjectNode payload = (ObjectNode) json.readTree(Base64.getUrlDecoder().decode(encoded));
        payload.put("expires", Instant.now().minusSeconds(1).getEpochSecond());
        String expired = Base64.getUrlEncoder().withoutPadding().encodeToString(json.writeValueAsBytes(payload));
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(
                ("FINSEC_REVIEWER_SESSION_V1:" + expired).getBytes(StandardCharsets.UTF_8)));
        return expired + "." + signature;
    }

    private record Seed(UUID releaseId, UUID suiteId) {
        TestRunPersistenceDto.RegisterRequest request() {
            return new TestRunPersistenceDto.RegisterRequest(releaseId, suiteId, null, TestRunMode.BASELINE,
                    null, null, HASH, HASH, 42L, 1);
        }
    }

    private record Grant(UUID workspace, String actor, String role, String sessionDigest,
                         String authorityStamp, Instant expiresAt) { }
}
