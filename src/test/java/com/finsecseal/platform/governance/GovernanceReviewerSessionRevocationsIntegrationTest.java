package com.finsecseal.platform.governance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.release.DigestService;
import jakarta.servlet.http.Cookie;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
        "finsec.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "finsec.cors.allowed-origins=http://localhost:5173",
        "finsec.scheduling.enabled=false",
        "finsec.generation.worker-enabled=false"
})
class GovernanceReviewerSessionRevocationsIntegrationTest {
    private static final String BOOTSTRAP = "synthetic-governance-bootstrap-at-least-32-bytes";
    private static final String SIGNING = "synthetic-governance-signing-at-least-32-bytes";
    private static final String ACTOR = "governance-revocation-actor-canary";
    private static final String WORKSPACE = "0198f1e2-abcd-7000-8000-000000000001";

    @Container @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired JdbcTemplate db;
    @Autowired DigestService digest;
    @Autowired PlatformTransactionManager transactions;
    private MutableClock clock;
    private GovernanceReviewerCredentials issuer;
    private GovernanceReviewerSessionRevocations revocations;
    private GovernanceReviewerCredentials.Session session;
    private GovernanceReviewerContext mutation;

    @BeforeEach void issueIsolatedSession() {
        clock = new MutableClock(Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS));
        issuer = newIssuer(clock);
        revocations = new GovernanceReviewerSessionRevocations(db, digest, issuer);
        session = issue(issuer);
        mutation = issuer.mutationContext(session, csrf(session.csrfToken()));
        assertThat(mutation).isNotNull();
        assertThat(revocations.isRevoked(session.identity())).isFalse();
    }

    @Test void migratedTableStoresOnlySeparatedDigestAndExactExpiryAndDatabaseTime() {
        Instant before = databaseTime();
        revocations.revoke(mutation);
        Instant after = databaseTime();
        String expected = governanceDigest(session.identity());
        var row = db.queryForMap("select * from reviewer_session_revocations where session_digest=?", expected);
        assertThat(row).containsOnlyKeys("session_digest", "expires_at", "revoked_at");
        assertThat(row.get("session_digest")).isEqualTo(expected);
        assertThat(expected).matches("sha256:[0-9a-f]{64}");
        assertThat(((Timestamp) row.get("expires_at")).toInstant())
                .isEqualTo(Instant.ofEpochSecond(session.identity().expiresAt()));
        assertThat(((Timestamp) row.get("revoked_at")).toInstant()).isBetween(before, after);
        String persisted = db.queryForObject("select row_to_json(r)::text from reviewer_session_revocations r where session_digest=?",
                String.class, expected);
        assertThat(persisted).doesNotContain(BOOTSTRAP, SIGNING, ACTOR, session.token(),
                session.csrfToken(), session.identity().sessionId().toString(), WORKSPACE);
    }

    @Test void committedRevocationIsVisibleToIndependentAndRestartedReaders() {
        new TransactionTemplate(transactions).executeWithoutResult(status -> revocations.revoke(mutation));
        var independent = new GovernanceReviewerSessionRevocations(independentDb(), digest, issuer);
        assertThat(independent.isRevoked(session.identity())).isTrue();
        var restartedIssuer = newIssuer(clock);
        var restartedSession = restartedIssuer.session(cookie(session.token()));
        assertThat(restartedSession).isNotNull();
        var restartedReader = new GovernanceReviewerSessionRevocations(independentDb(), new DigestService(), restartedIssuer);
        assertThat(restartedReader.isRevoked(restartedSession.identity())).isTrue();
        assertThat(restartedReader.isRevoked(issue(restartedIssuer).identity())).isFalse();
    }

    @Test void uncommittedRevocationIsHiddenThenVisibleAfterPhysicalCommit() {
        var independent = new GovernanceReviewerSessionRevocations(independentDb(), digest, issuer);
        new TransactionTemplate(transactions).executeWithoutResult(status -> {
            revocations.revoke(mutation);
            assertThat(revocations.isRevoked(session.identity())).isTrue();
            assertThat(independent.isRevoked(session.identity())).isFalse();
        });
        assertThat(independent.isRevoked(session.identity())).isTrue();
    }

    @Test void rolledBackRevocationNeverBecomesVisible() {
        var independent = new GovernanceReviewerSessionRevocations(independentDb(), digest, issuer);
        new TransactionTemplate(transactions).executeWithoutResult(status -> {
            revocations.revoke(mutation);
            assertThat(revocations.isRevoked(session.identity())).isTrue();
            assertThat(independent.isRevoked(session.identity())).isFalse();
            status.setRollbackOnly();
        });
        assertThat(revocations.isRevoked(session.identity())).isFalse();
        assertThat(independent.isRevoked(session.identity())).isFalse();
        assertThat(rowCount(session.identity())).isZero();
    }

    @Test void concurrentDuplicateRevocationCommitsOneRowWithoutReplacingFacts() throws Exception {
        var gate = new CountDownLatch(1);
        try (var pool = Executors.newFixedThreadPool(2)) {
            java.util.concurrent.Callable<Void> attempt = () -> {
                assertThat(gate.await(10, TimeUnit.SECONDS)).isTrue();
                new TransactionTemplate(transactions).executeWithoutResult(status -> revocations.revoke(mutation));
                return null;
            };
            var first = pool.submit(attempt);
            var second = pool.submit(attempt);
            gate.countDown();
            first.get(15, TimeUnit.SECONDS);
            second.get(15, TimeUnit.SECONDS);
        }
        assertThat(rowCount(session.identity())).isEqualTo(1);
        var original = db.queryForMap("select * from reviewer_session_revocations where session_digest=?",
                governanceDigest(session.identity()));
        revocations.revoke(mutation);
        assertThat(db.queryForMap("select * from reviewer_session_revocations where session_digest=?",
                governanceDigest(session.identity()))).isEqualTo(original);
        assertThat(rowCount(session.identity())).isEqualTo(1);
    }

    @Test void otherSessionAndOtherDigestDomainCannotRevokeGovernanceSession() {
        var other = issue(issuer);
        revocations.revoke(issuer.mutationContext(other, csrf(other.csrfToken())));
        String contractDomain = digest.sha256("FINSEC_REVIEWER_SESSION_ID_V1:"
                + session.identity().workspaceId() + ":" + session.identity().sessionId());
        db.update("insert into reviewer_session_revocations(session_digest,expires_at) values (?,?)",
                contractDomain, Timestamp.from(Instant.ofEpochSecond(session.identity().expiresAt())));
        assertThat(revocations.isRevoked(session.identity())).isFalse();
        assertThat(rowCount(session.identity())).isZero();
        revocations.revoke(mutation);
        assertThat(governanceDigest(session.identity())).isNotEqualTo(contractDomain);
        assertThat(revocations.isRevoked(session.identity())).isTrue();
    }

    @Test void nullReadOnlyWrongCsrfAndForeignIssuerCannotWriteRevocation() {
        assertDenied(null);
        assertDenied(session.identity());
        assertDenied(issuer.mutationContext(session, csrf("wrong-csrf-canary")));
        var foreignIssuer = newIssuer(clock);
        var foreignSession = foreignIssuer.session(cookie(session.token()));
        assertThat(foreignSession).isNotNull();
        assertDenied(foreignIssuer.mutationContext(foreignSession, csrf(foreignSession.csrfToken())));
        assertThat(rowCount(session.identity())).isZero();
    }

    @Test void exactExpiryRejectsHeldIdentityWithoutCreatingRows() {
        clock.now = Instant.ofEpochSecond(session.identity().expiresAt());
        assertDenied(mutation);
        assertThatThrownBy(() -> revocations.isRevoked(session.identity()))
                .isInstanceOf(BusinessException.class).hasMessage("Current governance reviewer authority required");
        assertThat(rowCount(session.identity())).isZero();
    }

    @Test void actualReadOnlyPostgresFailurePropagatesAndDoesNotCreateRevocation() {
        TransactionTemplate readOnly = new TransactionTemplate(transactions);
        readOnly.setReadOnly(true);
        assertThatThrownBy(() -> readOnly.executeWithoutResult(status -> {
            assertThat(db.queryForObject("show transaction_read_only", String.class)).isEqualTo("on");
            revocations.revoke(mutation);
        })).isInstanceOf(DataAccessException.class);
        assertThat(rowCount(session.identity())).isZero();
        assertThat(revocations.isRevoked(session.identity())).isFalse();
    }

    private void assertDenied(GovernanceReviewerContext identity) {
        assertThatThrownBy(() -> revocations.revoke(identity)).isInstanceOfSatisfying(BusinessException.class,
                failure -> {
                    assertThat(failure.errorCode()).isEqualTo(ErrorCode.OPERATOR_AUTH_REQUIRED);
                    assertThat(failure.getMessage()).isEqualTo("Current governance reviewer authority required")
                            .doesNotContain(BOOTSTRAP, SIGNING, ACTOR, session.token(), session.csrfToken());
                });
    }

    private GovernanceReviewerCredentials newIssuer(Clock sourceClock) {
        return new GovernanceReviewerCredentials(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, "", sourceClock);
    }

    private GovernanceReviewerCredentials.Session issue(GovernanceReviewerCredentials credentials) {
        var request = new MockHttpServletRequest("GET", GovernanceReviewerCredentials.SESSION_PATH);
        request.addHeader("Authorization", "GovernanceBootstrap " + BOOTSTRAP);
        var issued = credentials.exchange(request);
        assertThat(issued).isNotNull();
        return issued;
    }

    private MockHttpServletRequest csrf(String value) {
        var request = new MockHttpServletRequest();
        request.addHeader("X-CSRF-Token", value);
        return request;
    }

    private MockHttpServletRequest cookie(String token) {
        var request = new MockHttpServletRequest();
        request.setCookies(new Cookie(GovernanceReviewerCredentials.COOKIE, token));
        return request;
    }

    private String governanceDigest(GovernanceReviewerContext identity) {
        return digest.sha256("FINSEC_GOVERNANCE_SESSION_ID_V1:"
                + identity.workspaceId() + ":" + identity.sessionId());
    }

    private int rowCount(GovernanceReviewerContext identity) {
        return db.queryForObject("select count(*) from reviewer_session_revocations where session_digest=?",
                Integer.class, governanceDigest(identity));
    }

    private Instant databaseTime() {
        return db.queryForObject("select clock_timestamp()", Timestamp.class).toInstant();
    }

    private JdbcTemplate independentDb() {
        return new JdbcTemplate(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()));
    }

    private static final class MutableClock extends Clock {
        private volatile Instant now;
        private MutableClock(Instant now) { this.now = now; }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
