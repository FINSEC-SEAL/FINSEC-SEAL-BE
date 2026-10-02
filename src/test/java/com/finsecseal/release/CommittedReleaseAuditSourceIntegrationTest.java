package com.finsecseal.release;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.audit.AuditDto;
import com.finsecseal.audit.AuditService;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.platform.contract.ContractPersistenceService;
import jakarta.persistence.EntityManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.PayloadApplicationEvent;
import org.springframework.context.event.ApplicationEventMulticaster;
import org.springframework.context.event.SimpleApplicationEventMulticaster;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.util.AopTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/** Task-derived AC-PG controls; fixtures are not runtime or certification evidence. */
@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "finsec.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "finsec.scheduling.enabled=false",
        "finsec.contract-access.key=test-reviewer-key-at-least-32-bytes-long",
        "finsec.contract-access.actor=contract-integration-reviewer",
        "finsec.contract-access.workspace=0198f1e2-0000-7000-8000-000000000001"
})
class CommittedReleaseAuditSourceIntegrationTest {

    @Container @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");
    private static final String APPLIED = "RELEASE_CONTRACT_FINGERPRINT_APPLIED";
    private static final String INVALIDATED = "AGENT_RELEASE_INVALIDATED";
    private static final String REVIEWER_KEY = "test-reviewer-key-at-least-32-bytes-long";
    private static final String ACTOR_CANARY = "actor-sensitive-canary";
    private static final String MESSAGE_CANARY = "listener-message-sensitive-canary";
    private final ReviewerContext reviewer = new ReviewerContext(AgentService.DEMO_WORKSPACE_ID,
            "contract-integration-reviewer", "AI_SECURITY_REVIEWER", "synthetic-test-session", true, true, false);

    @Autowired ReleaseService releases;
    @Autowired ContractPersistenceService contracts;
    @Autowired JdbcTemplate db;
    @Autowired DataSource dataSource;
    @Autowired ObjectMapper json;
    @Autowired PlatformTransactionManager manager;
    @Autowired EntityManager entityManager;
    @Autowired @Qualifier("applicationEventMulticaster") ApplicationEventMulticaster multicaster;
    @LocalServerPort int port;
    @MockitoSpyBean AuditService audits;
    @MockitoSpyBean AgentService agents;
    @MockitoSpyBean AgentReleaseRepository repository;
    @MockitoSpyBean DecisionInvalidationWriter invalidations;
    @MockitoSpyBean FingerprintService fingerprints;

    private final Map<UUID, AuditDto.Record> receipts = new ConcurrentHashMap<>();
    private final Map<UUID, Thread> appendThreads = new ConcurrentHashMap<>();
    private final List<Observation> observations = new CopyOnWriteArrayList<>();
    private final List<Exception> observerErrors = new CopyOnWriteArrayList<>();
    private UUID watchedRelease;
    private boolean throwAfterObservation;
    private ApplicationListener<ApplicationEvent> listener;
    private ListAppender<ILoggingEvent> logCapture;
    private Logger producerLogger;

    @BeforeEach
    void observeRealReceiptsAndCommittedRows() {
        doAnswer(call -> {
            AuditDto.Record receipt = (AuditDto.Record) call.callRealMethod();
            if (List.of(APPLIED, INVALIDATED).contains(receipt.action())) {
                receipts.put(receipt.id(), receipt);
                appendThreads.put(receipt.id(), Thread.currentThread());
            }
            return receipt;
        }).when(audits).append(any(), any(), any(), any(), any(), any(), any(), any());
        listener = event -> {
            if (!(event instanceof PayloadApplicationEvent<?> payload)
                    || !(payload.getPayload() instanceof AuditDto.Record receipt)
                    || !receipt.resourceId().equals(watchedRelease)) return;
            // Assertions occur in the test, so the producer cannot swallow failed observations.
            try (Connection connection = dataSource.getConnection()) {
                AuditDto.Record persisted = persisted(connection, receipt.id());
                String state = scalar(connection, "select lifecycle_state from agent_releases where id=?", watchedRelease);
                int approved = count(connection, "select count(*) from safety_contract_versions v join safety_contracts c "
                        + "on c.id=v.contract_id where c.release_id=? and v.state='APPROVED'", watchedRelease);
                int approvedAudits = count(connection, "select count(*) from audit_records a join safety_contract_versions v "
                        + "on v.id=a.resource_id join safety_contracts c on c.id=v.contract_id "
                        + "where c.release_id=? and a.action='CONTRACT_APPROVED'", watchedRelease);
                int invalidationCount = count(connection, "select count(*) from decision_invalidations i "
                        + "join release_decisions d on d.id=i.release_decision_id where d.release_id=?", watchedRelease);
                observations.add(new Observation(receipt, persisted, state, approved, approvedAudits,
                        invalidationCount, Thread.currentThread(), connection.getAutoCommit()));
            } catch (Exception problem) {
                observerErrors.add(problem);
            }
            if (throwAfterObservation) throw new CanaryListenerException(MESSAGE_CANARY);
        };
        multicaster.addApplicationListener(listener);
        producerLogger = (Logger) LoggerFactory.getLogger(CommittedReleaseAuditPublisher.class);
        logCapture = new ListAppender<>();
        logCapture.start();
        producerLogger.addAppender(logCapture);
    }

    @AfterEach
    void removeObservers() {
        multicaster.removeApplicationListener(listener);
        producerLogger.detachAppender(logCapture);
        logCapture.stop();
    }

    @Test
    void normalApprovalWaitsForPhysicalOuterCommitAndObservesAllApprovalWrites() throws Exception {
        Candidate fixture = candidate();
        watch(fixture.release());
        Thread caller = Thread.currentThread();
        assertThat(manager).isInstanceOf(JpaTransactionManager.class);
        assertThat(((JpaTransactionManager) manager).isNestedTransactionAllowed()).isFalse();
        assertThat(multicaster).isInstanceOf(SimpleApplicationEventMulticaster.class);
        transaction().executeWithoutResult(status -> {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isTrue();
            assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isTrue();
            assertThat(db.queryForObject("show transaction_read_only", String.class)).isEqualTo("off");
            assertThat(db.queryForObject("show transaction_isolation", String.class)).isEqualTo("read committed");
            assertThat(approve(fixture).state()).isEqualTo("APPROVED");
            assertThat(observations).isEmpty();
            assertThat(receipts).hasSize(1);
        });
        Observation observed = single(APPLIED, "VERIFYING");
        assertThat(observed.thread()).isSameAs(caller);
        assertThat(observed.connectionAutoCommit()).isTrue();
        assertThat(observed.approved()).isEqualTo(1);
        assertThat(observed.approvedAudits()).isEqualTo(1);
    }

    @Test
    void terminalInvalidationCommitsLatestDecisionEvidenceAndSameDigestReceipt() throws Exception {
        UUID release = terminalRelease();
        watch(release);
        transaction().executeWithoutResult(status -> {
            assertThat(releases.invalidate(release, reason(), ACTOR_CANARY).lifecycleState().name())
                    .isEqualTo("NEEDS_REVALIDATION");
            assertThat(observations).isEmpty();
        });
        Observation observed = single(INVALIDATED, "NEEDS_REVALIDATION");
        assertThat(observed.invalidations()).isEqualTo(1);
        assertThat(observed.receipt().beforeDigest()).isEqualTo(observed.receipt().afterDigest());
        assertThat(observed.receipt().actorId()).isEqualTo(ACTOR_CANARY);
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void approvalExceptionAndRollbackOnlyRestoreOwnerAndAuditWithoutDelivery(boolean rollbackOnly) throws Exception {
        Candidate fixture = candidate();
        watch(fixture.release());
        Runnable action = () -> transaction().executeWithoutResult(status -> {
            approve(fixture);
            assertThat(observations).isEmpty();
            if (rollbackOnly) status.setRollbackOnly();
            else throw new CanaryListenerException("outer-rollback");
        });
        if (rollbackOnly) action.run();
        else assertThatThrownBy(action::run).isInstanceOf(CanaryListenerException.class);
        assertThat(contracts.find(fixture.version().id(), reviewer).state()).isEqualTo("VALIDATED");
        assertThat(state(fixture.release())).isEqualTo("REMEDIATION");
        assertThat(releaseAuditCount(fixture.release())).isZero();
        assertThat(observations).isEmpty();
        assertThat(observerErrors).isEmpty();
    }

    @Test
    void unrelatedRequiresNewAuditSurvivesOuterRollbackWithoutReleaseNotification() throws Exception {
        Candidate fixture = candidate();
        UUID unrelated = newRelease(); // Actual unrelated Release commits before the outer approval transaction.
        var survivingReceipt = new java.util.concurrent.atomic.AtomicReference<AuditDto.Record>();
        watch(fixture.release());
        transaction().executeWithoutResult(status -> {
            approve(fixture);
            survivingReceipt.set(audits.appendRequiresNew(AgentService.DEMO_WORKSPACE_ID,
                    "requires-new-test", "UNRELATED_AUDIT", "AGENT_RELEASE", unrelated,
                    null, null, json.createObjectNode()));
            status.setRollbackOnly();
        });
        AuditDto.Record receipt = survivingReceipt.get();
        assertThat(receipt).isNotNull();
        assertThat(receipt.workspaceId()).isEqualTo(AgentService.DEMO_WORKSPACE_ID);
        assertThat(receipt.resourceId()).isEqualTo(unrelated);
        assertThat(receipt.resourceType()).isEqualTo("AGENT_RELEASE");
        assertThat(receipt.action()).isEqualTo("UNRELATED_AUDIT");
        assertThat(db.queryForObject("select count(*) from audit_records where id=? and workspace_id=? "
                        + "and resource_id=? and resource_type='AGENT_RELEASE' and action='UNRELATED_AUDIT'",
                Integer.class, receipt.id(), AgentService.DEMO_WORKSPACE_ID, unrelated))
                .isEqualTo(1);
        assertThat(releaseAuditCount(fixture.release())).isZero();
        assertThat(state(fixture.release())).isEqualTo("REMEDIATION");
        assertThat(observations).isEmpty();
        assertThat(observerErrors).isEmpty();
    }

    @Test
    void deferred23514OccursOnlyAtPhysicalCommitAfterActualRegistrationAndSuccessfulFlush() throws Exception {
        Candidate fixture = candidate();
        approve(fixture); // Actual APPROVED contract and Release commit first.
        String oldHash = releases.find(fixture.release()).safetyContractHash();
        String oldFingerprint = releases.find(fixture.release()).releaseFingerprint();
        transaction().executeWithoutResult(status -> db.update(
                "update agent_releases set lifecycle_state='REMEDIATION',effective_status='REMEDIATION' where id=?",
                fixture.release())); // Separate legal fixture setup commit; no hash change.
        watch(fixture.release());
        int beforeAudits = releaseAuditCount(fixture.release());
        AtomicBoolean returnedAndFlushed = new AtomicBoolean();
        String unapprovedHash = "sha256:" + (oldHash.equals("sha256:" + "9".repeat(64)) ? "8" : "9").repeat(64);
        Throwable failure = catchThrowable(() -> transaction().executeWithoutResult(status -> {
            entityManager.clear();
            assertThat(releases.getRequired(fixture.release()).getLifecycleState().name()).isEqualTo("REMEDIATION");
            releases.applySafetyContractHash(fixture.release(), unapprovedHash, reason());
            assertThat(receipts).hasSize(1);
            assertThat(TransactionSynchronizationManager.getSynchronizations()).anyMatch(synchronization ->
                    synchronization.getClass().getEnclosingClass() == CommittedReleaseAuditPublisher.class);
            assertThat(observations).isEmpty();
            entityManager.flush(); // BEFORE guard and mutation SQL have succeeded; deferred check remains.
            returnedAndFlushed.set(true);
        }));
        assertThat(returnedAndFlushed).isTrue();
        assertThat(failure).isNotNull();
        assertThat(sqlState(failure)).isEqualTo("23514");
        assertThat(state(fixture.release())).isEqualTo("REMEDIATION");
        assertThat(releases.find(fixture.release()).safetyContractHash()).isEqualTo(oldHash);
        assertThat(releases.find(fixture.release()).releaseFingerprint()).isEqualTo(oldFingerprint);
        assertThat(releaseAuditCount(fixture.release())).isEqualTo(beforeAudits);
        assertThat(observations).isEmpty();
        assertThat(observerErrors).isEmpty();
    }

    @ParameterizedTest @ValueSource(strings = {"NO_TX", "SUPPORTS", "READ_ONLY"})
    void bothActualOwnerPathsRefuseBeforeFirstCollaboratorIo(String mode) throws Exception {
        UUID release = terminalRelease();
        watch(release);
        String before = releaseSnapshot(release);
        int beforeAudits = releaseAuditCount(release);
        ReleaseService target = AopTestUtils.getUltimateTargetObject(releases);
        for (boolean invalidate : List.of(false, true)) {
            clearInvocations(repository, agents, invalidations, fingerprints, audits);
            Runnable mutation = () -> {
                if (invalidate) target.invalidate(release, reason(), ACTOR_CANARY);
                else target.applySafetyContractHash(release, "sha256:" + "9".repeat(64), reason());
            };
            if (mode.equals("NO_TX")) {
                assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
                assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isFalse();
                assertThatThrownBy(mutation::run).isInstanceOf(IllegalStateException.class);
            } else {
                TransactionTemplate boundary = transaction();
                if (mode.equals("SUPPORTS")) boundary.setPropagationBehavior(TransactionDefinition.PROPAGATION_SUPPORTS);
                else boundary.setReadOnly(true);
                boundary.executeWithoutResult(status -> {
                    assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isTrue();
                    assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isEqualTo(!mode.equals("SUPPORTS"));
                    if (mode.equals("READ_ONLY")) {
                        assertThat(TransactionSynchronizationManager.isCurrentTransactionReadOnly()).isTrue();
                        assertThat(db.queryForObject("show transaction_read_only", String.class)).isEqualTo("on");
                    }
                    assertThatThrownBy(mutation::run).isInstanceOf(IllegalStateException.class);
                });
            }
            verifyNoInteractions(repository, agents, invalidations, fingerprints, audits);
        }
        assertThat(releaseSnapshot(release)).isEqualTo(before);
        assertThat(releaseAuditCount(release)).isEqualTo(beforeAudits);
        assertThat(db.queryForObject("select count(*) from decision_invalidations i join release_decisions d "
                + "on d.id=i.release_decision_id where d.release_id=?", Integer.class, release)).isZero();
        assertThat(observations).isEmpty();
    }

    @ParameterizedTest @ValueSource(strings = {"RECEIPT", "SNAPSHOT", "REGISTRATION"})
    void failuresAfterRealAppendRollBackOwnerDecisionAndAudit(String fault) throws Exception {
        UUID release = terminalRelease();
        watch(release);
        String before = releaseSnapshot(release);
        int beforeAudits = releaseAuditCount(release);
        AtomicBoolean appended = new AtomicBoolean();
        doAnswer(call -> {
            AuditDto.Record receipt = (AuditDto.Record) call.callRealMethod();
            if (!INVALIDATED.equals(receipt.action())) return receipt;
            appended.set(true);
            receipts.put(receipt.id(), receipt);
            if (fault.equals("RECEIPT")) return copy(receipt, null, receipt.metadata());
            if (fault.equals("SNAPSHOT")) {
                JsonNode broken = mock(JsonNode.class);
                when(broken.deepCopy()).thenThrow(new IllegalStateException("test snapshot failure"));
                return copy(receipt, receipt.id(), broken);
            }
            return receipt;
        }).when(audits).append(any(), any(), any(), any(), any(), any(), any(), any());
        assertThatThrownBy(() -> transaction().executeWithoutResult(status -> {
            if (fault.equals("REGISTRATION")) {
                try (var synchronization = mockStatic(TransactionSynchronizationManager.class, CALLS_REAL_METHODS)) {
                    synchronization.when(() -> TransactionSynchronizationManager.registerSynchronization(any()))
                            .thenAnswer(call -> {
                                if (call.getArgument(0).getClass().getEnclosingClass() == CommittedReleaseAuditPublisher.class)
                                    throw new IllegalStateException("test registration failure");
                                return call.callRealMethod();
                            });
                    releases.invalidate(release, reason(), ACTOR_CANARY);
                }
            } else releases.invalidate(release, reason(), ACTOR_CANARY);
        })).isInstanceOf(RuntimeException.class);
        assertThat(appended).isTrue();
        assertThat(releaseSnapshot(release)).isEqualTo(before);
        assertThat(releaseAuditCount(release)).isEqualTo(beforeAudits);
        assertThat(db.queryForObject("select count(*) from decision_invalidations i join release_decisions d "
                + "on d.id=i.release_decision_id where d.release_id=?", Integer.class, release)).isZero();
        assertThat(observations).isEmpty();
        assertThat(logCapture.list).isEmpty();
    }

    @Test
    void realReceiptMetadataIsDetachedBeforeOuterCommitAndEqualDigestApplyStillDelivers() throws Exception {
        Candidate fixture = candidate();
        approve(fixture);
        String hash = releases.find(fixture.release()).safetyContractHash();
        watch(fixture.release());
        transaction().executeWithoutResult(status -> {
            releases.applySafetyContractHash(fixture.release(), hash, reason());
            assertThat(receipts).hasSize(1);
            ((ObjectNode) receipts.values().iterator().next().metadata()).put("lifecycleState", "receipt-mutation-canary");
            assertThat(observations).isEmpty();
        });
        assertThat(observerErrors).isEmpty();
        assertThat(observations).hasSize(1);
        Observation observed = observations.getFirst();
        assertThat(observed.receipt().beforeDigest()).isEqualTo(observed.receipt().afterDigest());
        assertThat(observed.receipt().metadata()).isEqualTo(observed.persisted().metadata());
        assertThat(observed.receipt().metadata().path("lifecycleState").asString()).isEqualTo("VERIFYING");
        assertThat(receipts.get(observed.receipt().id()).metadata().path("lifecycleState").asString())
                .isEqualTo("receipt-mutation-canary");
        ((ObjectNode) observed.receipt().metadata()).put("lifecycleState", "event-mutation-canary");
        assertThat(receipts.get(observed.receipt().id()).metadata().path("lifecycleState").asString())
                .isEqualTo("receipt-mutation-canary");
        assertThat(audits.find("AGENT_RELEASE", fixture.release(), 100).stream()
                .filter(row -> row.id().equals(observed.receipt().id())).findFirst().orElseThrow().metadata())
                .isEqualTo(observed.persisted().metadata());
    }

    @ParameterizedTest @ValueSource(strings = {"APPROVE", "INVALIDATE"})
    void actualHttpSucceedsAfterSynchronousListenerRuntimeFailureAndLogsOnlyBoundedSafeFacts(String operation)
            throws Exception {
        UUID release;
        String path;
        String body;
        Map<String, String> headers;
        String action;
        String expectedState;
        if (operation.equals("APPROVE")) {
            Candidate fixture = candidate();
            release = fixture.release();
            path = "/api/v1/contract-versions/" + fixture.version().id() + ":approve";
            body = json.createObjectNode().put("comment", "policy-review-sensitive-canary").toString();
            headers = Map.of("If-Match", etag(fixture.version()), "X-Contract-Reviewer-Key", REVIEWER_KEY);
            action = APPLIED;
            expectedState = "VERIFYING";
        } else {
            release = terminalRelease();
            path = "/api/v1/releases/" + release + ":invalidate";
            body = json.createObjectNode().set("reason", reason()).toString();
            headers = Map.of("X-Actor-Id", ACTOR_CANARY);
            action = INVALIDATED;
            expectedState = "NEEDS_REVALIDATION";
        }
        watch(release);
        throwAfterObservation = true;
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .timeout(Duration.ofSeconds(15)).header("Content-Type", "application/json")
                .header("Idempotency-Key", UUID.randomUUID().toString());
        headers.forEach(request::header);
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                request.POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).withFailMessage(response.body()).isEqualTo(200);
        Observation observed = single(action, expectedState);
        assertThat(observed.thread()).isSameAs(appendThreads.get(observed.receipt().id()));
        assertThat(state(release)).isEqualTo(expectedState);
        if (operation.equals("APPROVE")) {
            assertThat(observed.approved()).isEqualTo(1);
            assertThat(observed.approvedAudits()).isEqualTo(1);
        } else assertThat(observed.invalidations()).isEqualTo(1);
        assertThat(logCapture.list).hasSize(1); // One publication attempt, no retry.
        ILoggingEvent warning = logCapture.list.getFirst();
        assertThat(warning.getLevel().toString()).isEqualTo("WARN");
        assertThat(warning.getMessage()).isEqualTo(
                "Committed Release audit notification failed auditId={} releaseId={} action={} causeClass={}");
        assertThat(warning.getArgumentArray()).containsExactly(observed.receipt().id(), release, action,
                CanaryListenerException.class.getName());
        assertThat(warning.getArgumentArray()[3].toString()).hasSizeLessThanOrEqualTo(128)
                .matches("[A-Za-z0-9_.$]+");
        assertThat(warning.getThrowableProxy()).isNull();
        assertThat(warning.getFormattedMessage()).doesNotContain(MESSAGE_CANARY, ACTOR_CANARY, REVIEWER_KEY,
                "policy-review-sensitive-canary", "metadata-sensitive-canary", "session-sensitive-canary",
                observed.receipt().beforeDigest(), observed.receipt().afterDigest());
    }

    private Candidate candidate() throws Exception {
        UUID release = newRelease();
        transaction().executeWithoutResult(status -> db.update(
                "update agent_releases set lifecycle_state='REMEDIATION',effective_status='REMEDIATION' where id=?", release));
        var candidate = contracts.create(release, fixture("loan-review-safety-contract.json"), reviewer);
        return new Candidate(release, contracts.validate(candidate.id(), etag(candidate), reviewer));
    }

    private ContractPersistenceService.Version approve(Candidate candidate) {
        return contracts.approve(candidate.version().id(), etag(candidate.version()), "Reviewed scope", reviewer);
    }

    private UUID newRelease() throws Exception {
        String key = "committed-audit-" + UUID.randomUUID();
        var agent = agents.create(new AgentDto.CreateRequest(key, "Committed audit test", "Document review"));
        ObjectNode manifest = (ObjectNode) fixture("valid-release-manifest-v1.1.json");
        ((ObjectNode) manifest.path("agent")).put("id", key);
        var release = releases.create(agent.id(), manifest, ACTOR_CANARY);
        releases.analyze(release.id(), ACTOR_CANARY);
        return release.id();
    }

    private UUID terminalRelease() throws Exception {
        UUID release = newRelease();
        transaction().executeWithoutResult(status -> {
            db.update("update agent_releases set lifecycle_state='PASS',effective_status='PASS' where id=?", release);
            db.update("""
                    insert into release_decisions
                        (id,release_id,decision,gate_policy_version,input_snapshot_json,input_digest,
                         proposed_at,confirmed_by,confirmed_at)
                    values (?,?,'PASS','1.0','{}'::jsonb,?,now(),'synthetic-fixture-reviewer',now())
                    """, UUID.randomUUID(), release, "sha256:" + "a".repeat(64));
        });
        return release;
    }

    private void watch(UUID release) {
        watchedRelease = release;
        receipts.clear();
        appendThreads.clear();
        observations.clear();
        observerErrors.clear();
        logCapture.list.clear();
        throwAfterObservation = false;
    }

    private Observation single(String action, String state) {
        assertThat(observerErrors).isEmpty();
        assertThat(observations).hasSize(1);
        Observation observed = observations.getFirst();
        assertThat(observed.state()).isEqualTo(state);
        assertThat(observed.receipt().action()).isEqualTo(action);
        assertThat(observed.receipt().resourceId()).isEqualTo(watchedRelease);
        AuditDto.Record original = receipts.get(observed.receipt().id());
        assertThat(original).isNotNull();
        assertThat(observed.receipt()).isEqualTo(original);
        assertThat(observed.receipt()).isNotSameAs(original);
        assertThat(observed.receipt().metadata()).isNotSameAs(original.metadata());
        AuditDto.Record persisted = observed.persisted();
        assertThat(persisted).isNotNull();
        assertThat(persisted.id()).isEqualTo(original.id());
        assertThat(persisted.workspaceId()).isEqualTo(original.workspaceId()).isEqualTo(AgentService.DEMO_WORKSPACE_ID);
        assertThat(persisted.resourceType()).isEqualTo(original.resourceType()).isEqualTo("AGENT_RELEASE");
        assertThat(persisted.resourceId()).isEqualTo(original.resourceId());
        assertThat(persisted.actorId()).isEqualTo(original.actorId());
        assertThat(persisted.action()).isEqualTo(original.action());
        assertThat(persisted.beforeDigest()).isEqualTo(original.beforeDigest());
        assertThat(persisted.afterDigest()).isEqualTo(original.afterDigest());
        assertThat(persisted.metadata()).isEqualTo(original.metadata());
        assertThat(Duration.between(original.occurredAt(), persisted.occurredAt()).abs())
                .isLessThanOrEqualTo(Duration.ofNanos(1000)); // PG timestamptz microsecond precision.
        assertThat(observed.receipt().occurredAt()).isEqualTo(original.occurredAt());
        return observed;
    }

    private AuditDto.Record persisted(Connection connection, UUID id) throws Exception {
        try (var statement = connection.prepareStatement("select * from audit_records where id=?")) {
            statement.setObject(1, id);
            try (var row = statement.executeQuery()) {
                if (!row.next()) throw new IllegalStateException("Audit not committed-visible");
                return new AuditDto.Record(row.getObject("id", UUID.class), row.getObject("workspace_id", UUID.class),
                        row.getString("actor_id"), row.getString("action"), row.getString("resource_type"),
                        row.getObject("resource_id", UUID.class), row.getString("before_digest"),
                        row.getString("after_digest"), json.readTree(row.getString("metadata_json")),
                        row.getTimestamp("occurred_at").toInstant());
            }
        }
    }

    private String scalar(Connection connection, String query, UUID id) throws SQLException {
        try (var statement = connection.prepareStatement(query)) {
            statement.setObject(1, id);
            try (var row = statement.executeQuery()) {
                if (!row.next()) throw new SQLException("Missing fixture row");
                return row.getString(1);
            }
        }
    }

    private int count(Connection connection, String query, UUID id) throws SQLException {
        return Integer.parseInt(scalar(connection, query, id));
    }

    private TransactionTemplate transaction() { return new TransactionTemplate(manager); }
    private String state(UUID release) {
        return db.queryForObject("select lifecycle_state from agent_releases where id=?", String.class, release);
    }
    private String releaseSnapshot(UUID release) {
        return db.queryForObject("select row_to_json(r)::text from agent_releases r where id=?", String.class, release);
    }
    private int releaseAuditCount(UUID release) {
        return db.queryForObject("select count(*) from audit_records where resource_id=? and action in (?,?)",
                Integer.class, release, APPLIED, INVALIDATED);
    }
    private JsonNode fixture(String name) throws Exception {
        return json.readTree(getClass().getResourceAsStream("/fixtures/" + name));
    }
    private String etag(ContractPersistenceService.Version version) { return '"' + version.resourceHash() + '"'; }
    private ObjectNode reason() {
        return json.createObjectNode().put("code", "metadata-sensitive-canary").put("session", "session-sensitive-canary");
    }
    private static AuditDto.Record copy(AuditDto.Record record, UUID id, JsonNode metadata) {
        return new AuditDto.Record(id, record.workspaceId(), record.actorId(), record.action(), record.resourceType(),
                record.resourceId(), record.beforeDigest(), record.afterDigest(), metadata, record.occurredAt());
    }
    private static String sqlState(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof SQLException sql) return sql.getSQLState();
        }
        return null;
    }

    private record Candidate(UUID release, ContractPersistenceService.Version version) {}
    private record Observation(AuditDto.Record receipt, AuditDto.Record persisted, String state, int approved,
                               int approvedAudits, int invalidations, Thread thread, boolean connectionAutoCommit) {}
    private static final class CanaryListenerException extends RuntimeException {
        CanaryListenerException(String message) { super(message); }
    }
}
