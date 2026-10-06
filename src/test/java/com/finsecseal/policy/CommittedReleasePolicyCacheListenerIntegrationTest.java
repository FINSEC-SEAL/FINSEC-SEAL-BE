package com.finsecseal.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mockingDetails;

import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.attestation.AttestationDto;
import com.finsecseal.attestation.AttestationService;
import com.finsecseal.audit.AuditDto;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.contract.SafetyContractSemanticValidator;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.evidence.TestRunProjectionService;
import com.finsecseal.platform.contract.ContractPersistenceService;
import com.finsecseal.platform.contract.ContractPersistenceService.Version;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.ReleaseService;
import jakarta.persistence.EntityManager;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.PayloadApplicationEvent;
import org.springframework.context.event.ApplicationEventMulticaster;
import org.springframework.core.Ordered;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.util.AopTestUtils;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/** Physical owner commits and existing cache algorithm; fixtures are not B runtime or D decisions. */
@Testcontainers
@SpringBootTest(properties = {
        "finsec.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "finsec.scheduling.enabled=false", "finsec.ai.enabled=false"
})
class CommittedReleasePolicyCacheListenerIntegrationTest {
    private static final String ACTOR = "c-committed-cache-integration";
    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final ReviewerContext REVIEWER = new ReviewerContext(
            AgentService.DEMO_WORKSPACE_ID, ACTOR, "AI_SECURITY_REVIEWER", "synthetic-session", true, true, false);
    @Container @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");
    @Autowired AgentService agents;
    @Autowired ReleaseService releases;
    @Autowired ContractPersistenceService contracts;
    @Autowired TestRunPersistenceService cases;
    @Autowired TestRunProjectionService runs;
    @Autowired ExecutionEventService events;
    @Autowired GatewayApprovedPolicySourceService sources;
    @Autowired AttestationService attestations;
    @Autowired CanonicalJsonService canonical;
    @Autowired DigestService digest;
    @Autowired ObjectMapper json;
    @Autowired JdbcTemplate db;
    @Autowired DataSource dataSource;
    @Autowired PlatformTransactionManager transactionManager;
    @Autowired EntityManager entityManager;
    @Autowired ApplicationEventMulticaster multicaster;
    @MockitoSpyBean SafetyContractSemanticValidator validator;
    private final Set<UUID> watched = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private final List<Observation> observations = new CopyOnWriteArrayList<>();
    private final List<Exception> observerErrors = new CopyOnWriteArrayList<>();
    private final ApplicationListener<ApplicationEvent> observer = event -> {
        if (!(event instanceof PayloadApplicationEvent<?> payload)
                || !(payload.getPayload() instanceof AuditDto.Record record)
                || !watched.contains(record.resourceId())
                || !"AGENT_RELEASE".equals(record.resourceType())
                || !("AGENT_RELEASE_INVALIDATED".equals(record.action())
                || "RELEASE_CONTRACT_FINGERPRINT_APPLIED".equals(record.action()))) return;
        // Independent physical connection; collect facts/errors, never assert inside contained callback.
        try (Connection connection = dataSource.getConnection()) {
            int rows;
            try (var statement = connection.prepareStatement(
                    "select count(*) from audit_records where id=? and workspace_id=? and resource_id=? and action=?")) {
                statement.setObject(1, record.id()); statement.setObject(2, record.workspaceId());
                statement.setObject(3, record.resourceId()); statement.setString(4, record.action());
                try (var result = statement.executeQuery()) { result.next(); rows = result.getInt(1); }
            }
            observations.add(new Observation(record.id(), record.resourceId(), record.action(),
                    rows, Thread.currentThread().getId()));
        } catch (Exception exception) { observerErrors.add(exception); }
    };

    @BeforeEach void observeRealBus() { multicaster.addApplicationListener(observer); }
    @AfterEach void removeObserver() { multicaster.removeApplicationListener(observer); }

    @Test
    void successfulOuterApprovalCommitsBeforeTargetOnlyEvictionAndKeepsOwnerChecks() throws Exception {
        Seed target = seed(); Seed other = seed();
        remediation(target);
        Version v2 = contracts.create(target.release(), policy(2), REVIEWER);
        // The rejected owner transaction is separate from the later successful measured outer transaction.
        Throwable activeRun = catchThrowable(() -> contracts.validate(v2.id(), etag(v2), REVIEWER));
        assertThat(activeRun).isInstanceOfSatisfying(BusinessException.class,
                failure -> assertThat(failure.errorCode()).isEqualTo(ErrorCode.RESOURCE_CONFLICT));
        cancel(target);
        contracts.validate(v2.id(), etag(v2), REVIEWER);
        warm(target); warm(other);
        CacheState before = cache(); assertWarm(before, target, other);
        watched.add(target.release());
        ObjectNode thirdPolicy = policy(3);
        Version v3 = transaction(false).execute(status -> {
            Version created = contracts.create(target.release(), thirdPolicy, REVIEWER);
            Version validated = contracts.validate(created.id(), etag(created), REVIEWER);
            Version approved = contracts.approve(validated.id(), etag(validated), "Current source reviewed", REVIEWER);
            assertThat(cache()).isEqualTo(before);
            assertThat(observations).isEmpty();
            return approved;
        });
        assertThat(v3).isNotNull(); assertThat(v3.state()).isEqualTo("APPROVED");
        assertThat(observations.get(0).thread()).isEqualTo(Thread.currentThread().getId());
        assertCommittedEviction(before, target, other, "RELEASE_CONTRACT_FINGERPRINT_APPLIED");
        assertThat(db.queryForObject("select count(*) from audit_records where resource_id=? and action='CONTRACT_APPROVED'",
                Integer.class, v3.id())).isEqualTo(1);
        Throwable stale = catchThrowable(() -> warm(target));
        assertThat(stale).isInstanceOfSatisfying(BusinessException.class,
                failure -> assertThat(failure.errorCode()).isEqualTo(ErrorCode.RELEASE_CHANGED));
        Registered current = register(target.release(), target.suite(), target.testCase(), v3.id());
        assertThat(sources.load(current.run(), current.caseRun(), REVIEWER)).isNotNull();
        assertThat(cache().releases()).contains(target.release(), other.release());
    }

    @Test
    void terminalSameWarmApprovedReleasePreservesActualDecisionAndAttestationAndBecomesStale() throws Exception {
        Seed target = seed(); Seed other = seed();
        cancel(target);
        UUID decision = blockedDecision(target);
        AttestationDto.View stored = attestations.findOrCreate(target.release(), ACTOR); // Committed before warming.
        assertThat(stored.stale()).isFalse();
        assertThat(stored.releaseDecisionId()).isEqualTo(decision);
        String decisionBefore = decisionRow(decision);
        String attestationBefore = attestationRow(stored.id());
        byte[] jsonBefore = attestations.export(target.release(), "json", ACTOR).content();
        byte[] htmlBefore = attestations.export(target.release(), "html", ACTOR).content();
        warm(target); warm(other);
        CacheState before = cache(); assertWarm(before, target, other);
        watched.add(target.release());
        transaction(false).executeWithoutResult(status -> {
            releases.invalidate(target.release(), reason(), ACTOR);
            assertThat(cache()).isEqualTo(before);
            assertThat(observations).isEmpty();
        });
        assertCommittedEviction(before, target, other, "AGENT_RELEASE_INVALIDATED");
        assertThat(observations.get(0).thread()).isEqualTo(Thread.currentThread().getId());
        assertThat(releases.find(target.release()).lifecycleState().name()).isEqualTo("NEEDS_REVALIDATION");
        assertThat(db.queryForObject("select count(*) from decision_invalidations where release_decision_id=?",
                Integer.class, decision)).isEqualTo(1);
        assertThat(decisionRow(decision)).isEqualTo(decisionBefore);
        assertThat(attestationRow(stored.id())).isEqualTo(attestationBefore);
        AttestationDto.View stale = attestations.findOrCreate(target.release(), ACTOR);
        assertThat(stale.stale()).isTrue(); assertThat(stale.id()).isEqualTo(stored.id());
        assertThat(stale.document()).isEqualTo(stored.document());
        assertThat(stale.documentHash()).isEqualTo(stored.documentHash());
        assertThat(stale.generatedAt()).isEqualTo(stored.generatedAt());
        assertThat(stale.invalidation()).isNotNull();
        assertThat(attestations.export(target.release(), "json", ACTOR).content()).isEqualTo(jsonBefore);
        assertThat(htmlBefore).isNotEmpty();
        assertThat(attestationRow(stored.id())).isEqualTo(attestationBefore); // Original HTML/timestamps remain immutable.
        assertThat(decisionRow(decision)).isEqualTo(decisionBefore);
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void exceptionAndRollbackOnlyNeverPublishOrEvict(boolean rollbackOnly) throws Exception {
        Seed target = seed(); Seed other = seed(); warm(target); warm(other);
        CacheState before = cache(); assertWarm(before, target, other);
        String ownerBefore = releaseRow(target.release()); int auditBefore = releaseAuditCount(target.release());
        watched.add(target.release());
        Throwable failure = catchThrowable(() -> transaction(false).executeWithoutResult(status -> {
            releases.applySafetyContractHash(target.release(), target.approved().policyHash(), reason());
            assertPublisherRegistered();
            assertThat(cache()).isEqualTo(before); assertThat(observations).isEmpty();
            if (rollbackOnly) status.setRollbackOnly(); else throw new FixtureRollback();
        }));
        if (rollbackOnly) assertThat(failure).isNull(); else assertThat(failure).isInstanceOf(FixtureRollback.class);
        assertThat(cache()).isEqualTo(before); assertThat(releaseRow(target.release())).isEqualTo(ownerBefore);
        assertThat(releaseAuditCount(target.release())).isEqualTo(auditBefore);
        assertThat(observations).isEmpty(); assertThat(observerErrors).isEmpty();
    }

    @Test
    void successfulFlushThenDeferredPhysical23514PreservesNonemptyCacheAndOwnerAudit() throws Exception {
        Seed target = seed(); Seed other = seed(); remediation(target);
        warm(target); warm(other);
        CacheState before = cache(); assertWarm(before, target, other);
        String ownerBefore = releaseRow(target.release()); int auditBefore = releaseAuditCount(target.release());
        AtomicBoolean flushed = new AtomicBoolean(); watched.add(target.release());
        String badHash = "sha256:" + "9".repeat(64);
        assertThat(badHash).isNotEqualTo(target.approved().policyHash());
        Throwable failure = catchThrowable(() -> transaction(false).executeWithoutResult(status -> {
            entityManager.clear();
            assertThat(releases.getRequired(target.release()).getLifecycleState().name()).isEqualTo("REMEDIATION");
            releases.applySafetyContractHash(target.release(), badHash, reason());
            assertPublisherRegistered();
            assertThat(cache()).isEqualTo(before); assertThat(observations).isEmpty();
            entityManager.flush(); flushed.set(true);
        }));
        assertThat(flushed).isTrue(); assertThat(failure).isNotNull(); assertThat(sqlState(failure)).isEqualTo("23514");
        assertThat(cache()).isEqualTo(before); assertThat(releaseRow(target.release())).isEqualTo(ownerBefore);
        assertThat(releaseAuditCount(target.release())).isEqualTo(auditBefore);
        assertThat(observations).isEmpty(); assertThat(observerErrors).isEmpty();
    }

    @Test
    void physicallyCommittedReaderPendingFillCannotResurrectAfterLaterActualWriterCommit() throws Exception {
        Seed target = seed(); Seed other = seed(); warm(other);
        CacheState before = cache(); assertThat(before.releases()).doesNotContain(target.release()).contains(other.release());
        assertThat(before.pending()).isZero();
        clearInvocations(validator); watched.add(target.release());
        CountDownLatch committed = new CountDownLatch(1); CountDownLatch resume = new CountDownLatch(1);
        ExecutorService workers = Executors.newFixedThreadPool(2);
        Future<?> reader = null;
        try {
            reader = workers.submit(() -> transaction(true).executeWithoutResult(status -> {
                TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                    @Override public int getOrder() { return Ordered.HIGHEST_PRECEDENCE; }
                    @Override public void afterCommit() { committed.countDown(); await(resume); }
                });
                sources.load(target.run(), target.caseRun(), REVIEWER);
            }));
            assertThat(committed.await(15, TimeUnit.SECONDS)).isTrue();
            CacheState paused = cache(); assertThat(paused.pending()).isEqualTo(before.pending() + 1);
            assertThat(paused.releases()).doesNotContain(target.release()).contains(other.release());
            // Probe fully commits/closes BEFORE starting the independent A writer and waiting for it.
            assertThat(canAcquireReleaseLock(target.release())).isTrue();
            Future<?> writer = workers.submit(() -> releases.applySafetyContractHash(
                    target.release(), target.approved().policyHash(), reason()));
            writer.get(15, TimeUnit.SECONDS);
            assertCommittedEviction(before, target, other, "RELEASE_CONTRACT_FINGERPRINT_APPLIED");
            resume.countDown(); reader.get(15, TimeUnit.SECONDS); // Join through afterCompletion before inspecting pending.
            CacheState completed = cache(); assertThat(completed.pending()).isEqualTo(before.pending());
            assertThat(completed.releases()).doesNotContain(target.release()).contains(other.release());
            assertThat(semanticCalls()).isEqualTo(1);
            warm(target); assertThat(semanticCalls()).isEqualTo(2);
            assertThat(cache().releases()).contains(target.release(), other.release());
            assertThat(observerErrors).isEmpty();
        } finally {
            resume.countDown();
            workers.shutdownNow(); assertThat(workers.awaitTermination(15, TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test
    void committedFillBeforeActualWriterIsEvictedAndNextReadRemainsCold() throws Exception {
        Seed target = seed(); Seed other = seed(); warm(other); clearInvocations(validator);
        warm(target); CacheState before = cache(); assertWarm(before, target, other);
        assertThat(before.pending()).isZero(); assertThat(semanticCalls()).isEqualTo(1);
        watched.add(target.release());
        assertThat(canAcquireReleaseLock(target.release())).isTrue();
        releases.applySafetyContractHash(target.release(), target.approved().policyHash(), reason());
        assertCommittedEviction(before, target, other, "RELEASE_CONTRACT_FINGERPRINT_APPLIED");
        warm(target); assertThat(semanticCalls()).isEqualTo(2);
        assertThat(cache().releases()).contains(target.release(), other.release());
        assertThat(cache().pending()).isZero(); assertThat(observerErrors).isEmpty();
    }

    private Seed seed() throws Exception {
        String key = "committed-cache-" + UUID.randomUUID();
        AgentDto.Response agent = agents.create(new AgentDto.CreateRequest(key, "Committed cache fixture", "Document review"));
        ObjectNode manifest;
        try (var input = getClass().getResourceAsStream("/fixtures/valid-release-manifest-v1.1.json")) {
            manifest = (ObjectNode) json.readTree(input);
        }
        ((ObjectNode) manifest.path("agent")).put("id", key);
        UUID release = releases.create(agent.id(), manifest, ACTOR).id(); releases.analyze(release, ACTOR);
        // Existing legal lifecycle-only setup seam; artifact, inputs, hashes and guards unchanged.
        db.update("update agent_releases set lifecycle_state='REMEDIATION',effective_status='REMEDIATION' where id=?", release);
        Version candidate = contracts.create(release, policy(1), REVIEWER);
        Version validated = contracts.validate(candidate.id(), etag(candidate), REVIEWER);
        Version approved = contracts.approve(validated.id(), etag(validated), "Fixture policy reviewed", REVIEWER);
        UUID suite = UUID.randomUUID(); UUID testCase = UUID.randomUUID();
        db.update("""
                insert into test_suites(id,workspace_id,suite_key,version,fixture_version,generation_config_json,suite_hash,status)
                values(?,?,?,'1.0','gateway-source-v1','{}'::jsonb,?,'BUILDING')
                """, suite, AgentService.DEMO_WORKSPACE_ID, "committed-cache-suite-" + UUID.randomUUID(), HASH);
        db.update("""
                insert into test_cases(id,suite_id,case_key,case_type,partition_name,category,severity,delivery_channel,
                    payload_hash,preconditions_json,expected_invariant,oracle_type,generation_source,expected_result_json,trial_policy_json)
                values(?,?,'normal-1','NORMAL','NORMAL','NORMAL','LOW','DIRECT',?,'{}'::jsonb,
                    'INV-NORMAL','NORMAL_TASK','CURATED','{}'::jsonb,'{}'::jsonb)
                """, testCase, suite, HASH);
        db.update("update test_suites set status='READY' where id=?", suite);
        Registered registered = register(release, suite, testCase, approved.id());
        return new Seed(release, suite, testCase, registered.run(), registered.caseRun(), approved, agent, manifest);
    }

    private Registered register(UUID release, UUID suite, UUID testCase, UUID contract) {
        UUID run = cases.register(new TestRunPersistenceDto.RegisterRequest(release, suite, contract,
                TestRunMode.SEAL_REPLAY, UUID.randomUUID(), json.createObjectNode(), HASH, HASH, 42L, 1), ACTOR).runId();
        UUID caseRun = cases.registerCase(run, new TestRunPersistenceDto.CaseRunRegisterRequest(testCase, 0, HASH), ACTOR).id();
        return new Registered(run, caseRun);
    }

    private void cancel(Seed seed) {
        UUID trace = UUID.randomUUID();
        for (ExecutionEventType type : List.of(ExecutionEventType.RUN_STARTED, ExecutionEventType.RUN_CANCEL_REQUESTED)) {
            events.append(seed.run(), new ExecutionEventDto.AppendRequest(null, trace, type, null, null, null,
                    null, type.name(), json.createObjectNode()), ACTOR);
        }
        cases.updateCaseStatus(seed.run(), seed.caseRun(), new TestRunPersistenceDto.CaseRunStatusRequest(
                TestCaseRunStatus.CANCELLED, null, null, null, null, null, null), ACTOR);
        cases.updateStatus(seed.run(), new TestRunPersistenceDto.StatusRequest(TestRunStatus.CANCELLED, 1, 0, null), ACTOR);
        assertThat(cases.findCase(seed.caseRun()).status()).isEqualTo(TestCaseRunStatus.CANCELLED);
        assertThat(runs.find(seed.run()).status()).isEqualTo(TestRunStatus.CANCELLED);
    }

    private void remediation(Seed seed) {
        transaction(false).executeWithoutResult(status -> db.update(
                "update agent_releases set lifecycle_state='REMEDIATION',effective_status='REMEDIATION' where id=?", seed.release()));
    }

    private UUID blockedDecision(Seed seed) {
        var release = releases.find(seed.release()); var fingerprints = releases.fingerprint(seed.release(), ACTOR);
        Instant confirmed = Instant.now().truncatedTo(ChronoUnit.MICROS);
        ObjectNode snapshot = json.createObjectNode().put("schemaVersion", "1.0");
        snapshot.set("agent", json.createObjectNode().put("id", seed.agent().id().toString()).put("name", seed.agent().name()));
        snapshot.set("release", json.createObjectNode().put("id", release.id().toString()).put("version", release.version())
                .put("fingerprint", release.releaseFingerprint()).put("agentArtifactFingerprint", release.agentArtifactFingerprint()));
        snapshot.set("model", json.createObjectNode().put("provider", seed.manifest().at("/model/provider").asString())
                .put("name", seed.manifest().at("/model/name").asString()).put("resolvedName", seed.manifest().at("/model/name").asString())
                .put("parametersHash", fingerprints.components().get("modelHash")));
        snapshot.put("systemPromptFingerprint", fingerprints.components().get("systemPromptHash"));
        snapshot.put("toolSetFingerprint", fingerprints.components().get("toolSetHash"));
        var tools = snapshot.putArray("toolSchemaFingerprints");
        db.query("""
                select d.tool_key,d.schema_hash,d.description_hash from release_tools r
                join tool_definitions d on d.id=r.tool_definition_id where r.release_id=? order by r.ordinal
                """, result -> {
                    while (result.next()) tools.add(json.createObjectNode().put("toolName", result.getString(1))
                            .put("schemaHash", result.getString(2)).put("descriptionHash", result.getString(3)));
                    return null;
                }, seed.release());
        snapshot.put("ragConfigurationFingerprint", fingerprints.components().get("ragConfigHash"));
        snapshot.set("safetyContract", json.createObjectNode().put("status", "APPROVED")
                .put("versionId", seed.approved().id().toString()).put("version", seed.approved().version())
                .put("hash", seed.approved().policyHash()));
        snapshot.set("testSuite", json.createObjectNode().put("id", seed.suite().toString()).put("version", "1.0").put("hash", HASH));
        snapshot.set("sandbox", json.createObjectNode().put("fixtureVersion", "gateway-source-v1").put("fixtureDigest", HASH));
        ObjectNode results = snapshot.putObject("results");
        for (String field : List.of("baseline", "sealReplay", "heldOut", "normalRegression")) {
            ObjectNode result = json.createObjectNode().put("status", "N_A").put("reason", "No conclusive trials");
            result.putArray("sourceRunIds"); results.set(field, result);
        }
        var metrics = snapshot.putArray("metrics");
        for (String name : List.of("BaselineASR", "SealReplayASR", "HeldOutASR", "NormalRegression")) {
            ObjectNode metric = json.createObjectNode().put("metric", name).put("status", "N_A")
                    .put("reason", "No conclusive trials").put("calculatorVersion", "1.0");
            metric.putArray("sourceTestRunIds"); metrics.add(metric);
        }
        snapshot.putArray("remainingFindings"); snapshot.putNull("approvedPatch");
        ObjectNode decision = snapshot.putObject("decision").put("value", "BLOCKED").put("gatePolicyVersion", "mvp-gate/1");
        decision.putArray("ruleTrace").add(json.createObjectNode().put("ruleId", "INTEGRITY_BLOCK"));
        snapshot.put("testedAt", confirmed.toString());
        UUID id = UUID.randomUUID(); String inputDigest = digest.sha256(canonical.canonicalize(snapshot));
        transaction(false).executeWithoutResult(status -> {
            db.update("update agent_releases set lifecycle_state='BLOCKED',effective_status='BLOCKED' where id=?", seed.release());
            db.update("""
                    insert into release_decisions(id,release_id,decision,gate_policy_version,input_snapshot_json,input_digest,
                        proposed_at,confirmed_by,confirmed_at)
                    values(?,?,'BLOCKED','mvp-gate/1',?::jsonb,?,?,?,?)
                    """, id, seed.release(), snapshot.toString(), inputDigest, Timestamp.from(confirmed.minusSeconds(1)),
                    ACTOR, Timestamp.from(confirmed));
        });
        return id;
    }

    private TransactionTemplate transaction(boolean reader) {
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);
        if (reader) transaction.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        return transaction;
    }
    private void warm(Seed seed) { assertThat(sources.load(seed.run(), seed.caseRun(), REVIEWER)).isNotNull(); }
    private ObjectNode policy(int version) throws Exception {
        try (var input = getClass().getResourceAsStream("/fixtures/loan-review-safety-contract.json")) {
            return ((ObjectNode) json.readTree(input)).put("contractId", "gateway-source-policy").put("version", version);
        }
    }
    private String etag(Version version) { return '"' + version.resourceHash() + '"'; }
    private ObjectNode reason() { return json.createObjectNode().put("kind", "C_COMMITTED_CACHE_FIXTURE"); }
    private long semanticCalls() {
        return mockingDetails(validator).getInvocations().stream().filter(call -> call.getMethod().getName().equals("validate")).count();
    }
    private CacheState cache() {
        Object target = AopTestUtils.getUltimateTargetObject(sources);
        Object lock = ReflectionTestUtils.getField(target, "cacheLock");
        synchronized (lock) {
            Map<?, ?> map = (Map<?, ?>) ReflectionTestUtils.getField(target, "validationCache");
            Set<Object> keys = new HashSet<>(map.keySet()); Set<UUID> releaseIds = new HashSet<>();
            for (Object key : keys) releaseIds.add((UUID) ReflectionTestUtils.getField(key, "releaseId"));
            return new CacheState(Set.copyOf(keys), Set.copyOf(releaseIds),
                    ((Number) ReflectionTestUtils.getField(target, "invalidationEpoch")).longValue(),
                    ((Number) ReflectionTestUtils.getField(target, "pendingFills")).intValue());
        }
    }
    private void assertWarm(CacheState state, Seed target, Seed other) {
        assertThat(state.keys()).isNotEmpty(); assertThat(state.releases()).contains(target.release(), other.release());
        assertThat(state.pending()).isZero();
    }
    private void assertCommittedEviction(CacheState before, Seed target, Seed other, String action) {
        CacheState after = cache(); assertThat(after.epoch()).isEqualTo(before.epoch() + 1);
        assertThat(after.releases()).doesNotContain(target.release()).contains(other.release());
        assertThat(observerErrors).isEmpty(); assertThat(observations).hasSize(1);
        Observation observation = observations.get(0);
        assertThat(observation.release()).isEqualTo(target.release()); assertThat(observation.action()).isEqualTo(action);
        assertThat(observation.persistedRows()).isEqualTo(1);
        assertThat(db.queryForObject("select count(*) from audit_records where id=?", Integer.class, observation.audit())).isEqualTo(1);
    }
    private void assertPublisherRegistered() {
        assertThat(TransactionSynchronizationManager.getSynchronizations()).anyMatch(sync ->
                sync.getClass().getEnclosingClass() != null && sync.getClass().getEnclosingClass().getName()
                        .equals("com.finsecseal.release.CommittedReleaseAuditPublisher"));
    }
    private boolean canAcquireReleaseLock(UUID release) throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try (var statement = connection.prepareStatement("select id from agent_releases where id=? for update nowait")) {
                statement.setObject(1, release);
                try (var result = statement.executeQuery()) {
                    boolean found = result.next() && release.equals(result.getObject(1, UUID.class));
                    connection.commit(); return found;
                }
            } catch (SQLException failure) {
                connection.rollback(); if ("55P03".equals(failure.getSQLState())) return false; throw failure;
            }
        }
    }
    private static void await(CountDownLatch latch) {
        try { if (!latch.await(15, TimeUnit.SECONDS)) throw new IllegalStateException("Bounded afterCommit pause timed out"); }
        catch (InterruptedException exception) { Thread.currentThread().interrupt(); throw new IllegalStateException(exception); }
    }
    private static String sqlState(Throwable failure) {
        for (Throwable current = failure; current != null; current = current.getCause())
            if (current instanceof SQLException sql && sql.getSQLState() != null) return sql.getSQLState();
        return null;
    }
    private String releaseRow(UUID release) {
        return db.queryForObject("select to_jsonb(r)::text from agent_releases r where id=?", String.class, release);
    }
    private String decisionRow(UUID id) {
        return db.queryForObject("select to_jsonb(d)::text from release_decisions d where id=?", String.class, id);
    }
    private String attestationRow(UUID id) {
        return db.queryForObject("select to_jsonb(a)::text from release_attestations a where id=?", String.class, id);
    }
    private int releaseAuditCount(UUID release) {
        return db.queryForObject("select count(*) from audit_records where resource_type='AGENT_RELEASE' and resource_id=?",
                Integer.class, release);
    }
    private record Seed(UUID release, UUID suite, UUID testCase, UUID run, UUID caseRun,
                        Version approved, AgentDto.Response agent, ObjectNode manifest) { }
    private record Registered(UUID run, UUID caseRun) { }
    private record CacheState(Set<Object> keys, Set<UUID> releases, long epoch, int pending) { }
    private record Observation(UUID audit, UUID release, String action, int persistedRows, long thread) { }
    private static final class FixtureRollback extends RuntimeException { }
}
