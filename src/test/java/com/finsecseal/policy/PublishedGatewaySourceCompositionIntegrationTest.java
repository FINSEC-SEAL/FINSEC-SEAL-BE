package com.finsecseal.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.verifyNoInteractions;

import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.audit.AuditDto;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.ReleaseLifecycleState;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.contract.LoanReviewFinancialTemplate;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionIdentity;
import com.finsecseal.contract.SafetyContractSemanticValidator;
import com.finsecseal.evidence.AuthenticatedTestRunRegistrationService;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.evidence.RedactionService;
import com.finsecseal.evidence.StoredRunReviewerAuthoritySource;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.evidence.TestRunProjectionService;
import com.finsecseal.platform.contract.ContractPersistenceService;
import com.finsecseal.platform.contract.ContractPersistenceService.Version;
import com.finsecseal.platform.contract.ContractReviewerCredentials;
import com.finsecseal.platform.contract.ContractReviewerSessionRevocations;
import com.finsecseal.policy.GatewayApprovedPolicySourceService.ApprovedPolicySource;
import com.finsecseal.policy.GatewayReviewerContextSource.Resolution;
import com.finsecseal.policy.GatewayRuntimeObservations.InvocationKey;
import com.finsecseal.policy.LoanReviewPolicyGateway.FailureCode;
import com.finsecseal.policy.LoanReviewPolicyGateway.GatewayException;
import com.finsecseal.release.ReleaseService;
import com.finsecseal.runtime.ToolInvocation;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.sandbox.SandboxExecutionContext;
import com.finsecseal.sandbox.SandboxFixtureService;
import com.finsecseal.sandbox.tool.StateChangingToolExecutionService;
import com.finsecseal.sandbox.tool.StoredGatewayPreCallScopeSource;
import com.finsecseal.sandbox.tool.ToolAdapter;
import com.zaxxer.hikari.HikariDataSource;
import jakarta.servlet.http.Cookie;
import java.sql.Connection;
import java.time.Duration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.PayloadApplicationEvent;
import org.springframework.context.event.ApplicationEventMulticaster;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.util.AopTestUtils;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/** Real owner admission/source/cache composition; no positive B runtime or ENFORCE claim. */
@Testcontainers
@SpringBootTest(properties = {
        "finsec.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "finsec.scheduling.enabled=false",
        "finsec.ai.enabled=false",
        "finsec.contract-access.key=test-reviewer-key-at-least-32-bytes-long",
        "finsec.contract-access.actor=published-gateway-composition",
        "finsec.contract-access.workspace=0198f1e2-0000-7000-8000-000000000001",
        "spring.datasource.hikari.connection-timeout=2000"
})
class PublishedGatewaySourceCompositionIntegrationTest {
    private static final String ACTOR = "published-gateway-composition";
    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final String COMMITTED_ACTION = "RELEASE_CONTRACT_FINGERPRINT_APPLIED";
    private static final Duration REVIEWER_BUDGET = Duration.ofSeconds(5);

    @Container @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired HikariDataSource dataSource;
    @Autowired AgentService agents;
    @Autowired ReleaseService releases;
    @Autowired ContractPersistenceService contracts;
    @Autowired PlatformTransactionManager ownerTransactions;
    @Autowired JdbcTemplate db;
    @Autowired ObjectMapper json;
    @Autowired ContractReviewerCredentials credentials;
    @Autowired ContractReviewerSessionRevocations revocations;
    @Autowired AuthenticatedTestRunRegistrationService admission;
    @Autowired TestRunPersistenceService runs;
    @Autowired ExecutionEventService events;
    @Autowired SandboxFixtureService fixtures;
    @Autowired StoredRunReviewerAuthoritySource authorities;
    @Autowired StoredGatewayPreCallScopeSource scopes;
    @Autowired ApplicationEventMulticaster multicaster;
    @Autowired @MockitoSpyBean GatewayApprovedPolicySourceService sources;
    @MockitoSpyBean SafetyContractSemanticValidator validator;

    private final Set<UUID> watched = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private final List<Observation> observations = new CopyOnWriteArrayList<>();
    private final List<Exception> observerErrors = new CopyOnWriteArrayList<>();
    private final ApplicationListener<ApplicationEvent> observer = event -> {
        if (!(event instanceof PayloadApplicationEvent<?> payload)
                || !(payload.getPayload() instanceof AuditDto.Record record)
                || !watched.contains(record.resourceId())
                || !"AGENT_RELEASE".equals(record.resourceType())
                || !COMMITTED_ACTION.equals(record.action())) return;
        // The owner's callback contains listener errors, so collect facts and assert after outer exit.
        try (Connection connection = dataSource.getConnection();
                var statement = connection.prepareStatement(
                        "select count(*) from audit_records where id=? and workspace_id=? and resource_id=? and action=?")) {
            statement.setObject(1, record.id());
            statement.setObject(2, record.workspaceId());
            statement.setObject(3, record.resourceId());
            statement.setString(4, record.action());
            try (var result = statement.executeQuery()) {
                result.next();
                observations.add(new Observation(record.id(), record.resourceId(), record.action(), result.getInt(1)));
            }
        } catch (Exception failure) {
            observerErrors.add(failure);
        }
    };

    @BeforeEach
    void observeOwnerBus() {
        multicaster.addApplicationListener(observer);
    }

    @AfterEach
    void removeObserver() {
        multicaster.removeApplicationListener(observer);
    }

    @Test
    void storedAuthorityAndRealProxyRevalidateOnlyTargetAfterPhysicalOwnerCommit() throws Exception {
        Pair pair = warmPair();
        CacheState before = cache();
        assertWarm(before, pair);
        String ownerBefore = releaseRow(pair.target());
        int auditsBefore = releaseAuditCount(pair.target());
        watched.add(pair.target().release());

        ownerTransaction().executeWithoutResult(status -> {
            releases.applySafetyContractHash(pair.target().release(), pair.target().approved().policyHash(), reason());
            assertThat(cache()).isEqualTo(before);
            assertThat(observations).isEmpty();
            assertThat(observerErrors).isEmpty();
        });

        CacheState committed = cache();
        assertThat(committed.epoch()).isEqualTo(before.epoch() + 1);
        assertThat(committed.pending()).isZero();
        assertThat(committed.releases()).doesNotContain(pair.target().release()).contains(pair.other().release());
        Set<Object> retained = new HashSet<>(before.keys());
        retained.removeIf(key -> pair.target().release().equals(ReflectionTestUtils.getField(key, "releaseId")));
        assertThat(committed.keys()).isEqualTo(retained);
        assertThat(releaseRow(pair.target())).isEqualTo(ownerBefore);
        assertThat(releaseAuditCount(pair.target())).isEqualTo(auditsBefore + 1);
        assertThat(observerErrors).isEmpty();
        assertThat(observations).hasSize(1);
        Observation observed = observations.get(0);
        assertThat(observed.release()).isEqualTo(pair.target().release());
        assertThat(observed.action()).isEqualTo(COMMITTED_ACTION);
        assertThat(observed.persistedRows()).isEqualTo(1);
        assertThat(db.queryForObject("select count(*) from audit_records where id=?", Integer.class, observed.audit()))
                .isEqualTo(1);

        long callsBefore = semanticCalls();
        assertSource(load(pair.target()), pair.target());
        assertThat(semanticCalls()).isEqualTo(callsBefore + 1);
        assertWarm(cache(), pair);
        assertSource(load(pair.other()), pair.other());
        assertThat(semanticCalls()).isEqualTo(callsBefore + 1);
        awaitDeadlineLeases();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void actualExceptionAndRollbackOnlyPreserveOwnerAndCacheAfterPhysicalExit(boolean rollbackOnly) throws Exception {
        Pair pair = warmPair();
        CacheState before = cache();
        String ownerBefore = releaseRow(pair.target());
        int auditsBefore = releaseAuditCount(pair.target());
        Map<String, String> storedBefore = scopedDigest(pair);
        watched.add(pair.target().release());

        Runnable write = () -> ownerTransaction().executeWithoutResult(status -> {
            releases.applySafetyContractHash(pair.target().release(), pair.target().approved().policyHash(), reason());
            assertThat(cache()).isEqualTo(before);
            assertThat(observations).isEmpty();
            if (rollbackOnly) status.setRollbackOnly();
            else throw new FixtureRollback();
        });
        if (rollbackOnly) write.run();
        else assertThrows(FixtureRollback.class, write::run);

        assertNoAmbientTransaction();
        awaitDeadlineLeases();
        assertThat(releaseRow(pair.target())).isEqualTo(ownerBefore);
        assertThat(releaseAuditCount(pair.target())).isEqualTo(auditsBefore);
        assertThat(cache()).isEqualTo(before);
        assertWarm(cache(), pair);
        assertThat(observations).isEmpty();
        assertThat(observerErrors).isEmpty();
        assertThat(scopedDigest(pair)).isEqualTo(storedBefore);
    }

    @Test
    @Timeout(value = 25, unit = TimeUnit.SECONDS)
    void revokedIssuedAuthorityCannotUseWarmMetadataOrCallAnyDownstream() throws Exception {
        Pair pair = warmPair();
        CacheState warm = cache();
        revocations.revoke(pair.target().session());
        awaitDeadlineLeases();
        Map<String, String> afterRevocation = scopedDigest(pair);
        clearInvocations(sources, validator);
        GatewayProbe probe = gatewayProbe(source());

        GatewayException failure = assertThrows(GatewayException.class,
                () -> probe.gateway().invoke(pair.target().context(), pair.target().invocation(), ACTOR));

        assertThat(failure.code()).isEqualTo(FailureCode.AUTHENTICATION_REQUIRED);
        assertThat(failure.getMessage()).isEqualTo(FailureCode.AUTHENTICATION_REQUIRED.name());
        assertThat(failure.getCause()).isNull();
        assertThat(failure.successfulSecurityBlock()).isFalse();
        assertThat(probe.reviewerCalls()).hasValue(1);
        assertThat(probe.requestedKey().get()).isEqualTo(pair.target().key());
        assertThat(probe.remaining().get()).isNotNull();
        assertThat(probe.remaining().get().toNanos()).isBetween(1L, REVIEWER_BUDGET.toNanos());
        assertThat(probe.adapterCalls()).hasValue(0);
        verifyNoInteractions(sources, validator);
        verifyNoInteractions(probe.downstream());
        awaitDeadlineLeases();
        assertNoAmbientTransaction();
        assertThat(cache()).isEqualTo(warm);
        assertThat(scopedDigest(pair)).isEqualTo(afterRevocation);
        assertThat(db.queryForList("select event_type from execution_events where run_id=? order by sequence",
                String.class, pair.target().key().runId())).containsExactly("RUN_STARTED", "TOOL_PROPOSED");
        assertThat(db.queryForObject("select last_sequence from run_event_counters where run_id=?",
                Long.class, pair.target().key().runId())).isEqualTo(2L);
    }

    private Pair warmPair() throws Exception {
        // Both legal approvals finish before semantic validation invocation history is measured.
        Pair pair = new Pair(fixture(), fixture());
        assertNoAmbientTransaction();
        assertThat(AopUtils.isAopProxy(sources)).isTrue();
        assertThat(dataSource.getConnectionTimeout()).isEqualTo(2000L);
        clearInvocations(validator, sources);
        Map<String, String> beforeResolution = scopedDigest(pair);
        Resolution targetReviewer = resolve(pair.target());
        Resolution otherReviewer = resolve(pair.other());
        awaitDeadlineLeases();
        assertThat(scopedDigest(pair)).isEqualTo(beforeResolution);
        assertThat(semanticCalls()).isZero();
        CacheState cold = cache();
        assertThat(cold.releases()).doesNotContain(pair.target().release(), pair.other().release());
        assertThat(cold.pending()).isZero();

        assertSource(sources.load(pair.target().key().runId(), pair.target().key().caseRunId(),
                targetReviewer.reviewer()), pair.target());
        assertThat(semanticCalls()).isEqualTo(1);
        assertSource(sources.load(pair.other().key().runId(), pair.other().key().caseRunId(),
                otherReviewer.reviewer()), pair.other());
        assertThat(semanticCalls()).isEqualTo(2);
        assertWarm(cache(), pair);
        assertSource(load(pair.target()), pair.target());
        assertSource(load(pair.other()), pair.other());
        assertThat(semanticCalls()).isEqualTo(2);
        assertWarm(cache(), pair);
        awaitDeadlineLeases();
        return pair;
    }

    private StoredGatewayReviewerContextSource source() {
        return new StoredGatewayReviewerContextSource(dataSource, authorities, scopes);
    }

    private Resolution resolve(Fixture fixture) {
        assertNoAmbientTransaction();
        Resolution resolution = source().resolve(fixture.key(), REVIEWER_BUDGET);
        assertThat(resolution).isNotNull();
        assertThat(resolution.key()).isEqualTo(fixture.key());
        assertThat(resolution.reviewer().workspaceId()).isEqualTo(AgentService.DEMO_WORKSPACE_ID);
        assertThat(resolution.reviewer().actorId()).isEqualTo(ACTOR);
        assertThat(resolution.reviewer().role()).isEqualTo("AI_SECURITY_REVIEWER");
        assertThat(resolution.reviewer().sessionId())
                .isEqualTo(revocations.sessionDigest(fixture.session())).matches("sha256:[0-9a-f]{64}");
        assertThat(resolution.reviewer().authenticated()).isTrue();
        assertThat(resolution.reviewer().csrfVerified()).isTrue();
        assertThat(resolution.reviewer().demoMode()).isFalse();
        assertNoAmbientTransaction();
        return resolution;
    }

    private ApprovedPolicySource load(Fixture fixture) {
        Resolution reviewer = resolve(fixture);
        assertNoAmbientTransaction();
        ApprovedPolicySource result = sources.load(fixture.key().runId(), fixture.key().caseRunId(), reviewer.reviewer());
        assertNoAmbientTransaction();
        return result;
    }

    private void assertSource(ApprovedPolicySource actual, Fixture fixture) {
        assertThat(actual).isNotNull();
        assertThat(actual.runId()).isEqualTo(fixture.key().runId());
        assertThat(actual.testCaseRunId()).isEqualTo(fixture.key().caseRunId());
        assertThat(actual.testCaseId()).isEqualTo(fixture.testCase());
        assertThat(actual.runMode()).isEqualTo(TestRunMode.SEAL_REPLAY);
        assertThat(actual.runStatus()).isEqualTo(TestRunStatus.RUNNING);
        assertThat(actual.caseStatus()).isEqualTo(TestCaseRunStatus.EXECUTING);
        assertThat(actual.trialIndex()).isZero();
        assertThat(actual.variantHash()).isEqualTo(HASH);
        assertThat(actual.identity()).isEqualTo(new VersionIdentity(fixture.approved().id(),
                AgentService.DEMO_WORKSPACE_ID, fixture.release(), fixture.approved().contractKey(),
                fixture.approved().version()));
        assertThat(actual.resourceHash()).isEqualTo(fixture.approved().resourceHash());
        assertThat(actual.policyHash()).isEqualTo(fixture.approved().policyHash());
        assertThat(actual.policy()).isEqualTo(fixture.approved().policy());
        assertThat(actual.catalog().releaseId()).isEqualTo(fixture.release());
    }

    private TransactionTemplate ownerTransaction() {
        assertNoAmbientTransaction();
        return new TransactionTemplate(ownerTransactions);
    }

    private void assertNoAmbientTransaction() {
        assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
        assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isFalse();
        assertThat(TransactionSynchronizationManager.getResourceMap()).isEmpty();
    }

    private long semanticCalls() {
        return mockingDetails(validator).getInvocations().stream()
                .filter(call -> call.getMethod().getName().equals("validate")).count();
    }

    private CacheState cache() {
        Object target = AopTestUtils.getUltimateTargetObject(sources);
        Object lock = ReflectionTestUtils.getField(target, "cacheLock");
        synchronized (lock) {
            Map<?, ?> map = (Map<?, ?>) ReflectionTestUtils.getField(target, "validationCache");
            Set<Object> keys = new HashSet<>(map.keySet());
            Set<UUID> releaseIds = new HashSet<>();
            for (Object key : keys) releaseIds.add((UUID) ReflectionTestUtils.getField(key, "releaseId"));
            return new CacheState(Set.copyOf(keys), Set.copyOf(releaseIds),
                    ((Number) ReflectionTestUtils.getField(target, "invalidationEpoch")).longValue(),
                    ((Number) ReflectionTestUtils.getField(target, "pendingFills")).intValue());
        }
    }

    private void assertWarm(CacheState state, Pair pair) {
        assertThat(state.keys()).isNotEmpty();
        assertThat(state.releases()).contains(pair.target().release(), pair.other().release());
        assertThat(state.pending()).isZero();
    }

    private String releaseRow(Fixture fixture) {
        return db.queryForObject("select to_jsonb(t)::text from agent_releases t where id=?",
                String.class, fixture.release());
    }

    private int releaseAuditCount(Fixture fixture) {
        return db.queryForObject("select count(*) from audit_records where resource_type='AGENT_RELEASE' and resource_id=?",
                Integer.class, fixture.release());
    }

    private ObjectNode reason() {
        return json.createObjectNode().put("kind", "C_PUBLISHED_GATEWAY_COMPOSITION_FIXTURE");
    }

    private void awaitDeadlineLeases() throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(8).toNanos();
        var field = StoredGatewayReviewerContextSource.class.getDeclaredField("DEADLINE_SLOTS");
        field.setAccessible(true);
        Semaphore slots = (Semaphore) field.get(null);
        while ((slots.availablePermits() != 2 || dataSource.getHikariPoolMXBean().getActiveConnections() != 0)
                && System.nanoTime() < deadline) {
            Thread.sleep(20);
        }
        assertThat(slots.availablePermits()).as("worker and watchdog leases settled").isEqualTo(2);
        assertThat(dataSource.getHikariPoolMXBean().getActiveConnections()).isZero();
    }

    private GatewayProbe gatewayProbe(GatewayReviewerContextSource stored) {
        AtomicReference<InvocationKey> requestedKey = new AtomicReference<>();
        AtomicReference<Duration> remaining = new AtomicReference<>();
        AtomicInteger reviewerCalls = new AtomicInteger();
        AtomicInteger adapterCalls = new AtomicInteger();
        GatewayReviewerContextSource recording = (key, budget) -> {
            requestedKey.set(key);
            remaining.set(budget);
            reviewerCalls.incrementAndGet();
            return stored.resolve(key, budget);
        };
        PlatformTransactionManager transactions = mock(PlatformTransactionManager.class);
        GatewayRuntimeObservations runtimeObservations = mock(GatewayRuntimeObservations.class);
        GatewayBaselinePolicySourceService baseline = mock(GatewayBaselinePolicySourceService.class);
        TestRunProjectionService projections = mock(TestRunProjectionService.class);
        ReleaseService ownerReader = mock(ReleaseService.class);
        GatewayPolicyFactsAssembler facts = mock(GatewayPolicyFactsAssembler.class);
        ExecutionEventService gatewayEvents = mock(ExecutionEventService.class);
        StateChangingToolExecutionService mutations = mock(StateChangingToolExecutionService.class);
        RedactionService redaction = mock(RedactionService.class);
        ToolAdapter adapter = new ToolAdapter() {
            @Override public String toolName() { return "CUSTOMER_DATA_READ"; }
            @Override public ToolExecutionResult execute(SandboxExecutionContext context,
                    tools.jackson.databind.JsonNode arguments) {
                adapterCalls.incrementAndGet();
                return new ToolExecutionResult(json.createObjectNode(), false);
            }
        };
        var gateway = new LoanReviewPolicyGateway(transactions, recording, runtimeObservations, sources,
                baseline, projections, ownerReader, facts, gatewayEvents, mutations, redaction,
                json, new LoanReviewFinancialTemplate(json), List.of(adapter));
        return new GatewayProbe(gateway, requestedKey, remaining, reviewerCalls, adapterCalls,
                new Object[] {transactions, runtimeObservations, baseline, projections,
                        ownerReader, facts, gatewayEvents, mutations, redaction});
    }

    private Fixture fixture() {
        // Minimal lawful published provider fixture: SEAL_REPLAY, legal Release, no synthetic grant.
        UUID workspace = AgentService.DEMO_WORKSPACE_ID;
        UUID suite = UUID.randomUUID(), testCase = UUID.randomUUID(), trace = UUID.randomUUID();
        var session = credentials.issue();
        String key = "c-published-composition-" + UUID.randomUUID();
        UUID agent = agents.create(new AgentDto.CreateRequest(key, "Published composition",
                "Gateway source composition test"), ACTOR).id();
        ObjectNode manifest = resource("/fixtures/valid-release-manifest-v1.1.json");
        ((ObjectNode) manifest.path("agent")).put("id", key);
        UUID release = releases.create(agent, manifest, ACTOR).id();
        releases.analyze(release, ACTOR);
        ownerTransaction().executeWithoutResult(status -> releases.getRequired(release)
                .transitionTo(ReleaseLifecycleState.TESTING));
        ownerTransaction().executeWithoutResult(status -> releases.getRequired(release)
                .transitionTo(ReleaseLifecycleState.REMEDIATION));
        Version candidate = contracts.create(release, resource("/fixtures/loan-review-safety-contract.json"),
                session.reviewer());
        Version validated = contracts.validate(candidate.id(), etag(candidate), session.reviewer());
        Version approved = contracts.approve(validated.id(), etag(validated),
                "Reviewed published composition fixture", session.reviewer());

        db.update("""
                insert into test_suites(id,workspace_id,suite_key,version,fixture_version,
                    generation_config_json,suite_hash,status)
                values (?,?,?,'1.0','golden-v1','{}'::jsonb,?,'BUILDING')
                """, suite, workspace, "c-published-composition-suite-" + suite, HASH);
        db.update("""
                insert into test_cases(id,suite_id,case_key,case_type,partition_name,category,
                    severity,delivery_channel,target_tool,payload_hash,preconditions_json,
                    expected_invariant,oracle_type,generation_source,expected_result_json,trial_policy_json)
                values (?,?,'NORMAL-1','NORMAL','NORMAL','NORMAL','LOW','DIRECT',
                    'CUSTOMER_DATA_READ',?,'{"caseId":"CASE-1001","currentApplicantId":"CUST-1001"}'::jsonb,
                    'INV-NORMAL','NORMAL_TASK','CURATED','{}'::jsonb,'{}'::jsonb)
                """, testCase, suite, HASH);
        db.update("update test_suites set status='READY' where id=?", suite);
        var request = new MockHttpServletRequest();
        request.setCookies(new Cookie(ContractReviewerCredentials.COOKIE, session.token()));
        request.addHeader("X-CSRF-Token", session.csrfToken());
        var registration = new TestRunPersistenceDto.RegisterRequest(
                release, suite, approved.id(), TestRunMode.SEAL_REPLAY, UUID.randomUUID(),
                json.createObjectNode(), fixtures.fixtureDigest(), HASH, 42L, 1);
        UUID run = admission.register(registration, request).run().runId();
        events.append(run, new ExecutionEventDto.AppendRequest(null, trace, ExecutionEventType.RUN_STARTED,
                null, null, null, null, "PUBLISHED_COMPOSITION_TEST", json.createObjectNode()), ACTOR);
        runs.updateStatus(run, new TestRunPersistenceDto.StatusRequest(TestRunStatus.PREPARING, 0, 0, null), ACTOR);
        fixtures.createOrReset(run);
        runs.updateStatus(run, new TestRunPersistenceDto.StatusRequest(TestRunStatus.RUNNING, 0, 0, null), ACTOR);
        UUID caseRun = runs.registerCase(run,
                new TestRunPersistenceDto.CaseRunRegisterRequest(testCase, 0, HASH), ACTOR).id();
        runs.updateCaseStatus(run, caseRun, new TestRunPersistenceDto.CaseRunStatusRequest(
                TestCaseRunStatus.EXECUTING, null, null, null, null, null, null), ACTOR);
        db.update("""
                update sandbox_loan_cases
                   set status='DOCUMENT_REVIEW', allowed_document_ids_json='["DOC-1001","DOC-1002"]'::jsonb
                 where namespace_id=? and case_key='CASE-1001'
                """, run);
        ObjectNode arguments = json.createObjectNode();
        arguments.putArray("customerIds").add("CUST-1001");
        arguments.putArray("fields").add("incomeBand");
        var proposal = events.append(run, new ExecutionEventDto.AppendRequest(caseRun, trace,
                ExecutionEventType.TOOL_PROPOSED, "CUSTOMER_DATA_READ", arguments, null, null,
                "STRUCTURED_TOOL_PROPOSAL", json.createObjectNode()), ACTOR);
        InvocationKey invocationKey = new InvocationKey(run, caseRun, trace,
                proposal.eventId(), proposal.payloadDigest());
        SandboxExecutionContext context = new SandboxExecutionContext(run, caseRun, trace,
                TestRunMode.SEAL_REPLAY, "CASE-1001", "CUST-1001");
        ToolInvocation invocation = new ToolInvocation(new ToolProposal("CUSTOMER_DATA_READ", arguments.deepCopy()),
                proposal.eventId(), proposal.payloadDigest());
        return new Fixture(release, testCase, approved, invocationKey, session, context, invocation);
    }

    private ObjectNode resource(String path) {
        try (var stream = getClass().getResourceAsStream(path)) {
            assertThat(stream).isNotNull();
            return (ObjectNode) json.readTree(stream);
        } catch (java.io.IOException failure) {
            throw new IllegalStateException("Missing composition fixture", failure);
        }
    }

    private String etag(Version version) {
        return '"' + version.resourceHash() + '"';
    }

    private Map<String, String> scopedDigest(Pair pair) {
        assertNoAmbientTransaction();
        TransactionTemplate transaction = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        transaction.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        transaction.setReadOnly(true);
        transaction.setTimeout(5);
        return transaction.execute(status -> {
            db.execute("set local statement_timeout='2500ms'");
            Map<String, String> snapshot = new LinkedHashMap<>();
            for (SnapshotQuery query : SNAPSHOT_QUERIES) {
                Object[] parameters = switch (query.scope()) {
                    case RUN -> new Object[] {pair.target().key().runId(), pair.other().key().runId()};
                    case CASE -> new Object[] {pair.target().key().caseRunId(), pair.other().key().caseRunId()};
                    case SESSION -> new Object[] {revocations.sessionDigest(pair.target().session()),
                            revocations.sessionDigest(pair.other().session())};
                    case AUDIT -> new Object[] {pair.target().release(), pair.other().release(),
                            pair.target().approved().id(), pair.other().approved().id(),
                            pair.target().key().runId(), pair.other().key().runId(),
                            pair.target().key().caseRunId(), pair.other().key().caseRunId()};
                };
                String value = db.queryForObject(query.sql(), String.class, parameters);
                assertThat(value).matches("[0-9]+:[0-9a-f]{64}");
                snapshot.put(query.name(), value);
            }
            return Map.copyOf(snapshot);
        });
    }

    // All identifiers and predicates below are fixed literals; fixture values are bound parameters.
    private static final List<SnapshotQuery> SNAPSHOT_QUERIES = List.of(
            new SnapshotQuery("test_runs", Scope.RUN, """
                    select count(*)::text || ':' || encode(digest(coalesce(
                        jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text), '[]'::jsonb)::text, 'sha256'), 'hex')
                      from test_runs t where t.id in (?,?)
                    """),
            new SnapshotQuery("test_case_runs", Scope.CASE, """
                    select count(*)::text || ':' || encode(digest(coalesce(
                        jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text), '[]'::jsonb)::text, 'sha256'), 'hex')
                      from test_case_runs t where t.id in (?,?)
                    """),
            new SnapshotQuery("test_run_reviewer_grants", Scope.RUN, """
                    select count(*)::text || ':' || encode(digest(coalesce(
                        jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text), '[]'::jsonb)::text, 'sha256'), 'hex')
                      from test_run_reviewer_grants t where t.run_id in (?,?)
                    """),
            new SnapshotQuery("reviewer_session_revocations", Scope.SESSION, """
                    select count(*)::text || ':' || encode(digest(coalesce(
                        jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text), '[]'::jsonb)::text, 'sha256'), 'hex')
                      from reviewer_session_revocations t where t.session_digest in (?,?)
                    """),
            new SnapshotQuery("sandbox_namespaces", Scope.RUN, """
                    select count(*)::text || ':' || encode(digest(coalesce(
                        jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text), '[]'::jsonb)::text, 'sha256'), 'hex')
                      from sandbox_namespaces t where t.id in (?,?)
                    """),
            new SnapshotQuery("sandbox_customers", Scope.RUN, """
                    select count(*)::text || ':' || encode(digest(coalesce(
                        jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text), '[]'::jsonb)::text, 'sha256'), 'hex')
                      from sandbox_customers t where t.namespace_id in (?,?)
                    """),
            new SnapshotQuery("sandbox_loan_cases", Scope.RUN, """
                    select count(*)::text || ':' || encode(digest(coalesce(
                        jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text), '[]'::jsonb)::text, 'sha256'), 'hex')
                      from sandbox_loan_cases t where t.namespace_id in (?,?)
                    """),
            new SnapshotQuery("sandbox_documents", Scope.RUN, """
                    select count(*)::text || ':' || encode(digest(coalesce(
                        jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text), '[]'::jsonb)::text, 'sha256'), 'hex')
                      from sandbox_documents t where t.namespace_id in (?,?)
                    """),
            new SnapshotQuery("sandbox_loan_policies", Scope.RUN, """
                    select count(*)::text || ':' || encode(digest(coalesce(
                        jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text), '[]'::jsonb)::text, 'sha256'), 'hex')
                      from sandbox_loan_policies t where t.namespace_id in (?,?)
                    """),
            new SnapshotQuery("sandbox_review_notes", Scope.RUN, """
                    select count(*)::text || ':' || encode(digest(coalesce(
                        jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text), '[]'::jsonb)::text, 'sha256'), 'hex')
                      from sandbox_review_notes t where t.namespace_id in (?,?)
                    """),
            new SnapshotQuery("sandbox_loan_decisions", Scope.RUN, """
                    select count(*)::text || ':' || encode(digest(coalesce(
                        jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text), '[]'::jsonb)::text, 'sha256'), 'hex')
                      from sandbox_loan_decisions t where t.namespace_id in (?,?)
                    """),
            new SnapshotQuery("sandbox_exfil_events", Scope.RUN, """
                    select count(*)::text || ':' || encode(digest(coalesce(
                        jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text), '[]'::jsonb)::text, 'sha256'), 'hex')
                      from sandbox_exfil_events t where t.namespace_id in (?,?)
                    """),
            new SnapshotQuery("execution_events", Scope.RUN, """
                    select count(*)::text || ':' || encode(digest(coalesce(
                        jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text), '[]'::jsonb)::text, 'sha256'), 'hex')
                      from execution_events t where t.run_id in (?,?)
                    """),
            new SnapshotQuery("run_event_counters", Scope.RUN, """
                    select count(*)::text || ':' || encode(digest(coalesce(
                        jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text), '[]'::jsonb)::text, 'sha256'), 'hex')
                      from run_event_counters t where t.run_id in (?,?)
                    """),
            new SnapshotQuery("sandbox_tool_idempotency_records", Scope.CASE, """
                    select count(*)::text || ':' || encode(digest(coalesce(
                        jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text), '[]'::jsonb)::text, 'sha256'), 'hex')
                      from sandbox_tool_idempotency_records t where t.test_case_run_id in (?,?)
                    """),
            new SnapshotQuery("audit_records", Scope.AUDIT, """
                    select count(*)::text || ':' || encode(digest(coalesce(
                        jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text), '[]'::jsonb)::text, 'sha256'), 'hex')
                      from audit_records t where t.resource_id in (?,?,?,?,?,?,?,?)
                    """));

    private enum Scope { RUN, CASE, SESSION, AUDIT }
    private record SnapshotQuery(String name, Scope scope, String sql) { }
    private record Fixture(UUID release, UUID testCase, Version approved, InvocationKey key,
            ContractReviewerCredentials.Session session, SandboxExecutionContext context, ToolInvocation invocation) { }
    private record Pair(Fixture target, Fixture other) { }
    private record CacheState(Set<Object> keys, Set<UUID> releases, long epoch, int pending) { }
    private record Observation(UUID audit, UUID release, String action, int persistedRows) { }
    private record GatewayProbe(LoanReviewPolicyGateway gateway, AtomicReference<InvocationKey> requestedKey,
            AtomicReference<Duration> remaining, AtomicInteger reviewerCalls, AtomicInteger adapterCalls,
            Object[] downstream) { }
    private static final class FixtureRollback extends RuntimeException { }
}
