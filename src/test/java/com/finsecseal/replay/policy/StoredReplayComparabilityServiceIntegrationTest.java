package com.finsecseal.replay.policy;

import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.audit.AuditDto;
import com.finsecseal.audit.AuditService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.ReleaseLifecycleState;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.evidence.TestRunDto;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.evidence.TestRunProjectionService;
import com.finsecseal.platform.contract.ContractPersistenceService;
import com.finsecseal.platform.contract.ContractPersistenceService.Version;
import com.finsecseal.release.FingerprintService;
import com.finsecseal.release.ReleaseService;
import com.finsecseal.replay.policy.ReplayComparabilityResult.Mismatch;
import com.finsecseal.replay.policy.ReplayComparabilityResult.MismatchCode;
import com.finsecseal.replay.policy.ReplayRecordedSource.RecordedCaseControls;
import com.finsecseal.replay.policy.StoredReplayComparabilityService.FailureCode;
import com.finsecseal.replay.policy.StoredReplayComparabilityService.ReplaySourceException;
import com.finsecseal.replay.policy.StoredReplayComparabilityService.StoredReplayAssessment;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.stubbing.Answer;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/** Actual A storage and transaction reads; test-authored model events and explicitly synthetic controls. */
@Testcontainers
@SpringBootTest(properties = {
        "finsec.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "finsec.scheduling.enabled=false", "finsec.ai.enabled=false"
})
@Import(StoredReplayComparabilityServiceIntegrationTest.ReplayTestConfiguration.class)
@ExtendWith(OutputCaptureExtension.class)
class StoredReplayComparabilityServiceIntegrationTest {
    private static final String ACTOR = "c-stored-replay-pg";
    private static final String PRIVATE = "STORED-REPLAY-PRIVATE-CANARY";
    private static final String PROMPT = "STORED-REPLAY-PROMPT-CANARY";
    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final ReviewerContext APPROVER = new ReviewerContext(AgentService.DEMO_WORKSPACE_ID,
            "historical-pg-approver", "AI_SECURITY_REVIEWER", PRIVATE, true, true, false);
    private static final ReviewerContext REVIEWER = new ReviewerContext(AgentService.DEMO_WORKSPACE_ID,
            ACTOR, "AI_SECURITY_REVIEWER", PRIVATE, true, true, false);
    private static final List<String> DOMAIN_TABLES = List.of(
            "agents", "agent_releases", "release_artifacts", "safety_contracts", "safety_contract_versions",
            "contract_version_evidence", "api_idempotency_records", "patch_proposals", "patch_approvals",
            "test_suites", "test_cases", "test_runs", "test_case_runs", "run_event_counters", "execution_events",
            "findings", "oracle_results", "replay_links", "release_decisions", "evidence_references");

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired StoredReplayComparabilityService source;
    @Autowired ReplayRecordedSource controls;
    @Autowired ReplayComparabilityEvaluator comparator;
    @MockitoSpyBean TestRunProjectionService runs;
    @MockitoSpyBean TestRunPersistenceService cases;
    @MockitoSpyBean ContractPersistenceService contracts;
    @MockitoSpyBean AuditService audits;
    @MockitoSpyBean ExecutionEventService events;
    @Autowired AgentService agents;
    @Autowired ReleaseService releases;
    @Autowired FingerprintService fingerprints;
    @Autowired ObjectMapper json;
    @Autowired JdbcTemplate jdbc;
    @Autowired DataSource dataSource;
    @Autowired PlatformTransactionManager transactions;

    @Test
    void actualAReadsAndRecordedApprovalComposeWithExplicitlySyntheticControls(CapturedOutput output) throws Exception {
        Seed seed = seed();
        Observations observed = observeReads(seed);
        configureControls(seed, observed, false);
        Snapshot before = snapshot();
        clearSourceInvocations();

        StoredReplayAssessment result = compare(seed);

        assertThat(AopUtils.isAopProxy(source)).isTrue();
        assertThat(result).isEqualTo(new StoredReplayAssessment(seed.baseline().runId(), seed.baseline().caseRunId(),
                seed.replay().runId(), seed.replay().caseRunId(), seed.approved().id(), seed.approved().policyHash(),
                seed.expectedComparison()));
        verifyReadOrder(seed, true);
        observed.assertOnePhysicalSnapshot();
        assertSafeResult(result);
        assertUnchanged(before, output);
        assertNoAmbientTransaction();
    }

    @Test
    void actualAReadsCannotSubstituteForUnavailableRecordedControls(CapturedOutput output) throws Exception {
        Seed seed = seed();
        Observations observed = observeReads(seed);
        configureControls(seed, observed, true);
        Snapshot before = snapshot();
        clearSourceInvocations();

        assertFailure(() -> compare(seed), FailureCode.CONTROL_SOURCE_UNAVAILABLE);

        verifyReadOrder(seed, false);
        observed.assertOnePhysicalSnapshot();
        assertUnchanged(before, output);
        assertNoAmbientTransaction();
    }

    @Test
    void actualARejectsForeignReviewerBeforeBaselineOrEvidenceReads(CapturedOutput output) throws Exception {
        Seed seed = seed();
        ReviewerContext foreign = new ReviewerContext(UUID.randomUUID(), "foreign-reviewer", "AI_SECURITY_REVIEWER",
                PRIVATE, true, true, false);
        Snapshot before = snapshot();
        clearSourceInvocations();

        assertThatThrownBy(() -> source.compare(seed.baseline().caseRunId(), seed.replay().caseRunId(), foreign))
                .isInstanceOfSatisfying(BusinessException.class,
                        error -> assertThat(error.errorCode()).isEqualTo(ErrorCode.OPERATOR_AUTH_REQUIRED));

        var order = inOrder(cases, runs, contracts);
        order.verify(cases).findCase(seed.replay().caseRunId());
        order.verify(runs).find(seed.replay().runId());
        order.verify(contracts).find(seed.approved().id(), foreign);
        verify(cases, never()).findCase(seed.baseline().caseRunId());
        verify(runs, never()).find(seed.baseline().runId());
        verifyNoInteractions(audits, events, controls, comparator);
        assertUnchanged(before, output);
        assertNoAmbientTransaction();
    }

    @Test
    void differentActualReleaseStopsBeforeAuditHistoryAndControls(CapturedOutput output) throws Exception {
        Seed seed = seed();
        UUID otherRelease = analyzedRelease();
        RunCase foreignBaseline = completedRun(otherRelease, seed.suiteId(), seed.testCaseId(), seed.pairId(),
                null, TestRunMode.BASELINE);
        Snapshot before = snapshot();
        clearSourceInvocations();

        assertFailure(() -> source.compare(foreignBaseline.caseRunId(), seed.replay().caseRunId(), REVIEWER),
                FailureCode.SOURCE_BINDING_INVALID);

        var order = inOrder(cases, runs, contracts);
        order.verify(cases).findCase(seed.replay().caseRunId());
        order.verify(runs).find(seed.replay().runId());
        order.verify(contracts).find(seed.approved().id(), REVIEWER);
        order.verify(cases).findCase(foreignBaseline.caseRunId());
        order.verify(runs).find(foreignBaseline.runId());
        verifyNoInteractions(audits, events, controls, comparator);
        assertUnchanged(before, output);
        assertNoAmbientTransaction();
    }

    @ParameterizedTest(name = "reject {0}")
    @MethodSource("incompatibleTransactions")
    void incompatibleAmbientTransactionsStopBeforeEveryOwner(String label, int isolation, boolean readOnly,
            CapturedOutput output) throws Exception {
        Seed seed = seed();
        TransactionTemplate outer = transaction(isolation, readOnly);
        Snapshot before = snapshot();
        clearSourceInvocations();

        assertFailure(() -> outer.execute(status -> compare(seed)), FailureCode.UNSAFE_TRANSACTION);

        verifyNoInteractions(cases, runs, contracts, audits, events, controls, comparator);
        assertUnchanged(before, output);
        assertNoAmbientTransaction();
    }

    @Test
    void compatibleActualReadOnlyRepeatableReadRemainsOwnedByOuterCaller(CapturedOutput output) throws Exception {
        Seed seed = seed();
        Observations observed = observeReads(seed);
        configureControls(seed, observed, false);
        Snapshot before = snapshot();
        clearSourceInvocations();

        transaction(TransactionDefinition.ISOLATION_REPEATABLE_READ, true).executeWithoutResult(status -> {
            PhysicalTransaction outer = physicalTransaction();
            assertPhysical(outer);
            Object callerResource = TransactionSynchronizationManager.getResource(dataSource);
            assertThat(compare(seed).comparison()).isEqualTo(seed.expectedComparison());
            assertPhysical(physicalTransaction());
            assertThat(TransactionSynchronizationManager.getResource(dataSource)).isSameAs(callerResource);
            assertThat(observed.reads).allSatisfy(read -> assertThat(read.transaction().backendPid()).isEqualTo(outer.backendPid()));
            assertReleaseUnlocked(seed.releaseId(), outer.backendPid());
        });

        verifyReadOrder(seed, true);
        observed.assertOnePhysicalSnapshot();
        assertUnchanged(before, output);
        assertNoAmbientTransaction();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void synchronizationOnlyOuterIsRestoredAfterOwnSnapshotSuccessOrFailure(boolean unavailable,
            CapturedOutput output) throws Exception {
        Seed seed = seed();
        Observations observed = observeReads(seed);
        configureControls(seed, observed, unavailable);
        TransactionTemplate outer = new TransactionTemplate(transactions);
        outer.setPropagationBehavior(TransactionDefinition.PROPAGATION_SUPPORTS);
        AtomicInteger completions = new AtomicInteger();
        TransactionSynchronization marker = new TransactionSynchronization() {
            @Override public void afterCompletion(int status) {
                assertThat(status).isEqualTo(STATUS_COMMITTED);
                completions.incrementAndGet();
            }
        };
        Snapshot before = snapshot();
        clearSourceInvocations();

        outer.executeWithoutResult(status -> {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isTrue();
            assertThat(TransactionSynchronizationManager.hasResource(dataSource)).isFalse();
            TransactionSynchronizationManager.registerSynchronization(marker);
            if (unavailable) assertFailure(() -> compare(seed), FailureCode.CONTROL_SOURCE_UNAVAILABLE);
            else assertThat(compare(seed).comparison()).isEqualTo(seed.expectedComparison());
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isTrue();
            assertThat(TransactionSynchronizationManager.getSynchronizations()).contains(marker);
            assertThat(TransactionSynchronizationManager.hasResource(dataSource)).isFalse();
            assertThat(TransactionSynchronizationManager.isCurrentTransactionReadOnly()).isFalse();
            assertThat(TransactionSynchronizationManager.getCurrentTransactionIsolationLevel()).isNull();
            assertThat(completions).hasValue(0);
        });

        assertThat(completions).hasValue(1);
        verifyReadOrder(seed, !unavailable);
        observed.assertOnePhysicalSnapshot();
        assertUnchanged(before, output);
        assertNoAmbientTransaction();
    }

    private Seed seed() throws Exception {
        reset(controls, comparator);
        UUID releaseId = analyzedRelease();
        UUID suiteId = UUID.randomUUID(), testCaseId = UUID.randomUUID(), pairId = UUID.randomUUID();
        // Approved suite/case setup seam only. No owner lifecycle, policy, audit or event row is fabricated by SQL.
        jdbc.update("""
                insert into test_suites(id,workspace_id,suite_key,version,fixture_version,generation_config_json,suite_hash,status)
                values(?,?,?,'1.0','stored-replay-fixture-v1','{}'::jsonb,?,'BUILDING')
                """, suiteId, AgentService.DEMO_WORKSPACE_ID, "stored-replay-suite-" + UUID.randomUUID(), HASH);
        jdbc.update("""
                insert into test_cases(id,suite_id,case_key,case_type,partition_name,category,severity,delivery_channel,
                    payload_hash,preconditions_json,expected_invariant,oracle_type,generation_source,expected_result_json,trial_policy_json)
                values(?,?,'normal-1','NORMAL','NORMAL','NORMAL','LOW','DIRECT',?,'{}'::jsonb,
                    'INV-NORMAL','NORMAL_TASK','CURATED','{}'::jsonb,'{}'::jsonb)
                """, testCaseId, suiteId, HASH);
        jdbc.update("update test_suites set status='READY' where id=?", suiteId);

        // A snapshots the current fingerprint at registration. Baseline therefore precedes first approval.
        RunCase baseline = completedRun(releaseId, suiteId, testCaseId, pairId, null, TestRunMode.BASELINE);
        for (ReleaseLifecycleState target : List.of(ReleaseLifecycleState.TESTING, ReleaseLifecycleState.REMEDIATION)) {
            new TransactionTemplate(transactions).executeWithoutResult(status -> releases.getRequired(releaseId).transitionTo(target));
        }
        assertThat(releases.getRequired(releaseId).getLifecycleState()).isEqualTo(ReleaseLifecycleState.REMEDIATION);
        ObjectNode policy;
        try (var stream = getClass().getResourceAsStream("/fixtures/loan-review-safety-contract.json")) {
            policy = ((ObjectNode) json.readTree(stream)).put("contractId", "stored-replay-policy").put("version", 1);
        }
        Version candidate = contracts.create(releaseId, policy, APPROVER);
        Version validated = contracts.validate(candidate.id(), etag(candidate), APPROVER);
        Version approved = contracts.approve(validated.id(), etag(validated), "Stored replay source fixture", APPROVER);
        assertThat(approved.state()).isEqualTo("APPROVED");
        RunCase replay = completedRun(releaseId, suiteId, testCaseId, pairId, approved.id(), TestRunMode.SEAL_REPLAY);
        ReplayComparabilityResult expected = assertActualStoredEvidence(baseline, replay, approved);
        assertNoAmbientTransaction();
        return new Seed(releaseId, suiteId, testCaseId, pairId, baseline, replay, approved, expected);
    }

    private UUID analyzedRelease() throws Exception {
        String key = "stored-replay-" + UUID.randomUUID();
        var agent = agents.create(new AgentDto.CreateRequest(key, "Stored Replay source fixture", "Document review"));
        ObjectNode manifest;
        try (var stream = getClass().getResourceAsStream("/fixtures/valid-release-manifest-v1.1.json")) {
            manifest = (ObjectNode) json.readTree(stream);
        }
        ((ObjectNode) manifest.path("agent")).put("id", key);
        ((ObjectNode) manifest.path("systemPrompt")).put("text", PROMPT);
        UUID releaseId = releases.create(agent.id(), manifest, ACTOR).id();
        releases.analyze(releaseId, ACTOR);
        return releaseId;
    }

    private RunCase completedRun(UUID releaseId, UUID suiteId, UUID testCaseId, UUID pairId, UUID contractId, TestRunMode mode) {
        UUID runId = cases.register(new TestRunPersistenceDto.RegisterRequest(releaseId, suiteId, contractId, mode,
                pairId, json.createObjectNode(), HASH, HASH, 42L, 1), ACTOR).runId();
        UUID caseRunId = cases.registerCase(runId, new TestRunPersistenceDto.CaseRunRegisterRequest(testCaseId, 0, HASH), ACTOR).id();
        UUID trace = UUID.randomUUID();
        append(runId, null, trace, ExecutionEventType.RUN_STARTED, null);
        cases.updateStatus(runId, new TestRunPersistenceDto.StatusRequest(TestRunStatus.PREPARING, 0, 0, null), ACTOR);
        cases.updateStatus(runId, new TestRunPersistenceDto.StatusRequest(TestRunStatus.RUNNING, 0, 0, null), ACTOR);
        cases.updateCaseStatus(runId, caseRunId, new TestRunPersistenceDto.CaseRunStatusRequest(
                TestCaseRunStatus.EXECUTING, null, null, null, null, null, null), ACTOR);
        // Persisted by actual A append; this is a test-authored model report, not an actual B/model execution.
        append(runId, caseRunId, trace, ExecutionEventType.MODEL_RESPONSE, json.createObjectNode()
                .put("provider", "synthetic-reported-provider").put("model", "synthetic-reported-model").put("private", PRIVATE));
        cases.updateCaseStatus(runId, caseRunId, new TestRunPersistenceDto.CaseRunStatusRequest(
                TestCaseRunStatus.PASSED, null, null, null, null, null, null), ACTOR);
        append(runId, null, trace, ExecutionEventType.RUN_COMPLETED, null);
        cases.updateStatus(runId, new TestRunPersistenceDto.StatusRequest(TestRunStatus.COMPLETED, 1, 0, null), ACTOR);
        return new RunCase(runId, caseRunId);
    }

    private void append(UUID run, UUID caseRun, UUID trace, ExecutionEventType type, JsonNode body) {
        events.append(run, new ExecutionEventDto.AppendRequest(caseRun, trace, type, null, null, body, null,
                type.name(), json.createObjectNode().put("fixture", "test-authored historical event")), ACTOR);
    }

    private ReplayComparabilityResult assertActualStoredEvidence(RunCase baselineRun, RunCase replayRun, Version approved) {
        TestRunDto.Projection baseline = runs.find(baselineRun.runId());
        TestRunDto.Projection replay = runs.find(replayRun.runId());
        assertThat(baseline.contractVersionId()).isNull();
        assertThat(replay.contractVersionId()).isEqualTo(approved.id());
        assertThat(baseline.releaseFingerprint()).isEqualTo(fingerprints.releaseFingerprint(baseline.agentArtifactFingerprint(), null));
        assertThat(replay.releaseFingerprint()).isEqualTo(fingerprints.releaseFingerprint(replay.agentArtifactFingerprint(), approved.policyHash()));
        assertThat(replay.releaseFingerprint()).isNotEqualTo(baseline.releaseFingerprint());
        List<AuditDto.Record> approval = audits.find("CONTRACT_VERSION", approved.id(), 100).stream()
                .filter(audit -> audit.action().equals("CONTRACT_APPROVED")).toList();
        assertThat(approval).hasSize(1);
        AuditDto.Record record = approval.getFirst();
        assertThat(record.workspaceId()).isEqualTo(AgentService.DEMO_WORKSPACE_ID);
        assertThat(record.resourceType()).isEqualTo("CONTRACT_VERSION");
        assertThat(record.resourceId()).isEqualTo(approved.id());
        assertThat(record.actorId()).isEqualTo(APPROVER.actorId()).isNotEqualTo(REVIEWER.actorId());
        assertThat(record.afterDigest()).isEqualTo(approved.resourceHash());
        assertThat(record.metadata().path("state").stringValue()).isEqualTo("APPROVED");
        assertThat(record.metadata().path("policyHash").stringValue()).isEqualTo(approved.policyHash());
        assertThat(record.occurredAt()).isNotNull();
        assertThat(replay.startedAt()).isNotNull();
        for (RunCase run : List.of(baselineRun, replayRun)) {
            TestRunDto.Projection projection = runs.find(run.runId());
            assertThat(projection.status()).isEqualTo(TestRunStatus.COMPLETED);
            assertThat(projection.startedAt()).isNotNull();
            assertThat(projection.completedAt()).isNotNull();
            assertThat(cases.findCase(run.caseRunId()).status()).isEqualTo(TestCaseRunStatus.PASSED);
            var history = events.history(run.runId(), 0, 1000);
            var chain = events.verifyChain(run.runId());
            assertThat(history.items()).extracting(ExecutionEventDto.Event::eventType)
                    .containsExactly(ExecutionEventType.RUN_STARTED, ExecutionEventType.MODEL_RESPONSE, ExecutionEventType.RUN_COMPLETED);
            assertThat(history.nextCursor()).isNull();
            assertThat(history.headSequence()).isEqualTo(projection.latestSequence()).isEqualTo(3);
            assertThat(chain.valid()).isTrue();
            assertThat(chain.eventCount()).isEqualTo(3);
            assertThat(chain.headHash()).isEqualTo(projection.eventHeadHash()).isEqualTo(history.items().getLast().eventHash());
        }
        // Independent fixture expectation from actual stored times, before source invocation. A completed
        // approval call does not establish this recorded ordering or stronger commit/clock chronology.
        boolean ordered = !record.occurredAt().isAfter(replay.startedAt());
        System.out.printf("StoredReplay PG recorded-order: approval=%s, runStarted=%s, expected=%s%n",
                record.occurredAt(), replay.startedAt(), ordered ? "COMPARABLE" : "APPROVAL_UNKNOWN");
        return ordered ? new ReplayComparabilityResult(true, List.of())
                : new ReplayComparabilityResult(false, List.of(new Mismatch(
                        MismatchCode.REPLAY_POLICY_BINDING_INVALID, "/replay/contractApproved")));
    }

    private Observations observeReads(Seed seed) {
        Observations observed = new Observations();
        doAnswer(observed.read("case")).when(cases).findCase(any());
        doAnswer(observed.read("run")).when(runs).find(any());
        doAnswer(observed.read("contract")).when(contracts).find(eq(seed.approved().id()), any());
        doAnswer(observed.read("audit")).when(audits).find("CONTRACT_VERSION", seed.approved().id(), 100);
        doAnswer(observed.read("history")).when(events).history(any(), anyLong(), anyInt());
        doAnswer(observed.read("chain")).when(events).verifyChain(any());
        return observed;
    }

    private void configureControls(Seed seed, Observations observed, boolean unavailable) {
        doAnswer(invocation -> {
            PhysicalTransaction physical = observed.capture("controls");
            assertReleaseUnlocked(seed.releaseId(), physical.backendPid());
            if (unavailable) throw new IllegalStateException(PRIVATE);
            UUID run = invocation.getArgument(0), caseRun = invocation.getArgument(1);
            RunCase expected = run.equals(seed.baseline().runId()) ? seed.baseline() : seed.replay();
            assertThat(run).isEqualTo(expected.runId());
            assertThat(caseRun).isEqualTo(expected.caseRunId());
            // Deliberately synthetic, including completion/namespace/control history. This does not read
            // missing immutable A/B controls and is never a production provider or fully stored proof.
            return new RecordedCaseControls(run, caseRun, seed.pairId(), 42L,
                    Instant.parse("2026-09-01T00:00:00Z"), run, HASH, "synthetic-resolved-model", HASH,
                    HASH, HASH, "synthetic-rag-v1", HASH);
        }).when(controls).caseControls(any(), any());
    }

    private void verifyReadOrder(Seed seed, boolean complete) {
        var order = inOrder(cases, runs, contracts, audits, events, controls, comparator);
        order.verify(cases).findCase(seed.replay().caseRunId());
        order.verify(runs).find(seed.replay().runId());
        order.verify(contracts).find(seed.approved().id(), REVIEWER);
        order.verify(cases).findCase(seed.baseline().caseRunId());
        order.verify(runs).find(seed.baseline().runId());
        order.verify(audits).find("CONTRACT_VERSION", seed.approved().id(), 100);
        order.verify(events).history(seed.baseline().runId(), 0, 1000);
        order.verify(events).verifyChain(seed.baseline().runId());
        order.verify(events).history(seed.replay().runId(), 0, 1000);
        order.verify(events).verifyChain(seed.replay().runId());
        order.verify(controls).caseControls(seed.baseline().runId(), seed.baseline().caseRunId());
        if (complete) {
            order.verify(controls).caseControls(seed.replay().runId(), seed.replay().caseRunId());
            order.verify(comparator).evaluate(any(), any());
        } else {
            verify(controls, never()).caseControls(seed.replay().runId(), seed.replay().caseRunId());
            verifyNoInteractions(comparator);
        }
        verify(contracts, never()).approved(any(), any(), any());
    }

    private StoredReplayAssessment compare(Seed seed) {
        return source.compare(seed.baseline().caseRunId(), seed.replay().caseRunId(), REVIEWER);
    }

    private void clearSourceInvocations() { clearInvocations(cases, runs, contracts, audits, events, controls, comparator); }

    private Snapshot snapshot() {
        Map<String, String> domain = new LinkedHashMap<>();
        for (String table : DOMAIN_TABLES) {
            String key = table.equals("contract_version_evidence") ? "version_id" : table.equals("run_event_counters") ? "run_id" : "id";
            domain.put(table, tableSnapshot(table, key));
        }
        return new Snapshot(domain, tableSnapshot("audit_records", "id"));
    }

    private String tableSnapshot(String table, String key) {
        return jdbc.queryForObject("select coalesce(jsonb_agg(to_jsonb(t) order by " + key
                + ")::text, '[]') from " + table + " t", String.class);
    }

    private void assertUnchanged(Snapshot before, CapturedOutput output) {
        // Full rows include immutable event payload/hashchain, run head counters, ReplayLinks and Oracle rows.
        assertThat(snapshot()).isEqualTo(before);
        assertThat(jdbc.queryForObject("select count(*) from execution_events where event_type='TOOL_REQUEST'", Integer.class)).isZero();
        verify(contracts, never()).create(any(), any(), any());
        verify(contracts, never()).validate(any(), any(), any());
        verify(contracts, never()).approve(any(), any(), any(), any());
        verify(contracts, never()).approve(any(), any(), any(), any(), any());
        verify(contracts, never()).reject(any(), any(), any(), any());
        verify(contracts, never()).storePatch(any(), any(), any(), any());
        verify(cases, never()).register(any(), any());
        verify(cases, never()).registerCase(any(), any(), any());
        verify(cases, never()).updateStatus(any(), any(), any());
        verify(cases, never()).updateCaseStatus(any(), any(), any(), any());
        verify(events, never()).append(any(), any(), any());
        verify(audits, never()).append(any(), any(), any(), any(), any(), any(), any(), any());
        assertThat(output.getAll()).doesNotContain(PRIVATE, PROMPT);
    }

    private PhysicalTransaction physicalTransaction() {
        Map<String, Object> values = jdbc.queryForMap("select current_setting('transaction_isolation') as isolation, "
                + "current_setting('transaction_read_only') as read_only, pg_backend_pid() as backend_pid");
        return new PhysicalTransaction((String) values.get("isolation"), (String) values.get("read_only"),
                ((Number) values.get("backend_pid")).intValue(), TransactionSynchronizationManager.isActualTransactionActive(),
                TransactionSynchronizationManager.isSynchronizationActive(), TransactionSynchronizationManager.isCurrentTransactionReadOnly(),
                TransactionSynchronizationManager.getCurrentTransactionIsolationLevel(), TransactionSynchronizationManager.getResource(dataSource));
    }

    private void assertPhysical(PhysicalTransaction tx) {
        assertThat(tx.isolation()).isEqualTo("repeatable read");
        assertThat(tx.readOnly()).isEqualTo("on");
        assertThat(tx.active()).isTrue();
        assertThat(tx.synchronization()).isTrue();
        assertThat(tx.metadataReadOnly()).isTrue();
        assertThat(tx.metadataIsolation()).isEqualTo(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        assertThat(tx.resource()).isNotNull();
    }

    private void assertReleaseUnlocked(UUID releaseId, int sourceBackend) {
        try (Connection independent = dataSource.getConnection()) {
            independent.setAutoCommit(false);
            try {
                try (var pid = independent.prepareStatement("select pg_backend_pid()")) {
                    try (var rows = pid.executeQuery()) {
                        assertThat(rows.next()).isTrue();
                        assertThat(rows.getInt(1)).isNotEqualTo(sourceBackend);
                    }
                }
                try (var lock = independent.prepareStatement("select id from agent_releases where id=? for update nowait")) {
                    lock.setQueryTimeout(2);
                    lock.setObject(1, releaseId);
                    try (var rows = lock.executeQuery()) {
                        assertThat(rows.next()).isTrue();
                        assertThat(rows.getObject(1, UUID.class)).isEqualTo(releaseId);
                    }
                }
            } finally {
                independent.rollback();
            }
        } catch (SQLException failure) {
            throw new AssertionError("Independent Release lock probe failed", failure);
        }
    }

    private void assertNoAmbientTransaction() {
        assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
        assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isFalse();
        assertThat(TransactionSynchronizationManager.hasResource(dataSource)).isFalse();
    }

    private void assertFailure(org.assertj.core.api.ThrowableAssert.ThrowingCallable call, FailureCode code) {
        ReplaySourceException failure = catchThrowableOfType(call, ReplaySourceException.class);
        assertThat(failure).isNotNull();
        assertThat(failure.code()).isEqualTo(code);
        assertThat(failure.getMessage()).isEqualTo("Stored replay source unavailable: " + code.name());
        assertThat(failure.getCause()).isNull();
        assertThat(failure.getSuppressed()).isEmpty();
        StringWriter rendered = new StringWriter();
        failure.printStackTrace(new PrintWriter(rendered));
        assertThat(rendered.toString()).doesNotContain(PRIVATE, PROMPT);
    }

    private void assertSafeResult(StoredReplayAssessment result) {
        assertThat(json.writeValueAsString(result)).doesNotContain(PRIVATE, PROMPT, "synthetic-reported-model", "synthetic-resolved-model");
        assertThat(result.toString()).doesNotContain(PRIVATE, PROMPT, "synthetic-reported-model", "synthetic-resolved-model");
    }

    private TransactionTemplate transaction(int isolation, boolean readOnly) {
        TransactionTemplate transaction = new TransactionTemplate(transactions);
        transaction.setIsolationLevel(isolation);
        transaction.setReadOnly(readOnly);
        return transaction;
    }

    private String etag(Version version) { return '"' + version.resourceHash() + '"'; }

    private static Stream<Arguments> incompatibleTransactions() {
        return Stream.of(
                Arguments.of("writable RR", TransactionDefinition.ISOLATION_REPEATABLE_READ, false),
                Arguments.of("read-only READ_COMMITTED", TransactionDefinition.ISOLATION_READ_COMMITTED, true),
                Arguments.of("read-only default isolation", TransactionDefinition.ISOLATION_DEFAULT, true));
    }

    private final class Observations {
        private final List<ReadObservation> reads = new ArrayList<>();
        private PhysicalTransaction capture(String stage) {
            PhysicalTransaction tx = physicalTransaction();
            assertPhysical(tx);
            reads.add(new ReadObservation(stage, tx));
            return tx;
        }
        private Answer<Object> read(String stage) {
            return invocation -> { capture(stage); return invocation.callRealMethod(); };
        }
        private void assertOnePhysicalSnapshot() {
            assertThat(reads).isNotEmpty();
            assertThat(reads.getFirst().stage()).isEqualTo("case");
            assertThat(reads).extracting(ReadObservation::stage).contains("contract", "audit", "history", "chain", "controls");
            assertThat(reads.stream().map(read -> read.transaction().backendPid()).distinct().toList()).hasSize(1);
            Object resource = reads.getFirst().transaction().resource();
            assertThat(reads).allSatisfy(read -> assertThat(read.transaction().resource()).isSameAs(resource));
        }
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class ReplayTestConfiguration {
        @Bean ReplayRecordedSource testRecordedControls() { return mock(ReplayRecordedSource.class); }
        @Bean ReplayComparabilityEvaluator testReplayComparator() { return spy(new ReplayComparabilityEvaluator()); }
        @Bean StoredReplayComparabilityService testStoredReplaySource(TestRunProjectionService runs,
                TestRunPersistenceService cases, ContractPersistenceService contracts, FingerprintService fingerprints,
                ExecutionEventService events, AuditService audits, ReplayRecordedSource recorded,
                ReplayComparabilityEvaluator comparator) {
            return new StoredReplayComparabilityService(runs, cases, contracts, fingerprints, events, audits, recorded, comparator);
        }
    }

    private record RunCase(UUID runId, UUID caseRunId) {}
    private record Seed(UUID releaseId, UUID suiteId, UUID testCaseId, UUID pairId, RunCase baseline, RunCase replay,
            Version approved, ReplayComparabilityResult expectedComparison) {}
    private record Snapshot(Map<String, String> domain, String audits) {}
    private record ReadObservation(String stage, PhysicalTransaction transaction) {}
    private record PhysicalTransaction(String isolation, String readOnly, int backendPid, boolean active,
            boolean synchronization, boolean metadataReadOnly, Integer metadataIsolation, Object resource) {}
}
