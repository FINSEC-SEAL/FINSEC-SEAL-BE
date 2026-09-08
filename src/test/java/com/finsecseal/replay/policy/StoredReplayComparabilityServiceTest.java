package com.finsecseal.replay.policy;

import com.finsecseal.audit.AuditDto;
import com.finsecseal.audit.AuditService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
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
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.FingerprintService;
import com.finsecseal.replay.policy.ReplayComparabilityResult.Mismatch;
import com.finsecseal.replay.policy.ReplayComparabilityResult.MismatchCode;
import com.finsecseal.replay.policy.ReplayRecordedSource.RecordedCaseControls;
import com.finsecseal.replay.policy.StoredReplayComparabilityService.FailureCode;
import com.finsecseal.replay.policy.StoredReplayComparabilityService.ReplaySourceException;
import com.finsecseal.replay.policy.StoredReplayComparabilityService.StoredReplayAssessment;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.BiFunction;
import java.util.stream.IntStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import tools.jackson.databind.node.StringNode;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Mock A projections and synthetic recorded controls test C assembly, not stored execution provenance. */
@ExtendWith(OutputCaptureExtension.class)
class StoredReplayComparabilityServiceTest {
    private static final UUID BASE_RUN = id(1), REPLAY_RUN = id(2), BASE_CASE = id(3), REPLAY_CASE = id(4);
    private static final UUID RELEASE = id(5), VERSION = id(6), WORKSPACE = id(7), ATTACK = id(8), PAIR = id(9);
    private static final String HASH = hash(1), POLICY_HASH = hash(2), RESOURCE_HASH = hash(3);
    private static final String PRIVATE = "synthetic-private-source-canary";
    private static final String HISTORICAL_ACTOR = "historical-reviewer";
    private static final Instant START = Instant.parse("2026-09-08T01:00:00Z");
    private static final Instant END = START.plusSeconds(10);
    private static final ReviewerContext REVIEWER = new ReviewerContext(WORKSPACE, "current-reviewer",
            "AI_SECURITY_REVIEWER", PRIVATE, true, true, false);

    private final ObjectMapper json = new ObjectMapper();
    private final TestRunProjectionService runs = mock(TestRunProjectionService.class);
    private final TestRunPersistenceService cases = mock(TestRunPersistenceService.class);
    private final ContractPersistenceService contracts = mock(ContractPersistenceService.class);
    private final ExecutionEventService events = mock(ExecutionEventService.class);
    private final AuditService audits = mock(AuditService.class);
    private final ReplayRecordedSource controls = mock(ReplayRecordedSource.class);
    private final FingerprintService fingerprints = new FingerprintService(
            new CanonicalJsonService(json), new DigestService(), json);
    private final ReplayComparabilityEvaluator comparator = spy(new ReplayComparabilityEvaluator());
    private final StoredReplayComparabilityService source = new StoredReplayComparabilityService(
            runs, cases, contracts, fingerprints, events, audits, controls, comparator);
    private final RunRow baseline = new RunRow(BASE_RUN, null, TestRunMode.BASELINE);
    private final RunRow replay = new RunRow(REPLAY_RUN, VERSION, TestRunMode.SEAL_REPLAY);
    private final CaseRow baseCase = new CaseRow(BASE_CASE, BASE_RUN);
    private final CaseRow replayCase = new CaseRow(REPLAY_CASE, REPLAY_RUN);
    private final VersionRow version = new VersionRow();
    private final Map<UUID, RecordedCaseControls> recorded = new HashMap<>();
    private final Map<UUID, List<ExecutionEventDto.Event>> histories = new HashMap<>();
    private final Map<UUID, ExecutionEventDto.ChainVerification> chains = new HashMap<>();
    private List<AuditDto.Record> approvalRecords;
    private BiFunction<UUID, Long, ExecutionEventDto.History> pages;
    private CapturedOutput output;

    @BeforeEach
    void setup(CapturedOutput captured) {
        output = captured;
        // Metadata-only unit fixture; physical PostgreSQL behavior belongs to the next PG unit.
        TransactionSynchronizationManager.setActualTransactionActive(true);
        TransactionSynchronizationManager.setCurrentTransactionReadOnly(true);
        TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        TransactionSynchronizationManager.initSynchronization();
        when(runs.find(BASE_RUN)).thenAnswer(call -> baseline.build());
        when(runs.find(REPLAY_RUN)).thenAnswer(call -> replay.build());
        when(cases.findCase(BASE_CASE)).thenAnswer(call -> baseCase.build());
        when(cases.findCase(REPLAY_CASE)).thenAnswer(call -> replayCase.build());
        when(contracts.find(eq(VERSION), any())).thenAnswer(call -> version.build());
        approvalRecords = List.of(approval(START.minusSeconds(1)));
        when(audits.find("CONTRACT_VERSION", VERSION, 100)).thenAnswer(call -> approvalRecords);
        for (UUID run : List.of(BASE_RUN, REPLAY_RUN)) {
            UUID selectedCase = run.equals(BASE_RUN) ? BASE_CASE : REPLAY_CASE;
            recorded.put(run, recorded(run, selectedCase));
            histories.put(run, new ArrayList<>(List.of(
                    event(run, null, 1, ExecutionEventType.RUN_STARTED, null),
                    event(run, selectedCase, 2, ExecutionEventType.MODEL_RESPONSE, model()),
                    event(run, null, 3, ExecutionEventType.RUN_COMPLETED, null))));
            chains.put(run, new ExecutionEventDto.ChainVerification(run, true, 3, null, hash(103)));
        }
        pages = (run, after) -> new ExecutionEventDto.History(histories.get(run), 3, null);
        when(events.history(any(), anyLong(), anyInt())).thenAnswer(call ->
                pages.apply(call.getArgument(0), call.getArgument(1)));
        when(events.verifyChain(any())).thenAnswer(call -> chains.get(call.getArgument(0)));
        when(controls.caseControls(any(), any())).thenAnswer(call -> recorded.get(call.getArgument(0)));
    }

    @AfterEach
    void restoreThreadContext() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.clearSynchronization();
        }
        TransactionSynchronizationManager.clear();
        assertThat(output.getAll()).doesNotContain(PRIVATE);
    }

    @Test
    void authenticatesBeforeForeignReadsAndAssemblesActualFingerprintFormulaOnce() {
        StoredReplayAssessment assessment = compare();
        assertThat(assessment).isEqualTo(new StoredReplayAssessment(BASE_RUN, BASE_CASE, REPLAY_RUN,
                REPLAY_CASE, VERSION, POLICY_HASH, new ReplayComparabilityResult(true, List.of())));
        var order = inOrder(cases, runs, contracts);
        order.verify(cases).findCase(REPLAY_CASE);
        order.verify(runs).find(REPLAY_RUN);
        order.verify(contracts).find(VERSION, REVIEWER);
        order.verify(cases).findCase(BASE_CASE);
        order.verify(runs).find(BASE_RUN);
        List<ReplayComparisonFacts> facts = evaluatedFacts();
        assertThat(facts).containsExactly(expectedFacts(BASE_RUN, TestRunMode.BASELINE, null, false),
                expectedFacts(REPLAY_RUN, TestRunMode.SEAL_REPLAY, VERSION, true));
        assertThat(facts.get(0).releaseFingerprint()).isEqualTo(fingerprints.releaseFingerprint(HASH, null));
        assertThat(facts.get(1).releaseFingerprint()).isEqualTo(fingerprints.releaseFingerprint(HASH, POLICY_HASH));
        assertThat(facts.get(0).contractApproved()).isFalse();
        assertThat(facts.get(1).contractApproved()).isTrue();
        assertThat(facts.get(1).modelName()).isEqualTo("reported-model");
        assertThat(facts.get(1).resolvedModelId()).isEqualTo("resolved-model-snapshot");
        verify(audits).find("CONTRACT_VERSION", VERSION, 100);
        assertSafeResult(assessment);
    }

    @Test
    void keepsVerifiedHistoricalV1WhenMockOwnerCurrentApprovalHasMovedToV2() {
        // Unit owner projection only: actual public lifecycle/history persistence is a PG concern.
        UUID v2 = id(26);
        when(contracts.approved(RELEASE, VERSION, REVIEWER)).thenThrow(new BusinessException(ErrorCode.RELEASE_CHANGED, "Current is v2"));
        when(contracts.approved(RELEASE, v2, REVIEWER)).thenReturn(new ContractPersistenceService.ApprovedContract(
                new Version(v2, WORKSPACE, RELEASE, "policy", 2, "APPROVED", json.createObjectNode(), hash(22),
                        hash(23), POLICY_HASH, json.createObjectNode(), version.review), HASH,
                fingerprints.releaseFingerprint(HASH, hash(22))));
        assertThat(contracts.approved(RELEASE, v2, REVIEWER).releaseFingerprint()).isNotEqualTo(replay.fingerprint);
        clearInvocations(contracts);
        assertThat(compare().comparison().comparable()).isTrue();
        assertThat(evaluatedFacts().get(1).contractVersionId()).isEqualTo(VERSION);
        verify(contracts).find(VERSION, REVIEWER);
        verify(contracts, never()).approved(any(), any(), any());
        verify(contracts, never()).find(eq(v2), any());
    }

    @Test
    void consumesEveryPageIncludingNonemptyLastAndIgnoresOtherCaseModel() {
        histories.get(BASE_RUN).set(0, event(BASE_RUN, id(40), 1, ExecutionEventType.MODEL_RESPONSE,
                json.createObjectNode().put("provider", "different-case").put("model", "irrelevant")));
        pages = (run, after) -> after == 0
                ? new ExecutionEventDto.History(histories.get(run).subList(0, 2), 3, 2L)
                : new ExecutionEventDto.History(histories.get(run).subList(2, 3), 3, null);
        assertThat(compare().comparison().comparable()).isTrue();
        evaluatedFacts();
        for (UUID run : List.of(BASE_RUN, REPLAY_RUN)) {
            verify(events).history(eq(run), eq(0L), anyInt());
            verify(events).history(eq(run), eq(2L), anyInt());
            verify(events).verifyChain(run);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"null-baseline", "null-replay", "same", "null-reviewer"})
    void invalidInvocationStopsBeforeOwners(String scenario) {
        UUID base = scenario.equals("null-baseline") ? null : BASE_CASE;
        UUID replayId = scenario.equals("null-replay") ? null : scenario.equals("same") ? BASE_CASE : REPLAY_CASE;
        assertSafeException(catchThrowableOfType(() -> source.compare(base, replayId,
                        scenario.equals("null-reviewer") ? null : REVIEWER), ReplaySourceException.class),
                FailureCode.INVALID_REQUEST);
        verifyNoInteractions(runs, cases, contracts, events, audits, controls, comparator);
    }

    @ParameterizedTest
    @ValueSource(strings = {"no-actual", "writable", "read-committed", "default"})
    void incompatibleMetadataStopsBeforeOwners(String scenario) {
        switch (scenario) {
            case "no-actual" -> TransactionSynchronizationManager.setActualTransactionActive(false);
            case "writable" -> TransactionSynchronizationManager.setCurrentTransactionReadOnly(false);
            case "read-committed" -> TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(2);
            case "default" -> TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(null);
        }
        failure(FailureCode.UNSAFE_TRANSACTION);
        verifyNoInteractions(runs, cases, contracts, events, audits, controls);
    }

    @Test
    void preservesAAuthenticationFailureBeforeBaselineAuditEventOrControls() {
        ReviewerContext foreign = new ReviewerContext(id(99), "foreign", "AI_SECURITY_REVIEWER", PRIVATE, true, true, false);
        BusinessException denied = new BusinessException(ErrorCode.OPERATOR_AUTH_REQUIRED, "Reviewer authentication required");
        when(contracts.find(VERSION, foreign)).thenThrow(denied);
        assertThatThrownBy(() -> source.compare(BASE_CASE, REPLAY_CASE, foreign)).isSameAs(denied);
        verify(cases, never()).findCase(BASE_CASE);
        verify(runs, never()).find(BASE_RUN);
        verifyNoInteractions(audits, events, controls, comparator);
    }

    @ParameterizedTest
    @ValueSource(strings = {"case-id", "case-run", "run-id", "version-id", "version-release", "workspace",
            "baseline-case-id", "baseline-run-id", "baseline-release", "baseline-fingerprint", "replay-fingerprint",
            "null-case", "null-run", "null-version"})
    void rejectsStoredIdentityAndFingerprintMismatchBeforeEvidence(String scenario) {
        switch (scenario) {
            case "case-id" -> replayCase.id = id(90);
            case "case-run" -> replayCase.runId = id(90);
            case "run-id" -> replay.id = id(90);
            case "version-id" -> version.id = id(90);
            case "version-release" -> version.releaseId = id(90);
            case "workspace" -> version.workspaceId = id(90);
            case "baseline-case-id" -> baseCase.id = id(90);
            case "baseline-run-id" -> baseline.id = id(90);
            case "baseline-release" -> baseline.releaseId = id(90);
            case "baseline-fingerprint" -> baseline.fingerprint = fingerprints.releaseFingerprint(HASH, POLICY_HASH);
            case "replay-fingerprint" -> replay.fingerprint = fingerprints.releaseFingerprint(HASH, null);
            case "null-case" -> when(cases.findCase(REPLAY_CASE)).thenReturn(null);
            case "null-run" -> when(runs.find(REPLAY_RUN)).thenReturn(null);
            case "null-version" -> when(contracts.find(VERSION, REVIEWER)).thenReturn(null);
        }
        failure(FailureCode.SOURCE_BINDING_INVALID);
        verifyNoInteractions(audits, events, controls);
    }

    @ParameterizedTest
    @ValueSource(strings = {"baseline-contract", "missing-replay-contract", "policy-hash", "resource-hash"})
    void policyReferenceMustBeKnownAndBound(String scenario) {
        switch (scenario) {
            case "baseline-contract" -> baseline.contractId = VERSION;
            case "missing-replay-contract" -> replay.contractId = null;
            case "policy-hash" -> version.policyHash = PRIVATE;
            case "resource-hash" -> version.resourceHash = PRIVATE;
        }
        failure(FailureCode.POLICY_EVIDENCE_INVALID);
        verifyNoInteractions(audits, events, controls);
    }

    @ParameterizedTest
    @ValueSource(strings = {"pairGroupId", "randomSeed", "caseCompletedAt", "namespaceId", "modelParametersDigest"})
    void boundMissingControlsRemainExactComparatorMismatches(String field) {
        RecordedCaseControls original = recorded.get(REPLAY_RUN);
        recorded.put(REPLAY_RUN, new RecordedCaseControls(REPLAY_RUN, REPLAY_CASE,
                field.equals("pairGroupId") ? null : original.pairGroupId(),
                field.equals("randomSeed") ? null : original.randomSeed(),
                field.equals("caseCompletedAt") ? null : original.caseCompletedAt(),
                field.equals("namespaceId") ? null : original.namespaceId(), original.initialStateDigest(),
                original.resolvedModelId(), field.equals("modelParametersDigest") ? null : original.modelParametersDigest(),
                original.runtimeTimeoutMaxStepsDigest(), original.toolSchemaDigest(), original.ragVersion(), original.ragConfigDigest()));
        var result = compare();
        assertThat(result.comparison().mismatches()).containsExactly(new Mismatch(
                field.equals("caseCompletedAt") ? MismatchCode.REPLAY_LIFECYCLE_INVALID : MismatchCode.REPLAY_REQUIRED_FACT_INVALID,
                "/replay/" + field));
        ReplayComparisonFacts facts = evaluatedFacts().get(1);
        Object missing = switch (field) {
            case "pairGroupId" -> facts.pairGroupId();
            case "randomSeed" -> facts.randomSeed();
            case "caseCompletedAt" -> facts.caseCompletedAt();
            case "namespaceId" -> facts.namespaceId();
            default -> facts.modelParametersDigest();
        };
        assertThat(missing).isNull();
        assertSafeResult(result);
    }

    @ParameterizedTest
    @ValueSource(strings = {"run", "case", "namespace"})
    void rejectsNonNullControlsBoundToDifferentExecution(String field) {
        RecordedCaseControls old = recorded.get(REPLAY_RUN);
        recorded.put(REPLAY_RUN, new RecordedCaseControls(field.equals("run") ? BASE_RUN : REPLAY_RUN,
                field.equals("case") ? BASE_CASE : REPLAY_CASE, old.pairGroupId(), old.randomSeed(), old.caseCompletedAt(),
                field.equals("namespace") ? BASE_RUN : REPLAY_RUN, old.initialStateDigest(), old.resolvedModelId(),
                old.modelParametersDigest(), old.runtimeTimeoutMaxStepsDigest(), old.toolSchemaDigest(), old.ragVersion(), old.ragConfigDigest()));
        failure(FailureCode.CONTROL_BINDING_INVALID);
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "runtime", "business"})
    void missingOrThrowingUntrustedControlsNeverBecomeFacts(String scenario) {
        if (scenario.equals("null")) recorded.put(REPLAY_RUN, null);
        else when(controls.caseControls(REPLAY_RUN, REPLAY_CASE)).thenThrow(scenario.equals("business")
                ? new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, PRIVATE) : new IllegalStateException(PRIVATE));
        failure(FailureCode.CONTROL_SOURCE_UNAVAILABLE);
    }

    @ParameterizedTest
    @ValueSource(strings = {"CANDIDATE", "VALIDATED", "REJECTED", "SUPERSEDED"})
    void knownVersionStatesPreserveFalseOrUnknownApproval(String state) {
        version.state = state;
        var result = compare();
        assertThat(result.comparison().mismatches()).containsExactly(new Mismatch(
                MismatchCode.REPLAY_POLICY_BINDING_INVALID, "/replay/contractApproved"));
        assertThat(evaluatedFacts().get(1).contractApproved()).isEqualTo(state.equals("SUPERSEDED") ? null : Boolean.FALSE);
        verifyNoInteractions(audits);
    }

    @ParameterizedTest
    @ValueSource(strings = {"null-state", "unknown-state", "null-review", "scalar-review", "decision", "missing-actor", "blank-actor", "numeric-actor"})
    void malformedApprovedVersionCannotUseAuditToRepairItsReview(String scenario) {
        switch (scenario) {
            case "null-state" -> version.state = null;
            case "unknown-state" -> version.state = PRIVATE;
            case "null-review" -> version.review = null;
            case "scalar-review" -> version.review = StringNode.valueOf(PRIVATE);
            case "decision" -> ((ObjectNode) version.review).put("decision", "REJECTED");
            case "missing-actor" -> ((ObjectNode) version.review).remove("actorId");
            case "blank-actor" -> ((ObjectNode) version.review).put("actorId", " ");
            case "numeric-actor" -> ((ObjectNode) version.review).put("actorId", 7);
        }
        failure(FailureCode.POLICY_EVIDENCE_INVALID);
    }

    @ParameterizedTest
    @ValueSource(strings = {"before", "equal", "after", "null-time", "null-start", "empty", "bounded-unrelated"})
    void usesOnlyBoundedRecordedOrderApprovalEvidence(String scenario) {
        switch (scenario) {
            case "before" -> approvalRecords = List.of(approval(START.minusNanos(1)));
            case "equal" -> approvalRecords = List.of(approval(START));
            case "after" -> approvalRecords = List.of(approval(START.plusNanos(1)));
            case "null-time" -> approvalRecords = List.of(approval(null));
            case "null-start" -> replay.startedAt = null;
            case "empty" -> approvalRecords = List.of();
            case "bounded-unrelated" -> approvalRecords = IntStream.range(0, 100).mapToObj(index ->
                    new AuditDto.Record(id(1000 + index), WORKSPACE, HISTORICAL_ACTOR, "CONTRACT_VALIDATED",
                            "CONTRACT_VERSION", VERSION, null, HASH, json.createObjectNode(), START)).toList();
        }
        var result = compare();
        boolean proved = scenario.equals("before") || scenario.equals("equal");
        assertThat(evaluatedFacts().get(1).contractApproved()).isEqualTo(proved ? Boolean.TRUE : null);
        assertThat(result.comparison().mismatches()).containsExactlyElementsOf(proved ? List.of() : List.of(
                new Mismatch(MismatchCode.REPLAY_POLICY_BINDING_INVALID, "/replay/contractApproved")));
        verify(audits).find("CONTRACT_VERSION", VERSION, 100);
    }

    @ParameterizedTest
    @ValueSource(strings = {"workspace", "type", "version", "actor", "digest", "metadata", "state", "policyHash",
            "duplicate", "conflicting-second", "null-record", "null-list"})
    void rejectsEachObservedApprovalBindingConflict(String scenario) {
        AuditDto.Record a = approval(START.minusSeconds(1));
        JsonNode metadata = a.metadata().deepCopy();
        if (scenario.equals("metadata")) metadata = StringNode.valueOf(PRIVATE);
        if (scenario.equals("state")) ((ObjectNode) metadata).put("state", "VALIDATED");
        if (scenario.equals("policyHash")) ((ObjectNode) metadata).put("policyHash", hash(90));
        AuditDto.Record changed = new AuditDto.Record(a.id(), scenario.equals("workspace") ? id(90) : a.workspaceId(),
                scenario.equals("actor") ? "wrong-actor" : a.actorId(), a.action(),
                scenario.equals("type") ? "RELEASE" : a.resourceType(), scenario.equals("version") ? id(90) : a.resourceId(),
                a.beforeDigest(), scenario.equals("digest") ? hash(90) : a.afterDigest(), metadata, a.occurredAt());
        approvalRecords = switch (scenario) {
            case "duplicate" -> List.of(a, a);
            case "conflicting-second" -> List.of(a, new AuditDto.Record(id(91), WORKSPACE, "wrong", "CONTRACT_APPROVED",
                    "CONTRACT_VERSION", VERSION, null, RESOURCE_HASH, a.metadata(), START.minusSeconds(2)));
            case "null-record" -> Arrays.asList((AuditDto.Record) null);
            case "null-list" -> null;
            default -> List.of(changed);
        };
        failure(FailureCode.POLICY_EVIDENCE_INVALID);
    }

    @Test
    void unrelatedAuditActionIsNotApprovalAndStillRequiresSourceBinding() {
        AuditDto.Record a = approval(START);
        approvalRecords = List.of(new AuditDto.Record(a.id(), WORKSPACE, HISTORICAL_ACTOR, "CONTRACT_CREATED",
                "CONTRACT_VERSION", id(90), null, RESOURCE_HASH, a.metadata(), START));
        failure(FailureCode.POLICY_EVIDENCE_INVALID);
    }

    @ParameterizedTest
    @ValueSource(strings = {"gap", "duplicate", "reverse", "wrong-run", "stalled-cursor", "wrong-cursor", "early-end",
            "head", "hash", "prev-hash", "empty", "null-page", "null-items", "null-event", "second-page-head"})
    void rejectsIncompleteOrInconsistentHistoryEvenWhenOwnerChainSaysValid(String scenario) {
        List<ExecutionEventDto.Event> original = histories.get(REPLAY_RUN);
        ExecutionEventDto.History bad = switch (scenario) {
            case "gap" -> new ExecutionEventDto.History(List.of(original.get(0), original.get(2)), 3, null);
            case "duplicate" -> new ExecutionEventDto.History(List.of(original.get(0), original.get(0), original.get(2)), 3, null);
            case "reverse" -> new ExecutionEventDto.History(List.of(original.get(1), original.get(0), original.get(2)), 3, null);
            case "wrong-run" -> new ExecutionEventDto.History(List.of(event(BASE_RUN, REPLAY_CASE, 1,
                    ExecutionEventType.MODEL_RESPONSE, model()), original.get(1), original.get(2)), 3, null);
            case "stalled-cursor" -> new ExecutionEventDto.History(original.subList(0, 2), 3, 0L);
            case "wrong-cursor" -> new ExecutionEventDto.History(original.subList(0, 2), 3, 1L);
            case "early-end" -> new ExecutionEventDto.History(original.subList(0, 2), 3, null);
            case "head" -> new ExecutionEventDto.History(original, 4, null);
            case "hash" -> new ExecutionEventDto.History(List.of(original.get(0), original.get(1),
                    withEventHash(original.get(2), hash(90))), 3, null);
            case "prev-hash" -> new ExecutionEventDto.History(List.of(withEventHash(original.get(0), hash(90)),
                    original.get(1), original.get(2)), 3, null);
            case "second-page-head" -> new ExecutionEventDto.History(original.subList(2, 3), 4, null);
            case "empty" -> new ExecutionEventDto.History(List.of(), 3, null);
            case "null-page" -> null;
            case "null-items" -> new ExecutionEventDto.History(null, 3, null);
            case "null-event" -> new ExecutionEventDto.History(Arrays.asList(original.get(0), null, original.get(2)), 3, null);
            default -> throw new AssertionError(scenario);
        };
        pages = (run, after) -> !run.equals(REPLAY_RUN) ? new ExecutionEventDto.History(histories.get(run), 3, null)
                : scenario.equals("second-page-head") && after == 0
                        ? new ExecutionEventDto.History(original.subList(0, 2), 3, 2L) : bad;
        failure(FailureCode.MODEL_HISTORY_INVALID);
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "wrong-run", "invalid", "invalid-sequence", "count", "head-hash"})
    void chainVerificationMustAgreeWithStoredProjection(String scenario) {
        chains.put(REPLAY_RUN, scenario.equals("null") ? null : new ExecutionEventDto.ChainVerification(
                scenario.equals("wrong-run") ? BASE_RUN : REPLAY_RUN, !scenario.equals("invalid"),
                scenario.equals("count") ? 2 : 3, scenario.equals("invalid-sequence") ? 2L : null,
                scenario.equals("head-hash") ? hash(90) : hash(103)));
        failure(FailureCode.MODEL_HISTORY_INVALID);
    }

    @ParameterizedTest
    @ValueSource(strings = {"other-case-only", "null-output", "scalar-output", "missing-provider", "missing-model",
            "blank-provider", "blank-model", "numeric-model", "mixed-provider", "mixed-model"})
    void selectedCaseNeedsOneConsistentReportedModelPairAcrossAllTurns(String scenario) {
        JsonNode body = model();
        switch (scenario) {
            case "null-output" -> body = null;
            case "scalar-output" -> body = StringNode.valueOf(PRIVATE);
            case "missing-provider" -> ((ObjectNode) body).remove("provider");
            case "missing-model" -> ((ObjectNode) body).remove("model");
            case "blank-provider" -> ((ObjectNode) body).put("provider", " ");
            case "blank-model" -> ((ObjectNode) body).put("model", " ");
            case "numeric-model" -> ((ObjectNode) body).put("model", 1);
        }
        histories.get(REPLAY_RUN).set(1, event(REPLAY_RUN, scenario.equals("other-case-only") ? BASE_CASE : REPLAY_CASE,
                2, ExecutionEventType.MODEL_RESPONSE, body));
        if (scenario.startsWith("mixed")) {
            ObjectNode other = model();
            other.put(scenario.equals("mixed-provider") ? "provider" : "model", "another-turn");
            histories.get(REPLAY_RUN).set(2, event(REPLAY_RUN, REPLAY_CASE, 3, ExecutionEventType.MODEL_RESPONSE, other));
        }
        failure(FailureCode.MODEL_HISTORY_INVALID);
    }

    @Test
    void preservesARetentionErrorBeforeInvalidChainOfStreamStartingAtSequenceTwo() {
        // Actual A combination after sequence 1 is no longer retained: the chain is invalid,
        // while the initial exclusive-cursor history read supplies the authoritative retention error.
        histories.put(REPLAY_RUN, List.copyOf(histories.get(REPLAY_RUN).subList(1, 3)));
        chains.put(REPLAY_RUN, new ExecutionEventDto.ChainVerification(REPLAY_RUN, false, 2, 2L, null));
        BusinessException expired = new BusinessException(ErrorCode.STREAM_CURSOR_EXPIRED, "Event history has expired");
        when(events.history(REPLAY_RUN, 0, 1000)).thenThrow(expired);
        assertThatThrownBy(this::compare).isSameAs(expired);
        verify(events).history(REPLAY_RUN, 0, 1000);
        verify(events, never()).verifyChain(REPLAY_RUN);
        verifyNoInteractions(controls, comparator);
    }

    @ParameterizedTest
    @ValueSource(strings = {"owner", "comparator"})
    void unexpectedDependencyDetailsStayOutOfExceptionAndLogs(String stage) {
        IllegalStateException privateError = new IllegalStateException(PRIVATE, new RuntimeException(PRIVATE));
        privateError.addSuppressed(new RuntimeException(PRIVATE));
        if (stage.equals("owner")) when(runs.find(REPLAY_RUN)).thenThrow(privateError);
        else doThrow(privateError).when(comparator).evaluate(any(), any());
        ReplaySourceException error = catchThrowableOfType(this::compare, ReplaySourceException.class);
        assertSafeException(error, FailureCode.PROCESSING_FAILURE);
        verify(comparator, times(stage.equals("owner") ? 0 : 1)).evaluate(any(), any());
    }

    @Test
    void returnedAssessmentDoesNotExposeMutableOwnerJsonOrRecordedControls() {
        StoredReplayAssessment result = compare();
        String before = result.toString();
        ((ObjectNode) version.review).put("actorId", PRIVATE);
        version.policy.put("secret", "changed");
        ((ObjectNode) histories.get(REPLAY_RUN).get(1).output()).put("model", PRIVATE);
        recorded.clear();
        assertThat(result.toString()).isEqualTo(before);
        assertThatThrownBy(() -> result.comparison().mismatches().add(new Mismatch(
                MismatchCode.REPLAY_FACTS_MISSING, "/replay"))).isInstanceOf(UnsupportedOperationException.class);
        assertSafeResult(result);
        evaluatedFacts();
    }

    private StoredReplayAssessment compare() { return source.compare(BASE_CASE, REPLAY_CASE, REVIEWER); }

    private void failure(FailureCode expected) {
        assertSafeException(catchThrowableOfType(this::compare, ReplaySourceException.class), expected);
        verify(comparator, never()).evaluate(any(), any());
    }

    private void assertSafeException(ReplaySourceException error, FailureCode expected) {
        assertThat(error).isNotNull();
        assertThat(error.code()).isEqualTo(expected);
        assertThat(error.getMessage()).isEqualTo("Stored replay source unavailable: " + expected.name());
        assertThat(error.getCause()).isNull();
        error.addSuppressed(new IllegalStateException(PRIVATE));
        assertThat(error.getSuppressed()).isEmpty();
        StringWriter rendered = new StringWriter();
        error.printStackTrace(new PrintWriter(rendered));
        assertThat(rendered.toString()).doesNotContain(PRIVATE);
    }

    private void assertSafeResult(StoredReplayAssessment result) {
        assertThat(result.toString()).doesNotContain(PRIVATE, HISTORICAL_ACTOR, "reported-model", "resolved-model-snapshot");
        assertThat(json.writeValueAsString(result)).doesNotContain(PRIVATE, HISTORICAL_ACTOR, "reported-model", "resolved-model-snapshot");
    }

    private List<ReplayComparisonFacts> evaluatedFacts() {
        ArgumentCaptor<ReplayComparisonFacts> base = ArgumentCaptor.forClass(ReplayComparisonFacts.class);
        ArgumentCaptor<ReplayComparisonFacts> replayFacts = ArgumentCaptor.forClass(ReplayComparisonFacts.class);
        verify(comparator).evaluate(base.capture(), replayFacts.capture());
        return List.of(base.getValue(), replayFacts.getValue());
    }

    private ObjectNode model() { return json.createObjectNode().put("provider", "reported-provider").put("model", "reported-model").put("private", PRIVATE); }

    private AuditDto.Record approval(Instant when) {
        return new AuditDto.Record(id(10), WORKSPACE, HISTORICAL_ACTOR, "CONTRACT_APPROVED", "CONTRACT_VERSION",
                VERSION, HASH, RESOURCE_HASH, json.createObjectNode().put("state", "APPROVED").put("policyHash", POLICY_HASH), when);
    }

    private RecordedCaseControls recorded(UUID run, UUID caseRun) {
        return new RecordedCaseControls(run, caseRun, PAIR, 42L, END, run, hash(4), "resolved-model-snapshot",
                hash(5), hash(6), hash(7), "rag-v1", hash(8));
    }

    private ReplayComparisonFacts expectedFacts(UUID run, TestRunMode mode, UUID contractId, boolean approved) {
        return new ReplayComparisonFacts(RELEASE, run, hash(4), HASH, "reported-provider", "reported-model",
                "resolved-model-snapshot", hash(5), ATTACK, hash(11), 0, "fixture-v1", hash(12), 42L, PAIR,
                hash(6), hash(7), "rag-v1", hash(8), mode, TestRunStatus.COMPLETED, TestCaseRunStatus.PASSED,
                END, END, contractId, approved, approved ? POLICY_HASH : null,
                fingerprints.releaseFingerprint(HASH, approved ? POLICY_HASH : null));
    }

    private ExecutionEventDto.Event event(UUID run, UUID caseRun, long sequence, ExecutionEventType type, JsonNode body) {
        return new ExecutionEventDto.Event("1.0", id(100 + sequence), id(50), run, caseRun, sequence,
                START.plusSeconds(sequence), type, null, null, body, HASH, null, null,
                json.createObjectNode().put("private", PRIVATE), sequence == 1 ? null : hash(99 + sequence), hash(100 + sequence));
    }

    private ExecutionEventDto.Event withEventHash(ExecutionEventDto.Event e, String hash) {
        return new ExecutionEventDto.Event(e.schemaVersion(), e.eventId(), e.traceId(), e.runId(), e.testCaseRunId(), e.sequence(),
                e.occurredAt(), e.eventType(), e.toolName(), e.input(), e.output(), e.payloadDigest(), e.policyDecision(),
                e.reasonCode(), e.metadata(), e.prevEventHash(), hash);
    }

    private final class RunRow {
        private UUID id, releaseId = RELEASE, contractId;
        private final TestRunMode mode;
        private String fingerprint;
        private Instant startedAt = START;
        private RunRow(UUID id, UUID contractId, TestRunMode mode) {
            this.id = id; this.contractId = contractId; this.mode = mode;
            fingerprint = fingerprints.releaseFingerprint(HASH, contractId == null ? null : POLICY_HASH);
        }
        private TestRunDto.Projection build() {
            return new TestRunDto.Projection(id, releaseId, id(20), contractId, mode, TestRunStatus.COMPLETED, HASH,
                    fingerprint, "fixture-v1", hash(12), 1, 1, 0, 3, ExecutionEventType.RUN_COMPLETED, hash(103),
                    json.createObjectNode().put("private", PRIVATE), startedAt, END, START.minusSeconds(2));
        }
    }

    private final class CaseRow {
        private UUID id, runId;
        private CaseRow(UUID id, UUID runId) { this.id = id; this.runId = runId; }
        private TestRunPersistenceDto.CaseRun build() {
            return new TestRunPersistenceDto.CaseRun(id, runId, ATTACK, 0, TestCaseRunStatus.PASSED,
                    null, null, hash(11), null, null, null, json.createObjectNode().put("private", PRIVATE));
        }
    }

    private final class VersionRow {
        private UUID id = VERSION, workspaceId = WORKSPACE, releaseId = RELEASE;
        private String state = "APPROVED", policyHash = POLICY_HASH, resourceHash = RESOURCE_HASH;
        private final ObjectNode policy = json.createObjectNode().put("private", PRIVATE);
        private JsonNode review = json.createObjectNode().put("decision", "APPROVED").put("actorId", HISTORICAL_ACTOR).put("comment", PRIVATE);
        private Version build() {
            return new Version(id, workspaceId, releaseId, "historical-policy", 1, state, policy, policyHash,
                    resourceHash, null, json.createObjectNode(), review);
        }
    }

    private static UUID id(long value) { return new UUID(0, value); }
    private static String hash(long value) { return "sha256:" + String.format("%064x", value); }
}
