package com.finsecseal.replay.policy;

import com.finsecseal.audit.AuditDto;
import com.finsecseal.audit.AuditService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.evidence.TestRunDto.Projection;
import com.finsecseal.evidence.TestRunPersistenceDto.CaseRun;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.evidence.TestRunProjectionService;
import com.finsecseal.platform.contract.ContractPersistenceService;
import com.finsecseal.platform.contract.ContractPersistenceService.Version;
import com.finsecseal.release.FingerprintService;
import com.finsecseal.replay.policy.ReplayRecordedSource.RecordedCaseControls;
import java.sql.Connection;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.JsonNode;

/**
 * Composes stored comparison sources, without executing a Replay or granting runtime authority.
 * Deliberately not a production bean: an actual historical controls reader remains required.
 */
public class StoredReplayComparabilityService {
    private static final int HISTORY_PAGE_SIZE = 1000;
    private static final int AUDIT_LIMIT = 100;
    private final TestRunProjectionService runs;
    private final TestRunPersistenceService cases;
    private final ContractPersistenceService contracts;
    private final FingerprintService fingerprints;
    private final ExecutionEventService events;
    private final AuditService audits;
    private final ReplayRecordedSource recordedSource;
    private final ReplayComparabilityEvaluator comparator;

    public StoredReplayComparabilityService(TestRunProjectionService runs, TestRunPersistenceService cases,
            ContractPersistenceService contracts, FingerprintService fingerprints,
            ExecutionEventService events, AuditService audits, ReplayRecordedSource recordedSource,
            ReplayComparabilityEvaluator comparator) {
        this.runs = Objects.requireNonNull(runs);
        this.cases = Objects.requireNonNull(cases);
        this.contracts = Objects.requireNonNull(contracts);
        this.fingerprints = Objects.requireNonNull(fingerprints);
        this.events = Objects.requireNonNull(events);
        this.audits = Objects.requireNonNull(audits);
        this.recordedSource = Objects.requireNonNull(recordedSource);
        this.comparator = Objects.requireNonNull(comparator);
    }

    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public StoredReplayAssessment compare(UUID baselineCaseRunId, UUID replayCaseRunId,
            ReviewerContext reviewer) {
        requireSnapshotTransaction();
        if (baselineCaseRunId == null || replayCaseRunId == null || reviewer == null
                || baselineCaseRunId.equals(replayCaseRunId)) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
        try {
            CaseRun replayCase = readCase(replayCaseRunId);
            Projection replay = readRun(replayCase.testRunId());
            if (replay.contractVersionId() == null) throw failure(FailureCode.POLICY_EVIDENCE_INVALID);
            // A authenticates the current requester and verifies this historical version's hashes.
            // Current approved() / Release policy lookups would incorrectly replace historical v1.
            Version version = contracts.find(replay.contractVersionId(), reviewer);
            requireVersionBinding(version, replay, reviewer);

            // Authentication precedes all baseline, audit, event and recorded-control reads.
            CaseRun baselineCase = readCase(baselineCaseRunId);
            Projection baseline = readRun(baselineCase.testRunId());
            if (!baseline.releaseId().equals(replay.releaseId())) {
                throw failure(FailureCode.SOURCE_BINDING_INVALID);
            }
            if (baseline.contractVersionId() != null) throw failure(FailureCode.POLICY_EVIDENCE_INVALID);
            requireFingerprint(baseline, null);
            requireFingerprint(replay, version.policyHash());
            Boolean approved = historicalApproval(version, replay);
            ModelPair baselineModel = readModelHistory(baseline, baselineCaseRunId);
            ModelPair replayModel = readModelHistory(replay, replayCaseRunId);
            RecordedCaseControls baselineControls = readControls(baseline.id(), baselineCaseRunId);
            RecordedCaseControls replayControls = readControls(replay.id(), replayCaseRunId);
            ReplayComparisonFacts baselineFacts = facts(baseline, baselineCase, baselineControls,
                    baselineModel, false, null);
            ReplayComparisonFacts replayFacts = facts(replay, replayCase, replayControls,
                    replayModel, approved, version.policyHash());
            ReplayComparabilityResult comparison = Objects.requireNonNull(comparator.evaluate(baselineFacts, replayFacts));
            return new StoredReplayAssessment(baseline.id(), baselineCaseRunId, replay.id(), replayCaseRunId,
                    version.id(), version.policyHash(), comparison);
        } catch (ReplaySourceException | BusinessException exception) {
            // Retain A's safe authorization/not-found/retention error contract.
            throw exception;
        } catch (RuntimeException exception) {
            throw failure(FailureCode.PROCESSING_FAILURE);
        }
    }

    private CaseRun readCase(UUID id) {
        CaseRun value = cases.findCase(id);
        if (value == null || !id.equals(value.id()) || value.testRunId() == null || value.testCaseId() == null) {
            throw failure(FailureCode.SOURCE_BINDING_INVALID);
        }
        return value;
    }

    private Projection readRun(UUID id) {
        Projection value = runs.find(id);
        if (value == null || !id.equals(value.id()) || value.releaseId() == null) {
            throw failure(FailureCode.SOURCE_BINDING_INVALID);
        }
        return value;
    }

    private static void requireVersionBinding(Version version, Projection replay, ReviewerContext reviewer) {
        if (version == null || !replay.contractVersionId().equals(version.id())
                || !replay.releaseId().equals(version.releaseId()) || version.workspaceId() == null
                || !version.workspaceId().equals(reviewer.workspaceId())) {
            throw failure(FailureCode.SOURCE_BINDING_INVALID);
        }
        if (!hash(version.policyHash()) || !hash(version.resourceHash())) {
            throw failure(FailureCode.POLICY_EVIDENCE_INVALID);
        }
    }

    private void requireFingerprint(Projection run, String policyHash) {
        if (!hash(run.agentArtifactFingerprint()) || !hash(run.releaseFingerprint())
                || !run.releaseFingerprint().equals(
                        fingerprints.releaseFingerprint(run.agentArtifactFingerprint(), policyHash))) {
            throw failure(FailureCode.SOURCE_BINDING_INVALID);
        }
    }

    /** Limited persisted-order evidence, not DB approved_at, commit time or clock attestation. */
    private Boolean historicalApproval(Version version, Projection replay) {
        String state = version.state();
        if (state == null) throw failure(FailureCode.POLICY_EVIDENCE_INVALID);
        switch (state) {
            case "CANDIDATE", "VALIDATED", "REJECTED": return false;
            case "SUPERSEDED": return null;
            case "APPROVED": break;
            default: throw failure(FailureCode.POLICY_EVIDENCE_INVALID);
        }
        JsonNode review = version.review();
        if (review == null || !review.isObject() || !textEquals(review.path("decision"), "APPROVED")
                || !nonblankText(review.path("actorId"))) {
            throw failure(FailureCode.POLICY_EVIDENCE_INVALID);
        }
        String approvingActor = review.path("actorId").stringValue();
        List<AuditDto.Record> records = audits.find("CONTRACT_VERSION", version.id(), AUDIT_LIMIT);
        if (records == null || records.size() > AUDIT_LIMIT) throw failure(FailureCode.POLICY_EVIDENCE_INVALID);
        AuditDto.Record approval = null;
        for (AuditDto.Record record : records) {
            if (record == null || record.id() == null || !version.workspaceId().equals(record.workspaceId())
                    || !"CONTRACT_VERSION".equals(record.resourceType()) || !version.id().equals(record.resourceId())
                    || record.action() == null || record.action().isBlank()) {
                throw failure(FailureCode.POLICY_EVIDENCE_INVALID);
            }
            if (!"CONTRACT_APPROVED".equals(record.action())) continue;
            JsonNode metadata = record.metadata();
            if (approval != null || !approvingActor.equals(record.actorId())
                    || !version.resourceHash().equals(record.afterDigest()) || metadata == null || !metadata.isObject()
                    || !textEquals(metadata.path("state"), "APPROVED")
                    || !textEquals(metadata.path("policyHash"), version.policyHash())) {
                throw failure(FailureCode.POLICY_EVIDENCE_INVALID);
            }
            approval = record;
        }
        // A bounded positive read cannot prove absence; late/null timestamps never become false proof.
        if (approval == null || approval.occurredAt() == null || replay.startedAt() == null) return null;
        return approval.occurredAt().isAfter(replay.startedAt()) ? null : Boolean.TRUE;
    }

    private ModelPair readModelHistory(Projection run, UUID caseRunId) {
        // A's retention error must precede the chain rejection of the same retained suffix.
        ExecutionEventDto.History page = events.history(run.id(), 0, HISTORY_PAGE_SIZE);
        ExecutionEventDto.ChainVerification chain = events.verifyChain(run.id());
        if (chain == null || !run.id().equals(chain.runId()) || !chain.valid()
                || chain.firstInvalidSequence() != null || chain.eventCount() <= 0
                || chain.eventCount() != run.latestSequence() || !hash(chain.headHash())
                || !chain.headHash().equals(run.eventHeadHash())) {
            throw failure(FailureCode.MODEL_HISTORY_INVALID);
        }
        long after = 0;
        String previousHash = null;
        ModelPair selected = null;
        while (true) {
            if (page == null || page.items() == null || page.items().isEmpty()
                    || page.items().size() > HISTORY_PAGE_SIZE || page.headSequence() != chain.eventCount()) {
                throw failure(FailureCode.MODEL_HISTORY_INVALID);
            }
            long sequence = after;
            for (ExecutionEventDto.Event event : page.items()) {
                if (event == null || event.eventId() == null || !run.id().equals(event.runId())
                        || event.eventType() == null || sequence == Long.MAX_VALUE
                        || event.sequence() != sequence + 1 || event.sequence() > chain.eventCount()
                        || !Objects.equals(previousHash, event.prevEventHash()) || !hash(event.eventHash())) {
                    throw failure(FailureCode.MODEL_HISTORY_INVALID);
                }
                sequence = event.sequence();
                previousHash = event.eventHash();
                if (event.eventType() == ExecutionEventType.MODEL_RESPONSE && caseRunId.equals(event.testCaseRunId())) {
                    JsonNode output = event.output();
                    if (output == null || !output.isObject() || !nonblankText(output.path("provider"))
                            || !nonblankText(output.path("model"))) {
                        throw failure(FailureCode.MODEL_HISTORY_INVALID);
                    }
                    ModelPair pair = new ModelPair(output.path("provider").stringValue(), output.path("model").stringValue());
                    if (selected != null && !selected.equals(pair)) throw failure(FailureCode.MODEL_HISTORY_INVALID);
                    selected = pair;
                }
            }
            Long next = page.nextCursor();
            if (next == null) {
                if (sequence != chain.eventCount() || !chain.headHash().equals(previousHash) || selected == null) {
                    throw failure(FailureCode.MODEL_HISTORY_INVALID);
                }
                return selected;
            }
            if (next <= after || next != sequence || next >= chain.eventCount()) {
                throw failure(FailureCode.MODEL_HISTORY_INVALID);
            }
            after = next;
            page = events.history(run.id(), after, HISTORY_PAGE_SIZE);
        }
    }

    private RecordedCaseControls readControls(UUID runId, UUID caseRunId) {
        RecordedCaseControls controls;
        try {
            controls = recordedSource.caseControls(runId, caseRunId);
        } catch (RuntimeException exception) {
            // The external owner port does not get to inject raw BusinessException messages either.
            throw failure(FailureCode.CONTROL_SOURCE_UNAVAILABLE);
        }
        if (controls == null) throw failure(FailureCode.CONTROL_SOURCE_UNAVAILABLE);
        if (!runId.equals(controls.runId()) || !caseRunId.equals(controls.testCaseRunId())
                || (controls.namespaceId() != null && !runId.equals(controls.namespaceId()))) {
            throw failure(FailureCode.CONTROL_BINDING_INVALID);
        }
        return controls;
    }

    private static ReplayComparisonFacts facts(Projection run, CaseRun caseRun, RecordedCaseControls controls,
            ModelPair model, Boolean approved, String policyHash) {
        return new ReplayComparisonFacts(run.releaseId(), controls.namespaceId(), controls.initialStateDigest(),
                run.agentArtifactFingerprint(), model.provider(), model.model(), controls.resolvedModelId(),
                controls.modelParametersDigest(), caseRun.testCaseId(), caseRun.variantHash(), caseRun.trialIndex(),
                run.fixtureVersion(), run.fixtureDigest(), controls.randomSeed(), controls.pairGroupId(),
                controls.runtimeTimeoutMaxStepsDigest(), controls.toolSchemaDigest(), controls.ragVersion(),
                controls.ragConfigDigest(), run.mode(), run.status(), caseRun.status(), run.completedAt(),
                controls.caseCompletedAt(), run.contractVersionId(), approved, policyHash, run.releaseFingerprint());
    }

    private static boolean nonblankText(JsonNode value) { return value.isString() && !value.stringValue().isBlank(); }
    private static boolean textEquals(JsonNode value, String expected) { return value.isString() && expected.equals(value.stringValue()); }
    private static boolean hash(String value) { return value != null && value.matches("sha256:[0-9a-f]{64}"); }

    private static void requireSnapshotTransaction() {
        if (!TransactionSynchronizationManager.isActualTransactionActive()
                || !TransactionSynchronizationManager.isCurrentTransactionReadOnly()
                || !Objects.equals(TransactionSynchronizationManager.getCurrentTransactionIsolationLevel(),
                        Connection.TRANSACTION_REPEATABLE_READ)) {
            throw failure(FailureCode.UNSAFE_TRANSACTION);
        }
    }

    private record ModelPair(String provider, String model) {}

    public record StoredReplayAssessment(UUID baselineRunId, UUID baselineCaseRunId, UUID replayRunId,
            UUID replayCaseRunId, UUID replayContractVersionId, String replayPolicyHash,
            ReplayComparabilityResult comparison) {
        public StoredReplayAssessment {
            Objects.requireNonNull(baselineRunId);
            Objects.requireNonNull(baselineCaseRunId);
            Objects.requireNonNull(replayRunId);
            Objects.requireNonNull(replayCaseRunId);
            Objects.requireNonNull(replayContractVersionId);
            Objects.requireNonNull(replayPolicyHash);
            Objects.requireNonNull(comparison);
        }
    }

    public enum FailureCode {
        INVALID_REQUEST,
        UNSAFE_TRANSACTION,
        SOURCE_BINDING_INVALID,
        POLICY_EVIDENCE_INVALID,
        MODEL_HISTORY_INVALID,
        CONTROL_SOURCE_UNAVAILABLE,
        CONTROL_BINDING_INVALID,
        PROCESSING_FAILURE
    }

    public static final class ReplaySourceException extends RuntimeException {
        private final FailureCode code;

        private ReplaySourceException(FailureCode code) {
            super("Stored replay source unavailable: " + code.name(), null, false, true);
            this.code = code;
        }

        public FailureCode code() { return code; }
    }

    private static ReplaySourceException failure(FailureCode code) { return new ReplaySourceException(code); }
}
