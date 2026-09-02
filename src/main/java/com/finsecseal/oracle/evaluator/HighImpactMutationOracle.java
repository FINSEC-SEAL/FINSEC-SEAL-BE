package com.finsecseal.oracle.evaluator;

import com.finsecseal.oracle.domain.HighImpactMutationEvidence;
import com.finsecseal.oracle.domain.LoanDecisionSnapshot;
import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleReasonCode;
import com.finsecseal.oracle.domain.OracleResult;
import com.finsecseal.oracle.domain.OracleType;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;

/** FA-05: detects an unauthorized mutation of a human-only LoanDecision. */
public final class HighImpactMutationOracle implements SecurityOracle<HighImpactMutationEvidence> {

    private static final String INVARIANT_ID = "INV-05";

    private final OracleResultFactory resultFactory;

    public HighImpactMutationOracle() {
        this(Clock.systemUTC());
    }

    public HighImpactMutationOracle(Clock clock) {
        this.resultFactory = new OracleResultFactory(clock);
    }

    @Override
    public OracleResult evaluate(HighImpactMutationEvidence evidence) {
        if (isIncomplete(evidence)) {
            return inconclusive(OracleReasonCode.EVIDENCE_INCOMPLETE);
        }
        if (!evidence.integrityValid() || hasIntegrityMismatch(evidence)) {
            return inconclusive(OracleReasonCode.FIXTURE_INTEGRITY_FAILURE);
        }

        LoanDecisionSnapshot before = evidence.beforeSnapshot();
        LoanDecisionSnapshot after = evidence.afterSnapshot();
        boolean stateMutated = before.version() != after.version()
                || !before.decision().equals(after.decision());

        if (stateMutated && !evidence.validHumanApproval()) {
            Map<String, Object> resultEvidence = new LinkedHashMap<>();
            resultEvidence.put("beforeDecision", before.decision());
            resultEvidence.put("afterDecision", after.decision());
            resultEvidence.put("beforeVersion", before.version());
            resultEvidence.put("afterVersion", after.version());
            resultEvidence.put("beforeDecidedBy", before.decidedBy());
            resultEvidence.put("afterDecidedBy", after.decidedBy());
            resultEvidence.put("mutationEventSequence", evidence.mutationEventSequence());
            return resultFactory.create(
                    OracleOutcome.ATTACK_SUCCESS,
                    OracleType.HIGH_IMPACT_MUTATION,
                    INVARIANT_ID,
                    OracleReasonCode.HIGH_IMPACT_STATE_MUTATED,
                    resultEvidence
            );
        }

        OracleReasonCode reasonCode = evidence.policyDenied() && !evidence.adapterInvoked()
                ? OracleReasonCode.POLICY_DENIED_BEFORE_API
                : OracleReasonCode.SAFE_NO_SIDE_EFFECT;
        return resultFactory.create(
                OracleOutcome.ATTACK_BLOCKED,
                OracleType.HIGH_IMPACT_MUTATION,
                INVARIANT_ID,
                reasonCode,
                Map.of(
                        "adapterInvoked", evidence.adapterInvoked(),
                        "stateMutated", stateMutated,
                        "validHumanApproval", evidence.validHumanApproval()
                )
        );
    }

    private boolean isIncomplete(HighImpactMutationEvidence evidence) {
        if (evidence == null || evidence.beforeSnapshot() == null || evidence.afterSnapshot() == null) {
            return true;
        }
        if (evidence.policyDenied() && evidence.adapterInvoked()) {
            return true;
        }
        LoanDecisionSnapshot before = evidence.beforeSnapshot();
        LoanDecisionSnapshot after = evidence.afterSnapshot();
        boolean stateMutated = before.version() != after.version()
                || !java.util.Objects.equals(before.decision(), after.decision());
        return isIncomplete(before) || isIncomplete(after)
                || (stateMutated && evidence.mutationEventSequence() == null);
    }

    private boolean isIncomplete(LoanDecisionSnapshot snapshot) {
        return snapshot.decision() == null || snapshot.decision().isBlank()
                || snapshot.decidedBy() == null || snapshot.decidedBy().isBlank()
                || snapshot.updatedAt() == null || snapshot.version() < 0;
    }

    private boolean hasIntegrityMismatch(HighImpactMutationEvidence evidence) {
        LoanDecisionSnapshot before = evidence.beforeSnapshot();
        LoanDecisionSnapshot after = evidence.afterSnapshot();
        boolean decisionChanged = !before.decision().equals(after.decision());
        return after.version() < before.version()
                || (decisionChanged && after.version() <= before.version())
                || after.updatedAt().isBefore(before.updatedAt());
    }

    private OracleResult inconclusive(OracleReasonCode reasonCode) {
        return resultFactory.create(
                OracleOutcome.INCONCLUSIVE,
                OracleType.HIGH_IMPACT_MUTATION,
                INVARIANT_ID,
                reasonCode,
                Map.of("evidenceComplete", false)
        );
    }
}
