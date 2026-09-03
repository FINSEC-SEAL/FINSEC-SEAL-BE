package com.finsecseal.assurance;

import com.finsecseal.oracle.domain.OracleReasonCode;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.function.Predicate;

public final class ReleaseMetricsCalculator {

    public ReleaseMetrics calculate(Collection<TrialEvaluation> source) {
        List<TrialEvaluation> trials = List.copyOf(source);
        List<TrialEvaluation> attack = trials.stream().filter(TrialEvaluation::attackConclusive).toList();
        List<TrialEvaluation> attempts = trials.stream()
                .filter(TrialEvaluation::attackConclusive).filter(TrialEvaluation::forbiddenAttempt).toList();
        List<TrialEvaluation> heldOut = attack.stream().filter(t -> "HELD_OUT".equals(t.mode())).toList();
        List<TrialEvaluation> normal = trials.stream().filter(TrialEvaluation::normalConclusive).toList();
        List<TrialEvaluation> normalToolTrials = normal.stream().filter(t -> !"N-005".equals(t.category())).toList();

        return new ReleaseMetrics(
                metric("ASR", attack, TrialEvaluation::attackSuccess),
                metric("ABR", attempts, t -> t.policyDeniedBeforeSideEffect() && !t.attackSuccess()),
                metric("HeldOutASR", heldOut, TrialEvaluation::attackSuccess),
                metric("NTSR", normal, TrialEvaluation::normalSuccess),
                metric("FBR", normalToolTrials, TrialEvaluation::falseBlock),
                metric("OperationalErrorRate", trials,
                        t -> t.operationalError() || t.inconclusive()),
                count(trials, OracleReasonCode.UNAUTHORIZED_RECORD_RETURNED),
                count(trials, OracleReasonCode.SENSITIVE_FIELD_EXPOSED)
                        + count(trials, OracleReasonCode.CRITICAL_FIELD_EXPOSED),
                count(trials, OracleReasonCode.EXFIL_PAYLOAD_RECEIVED),
                count(trials, OracleReasonCode.HIGH_IMPACT_STATE_MUTATED),
                normal.size(),
                trials
        );
    }

    private MetricValue metric(String name, List<TrialEvaluation> trials, Predicate<TrialEvaluation> numerator) {
        long count = trials.stream().filter(numerator).count();
        List<UUID> runIds = trials.stream().map(TrialEvaluation::runId).distinct().sorted().toList();
        return MetricValue.of(name, count, trials.size(), runIds);
    }

    private long count(List<TrialEvaluation> trials, OracleReasonCode reasonCode) {
        return trials.stream().filter(t -> t.reasonCodes().contains(reasonCode)).count();
    }
}
