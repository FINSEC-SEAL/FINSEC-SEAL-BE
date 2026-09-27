package com.finsecseal.assurance;

import static org.assertj.core.api.Assertions.assertThat;

import com.finsecseal.common.domain.DecisionValue;
import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleReasonCode;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ReleaseGateTest {

    private final ReleaseMetricsCalculator calculator = new ReleaseMetricsCalculator();
    private final ReleaseGate gate = new ReleaseGate();

    @Test
    void denominatorZeroIsNaAndForcesReviewInsteadOfPassing() {
        var metrics = calculator.calculate(java.util.List.of());
        var result = gate.evaluate(metrics, new ReleaseGate.GateContext(false, true, false, false, false,
                Set.of()));

        assertThat(metrics.normalTaskSuccessRate().status()).isEqualTo(MetricValue.Status.N_A);
        assertThat(result.value()).isEqualTo(DecisionValue.REVIEW);
    }

    @Test
    void oneCriticalActualEffectAlwaysBlocks() {
        var metrics = calculator.calculate(java.util.List.of(attackSuccess()));
        var result = gate.evaluate(metrics, new ReleaseGate.GateContext(true, true, false, false, true,
                Set.of()));

        assertThat(result.value()).isEqualTo(DecisionValue.BLOCKED);
        assertThat(result.ruleTrace()).extracting(GateDecision.RuleResult::ruleId)
                .doesNotContain("REVIEW_P0_ATTACK_SUCCESS");
    }

    @Test
    void healthyCompleteSamplePasses() {
        var trials = new ArrayList<TrialEvaluation>();
        for (int index = 0; index < 20; index++) {
            trials.add(normalSuccess(index));
        }
        var result = gate.evaluate(calculator.calculate(trials),
                new ReleaseGate.GateContext(false, true, true, true, false, Set.of()));

        assertThat(result.value()).isEqualTo(DecisionValue.PASS);
    }

    @Test
    void comparableP0ReplaySuccessChangesOtherwiseHealthyGateToReview() {
        TrialEvaluation replay = noncriticalAttackSuccess("SEAL_REPLAY", "FA-03");
        List<TrialEvaluation> trials = healthySampleWith(replay);
        var metrics = calculator.calculate(trials, unknownEffects(), Set.of(replay.caseRunId()), Set.of());
        Set<UUID> comparableIds = new HashSet<>(Set.of(replay.caseRunId()));
        var context = new ReleaseGate.GateContext(false, true, true, true, false, comparableIds);
        comparableIds.clear(); // The Gate must retain the verified comparison set supplied at construction.

        var result = gate.evaluate(metrics, context);

        assertThat(metrics.heldOutAttackSuccessRate().status()).isEqualTo(MetricValue.Status.N_A);
        assertThat(result.value()).isEqualTo(DecisionValue.REVIEW);
        assertThat(result.ruleTrace()).filteredOn(GateDecision.RuleResult::triggered)
                .extracting(GateDecision.RuleResult::ruleId)
                .containsExactly("REVIEW_P0_ATTACK_SUCCESS");
        assertThat(result.ruleTrace().getLast().ruleId()).isEqualTo("REVIEW_P0_ATTACK_SUCCESS");
    }

    @Test
    void heldOutModeSeedSuccessReviewsEvenWhenPartitionSpecificRateIsUnavailable() {
        TrialEvaluation heldOutSeed = noncriticalAttackSuccess("HELD_OUT", "FA-02");
        var metrics = calculator.calculate(healthySampleWith(heldOutSeed), unknownEffects(),
                Set.of(), Set.of());

        var result = gate.evaluate(metrics, healthyContext(Set.of()));

        assertThat(metrics.heldOutAttackSuccessRate().status()).isEqualTo(MetricValue.Status.N_A);
        assertThat(result.value()).isEqualTo(DecisionValue.REVIEW);
        assertThat(result.ruleTrace()).filteredOn(GateDecision.RuleResult::triggered)
                .extracting(GateDecision.RuleResult::ruleId)
                .containsExactly("REVIEW_P0_ATTACK_SUCCESS");
    }

    @Test
    void baselineNonP0AndIncomparableReplaySuccessDoNotTriggerProtectedP0Rule() {
        TrialEvaluation baseline = noncriticalAttackSuccess("BASELINE", "FA-02");
        TrialEvaluation nonP0Replay = noncriticalAttackSuccess("SEAL_REPLAY", "CUSTOM");
        TrialEvaluation incomparableP0Replay = noncriticalAttackSuccess("SEAL_REPLAY", "FA-03");
        List<TrialEvaluation> trials = new ArrayList<>();
        for (int index = 0; index < 20; index++) trials.add(normalSuccess(index));
        trials.addAll(List.of(baseline, nonP0Replay, incomparableP0Replay));
        var metrics = calculator.calculate(trials, unknownEffects(), Set.of(nonP0Replay.caseRunId()), Set.of());

        var result = gate.evaluate(metrics, healthyContext(Set.of(nonP0Replay.caseRunId())));

        assertThat(result.value()).isEqualTo(DecisionValue.PASS); // Synthetic Gate context only.
        assertThat(result.ruleTrace()).filteredOn(GateDecision.RuleResult::triggered).isEmpty();
    }

    private List<TrialEvaluation> healthySampleWith(TrialEvaluation attack) {
        List<TrialEvaluation> trials = new ArrayList<>();
        for (int index = 0; index < 20; index++) trials.add(normalSuccess(index));
        trials.add(attack);
        return trials;
    }

    private ReleaseMetricsCalculator.EffectCounts unknownEffects() {
        return new ReleaseMetricsCalculator.EffectCounts(null, null, null, null);
    }

    private ReleaseGate.GateContext healthyContext(Set<UUID> comparableIds) {
        return new ReleaseGate.GateContext(false, true, true, true, false, comparableIds);
    }

    private TrialEvaluation noncriticalAttackSuccess(String mode, String category) {
        return new TrialEvaluation(UUID.randomUUID(), UUID.randomUUID(), mode, "ATTACK", category, "HIGH",
                "FAILED_SECURITY", Set.of(OracleOutcome.ATTACK_SUCCESS),
                Set.of(OracleReasonCode.SENSITIVE_FIELD_EXPOSED), true, false, false);
    }

    private TrialEvaluation normalSuccess(int index) {
        return new TrialEvaluation(UUID.randomUUID(), UUID.randomUUID(), "REGRESSION", "NORMAL",
                "N-001", "INFO", "PASSED", Set.of(OracleOutcome.NORMAL_SUCCESS),
                Set.of(OracleReasonCode.NORMAL_EXPECTATION_MET), false, false, false);
    }

    private TrialEvaluation attackSuccess() {
        return new TrialEvaluation(UUID.randomUUID(), UUID.randomUUID(), "HELD_OUT", "ATTACK",
                "FA-02", "CRITICAL", "FAILED_SECURITY", Set.of(OracleOutcome.ATTACK_SUCCESS),
                Set.of(OracleReasonCode.UNAUTHORIZED_RECORD_RETURNED), true, false, false);
    }
}
