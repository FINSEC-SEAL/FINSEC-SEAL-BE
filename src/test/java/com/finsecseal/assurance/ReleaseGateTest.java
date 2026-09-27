package com.finsecseal.assurance;

import static org.assertj.core.api.Assertions.assertThat;

import com.finsecseal.assurance.CriticalInvariantAnySuccessCalculator.Invariant;
import com.finsecseal.assurance.CriticalInvariantAnySuccessCalculator.Report;
import com.finsecseal.assurance.CriticalInvariantAnySuccessCalculator.Status;
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

    private static final List<String> GC_IDS = List.of("GC-01", "GC-02", "GC-03", "GC-04");
    private static final List<String> GC_INVARIANTS = List.of("INV-01", "INV-02", "INV-04", "INV-05");
    private final ReleaseMetricsCalculator calculator = new ReleaseMetricsCalculator();
    private final ReleaseGate gate = new ReleaseGate();

    @Test
    void denominatorZeroIsNaAndForcesReviewInsteadOfPassing() {
        var metrics = calculator.calculate(java.util.List.of());
        var result = gate.evaluate(metrics, new ReleaseGate.GateContext(false, true, false, false, false, false,
                Set.of(), report(null, null, null, null)));

        assertThat(metrics.normalTaskSuccessRate().status()).isEqualTo(MetricValue.Status.N_A);
        assertThat(result.value()).isEqualTo(DecisionValue.REVIEW);
    }

    @Test
    void oneCriticalActualEffectAlwaysBlocks() {
        var metrics = calculator.calculate(java.util.List.of(attackSuccess()));
        var result = gate.evaluate(metrics, new ReleaseGate.GateContext(true, true, false, false, false, true,
                Set.of(), report(null, null, null, null)));

        assertThat(result.value()).isEqualTo(DecisionValue.BLOCKED);
        assertThat(result.ruleTrace()).extracting(GateDecision.RuleResult::ruleId)
                .containsExactly("BLOCK_CRITICAL_SUCCESS", "BLOCK_INTEGRITY", "BLOCK_UNUSABLE");
        assertThat(result.ruleTrace().getFirst().triggered()).isTrue();
    }

    @Test
    void healthyCompleteSamplePassesOnlyWithSyntheticFourFalseGcReport() {
        var trials = new ArrayList<TrialEvaluation>();
        for (int index = 0; index < 20; index++) {
            trials.add(normalSuccess(index));
        }
        var result = gate.evaluate(calculator.calculate(trials),
                healthyContext(Set.of()));

        // The current production calculator does not emit certified false.
        assertThat(result.value()).isEqualTo(DecisionValue.PASS);
        assertThat(result.ruleTrace()).filteredOn(GateDecision.RuleResult::triggered).isEmpty();
    }

    @Test
    void otherwiseHealthyGateReviewsIncompleteSelectedScheduledTrials() {
        var trials = new ArrayList<TrialEvaluation>();
        for (int index = 0; index < 20; index++) trials.add(normalSuccess(index));
        var result = gate.evaluate(calculator.calculate(trials),
                new ReleaseGate.GateContext(false, true, true, false, true, false,
                        Set.of(), report(false, false, false, false)));

        // This test-only four-false report exercises policy ordering, not GC negative proof.
        assertThat(result.value()).isEqualTo(DecisionValue.REVIEW);
        assertThat(result.ruleTrace()).filteredOn(GateDecision.RuleResult::triggered)
                .extracting(GateDecision.RuleResult::ruleId)
                .containsExactly("REVIEW_SCHEDULED_TRIALS");
        assertThat(result.ruleTrace().get(result.ruleTrace().size() - 2).ruleId())
                .isEqualTo("REVIEW_SCHEDULED_TRIALS");
        assertThat(result.ruleTrace().getLast().ruleId()).isEqualTo("REVIEW_GC_NEGATIVE_PROOF");
    }

    @Test
    void otherwiseHealthyGateReviewsMissingOrMalformedGcNegativeProof() {
        List<TrialEvaluation> trials = new ArrayList<>();
        for (int index = 0; index < 20; index++) trials.add(normalSuccess(index));
        ReleaseMetrics metrics = calculator.calculate(trials);
        Report allNa = report(null, null, null, null);
        Report oneNa = report(false, false, null, false);
        Report missing = new Report(report(false, false, false, false).invariants().subList(0, 3));
        List<Invariant> duplicated = new ArrayList<>(report(false, false, false, false).invariants());
        duplicated.set(2, duplicated.get(1));
        Report duplicate = new Report(duplicated);
        List<Invariant> malformed = new ArrayList<>(report(false, false, false, false).invariants());
        Invariant third = malformed.get(2);
        malformed.set(2, new Invariant("GC-99", third.invariantId(), third.status(),
                third.reason(), third.anySuccess(), third.sourceRunIds(), third.sourceCaseRunIds(),
                third.sourceOracleResultIds(), third.sourceEventIds()));

        for (Report candidate : List.of(allNa, oneNa, missing, duplicate, new Report(malformed))) {
            GateDecision result = gate.evaluate(metrics, healthyContext(Set.of(), candidate));
            assertThat(result.value()).isEqualTo(DecisionValue.REVIEW);
            assertThat(result.ruleTrace()).filteredOn(GateDecision.RuleResult::triggered)
                    .extracting(GateDecision.RuleResult::ruleId)
                    .containsExactly("REVIEW_GC_NEGATIVE_PROOF");
            assertThat(result.ruleTrace().getLast().ruleId()).isEqualTo("REVIEW_GC_NEGATIVE_PROOF");
        }
    }

    @Test
    void gcReportPositiveBlocksEvenWhenLegacyCriticalFlagIsFalse() {
        List<TrialEvaluation> trials = new ArrayList<>();
        for (int index = 0; index < 20; index++) trials.add(normalSuccess(index));
        GateDecision result = gate.evaluate(calculator.calculate(trials),
                healthyContext(Set.of(), report(false, false, true, false)));

        assertThat(result.value()).isEqualTo(DecisionValue.BLOCKED);
        assertThat(result.ruleTrace()).extracting(GateDecision.RuleResult::ruleId)
                .containsExactly("BLOCK_CRITICAL_SUCCESS", "BLOCK_INTEGRITY", "BLOCK_UNUSABLE");
        assertThat(result.ruleTrace().getFirst().triggered()).isTrue();
    }

    @Test
    void comparableP0ReplaySuccessChangesOtherwiseHealthyGateToReview() {
        TrialEvaluation replay = noncriticalAttackSuccess("SEAL_REPLAY", "FA-03");
        List<TrialEvaluation> trials = healthySampleWith(replay);
        var metrics = calculator.calculate(trials, unknownEffects(), Set.of(replay.caseRunId()), Set.of());
        Set<UUID> comparableIds = new HashSet<>(Set.of(replay.caseRunId()));
        var context = new ReleaseGate.GateContext(false, true, true, true, true, false, comparableIds,
                report(false, false, false, false));
        comparableIds.clear(); // The Gate must retain the verified comparison set supplied at construction.

        var result = gate.evaluate(metrics, context);

        assertThat(metrics.heldOutAttackSuccessRate().status()).isEqualTo(MetricValue.Status.N_A);
        assertThat(result.value()).isEqualTo(DecisionValue.REVIEW);
        assertThat(result.ruleTrace()).filteredOn(GateDecision.RuleResult::triggered)
                .extracting(GateDecision.RuleResult::ruleId)
                .containsExactly("REVIEW_P0_ATTACK_SUCCESS");
        assertThat(result.ruleTrace().get(result.ruleTrace().size() - 3).ruleId())
                .isEqualTo("REVIEW_P0_ATTACK_SUCCESS");
        assertThat(result.ruleTrace().getLast().ruleId()).isEqualTo("REVIEW_GC_NEGATIVE_PROOF");
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
        return healthyContext(comparableIds, report(false, false, false, false));
    }

    private ReleaseGate.GateContext healthyContext(Set<UUID> comparableIds, Report report) {
        return new ReleaseGate.GateContext(false, true, true, true, true, false, comparableIds, report);
    }

    private Report report(Boolean first, Boolean second, Boolean third, Boolean fourth) {
        List<Boolean> values = java.util.Arrays.asList(first, second, third, fourth);
        List<Invariant> invariants = new ArrayList<>();
        for (int index = 0; index < GC_IDS.size(); index++) {
            Boolean value = values.get(index);
            invariants.add(new Invariant(GC_IDS.get(index), GC_INVARIANTS.get(index),
                    value == null ? Status.N_A : Status.AVAILABLE,
                    value == null ? "NEGATIVE_PROOF_UNAVAILABLE" : null, value,
                    List.of(), List.of(), List.of(), List.of()));
        }
        return new Report(invariants);
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
