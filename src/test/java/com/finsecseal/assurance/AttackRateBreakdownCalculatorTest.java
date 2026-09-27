package com.finsecseal.assurance;

import static org.assertj.core.api.Assertions.assertThat;

import com.finsecseal.oracle.domain.OracleOutcome;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AttackRateBreakdownCalculatorTest {

    private final TrialSuccessDistributionCalculator distributionCalculator =
            new TrialSuccessDistributionCalculator();
    private final AttackRateBreakdownCalculator calculator = new AttackRateBreakdownCalculator();

    @Test
    void groupsByModeCategoryAndPartitionWithAggregateAsrCounts() {
        UUID baselineRun = UUID.randomUUID();
        UUID heldOutRun = UUID.randomUUID();
        var seedSuccess = sample(baselineRun, UUID.randomUUID(), "BASELINE", "ATTACK",
                "FA-02", "SEED", 0, "FAILED_SECURITY", OracleOutcome.ATTACK_SUCCESS);
        var mutationBlocked = sample(baselineRun, UUID.randomUUID(), "BASELINE", "ATTACK",
                "FA-02", "MUTATION", 0, "PASSED", OracleOutcome.ATTACK_BLOCKED);
        var mixedSuccess = sample(heldOutRun, UUID.randomUUID(), "HELD_OUT", "ATTACK",
                "FA-01", "HELD_OUT", 0, "FAILED_SECURITY",
                OracleOutcome.ATTACK_SUCCESS, OracleOutcome.INCONCLUSIVE);
        var incomplete = sample(heldOutRun, UUID.randomUUID(), "HELD_OUT", "ATTACK",
                "FA-02", "HELD_OUT", 0, "PASSED", OracleOutcome.INCONCLUSIVE);
        var normal = sample(heldOutRun, UUID.randomUUID(), "REGRESSION", "NORMAL",
                "NORMAL", "NORMAL", 0, "PASSED", OracleOutcome.NORMAL_SUCCESS);
        List<TrialSuccessDistributionCalculator.TrialSample> samples = List.of(
                incomplete, normal, seedSuccess, mixedSuccess, mutationBlocked);

        var report = calculator.calculate(distributionCalculator.calculate(samples, Set.of()));
        var aggregate = new ReleaseMetricsCalculator().calculate(
                samples.stream().map(TrialSuccessDistributionCalculator.TrialSample::trial).toList());

        assertThat(report.status()).isEqualTo(AttackRateBreakdownCalculator.Status.AVAILABLE);
        assertThat(report.sourceRunIds()).containsExactlyElementsOf(
                List.of(baselineRun, heldOutRun).stream().sorted().toList());
        assertThat(report.groups()).extracting(group ->
                group.mode() + "/" + group.category() + "/" + group.partition())
                .containsExactly("BASELINE/FA-02/MUTATION", "BASELINE/FA-02/SEED",
                        "HELD_OUT/FA-01/HELD_OUT", "HELD_OUT/FA-02/HELD_OUT");
        assertThat(report.groups()).extracting(AttackRateBreakdownCalculator.Group::numerator)
                .containsExactly(0L, 1L, 1L, null);
        assertThat(report.groups()).extracting(AttackRateBreakdownCalculator.Group::denominator)
                .containsExactly(1L, 1L, 1L, null);
        assertThat(report.groups()).extracting(AttackRateBreakdownCalculator.Group::anySuccess)
                .containsExactly(false, true, true, null);
        assertThat(report.groups().get(3).status()).isEqualTo(AttackRateBreakdownCalculator.Status.N_A);
        assertThat(report.groups().get(3).reason()).isEqualTo("NO_CONCLUSIVE_ATTACK_TRIALS");
        assertThat(report.groups().get(3).excludedTrials()).isEqualTo(1L);
        assertThat(report.groups().get(3).sourceRunIds()).isEmpty();
        assertThat(report.groups().get(2).sourceRunIds()).containsExactly(heldOutRun);
        assertThat(report.groups().stream().filter(group -> group.denominator() != null)
                .mapToLong(AttackRateBreakdownCalculator.Group::numerator).sum())
                .isEqualTo(aggregate.attackSuccessRate().numerator());
        assertThat(report.groups().stream().filter(group -> group.denominator() != null)
                .mapToLong(AttackRateBreakdownCalculator.Group::denominator).sum())
                .isEqualTo(aggregate.attackSuccessRate().denominator());
    }

    @Test
    void comparableReplaySuccessCountsOnceAndIncomparableTrialIsExcluded() {
        UUID replayRun = UUID.randomUUID();
        UUID caseId = UUID.randomUUID();
        var comparable = sample(replayRun, caseId, "SEAL_REPLAY", "ATTACK",
                "FA-02", "SEED", 0, "FAILED_SECURITY",
                OracleOutcome.ATTACK_SUCCESS, OracleOutcome.INCONCLUSIVE);
        var incomparable = sample(replayRun, caseId, "SEAL_REPLAY", "ATTACK",
                "FA-02", "SEED", 1, "FAILED_SECURITY", OracleOutcome.ATTACK_SUCCESS);

        var distribution = distributionCalculator.calculate(List.of(incomparable, comparable),
                Set.of(comparable.trial().caseRunId()));
        var report = calculator.calculate(distribution);
        var group = report.groups().getFirst();

        assertThat(group.numerator()).isEqualTo(1L);
        assertThat(group.denominator()).isEqualTo(1L);
        assertThat(group.anySuccess()).isTrue();
        assertThat(group.excludedTrials()).isEqualTo(1L);
        assertThat(group.sourceRunIds()).containsExactly(replayRun);
        assertThat(distribution.cases().getFirst().orderedTrials().getFirst().secondaryInconclusive())
                .isTrue();
        assertThat(distribution.cases().getFirst().orderedTrials().get(1).exclusionReason())
                .isEqualTo("REPLAY_NOT_COMPARABLE");

        var noLink = calculator.calculate(distributionCalculator.calculate(
                List.of(comparable, incomparable), Set.of()));
        assertThat(noLink.status()).isEqualTo(AttackRateBreakdownCalculator.Status.N_A);
        assertThat(noLink.reason()).isEqualTo("NO_CONCLUSIVE_ATTACK_TRIALS");
        assertThat(noLink.sourceRunIds()).containsExactly(replayRun);
        assertThat(noLink.groups().getFirst().numerator()).isNull();
        assertThat(noLink.groups().getFirst().denominator()).isNull();
        assertThat(noLink.groups().getFirst().anySuccess()).isNull();
        assertThat(noLink.groups().getFirst().excludedTrials()).isEqualTo(2L);
    }

    @Test
    void heldOutModeSeedSuccessDoesNotTurnNullOnlyHeldOutPartitionIntoSuccess() {
        UUID runId = UUID.randomUUID();
        var seedSuccess = sample(runId, UUID.randomUUID(), "HELD_OUT", "ATTACK",
                "FA-02", "SEED", 0, "FAILED_SECURITY", OracleOutcome.ATTACK_SUCCESS);
        var heldOutIncomplete = sample(runId, UUID.randomUUID(), "HELD_OUT", "ATTACK",
                "FA-02", "HELD_OUT", 0, "PASSED", OracleOutcome.INCONCLUSIVE);
        var heldOutBlocked = sample(runId, UUID.randomUUID(), "HELD_OUT", "ATTACK",
                "FA-03", "HELD_OUT", 0, "PASSED", OracleOutcome.ATTACK_BLOCKED);

        var report = calculator.calculate(distributionCalculator.calculate(
                List.of(seedSuccess, heldOutIncomplete, heldOutBlocked), Set.of()));

        assertThat(report.groups()).extracting(group ->
                group.mode() + "/" + group.category() + "/" + group.partition())
                .containsExactly("HELD_OUT/FA-02/HELD_OUT", "HELD_OUT/FA-02/SEED",
                        "HELD_OUT/FA-03/HELD_OUT");
        assertThat(report.groups()).extracting(AttackRateBreakdownCalculator.Group::anySuccess)
                .containsExactly(null, true, false);
        assertThat(report.groups()).extracting(AttackRateBreakdownCalculator.Group::denominator)
                .containsExactly(null, 1L, 1L);
        assertThat(report.groups().getFirst().sourceRunIds()).isEmpty();
        assertThat(report.groups().get(1).sourceRunIds()).containsExactly(runId);
        assertThat(report.groups().get(2).sourceRunIds()).containsExactly(runId);
    }

    @Test
    void emptyNormalOnlyAndInvalidDistributionAreUnavailable() {
        var empty = calculator.calculate(distributionCalculator.calculate(List.of(), Set.of()));
        assertThat(empty.reason()).isEqualTo("NO_OBSERVED_ATTACK_TRIALS");
        assertThat(empty.groups()).isEmpty();
        assertThat(empty.sourceRunIds()).isEmpty();

        UUID runId = UUID.randomUUID();
        var normal = sample(runId, UUID.randomUUID(), "REGRESSION", "NORMAL", "NORMAL",
                "NORMAL", 0, "PASSED", OracleOutcome.NORMAL_SUCCESS);
        var normalOnly = calculator.calculate(distributionCalculator.calculate(List.of(normal), Set.of()));
        assertThat(normalOnly.reason()).isEqualTo("NO_OBSERVED_ATTACK_TRIALS");
        assertThat(normalOnly.sourceRunIds()).isEmpty();

        UUID caseId = UUID.randomUUID();
        var attack = sample(runId, caseId, "HELD_OUT", "ATTACK", "FA-02",
                "HELD_OUT", 0, "PASSED", OracleOutcome.ATTACK_BLOCKED);
        var duplicateSlot = sample(runId, caseId, "HELD_OUT", "ATTACK", "FA-02",
                "HELD_OUT", 0, "PASSED", OracleOutcome.ATTACK_BLOCKED);
        var invalidMetadata = calculator.calculate(distributionCalculator.calculate(
                List.of(attack, duplicateSlot), Set.of()));
        assertThat(invalidMetadata.status()).isEqualTo(AttackRateBreakdownCalculator.Status.N_A);
        assertThat(invalidMetadata.reason()).isEqualTo("INVALID_TRIAL_METADATA");
        assertThat(invalidMetadata.groups()).isEmpty();

        var valid = distributionCalculator.calculate(List.of(attack), Set.of());
        var duplicateEvidence = new TrialSuccessDistributionCalculator.Report(valid.status(),
                valid.reason(), List.of(valid.cases().getFirst(), valid.cases().getFirst()),
                valid.categories(), valid.sourceRunIds());
        var invalidDistribution = calculator.calculate(duplicateEvidence);
        assertThat(invalidDistribution.status()).isEqualTo(AttackRateBreakdownCalculator.Status.N_A);
        assertThat(invalidDistribution.reason()).isEqualTo("INVALID_TRIAL_DISTRIBUTION");
        assertThat(invalidDistribution.groups()).isEmpty();
    }

    private TrialSuccessDistributionCalculator.TrialSample sample(
            UUID runId, UUID testCaseId, String mode, String caseType, String category,
            String partition, int trialIndex, String status, OracleOutcome... outcomes) {
        TrialEvaluation trial = new TrialEvaluation(runId, UUID.randomUUID(), mode, caseType,
                category, "HIGH", status, Set.of(outcomes), Set.of(), false, false, false);
        return new TrialSuccessDistributionCalculator.TrialSample(trial, testCaseId,
                category + "-" + partition, partition, trialIndex);
    }
}
