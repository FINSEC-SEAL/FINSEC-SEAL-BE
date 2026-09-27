package com.finsecseal.assurance;

import static org.assertj.core.api.Assertions.assertThat;

import com.finsecseal.oracle.domain.OracleOutcome;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class TrialSuccessDistributionCalculatorTest {

    private final TrialSuccessDistributionCalculator calculator =
            new TrialSuccessDistributionCalculator();

    @Test
    void ordersOneBitPerCaseRunAndDerivesCategoryFromCaseBits() {
        UUID runId = UUID.randomUUID();
        UUID firstCaseId = UUID.randomUUID();
        UUID secondCaseId = UUID.randomUUID();
        var blocked = sample(runId, firstCaseId, UUID.randomUUID(), "A", "HELD_OUT",
                "ATTACK", "FA-02", 2, "PASSED", false, OracleOutcome.ATTACK_BLOCKED);
        var success = sample(runId, firstCaseId, UUID.randomUUID(), "A", "HELD_OUT",
                "ATTACK", "FA-02", 0, "FAILED_SECURITY", false,
                OracleOutcome.ATTACK_SUCCESS, OracleOutcome.INCONCLUSIVE);
        var incomplete = sample(runId, firstCaseId, UUID.randomUUID(), "A", "HELD_OUT",
                "ATTACK", "FA-02", 1, "PASSED", false,
                OracleOutcome.ATTACK_BLOCKED, OracleOutcome.INCONCLUSIVE);
        var secondCase = sample(runId, secondCaseId, UUID.randomUUID(), "B", "HELD_OUT",
                "ATTACK", "FA-02", 0, "PASSED", false, OracleOutcome.ATTACK_BLOCKED);

        var report = calculator.calculate(List.of(blocked, secondCase, incomplete, success), Set.of());

        assertThat(report.status()).isEqualTo(TrialSuccessDistributionCalculator.Status.AVAILABLE);
        assertThat(report.sourceRunIds()).containsExactly(runId);
        assertThat(report.cases()).extracting(TrialSuccessDistributionCalculator.CaseDistribution::caseKey)
                .containsExactly("A", "B");
        var first = report.cases().getFirst();
        assertThat(first.successBits()).containsExactly(1, null, 0);
        assertThat(first.orderedTrials()).extracting(TrialSuccessDistributionCalculator.TrialBit::trialIndex)
                .containsExactly(0, 1, 2);
        assertThat(first.orderedTrials()).extracting(TrialSuccessDistributionCalculator.TrialBit::caseRunId)
                .containsExactly(success.trial().caseRunId(), incomplete.trial().caseRunId(),
                        blocked.trial().caseRunId());
        assertThat(first.orderedTrials().getFirst().secondaryInconclusive()).isTrue();
        assertThat(first.orderedTrials().get(1).exclusionReason()).isEqualTo("INCONCLUSIVE_ORACLE");
        assertThat(first.successCount()).isEqualTo(1L);
        assertThat(first.trials()).isEqualTo(2L);
        assertThat(first.excludedTrials()).isEqualTo(1L);
        assertThat(report.cases().get(1).successBits()).containsExactly(0);

        var category = report.categories().getFirst();
        assertThat(report.categories()).hasSize(1);
        assertThat(category.successBits()).containsExactly(1, null, 0, 0);
        assertThat(category.orderedTrials()).extracting(TrialSuccessDistributionCalculator.TrialBit::caseRunId)
                .containsExactly(success.trial().caseRunId(), incomplete.trial().caseRunId(),
                        blocked.trial().caseRunId(), secondCase.trial().caseRunId());
        assertThat(category.successCount()).isEqualTo(1L);
        assertThat(category.trials()).isEqualTo(3L);
        assertThat(category.excludedTrials()).isEqualTo(1L);
    }

    @Test
    void normalErrorsCancellationAndPendingStayNullInsteadOfFailure() {
        UUID runId = UUID.randomUUID();
        UUID testCaseId = UUID.randomUUID();
        var success = sample(runId, testCaseId, UUID.randomUUID(), "N-001", "REGRESSION",
                "NORMAL", "NORMAL", 0, "PASSED", false, OracleOutcome.NORMAL_SUCCESS);
        var failure = sample(runId, testCaseId, UUID.randomUUID(), "N-001", "REGRESSION",
                "NORMAL", "NORMAL", 1, "FAILED_FUNCTIONAL", false, OracleOutcome.NORMAL_FAILURE);
        var error = sample(runId, testCaseId, UUID.randomUUID(), "N-001", "REGRESSION",
                "NORMAL", "NORMAL", 2, "ERROR", true, OracleOutcome.NORMAL_SUCCESS);
        var cancelled = sample(runId, testCaseId, UUID.randomUUID(), "N-001", "REGRESSION",
                "NORMAL", "NORMAL", 3, "CANCELLED", true, OracleOutcome.NORMAL_FAILURE);
        var pending = sample(runId, testCaseId, UUID.randomUUID(), "N-001", "REGRESSION",
                "NORMAL", "NORMAL", 4, "PENDING", false);

        var report = calculator.calculate(List.of(pending, cancelled, error, failure, success), Set.of());

        var item = report.cases().getFirst();
        assertThat(item.successBits()).containsExactly(1, 0, null, null, null);
        assertThat(item.successCount()).isEqualTo(1L);
        assertThat(item.trials()).isEqualTo(2L);
        assertThat(item.excludedTrials()).isEqualTo(3L);
        assertThat(item.orderedTrials()).extracting(TrialSuccessDistributionCalculator.TrialBit::exclusionReason)
                .containsExactly(null, null, "OPERATIONAL_ERROR", "CANCELLED", "NON_TERMINAL_CASE");
        assertThat(report.categories().getFirst().successBits()).containsExactly(1, 0, null, null, null);
    }

    @Test
    void comparableReplayMixedSuccessCountsOnceAndIncomparableReplayDoesNot() {
        UUID runId = UUID.randomUUID();
        UUID testCaseId = UUID.randomUUID();
        var comparable = sample(runId, testCaseId, UUID.randomUUID(), "FA-01", "SEAL_REPLAY",
                "ATTACK", "FA-01", 0, "FAILED_SECURITY", false,
                OracleOutcome.ATTACK_SUCCESS, OracleOutcome.INCONCLUSIVE);
        var incomparable = sample(runId, testCaseId, UUID.randomUUID(), "FA-01", "SEAL_REPLAY",
                "ATTACK", "FA-01", 1, "FAILED_SECURITY", false,
                OracleOutcome.ATTACK_SUCCESS, OracleOutcome.INCONCLUSIVE);

        var report = calculator.calculate(List.of(incomparable, comparable),
                Set.of(comparable.trial().caseRunId()));

        var item = report.cases().getFirst();
        assertThat(item.successBits()).containsExactly(1, null);
        assertThat(item.successCount()).isEqualTo(1L);
        assertThat(item.trials()).isEqualTo(1L);
        assertThat(item.orderedTrials().getFirst().secondaryInconclusive()).isTrue();
        assertThat(item.orderedTrials().get(1).exclusionReason()).isEqualTo("REPLAY_NOT_COMPARABLE");
        assertThat(item.orderedTrials().get(1).secondaryInconclusive()).isTrue();
    }

    @Test
    void emptyAndAllInconclusiveAreUnavailableAndDuplicateSlotsFailClosed() {
        var empty = calculator.calculate(List.of(), Set.of());
        assertThat(empty.status()).isEqualTo(TrialSuccessDistributionCalculator.Status.N_A);
        assertThat(empty.reason()).isEqualTo("NO_OBSERVED_TRIALS");
        assertThat(empty.cases()).isEmpty();

        UUID runId = UUID.randomUUID();
        UUID testCaseId = UUID.randomUUID();
        var incomplete = sample(runId, testCaseId, UUID.randomUUID(), "A", "HELD_OUT",
                "ATTACK", "FA-02", 0, "PASSED", false, OracleOutcome.INCONCLUSIVE);
        var unavailable = calculator.calculate(List.of(incomplete), Set.of());
        assertThat(unavailable.status()).isEqualTo(TrialSuccessDistributionCalculator.Status.N_A);
        assertThat(unavailable.reason()).isEqualTo("NO_CONCLUSIVE_TRIALS");
        assertThat(unavailable.cases().getFirst().successBits()).containsExactly((Integer) null);
        assertThat(unavailable.cases().getFirst().successCount()).isNull();
        assertThat(unavailable.cases().getFirst().trials()).isNull();

        var duplicateIndex = sample(runId, testCaseId, UUID.randomUUID(), "A", "HELD_OUT",
                "ATTACK", "FA-02", 0, "PASSED", false, OracleOutcome.ATTACK_BLOCKED);
        var invalid = calculator.calculate(List.of(incomplete, duplicateIndex), Set.of());
        assertThat(invalid.status()).isEqualTo(TrialSuccessDistributionCalculator.Status.N_A);
        assertThat(invalid.reason()).isEqualTo("INVALID_TRIAL_METADATA");
        assertThat(invalid.cases()).isEmpty();
    }

    private TrialSuccessDistributionCalculator.TrialSample sample(
            UUID runId, UUID testCaseId, UUID caseRunId, String caseKey, String mode,
            String caseType, String category, int trialIndex, String status,
            boolean operationalError, OracleOutcome... outcomes) {
        TrialEvaluation trial = new TrialEvaluation(runId, caseRunId, mode, caseType, category,
                "HIGH", status, Set.of(outcomes), Set.of(), false, false, operationalError);
        return new TrialSuccessDistributionCalculator.TrialSample(
                trial, testCaseId, caseKey, "SEED", trialIndex);
    }
}
