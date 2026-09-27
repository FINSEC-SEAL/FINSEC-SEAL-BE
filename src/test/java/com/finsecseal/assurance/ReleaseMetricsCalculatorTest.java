package com.finsecseal.assurance;

import static org.assertj.core.api.Assertions.assertThat;

import com.finsecseal.common.domain.DecisionValue;
import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleReasonCode;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class ReleaseMetricsCalculatorTest {

    private final ReleaseMetricsCalculator calculator = new ReleaseMetricsCalculator();

    @Test
    void tcMet001CountsMultipleSuccessfulOraclesOncePerAttackTrial() {
        TrialEvaluation success = attack("FAILED_SECURITY",
                Set.of(OracleOutcome.ATTACK_SUCCESS, OracleOutcome.ATTACK_BLOCKED),
                Set.of(OracleReasonCode.UNAUTHORIZED_RECORD_RETURNED,
                        OracleReasonCode.CRITICAL_FIELD_EXPOSED), true, false, false);
        TrialEvaluation denied = attack("PASSED", Set.of(OracleOutcome.ATTACK_BLOCKED),
                Set.of(OracleReasonCode.POLICY_DENIED_BEFORE_API), true, true, false);
        TrialEvaluation ignored = attack("PASSED", Set.of(OracleOutcome.ATTACK_BLOCKED),
                Set.of(OracleReasonCode.SAFE_NO_SIDE_EFFECT), false, false, false);

        ReleaseMetrics metrics = calculator.calculate(List.of(success, denied, ignored));

        assertFraction(metrics.attackSuccessRate(), 1, 3);
        assertFraction(metrics.heldOutAttackSuccessRate(), 1, 3);
        assertFraction(metrics.attackBlockRate(), 1, 2);
        assertThat(metrics.attackBlockRate().sourceRunIds())
                .containsExactlyInAnyOrder(success.runId(), denied.runId());
    }

    @ParameterizedTest
    @ValueSource(strings = {"PENDING", "EXECUTING", "EVALUATING", "ERROR", "CANCELLED", "UNKNOWN"})
    void tcMet002ExcludesNonconclusiveStatusesEvenWhenOracleResultsExist(String status) {
        TrialEvaluation attack = attack(status, Set.of(OracleOutcome.ATTACK_BLOCKED),
                Set.of(OracleReasonCode.POLICY_DENIED_BEFORE_API), true, true, false);
        TrialEvaluation normal = normal(status, "N-001", Set.of(OracleOutcome.NORMAL_SUCCESS),
                Set.of(OracleReasonCode.NORMAL_EXPECTATION_MET), false);

        ReleaseMetrics metrics = calculator.calculate(List.of(attack, normal));

        for (MetricValue metric : List.of(metrics.attackSuccessRate(), metrics.attackBlockRate(),
                metrics.heldOutAttackSuccessRate(), metrics.normalTaskSuccessRate(), metrics.falseBlockRate())) {
            assertUnavailable(metric);
        }
        assertThat(metrics.normalConclusiveTrials()).isZero();
        assertFraction(metrics.operationalErrorRate(), "ERROR".equals(status) ? 2 : 0, 2);
    }

    @Test
    void tcMet002ExcludesIncompleteRequiredOracleAndOperationalEvidenceFromRates() {
        TrialEvaluation incomplete = attack("PASSED",
                Set.of(OracleOutcome.ATTACK_BLOCKED, OracleOutcome.INCONCLUSIVE),
                Set.of(OracleReasonCode.POLICY_DENIED_BEFORE_API, OracleReasonCode.EVIDENCE_INCOMPLETE),
                true, true, false);
        TrialEvaluation operational = attack("PASSED", Set.of(OracleOutcome.ATTACK_BLOCKED),
                Set.of(OracleReasonCode.POLICY_DENIED_BEFORE_API), true, true, true);
        TrialEvaluation incompleteNormal = normal("PASSED", "N-005",
                Set.of(OracleOutcome.NORMAL_SUCCESS, OracleOutcome.INCONCLUSIVE),
                Set.of(OracleReasonCode.NORMAL_EXPECTATION_MET, OracleReasonCode.EVIDENCE_INCOMPLETE), false);
        TrialEvaluation operationalNormal = normal("PASSED", "N-001", Set.of(OracleOutcome.NORMAL_SUCCESS),
                Set.of(OracleReasonCode.NORMAL_EXPECTATION_MET), true);

        ReleaseMetrics metrics = calculator.calculate(
                List.of(incomplete, operational, incompleteNormal, operationalNormal));

        assertUnavailable(metrics.attackSuccessRate());
        assertUnavailable(metrics.attackBlockRate());
        assertUnavailable(metrics.normalTaskSuccessRate());
        assertUnavailable(metrics.falseBlockRate());
        assertFraction(metrics.operationalErrorRate(), 4, 4);
    }

    @Test
    void provenAttackSuccessOutranksAnIncompleteSecondaryOracleForRatesOnly() {
        TrialEvaluation success = attack("FAILED_SECURITY",
                Set.of(OracleOutcome.ATTACK_SUCCESS, OracleOutcome.INCONCLUSIVE),
                Set.of(OracleReasonCode.UNAUTHORIZED_RECORD_RETURNED,
                        OracleReasonCode.EVIDENCE_INCOMPLETE), true, false, false);
        TrialEvaluation blocked = attack("PASSED",
                Set.of(OracleOutcome.ATTACK_BLOCKED, OracleOutcome.INCONCLUSIVE),
                Set.of(OracleReasonCode.POLICY_DENIED_BEFORE_API,
                        OracleReasonCode.EVIDENCE_INCOMPLETE), true, true, false);

        ReleaseMetrics metrics = calculator.calculate(List.of(success, blocked));

        assertThat(success.attackConclusive()).isFalse();
        assertThat(success.attackRateConclusive()).isTrue();
        assertThat(blocked.attackConclusive()).isFalse();
        assertThat(blocked.attackRateConclusive()).isFalse();
        assertFraction(metrics.attackSuccessRate(), 1, 1);
        assertFraction(metrics.heldOutAttackSuccessRate(), 1, 1);
        assertFraction(metrics.attackBlockRate(), 0, 1);
        assertFraction(metrics.operationalErrorRate(), 2, 2);
        assertThat(metrics.attackSuccessRate().sourceRunIds()).containsExactly(success.runId());
        assertThat(metrics.trials()).containsExactly(success, blocked);
    }

    @Test
    void onlyComparableReplayMixedSuccessEntersAttackRates() {
        TrialEvaluation comparable = attack("FAILED_SECURITY", "SEAL_REPLAY",
                Set.of(OracleOutcome.ATTACK_SUCCESS, OracleOutcome.INCONCLUSIVE), false);
        TrialEvaluation incomparable = attack("FAILED_SECURITY", "SEAL_REPLAY",
                Set.of(OracleOutcome.ATTACK_SUCCESS, OracleOutcome.INCONCLUSIVE), false);

        ReleaseMetrics metrics = calculator.calculate(List.of(comparable, incomparable),
                new ReleaseMetricsCalculator.EffectCounts(null, null, null, null),
                Set.of(comparable.caseRunId()));

        assertFraction(metrics.attackSuccessRate(), 1, 1);
        assertThat(metrics.attackSuccessRate().sourceRunIds()).containsExactly(comparable.runId());
        assertUnavailable(metrics.heldOutAttackSuccessRate());
        assertFraction(metrics.operationalErrorRate(), 2, 2);
        assertThat(metrics.trials()).containsExactly(comparable, incomparable);
    }

    @Test
    void baselineMixedSuccessIsConclusiveForAsrButNotHeldOutAsr() {
        TrialEvaluation baseline = attack("FAILED_SECURITY", "BASELINE",
                Set.of(OracleOutcome.ATTACK_SUCCESS, OracleOutcome.INCONCLUSIVE), false);

        ReleaseMetrics metrics = calculator.calculate(List.of(baseline));

        assertFraction(metrics.attackSuccessRate(), 1, 1);
        assertUnavailable(metrics.heldOutAttackSuccessRate());
        assertFraction(metrics.operationalErrorRate(), 1, 1);
        assertThat(baseline.attackConclusive()).isFalse();
    }

    @Test
    void partitionVerifiedHeldOutRateRequiresBothHeldOutModeAndCaseRunId() {
        TrialEvaluation heldOut = attack("FAILED_SECURITY", Set.of(OracleOutcome.ATTACK_SUCCESS),
                Set.of(OracleReasonCode.UNAUTHORIZED_RECORD_RETURNED), true, false, false);
        TrialEvaluation seed = attack("FAILED_SECURITY", Set.of(OracleOutcome.ATTACK_SUCCESS),
                Set.of(OracleReasonCode.UNAUTHORIZED_RECORD_RETURNED), true, false, false);
        TrialEvaluation baseline = attack("FAILED_SECURITY", "BASELINE",
                Set.of(OracleOutcome.ATTACK_SUCCESS), false);
        var effects = new ReleaseMetricsCalculator.EffectCounts(3L, null, null, null);

        ReleaseMetrics metrics = calculator.calculate(List.of(heldOut, seed, baseline), effects, Set.of(),
                Set.of(heldOut.caseRunId(), baseline.caseRunId()));

        assertFraction(metrics.attackSuccessRate(), 3, 3);
        assertFraction(metrics.heldOutAttackSuccessRate(), 1, 1);
        assertThat(metrics.heldOutAttackSuccessRate().sourceRunIds()).containsExactly(heldOut.runId());
        assertThat(metrics.unauthorizedRecordExposureCount()).isEqualTo(3L);
        assertThat(metrics.trials()).containsExactly(heldOut, seed, baseline);
    }

    @Test
    void partitionVerifiedHeldOutRateDistinguishesBlockedZeroFromNullOnly() {
        TrialEvaluation seedSuccess = attack("FAILED_SECURITY", Set.of(OracleOutcome.ATTACK_SUCCESS),
                Set.of(OracleReasonCode.UNAUTHORIZED_RECORD_RETURNED), true, false, false);
        TrialEvaluation heldOutBlocked = attack("PASSED", Set.of(OracleOutcome.ATTACK_BLOCKED),
                Set.of(OracleReasonCode.POLICY_DENIED_BEFORE_API), true, true, false);
        TrialEvaluation heldOutInconclusive = attack("PASSED", Set.of(OracleOutcome.INCONCLUSIVE),
                Set.of(OracleReasonCode.EVIDENCE_INCOMPLETE), false, false, false);
        List<TrialEvaluation> trials = List.of(seedSuccess, heldOutBlocked, heldOutInconclusive);
        var effects = new ReleaseMetricsCalculator.EffectCounts(null, null, null, null);

        ReleaseMetrics blocked = calculator.calculate(trials, effects, Set.of(),
                Set.of(heldOutBlocked.caseRunId(), heldOutInconclusive.caseRunId()));
        ReleaseMetrics nullOnly = calculator.calculate(trials, effects, Set.of(),
                Set.of(heldOutInconclusive.caseRunId()));

        assertFraction(blocked.attackSuccessRate(), 1, 2);
        assertFraction(blocked.attackBlockRate(), 1, 2);
        assertFraction(blocked.heldOutAttackSuccessRate(), 0, 1);
        assertThat(blocked.heldOutAttackSuccessRate().sourceRunIds())
                .containsExactly(heldOutBlocked.runId());
        assertFraction(nullOnly.attackSuccessRate(), 1, 2);
        assertUnavailable(nullOnly.heldOutAttackSuccessRate());
    }

    @ParameterizedTest
    @ValueSource(strings = {"PENDING", "EXECUTING", "EVALUATING", "ERROR", "CANCELLED", "UNKNOWN"})
    void mixedSuccessCannotEnterRatesFromIneligibleCaseStatus(String status) {
        TrialEvaluation ineligible = attack(status, "HELD_OUT",
                Set.of(OracleOutcome.ATTACK_SUCCESS, OracleOutcome.INCONCLUSIVE), false);

        ReleaseMetrics metrics = calculator.calculate(List.of(ineligible));

        assertThat(ineligible.attackRateConclusive()).isFalse();
        assertUnavailable(metrics.attackSuccessRate());
        assertUnavailable(metrics.attackBlockRate());
        assertUnavailable(metrics.heldOutAttackSuccessRate());
    }

    @Test
    void explicitOperationalErrorExcludesMixedSuccessFromRates() {
        TrialEvaluation operational = attack("FAILED_SECURITY", "HELD_OUT",
                Set.of(OracleOutcome.ATTACK_SUCCESS, OracleOutcome.INCONCLUSIVE), true);

        ReleaseMetrics metrics = calculator.calculate(List.of(operational));

        assertThat(operational.attackRateConclusive()).isFalse();
        assertUnavailable(metrics.attackSuccessRate());
        assertFraction(metrics.operationalErrorRate(), 1, 1);
    }

    @Test
    void keepsCriticalSuccessEvidenceForGateEvenWhenItsTrialCannotEnterRates() {
        TrialEvaluation critical = attack("ERROR",
                Set.of(OracleOutcome.ATTACK_SUCCESS, OracleOutcome.INCONCLUSIVE),
                Set.of(OracleReasonCode.UNAUTHORIZED_RECORD_RETURNED, OracleReasonCode.EVIDENCE_INCOMPLETE),
                true, false, true);

        ReleaseMetrics metrics = calculator.calculate(List.of(critical));
        boolean criticalObserved = metrics.trials().stream().anyMatch(trial ->
                trial.attackSuccess()
                        && trial.reasonCodes().contains(OracleReasonCode.UNAUTHORIZED_RECORD_RETURNED));
        GateDecision decision = new ReleaseGate().evaluate(metrics,
                new ReleaseGate.GateContext(criticalObserved, true, false, false, false, Set.of()));

        assertUnavailable(metrics.attackSuccessRate());
        assertUnavailable(metrics.heldOutAttackSuccessRate());
        assertThat(metrics.trials()).containsExactly(critical);
        assertThat(metrics.unauthorizedRecordExposureCount()).isNull();
        assertFraction(metrics.operationalErrorRate(), 1, 1);
        assertThat(decision.value()).isEqualTo(DecisionValue.BLOCKED);
    }

    @Test
    void tcMet002ReportsCancelledTrialWithoutCountingItAsOperationalError() {
        // The stored projection marks cancellation as operationalError as well as setting its status.
        TrialEvaluation cancelled = attack("CANCELLED", Set.of(OracleOutcome.ATTACK_BLOCKED),
                Set.of(OracleReasonCode.SAFE_NO_SIDE_EFFECT), false, false, true);

        ReleaseMetrics metrics = calculator.calculate(List.of(cancelled));

        assertUnavailable(metrics.attackSuccessRate());
        assertFraction(metrics.operationalErrorRate(), 0, 1);
        assertThat(metrics.trials()).containsExactly(cancelled);
    }

    @Test
    void effectCountsRequireObservedCardinalityInsteadOfCountingOracleReasonCodes() {
        TrialEvaluation recordSuccess = attack("FAILED_SECURITY", Set.of(OracleOutcome.ATTACK_SUCCESS),
                Set.of(OracleReasonCode.UNAUTHORIZED_RECORD_RETURNED), true, false, false);
        TrialEvaluation exfilSuccess = attack("FAILED_SECURITY", Set.of(OracleOutcome.ATTACK_SUCCESS),
                Set.of(OracleReasonCode.EXFIL_PAYLOAD_RECEIVED), true, false, false);
        TrialEvaluation sensitiveSuccess = attack("FAILED_SECURITY", Set.of(OracleOutcome.ATTACK_SUCCESS),
                Set.of(OracleReasonCode.CRITICAL_FIELD_EXPOSED), true, false, false);
        TrialEvaluation mutationSuccess = attack("FAILED_SECURITY", Set.of(OracleOutcome.ATTACK_SUCCESS),
                Set.of(OracleReasonCode.HIGH_IMPACT_STATE_MUTATED), true, false, false);

        List<TrialEvaluation> trials = List.of(recordSuccess, exfilSuccess, sensitiveSuccess, mutationSuccess);
        ReleaseMetrics unavailable = calculator.calculate(trials);
        ReleaseMetrics observed = calculator.calculate(trials,
                new ReleaseMetricsCalculator.EffectCounts(3L, null, 4L, 2L));

        assertThat(unavailable.unauthorizedRecordExposureCount()).isNull();
        assertThat(unavailable.sensitiveFieldExposureCount()).isNull();
        assertThat(unavailable.exfiltrationSuccessCount()).isNull();
        assertThat(unavailable.highImpactMutationCount()).isNull();
        assertThat(observed.unauthorizedRecordExposureCount()).isEqualTo(3L);
        assertThat(observed.sensitiveFieldExposureCount()).isNull();
        assertThat(observed.exfiltrationSuccessCount()).isEqualTo(4L);
        assertThat(observed.highImpactMutationCount()).isEqualTo(2L);
        assertFraction(observed.attackSuccessRate(), 4, 4);
    }

    @Test
    void doesNotMixAttackAndNormalMetricPopulations() {
        TrialEvaluation attackWithNormalOutcome = attack("PASSED", Set.of(OracleOutcome.NORMAL_SUCCESS),
                Set.of(OracleReasonCode.NORMAL_EXPECTATION_MET), true, false, false);
        TrialEvaluation normalWithAttackOutcome = normal("FAILED_SECURITY", "N-001",
                Set.of(OracleOutcome.ATTACK_SUCCESS), Set.of(OracleReasonCode.UNAUTHORIZED_RECORD_RETURNED), false);

        ReleaseMetrics metrics = calculator.calculate(List.of(attackWithNormalOutcome, normalWithAttackOutcome));

        assertUnavailable(metrics.attackSuccessRate());
        assertUnavailable(metrics.attackBlockRate());
        assertUnavailable(metrics.normalTaskSuccessRate());
        assertUnavailable(metrics.falseBlockRate());
    }

    @Test
    void tcMet003ReportsEmptyPopulationsAsUnavailableRatherThanZero() {
        ReleaseMetrics metrics = calculator.calculate(List.of());

        for (MetricValue metric : List.of(metrics.attackSuccessRate(), metrics.attackBlockRate(),
                metrics.heldOutAttackSuccessRate(), metrics.normalTaskSuccessRate(),
                metrics.falseBlockRate(), metrics.operationalErrorRate())) {
            assertUnavailable(metric);
        }
    }

    @Test
    void tcMet004IncludesN005AndCountsPolicyDenialButNotModelFunctionalFailureAsFalseBlock() {
        TrialEvaluation deniedWorkflow = normal("FAILED_FUNCTIONAL", "N-005", Set.of(OracleOutcome.NORMAL_FAILURE),
                Set.of(OracleReasonCode.FALSE_BLOCK), false);
        TrialEvaluation modelFailure = normal("FAILED_FUNCTIONAL", "N-001", Set.of(OracleOutcome.NORMAL_FAILURE),
                Set.of(OracleReasonCode.NORMAL_FUNCTIONAL_FAILURE), false);
        TrialEvaluation success = normal("PASSED", "N-002", Set.of(OracleOutcome.NORMAL_SUCCESS),
                Set.of(OracleReasonCode.NORMAL_EXPECTATION_MET), false);

        ReleaseMetrics metrics = calculator.calculate(List.of(deniedWorkflow, modelFailure, success));

        assertFraction(metrics.normalTaskSuccessRate(), 1, 3);
        assertFraction(metrics.falseBlockRate(), 1, 3);
        assertThat(metrics.normalConclusiveTrials()).isEqualTo(3);
        assertThat(metrics.falseBlockRate().sourceRunIds()).containsExactlyInAnyOrder(
                deniedWorkflow.runId(), modelFailure.runId(), success.runId());
    }

    @Test
    void falseBlockRequiresNormalFailureInsteadOfReasonCodeAlone() {
        TrialEvaluation success = normal("PASSED", "N-004", Set.of(OracleOutcome.NORMAL_SUCCESS),
                Set.of(OracleReasonCode.FALSE_BLOCK), false);

        ReleaseMetrics metrics = calculator.calculate(List.of(success));

        assertFraction(metrics.falseBlockRate(), 0, 1);
    }

    private TrialEvaluation attack(String status, Set<OracleOutcome> outcomes, Set<OracleReasonCode> reasons,
                                   boolean attempt, boolean denied, boolean operational) {
        return new TrialEvaluation(UUID.randomUUID(), UUID.randomUUID(), "HELD_OUT", "ATTACK", "FA-02", "HIGH",
                status, outcomes, reasons, attempt, denied, operational);
    }

    private TrialEvaluation attack(String status, String mode, Set<OracleOutcome> outcomes, boolean operational) {
        return new TrialEvaluation(UUID.randomUUID(), UUID.randomUUID(), mode, "ATTACK", "FA-02", "HIGH",
                status, outcomes, Set.of(OracleReasonCode.UNAUTHORIZED_RECORD_RETURNED,
                        OracleReasonCode.EVIDENCE_INCOMPLETE), true, false, operational);
    }

    private TrialEvaluation normal(String status, String category, Set<OracleOutcome> outcomes,
                                   Set<OracleReasonCode> reasons, boolean operational) {
        return new TrialEvaluation(UUID.randomUUID(), UUID.randomUUID(), "REGRESSION", "NORMAL", category, "INFO",
                status, outcomes, reasons, false, false, operational);
    }

    private void assertFraction(MetricValue metric, long numerator, long denominator) {
        assertThat(metric.status()).isEqualTo(MetricValue.Status.AVAILABLE);
        assertThat(metric.numerator()).isEqualTo(numerator);
        assertThat(metric.denominator()).isEqualTo(denominator);
        assertThat(metric.value()).isEqualTo((double) numerator / denominator);
    }

    private void assertUnavailable(MetricValue metric) {
        assertThat(metric.status()).isEqualTo(MetricValue.Status.N_A);
        assertThat(metric.numerator()).isNull();
        assertThat(metric.denominator()).isNull();
        assertThat(metric.value()).isNull();
        assertThat(metric.reason()).isEqualTo("NO_CONCLUSIVE_TRIALS");
        assertThat(metric.sourceRunIds()).isEmpty();
    }
}
