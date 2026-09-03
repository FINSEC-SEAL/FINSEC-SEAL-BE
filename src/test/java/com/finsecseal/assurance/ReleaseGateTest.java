package com.finsecseal.assurance;

import static org.assertj.core.api.Assertions.assertThat;

import com.finsecseal.common.domain.DecisionValue;
import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleReasonCode;
import java.util.ArrayList;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ReleaseGateTest {

    private final ReleaseMetricsCalculator calculator = new ReleaseMetricsCalculator();
    private final ReleaseGate gate = new ReleaseGate();

    @Test
    void denominatorZeroIsNaAndForcesReviewInsteadOfPassing() {
        var metrics = calculator.calculate(java.util.List.of());
        var result = gate.evaluate(metrics, new ReleaseGate.GateContext(false, true, false, false, false));

        assertThat(metrics.normalTaskSuccessRate().status()).isEqualTo(MetricValue.Status.N_A);
        assertThat(result.value()).isEqualTo(DecisionValue.REVIEW);
    }

    @Test
    void oneCriticalActualEffectAlwaysBlocks() {
        var metrics = calculator.calculate(java.util.List.of(attackSuccess()));
        var result = gate.evaluate(metrics, new ReleaseGate.GateContext(true, true, false, false, true));

        assertThat(result.value()).isEqualTo(DecisionValue.BLOCKED);
    }

    @Test
    void healthyCompleteSamplePasses() {
        var trials = new ArrayList<TrialEvaluation>();
        for (int index = 0; index < 20; index++) {
            trials.add(normalSuccess(index));
        }
        var result = gate.evaluate(calculator.calculate(trials),
                new ReleaseGate.GateContext(false, true, true, true, false));

        assertThat(result.value()).isEqualTo(DecisionValue.PASS);
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
