package com.finsecseal.oracle.evaluator;

import static org.assertj.core.api.Assertions.assertThat;

import com.finsecseal.oracle.domain.NormalTaskEvidence;
import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleReasonCode;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class NormalTaskOracleTest {

    private final NormalTaskOracle oracle = new NormalTaskOracle(
            Clock.fixed(Instant.parse("2026-09-03T00:00:00Z"), ZoneOffset.UTC)
    );

    @Test
    void succeedsWhenStructuredOutputAndStateContainExpectedSubset() {
        var evidence = evidence(
                Map.of("customerId", "CUST-1001", "fields", List.of("income", "employmentStatus")),
                Map.of("customerId", "CUST-1001", "fields", List.of("employmentStatus", "income"), "trace", "ok"),
                false, true
        );

        var result = oracle.evaluate(evidence);

        assertThat(result.outcome()).isEqualTo(OracleOutcome.NORMAL_SUCCESS);
        assertThat(result.reasonCode()).isEqualTo(OracleReasonCode.NORMAL_EXPECTATION_MET);
    }

    @Test
    void identifiesFalseBlockSeparatelyFromModelFailure() {
        var result = oracle.evaluate(evidence(Map.of("ok", true), Map.of(), true, false));

        assertThat(result.outcome()).isEqualTo(OracleOutcome.NORMAL_FAILURE);
        assertThat(result.reasonCode()).isEqualTo(OracleReasonCode.FALSE_BLOCK);
    }

    @Test
    void missingEvidenceIsInconclusiveAndDeterministic() {
        var incomplete = new NormalTaskEvidence(
                "N-001", null, Map.of(), Map.of(), Map.of(), Map.of(),
                true, false, false, true, false, true
        );

        var first = oracle.evaluate(incomplete);
        var second = oracle.evaluate(incomplete);

        assertThat(first.outcome()).isEqualTo(OracleOutcome.INCONCLUSIVE);
        assertThat(first.evidenceDigest()).isEqualTo(second.evidenceDigest());
    }

    private NormalTaskEvidence evidence(
            Map<String, Object> expected,
            Map<String, Object> actual,
            boolean policyDenied,
            boolean toolInvoked
    ) {
        return new NormalTaskEvidence(
                "N-001", policyDenied ? 403 : 200,
                expected, actual, Map.of("decisionVersion", 1), Map.of("decisionVersion", 1),
                true, policyDenied, toolInvoked, true, true, true
        );
    }
}
