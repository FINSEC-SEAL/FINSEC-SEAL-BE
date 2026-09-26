package com.finsecseal.assurance;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigDecimal;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

class PolicyLatencyCalculatorTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private final PolicyLatencyCalculator calculator = new PolicyLatencyCalculator();

    @Test
    void calculatesDecimalMeanAndNearestRanksAcrossEverySelectedEvent() throws Exception {
        UUID runA = id(10);
        UUID runB = id(20);
        var metric = calculator.calculate(List.of(
                sample(4, runB, "{\"durationMs\":10}"),
                sample(3, runA, "{\"durationMs\":2}"),
                sample(2, runA, "{\"durationMs\":1.5}"),
                sample(1, runB, "{\"durationMs\":0}")
        ));

        assertThat(metric.status()).isEqualTo(PolicyLatencyCalculator.Status.AVAILABLE);
        assertThat(metric.reason()).isNull();
        assertThat(metric.observedEventCount()).isEqualTo(4);
        assertThat(metric.invalidEventCount()).isZero();
        assertThat(metric.averageMs()).isEqualByComparingTo("3.375");
        assertThat(metric.p50Ms()).isEqualByComparingTo("1.5");
        assertThat(metric.p95Ms()).isEqualByComparingTo("10");
        assertThat(metric.p99Ms()).isEqualByComparingTo("10");
        assertThat(metric.sourceEventIds()).containsExactly(id(1), id(2), id(3), id(4));
        assertThat(metric.sourceRunIds()).containsExactly(runA, runB);
        JsonNode serialized = JSON.readTree(JSON.writeValueAsString(metric));
        assertThat(serialized.at("/averageMs").decimalValue()).isEqualByComparingTo("3.375");
    }

    @Test
    void usesNearestRankForOddAndSingleSamplesAndAcceptsZero() throws Exception {
        var odd = calculator.calculate(List.of(
                sample(1, id(10), "{\"durationMs\":3}"),
                sample(2, id(10), "{\"durationMs\":1}"),
                sample(3, id(10), "{\"durationMs\":2}")
        ));
        assertThat(odd.averageMs()).isEqualByComparingTo("2");
        assertThat(odd.p50Ms()).isEqualByComparingTo("2");
        assertThat(odd.p95Ms()).isEqualByComparingTo("3");
        assertThat(odd.p99Ms()).isEqualByComparingTo("3");

        var zero = calculator.calculate(List.of(sample(4, id(10), "{\"durationMs\":0}")));
        assertThat(zero.status()).isEqualTo(PolicyLatencyCalculator.Status.AVAILABLE);
        assertThat(zero.averageMs()).isEqualByComparingTo(BigDecimal.ZERO);
        assertThat(zero.p50Ms()).isEqualByComparingTo(BigDecimal.ZERO);
        assertThat(zero.p95Ms()).isEqualByComparingTo(BigDecimal.ZERO);
        assertThat(zero.p99Ms()).isEqualByComparingTo(BigDecimal.ZERO);
    }

    @Test
    void reportsNoEvaluationsAsUnavailableWithoutFabricatingZero() {
        var metric = calculator.calculate(List.of());

        assertThat(metric.status()).isEqualTo(PolicyLatencyCalculator.Status.N_A);
        assertThat(metric.reason()).isEqualTo("NO_POLICY_EVALUATIONS");
        assertThat(metric.observedEventCount()).isZero();
        assertThat(metric.averageMs()).isNull();
        assertThat(metric.sourceEventIds()).isEmpty();
        assertThat(metric.sourceRunIds()).isEmpty();
    }

    @Test
    void missingNegativeTextAndNullDurationsInvalidateWholeAggregate() throws Exception {
        var metric = calculator.calculate(List.of(
                sample(1, id(10), "{\"durationMs\":4}"),
                sample(2, id(10), "{}"),
                sample(3, id(10), "{\"durationMs\":-1}"),
                sample(4, id(10), "{\"durationMs\":\"2\"}"),
                new PolicyLatencyCalculator.EventSample(id(5), id(10), null)
        ));

        assertThat(metric.status()).isEqualTo(PolicyLatencyCalculator.Status.N_A);
        assertThat(metric.reason()).isEqualTo("MISSING_OR_INVALID_DURATION");
        assertThat(metric.observedEventCount()).isEqualTo(5);
        assertThat(metric.invalidEventCount()).isEqualTo(4);
        assertThat(metric.averageMs()).isNull();
        assertThat(metric.p50Ms()).isNull();
        assertThat(metric.p95Ms()).isNull();
        assertThat(metric.p99Ms()).isNull();
        assertThat(metric.sourceEventIds()).containsExactly(id(1), id(2), id(3), id(4), id(5));
        JsonNode serialized = JSON.readTree(JSON.writeValueAsString(metric));
        assertThat(serialized.at("/status").asString()).isEqualTo("N_A");
        assertThat(serialized.at("/averageMs").isNull()).isTrue();
    }

    private PolicyLatencyCalculator.EventSample sample(int event, UUID run, String decision) throws Exception {
        return new PolicyLatencyCalculator.EventSample(id(event), run, JSON.readTree(decision));
    }

    private UUID id(int value) {
        return new UUID(0, value);
    }
}
