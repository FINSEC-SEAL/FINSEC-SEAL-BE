package com.finsecseal.assurance;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class CompletionRateCalculatorTest {

    private final CompletionRateCalculator calculator = new CompletionRateCalculator();

    @Test
    void dividesTerminalNonCancelledCasesByImmutableScheduledSlots() {
        var result = calculator.calculate(List.of(
                run(4, 2, 1, 0, 1), // cancelled parent: one cancelled, one unmaterialized
                run(3, 2, 0, 0, 0), // queued and empty
                run(2, 3, 2, 1, 1), // active: ERROR is terminal, CANCELLED is not numerator
                run(1, 1, 1, 1, 0)  // completed
        ));

        assertThat(result.status()).isEqualTo(CompletionRateCalculator.Status.AVAILABLE);
        assertThat(result.reason()).isNull();
        assertThat(result.numerator()).isEqualTo(2L);
        assertThat(result.denominator()).isEqualTo(8L);
        assertThat(result.value()).isEqualTo(0.25);
        assertThat(result.cancelledTrials()).isEqualTo(2L);
        assertThat(result.unmaterializedTrials()).isEqualTo(4L);
        assertThat(result.sourceRunIds()).containsExactly(id(1), id(2), id(3), id(4));
    }

    @Test
    void zeroScheduledTrialsAreUnavailableRatherThanZeroOverZero() {
        var empty = calculator.calculate(List.of());
        var zeroPlan = calculator.calculate(List.of(run(1, 0, 0, 0, 0)));

        for (var result : List.of(empty, zeroPlan)) {
            assertThat(result.status()).isEqualTo(CompletionRateCalculator.Status.N_A);
            assertThat(result.reason()).isEqualTo("NO_SCHEDULED_TRIALS");
            assertThat(result.numerator()).isNull();
            assertThat(result.denominator()).isNull();
            assertThat(result.value()).isNull();
        }
        assertThat(empty.sourceRunIds()).isEmpty();
        assertThat(zeroPlan.sourceRunIds()).containsExactly(id(1));
    }

    @Test
    void rejectsNegativeOrImpossiblePerRunCounts() {
        List<CompletionRateCalculator.RunCounts> invalid = List.of(
                run(1, -1, 0, 0, 0),
                run(1, 1, -1, 0, 0),
                run(1, 1, 1, -1, 0),
                run(1, 1, 1, 0, -1),
                run(1, 1, 2, 1, 0),
                run(1, 2, 1, 1, 1)
        );
        for (var row : invalid) {
            var result = calculator.calculate(List.of(row));
            assertThat(result.status()).isEqualTo(CompletionRateCalculator.Status.N_A);
            assertThat(result.reason()).isEqualTo("INCONSISTENT_TRIAL_COUNTS");
            assertThat(result.numerator()).isNull();
        }
    }

    @Test
    void rejectsDuplicateRunAndAggregateOverflowWithoutPublishingAValue() {
        var duplicate = calculator.calculate(List.of(run(1, 1, 1, 1, 0), run(1, 1, 1, 1, 0)));
        var overflow = calculator.calculate(List.of(
                new CompletionRateCalculator.RunCounts(id(1), Long.MAX_VALUE, 0, 0, 0),
                run(2, 1, 0, 0, 0)
        ));

        assertThat(duplicate.status()).isEqualTo(CompletionRateCalculator.Status.N_A);
        assertThat(duplicate.reason()).isEqualTo("INCONSISTENT_TRIAL_COUNTS");
        assertThat(duplicate.sourceRunIds()).containsExactly(id(1));
        assertThat(overflow.status()).isEqualTo(CompletionRateCalculator.Status.N_A);
        assertThat(overflow.reason()).isEqualTo("INCONSISTENT_TRIAL_COUNTS");
        assertThat(overflow.denominator()).isNull();
    }

    private CompletionRateCalculator.RunCounts run(int runId, long scheduled, long materialized,
                                                    long terminalNonCancelled, long cancelled) {
        return new CompletionRateCalculator.RunCounts(
                id(runId), scheduled, materialized, terminalNonCancelled, cancelled);
    }

    private UUID id(int value) {
        return new UUID(0, value);
    }
}
