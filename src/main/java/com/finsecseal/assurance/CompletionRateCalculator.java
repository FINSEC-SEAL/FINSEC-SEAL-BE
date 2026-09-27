package com.finsecseal.assurance;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Spec 19 completion is terminal non-cancelled cases over immutable scheduled slots. */
public final class CompletionRateCalculator {

    public CompletionRate calculate(Collection<RunCounts> source) {
        List<RunCounts> runs = List.copyOf(source);
        List<UUID> runIds = runs.stream().map(RunCounts::runId).distinct().sorted().toList();
        Set<UUID> unique = new HashSet<>();
        long scheduled = 0;
        long terminalNonCancelled = 0;
        long cancelled = 0;
        long unmaterialized = 0;
        try {
            for (RunCounts run : runs) {
                if (!unique.add(run.runId()) || run.scheduled() < 0 || run.materialized() < 0
                        || run.terminalNonCancelled() < 0 || run.cancelled() < 0
                        || Math.addExact(run.terminalNonCancelled(), run.cancelled()) > run.materialized()
                        || run.materialized() > run.scheduled()) {
                    return unavailable("INCONSISTENT_TRIAL_COUNTS", runIds);
                }
                scheduled = Math.addExact(scheduled, run.scheduled());
                terminalNonCancelled = Math.addExact(terminalNonCancelled, run.terminalNonCancelled());
                cancelled = Math.addExact(cancelled, run.cancelled());
                unmaterialized = Math.addExact(unmaterialized, run.scheduled() - run.materialized());
            }
        } catch (ArithmeticException overflow) {
            return unavailable("INCONSISTENT_TRIAL_COUNTS", runIds);
        }
        if (scheduled == 0) return unavailable("NO_SCHEDULED_TRIALS", runIds);
        return new CompletionRate(Status.AVAILABLE, null, terminalNonCancelled, scheduled,
                (double) terminalNonCancelled / scheduled, cancelled, unmaterialized, runIds);
    }

    private CompletionRate unavailable(String reason, List<UUID> runIds) {
        return new CompletionRate(Status.N_A, reason, null, null, null, null, null, runIds);
    }

    public enum Status { AVAILABLE, N_A }

    public record RunCounts(UUID runId, long scheduled, long materialized,
                            long terminalNonCancelled, long cancelled) {
        public RunCounts {
            Objects.requireNonNull(runId, "runId");
        }
    }

    public record CompletionRate(
            Status status,
            String reason,
            Long numerator,
            Long denominator,
            Double value,
            Long cancelledTrials,
            Long unmaterializedTrials,
            List<UUID> sourceRunIds
    ) {
        public CompletionRate {
            sourceRunIds = List.copyOf(sourceRunIds);
        }
    }
}
