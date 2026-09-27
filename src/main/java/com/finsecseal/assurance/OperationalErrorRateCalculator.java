package com.finsecseal.assurance;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Spec 19 operational errors over persisted scheduled slots, including unmaterialized slots. */
public final class OperationalErrorRateCalculator {

    public MetricValue calculate(Collection<RunCounts> source) {
        List<RunCounts> runs = List.copyOf(source);
        List<UUID> runIds = runs.stream().map(RunCounts::runId).distinct().sorted().toList();
        Set<UUID> unique = new HashSet<>();
        long scheduled = 0;
        long errorOrInconclusive = 0;
        try {
            for (RunCounts run : runs) {
                if (!unique.add(run.runId()) || run.scheduled() < 0 || run.materialized() < 0
                        || run.errorOrInconclusive() < 0 || run.materialized() > run.scheduled()
                        || run.errorOrInconclusive() > run.materialized()) {
                    return unavailable("INCONSISTENT_TRIAL_COUNTS", runIds);
                }
                scheduled = Math.addExact(scheduled, run.scheduled());
                errorOrInconclusive = Math.addExact(errorOrInconclusive, run.errorOrInconclusive());
            }
        } catch (ArithmeticException overflow) {
            return unavailable("INCONSISTENT_TRIAL_COUNTS", runIds);
        }
        if (scheduled == 0) return unavailable("NO_SCHEDULED_TRIALS", runIds);
        return MetricValue.of("OperationalErrorRate", errorOrInconclusive, scheduled, runIds);
    }

    private MetricValue unavailable(String reason, List<UUID> runIds) {
        return new MetricValue("OperationalErrorRate", MetricValue.Status.N_A,
                null, null, null, reason, runIds);
    }

    public record RunCounts(UUID runId, long scheduled, long materialized,
                            long errorOrInconclusive) {
        public RunCounts {
            Objects.requireNonNull(runId, "runId");
        }
    }
}
