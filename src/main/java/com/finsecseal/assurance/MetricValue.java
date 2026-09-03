package com.finsecseal.assurance;

import java.util.List;
import java.util.UUID;

/** A fraction-backed metric. Empty denominators are explicitly N_A, never zero. */
public record MetricValue(
        String name,
        Status status,
        Long numerator,
        Long denominator,
        Double value,
        String reason,
        List<UUID> sourceRunIds
) {
    public enum Status { AVAILABLE, N_A }

    public static MetricValue of(String name, long numerator, long denominator, List<UUID> runIds) {
        if (denominator == 0) {
            return new MetricValue(name, Status.N_A, null, null, null,
                    "NO_CONCLUSIVE_TRIALS", List.copyOf(runIds));
        }
        return new MetricValue(name, Status.AVAILABLE, numerator, denominator,
                (double) numerator / denominator, null, List.copyOf(runIds));
    }
}
