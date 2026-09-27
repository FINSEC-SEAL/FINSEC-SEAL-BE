package com.finsecseal.assurance;

import java.math.BigDecimal;
import java.math.MathContext;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

/** Measures policy evaluation only, using every selected POLICY_EVALUATED event. */
public final class PolicyLatencyCalculator {

    private static final MathContext AVERAGE_PRECISION = MathContext.DECIMAL64;

    public PolicyLatency calculate(Collection<EventSample> source) {
        List<EventSample> events = List.copyOf(source);
        List<UUID> eventIds = events.stream().map(EventSample::eventId).distinct().sorted().toList();
        List<UUID> runIds = events.stream().map(EventSample::runId).distinct().sorted().toList();
        List<BigDecimal> durations = events.stream().map(this::durationMs).filter(Objects::nonNull)
                .sorted().toList();
        long invalidCount = events.size() - durations.size();
        if (events.isEmpty() || invalidCount > 0) {
            return new PolicyLatency(Status.N_A,
                    events.isEmpty() ? "NO_POLICY_EVALUATIONS" : "MISSING_OR_INVALID_DURATION",
                    events.size(), invalidCount, null, null, null, null, eventIds, runIds);
        }

        BigDecimal sum = durations.stream().reduce(BigDecimal.ZERO, BigDecimal::add);
        return new PolicyLatency(Status.AVAILABLE, null, events.size(), 0,
                sum.divide(BigDecimal.valueOf(events.size()), AVERAGE_PRECISION),
                nearestRank(durations, 50), nearestRank(durations, 95), nearestRank(durations, 99),
                eventIds, runIds);
    }

    private BigDecimal durationMs(EventSample event) {
        JsonNode value = event.policyDecision() == null
                ? null : event.policyDecision().path("durationMs");
        if (value == null || !value.isNumber()) return null;
        Number number = value.numberValue();
        if (number instanceof Double floating && !Double.isFinite(floating)) return null;
        if (number instanceof Float floating && !Float.isFinite(floating)) return null;
        try {
            BigDecimal duration = value.decimalValue();
            return duration.signum() < 0 ? null : duration;
        } catch (ArithmeticException | NumberFormatException invalid) {
            return null;
        }
    }

    private BigDecimal nearestRank(List<BigDecimal> sorted, int percentile) {
        int index = (int) (((long) percentile * sorted.size() + 99) / 100 - 1);
        return sorted.get(index);
    }

    public enum Status { AVAILABLE, N_A }

    public record EventSample(UUID eventId, UUID runId, JsonNode policyDecision) {
        public EventSample {
            Objects.requireNonNull(eventId, "eventId");
            Objects.requireNonNull(runId, "runId");
        }
    }

    public record PolicyLatency(
            Status status,
            String reason,
            long observedEventCount,
            long invalidEventCount,
            BigDecimal averageMs,
            BigDecimal p50Ms,
            BigDecimal p95Ms,
            BigDecimal p99Ms,
            List<UUID> sourceEventIds,
            List<UUID> sourceRunIds
    ) {
        public PolicyLatency {
            sourceEventIds = List.copyOf(sourceEventIds);
            sourceRunIds = List.copyOf(sourceRunIds);
        }
    }
}
