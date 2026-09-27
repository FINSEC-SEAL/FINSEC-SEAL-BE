package com.finsecseal.assurance;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;

/** Spec 19 ASR dimensions projected from the same conclusive bits as the trial distribution. */
public final class AttackRateBreakdownCalculator {

    private static final Comparator<Key> KEY_ORDER = Comparator.comparing(Key::mode)
            .thenComparing(Key::category).thenComparing(Key::partition);

    public Report calculate(TrialSuccessDistributionCalculator.Report distribution) {
        Objects.requireNonNull(distribution, "trial distribution is required");
        if ("INVALID_TRIAL_METADATA".equals(distribution.reason())) {
            return unavailable("INVALID_TRIAL_METADATA", List.of());
        }

        List<TrialSuccessDistributionCalculator.CaseDistribution> attackCases = distribution.cases()
                .stream().filter(item -> "ATTACK".equals(item.caseType())).toList();
        List<UUID> observedRunIds = attackCases.stream().map(
                TrialSuccessDistributionCalculator.CaseDistribution::runId).distinct().sorted().toList();
        if (attackCases.isEmpty()) {
            return unavailable("NO_OBSERVED_ATTACK_TRIALS", observedRunIds);
        }

        Map<Key, Counts> byDimension = new TreeMap<>(KEY_ORDER);
        Set<UUID> caseRunIds = new HashSet<>();
        try {
            for (TrialSuccessDistributionCalculator.CaseDistribution item : attackCases) {
                if (item.runId() == null || item.testCaseId() == null || item.mode() == null
                        || item.category() == null || item.partition() == null
                        || item.successBits().size() != item.orderedTrials().size()) {
                    return unavailable("INVALID_TRIAL_DISTRIBUTION", observedRunIds);
                }
                Counts counts = byDimension.computeIfAbsent(
                        new Key(item.mode(), item.category(), item.partition()), ignored -> new Counts());
                for (int index = 0; index < item.orderedTrials().size(); index++) {
                    TrialSuccessDistributionCalculator.TrialBit trial = item.orderedTrials().get(index);
                    Integer bit = trial.successBit();
                    if (trial.runId() == null || trial.caseRunId() == null
                            || !item.runId().equals(trial.runId())
                            || !item.testCaseId().equals(trial.testCaseId())
                            || !caseRunIds.add(trial.caseRunId())
                            || !Objects.equals(item.successBits().get(index), bit)
                            || (bit != null && bit != 0 && bit != 1)
                            || (bit == null && trial.exclusionReason() == null)
                            || (bit != null && trial.exclusionReason() != null)) {
                        return unavailable("INVALID_TRIAL_DISTRIBUTION", observedRunIds);
                    }
                    if (bit == null) {
                        counts.excluded = Math.addExact(counts.excluded, 1);
                    } else {
                        counts.denominator = Math.addExact(counts.denominator, 1);
                        counts.numerator = Math.addExact(counts.numerator, bit);
                        counts.conclusiveRunIds.add(trial.runId());
                    }
                }
            }
        } catch (ArithmeticException overflow) {
            return unavailable("INVALID_TRIAL_DISTRIBUTION", observedRunIds);
        }

        List<Group> groups = new ArrayList<>();
        for (Map.Entry<Key, Counts> entry : byDimension.entrySet()) {
            Counts counts = entry.getValue();
            List<UUID> sourceRunIds = counts.conclusiveRunIds.stream().sorted().toList();
            if (counts.denominator == 0) {
                groups.add(new Group(Status.N_A, "NO_CONCLUSIVE_ATTACK_TRIALS",
                        entry.getKey().mode(), entry.getKey().category(), entry.getKey().partition(),
                        null, null, null, null, counts.excluded, sourceRunIds));
            } else {
                groups.add(new Group(Status.AVAILABLE, null,
                        entry.getKey().mode(), entry.getKey().category(), entry.getKey().partition(),
                        counts.numerator, counts.denominator,
                        (double) counts.numerator / counts.denominator, counts.numerator > 0,
                        counts.excluded, sourceRunIds));
            }
        }
        boolean available = groups.stream().anyMatch(group -> group.status() == Status.AVAILABLE);
        return new Report(available ? Status.AVAILABLE : Status.N_A,
                available ? null : "NO_CONCLUSIVE_ATTACK_TRIALS", groups, observedRunIds);
    }

    private Report unavailable(String reason, List<UUID> sourceRunIds) {
        return new Report(Status.N_A, reason, List.of(), sourceRunIds);
    }

    public enum Status { AVAILABLE, N_A }

    public record Group(Status status, String reason, String mode, String category, String partition,
                        Long numerator, Long denominator, Double value, Boolean anySuccess,
                        long excludedTrials,
                        List<UUID> sourceRunIds) {
        public Group {
            sourceRunIds = List.copyOf(sourceRunIds);
        }
    }

    public record Report(Status status, String reason, List<Group> groups, List<UUID> sourceRunIds) {
        public Report {
            groups = List.copyOf(groups);
            sourceRunIds = List.copyOf(sourceRunIds);
        }
    }

    private record Key(String mode, String category, String partition) {
    }

    private static final class Counts {
        private long numerator;
        private long denominator;
        private long excluded;
        private final Set<UUID> conclusiveRunIds = new HashSet<>();
    }
}
