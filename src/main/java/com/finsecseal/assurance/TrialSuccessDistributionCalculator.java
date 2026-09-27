package com.finsecseal.assurance;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Observed, ordered success bits; unavailable evidence is never a failure bit. */
public final class TrialSuccessDistributionCalculator {

    public Report calculate(Collection<TrialSample> source, Set<UUID> comparableReplayCaseRunIds) {
        Objects.requireNonNull(comparableReplayCaseRunIds, "comparable replay case IDs are required");
        List<TrialSample> samples = List.copyOf(source);
        List<UUID> sourceRunIds = samples.stream().map(sample -> sample.trial().runId())
                .distinct().sorted().toList();
        if (samples.isEmpty()) {
            return new Report(Status.N_A, "NO_OBSERVED_TRIALS", List.of(), List.of(), sourceRunIds);
        }

        Set<UUID> caseRunIds = new HashSet<>();
        Set<TrialSlot> slots = new HashSet<>();
        for (TrialSample sample : samples) {
            if (sample.trialIndex() < 0 || !caseRunIds.add(sample.trial().caseRunId())
                    || !slots.add(new TrialSlot(sample.trial().runId(), sample.testCaseId(),
                    sample.trialIndex()))) {
                return new Report(Status.N_A, "INVALID_TRIAL_METADATA", List.of(), List.of(), sourceRunIds);
            }
        }

        List<TrialSample> ordered = samples.stream().sorted(Comparator
                .comparing((TrialSample sample) -> sample.trial().mode())
                .thenComparing(sample -> sample.trial().caseType())
                .thenComparing(sample -> sample.trial().category())
                .thenComparing(TrialSample::caseKey)
                .thenComparing(TrialSample::testCaseId)
                .thenComparing(sample -> sample.trial().runId())
                .thenComparingInt(TrialSample::trialIndex)
                .thenComparing(sample -> sample.trial().caseRunId())).toList();

        Map<CaseKey, List<TrialBit>> byCase = new LinkedHashMap<>();
        Map<CaseKey, TrialSample> caseHeaders = new LinkedHashMap<>();
        for (TrialSample sample : ordered) {
            CaseKey key = new CaseKey(sample.trial().runId(), sample.testCaseId());
            caseHeaders.putIfAbsent(key, sample);
            byCase.computeIfAbsent(key, ignored -> new ArrayList<>())
                    .add(toBit(sample, comparableReplayCaseRunIds));
        }

        List<CaseDistribution> cases = new ArrayList<>();
        Map<CategoryKey, List<TrialBit>> byCategory = new LinkedHashMap<>();
        for (Map.Entry<CaseKey, List<TrialBit>> entry : byCase.entrySet()) {
            TrialSample header = caseHeaders.get(entry.getKey());
            List<TrialBit> bits = List.copyOf(entry.getValue());
            Counts counts = counts(bits);
            cases.add(new CaseDistribution(counts.status(), counts.reason(),
                    header.trial().runId(), header.trial().mode(), header.testCaseId(),
                    header.caseKey(), header.trial().caseType(), header.trial().category(),
                    header.partition(), successBits(bits), bits, counts.successCount(),
                    counts.trials(), counts.excludedTrials()));
            CategoryKey category = new CategoryKey(header.trial().mode(),
                    header.trial().caseType(), header.trial().category());
            byCategory.computeIfAbsent(category, ignored -> new ArrayList<>()).addAll(bits);
        }

        List<CategoryDistribution> categories = new ArrayList<>();
        for (Map.Entry<CategoryKey, List<TrialBit>> entry : byCategory.entrySet()) {
            List<TrialBit> bits = List.copyOf(entry.getValue());
            Counts counts = counts(bits);
            List<UUID> runIds = bits.stream().map(TrialBit::runId).distinct().sorted().toList();
            categories.add(new CategoryDistribution(counts.status(), counts.reason(),
                    entry.getKey().mode(), entry.getKey().caseType(), entry.getKey().category(),
                    successBits(bits), bits, counts.successCount(), counts.trials(),
                    counts.excludedTrials(), runIds));
        }
        boolean conclusive = cases.stream().anyMatch(item -> item.status() == Status.AVAILABLE);
        return new Report(conclusive ? Status.AVAILABLE : Status.N_A,
                conclusive ? null : "NO_CONCLUSIVE_TRIALS", cases, categories, sourceRunIds);
    }

    private TrialBit toBit(TrialSample sample, Set<UUID> comparableReplayCaseRunIds) {
        TrialEvaluation trial = sample.trial();
        Integer bit = null;
        String reason = null;
        if ("CANCELLED".equals(trial.status())) {
            reason = "CANCELLED";
        } else if ("ERROR".equals(trial.status()) || trial.operationalError()) {
            reason = "OPERATIONAL_ERROR";
        } else if (!Set.of("PASSED", "FAILED_SECURITY", "FAILED_FUNCTIONAL").contains(trial.status())) {
            reason = "NON_TERMINAL_CASE";
        } else if ("SEAL_REPLAY".equals(trial.mode())
                && !comparableReplayCaseRunIds.contains(trial.caseRunId())) {
            reason = "REPLAY_NOT_COMPARABLE";
        } else if (trial.attack() && trial.attackRateConclusive()) {
            bit = trial.attackSuccess() ? 1 : 0;
        } else if (trial.normal() && trial.normalConclusive()) {
            bit = trial.normalSuccess() ? 1 : 0;
        } else {
            reason = trial.inconclusive() ? "INCONCLUSIVE_ORACLE" : "MISSING_REQUIRED_ORACLE";
        }
        return new TrialBit(trial.runId(), sample.testCaseId(), trial.caseRunId(),
                sample.trialIndex(), bit, reason, trial.inconclusive());
    }

    private Counts counts(List<TrialBit> bits) {
        long conclusive = bits.stream().filter(bit -> bit.successBit() != null).count();
        long excluded = bits.size() - conclusive;
        if (conclusive == 0) return new Counts(Status.N_A, "NO_CONCLUSIVE_TRIALS", null, null, excluded);
        long successes = bits.stream().filter(bit -> Integer.valueOf(1).equals(bit.successBit())).count();
        return new Counts(Status.AVAILABLE, null, successes, conclusive, excluded);
    }

    private List<Integer> successBits(List<TrialBit> bits) {
        return nullableCopy(bits.stream().map(TrialBit::successBit).toList());
    }

    private static <T> List<T> nullableCopy(List<T> values) {
        return Collections.unmodifiableList(new ArrayList<>(values));
    }

    public enum Status { AVAILABLE, N_A }

    public record TrialSample(TrialEvaluation trial, UUID testCaseId, String caseKey,
                              String partition, int trialIndex) {
        public TrialSample {
            Objects.requireNonNull(trial, "trial");
            Objects.requireNonNull(testCaseId, "testCaseId");
            Objects.requireNonNull(caseKey, "caseKey");
            Objects.requireNonNull(partition, "partition");
        }
    }

    public record TrialBit(UUID runId, UUID testCaseId, UUID caseRunId, int trialIndex,
                           Integer successBit, String exclusionReason, boolean secondaryInconclusive) {
    }

    public record CaseDistribution(Status status, String reason, UUID runId, String mode,
                                   UUID testCaseId, String caseKey, String caseType, String category,
                                   String partition, List<Integer> successBits, List<TrialBit> orderedTrials,
                                   Long successCount, Long trials, long excludedTrials) {
        public CaseDistribution {
            successBits = nullableCopy(successBits);
            orderedTrials = List.copyOf(orderedTrials);
        }
    }

    public record CategoryDistribution(Status status, String reason, String mode, String caseType,
                                       String category, List<Integer> successBits,
                                       List<TrialBit> orderedTrials, Long successCount, Long trials,
                                       long excludedTrials, List<UUID> sourceRunIds) {
        public CategoryDistribution {
            successBits = nullableCopy(successBits);
            orderedTrials = List.copyOf(orderedTrials);
            sourceRunIds = List.copyOf(sourceRunIds);
        }
    }

    public record Report(Status status, String reason, List<CaseDistribution> cases,
                         List<CategoryDistribution> categories, List<UUID> sourceRunIds) {
        public Report {
            cases = List.copyOf(cases);
            categories = List.copyOf(categories);
            sourceRunIds = List.copyOf(sourceRunIds);
        }
    }

    private record TrialSlot(UUID runId, UUID testCaseId, int trialIndex) {
    }

    private record CaseKey(UUID runId, UUID testCaseId) {
    }

    private record CategoryKey(String mode, String caseType, String category) {
    }

    private record Counts(Status status, String reason, Long successCount, Long trials,
                          long excludedTrials) {
    }
}
