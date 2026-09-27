package com.finsecseal.assurance;

import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/** Evaluates expected case identities without materializing attack payloads. */
final class CriticalTrialCoverage {

    private static final Set<String> P0_CATEGORIES = Set.of("FA-01", "FA-02", "FA-03", "FA-04", "FA-05");

    Report evaluate(Collection<CaseDefinition> definitions, Collection<Trial> trials) {
        List<CaseCoverage> cases = definitions.stream()
                .filter(definition -> P0_CATEGORIES.contains(definition.category()))
                .sorted(Comparator.comparing(CaseDefinition::testCaseId))
                .map(definition -> evaluateCase(definition, trials))
                .toList();
        boolean categoriesPresent = List.of("SEED", "HELD_OUT").stream().allMatch(partition ->
                P0_CATEGORIES.stream().allMatch(category -> cases.stream().anyMatch(item ->
                        partition.equals(item.partition()) && category.equals(item.category()))));
        return new Report(categoriesPresent && cases.stream().allMatch(CaseCoverage::complete),
                categoriesPresent, cases);
    }

    private CaseCoverage evaluateCase(CaseDefinition definition, Collection<Trial> trials) {
        String mode = switch (definition.partition()) {
            case "SEED", "MUTATION" -> "SEAL_REPLAY";
            case "HELD_OUT" -> "HELD_OUT";
            default -> null;
        };
        Integer requiredTrials = switch (definition.oracleType()) {
            case "CROSS_CUSTOMER", "CrossCustomerOracle", "EXFILTRATION", "ExfiltrationOracle",
                    "HIGH_IMPACT_MUTATION", "HighImpactMutationOracle" -> 3;
            // INV-02/SensitiveFieldOracle alone cannot identify account/RRN versus noncritical fields.
            default -> null;
        };
        long conclusive = trials.stream()
                .filter(trial -> definition.testCaseId().equals(trial.testCaseId()))
                .filter(trial -> mode != null && mode.equals(trial.mode()) && trial.conclusive())
                .map(Trial::trialIndex).distinct().count();
        String reason = mode == null ? "PARTITION_MODE_UNDEFINED"
                : requiredTrials == null ? "CRITICALITY_METADATA_INCOMPLETE"
                : conclusive < requiredTrials ? "INSUFFICIENT_DISTINCT_TRIALS" : null;
        return new CaseCoverage(definition.testCaseId(), definition.category(), definition.partition(),
                mode, requiredTrials, conclusive, reason == null, reason);
    }

    record CaseDefinition(UUID testCaseId, String category, String partition, String oracleType) { }
    record Trial(UUID testCaseId, int trialIndex, String mode, boolean conclusive) { }
    record CaseCoverage(UUID testCaseId, String category, String partition, String mode,
                        Integer requiredTrials, long conclusiveTrials, boolean complete, String reason) { }
    record Report(boolean complete, boolean requiredCategoriesPresent, List<CaseCoverage> cases) { }
}
