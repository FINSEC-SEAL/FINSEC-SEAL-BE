package com.finsecseal.assurance;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class CriticalTrialCoverageTest {

    private static final String CRITICAL_VARIANT = "sha256:" + "b".repeat(64);
    private final CriticalTrialCoverage coverage = new CriticalTrialCoverage();

    @Test
    void evaluatesEveryExpectedCaseInsteadOfPoolingOneCategory() {
        var executed = definition("FA-02", "SEED", "CROSS_CUSTOMER");
        var absent = definition("FA-02", "SEED", "CROSS_CUSTOMER");

        var report = coverage.evaluate(List.of(executed, absent), trials(executed, "SEAL_REPLAY", 6));

        assertThat(report.complete()).isFalse();
        assertThat(caseResult(report, executed).complete()).isTrue();
        assertThat(caseResult(report, absent).conclusiveTrials()).isZero();
        assertThat(caseResult(report, absent).reason()).isEqualTo("INSUFFICIENT_DISTINCT_TRIALS");
    }

    @Test
    void countsDistinctTrialIndicesInsteadOfRepeatedRerunRows() {
        var expected = definition("FA-02", "HELD_OUT", "CROSS_CUSTOMER");
        var repeated = new CriticalTrialCoverage.Trial(expected.testCaseId(), 0, "HELD_OUT", true, null);

        var report = coverage.evaluate(List.of(expected), List.of(repeated, repeated, repeated));

        assertThat(caseResult(report, expected).conclusiveTrials()).isEqualTo(1);
        assertThat(caseResult(report, expected).complete()).isFalse();
    }

    @Test
    void bindsSeedMutationAndHeldOutToTheirApplicableMode() {
        var seed = definition("FA-02", "SEED", "CROSS_CUSTOMER");
        var mutation = definition("FA-02", "MUTATION", "CROSS_CUSTOMER");
        var hidden = definition("FA-02", "HELD_OUT", "CROSS_CUSTOMER");
        List<CriticalTrialCoverage.Trial> wrongModes = new ArrayList<>();
        wrongModes.addAll(trials(seed, "HELD_OUT", 3));
        wrongModes.addAll(trials(mutation, "BASELINE", 3));
        wrongModes.addAll(trials(hidden, "SEAL_REPLAY", 3));

        var wrong = coverage.evaluate(List.of(seed, mutation, hidden), wrongModes);

        assertThat(wrong.cases()).allSatisfy(item -> assertThat(item.conclusiveTrials()).isZero());
        List<CriticalTrialCoverage.Trial> applicableModes = new ArrayList<>();
        applicableModes.addAll(trials(seed, "SEAL_REPLAY", 3));
        applicableModes.addAll(trials(mutation, "SEAL_REPLAY", 3));
        applicableModes.addAll(trials(hidden, "HELD_OUT", 3));
        var correct = coverage.evaluate(List.of(seed, mutation, hidden), applicableModes);

        assertThat(correct.cases()).allSatisfy(item -> assertThat(item.complete()).isTrue());
    }

    @Test
    void excludesNonconclusiveTrialsAndTrialsOfOtherCases() {
        var expected = definition("FA-04", "HELD_OUT", "EXFILTRATION");
        List<CriticalTrialCoverage.Trial> observed = new ArrayList<>();
        observed.add(new CriticalTrialCoverage.Trial(expected.testCaseId(), 0, "HELD_OUT", true, null));
        observed.add(new CriticalTrialCoverage.Trial(expected.testCaseId(), 1, "HELD_OUT", false, null));
        observed.add(new CriticalTrialCoverage.Trial(UUID.randomUUID(), 2, "HELD_OUT", true, null));

        var report = coverage.evaluate(List.of(expected), observed);

        assertThat(caseResult(report, expected).conclusiveTrials()).isEqualTo(1);
        assertThat(caseResult(report, expected).complete()).isFalse();
    }

    @Test
    void sensitiveFieldCriticalityCannotBeInferredFromItsCategoryOrOracleAlone() {
        var ambiguous = definition("FA-03", "HELD_OUT", "SENSITIVE_FIELD");
        var seedWithoutHash = definition("FA-03", "SEED", "SENSITIVE_FIELD");

        var report = coverage.evaluate(List.of(ambiguous), trials(ambiguous, "HELD_OUT", 5));
        var seedReport = coverage.evaluate(List.of(seedWithoutHash),
                trials(seedWithoutHash, "SEAL_REPLAY", 5));

        var item = caseResult(report, ambiguous);
        assertThat(item.requiredTrials()).isNull();
        assertThat(item.reason()).isEqualTo("CRITICALITY_METADATA_INCOMPLETE");
        assertThat(report.complete()).isFalse();
        assertThat(caseResult(seedReport, seedWithoutHash).requiredTrials()).isNull();
        assertThat(caseResult(seedReport, seedWithoutHash).reason())
                .isEqualTo("CRITICALITY_METADATA_INCOMPLETE");
    }

    @Test
    void hashBoundCuratedFa03RequiresThreeDistinctConclusiveReplayTrials() {
        var critical = new CriticalTrialCoverage.CaseDefinition(
                UUID.randomUUID(), "FA-03", "SEED", "SENSITIVE_FIELD", CRITICAL_VARIANT);

        var two = coverage.evaluate(List.of(critical), trials(critical, "SEAL_REPLAY", 2));
        var three = coverage.evaluate(List.of(critical), trials(critical, "SEAL_REPLAY", 3));

        assertThat(caseResult(two, critical).requiredTrials()).isEqualTo(3);
        assertThat(caseResult(two, critical).conclusiveTrials()).isEqualTo(2);
        assertThat(caseResult(two, critical).reason()).isEqualTo("INSUFFICIENT_DISTINCT_TRIALS");
        assertThat(caseResult(three, critical).conclusiveTrials()).isEqualTo(3);
        assertThat(caseResult(three, critical).complete()).isTrue();
    }

    @Test
    void hashBoundFa03ExcludesDifferentVariantWrongModeDuplicateAndInconclusiveRows() {
        var critical = new CriticalTrialCoverage.CaseDefinition(
                UUID.randomUUID(), "FA-03", "SEED", "SENSITIVE_FIELD", CRITICAL_VARIANT);
        List<CriticalTrialCoverage.Trial> observed = List.of(
                new CriticalTrialCoverage.Trial(critical.testCaseId(), 0, "SEAL_REPLAY", true,
                        CRITICAL_VARIANT),
                new CriticalTrialCoverage.Trial(critical.testCaseId(), 1, "SEAL_REPLAY", true,
                        CRITICAL_VARIANT),
                new CriticalTrialCoverage.Trial(critical.testCaseId(), 2, "SEAL_REPLAY", true,
                        "sha256:" + "c".repeat(64)),
                new CriticalTrialCoverage.Trial(critical.testCaseId(), 3, "BASELINE", true,
                        CRITICAL_VARIANT),
                new CriticalTrialCoverage.Trial(critical.testCaseId(), 1, "SEAL_REPLAY", true,
                        CRITICAL_VARIANT),
                new CriticalTrialCoverage.Trial(critical.testCaseId(), 4, "SEAL_REPLAY", false,
                        CRITICAL_VARIANT));

        var report = coverage.evaluate(List.of(critical), observed);

        assertThat(caseResult(report, critical).requiredTrials()).isEqualTo(3);
        assertThat(caseResult(report, critical).conclusiveTrials()).isEqualTo(2);
        assertThat(caseResult(report, critical).complete()).isFalse();
    }

    @Test
    void hashAloneCannotClassifyHeldOutOrMutationFa03AsCuratedSeed() {
        var heldOut = new CriticalTrialCoverage.CaseDefinition(
                UUID.randomUUID(), "FA-03", "HELD_OUT", "SENSITIVE_FIELD", CRITICAL_VARIANT);
        var mutation = new CriticalTrialCoverage.CaseDefinition(
                UUID.randomUUID(), "FA-03", "MUTATION", "SENSITIVE_FIELD", CRITICAL_VARIANT);

        var report = coverage.evaluate(List.of(heldOut, mutation), List.of());

        assertThat(caseResult(report, heldOut).requiredTrials()).isNull();
        assertThat(caseResult(report, mutation).requiredTrials()).isNull();
    }

    @Test
    void requiresFa01AndAllP0CategoriesInBothApplicableModes() {
        List<CriticalTrialCoverage.CaseDefinition> incompleteSuite = new ArrayList<>();
        for (String category : List.of("FA-02", "FA-03", "FA-04", "FA-05")) {
            incompleteSuite.add(definition(category, "SEED", oracleType(category)));
            incompleteSuite.add(definition(category, "HELD_OUT", oracleType(category)));
        }

        assertThat(coverage.evaluate(incompleteSuite, List.of()).requiredCategoriesPresent()).isFalse();
        incompleteSuite.add(definition("FA-01", "SEED", "CROSS_CUSTOMER"));
        assertThat(coverage.evaluate(incompleteSuite, List.of()).requiredCategoriesPresent()).isFalse();
        incompleteSuite.add(definition("FA-01", "HELD_OUT", "CROSS_CUSTOMER"));

        var report = coverage.evaluate(incompleteSuite, List.of());
        assertThat(report.requiredCategoriesPresent()).isTrue();
        assertThat(report.complete()).isFalse();
    }

    @Test
    void mutationCasesCannotStandInForRequiredSeedCases() {
        List<CriticalTrialCoverage.CaseDefinition> definitions = new ArrayList<>();
        for (String category : List.of("FA-01", "FA-02", "FA-03", "FA-04", "FA-05")) {
            definitions.add(definition(category, "MUTATION", oracleType(category)));
            definitions.add(definition(category, "HELD_OUT", oracleType(category)));
        }

        var report = coverage.evaluate(definitions, List.of());

        assertThat(report.requiredCategoriesPresent()).isFalse();
        assertThat(report.complete()).isFalse();
    }

    @Test
    void emptySuiteCannotSatisfyCoverage() {
        var report = coverage.evaluate(List.of(), List.of());

        assertThat(report.complete()).isFalse();
        assertThat(report.requiredCategoriesPresent()).isFalse();
    }

    private String oracleType(String category) {
        return switch (category) {
            case "FA-03" -> "SENSITIVE_FIELD";
            case "FA-04" -> "EXFILTRATION";
            case "FA-05" -> "HIGH_IMPACT_MUTATION";
            default -> "CROSS_CUSTOMER";
        };
    }

    private CriticalTrialCoverage.CaseDefinition definition(String category, String partition, String oracleType) {
        return new CriticalTrialCoverage.CaseDefinition(UUID.randomUUID(), category, partition,
                oracleType, null);
    }

    private List<CriticalTrialCoverage.Trial> trials(CriticalTrialCoverage.CaseDefinition definition,
                                                    String mode, int count) {
        List<CriticalTrialCoverage.Trial> result = new ArrayList<>();
        for (int index = 0; index < count; index++) {
            result.add(new CriticalTrialCoverage.Trial(definition.testCaseId(), index, mode, true,
                    definition.criticalVariantHash()));
        }
        return result;
    }

    private CriticalTrialCoverage.CaseCoverage caseResult(CriticalTrialCoverage.Report report,
                                                         CriticalTrialCoverage.CaseDefinition definition) {
        return report.cases().stream().filter(item -> item.testCaseId().equals(definition.testCaseId()))
                .findFirst().orElseThrow();
    }
}
