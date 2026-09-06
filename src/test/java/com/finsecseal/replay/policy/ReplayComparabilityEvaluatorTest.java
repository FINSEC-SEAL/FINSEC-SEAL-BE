package com.finsecseal.replay.policy;

import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.replay.policy.ReplayComparabilityResult.Mismatch;
import com.finsecseal.replay.policy.ReplayComparabilityResult.MismatchCode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ReplayComparabilityEvaluatorTest {

    private static final UUID RELEASE_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID BASELINE_NAMESPACE = UUID.fromString("22222222-2222-2222-2222-222222222222");
    private static final UUID REPLAY_NAMESPACE = UUID.fromString("33333333-3333-3333-3333-333333333333");
    private static final UUID ATTACK_CASE_ID = UUID.fromString("44444444-4444-4444-4444-444444444444");
    private static final UUID PAIR_GROUP_ID = UUID.fromString("55555555-5555-5555-5555-555555555555");
    private static final UUID CONTRACT_VERSION_ID = UUID.fromString("66666666-6666-6666-6666-666666666666");
    private static final Instant COMPLETED_AT = Instant.parse("2026-09-05T00:00:00Z");

    private final ReplayComparabilityEvaluator evaluator = new ReplayComparabilityEvaluator();

    @Test
    void acceptsOnlyPolicyDifferentControlledReplayPair() {
        ReplayComparabilityResult result = evaluator.evaluate(validBaseline(), validReplay());

        assertThat(result.comparable()).isTrue();
        assertThat(result.mismatches()).isEmpty();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("controlledVariableMismatches")
    void rejectsEveryControlledVariableMismatch(
            MismatchCode expectedCode,
            Consumer<FactsBuilder> replayMutation
    ) {
        FactsBuilder replay = new FactsBuilder(validReplay());
        replayMutation.accept(replay);

        ReplayComparabilityResult result = evaluator.evaluate(validBaseline(), replay.build());

        assertThat(result.comparable()).isFalse();
        assertThat(result.mismatches()).extracting(Mismatch::code).containsExactly(expectedCode);
    }

    @ParameterizedTest(name = "invalid replay fact {0}")
    @MethodSource("invalidRequiredFacts")
    void rejectsEveryMissingOrMalformedRequiredFact(
            String field,
            Consumer<FactsBuilder> replayMutation
    ) {
        FactsBuilder replay = new FactsBuilder(validReplay());
        replayMutation.accept(replay);

        ReplayComparabilityResult result = evaluator.evaluate(validBaseline(), replay.build());

        assertThat(result.mismatches()).containsExactly(new Mismatch(
                MismatchCode.REPLAY_REQUIRED_FACT_INVALID,
                "/replay/" + field
        ));
    }

    @ParameterizedTest(name = "invalid baseline fact {0}")
    @MethodSource("invalidRequiredFacts")
    void rejectsEveryMissingOrMalformedBaselineRequiredFact(
            String field,
            Consumer<FactsBuilder> baselineMutation
    ) {
        FactsBuilder baseline = new FactsBuilder(validBaseline());
        baselineMutation.accept(baseline);

        ReplayComparabilityResult result = evaluator.evaluate(baseline.build(), validReplay());

        assertThat(result.mismatches()).containsExactly(new Mismatch(
                MismatchCode.BASELINE_REQUIRED_FACT_INVALID,
                "/baseline/" + field
        ));
    }

    @ParameterizedTest(name = "missing required fact {0} on both sides")
    @MethodSource("missingRequiredFacts")
    void rejectsEveryMissingRequiredFactOnBothSides(
            String field,
            Consumer<FactsBuilder> mutation
    ) {
        FactsBuilder baseline = new FactsBuilder(validBaseline());
        mutation.accept(baseline);
        assertThat(evaluator.evaluate(baseline.build(), validReplay()).mismatches()).containsExactly(
                new Mismatch(MismatchCode.BASELINE_REQUIRED_FACT_INVALID, "/baseline/" + field)
        );

        FactsBuilder replay = new FactsBuilder(validReplay());
        mutation.accept(replay);
        assertThat(evaluator.evaluate(validBaseline(), replay.build()).mismatches()).containsExactly(
                new Mismatch(MismatchCode.REPLAY_REQUIRED_FACT_INVALID, "/replay/" + field)
        );
    }

    @Test
    void rejectsEqualMalformedValuesBeforeComparingThem() {
        FactsBuilder baseline = new FactsBuilder(validBaseline());
        FactsBuilder replay = new FactsBuilder(validReplay());
        baseline.initialStateDigest = "not-a-digest";
        replay.initialStateDigest = "not-a-digest";

        ReplayComparabilityResult result = evaluator.evaluate(baseline.build(), replay.build());

        assertThat(result.mismatches()).containsExactly(
                new Mismatch(MismatchCode.BASELINE_REQUIRED_FACT_INVALID, "/baseline/initialStateDigest"),
                new Mismatch(MismatchCode.REPLAY_REQUIRED_FACT_INVALID, "/replay/initialStateDigest")
        );
    }

    @Test
    void failsClosedWhenEitherFactsObjectIsMissing() {
        assertThat(evaluator.evaluate(null, null).mismatches()).containsExactly(
                new Mismatch(MismatchCode.BASELINE_FACTS_MISSING, "/baseline"),
                new Mismatch(MismatchCode.REPLAY_FACTS_MISSING, "/replay")
        );
        assertThat(evaluator.evaluate(validBaseline(), null).mismatches()).containsExactly(
                new Mismatch(MismatchCode.REPLAY_FACTS_MISSING, "/replay")
        );
        assertThat(evaluator.evaluate(null, validReplay()).mismatches()).containsExactly(
                new Mismatch(MismatchCode.BASELINE_FACTS_MISSING, "/baseline")
        );
    }

    @ParameterizedTest
    @MethodSource("nonCompletedRunStatuses")
    void requiresExactCompletedRunStatus(TestRunStatus status) {
        FactsBuilder baseline = new FactsBuilder(validBaseline());
        baseline.runStatus = status;
        assertThat(evaluator.evaluate(baseline.build(), validReplay()).mismatches()).containsExactly(
                new Mismatch(MismatchCode.BASELINE_LIFECYCLE_INVALID, "/baseline/runStatus")
        );

        FactsBuilder replay = new FactsBuilder(validReplay());
        replay.runStatus = status;
        assertThat(evaluator.evaluate(validBaseline(), replay.build()).mismatches()).containsExactly(
                new Mismatch(MismatchCode.REPLAY_LIFECYCLE_INVALID, "/replay/runStatus")
        );
    }

    @ParameterizedTest
    @MethodSource("inconclusiveCaseStatuses")
    void rejectsInconclusiveCaseStatus(TestCaseRunStatus status) {
        FactsBuilder baseline = new FactsBuilder(validBaseline());
        baseline.caseStatus = status;
        assertThat(evaluator.evaluate(baseline.build(), validReplay()).mismatches()).containsExactly(
                new Mismatch(MismatchCode.BASELINE_LIFECYCLE_INVALID, "/baseline/caseStatus")
        );

        FactsBuilder replay = new FactsBuilder(validReplay());
        replay.caseStatus = status;
        assertThat(evaluator.evaluate(validBaseline(), replay.build()).mismatches()).containsExactly(
                new Mismatch(MismatchCode.REPLAY_LIFECYCLE_INVALID, "/replay/caseStatus")
        );
    }

    @ParameterizedTest
    @MethodSource("conclusiveCaseStatuses")
    void acceptsEveryConclusiveCaseStatusOnBothSides(TestCaseRunStatus status) {
        FactsBuilder baseline = new FactsBuilder(validBaseline());
        baseline.caseStatus = status;
        FactsBuilder replay = new FactsBuilder(validReplay());
        replay.caseStatus = status;

        assertThat(evaluator.evaluate(baseline.build(), replay.build()).comparable()).isTrue();
    }

    @Test
    void requiresBothCompletionMarkers() {
        FactsBuilder baseline = new FactsBuilder(validBaseline());
        baseline.runCompletedAt = null;
        baseline.caseCompletedAt = null;
        assertThat(evaluator.evaluate(baseline.build(), validReplay()).mismatches()).containsExactly(
                new Mismatch(MismatchCode.BASELINE_LIFECYCLE_INVALID, "/baseline/runCompletedAt"),
                new Mismatch(MismatchCode.BASELINE_LIFECYCLE_INVALID, "/baseline/caseCompletedAt")
        );

        FactsBuilder replay = new FactsBuilder(validReplay());
        replay.runCompletedAt = null;
        replay.caseCompletedAt = null;

        assertThat(evaluator.evaluate(validBaseline(), replay.build()).mismatches()).containsExactly(
                new Mismatch(MismatchCode.REPLAY_LIFECYCLE_INVALID, "/replay/runCompletedAt"),
                new Mismatch(MismatchCode.REPLAY_LIFECYCLE_INVALID, "/replay/caseCompletedAt")
        );
    }

    @Test
    void rejectsMissingLifecycleStatusesOnBothSides() {
        FactsBuilder baseline = new FactsBuilder(validBaseline());
        baseline.runStatus = null;
        baseline.caseStatus = null;
        assertThat(evaluator.evaluate(baseline.build(), validReplay()).mismatches()).containsExactly(
                new Mismatch(MismatchCode.BASELINE_LIFECYCLE_INVALID, "/baseline/runStatus"),
                new Mismatch(MismatchCode.BASELINE_LIFECYCLE_INVALID, "/baseline/caseStatus")
        );

        FactsBuilder replay = new FactsBuilder(validReplay());
        replay.runStatus = null;
        replay.caseStatus = null;
        assertThat(evaluator.evaluate(validBaseline(), replay.build()).mismatches()).containsExactly(
                new Mismatch(MismatchCode.REPLAY_LIFECYCLE_INVALID, "/replay/runStatus"),
                new Mismatch(MismatchCode.REPLAY_LIFECYCLE_INVALID, "/replay/caseStatus")
        );
    }

    @ParameterizedTest(name = "baseline policy binding {0}")
    @MethodSource("invalidBaselinePolicyBindings")
    void distinguishesIntentionalBaselineContractAbsence(
            String expectedPath,
            Consumer<FactsBuilder> baselineMutation
    ) {
        FactsBuilder baseline = new FactsBuilder(validBaseline());
        baselineMutation.accept(baseline);

        assertThat(evaluator.evaluate(baseline.build(), validReplay()).mismatches()).containsExactly(
                new Mismatch(MismatchCode.BASELINE_POLICY_BINDING_INVALID, expectedPath)
        );
    }

    @ParameterizedTest(name = "replay policy binding {0}")
    @MethodSource("invalidReplayPolicyBindings")
    void requiresApprovedReplayContractEvidence(
            String expectedPath,
            Consumer<FactsBuilder> replayMutation
    ) {
        FactsBuilder replay = new FactsBuilder(validReplay());
        replayMutation.accept(replay);

        assertThat(evaluator.evaluate(validBaseline(), replay.build()).mismatches()).containsExactly(
                new Mismatch(MismatchCode.REPLAY_POLICY_BINDING_INVALID, expectedPath)
        );
    }

    @Test
    void requiresIndependentNamespacesWithEquivalentInitialState() {
        FactsBuilder replay = new FactsBuilder(validReplay());
        replay.namespaceId = BASELINE_NAMESPACE;

        assertThat(evaluator.evaluate(validBaseline(), replay.build()).mismatches()).containsExactly(
                new Mismatch(MismatchCode.NAMESPACE_NOT_ISOLATED, "/namespaceId")
        );

        replay.namespaceId = REPLAY_NAMESPACE;
        replay.initialStateDigest = digest('9');
        assertThat(evaluator.evaluate(validBaseline(), replay.build()).mismatches()).containsExactly(
                new Mismatch(MismatchCode.INITIAL_STATE_MISMATCH, "/initialStateDigest")
        );
    }

    @Test
    void requiresFinalReleaseFingerprintToReflectPolicyDifference() {
        FactsBuilder replay = new FactsBuilder(validReplay());
        replay.releaseFingerprint = validBaseline().releaseFingerprint();

        assertThat(evaluator.evaluate(validBaseline(), replay.build()).mismatches()).containsExactly(
                new Mismatch(MismatchCode.POLICY_FINGERPRINT_NOT_DISTINCT, "/releaseFingerprint")
        );
    }

    @Test
    void acceptsZeroTrialIndexAndRandomSeed() {
        FactsBuilder baseline = new FactsBuilder(validBaseline());
        baseline.trialIndex = 0;
        baseline.randomSeed = 0L;
        FactsBuilder replay = new FactsBuilder(validReplay());
        replay.trialIndex = 0;
        replay.randomSeed = 0L;

        assertThat(evaluator.evaluate(baseline.build(), replay.build()).comparable()).isTrue();
    }

    @Test
    void returnsStablePrecedenceAndImmutableResultsWithoutMutatingInputs() {
        ReplayComparisonFacts baseline = validBaseline();
        FactsBuilder replayBuilder = new FactsBuilder(validReplay());
        replayBuilder.runStatus = TestRunStatus.FAILED;
        replayBuilder.contractApproved = false;
        replayBuilder.namespaceId = BASELINE_NAMESPACE;
        replayBuilder.releaseId = UUID.fromString("77777777-7777-7777-7777-777777777777");
        replayBuilder.agentArtifactFingerprint = digest('9');
        replayBuilder.modelParametersDigest = digest('8');
        ReplayComparisonFacts replay = replayBuilder.build();

        ReplayComparabilityResult first = evaluator.evaluate(baseline, replay);
        ReplayComparabilityResult second = evaluator.evaluate(baseline, replay);

        assertThat(first).isEqualTo(second);
        assertThat(first.mismatches()).extracting(Mismatch::code).containsExactly(
                MismatchCode.REPLAY_LIFECYCLE_INVALID,
                MismatchCode.REPLAY_POLICY_BINDING_INVALID,
                MismatchCode.NAMESPACE_NOT_ISOLATED,
                MismatchCode.RELEASE_MISMATCH,
                MismatchCode.AGENT_ARTIFACT_MISMATCH,
                MismatchCode.MODEL_PARAMETERS_MISMATCH
        );
        assertThat(baseline).isEqualTo(validBaseline());
        assertThat(replay).isEqualTo(replayBuilder.build());
        assertThatThrownBy(() -> first.mismatches().add(
                new Mismatch(MismatchCode.RELEASE_MISMATCH, "/releaseId")
        )).isInstanceOf(UnsupportedOperationException.class);
    }

    private static Stream<Arguments> controlledVariableMismatches() {
        return Stream.of(
                mismatch(MismatchCode.RELEASE_MISMATCH,
                        facts -> facts.releaseId = UUID.fromString("77777777-7777-7777-7777-777777777777")),
                mismatch(MismatchCode.INITIAL_STATE_MISMATCH, facts -> facts.initialStateDigest = digest('9')),
                mismatch(MismatchCode.AGENT_ARTIFACT_MISMATCH, facts -> facts.agentArtifactFingerprint = digest('9')),
                mismatch(MismatchCode.MODEL_PROVIDER_MISMATCH, facts -> facts.modelProvider = "another-provider"),
                mismatch(MismatchCode.MODEL_NAME_MISMATCH, facts -> facts.modelName = "another-model"),
                mismatch(MismatchCode.RESOLVED_MODEL_MISMATCH, facts -> facts.resolvedModelId = "resolved-v2"),
                mismatch(MismatchCode.MODEL_PARAMETERS_MISMATCH, facts -> facts.modelParametersDigest = digest('9')),
                mismatch(MismatchCode.ATTACK_CASE_MISMATCH,
                        facts -> facts.attackCaseId = UUID.fromString("88888888-8888-8888-8888-888888888888")),
                mismatch(MismatchCode.VARIANT_MISMATCH, facts -> facts.variantHash = digest('9')),
                mismatch(MismatchCode.TRIAL_INDEX_MISMATCH, facts -> facts.trialIndex = 2),
                mismatch(MismatchCode.FIXTURE_VERSION_MISMATCH, facts -> facts.fixtureVersion = "fixture-v2"),
                mismatch(MismatchCode.FIXTURE_DIGEST_MISMATCH, facts -> facts.fixtureDigest = digest('9')),
                mismatch(MismatchCode.RANDOM_SEED_MISMATCH, facts -> facts.randomSeed = 43L),
                mismatch(MismatchCode.PAIR_GROUP_MISMATCH,
                        facts -> facts.pairGroupId = UUID.fromString("99999999-9999-9999-9999-999999999999")),
                mismatch(MismatchCode.RUNTIME_CONTROLS_MISMATCH,
                        facts -> facts.runtimeTimeoutMaxStepsDigest = digest('9')),
                mismatch(MismatchCode.TOOL_SCHEMA_MISMATCH, facts -> facts.toolSchemaDigest = digest('9')),
                mismatch(MismatchCode.RAG_VERSION_MISMATCH, facts -> facts.ragVersion = "rag-v2"),
                mismatch(MismatchCode.RAG_CONFIG_MISMATCH, facts -> facts.ragConfigDigest = digest('9'))
        );
    }

    private static Stream<Arguments> invalidRequiredFacts() {
        return Stream.of(
                invalid("releaseId", facts -> facts.releaseId = null),
                invalid("namespaceId", facts -> facts.namespaceId = null),
                invalid("initialStateDigest", facts -> facts.initialStateDigest = null),
                invalid("agentArtifactFingerprint", facts -> facts.agentArtifactFingerprint = "SHA256:ABC"),
                invalid("modelProvider", facts -> facts.modelProvider = " "),
                invalid("modelName", facts -> facts.modelName = null),
                invalid("resolvedModelId", facts -> facts.resolvedModelId = ""),
                invalid("modelParametersDigest", facts -> facts.modelParametersDigest = "not-a-digest"),
                invalid("attackCaseId", facts -> facts.attackCaseId = null),
                invalid("variantHash", facts -> facts.variantHash = null),
                invalid("trialIndex", facts -> facts.trialIndex = -1),
                invalid("fixtureVersion", facts -> facts.fixtureVersion = "\t"),
                invalid("fixtureDigest", facts -> facts.fixtureDigest = digest('A')),
                invalid("randomSeed", facts -> facts.randomSeed = null),
                invalid("pairGroupId", facts -> facts.pairGroupId = null),
                invalid("runtimeTimeoutMaxStepsDigest", facts -> facts.runtimeTimeoutMaxStepsDigest = "bad"),
                invalid("toolSchemaDigest", facts -> facts.toolSchemaDigest = null),
                invalid("ragVersion", facts -> facts.ragVersion = " "),
                invalid("ragConfigDigest", facts -> facts.ragConfigDigest = "bad"),
                invalid("releaseFingerprint", facts -> facts.releaseFingerprint = null)
        );
    }

    private static Stream<Arguments> missingRequiredFacts() {
        return Stream.of(
                invalid("releaseId", facts -> facts.releaseId = null),
                invalid("namespaceId", facts -> facts.namespaceId = null),
                invalid("initialStateDigest", facts -> facts.initialStateDigest = null),
                invalid("agentArtifactFingerprint", facts -> facts.agentArtifactFingerprint = null),
                invalid("modelProvider", facts -> facts.modelProvider = null),
                invalid("modelName", facts -> facts.modelName = null),
                invalid("resolvedModelId", facts -> facts.resolvedModelId = null),
                invalid("modelParametersDigest", facts -> facts.modelParametersDigest = null),
                invalid("attackCaseId", facts -> facts.attackCaseId = null),
                invalid("variantHash", facts -> facts.variantHash = null),
                invalid("trialIndex", facts -> facts.trialIndex = null),
                invalid("fixtureVersion", facts -> facts.fixtureVersion = null),
                invalid("fixtureDigest", facts -> facts.fixtureDigest = null),
                invalid("randomSeed", facts -> facts.randomSeed = null),
                invalid("pairGroupId", facts -> facts.pairGroupId = null),
                invalid("runtimeTimeoutMaxStepsDigest", facts -> facts.runtimeTimeoutMaxStepsDigest = null),
                invalid("toolSchemaDigest", facts -> facts.toolSchemaDigest = null),
                invalid("ragVersion", facts -> facts.ragVersion = null),
                invalid("ragConfigDigest", facts -> facts.ragConfigDigest = null),
                invalid("releaseFingerprint", facts -> facts.releaseFingerprint = null)
        );
    }

    private static Stream<TestRunStatus> nonCompletedRunStatuses() {
        return Stream.of(
                TestRunStatus.QUEUED,
                TestRunStatus.PREPARING,
                TestRunStatus.RUNNING,
                TestRunStatus.CANCELLING,
                TestRunStatus.FAILED,
                TestRunStatus.CANCELLED
        );
    }

    private static Stream<TestCaseRunStatus> inconclusiveCaseStatuses() {
        return Stream.of(
                TestCaseRunStatus.PENDING,
                TestCaseRunStatus.EXECUTING,
                TestCaseRunStatus.EVALUATING,
                TestCaseRunStatus.ERROR,
                TestCaseRunStatus.CANCELLED
        );
    }

    private static Stream<TestCaseRunStatus> conclusiveCaseStatuses() {
        return Stream.of(
                TestCaseRunStatus.PASSED,
                TestCaseRunStatus.FAILED_SECURITY,
                TestCaseRunStatus.FAILED_FUNCTIONAL
        );
    }

    private static Stream<Arguments> invalidBaselinePolicyBindings() {
        return Stream.of(
                policy("/baseline/runMode", facts -> facts.runMode = TestRunMode.SEAL_REPLAY),
                policy("/baseline/runMode", facts -> facts.runMode = null),
                policy("/baseline/contractApproved", facts -> facts.contractApproved = true),
                policy("/baseline/contractApproved", facts -> facts.contractApproved = null),
                policy("/baseline/contractVersionId", facts -> facts.contractVersionId = CONTRACT_VERSION_ID),
                policy("/baseline/contractHash", facts -> facts.contractHash = digest('7'))
        );
    }

    private static Stream<Arguments> invalidReplayPolicyBindings() {
        return Stream.of(
                policy("/replay/runMode", facts -> facts.runMode = TestRunMode.BASELINE),
                policy("/replay/runMode", facts -> facts.runMode = null),
                policy("/replay/contractApproved", facts -> facts.contractApproved = false),
                policy("/replay/contractApproved", facts -> facts.contractApproved = null),
                policy("/replay/contractVersionId", facts -> facts.contractVersionId = null),
                policy("/replay/contractHash", facts -> facts.contractHash = null),
                policy("/replay/contractHash", facts -> facts.contractHash = "not-a-digest")
        );
    }

    private static Arguments mismatch(MismatchCode code, Consumer<FactsBuilder> mutation) {
        return Arguments.of(code, mutation);
    }

    private static Arguments invalid(String field, Consumer<FactsBuilder> mutation) {
        return Arguments.of(field, mutation);
    }

    private static Arguments policy(String path, Consumer<FactsBuilder> mutation) {
        return Arguments.of(path, mutation);
    }

    private static ReplayComparisonFacts validBaseline() {
        return new FactsBuilder().build();
    }

    private static ReplayComparisonFacts validReplay() {
        FactsBuilder replay = new FactsBuilder();
        replay.namespaceId = REPLAY_NAMESPACE;
        replay.runMode = TestRunMode.SEAL_REPLAY;
        replay.contractVersionId = CONTRACT_VERSION_ID;
        replay.contractApproved = true;
        replay.contractHash = digest('7');
        replay.releaseFingerprint = digest('8');
        return replay.build();
    }

    private static String digest(char character) {
        return "sha256:" + String.valueOf(character).repeat(64);
    }

    private static final class FactsBuilder {
        private UUID releaseId = RELEASE_ID;
        private UUID namespaceId = BASELINE_NAMESPACE;
        private String initialStateDigest = digest('1');
        private String agentArtifactFingerprint = digest('2');
        private String modelProvider = "provider";
        private String modelName = "model";
        private String resolvedModelId = "resolved-v1";
        private String modelParametersDigest = digest('3');
        private UUID attackCaseId = ATTACK_CASE_ID;
        private String variantHash = digest('4');
        private Integer trialIndex = 1;
        private String fixtureVersion = "fixture-v1";
        private String fixtureDigest = digest('5');
        private Long randomSeed = 42L;
        private UUID pairGroupId = PAIR_GROUP_ID;
        private String runtimeTimeoutMaxStepsDigest = digest('6');
        private String toolSchemaDigest = digest('a');
        private String ragVersion = "rag-v1";
        private String ragConfigDigest = digest('b');
        private TestRunMode runMode = TestRunMode.BASELINE;
        private TestRunStatus runStatus = TestRunStatus.COMPLETED;
        private TestCaseRunStatus caseStatus = TestCaseRunStatus.FAILED_SECURITY;
        private Instant runCompletedAt = COMPLETED_AT;
        private Instant caseCompletedAt = COMPLETED_AT;
        private UUID contractVersionId;
        private Boolean contractApproved = false;
        private String contractHash;
        private String releaseFingerprint = digest('c');

        private FactsBuilder() {
        }

        private FactsBuilder(ReplayComparisonFacts facts) {
            releaseId = facts.releaseId();
            namespaceId = facts.namespaceId();
            initialStateDigest = facts.initialStateDigest();
            agentArtifactFingerprint = facts.agentArtifactFingerprint();
            modelProvider = facts.modelProvider();
            modelName = facts.modelName();
            resolvedModelId = facts.resolvedModelId();
            modelParametersDigest = facts.modelParametersDigest();
            attackCaseId = facts.attackCaseId();
            variantHash = facts.variantHash();
            trialIndex = facts.trialIndex();
            fixtureVersion = facts.fixtureVersion();
            fixtureDigest = facts.fixtureDigest();
            randomSeed = facts.randomSeed();
            pairGroupId = facts.pairGroupId();
            runtimeTimeoutMaxStepsDigest = facts.runtimeTimeoutMaxStepsDigest();
            toolSchemaDigest = facts.toolSchemaDigest();
            ragVersion = facts.ragVersion();
            ragConfigDigest = facts.ragConfigDigest();
            runMode = facts.runMode();
            runStatus = facts.runStatus();
            caseStatus = facts.caseStatus();
            runCompletedAt = facts.runCompletedAt();
            caseCompletedAt = facts.caseCompletedAt();
            contractVersionId = facts.contractVersionId();
            contractApproved = facts.contractApproved();
            contractHash = facts.contractHash();
            releaseFingerprint = facts.releaseFingerprint();
        }

        private ReplayComparisonFacts build() {
            return new ReplayComparisonFacts(
                    releaseId,
                    namespaceId,
                    initialStateDigest,
                    agentArtifactFingerprint,
                    modelProvider,
                    modelName,
                    resolvedModelId,
                    modelParametersDigest,
                    attackCaseId,
                    variantHash,
                    trialIndex,
                    fixtureVersion,
                    fixtureDigest,
                    randomSeed,
                    pairGroupId,
                    runtimeTimeoutMaxStepsDigest,
                    toolSchemaDigest,
                    ragVersion,
                    ragConfigDigest,
                    runMode,
                    runStatus,
                    caseStatus,
                    runCompletedAt,
                    caseCompletedAt,
                    contractVersionId,
                    contractApproved,
                    contractHash,
                    releaseFingerprint
            );
        }
    }
}
