package com.finsecseal.replay.policy;

import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.replay.policy.ReplayComparabilityResult.Mismatch;
import com.finsecseal.replay.policy.ReplayComparabilityResult.MismatchCode;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.regex.Pattern;

public final class ReplayComparabilityEvaluator {

    private static final Pattern SHA_256 = Pattern.compile("sha256:[0-9a-f]{64}");
    private static final EnumSet<TestCaseRunStatus> CONCLUSIVE_CASE_STATUSES = EnumSet.of(
            TestCaseRunStatus.PASSED,
            TestCaseRunStatus.FAILED_SECURITY,
            TestCaseRunStatus.FAILED_FUNCTIONAL
    );

    public ReplayComparabilityResult evaluate(
            ReplayComparisonFacts baseline,
            ReplayComparisonFacts replay
    ) {
        List<Mismatch> mismatches = new ArrayList<>();
        if (baseline == null) {
            mismatches.add(new Mismatch(MismatchCode.BASELINE_FACTS_MISSING, "/baseline"));
        }
        if (replay == null) {
            mismatches.add(new Mismatch(MismatchCode.REPLAY_FACTS_MISSING, "/replay"));
        }
        if (baseline == null || replay == null) {
            return result(mismatches);
        }

        EnumSet<Fact> validBaselineFacts = validateRequiredFacts(
                baseline,
                "/baseline/",
                MismatchCode.BASELINE_REQUIRED_FACT_INVALID,
                mismatches
        );
        EnumSet<Fact> validReplayFacts = validateRequiredFacts(
                replay,
                "/replay/",
                MismatchCode.REPLAY_REQUIRED_FACT_INVALID,
                mismatches
        );

        validateLifecycle(
                baseline,
                "/baseline/",
                MismatchCode.BASELINE_LIFECYCLE_INVALID,
                mismatches
        );
        validateLifecycle(
                replay,
                "/replay/",
                MismatchCode.REPLAY_LIFECYCLE_INVALID,
                mismatches
        );
        validateBaselinePolicyBinding(baseline, mismatches);
        validateReplayPolicyBinding(replay, mismatches);

        if (bothValid(Fact.NAMESPACE_ID, validBaselineFacts, validReplayFacts)
                && baseline.namespaceId().equals(replay.namespaceId())) {
            mismatches.add(new Mismatch(MismatchCode.NAMESPACE_NOT_ISOLATED, "/namespaceId"));
        }

        compare(Fact.RELEASE_ID, validBaselineFacts, validReplayFacts, baseline, replay,
                ReplayComparisonFacts::releaseId, MismatchCode.RELEASE_MISMATCH, "/releaseId", mismatches);
        compare(Fact.INITIAL_STATE_DIGEST, validBaselineFacts, validReplayFacts, baseline, replay,
                ReplayComparisonFacts::initialStateDigest, MismatchCode.INITIAL_STATE_MISMATCH,
                "/initialStateDigest", mismatches);
        compare(Fact.AGENT_ARTIFACT_FINGERPRINT, validBaselineFacts, validReplayFacts, baseline, replay,
                ReplayComparisonFacts::agentArtifactFingerprint, MismatchCode.AGENT_ARTIFACT_MISMATCH,
                "/agentArtifactFingerprint", mismatches);
        compare(Fact.MODEL_PROVIDER, validBaselineFacts, validReplayFacts, baseline, replay,
                ReplayComparisonFacts::modelProvider, MismatchCode.MODEL_PROVIDER_MISMATCH,
                "/modelProvider", mismatches);
        compare(Fact.MODEL_NAME, validBaselineFacts, validReplayFacts, baseline, replay,
                ReplayComparisonFacts::modelName, MismatchCode.MODEL_NAME_MISMATCH,
                "/modelName", mismatches);
        compare(Fact.RESOLVED_MODEL_ID, validBaselineFacts, validReplayFacts, baseline, replay,
                ReplayComparisonFacts::resolvedModelId, MismatchCode.RESOLVED_MODEL_MISMATCH,
                "/resolvedModelId", mismatches);
        compare(Fact.MODEL_PARAMETERS_DIGEST, validBaselineFacts, validReplayFacts, baseline, replay,
                ReplayComparisonFacts::modelParametersDigest, MismatchCode.MODEL_PARAMETERS_MISMATCH,
                "/modelParametersDigest", mismatches);
        compare(Fact.ATTACK_CASE_ID, validBaselineFacts, validReplayFacts, baseline, replay,
                ReplayComparisonFacts::attackCaseId, MismatchCode.ATTACK_CASE_MISMATCH,
                "/attackCaseId", mismatches);
        compare(Fact.VARIANT_HASH, validBaselineFacts, validReplayFacts, baseline, replay,
                ReplayComparisonFacts::variantHash, MismatchCode.VARIANT_MISMATCH,
                "/variantHash", mismatches);
        compare(Fact.TRIAL_INDEX, validBaselineFacts, validReplayFacts, baseline, replay,
                ReplayComparisonFacts::trialIndex, MismatchCode.TRIAL_INDEX_MISMATCH,
                "/trialIndex", mismatches);
        compare(Fact.FIXTURE_VERSION, validBaselineFacts, validReplayFacts, baseline, replay,
                ReplayComparisonFacts::fixtureVersion, MismatchCode.FIXTURE_VERSION_MISMATCH,
                "/fixtureVersion", mismatches);
        compare(Fact.FIXTURE_DIGEST, validBaselineFacts, validReplayFacts, baseline, replay,
                ReplayComparisonFacts::fixtureDigest, MismatchCode.FIXTURE_DIGEST_MISMATCH,
                "/fixtureDigest", mismatches);
        compare(Fact.RANDOM_SEED, validBaselineFacts, validReplayFacts, baseline, replay,
                ReplayComparisonFacts::randomSeed, MismatchCode.RANDOM_SEED_MISMATCH,
                "/randomSeed", mismatches);
        compare(Fact.PAIR_GROUP_ID, validBaselineFacts, validReplayFacts, baseline, replay,
                ReplayComparisonFacts::pairGroupId, MismatchCode.PAIR_GROUP_MISMATCH,
                "/pairGroupId", mismatches);
        compare(Fact.RUNTIME_CONTROLS_DIGEST, validBaselineFacts, validReplayFacts, baseline, replay,
                ReplayComparisonFacts::runtimeTimeoutMaxStepsDigest, MismatchCode.RUNTIME_CONTROLS_MISMATCH,
                "/runtimeTimeoutMaxStepsDigest", mismatches);
        compare(Fact.TOOL_SCHEMA_DIGEST, validBaselineFacts, validReplayFacts, baseline, replay,
                ReplayComparisonFacts::toolSchemaDigest, MismatchCode.TOOL_SCHEMA_MISMATCH,
                "/toolSchemaDigest", mismatches);
        compare(Fact.RAG_VERSION, validBaselineFacts, validReplayFacts, baseline, replay,
                ReplayComparisonFacts::ragVersion, MismatchCode.RAG_VERSION_MISMATCH,
                "/ragVersion", mismatches);
        compare(Fact.RAG_CONFIG_DIGEST, validBaselineFacts, validReplayFacts, baseline, replay,
                ReplayComparisonFacts::ragConfigDigest, MismatchCode.RAG_CONFIG_MISMATCH,
                "/ragConfigDigest", mismatches);

        if (bothValid(Fact.RELEASE_FINGERPRINT, validBaselineFacts, validReplayFacts)
                && baseline.releaseFingerprint().equals(replay.releaseFingerprint())) {
            mismatches.add(new Mismatch(
                    MismatchCode.POLICY_FINGERPRINT_NOT_DISTINCT,
                    "/releaseFingerprint"
            ));
        }

        return result(mismatches);
    }

    private EnumSet<Fact> validateRequiredFacts(
            ReplayComparisonFacts facts,
            String pathPrefix,
            MismatchCode invalidCode,
            List<Mismatch> mismatches
    ) {
        EnumSet<Fact> valid = EnumSet.noneOf(Fact.class);
        validate(facts.releaseId() != null, Fact.RELEASE_ID, "releaseId", pathPrefix, invalidCode, valid, mismatches);
        validate(facts.namespaceId() != null, Fact.NAMESPACE_ID, "namespaceId", pathPrefix, invalidCode, valid, mismatches);
        validateDigest(facts.initialStateDigest(), Fact.INITIAL_STATE_DIGEST, "initialStateDigest",
                pathPrefix, invalidCode, valid, mismatches);
        validateDigest(facts.agentArtifactFingerprint(), Fact.AGENT_ARTIFACT_FINGERPRINT,
                "agentArtifactFingerprint", pathPrefix, invalidCode, valid, mismatches);
        validateText(facts.modelProvider(), Fact.MODEL_PROVIDER, "modelProvider",
                pathPrefix, invalidCode, valid, mismatches);
        validateText(facts.modelName(), Fact.MODEL_NAME, "modelName",
                pathPrefix, invalidCode, valid, mismatches);
        validateText(facts.resolvedModelId(), Fact.RESOLVED_MODEL_ID, "resolvedModelId",
                pathPrefix, invalidCode, valid, mismatches);
        validateDigest(facts.modelParametersDigest(), Fact.MODEL_PARAMETERS_DIGEST,
                "modelParametersDigest", pathPrefix, invalidCode, valid, mismatches);
        validate(facts.attackCaseId() != null, Fact.ATTACK_CASE_ID, "attackCaseId",
                pathPrefix, invalidCode, valid, mismatches);
        validateDigest(facts.variantHash(), Fact.VARIANT_HASH, "variantHash",
                pathPrefix, invalidCode, valid, mismatches);
        validate(facts.trialIndex() != null && facts.trialIndex() >= 0, Fact.TRIAL_INDEX, "trialIndex",
                pathPrefix, invalidCode, valid, mismatches);
        validateText(facts.fixtureVersion(), Fact.FIXTURE_VERSION, "fixtureVersion",
                pathPrefix, invalidCode, valid, mismatches);
        validateDigest(facts.fixtureDigest(), Fact.FIXTURE_DIGEST, "fixtureDigest",
                pathPrefix, invalidCode, valid, mismatches);
        validate(facts.randomSeed() != null, Fact.RANDOM_SEED, "randomSeed",
                pathPrefix, invalidCode, valid, mismatches);
        validate(facts.pairGroupId() != null, Fact.PAIR_GROUP_ID, "pairGroupId",
                pathPrefix, invalidCode, valid, mismatches);
        validateDigest(facts.runtimeTimeoutMaxStepsDigest(), Fact.RUNTIME_CONTROLS_DIGEST,
                "runtimeTimeoutMaxStepsDigest", pathPrefix, invalidCode, valid, mismatches);
        validateDigest(facts.toolSchemaDigest(), Fact.TOOL_SCHEMA_DIGEST, "toolSchemaDigest",
                pathPrefix, invalidCode, valid, mismatches);
        validateText(facts.ragVersion(), Fact.RAG_VERSION, "ragVersion",
                pathPrefix, invalidCode, valid, mismatches);
        validateDigest(facts.ragConfigDigest(), Fact.RAG_CONFIG_DIGEST, "ragConfigDigest",
                pathPrefix, invalidCode, valid, mismatches);
        validateDigest(facts.releaseFingerprint(), Fact.RELEASE_FINGERPRINT, "releaseFingerprint",
                pathPrefix, invalidCode, valid, mismatches);
        return valid;
    }

    private void validateLifecycle(
            ReplayComparisonFacts facts,
            String pathPrefix,
            MismatchCode invalidCode,
            List<Mismatch> mismatches
    ) {
        if (facts.runStatus() != TestRunStatus.COMPLETED) {
            mismatches.add(new Mismatch(invalidCode, pathPrefix + "runStatus"));
        }
        if (facts.runCompletedAt() == null) {
            mismatches.add(new Mismatch(invalidCode, pathPrefix + "runCompletedAt"));
        }
        if (facts.caseStatus() == null || !CONCLUSIVE_CASE_STATUSES.contains(facts.caseStatus())) {
            mismatches.add(new Mismatch(invalidCode, pathPrefix + "caseStatus"));
        }
        if (facts.caseCompletedAt() == null) {
            mismatches.add(new Mismatch(invalidCode, pathPrefix + "caseCompletedAt"));
        }
    }

    private void validateBaselinePolicyBinding(
            ReplayComparisonFacts baseline,
            List<Mismatch> mismatches
    ) {
        if (baseline.runMode() != TestRunMode.BASELINE) {
            mismatches.add(new Mismatch(
                    MismatchCode.BASELINE_POLICY_BINDING_INVALID,
                    "/baseline/runMode"
            ));
        }
        if (!Boolean.FALSE.equals(baseline.contractApproved())) {
            mismatches.add(new Mismatch(
                    MismatchCode.BASELINE_POLICY_BINDING_INVALID,
                    "/baseline/contractApproved"
            ));
        }
        if (baseline.contractVersionId() != null) {
            mismatches.add(new Mismatch(
                    MismatchCode.BASELINE_POLICY_BINDING_INVALID,
                    "/baseline/contractVersionId"
            ));
        }
        if (baseline.contractHash() != null) {
            mismatches.add(new Mismatch(
                    MismatchCode.BASELINE_POLICY_BINDING_INVALID,
                    "/baseline/contractHash"
            ));
        }
    }

    private void validateReplayPolicyBinding(
            ReplayComparisonFacts replay,
            List<Mismatch> mismatches
    ) {
        if (replay.runMode() != TestRunMode.SEAL_REPLAY) {
            mismatches.add(new Mismatch(
                    MismatchCode.REPLAY_POLICY_BINDING_INVALID,
                    "/replay/runMode"
            ));
        }
        if (!Boolean.TRUE.equals(replay.contractApproved())) {
            mismatches.add(new Mismatch(
                    MismatchCode.REPLAY_POLICY_BINDING_INVALID,
                    "/replay/contractApproved"
            ));
        }
        if (replay.contractVersionId() == null) {
            mismatches.add(new Mismatch(
                    MismatchCode.REPLAY_POLICY_BINDING_INVALID,
                    "/replay/contractVersionId"
            ));
        }
        if (!isDigest(replay.contractHash())) {
            mismatches.add(new Mismatch(
                    MismatchCode.REPLAY_POLICY_BINDING_INVALID,
                    "/replay/contractHash"
            ));
        }
    }

    private <T> void compare(
            Fact fact,
            EnumSet<Fact> validBaselineFacts,
            EnumSet<Fact> validReplayFacts,
            ReplayComparisonFacts baseline,
            ReplayComparisonFacts replay,
            Function<ReplayComparisonFacts, T> extractor,
            MismatchCode mismatchCode,
            String path,
            List<Mismatch> mismatches
    ) {
        if (bothValid(fact, validBaselineFacts, validReplayFacts)
                && !Objects.equals(extractor.apply(baseline), extractor.apply(replay))) {
            mismatches.add(new Mismatch(mismatchCode, path));
        }
    }

    private boolean bothValid(
            Fact fact,
            EnumSet<Fact> validBaselineFacts,
            EnumSet<Fact> validReplayFacts
    ) {
        return validBaselineFacts.contains(fact) && validReplayFacts.contains(fact);
    }

    private void validateText(
            String value,
            Fact fact,
            String field,
            String pathPrefix,
            MismatchCode invalidCode,
            EnumSet<Fact> valid,
            List<Mismatch> mismatches
    ) {
        validate(value != null && !value.isBlank(), fact, field, pathPrefix, invalidCode, valid, mismatches);
    }

    private void validateDigest(
            String value,
            Fact fact,
            String field,
            String pathPrefix,
            MismatchCode invalidCode,
            EnumSet<Fact> valid,
            List<Mismatch> mismatches
    ) {
        validate(isDigest(value), fact, field, pathPrefix, invalidCode, valid, mismatches);
    }

    private void validate(
            boolean condition,
            Fact fact,
            String field,
            String pathPrefix,
            MismatchCode invalidCode,
            EnumSet<Fact> valid,
            List<Mismatch> mismatches
    ) {
        if (condition) {
            valid.add(fact);
        } else {
            mismatches.add(new Mismatch(invalidCode, pathPrefix + field));
        }
    }

    private boolean isDigest(String value) {
        return value != null && SHA_256.matcher(value).matches();
    }

    private ReplayComparabilityResult result(List<Mismatch> mismatches) {
        return new ReplayComparabilityResult(mismatches.isEmpty(), mismatches);
    }

    private enum Fact {
        RELEASE_ID,
        NAMESPACE_ID,
        INITIAL_STATE_DIGEST,
        AGENT_ARTIFACT_FINGERPRINT,
        MODEL_PROVIDER,
        MODEL_NAME,
        RESOLVED_MODEL_ID,
        MODEL_PARAMETERS_DIGEST,
        ATTACK_CASE_ID,
        VARIANT_HASH,
        TRIAL_INDEX,
        FIXTURE_VERSION,
        FIXTURE_DIGEST,
        RANDOM_SEED,
        PAIR_GROUP_ID,
        RUNTIME_CONTROLS_DIGEST,
        TOOL_SCHEMA_DIGEST,
        RAG_VERSION,
        RAG_CONFIG_DIGEST,
        RELEASE_FINGERPRINT
    }
}
