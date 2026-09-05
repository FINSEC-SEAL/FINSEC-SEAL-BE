package com.finsecseal.replay.policy;

import java.util.List;
import java.util.Objects;

public record ReplayComparabilityResult(boolean comparable, List<Mismatch> mismatches) {

    public ReplayComparabilityResult {
        mismatches = List.copyOf(Objects.requireNonNull(mismatches, "mismatches"));
        if (comparable != mismatches.isEmpty()) {
            throw new IllegalArgumentException("comparable must match whether mismatches are empty");
        }
    }

    public record Mismatch(MismatchCode code, String factPath) {
        public Mismatch {
            Objects.requireNonNull(code, "code");
            if (factPath == null || factPath.isBlank()) {
                throw new IllegalArgumentException("factPath must not be blank");
            }
        }
    }

    public enum MismatchCode {
        BASELINE_FACTS_MISSING,
        REPLAY_FACTS_MISSING,
        BASELINE_REQUIRED_FACT_INVALID,
        REPLAY_REQUIRED_FACT_INVALID,
        BASELINE_LIFECYCLE_INVALID,
        REPLAY_LIFECYCLE_INVALID,
        BASELINE_POLICY_BINDING_INVALID,
        REPLAY_POLICY_BINDING_INVALID,
        NAMESPACE_NOT_ISOLATED,
        RELEASE_MISMATCH,
        INITIAL_STATE_MISMATCH,
        AGENT_ARTIFACT_MISMATCH,
        MODEL_PROVIDER_MISMATCH,
        MODEL_NAME_MISMATCH,
        RESOLVED_MODEL_MISMATCH,
        MODEL_PARAMETERS_MISMATCH,
        ATTACK_CASE_MISMATCH,
        VARIANT_MISMATCH,
        TRIAL_INDEX_MISMATCH,
        FIXTURE_VERSION_MISMATCH,
        FIXTURE_DIGEST_MISMATCH,
        RANDOM_SEED_MISMATCH,
        PAIR_GROUP_MISMATCH,
        RUNTIME_CONTROLS_MISMATCH,
        TOOL_SCHEMA_MISMATCH,
        RAG_VERSION_MISMATCH,
        RAG_CONFIG_MISMATCH,
        POLICY_FINGERPRINT_NOT_DISTINCT
    }
}
