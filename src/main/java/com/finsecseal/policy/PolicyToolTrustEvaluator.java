package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEvaluationReason.TOOL_INTEGRITY_FAILURE;
import static com.finsecseal.policy.PolicyEvaluationReason.UNTRUSTED_TOOL;
import static com.finsecseal.policy.PolicyEvaluationStage.TOOL_TRUST;

import java.util.List;
import java.util.Optional;

import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;
import com.finsecseal.policy.PolicyToolTrustFacts.ReleaseToolBinding;
import com.finsecseal.policy.PolicyToolTrustFacts.ToolRegistryEntry;

/**
 * Deterministic integrity-first evaluation for only the Tool Trust policy stage.
 */
public final class PolicyToolTrustEvaluator {

    public StageOutcome evaluate(
            PolicyEvaluationStage stage,
            PolicyToolTrustFacts facts
    ) {
        if (stage == null) {
            throw new IllegalArgumentException("stage must not be null");
        }
        if (facts == null) {
            throw new IllegalArgumentException("facts must not be null");
        }
        if (stage != TOOL_TRUST) {
            throw new IllegalArgumentException(
                    "PolicyToolTrustEvaluator supports only TOOL_TRUST"
            );
        }

        if (!facts.releaseFingerprintMatches()) {
            return integrityFailure();
        }

        List<ReleaseToolBinding> bindings = facts.requestedReleaseBindings();
        if (bindings.size() != 1) {
            return integrityFailure();
        }

        ReleaseToolBinding binding = bindings.getFirst();
        if (!binding.enabled()) {
            return integrityFailure();
        }

        Optional<ToolRegistryEntry> registryEntry = facts.registryEntryFor(binding);
        if (registryEntry.isEmpty()) {
            return integrityFailure();
        }

        ToolRegistryEntry registry = registryEntry.orElseThrow();
        if (!binding.schemaDigest().equals(registry.schemaDigest())
                || !binding.descriptionDigest().equals(registry.descriptionDigest())) {
            return integrityFailure();
        }

        if (facts.trustPolicy().requireTrustedTool()
                && !facts.trustPolicy().allows(registry.trustLevel())) {
            return StageOutcome.deny(TOOL_TRUST, UNTRUSTED_TOOL);
        }

        return StageOutcome.pass(TOOL_TRUST);
    }

    private static StageOutcome integrityFailure() {
        return StageOutcome.error(TOOL_TRUST, TOOL_INTEGRITY_FAILURE);
    }
}
