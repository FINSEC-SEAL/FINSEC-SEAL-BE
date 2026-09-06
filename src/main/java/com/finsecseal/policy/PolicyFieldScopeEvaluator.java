package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEvaluationReason.FIELD_SCOPE_VIOLATION;
import static com.finsecseal.policy.PolicyEvaluationStage.FIELD_SCOPE;

import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;
import com.finsecseal.policy.PolicyFieldScopeFacts.FieldPolicy;

/**
 * Deterministic evaluation for only the pre-call Field Scope policy stage.
 */
public final class PolicyFieldScopeEvaluator {

    public StageOutcome evaluate(
            PolicyEvaluationStage stage,
            PolicyFieldScopeFacts facts
    ) {
        if (stage == null) {
            throw new IllegalArgumentException("stage must not be null");
        }
        if (facts == null) {
            throw new IllegalArgumentException("facts must not be null");
        }
        if (stage != FIELD_SCOPE) {
            throw new IllegalArgumentException(
                    "PolicyFieldScopeEvaluator supports only FIELD_SCOPE"
            );
        }
        if (!facts.isRequestedToolCatalogKnown()) {
            throw new IllegalStateException(
                    "requested tool must be resolved by the Tool stage before Field Scope"
            );
        }

        FieldPolicy policy = facts.requestedFieldPolicy().orElse(null);
        if (policy == null) {
            return StageOutcome.pass(FIELD_SCOPE);
        }

        for (String requestedField : facts.requestedFields().orElseThrow()) {
            if (!policy.allowedFields().contains(requestedField)) {
                return StageOutcome.deny(
                        FIELD_SCOPE,
                        FIELD_SCOPE_VIOLATION
                );
            }
        }
        return StageOutcome.pass(FIELD_SCOPE);
    }
}
