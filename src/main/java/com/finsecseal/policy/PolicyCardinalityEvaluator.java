package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEvaluationReason.RECORD_LIMIT_EXCEEDED;
import static com.finsecseal.policy.PolicyEvaluationStage.CARDINALITY;

import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;

/**
 * Deterministic evaluation for only the pre-call Cardinality policy stage.
 */
public final class PolicyCardinalityEvaluator {

    public StageOutcome evaluate(
            PolicyEvaluationStage stage,
            PolicyCardinalityFacts facts
    ) {
        if (stage == null) {
            throw new IllegalArgumentException("stage must not be null");
        }
        if (facts == null) {
            throw new IllegalArgumentException("facts must not be null");
        }
        if (stage != CARDINALITY) {
            throw new IllegalArgumentException(
                    "PolicyCardinalityEvaluator supports only CARDINALITY"
            );
        }

        if (!facts.isRequestedToolCatalogKnown()) {
            throw new IllegalStateException(
                    "requested tool must be resolved by the Tool stage before Cardinality"
            );
        }

        return facts.requestedCardinalityPolicy()
                .filter(policy -> facts.normalizedRequestedRecordCount()
                        > policy.maxRequestedRecords())
                .map(policy -> StageOutcome.deny(CARDINALITY, RECORD_LIMIT_EXCEEDED))
                .orElseGet(() -> StageOutcome.pass(CARDINALITY));
    }
}
