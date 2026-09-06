package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEvaluationReason.HUMAN_ONLY_ACTION;
import static com.finsecseal.policy.PolicyEvaluationStage.HUMAN_BOUNDARY;

import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;

/**
 * Deterministic evaluation for only the Human Approval Boundary policy stage.
 */
public final class PolicyHumanBoundaryEvaluator {

    public StageOutcome evaluate(
            PolicyEvaluationStage stage,
            PolicyHumanBoundaryFacts facts
    ) {
        if (stage == null) {
            throw new IllegalArgumentException("stage must not be null");
        }
        if (facts == null) {
            throw new IllegalArgumentException("facts must not be null");
        }
        if (stage != HUMAN_BOUNDARY) {
            throw new IllegalArgumentException(
                    "PolicyHumanBoundaryEvaluator supports only HUMAN_BOUNDARY"
            );
        }

        if (!facts.isRequestedToolCatalogKnown()) {
            throw new IllegalStateException(
                    "requested tool must be resolved by the Tool stage before Human Boundary"
            );
        }

        return facts.requestedHighImpactAction()
                .map(action -> switch (action.mode()) {
                    case HUMAN_ONLY -> StageOutcome.deny(
                            HUMAN_BOUNDARY,
                            HUMAN_ONLY_ACTION
                    );
                })
                .orElseGet(() -> StageOutcome.pass(HUMAN_BOUNDARY));
    }
}
