package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEgressFacts.EgressClassification.EXTERNAL;
import static com.finsecseal.policy.PolicyEvaluationReason.EXTERNAL_EGRESS_DENIED;
import static com.finsecseal.policy.PolicyEvaluationStage.EGRESS;

import com.finsecseal.policy.PolicyEgressFacts.CatalogTool;
import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;

/**
 * Deterministic evaluation for only the Egress policy stage.
 */
public final class PolicyEgressEvaluator {

    public StageOutcome evaluate(PolicyEvaluationStage stage, PolicyEgressFacts facts) {
        if (stage == null) {
            throw new IllegalArgumentException("stage must not be null");
        }
        if (facts == null) {
            throw new IllegalArgumentException("facts must not be null");
        }
        if (stage != EGRESS) {
            throw new IllegalArgumentException("PolicyEgressEvaluator supports only EGRESS");
        }

        CatalogTool tool = facts.requestedCatalogTool()
                .orElseThrow(() -> new IllegalStateException(
                        "requested tool must be resolved by the Tool stage before Egress"
                ));

        if (tool.egressClassification() == EXTERNAL) {
            return StageOutcome.deny(EGRESS, EXTERNAL_EGRESS_DENIED);
        }
        return StageOutcome.pass(EGRESS);
    }
}
