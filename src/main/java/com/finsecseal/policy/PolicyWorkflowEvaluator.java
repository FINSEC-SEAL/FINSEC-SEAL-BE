package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEvaluationReason.INVALID_WORKFLOW_STAGE;
import static com.finsecseal.policy.PolicyEvaluationStage.WORKFLOW;

import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;

/**
 * Deterministic evaluation for only the Workflow policy stage.
 */
public final class PolicyWorkflowEvaluator {

    public StageOutcome evaluate(
            PolicyEvaluationStage stage,
            PolicyWorkflowFacts facts
    ) {
        if (stage == null) {
            throw new IllegalArgumentException("stage must not be null");
        }
        if (facts == null) {
            throw new IllegalArgumentException("facts must not be null");
        }
        if (stage != WORKFLOW) {
            throw new IllegalArgumentException(
                    "PolicyWorkflowEvaluator supports only WORKFLOW"
            );
        }

        PolicyWorkflowFacts.CatalogTool tool = facts.requestedCatalogTool()
                .orElseThrow(() -> new IllegalStateException(
                        "requested tool must be resolved by the Tool stage before Workflow"
                ));

        if (facts.isServerWorkflowStageAllowed() || tool.workflowBootstrap()) {
            return StageOutcome.pass(WORKFLOW);
        }
        return StageOutcome.deny(WORKFLOW, INVALID_WORKFLOW_STAGE);
    }
}
