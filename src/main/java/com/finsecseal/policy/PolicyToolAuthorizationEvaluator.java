package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEvaluationReason.OPERATION_NOT_ALLOWED;
import static com.finsecseal.policy.PolicyEvaluationReason.TOOL_NOT_ALLOWED;
import static com.finsecseal.policy.PolicyEvaluationStage.OPERATION;
import static com.finsecseal.policy.PolicyEvaluationStage.TOOL;

import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;

/**
 * Deterministic evaluation for only the Tool and Operation policy stages.
 */
public final class PolicyToolAuthorizationEvaluator {

    public StageOutcome evaluate(
            PolicyEvaluationStage stage,
            PolicyToolAuthorizationFacts facts
    ) {
        if (stage == null) {
            throw new IllegalArgumentException("stage must not be null");
        }
        if (facts == null) {
            throw new IllegalArgumentException("facts must not be null");
        }

        return switch (stage) {
            case TOOL -> evaluateTool(facts);
            case OPERATION -> evaluateOperation(facts);
            default -> throw new IllegalArgumentException(
                    "PolicyToolAuthorizationEvaluator supports only TOOL and OPERATION"
            );
        };
    }

    private StageOutcome evaluateTool(PolicyToolAuthorizationFacts facts) {
        return facts.requestedCatalogTool()
                .map(tool -> evaluateKnownTool(facts, tool))
                .orElseGet(() -> StageOutcome.deny(TOOL, TOOL_NOT_ALLOWED));
    }

    private StageOutcome evaluateKnownTool(
            PolicyToolAuthorizationFacts facts,
            PolicyToolAuthorizationFacts.CatalogTool tool
    ) {
        if (facts.isRequestedToolAllowed()) {
            return StageOutcome.pass(TOOL);
        }
        if (tool.externalEgressTool() && facts.externalEgressExplicitlyDenied()) {
            return StageOutcome.pass(TOOL);
        }
        if (facts.isRequestedToolHumanOnly()) {
            return StageOutcome.pass(TOOL);
        }
        return StageOutcome.deny(TOOL, TOOL_NOT_ALLOWED);
    }

    private StageOutcome evaluateOperation(PolicyToolAuthorizationFacts facts) {
        return facts.requestedCatalogTool()
                .filter(tool -> tool.operation().equals(facts.requestedOperation()))
                .map(tool -> StageOutcome.pass(OPERATION))
                .orElseGet(() -> StageOutcome.deny(OPERATION, OPERATION_NOT_ALLOWED));
    }
}
