package com.finsecseal.policy;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;

/**
 * Executes preflight and policy checks lazily in the authoritative fixed order.
 */
public final class PolicyEvaluationSequence {

    private PolicyEvaluationSequence() {
    }

    public static PolicyEvaluationDecision evaluate(
            PreflightEvaluator preflightEvaluator,
            PolicyStageEvaluator policyStageEvaluator
    ) {
        Objects.requireNonNull(preflightEvaluator, "preflightEvaluator must not be null");
        Objects.requireNonNull(policyStageEvaluator, "policyStageEvaluator must not be null");

        List<PolicyEvaluationStage> evaluatedStages = new ArrayList<>();

        StageOutcome preflight = invoke(
                PolicyEvaluationStage.PREFLIGHT,
                preflightEvaluator::evaluate
        );
        evaluatedStages.add(PolicyEvaluationStage.PREFLIGHT);

        if (preflight.outcomeType() == PolicyEvaluationDecision.OutcomeType.ERROR) {
            return terminalDecision(preflight, evaluatedStages);
        }
        if (preflight.outcomeType() != PolicyEvaluationDecision.OutcomeType.PASS) {
            throw new PolicyEvaluationException(
                    PolicyEvaluationStage.PREFLIGHT,
                    "preflight may only PASS or produce an operational ERROR"
            );
        }

        for (PolicyEvaluationStage stage : PolicyEvaluationStage.policyOrder()) {
            StageOutcome outcome = invoke(stage, () -> policyStageEvaluator.evaluate(stage));
            evaluatedStages.add(stage);

            if (outcome.outcomeType() != PolicyEvaluationDecision.OutcomeType.PASS) {
                return terminalDecision(outcome, evaluatedStages);
            }
        }

        return PolicyEvaluationDecision.allow(evaluatedStages);
    }

    private static StageOutcome invoke(
            PolicyEvaluationStage expectedStage,
            OutcomeSupplier evaluator
    ) {
        StageOutcome outcome;
        try {
            outcome = evaluator.evaluate();
        } catch (RuntimeException exception) {
            throw new PolicyEvaluationException(
                    expectedStage,
                    "policy evaluator failed before returning a valid outcome",
                    exception
            );
        }

        if (outcome == null) {
            throw new PolicyEvaluationException(
                    expectedStage,
                    "policy evaluator returned no outcome"
            );
        }
        if (outcome.stage() != expectedStage) {
            throw new PolicyEvaluationException(
                    expectedStage,
                    "policy evaluator returned an outcome for a different stage"
            );
        }
        return outcome;
    }

    private static PolicyEvaluationDecision terminalDecision(
            StageOutcome outcome,
            List<PolicyEvaluationStage> evaluatedStages
    ) {
        PolicyEvaluationReason reason = outcome.reason().orElseThrow(() ->
                new PolicyEvaluationException(
                        outcome.stage(),
                        "terminal outcome did not contain a reason"
                )
        );
        try {
            return PolicyEvaluationDecision.terminal(reason, outcome.stage(), evaluatedStages);
        } catch (RuntimeException exception) {
            throw new PolicyEvaluationException(
                    outcome.stage(),
                    "terminal outcome could not produce a valid decision",
                    exception
            );
        }
    }

    @FunctionalInterface
    public interface PreflightEvaluator {
        StageOutcome evaluate();
    }

    @FunctionalInterface
    public interface PolicyStageEvaluator {
        StageOutcome evaluate(PolicyEvaluationStage stage);
    }

    @FunctionalInterface
    private interface OutcomeSupplier {
        StageOutcome evaluate();
    }

    public static final class PolicyEvaluationException extends RuntimeException {

        private final PolicyEvaluationStage stage;

        public PolicyEvaluationException(PolicyEvaluationStage stage, String message) {
            super(message);
            this.stage = Objects.requireNonNull(stage, "stage must not be null");
        }

        public PolicyEvaluationException(
                PolicyEvaluationStage stage,
                String message,
                Throwable cause
        ) {
            super(message, cause);
            this.stage = Objects.requireNonNull(stage, "stage must not be null");
        }

        public PolicyEvaluationStage stage() {
            return stage;
        }
    }
}
