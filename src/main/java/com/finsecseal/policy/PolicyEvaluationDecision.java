package com.finsecseal.policy;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable evidence produced by the deterministic pre-call evaluation sequence.
 */
public record PolicyEvaluationDecision(
        DecisionType decisionType,
        Optional<PolicyEvaluationReason> reason,
        Optional<PolicyEvaluationStage> failedStage,
        List<PolicyEvaluationStage> evaluatedStages
) {

    public PolicyEvaluationDecision {
        Objects.requireNonNull(decisionType, "decisionType must not be null");
        Objects.requireNonNull(reason, "reason must not be null");
        Objects.requireNonNull(failedStage, "failedStage must not be null");
        evaluatedStages = List.copyOf(Objects.requireNonNull(
                evaluatedStages,
                "evaluatedStages must not be null"
        ));

        validateExactPrefix(evaluatedStages);

        if (decisionType == DecisionType.ALLOW) {
            if (reason.isPresent() || failedStage.isPresent()) {
                throw new IllegalArgumentException("ALLOW must not contain terminal evidence");
            }
            if (!evaluatedStages.equals(PolicyEvaluationStage.completeOrder())) {
                throw new IllegalArgumentException("ALLOW requires the complete evaluation order");
            }
        } else {
            PolicyEvaluationReason terminalReason = reason.orElseThrow(
                    () -> new IllegalArgumentException("terminal decision requires a reason")
            );
            PolicyEvaluationStage terminalStage = failedStage.orElseThrow(
                    () -> new IllegalArgumentException("terminal decision requires a failed stage")
            );

            if (evaluatedStages.getLast() != terminalStage) {
                throw new IllegalArgumentException("failed stage must be the last evaluated stage");
            }
            if (!terminalReason.isAllowedAt(terminalStage)) {
                throw new IllegalArgumentException("reason is not valid for the failed stage");
            }

            DecisionType expectedType = switch (terminalReason.classification()) {
                case DENY -> DecisionType.DENY;
                case ERROR -> DecisionType.ERROR;
            };
            if (decisionType != expectedType) {
                throw new IllegalArgumentException("reason classification does not match decision type");
            }
        }
    }

    public static PolicyEvaluationDecision allow(List<PolicyEvaluationStage> evaluatedStages) {
        return new PolicyEvaluationDecision(
                DecisionType.ALLOW,
                Optional.empty(),
                Optional.empty(),
                evaluatedStages
        );
    }

    public static PolicyEvaluationDecision terminal(
            PolicyEvaluationReason reason,
            PolicyEvaluationStage failedStage,
            List<PolicyEvaluationStage> evaluatedStages
    ) {
        Objects.requireNonNull(reason, "reason must not be null");
        DecisionType decisionType = switch (reason.classification()) {
            case DENY -> DecisionType.DENY;
            case ERROR -> DecisionType.ERROR;
        };
        return new PolicyEvaluationDecision(
                decisionType,
                Optional.of(reason),
                Optional.ofNullable(failedStage),
                evaluatedStages
        );
    }

    public boolean successfulSecurityBlock() {
        return decisionType == DecisionType.DENY;
    }

    private static void validateExactPrefix(List<PolicyEvaluationStage> evaluatedStages) {
        List<PolicyEvaluationStage> completeOrder = PolicyEvaluationStage.completeOrder();
        if (evaluatedStages.isEmpty() || evaluatedStages.size() > completeOrder.size()) {
            throw new IllegalArgumentException("evaluated stages must be a non-empty sequence prefix");
        }
        if (!evaluatedStages.equals(completeOrder.subList(0, evaluatedStages.size()))) {
            throw new IllegalArgumentException("evaluated stages must follow the exact sequence prefix");
        }
    }

    public enum DecisionType {
        ALLOW,
        DENY,
        ERROR
    }

    public record StageOutcome(
            PolicyEvaluationStage stage,
            OutcomeType outcomeType,
            Optional<PolicyEvaluationReason> reason
    ) {

        public StageOutcome {
            Objects.requireNonNull(stage, "stage must not be null");
            Objects.requireNonNull(outcomeType, "outcomeType must not be null");
            Objects.requireNonNull(reason, "reason must not be null");

            if (outcomeType == OutcomeType.PASS) {
                if (reason.isPresent()) {
                    throw new IllegalArgumentException("PASS must not contain a terminal reason");
                }
            } else {
                PolicyEvaluationReason terminalReason = reason.orElseThrow(
                        () -> new IllegalArgumentException("terminal outcome requires a reason")
                );
                if (!terminalReason.isAllowedAt(stage)) {
                    throw new IllegalArgumentException("reason is not valid for the outcome stage");
                }

                OutcomeType expectedType = switch (terminalReason.classification()) {
                    case DENY -> OutcomeType.DENY;
                    case ERROR -> OutcomeType.ERROR;
                };
                if (outcomeType != expectedType) {
                    throw new IllegalArgumentException(
                            "reason classification does not match outcome type"
                    );
                }
            }
        }

        public static StageOutcome pass(PolicyEvaluationStage stage) {
            return new StageOutcome(stage, OutcomeType.PASS, Optional.empty());
        }

        public static StageOutcome deny(
                PolicyEvaluationStage stage,
                PolicyEvaluationReason reason
        ) {
            return new StageOutcome(stage, OutcomeType.DENY, Optional.ofNullable(reason));
        }

        public static StageOutcome error(
                PolicyEvaluationStage stage,
                PolicyEvaluationReason reason
        ) {
            return new StageOutcome(stage, OutcomeType.ERROR, Optional.ofNullable(reason));
        }
    }

    public enum OutcomeType {
        PASS,
        DENY,
        ERROR
    }
}
