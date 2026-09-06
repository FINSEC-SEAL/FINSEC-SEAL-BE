package com.finsecseal.policy;

import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import tools.jackson.databind.JsonNode;

/**
 * Immutable result of the ENFORCE-only post-call response boundary.
 */
public record EnforcePolicyPostCallDecision(
        Outcome outcome,
        Optional<OperationalReason> reason,
        Optional<PostCallCheck> failedCheck,
        List<PostCallCheck> evaluatedChecks,
        Optional<JsonNode> deliverableOutput
) {

    public EnforcePolicyPostCallDecision {
        Objects.requireNonNull(outcome, "outcome must not be null");
        Objects.requireNonNull(reason, "reason must not be null");
        Objects.requireNonNull(failedCheck, "failedCheck must not be null");
        evaluatedChecks = List.copyOf(Objects.requireNonNull(
                evaluatedChecks,
                "evaluatedChecks must not be null"
        ));
        Objects.requireNonNull(
                deliverableOutput,
                "deliverableOutput must not be null"
        );
        deliverableOutput = deliverableOutput.map(JsonNode::deepCopy);

        validateExactPrefix(evaluatedChecks);
        if (outcome == Outcome.PASS) {
            if (reason.isPresent() || failedCheck.isPresent()) {
                throw new IllegalArgumentException(
                        "PASS must not contain operational failure evidence"
                );
            }
            if (!evaluatedChecks.equals(PostCallCheck.completeOrder())) {
                throw new IllegalArgumentException(
                        "PASS requires the complete post-call check order"
                );
            }
            if (deliverableOutput.isEmpty()) {
                throw new IllegalArgumentException("PASS requires deliverable output");
            }
        } else {
            OperationalReason terminalReason = reason.orElseThrow(
                    () -> new IllegalArgumentException("QUARANTINE requires a reason")
            );
            PostCallCheck terminalCheck = failedCheck.orElseThrow(
                    () -> new IllegalArgumentException("QUARANTINE requires a failed check")
            );
            if (evaluatedChecks.getLast() != terminalCheck) {
                throw new IllegalArgumentException(
                        "failed check must be the last evaluated check"
                );
            }
            if (!terminalReason.isAllowedAt(terminalCheck)) {
                throw new IllegalArgumentException(
                        "reason is not valid for the failed check"
                );
            }
            if (deliverableOutput.isPresent()) {
                throw new IllegalArgumentException(
                        "QUARANTINE must not contain deliverable output"
                );
            }
        }
    }

    public static EnforcePolicyPostCallDecision pass(JsonNode response) {
        return new EnforcePolicyPostCallDecision(
                Outcome.PASS,
                Optional.empty(),
                Optional.empty(),
                PostCallCheck.completeOrder(),
                Optional.ofNullable(response)
        );
    }

    public static EnforcePolicyPostCallDecision quarantine(
            PostCallCheck failedCheck,
            OperationalReason reason,
            List<PostCallCheck> evaluatedChecks
    ) {
        return new EnforcePolicyPostCallDecision(
                Outcome.QUARANTINE,
                Optional.ofNullable(reason),
                Optional.ofNullable(failedCheck),
                evaluatedChecks,
                Optional.empty()
        );
    }

    @Override
    public Optional<JsonNode> deliverableOutput() {
        return deliverableOutput.map(JsonNode::deepCopy);
    }

    /**
     * Adapter failures are operational failures and never attack-block credit.
     */
    public boolean successfulSecurityBlock() {
        return false;
    }

    public boolean operationalFailure() {
        return outcome == Outcome.QUARANTINE;
    }

    private static void validateExactPrefix(List<PostCallCheck> evaluatedChecks) {
        List<PostCallCheck> completeOrder = PostCallCheck.completeOrder();
        if (evaluatedChecks.isEmpty() || evaluatedChecks.size() > completeOrder.size()) {
            throw new IllegalArgumentException(
                    "evaluated checks must be a non-empty sequence prefix"
            );
        }
        if (!evaluatedChecks.equals(completeOrder.subList(0, evaluatedChecks.size()))) {
            throw new IllegalArgumentException(
                    "evaluated checks must follow the exact post-call sequence"
            );
        }
    }

    public enum Outcome {
        PASS,
        QUARANTINE
    }

    public enum PostCallCheck {
        OUTPUT_SCHEMA,
        CLASSIFICATION,
        OBJECT_SCOPE,
        FIELD_PROJECTION,
        RETURNED_CARDINALITY,
        STATE_DELTA_PROVENANCE;

        private static final List<PostCallCheck> COMPLETE_ORDER = List.of(values());

        public static List<PostCallCheck> completeOrder() {
            return COMPLETE_ORDER;
        }
    }

    public enum OperationalReason {
        ADAPTER_CONTRACT_FAILURE(EnumSet.of(
                PostCallCheck.OUTPUT_SCHEMA,
                PostCallCheck.CLASSIFICATION,
                PostCallCheck.OBJECT_SCOPE,
                PostCallCheck.FIELD_PROJECTION,
                PostCallCheck.STATE_DELTA_PROVENANCE
        )),
        RESPONSE_CARDINALITY_VIOLATION(EnumSet.of(
                PostCallCheck.RETURNED_CARDINALITY
        ));

        private final Set<PostCallCheck> allowedChecks;

        OperationalReason(Set<PostCallCheck> allowedChecks) {
            this.allowedChecks = Set.copyOf(allowedChecks);
        }

        public Set<PostCallCheck> allowedChecks() {
            return allowedChecks;
        }

        public boolean isAllowedAt(PostCallCheck check) {
            return check != null && allowedChecks.contains(check);
        }
    }
}
