package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEvaluationReason.CASE_SCOPE_VIOLATION;
import static com.finsecseal.policy.PolicyEvaluationReason.CUSTOMER_SCOPE_VIOLATION;
import static com.finsecseal.policy.PolicyEvaluationReason.DOCUMENT_SCOPE_VIOLATION;
import static com.finsecseal.policy.PolicyEvaluationStage.OBJECT_SCOPE;

import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;
import com.finsecseal.policy.PolicyObjectScopeFacts.ObjectScopePolicy;

/**
 * Deterministic evaluation for only the Object Scope policy stage.
 */
public final class PolicyObjectScopeEvaluator {

    public StageOutcome evaluate(
            PolicyEvaluationStage stage,
            PolicyObjectScopeFacts facts
    ) {
        if (stage == null) {
            throw new IllegalArgumentException("stage must not be null");
        }
        if (facts == null) {
            throw new IllegalArgumentException("facts must not be null");
        }
        if (stage != OBJECT_SCOPE) {
            throw new IllegalArgumentException(
                    "PolicyObjectScopeEvaluator supports only OBJECT_SCOPE"
            );
        }
        if (!facts.isRequestedToolCatalogKnown()) {
            throw new IllegalStateException(
                    "requested tool must be resolved by the Tool stage before Object Scope"
            );
        }

        ObjectScopePolicy policy = facts.requestedScopePolicy().orElse(null);
        if (policy == null) {
            return StageOutcome.pass(OBJECT_SCOPE);
        }

        if (policy.currentCaseOnly()
                && !facts.requestedCaseId().orElseThrow()
                .equals(facts.currentCaseId().orElseThrow())) {
            return StageOutcome.deny(OBJECT_SCOPE, CASE_SCOPE_VIOLATION);
        }

        if (policy.allowedDocumentsOnly()) {
            for (String documentId : facts.requestedDocumentIds().orElseThrow()) {
                if (!facts.allowedDocumentIds().orElseThrow().contains(documentId)) {
                    return StageOutcome.deny(
                            OBJECT_SCOPE,
                            DOCUMENT_SCOPE_VIOLATION
                    );
                }
            }
        }

        if (policy.currentApplicantOnly()) {
            String currentApplicantId = facts.currentApplicantId().orElseThrow();
            for (String customerId : facts.requestedCustomerIds().orElseThrow()) {
                if (!currentApplicantId.equals(customerId)) {
                    return StageOutcome.deny(
                            OBJECT_SCOPE,
                            CUSTOMER_SCOPE_VIOLATION
                    );
                }
            }
        }

        return StageOutcome.pass(OBJECT_SCOPE);
    }
}
