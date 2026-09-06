package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEvaluationReason.CONTEXT_INTEGRITY_FAILURE;
import static com.finsecseal.policy.PolicyEvaluationStage.BUSINESS_CONTEXT;

import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Deterministic evaluation for only the Business Context policy stage.
 */
public final class PolicyBusinessContextEvaluator {

    public StageOutcome evaluate(
            PolicyEvaluationStage stage,
            PolicyBusinessContextFacts facts
    ) {
        if (stage == null) {
            throw new IllegalArgumentException("stage must not be null");
        }
        if (facts == null) {
            throw new IllegalArgumentException("facts must not be null");
        }
        if (stage != BUSINESS_CONTEXT) {
            throw new IllegalArgumentException(
                    "PolicyBusinessContextEvaluator supports only BUSINESS_CONTEXT"
            );
        }

        if (!facts.serverResolved()
                || !hasText(facts.contractPurpose())
                || !hasText(facts.releasePurpose())
                || !hasText(facts.runPurpose())
                || !hasText(facts.casePurpose())
                || !hasText(facts.namespaceId())
                || !hasText(facts.caseId())
                || !hasText(facts.currentApplicantId())
                || !hasText(facts.workflowStage())
                || facts.allowedDocumentIds().isEmpty()) {
            return integrityError();
        }

        String expectedPurpose = facts.contractPurpose().orElseThrow();
        if (!expectedPurpose.equals(facts.releasePurpose().orElseThrow())
                || !expectedPurpose.equals(facts.runPurpose().orElseThrow())
                || !expectedPurpose.equals(facts.casePurpose().orElseThrow())
                || !validDocumentIds(facts.allowedDocumentIds().orElseThrow())) {
            return integrityError();
        }

        return StageOutcome.pass(BUSINESS_CONTEXT);
    }

    private boolean hasText(Optional<String> value) {
        return value.isPresent() && !value.orElseThrow().isBlank();
    }

    private boolean validDocumentIds(List<String> documentIds) {
        Set<String> unique = new HashSet<>();
        for (String documentId : documentIds) {
            if (documentId == null || documentId.isBlank() || !unique.add(documentId)) {
                return false;
            }
        }
        return true;
    }

    private StageOutcome integrityError() {
        return StageOutcome.error(BUSINESS_CONTEXT, CONTEXT_INTEGRITY_FAILURE);
    }
}
