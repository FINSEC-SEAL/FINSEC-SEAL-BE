package com.finsecseal.policy;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import static com.finsecseal.policy.PolicyEvaluationReason.TerminalClassification.DENY;
import static com.finsecseal.policy.PolicyEvaluationReason.TerminalClassification.ERROR;
import static com.finsecseal.policy.PolicyEvaluationStage.BUSINESS_CONTEXT;
import static com.finsecseal.policy.PolicyEvaluationStage.CARDINALITY;
import static com.finsecseal.policy.PolicyEvaluationStage.EGRESS;
import static com.finsecseal.policy.PolicyEvaluationStage.FIELD_SCOPE;
import static com.finsecseal.policy.PolicyEvaluationStage.HUMAN_BOUNDARY;
import static com.finsecseal.policy.PolicyEvaluationStage.OBJECT_SCOPE;
import static com.finsecseal.policy.PolicyEvaluationStage.OPERATION;
import static com.finsecseal.policy.PolicyEvaluationStage.PREFLIGHT;
import static com.finsecseal.policy.PolicyEvaluationStage.TOOL;
import static com.finsecseal.policy.PolicyEvaluationStage.TOOL_TRUST;
import static com.finsecseal.policy.PolicyEvaluationStage.WORKFLOW;

/**
 * In-scope pre-call terminal reasons and their authoritative classification/stage binding.
 */
public enum PolicyEvaluationReason {
    INVALID_REQUEST_SCHEMA(ERROR, PREFLIGHT),
    CONTEXT_INTEGRITY_FAILURE(ERROR, PREFLIGHT, BUSINESS_CONTEXT),
    CONTRACT_NOT_APPROVED(ERROR, PREFLIGHT),
    RELEASE_FINGERPRINT_MISMATCH(ERROR, PREFLIGHT),
    POLICY_EVALUATION_TIMEOUT(ERROR, PREFLIGHT),

    TOOL_NOT_ALLOWED(DENY, TOOL),
    OPERATION_NOT_ALLOWED(DENY, OPERATION),
    CASE_SCOPE_VIOLATION(DENY, OBJECT_SCOPE),
    DOCUMENT_SCOPE_VIOLATION(DENY, OBJECT_SCOPE),
    CUSTOMER_SCOPE_VIOLATION(DENY, OBJECT_SCOPE),
    FIELD_SCOPE_VIOLATION(DENY, FIELD_SCOPE),
    RECORD_LIMIT_EXCEEDED(DENY, CARDINALITY),
    EXTERNAL_EGRESS_DENIED(DENY, EGRESS),
    INVALID_WORKFLOW_STAGE(DENY, WORKFLOW),
    HUMAN_ONLY_ACTION(DENY, HUMAN_BOUNDARY),
    UNTRUSTED_TOOL(DENY, TOOL_TRUST),
    TOOL_INTEGRITY_FAILURE(ERROR, TOOL_TRUST);

    private final TerminalClassification classification;
    private final Set<PolicyEvaluationStage> allowedStages;

    PolicyEvaluationReason(
            TerminalClassification classification,
            PolicyEvaluationStage firstStage,
            PolicyEvaluationStage... additionalStages
    ) {
        this.classification = classification;
        EnumSet<PolicyEvaluationStage> stages = EnumSet.of(firstStage, additionalStages);
        this.allowedStages = Collections.unmodifiableSet(stages);
    }

    public TerminalClassification classification() {
        return classification;
    }

    public Set<PolicyEvaluationStage> allowedStages() {
        return allowedStages;
    }

    public boolean isAllowedAt(PolicyEvaluationStage stage) {
        return stage != null && allowedStages.contains(stage);
    }

    public enum TerminalClassification {
        DENY,
        ERROR
    }
}
