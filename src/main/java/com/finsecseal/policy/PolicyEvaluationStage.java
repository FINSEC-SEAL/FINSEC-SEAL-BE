package com.finsecseal.policy;

import java.util.List;

/**
 * Deterministic stages evaluated before a tool invocation is allowed.
 */
public enum PolicyEvaluationStage {
    PREFLIGHT,
    TOOL,
    OPERATION,
    BUSINESS_CONTEXT,
    OBJECT_SCOPE,
    FIELD_SCOPE,
    CARDINALITY,
    EGRESS,
    WORKFLOW,
    HUMAN_BOUNDARY,
    TOOL_TRUST;

    private static final List<PolicyEvaluationStage> POLICY_ORDER = List.of(
            TOOL,
            OPERATION,
            BUSINESS_CONTEXT,
            OBJECT_SCOPE,
            FIELD_SCOPE,
            CARDINALITY,
            EGRESS,
            WORKFLOW,
            HUMAN_BOUNDARY,
            TOOL_TRUST
    );

    private static final List<PolicyEvaluationStage> COMPLETE_ORDER = List.of(values());

    public static List<PolicyEvaluationStage> policyOrder() {
        return POLICY_ORDER;
    }

    public static List<PolicyEvaluationStage> completeOrder() {
        return COMPLETE_ORDER;
    }
}
