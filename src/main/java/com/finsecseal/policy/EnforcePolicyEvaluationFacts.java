package com.finsecseal.policy;

import java.util.Objects;

/**
 * Immutable policy inputs supplied by the trusted integration boundary. This aggregate does
 * not establish approval, source provenance or runtime authority by itself.
 */
public record EnforcePolicyEvaluationFacts(
        PolicyToolAuthorizationFacts authorization,
        PolicyBusinessContextFacts businessContext,
        PolicyObjectScopeFacts objectScope,
        PolicyFieldScopeFacts fieldScope,
        PolicyCardinalityFacts cardinality,
        PolicyEgressFacts egress,
        PolicyWorkflowFacts workflow,
        PolicyHumanBoundaryFacts humanBoundary,
        PolicyToolTrustFacts toolTrust
) {

    public EnforcePolicyEvaluationFacts {
        Objects.requireNonNull(authorization, "authorization");
        Objects.requireNonNull(businessContext, "businessContext");
        Objects.requireNonNull(objectScope, "objectScope");
        Objects.requireNonNull(fieldScope, "fieldScope");
        Objects.requireNonNull(cardinality, "cardinality");
        Objects.requireNonNull(egress, "egress");
        Objects.requireNonNull(workflow, "workflow");
        Objects.requireNonNull(humanBoundary, "humanBoundary");
        Objects.requireNonNull(toolTrust, "toolTrust");
    }
}
