package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEgressFacts.EgressClassification.EXTERNAL;
import static com.finsecseal.policy.PolicyEvaluationDecision.OutcomeType.PASS;
import static com.finsecseal.policy.PolicyEvaluationReason.CONTEXT_INTEGRITY_FAILURE;
import static com.finsecseal.policy.PolicyEvaluationStage.PREFLIGHT;

import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;
import com.finsecseal.policy.PolicyEvaluationSequence.PreflightEvaluator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Composes the existing policy judgments. The caller must provide authoritative preflight;
 * local consistency checks cannot prove stored approval or the provenance of supplied facts.
 * This class does not activate a gateway or invoke an adapter.
 */
public final class EnforcePolicyEvaluator {

    private final PolicyToolAuthorizationEvaluator authorization;
    private final PolicyBusinessContextEvaluator businessContext;
    private final PolicyObjectScopeEvaluator objectScope;
    private final PolicyFieldScopeEvaluator fieldScope;
    private final PolicyCardinalityEvaluator cardinality;
    private final PolicyEgressEvaluator egress;
    private final PolicyWorkflowEvaluator workflow;
    private final PolicyHumanBoundaryEvaluator humanBoundary;
    private final PolicyToolTrustEvaluator toolTrust;

    public EnforcePolicyEvaluator() {
        this(new PolicyToolAuthorizationEvaluator(), new PolicyBusinessContextEvaluator(),
                new PolicyObjectScopeEvaluator(), new PolicyFieldScopeEvaluator(),
                new PolicyCardinalityEvaluator(), new PolicyEgressEvaluator(),
                new PolicyWorkflowEvaluator(), new PolicyHumanBoundaryEvaluator(),
                new PolicyToolTrustEvaluator());
    }

    EnforcePolicyEvaluator(
            PolicyToolAuthorizationEvaluator authorization,
            PolicyBusinessContextEvaluator businessContext,
            PolicyObjectScopeEvaluator objectScope,
            PolicyFieldScopeEvaluator fieldScope,
            PolicyCardinalityEvaluator cardinality,
            PolicyEgressEvaluator egress,
            PolicyWorkflowEvaluator workflow,
            PolicyHumanBoundaryEvaluator humanBoundary,
            PolicyToolTrustEvaluator toolTrust
    ) {
        this.authorization = Objects.requireNonNull(authorization, "authorization");
        this.businessContext = Objects.requireNonNull(businessContext, "businessContext");
        this.objectScope = Objects.requireNonNull(objectScope, "objectScope");
        this.fieldScope = Objects.requireNonNull(fieldScope, "fieldScope");
        this.cardinality = Objects.requireNonNull(cardinality, "cardinality");
        this.egress = Objects.requireNonNull(egress, "egress");
        this.workflow = Objects.requireNonNull(workflow, "workflow");
        this.humanBoundary = Objects.requireNonNull(humanBoundary, "humanBoundary");
        this.toolTrust = Objects.requireNonNull(toolTrust, "toolTrust");
    }

    public PolicyEvaluationDecision evaluate(
            PreflightEvaluator preflight,
            EnforcePolicyEvaluationFacts facts
    ) {
        Objects.requireNonNull(preflight, "preflight");
        Objects.requireNonNull(facts, "facts");
        return PolicyEvaluationSequence.evaluate(
                () -> {
                    StageOutcome outcome = preflight.evaluate();
                    if (outcome == null || outcome.stage() != PREFLIGHT
                            || outcome.outcomeType() != PASS) {
                        return outcome;
                    }
                    return consistent(facts) ? outcome
                            : StageOutcome.error(PREFLIGHT, CONTEXT_INTEGRITY_FAILURE);
                },
                stage -> switch (stage) {
                    case TOOL, OPERATION -> authorization.evaluate(stage, facts.authorization());
                    case BUSINESS_CONTEXT -> businessContext.evaluate(stage, facts.businessContext());
                    case OBJECT_SCOPE -> objectScope.evaluate(stage, facts.objectScope());
                    case FIELD_SCOPE -> fieldScope.evaluate(stage, facts.fieldScope());
                    case CARDINALITY -> cardinality.evaluate(stage, facts.cardinality());
                    case EGRESS -> egress.evaluate(stage, facts.egress());
                    case WORKFLOW -> workflow.evaluate(stage, facts.workflow());
                    case HUMAN_BOUNDARY -> humanBoundary.evaluate(stage, facts.humanBoundary());
                    case TOOL_TRUST -> toolTrust.evaluate(stage, facts.toolTrust());
                    case PREFLIGHT -> throw new IllegalArgumentException("preflight is not a policy stage");
                }
        );
    }

    private static boolean consistent(EnforcePolicyEvaluationFacts facts) {
        String tool = facts.authorization().requestedTool();
        if (!List.of(facts.objectScope().requestedTool(), facts.fieldScope().requestedTool(),
                        facts.cardinality().requestedTool(), facts.egress().requestedTool(),
                        facts.workflow().requestedTool(), facts.humanBoundary().requestedTool(),
                        facts.toolTrust().requestedTool()).stream().allMatch(tool::equals)) {
            return false;
        }

        boolean known = facts.authorization().requestedCatalogTool().isPresent();
        if (known != facts.objectScope().isRequestedToolCatalogKnown()
                || known != facts.fieldScope().isRequestedToolCatalogKnown()
                || known != facts.cardinality().isRequestedToolCatalogKnown()
                || known != facts.egress().requestedCatalogTool().isPresent()
                || known != facts.workflow().requestedCatalogTool().isPresent()
                || known != facts.humanBoundary().isRequestedToolCatalogKnown()) {
            return false;
        }
        if (known && facts.authorization().requestedCatalogTool().orElseThrow().externalEgressTool()
                != (facts.egress().requestedCatalogTool().orElseThrow().egressClassification() == EXTERNAL)) {
            return false;
        }
        if (facts.authorization().isRequestedToolHumanOnly()
                != facts.humanBoundary().requestedHighImpactAction().isPresent()) {
            return false;
        }

        PolicyObjectScopeFacts object = facts.objectScope();
        PolicyBusinessContextFacts context = facts.businessContext();
        if (!agreesWhenPresent(object.currentCaseId(), context.caseId())
                || !agreesWhenPresent(object.currentApplicantId(), context.currentApplicantId())
                || !documentSetsAgree(object.allowedDocumentIds(), context.allowedDocumentIds())
                || !agreesWhenPresent(context.workflowStage(), Optional.of(facts.workflow().serverWorkflowStage()))) {
            return false;
        }
        return !tool.equals("CUSTOMER_DATA_READ") || object.requestedCustomerIds().isEmpty()
                || object.requestedCustomerIds().orElseThrow().size()
                == facts.cardinality().normalizedRequestedRecordCount();
    }

    private static <T> boolean agreesWhenPresent(Optional<T> value, Optional<T> counterpart) {
        return value.isEmpty() || value.equals(counterpart);
    }

    private static boolean documentSetsAgree(
            Optional<List<String>> objectDocuments,
            Optional<List<String>> contextDocuments
    ) {
        if (objectDocuments.isEmpty()) {
            return true;
        }
        if (contextDocuments.isEmpty()) {
            return false;
        }
        Set<String> contextSet = new HashSet<>();
        for (String document : contextDocuments.orElseThrow()) {
            if (document == null || document.isBlank() || !contextSet.add(document)) {
                return false;
            }
        }
        return contextSet.equals(new HashSet<>(objectDocuments.orElseThrow()));
    }
}
