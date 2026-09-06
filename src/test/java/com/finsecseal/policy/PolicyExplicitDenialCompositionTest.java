package com.finsecseal.policy;

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
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * C-GW-002/003 and decision portions of TC-GW-001/005/006.
 * Only Tool, Operation, Egress and Human evaluators are composed here. Other stages
 * explicitly return PASS; these tests do not establish trusted preflight or adapter enforcement.
 */
class PolicyExplicitDenialCompositionTest {

    private static final String CUSTOMER = "CUSTOMER_DATA_READ";
    private static final String EXTERNAL = "EXTERNAL_HTTP";
    private static final String HUMAN = "LOAN_DECISION_UPDATE";
    private static final List<PolicyEvaluationStage> SPEC_ORDER = List.of(
            PREFLIGHT, TOOL, OPERATION, BUSINESS_CONTEXT, OBJECT_SCOPE, FIELD_SCOPE,
            CARDINALITY, EGRESS, WORKFLOW, HUMAN_BOUNDARY, TOOL_TRUST
    );

    @ParameterizedTest(name = "{0}")
    @MethodSource("decisionCases")
    void preservesExplicitDenialsAndFirstFailureAcrossRealEvaluators(
            String description,
            String requestedTool,
            String requestedOperation,
            boolean explicitEgressDenial,
            List<String> allowedTools,
            PolicyEvaluationStage failedStage,
            PolicyEvaluationReason reason
    ) {
        var toolEvaluator = spy(new PolicyToolAuthorizationEvaluator());
        var egressEvaluator = spy(new PolicyEgressEvaluator());
        var humanEvaluator = spy(new PolicyHumanBoundaryEvaluator());
        var authorization = new PolicyToolAuthorizationFacts(
                requestedTool,
                requestedOperation,
                List.of(
                        new PolicyToolAuthorizationFacts.CatalogTool(CUSTOMER, "READ", false),
                        new PolicyToolAuthorizationFacts.CatalogTool(EXTERNAL, "SEND", true),
                        new PolicyToolAuthorizationFacts.CatalogTool(HUMAN, "UPDATE", false)
                ),
                allowedTools,
                explicitEgressDenial,
                List.of(HUMAN)
        );
        Map<PolicyEvaluationStage, Integer> stageCalls = new EnumMap<>(PolicyEvaluationStage.class);

        PolicyEvaluationDecision decision = PolicyEvaluationSequence.evaluate(
                () -> {
                    stageCalls.merge(PREFLIGHT, 1, Integer::sum);
                    return StageOutcome.pass(PREFLIGHT);
                },
                stage -> {
                    stageCalls.merge(stage, 1, Integer::sum);
                    return switch (stage) {
                        case TOOL, OPERATION -> toolEvaluator.evaluate(stage, authorization);
                        case EGRESS -> egressEvaluator.evaluate(stage, new PolicyEgressFacts(
                                requestedTool,
                                List.of(
                                        new PolicyEgressFacts.CatalogTool(CUSTOMER,
                                                PolicyEgressFacts.EgressClassification.INTERNAL),
                                        new PolicyEgressFacts.CatalogTool(EXTERNAL,
                                                PolicyEgressFacts.EgressClassification.EXTERNAL),
                                        new PolicyEgressFacts.CatalogTool(HUMAN,
                                                PolicyEgressFacts.EgressClassification.INTERNAL)
                                ),
                                false,
                                List.of()
                        ));
                        case HUMAN_BOUNDARY -> humanEvaluator.evaluate(stage,
                                new PolicyHumanBoundaryFacts(
                                        requestedTool,
                                        List.of(CUSTOMER, EXTERNAL, HUMAN),
                                        List.of(new PolicyHumanBoundaryFacts.HighImpactAction(
                                                HUMAN,
                                                PolicyHumanBoundaryFacts.BoundaryMode.HUMAN_ONLY
                                        ))
                                ));
                        default -> StageOutcome.pass(stage);
                    };
                }
        );

        List<PolicyEvaluationStage> expectedOrder = failedStage == null
                ? SPEC_ORDER
                : SPEC_ORDER.subList(0, SPEC_ORDER.indexOf(failedStage) + 1);
        assertThat(decision.decisionType()).isEqualTo(failedStage == null
                ? PolicyEvaluationDecision.DecisionType.ALLOW
                : PolicyEvaluationDecision.DecisionType.DENY);
        assertThat(decision.reason()).isEqualTo(Optional.ofNullable(reason));
        assertThat(decision.failedStage()).isEqualTo(Optional.ofNullable(failedStage));
        assertThat(decision.evaluatedStages()).containsExactlyElementsOf(expectedOrder);
        for (PolicyEvaluationStage stage : SPEC_ORDER) {
            assertThat(stageCalls.getOrDefault(stage, 0))
                    .as("%s invocation count for %s", stage, description)
                    .isEqualTo(expectedOrder.contains(stage) ? 1 : 0);
        }

        // Verify calls on the real evaluators, not just the stage names recorded by the sequence.
        verify(toolEvaluator).evaluate(TOOL, authorization);
        verify(toolEvaluator, times(expectedOrder.contains(OPERATION) ? 1 : 0))
                .evaluate(OPERATION, authorization);
        verify(egressEvaluator, times(expectedOrder.contains(EGRESS) ? 1 : 0))
                .evaluate(eq(EGRESS), any(PolicyEgressFacts.class));
        verify(humanEvaluator, times(expectedOrder.contains(HUMAN_BOUNDARY) ? 1 : 0))
                .evaluate(eq(HUMAN_BOUNDARY), any(PolicyHumanBoundaryFacts.class));
        verifyNoMoreInteractions(toolEvaluator, egressEvaluator, humanEvaluator);
    }

    private static Stream<Arguments> decisionCases() {
        return Stream.of(
                Arguments.of("external deferral reaches actual Egress denial",
                        EXTERNAL, "SEND", true, List.of(CUSTOMER),
                        EGRESS, PolicyEvaluationReason.EXTERNAL_EGRESS_DENIED),
                Arguments.of("absent explicit rule denies at Tool",
                        EXTERNAL, "SEND", false, List.of(CUSTOMER),
                        TOOL, PolicyEvaluationReason.TOOL_NOT_ALLOWED),
                Arguments.of("unknown tool stays denied even if allowlisted",
                        "UNKNOWN_TOOL", "READ", true, List.of("UNKNOWN_TOOL"),
                        TOOL, PolicyEvaluationReason.TOOL_NOT_ALLOWED),
                Arguments.of("operation mismatch precedes external denial",
                        EXTERNAL, "READ", true, List.of(CUSTOMER),
                        OPERATION, PolicyEvaluationReason.OPERATION_NOT_ALLOWED),
                Arguments.of("human deferral reaches actual Human denial",
                        HUMAN, "UPDATE", true, List.of(CUSTOMER),
                        HUMAN_BOUNDARY, PolicyEvaluationReason.HUMAN_ONLY_ACTION),
                Arguments.of("operation mismatch precedes human denial",
                        HUMAN, "READ", true, List.of(CUSTOMER),
                        OPERATION, PolicyEvaluationReason.OPERATION_NOT_ALLOWED),
                Arguments.of("ordinary authorized internal tool passes composed stages",
                        CUSTOMER, "READ", true, List.of(CUSTOMER), null, null)
        );
    }
}
