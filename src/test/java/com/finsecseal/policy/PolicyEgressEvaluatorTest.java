package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEgressFacts.EgressClassification.EXTERNAL;
import static com.finsecseal.policy.PolicyEgressFacts.EgressClassification.INTERNAL;
import static com.finsecseal.policy.PolicyEvaluationDecision.DecisionType.DENY;
import static com.finsecseal.policy.PolicyEvaluationReason.EXTERNAL_EGRESS_DENIED;
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.policy.PolicyEgressFacts.CatalogTool;
import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;
import com.finsecseal.policy.PolicyEvaluationSequence.PolicyEvaluationException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class PolicyEgressEvaluatorTest {

    private static final String CUSTOMER_DATA_READ = "CUSTOMER_DATA_READ";
    private static final String EXTERNAL_HTTP = "EXTERNAL_HTTP";
    private static final String EXTERNAL_HTTP_MOCK = "EXTERNAL_HTTP_MOCK";

    private PolicyEgressEvaluator evaluator;

    @BeforeEach
    void setUp() {
        evaluator = new PolicyEgressEvaluator();
    }

    @Test
    void deniesExactCatalogToolExplicitlyClassifiedExternal() {
        assertThat(evaluator.evaluate(EGRESS, externalFacts()))
                .isEqualTo(StageOutcome.deny(EGRESS, EXTERNAL_EGRESS_DENIED));
    }

    @Test
    void passesOrdinaryCatalogToolExplicitlyClassifiedInternal() {
        PolicyEgressFacts facts = facts(
                CUSTOMER_DATA_READ,
                baseCatalog(),
                false,
                List.of()
        );

        assertThat(evaluator.evaluate(EGRESS, facts))
                .isEqualTo(StageOutcome.pass(EGRESS));
    }

    @Test
    void externalLookingNameClassifiedInternalDoesNotInferExternalEgress() {
        PolicyEgressFacts facts = facts(
                EXTERNAL_HTTP,
                List.of(new CatalogTool(EXTERNAL_HTTP, INTERNAL)),
                false,
                List.of()
        );

        assertThat(evaluator.evaluate(EGRESS, facts))
                .isEqualTo(StageOutcome.pass(EGRESS));
    }

    @Test
    void similarCatalogToolNameDoesNotInheritExternalClassification() {
        PolicyEgressFacts facts = facts(
                EXTERNAL_HTTP_MOCK,
                baseCatalog(),
                false,
                List.of()
        );

        assertThat(evaluator.evaluate(EGRESS, facts))
                .isEqualTo(StageOutcome.pass(EGRESS));
    }

    @ParameterizedTest
    @ValueSource(strings = {"UNKNOWN_TOOL", "external_http", "EXTERNAL_HTTP "})
    void unknownToolFailsCompositionBeforeEgressDecision(String requestedTool) {
        PolicyEgressFacts facts = facts(
                requestedTool,
                baseCatalog(),
                false,
                List.of()
        );

        assertThatThrownBy(() -> evaluator.evaluate(EGRESS, facts))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("requested tool must be resolved by the Tool stage before Egress");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t"})
    void rejectsNullOrBlankRequestedTool(String requestedTool) {
        assertThatThrownBy(() -> facts(
                requestedTool,
                baseCatalog(),
                false,
                List.of()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("requestedTool must not be blank");
    }

    @Test
    void rejectsExternalEgressEnablementInP0ContractFacts() {
        assertThatThrownBy(() -> facts(
                EXTERNAL_HTTP,
                baseCatalog(),
                true,
                List.of()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("P0 external egress must remain disabled");
    }

    @Test
    void rejectsEveryDestinationExceptionInP0ContractFacts() {
        assertThatThrownBy(() -> facts(
                EXTERNAL_HTTP,
                baseCatalog(),
                false,
                List.of("MOCK_COLLECTOR")
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("P0 destination exceptions are not supported");
    }

    @Test
    void validatesDestinationCollectionBeforeRejectingUnsupportedExceptions() {
        assertThatThrownBy(() -> facts(
                EXTERNAL_HTTP,
                baseCatalog(),
                false,
                null
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("allowedDestinations must not be null");

        List<String> nullMember = new ArrayList<>();
        nullMember.add(null);
        assertThatThrownBy(() -> facts(
                EXTERNAL_HTTP,
                baseCatalog(),
                false,
                nullMember
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("allowedDestinations[0] must not be blank");

        assertThatThrownBy(() -> facts(
                EXTERNAL_HTTP,
                baseCatalog(),
                false,
                List.of(" ")
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("allowedDestinations[0] must not be blank");

        assertThatThrownBy(() -> facts(
                EXTERNAL_HTTP,
                baseCatalog(),
                false,
                List.of("MOCK_COLLECTOR", "MOCK_COLLECTOR")
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("allowedDestinations must not contain duplicate values");
    }

    @Test
    void rejectsInvalidCatalogCollectionsBeforeLookup() {
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                null,
                false,
                List.of()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogTools must not be null");

        List<CatalogTool> nullMember = new ArrayList<>();
        nullMember.add(null);
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                nullMember,
                false,
                List.of()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogTools must not contain null entries");

        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                List.of(
                        new CatalogTool(CUSTOMER_DATA_READ, INTERNAL),
                        new CatalogTool(CUSTOMER_DATA_READ, EXTERNAL)
                ),
                false,
                List.of()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogTools must not contain duplicate tool names");
    }

    @Test
    void rejectsMalformedCatalogEntries() {
        assertThatThrownBy(() -> new CatalogTool(null, INTERNAL))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalog tool name must not be blank");
        assertThatThrownBy(() -> new CatalogTool(" ", INTERNAL))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalog tool name must not be blank");
        assertThatThrownBy(() -> new CatalogTool(CUSTOMER_DATA_READ, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalog egress classification must not be null");
    }

    @Test
    void defensivelyCopiesSourcesAndPreservesNontrivialCatalogOrder() {
        List<CatalogTool> catalog = new ArrayList<>(baseCatalog());
        List<String> destinations = new ArrayList<>();
        List<CatalogTool> expectedCatalogOrder = List.copyOf(catalog);
        PolicyEgressFacts facts = facts(
                EXTERNAL_HTTP,
                catalog,
                false,
                destinations
        );

        catalog.clear();
        destinations.add("LATE_MUTATION");

        assertThat(facts.catalogTools()).containsExactlyElementsOf(expectedCatalogOrder);
        assertThat(facts.allowedDestinations()).isEmpty();
        assertThatThrownBy(() -> facts.catalogTools().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> facts.allowedDestinations().add("CHANGED"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(evaluator.evaluate(EGRESS, facts))
                .isEqualTo(StageOutcome.deny(EGRESS, EXTERNAL_EGRESS_DENIED));
    }

    @ParameterizedTest
    @EnumSource(
            value = PolicyEvaluationStage.class,
            mode = EnumSource.Mode.EXCLUDE,
            names = "EGRESS"
    )
    void rejectsEveryUnsupportedStage(PolicyEvaluationStage stage) {
        assertThatThrownBy(() -> evaluator.evaluate(stage, externalFacts()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("PolicyEgressEvaluator supports only EGRESS");
    }

    @Test
    void rejectsNullStageAndFacts() {
        assertThatThrownBy(() -> evaluator.evaluate(null, externalFacts()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("stage must not be null");
        assertThatThrownBy(() -> evaluator.evaluate(EGRESS, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("facts must not be null");
    }

    @Test
    void sequenceStopsAtEgressDenialBeforeAllLaterStages() {
        AtomicInteger workflowEvaluations = new AtomicInteger();
        AtomicInteger humanEvaluations = new AtomicInteger();
        AtomicInteger trustEvaluations = new AtomicInteger();

        PolicyEvaluationDecision decision = PolicyEvaluationSequence.evaluate(
                () -> StageOutcome.pass(PREFLIGHT),
                stage -> {
                    if (stage == EGRESS) {
                        return evaluator.evaluate(stage, externalFacts());
                    }
                    if (stage == WORKFLOW) {
                        workflowEvaluations.incrementAndGet();
                    }
                    if (stage == HUMAN_BOUNDARY) {
                        humanEvaluations.incrementAndGet();
                    }
                    if (stage == TOOL_TRUST) {
                        trustEvaluations.incrementAndGet();
                    }
                    return StageOutcome.pass(stage);
                }
        );

        assertThat(decision.decisionType()).isEqualTo(DENY);
        assertThat(decision.reason()).contains(EXTERNAL_EGRESS_DENIED);
        assertThat(decision.failedStage()).contains(EGRESS);
        assertThat(decision.evaluatedStages()).containsExactly(
                PREFLIGHT,
                TOOL,
                OPERATION,
                BUSINESS_CONTEXT,
                OBJECT_SCOPE,
                FIELD_SCOPE,
                CARDINALITY,
                EGRESS
        );
        assertThat(decision.successfulSecurityBlock()).isTrue();
        assertThat(workflowEvaluations).hasValue(0);
        assertThat(humanEvaluations).hasValue(0);
        assertThat(trustEvaluations).hasValue(0);
    }

    @Test
    void sequenceWrapsUnknownToolMisuseAtEgressWithOriginalCause() {
        PolicyEgressFacts facts = facts(
                "UNKNOWN_TOOL",
                baseCatalog(),
                false,
                List.of()
        );
        AtomicInteger laterEvaluations = new AtomicInteger();

        assertThatThrownBy(() -> PolicyEvaluationSequence.evaluate(
                () -> StageOutcome.pass(PREFLIGHT),
                stage -> {
                    if (stage == EGRESS) {
                        return evaluator.evaluate(stage, facts);
                    }
                    if (stage == WORKFLOW || stage == HUMAN_BOUNDARY || stage == TOOL_TRUST) {
                        laterEvaluations.incrementAndGet();
                    }
                    return StageOutcome.pass(stage);
                }
        ))
                .isInstanceOf(PolicyEvaluationException.class)
                .satisfies(exception -> {
                    PolicyEvaluationException evaluationException =
                            (PolicyEvaluationException) exception;
                    assertThat(evaluationException.stage()).isEqualTo(EGRESS);
                    assertThat(evaluationException.getCause())
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessage(
                                    "requested tool must be resolved by the Tool stage before Egress"
                            );
                });
        assertThat(laterEvaluations).hasValue(0);
    }

    @Test
    void repeatedPassDenialAndMisuseResultsAreDeterministic() {
        PolicyEgressFacts allowed = facts(
                CUSTOMER_DATA_READ,
                baseCatalog(),
                false,
                List.of()
        );
        PolicyEgressFacts denied = externalFacts();
        PolicyEgressFacts unknown = facts(
                "UNKNOWN_TOOL",
                baseCatalog(),
                false,
                List.of()
        );

        assertThat(evaluator.evaluate(EGRESS, allowed))
                .isEqualTo(evaluator.evaluate(EGRESS, allowed));
        assertThat(evaluator.evaluate(EGRESS, denied))
                .isEqualTo(evaluator.evaluate(EGRESS, denied));
        assertThatThrownBy(() -> evaluator.evaluate(EGRESS, unknown))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("requested tool must be resolved by the Tool stage before Egress");
        assertThatThrownBy(() -> evaluator.evaluate(EGRESS, unknown))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("requested tool must be resolved by the Tool stage before Egress");
    }

    private PolicyEgressFacts externalFacts() {
        return facts(EXTERNAL_HTTP, baseCatalog(), false, List.of());
    }

    private PolicyEgressFacts facts(
            String requestedTool,
            List<CatalogTool> catalogTools,
            boolean externalEgressAllowed,
            List<String> allowedDestinations
    ) {
        return new PolicyEgressFacts(
                requestedTool,
                catalogTools,
                externalEgressAllowed,
                allowedDestinations
        );
    }

    private List<CatalogTool> baseCatalog() {
        return List.of(
                new CatalogTool(CUSTOMER_DATA_READ, INTERNAL),
                new CatalogTool(EXTERNAL_HTTP, EXTERNAL),
                new CatalogTool(EXTERNAL_HTTP_MOCK, INTERNAL)
        );
    }
}
