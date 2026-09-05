package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEvaluationDecision.DecisionType.DENY;
import static com.finsecseal.policy.PolicyEvaluationReason.HUMAN_ONLY_ACTION;
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
import static com.finsecseal.policy.PolicyHumanBoundaryFacts.BoundaryMode.HUMAN_ONLY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;
import com.finsecseal.policy.PolicyEvaluationSequence.PolicyEvaluationException;
import com.finsecseal.policy.PolicyHumanBoundaryFacts.HighImpactAction;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class PolicyHumanBoundaryEvaluatorTest {

    private static final String CUSTOMER_DATA_READ = "CUSTOMER_DATA_READ";
    private static final String LOAN_DECISION_UPDATE = "LOAN_DECISION_UPDATE";
    private static final String LOAN_DECISION_UPDATER = "LOAN_DECISION_UPDATER";

    private PolicyHumanBoundaryEvaluator evaluator;

    @BeforeEach
    void setUp() {
        evaluator = new PolicyHumanBoundaryEvaluator();
    }

    @Test
    void deniesExactCatalogToolWithExplicitHumanOnlyContractAction() {
        assertThat(evaluator.evaluate(HUMAN_BOUNDARY, humanOnlyFacts()))
                .isEqualTo(StageOutcome.deny(HUMAN_BOUNDARY, HUMAN_ONLY_ACTION));
    }

    @Test
    void passesOrdinaryCatalogToolWithoutHighImpactAction() {
        PolicyHumanBoundaryFacts facts = facts(
                CUSTOMER_DATA_READ,
                baseCatalog(),
                humanOnlyActions()
        );

        assertThat(evaluator.evaluate(HUMAN_BOUNDARY, facts))
                .isEqualTo(StageOutcome.pass(HUMAN_BOUNDARY));
    }

    @Test
    void exactHighImpactNameWithoutExplicitMappingDoesNotInferHumanOnlyStatus() {
        PolicyHumanBoundaryFacts facts = facts(
                LOAN_DECISION_UPDATE,
                baseCatalog(),
                List.of()
        );

        assertThat(evaluator.evaluate(HUMAN_BOUNDARY, facts))
                .isEqualTo(StageOutcome.pass(HUMAN_BOUNDARY));
    }

    @Test
    void similarCatalogToolNameDoesNotInheritAnotherToolsHumanOnlyMapping() {
        PolicyHumanBoundaryFacts facts = facts(
                LOAN_DECISION_UPDATER,
                baseCatalog(),
                humanOnlyActions()
        );

        assertThat(evaluator.evaluate(HUMAN_BOUNDARY, facts))
                .isEqualTo(StageOutcome.pass(HUMAN_BOUNDARY));
    }

    @ParameterizedTest
    @ValueSource(strings = {"UNKNOWN_TOOL", "loan_decision_update", "LOAN_DECISION_UPDATE "})
    void unknownToolFailsCompositionBeforeHumanBoundaryDecision(String requestedTool) {
        PolicyHumanBoundaryFacts facts = facts(
                requestedTool,
                baseCatalog(),
                humanOnlyActions()
        );

        assertThatThrownBy(() -> evaluator.evaluate(HUMAN_BOUNDARY, facts))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage(
                        "requested tool must be resolved by the Tool stage before Human Boundary"
                );
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t"})
    void rejectsNullOrBlankRequestedTool(String requestedTool) {
        assertThatThrownBy(() -> facts(
                requestedTool,
                baseCatalog(),
                humanOnlyActions()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("requestedTool must not be blank");
    }

    @Test
    void rejectsInvalidCatalogCollectionsBeforeLookup() {
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                null,
                humanOnlyActions()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogTools must not be null");

        List<String> nullMember = new ArrayList<>();
        nullMember.add(null);
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                nullMember,
                List.of()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogTools[0] must not be blank");

        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                List.of(" "),
                List.of()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogTools[0] must not be blank");

        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                List.of(CUSTOMER_DATA_READ, CUSTOMER_DATA_READ),
                List.of()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogTools must not contain duplicate tool names");
    }

    @Test
    void rejectsInvalidHighImpactActionCollectionsBeforeLookup() {
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                baseCatalog(),
                null
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("highImpactActions must not be null");

        List<HighImpactAction> nullMember = new ArrayList<>();
        nullMember.add(null);
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                baseCatalog(),
                nullMember
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("highImpactActions must not contain null entries");

        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                baseCatalog(),
                List.of(
                        new HighImpactAction(LOAN_DECISION_UPDATE, HUMAN_ONLY),
                        new HighImpactAction(LOAN_DECISION_UPDATE, HUMAN_ONLY)
                )
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("highImpactActions must not contain duplicate tool names");
    }

    @Test
    void rejectsMalformedHighImpactActionEntries() {
        assertThatThrownBy(() -> new HighImpactAction(null, HUMAN_ONLY))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("high-impact tool name must not be blank");
        assertThatThrownBy(() -> new HighImpactAction(" ", HUMAN_ONLY))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("high-impact tool name must not be blank");
        assertThatThrownBy(() -> new HighImpactAction(LOAN_DECISION_UPDATE, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("high-impact boundary mode must not be null");
    }

    @Test
    void rejectsHighImpactActionForToolAbsentFromCatalog() {
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                List.of(CUSTOMER_DATA_READ),
                humanOnlyActions()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("highImpactActions must reference catalog tools");
    }

    @Test
    void exactCatalogCrossReferenceDoesNotNormalizeActionToolName() {
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                List.of(CUSTOMER_DATA_READ, LOAN_DECISION_UPDATE),
                List.of(new HighImpactAction("loan_decision_update", HUMAN_ONLY))
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("highImpactActions must reference catalog tools");
    }

    @Test
    void defensivelyCopiesSourceListsAndPreservesImmutableOrder() {
        List<String> catalog = new ArrayList<>(baseCatalog());
        List<HighImpactAction> actions = new ArrayList<>(List.of(
                new HighImpactAction(LOAN_DECISION_UPDATE, HUMAN_ONLY),
                new HighImpactAction(LOAN_DECISION_UPDATER, HUMAN_ONLY)
        ));
        List<HighImpactAction> expectedActionOrder = List.copyOf(actions);
        PolicyHumanBoundaryFacts facts = facts(
                LOAN_DECISION_UPDATE,
                catalog,
                actions
        );

        catalog.clear();
        actions.clear();

        assertThat(facts.catalogTools()).containsExactlyElementsOf(baseCatalog());
        assertThat(facts.highImpactActions()).containsExactlyElementsOf(expectedActionOrder);
        assertThatThrownBy(() -> facts.catalogTools().add("CHANGED"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> facts.highImpactActions().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(evaluator.evaluate(HUMAN_BOUNDARY, facts))
                .isEqualTo(StageOutcome.deny(HUMAN_BOUNDARY, HUMAN_ONLY_ACTION));
    }

    @ParameterizedTest
    @EnumSource(
            value = PolicyEvaluationStage.class,
            mode = EnumSource.Mode.EXCLUDE,
            names = "HUMAN_BOUNDARY"
    )
    void rejectsEveryUnsupportedStage(PolicyEvaluationStage stage) {
        assertThatThrownBy(() -> evaluator.evaluate(stage, humanOnlyFacts()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(
                        "PolicyHumanBoundaryEvaluator supports only HUMAN_BOUNDARY"
                );
    }

    @Test
    void rejectsNullStageAndFacts() {
        assertThatThrownBy(() -> evaluator.evaluate(null, humanOnlyFacts()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("stage must not be null");
        assertThatThrownBy(() -> evaluator.evaluate(HUMAN_BOUNDARY, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("facts must not be null");
    }

    @Test
    void sequenceStopsAtHumanBoundaryDenialBeforeToolTrust() {
        AtomicInteger trustEvaluations = new AtomicInteger();

        PolicyEvaluationDecision decision = PolicyEvaluationSequence.evaluate(
                () -> StageOutcome.pass(PREFLIGHT),
                stage -> {
                    if (stage == HUMAN_BOUNDARY) {
                        return evaluator.evaluate(stage, humanOnlyFacts());
                    }
                    if (stage == TOOL_TRUST) {
                        trustEvaluations.incrementAndGet();
                    }
                    return StageOutcome.pass(stage);
                }
        );

        assertThat(decision.decisionType()).isEqualTo(DENY);
        assertThat(decision.reason()).contains(HUMAN_ONLY_ACTION);
        assertThat(decision.failedStage()).contains(HUMAN_BOUNDARY);
        assertThat(decision.evaluatedStages()).containsExactly(
                PREFLIGHT,
                TOOL,
                OPERATION,
                BUSINESS_CONTEXT,
                OBJECT_SCOPE,
                FIELD_SCOPE,
                CARDINALITY,
                EGRESS,
                WORKFLOW,
                HUMAN_BOUNDARY
        );
        assertThat(decision.successfulSecurityBlock()).isTrue();
        assertThat(trustEvaluations).hasValue(0);
    }

    @Test
    void sequenceWrapsUnknownToolMisuseAtHumanBoundaryWithOriginalCause() {
        PolicyHumanBoundaryFacts facts = facts(
                "UNKNOWN_TOOL",
                baseCatalog(),
                humanOnlyActions()
        );
        AtomicInteger trustEvaluations = new AtomicInteger();

        assertThatThrownBy(() -> PolicyEvaluationSequence.evaluate(
                () -> StageOutcome.pass(PREFLIGHT),
                stage -> {
                    if (stage == HUMAN_BOUNDARY) {
                        return evaluator.evaluate(stage, facts);
                    }
                    if (stage == TOOL_TRUST) {
                        trustEvaluations.incrementAndGet();
                    }
                    return StageOutcome.pass(stage);
                }
        ))
                .isInstanceOf(PolicyEvaluationException.class)
                .satisfies(exception -> {
                    PolicyEvaluationException evaluationException =
                            (PolicyEvaluationException) exception;
                    assertThat(evaluationException.stage()).isEqualTo(HUMAN_BOUNDARY);
                    assertThat(evaluationException.getCause())
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessage(
                                    "requested tool must be resolved by the Tool stage "
                                            + "before Human Boundary"
                            );
                });
        assertThat(trustEvaluations).hasValue(0);
    }

    @Test
    void repeatedPassDenialAndMisuseResultsAreDeterministic() {
        PolicyHumanBoundaryFacts allowed = facts(
                CUSTOMER_DATA_READ,
                baseCatalog(),
                humanOnlyActions()
        );
        PolicyHumanBoundaryFacts denied = humanOnlyFacts();
        PolicyHumanBoundaryFacts unknown = facts(
                "UNKNOWN_TOOL",
                baseCatalog(),
                humanOnlyActions()
        );

        assertThat(evaluator.evaluate(HUMAN_BOUNDARY, allowed))
                .isEqualTo(evaluator.evaluate(HUMAN_BOUNDARY, allowed));
        assertThat(evaluator.evaluate(HUMAN_BOUNDARY, denied))
                .isEqualTo(evaluator.evaluate(HUMAN_BOUNDARY, denied));
        assertThatThrownBy(() -> evaluator.evaluate(HUMAN_BOUNDARY, unknown))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage(
                        "requested tool must be resolved by the Tool stage before Human Boundary"
                );
        assertThatThrownBy(() -> evaluator.evaluate(HUMAN_BOUNDARY, unknown))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage(
                        "requested tool must be resolved by the Tool stage before Human Boundary"
                );
    }

    private PolicyHumanBoundaryFacts humanOnlyFacts() {
        return facts(
                LOAN_DECISION_UPDATE,
                baseCatalog(),
                humanOnlyActions()
        );
    }

    private PolicyHumanBoundaryFacts facts(
            String requestedTool,
            List<String> catalogTools,
            List<HighImpactAction> highImpactActions
    ) {
        return new PolicyHumanBoundaryFacts(
                requestedTool,
                catalogTools,
                highImpactActions
        );
    }

    private List<String> baseCatalog() {
        return List.of(
                CUSTOMER_DATA_READ,
                LOAN_DECISION_UPDATE,
                LOAN_DECISION_UPDATER
        );
    }

    private List<HighImpactAction> humanOnlyActions() {
        return List.of(new HighImpactAction(LOAN_DECISION_UPDATE, HUMAN_ONLY));
    }
}
