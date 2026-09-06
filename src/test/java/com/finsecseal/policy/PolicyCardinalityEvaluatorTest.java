package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEvaluationDecision.DecisionType.DENY;
import static com.finsecseal.policy.PolicyEvaluationReason.RECORD_LIMIT_EXCEEDED;
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

import com.finsecseal.policy.PolicyCardinalityFacts.CardinalityPolicy;
import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;
import com.finsecseal.policy.PolicyEvaluationSequence.PolicyEvaluationException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class PolicyCardinalityEvaluatorTest {

    private static final String CUSTOMER_DATA_READ = "CUSTOMER_DATA_READ";
    private static final String CUSTOMER_DATA_BATCH_READ = "CUSTOMER_DATA_BATCH_READ";
    private static final String CUSTOMER_DATA_READER = "CUSTOMER_DATA_READER";

    private PolicyCardinalityEvaluator evaluator;

    @BeforeEach
    void setUp() {
        evaluator = new PolicyCardinalityEvaluator();
    }

    @Test
    void deniesWhenTrustedRequestedCountExceedsExactToolLimit() {
        assertThat(evaluator.evaluate(CARDINALITY, facts(CUSTOMER_DATA_READ, 2)))
                .isEqualTo(StageOutcome.deny(CARDINALITY, RECORD_LIMIT_EXCEEDED));
    }

    @Test
    void passesWhenTrustedRequestedCountEqualsExactToolLimit() {
        assertThat(evaluator.evaluate(CARDINALITY, facts(CUSTOMER_DATA_READ, 1)))
                .isEqualTo(StageOutcome.pass(CARDINALITY));
    }

    @Test
    void passesBelowLimitBecauseMinimumPresenceBelongsToEarlierValidation() {
        assertThat(evaluator.evaluate(CARDINALITY, facts(CUSTOMER_DATA_READ, 0)))
                .isEqualTo(StageOutcome.pass(CARDINALITY));
    }

    @Test
    void passesCatalogToolWithoutExplicitCardinalityPolicy() {
        PolicyCardinalityFacts facts = facts(
                CUSTOMER_DATA_READER,
                100,
                baseCatalog(),
                basePolicies()
        );

        assertThat(evaluator.evaluate(CARDINALITY, facts))
                .isEqualTo(StageOutcome.pass(CARDINALITY));
    }

    @Test
    void similarCatalogToolNameDoesNotInheritAnotherToolsLimit() {
        PolicyCardinalityFacts facts = facts(
                CUSTOMER_DATA_READER,
                2,
                baseCatalog(),
                basePolicies()
        );

        assertThat(evaluator.evaluate(CARDINALITY, facts))
                .isEqualTo(StageOutcome.pass(CARDINALITY));
    }

    @ParameterizedTest
    @ValueSource(strings = {"UNKNOWN_TOOL", "customer_data_read", "CUSTOMER_DATA_READ "})
    void unknownToolFailsCompositionBeforeCardinalityDecision(String requestedTool) {
        PolicyCardinalityFacts facts = facts(
                requestedTool,
                2,
                baseCatalog(),
                basePolicies()
        );

        assertThatThrownBy(() -> evaluator.evaluate(CARDINALITY, facts))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage(
                        "requested tool must be resolved by the Tool stage before Cardinality"
                );
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t"})
    void rejectsNullOrBlankRequestedTool(String requestedTool) {
        assertThatThrownBy(() -> facts(
                requestedTool,
                1,
                baseCatalog(),
                basePolicies()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("requestedTool must not be blank");
    }

    @Test
    void rejectsNegativeNormalizedRequestedRecordCount() {
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                -1,
                baseCatalog(),
                basePolicies()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("normalizedRequestedRecordCount must not be negative");
    }

    @Test
    void rejectsInvalidCatalogCollectionsBeforeLookup() {
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                1,
                null,
                List.of()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogTools must not be null");

        List<String> nullMember = new ArrayList<>();
        nullMember.add(null);
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                1,
                nullMember,
                List.of()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogTools[0] must not be blank");

        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                1,
                List.of(" "),
                List.of()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogTools[0] must not be blank");

        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                1,
                List.of(CUSTOMER_DATA_READ, CUSTOMER_DATA_READ),
                List.of()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogTools must not contain duplicate tool names");
    }

    @Test
    void rejectsInvalidCardinalityPolicyCollectionsBeforeLookup() {
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                1,
                baseCatalog(),
                null
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("cardinalityPolicies must not be null");

        List<CardinalityPolicy> nullMember = new ArrayList<>();
        nullMember.add(null);
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                1,
                baseCatalog(),
                nullMember
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("cardinalityPolicies must not contain null entries");

        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                1,
                baseCatalog(),
                List.of(
                        new CardinalityPolicy(CUSTOMER_DATA_READ, 1),
                        new CardinalityPolicy(CUSTOMER_DATA_READ, 2)
                )
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("cardinalityPolicies must not contain duplicate tool names");
    }

    @Test
    void rejectsMalformedCardinalityPolicyEntries() {
        assertThatThrownBy(() -> new CardinalityPolicy(null, 1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("cardinality policy tool name must not be blank");
        assertThatThrownBy(() -> new CardinalityPolicy(" ", 1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("cardinality policy tool name must not be blank");
        assertThatThrownBy(() -> new CardinalityPolicy(CUSTOMER_DATA_READ, 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("maxRequestedRecords must be greater than zero");
        assertThatThrownBy(() -> new CardinalityPolicy(CUSTOMER_DATA_READ, -1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("maxRequestedRecords must be greater than zero");
    }

    @Test
    void rejectsPolicyForToolAbsentFromCatalog() {
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                1,
                List.of(CUSTOMER_DATA_READ),
                List.of(new CardinalityPolicy(CUSTOMER_DATA_BATCH_READ, 5))
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("cardinalityPolicies must reference catalog tools");
    }

    @Test
    void exactCatalogCrossReferenceDoesNotNormalizePolicyToolName() {
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                1,
                baseCatalog(),
                List.of(new CardinalityPolicy("customer_data_read", 1))
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("cardinalityPolicies must reference catalog tools");
    }

    @Test
    void defensivelyCopiesSourcesAndPreservesNontrivialOrders() {
        List<String> catalog = new ArrayList<>(baseCatalog());
        List<CardinalityPolicy> policies = new ArrayList<>(basePolicies());
        List<String> expectedCatalogOrder = List.copyOf(catalog);
        List<CardinalityPolicy> expectedPolicyOrder = List.copyOf(policies);
        PolicyCardinalityFacts facts = facts(
                CUSTOMER_DATA_READ,
                2,
                catalog,
                policies
        );

        catalog.clear();
        policies.clear();

        assertThat(facts.catalogTools()).containsExactlyElementsOf(expectedCatalogOrder);
        assertThat(facts.cardinalityPolicies()).containsExactlyElementsOf(expectedPolicyOrder);
        assertThatThrownBy(() -> facts.catalogTools().add("CHANGED"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> facts.cardinalityPolicies().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(evaluator.evaluate(CARDINALITY, facts))
                .isEqualTo(StageOutcome.deny(CARDINALITY, RECORD_LIMIT_EXCEEDED));
    }

    @ParameterizedTest
    @EnumSource(
            value = PolicyEvaluationStage.class,
            mode = EnumSource.Mode.EXCLUDE,
            names = "CARDINALITY"
    )
    void rejectsEveryUnsupportedStage(PolicyEvaluationStage stage) {
        assertThatThrownBy(() -> evaluator.evaluate(stage, facts(CUSTOMER_DATA_READ, 1)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("PolicyCardinalityEvaluator supports only CARDINALITY");
    }

    @Test
    void rejectsNullStageAndFacts() {
        assertThatThrownBy(() -> evaluator.evaluate(null, facts(CUSTOMER_DATA_READ, 1)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("stage must not be null");
        assertThatThrownBy(() -> evaluator.evaluate(CARDINALITY, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("facts must not be null");
    }

    @Test
    void sequenceStopsAtCardinalityDenialBeforeEveryLaterStage() {
        AtomicInteger egressEvaluations = new AtomicInteger();
        AtomicInteger workflowEvaluations = new AtomicInteger();
        AtomicInteger humanEvaluations = new AtomicInteger();
        AtomicInteger trustEvaluations = new AtomicInteger();

        PolicyEvaluationDecision decision = PolicyEvaluationSequence.evaluate(
                () -> StageOutcome.pass(PREFLIGHT),
                stage -> {
                    if (stage == CARDINALITY) {
                        return evaluator.evaluate(stage, facts(CUSTOMER_DATA_READ, 2));
                    }
                    if (stage == EGRESS) {
                        egressEvaluations.incrementAndGet();
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
        assertThat(decision.reason()).contains(RECORD_LIMIT_EXCEEDED);
        assertThat(decision.failedStage()).contains(CARDINALITY);
        assertThat(decision.evaluatedStages()).containsExactly(
                PREFLIGHT,
                TOOL,
                OPERATION,
                BUSINESS_CONTEXT,
                OBJECT_SCOPE,
                FIELD_SCOPE,
                CARDINALITY
        );
        assertThat(decision.successfulSecurityBlock()).isTrue();
        assertThat(egressEvaluations).hasValue(0);
        assertThat(workflowEvaluations).hasValue(0);
        assertThat(humanEvaluations).hasValue(0);
        assertThat(trustEvaluations).hasValue(0);
    }

    @Test
    void sequenceWrapsUnknownToolMisuseAtCardinalityWithOriginalCause() {
        PolicyCardinalityFacts facts = facts(
                "UNKNOWN_TOOL",
                2,
                baseCatalog(),
                basePolicies()
        );
        AtomicInteger laterEvaluations = new AtomicInteger();
        AtomicReference<IllegalStateException> originalCause = new AtomicReference<>();

        assertThatThrownBy(() -> PolicyEvaluationSequence.evaluate(
                () -> StageOutcome.pass(PREFLIGHT),
                stage -> {
                    if (stage == CARDINALITY) {
                        try {
                            return evaluator.evaluate(stage, facts);
                        } catch (IllegalStateException exception) {
                            originalCause.set(exception);
                            throw exception;
                        }
                    }
                    if (stage == EGRESS
                            || stage == WORKFLOW
                            || stage == HUMAN_BOUNDARY
                            || stage == TOOL_TRUST) {
                        laterEvaluations.incrementAndGet();
                    }
                    return StageOutcome.pass(stage);
                }
        ))
                .isInstanceOf(PolicyEvaluationException.class)
                .satisfies(exception -> {
                    PolicyEvaluationException evaluationException =
                            (PolicyEvaluationException) exception;
                    assertThat(evaluationException.stage()).isEqualTo(CARDINALITY);
                    assertThat(evaluationException.getCause())
                            .isInstanceOf(IllegalStateException.class)
                            .isSameAs(originalCause.get())
                            .hasMessage(
                                    "requested tool must be resolved by the Tool stage "
                                            + "before Cardinality"
                            );
                });
        assertThat(laterEvaluations).hasValue(0);
    }

    @Test
    void repeatedPassDenialAndMisuseResultsAreDeterministic() {
        PolicyCardinalityFacts allowed = facts(CUSTOMER_DATA_READ, 1);
        PolicyCardinalityFacts denied = facts(CUSTOMER_DATA_READ, 2);
        PolicyCardinalityFacts unknown = facts(
                "UNKNOWN_TOOL",
                2,
                baseCatalog(),
                basePolicies()
        );

        assertThat(evaluator.evaluate(CARDINALITY, allowed))
                .isEqualTo(evaluator.evaluate(CARDINALITY, allowed));
        assertThat(evaluator.evaluate(CARDINALITY, denied))
                .isEqualTo(evaluator.evaluate(CARDINALITY, denied));
        assertThatThrownBy(() -> evaluator.evaluate(CARDINALITY, unknown))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage(
                        "requested tool must be resolved by the Tool stage before Cardinality"
                );
        assertThatThrownBy(() -> evaluator.evaluate(CARDINALITY, unknown))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage(
                        "requested tool must be resolved by the Tool stage before Cardinality"
                );
    }

    private PolicyCardinalityFacts facts(String requestedTool, int requestedRecordCount) {
        return facts(
                requestedTool,
                requestedRecordCount,
                baseCatalog(),
                basePolicies()
        );
    }

    private PolicyCardinalityFacts facts(
            String requestedTool,
            int requestedRecordCount,
            List<String> catalogTools,
            List<CardinalityPolicy> policies
    ) {
        return new PolicyCardinalityFacts(
                requestedTool,
                requestedRecordCount,
                catalogTools,
                policies
        );
    }

    private List<String> baseCatalog() {
        return List.of(
                CUSTOMER_DATA_READ,
                CUSTOMER_DATA_BATCH_READ,
                CUSTOMER_DATA_READER
        );
    }

    private List<CardinalityPolicy> basePolicies() {
        return List.of(
                new CardinalityPolicy(CUSTOMER_DATA_READ, 1),
                new CardinalityPolicy(CUSTOMER_DATA_BATCH_READ, 5)
        );
    }
}
