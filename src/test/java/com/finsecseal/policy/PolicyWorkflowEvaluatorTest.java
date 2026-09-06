package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEvaluationDecision.DecisionType.DENY;
import static com.finsecseal.policy.PolicyEvaluationReason.INVALID_WORKFLOW_STAGE;
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

import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;
import com.finsecseal.policy.PolicyEvaluationSequence.PolicyEvaluationException;
import com.finsecseal.policy.PolicyWorkflowFacts.CatalogTool;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class PolicyWorkflowEvaluatorTest {

    private static final String CASE_CONTEXT_READ = "CASE_CONTEXT_READ";
    private static final String CUSTOMER_DATA_READ = "CUSTOMER_DATA_READ";
    private static final String CASE_CONTEXT_READER = "CASE_CONTEXT_READER";
    private static final String DOCUMENT_REVIEW = "DOCUMENT_REVIEW";

    private PolicyWorkflowEvaluator evaluator;

    @BeforeEach
    void setUp() {
        evaluator = new PolicyWorkflowEvaluator();
    }

    @Test
    void passesKnownToolAtExactlyAllowedServerStage() {
        PolicyWorkflowFacts facts = facts(
                CUSTOMER_DATA_READ,
                DOCUMENT_REVIEW,
                List.of("INITIAL_REVIEW", DOCUMENT_REVIEW),
                baseCatalog()
        );

        assertThat(evaluator.evaluate(WORKFLOW, facts))
                .isEqualTo(StageOutcome.pass(WORKFLOW));
    }

    @ParameterizedTest
    @ValueSource(strings = {"CREDIT_REVIEW", "document_review", "DOCUMENT_REVIEW "})
    void deniesKnownToolWhenServerStageIsNotExactlyAllowed(String serverStage) {
        PolicyWorkflowFacts facts = facts(
                CUSTOMER_DATA_READ,
                serverStage,
                List.of(DOCUMENT_REVIEW),
                baseCatalog()
        );

        assertThat(evaluator.evaluate(WORKFLOW, facts))
                .isEqualTo(StageOutcome.deny(WORKFLOW, INVALID_WORKFLOW_STAGE));
    }

    @Test
    void deniesKnownToolWhenAllowedStagesAreEmpty() {
        PolicyWorkflowFacts facts = facts(
                CUSTOMER_DATA_READ,
                DOCUMENT_REVIEW,
                List.of(),
                baseCatalog()
        );

        assertThat(evaluator.evaluate(WORKFLOW, facts))
                .isEqualTo(StageOutcome.deny(WORKFLOW, INVALID_WORKFLOW_STAGE));
    }

    @Test
    void passesExactCatalogClassifiedBootstrapAtDisallowedStage() {
        PolicyWorkflowFacts facts = facts(
                CASE_CONTEXT_READ,
                "CONTEXT_BOOTSTRAP",
                List.of(DOCUMENT_REVIEW),
                baseCatalog()
        );

        assertThat(evaluator.evaluate(WORKFLOW, facts))
                .isEqualTo(StageOutcome.pass(WORKFLOW));
    }

    @Test
    void exactBootstrapNameWithoutClassificationDoesNotReceiveException() {
        PolicyWorkflowFacts facts = facts(
                CASE_CONTEXT_READ,
                "CONTEXT_BOOTSTRAP",
                List.of(DOCUMENT_REVIEW),
                List.of(new CatalogTool(CASE_CONTEXT_READ, false))
        );

        assertThat(evaluator.evaluate(WORKFLOW, facts))
                .isEqualTo(StageOutcome.deny(WORKFLOW, INVALID_WORKFLOW_STAGE));
    }

    @Test
    void knownSimilarToolNameDoesNotReceiveBootstrapException() {
        PolicyWorkflowFacts facts = facts(
                CASE_CONTEXT_READER,
                "CONTEXT_BOOTSTRAP",
                List.of(DOCUMENT_REVIEW),
                baseCatalog()
        );

        assertThat(evaluator.evaluate(WORKFLOW, facts))
                .isEqualTo(StageOutcome.deny(WORKFLOW, INVALID_WORKFLOW_STAGE));
    }

    @ParameterizedTest
    @ValueSource(strings = {"UNKNOWN_TOOL", "case_context_read", "CASE_CONTEXT_READ "})
    void unknownToolFailsCompositionBeforeAllowedStageFastPath(String requestedTool) {
        PolicyWorkflowFacts facts = facts(
                requestedTool,
                DOCUMENT_REVIEW,
                List.of(DOCUMENT_REVIEW),
                baseCatalog()
        );

        assertThatThrownBy(() -> evaluator.evaluate(WORKFLOW, facts))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("requested tool must be resolved by the Tool stage before Workflow");
    }

    @Test
    void rejectsBootstrapClassificationForAnyOtherCatalogTool() {
        assertThatThrownBy(() -> new CatalogTool(CASE_CONTEXT_READER, true))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("workflow bootstrap classification is reserved for CASE_CONTEXT_READ");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t"})
    void rejectsNullOrBlankRequestedTool(String requestedTool) {
        assertThatThrownBy(() -> facts(
                requestedTool,
                DOCUMENT_REVIEW,
                List.of(DOCUMENT_REVIEW),
                baseCatalog()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("requestedTool must not be blank");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t"})
    void rejectsNullOrBlankServerWorkflowStage(String serverStage) {
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                serverStage,
                List.of(DOCUMENT_REVIEW),
                baseCatalog()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("serverWorkflowStage must not be blank");
    }

    @Test
    void rejectsInvalidAllowedStageCollectionsBeforeLookup() {
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                DOCUMENT_REVIEW,
                null,
                baseCatalog()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("allowedStages must not be null");

        List<String> nullMember = new ArrayList<>();
        nullMember.add(null);
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                DOCUMENT_REVIEW,
                nullMember,
                baseCatalog()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("allowedStages[0] must not be blank");

        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                DOCUMENT_REVIEW,
                List.of(" "),
                baseCatalog()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("allowedStages[0] must not be blank");

        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                DOCUMENT_REVIEW,
                List.of(DOCUMENT_REVIEW, DOCUMENT_REVIEW),
                baseCatalog()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("allowedStages must not contain duplicate values");
    }

    @Test
    void rejectsInvalidCatalogCollectionsBeforeLookup() {
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                DOCUMENT_REVIEW,
                List.of(DOCUMENT_REVIEW),
                null
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogTools must not be null");

        List<CatalogTool> nullMember = new ArrayList<>(baseCatalog());
        nullMember.add(null);
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                DOCUMENT_REVIEW,
                List.of(DOCUMENT_REVIEW),
                nullMember
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogTools must not contain null entries");

        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                DOCUMENT_REVIEW,
                List.of(DOCUMENT_REVIEW),
                List.of(
                        new CatalogTool(CUSTOMER_DATA_READ, false),
                        new CatalogTool(CUSTOMER_DATA_READ, false)
                )
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogTools must not contain duplicate tool names");
    }

    @Test
    void rejectsNullOrBlankCatalogToolName() {
        assertThatThrownBy(() -> new CatalogTool(null, false))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalog tool name must not be blank");
        assertThatThrownBy(() -> new CatalogTool(" ", false))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalog tool name must not be blank");
    }

    @Test
    void defensivelyCopiesSourceListsAndPreservesImmutableOrder() {
        List<String> allowedStages = new ArrayList<>(List.of("INITIAL_REVIEW", DOCUMENT_REVIEW));
        List<CatalogTool> catalog = new ArrayList<>(baseCatalog());
        PolicyWorkflowFacts facts = facts(
                CUSTOMER_DATA_READ,
                DOCUMENT_REVIEW,
                allowedStages,
                catalog
        );

        allowedStages.clear();
        catalog.clear();

        assertThat(facts.allowedStages()).containsExactly("INITIAL_REVIEW", DOCUMENT_REVIEW);
        assertThat(facts.catalogTools()).containsExactlyElementsOf(baseCatalog());
        assertThatThrownBy(() -> facts.allowedStages().add("CHANGED"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> facts.catalogTools().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(evaluator.evaluate(WORKFLOW, facts))
                .isEqualTo(StageOutcome.pass(WORKFLOW));
    }

    @ParameterizedTest
    @EnumSource(
            value = PolicyEvaluationStage.class,
            mode = EnumSource.Mode.EXCLUDE,
            names = "WORKFLOW"
    )
    void rejectsEveryUnsupportedStage(PolicyEvaluationStage stage) {
        assertThatThrownBy(() -> evaluator.evaluate(stage, validFacts()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("PolicyWorkflowEvaluator supports only WORKFLOW");
    }

    @Test
    void rejectsNullStageAndFacts() {
        assertThatThrownBy(() -> evaluator.evaluate(null, validFacts()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("stage must not be null");
        assertThatThrownBy(() -> evaluator.evaluate(WORKFLOW, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("facts must not be null");
    }

    @Test
    void sequenceStopsAtWorkflowDenialBeforeHumanAndTrust() {
        PolicyWorkflowFacts facts = facts(
                CUSTOMER_DATA_READ,
                "CREDIT_REVIEW",
                List.of(DOCUMENT_REVIEW),
                baseCatalog()
        );
        AtomicInteger humanEvaluations = new AtomicInteger();
        AtomicInteger trustEvaluations = new AtomicInteger();

        PolicyEvaluationDecision decision = PolicyEvaluationSequence.evaluate(
                () -> StageOutcome.pass(PREFLIGHT),
                stage -> {
                    if (stage == WORKFLOW) {
                        return evaluator.evaluate(stage, facts);
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
        assertThat(decision.reason()).contains(INVALID_WORKFLOW_STAGE);
        assertThat(decision.failedStage()).contains(WORKFLOW);
        assertThat(decision.evaluatedStages()).containsExactly(
                PREFLIGHT,
                TOOL,
                OPERATION,
                BUSINESS_CONTEXT,
                OBJECT_SCOPE,
                FIELD_SCOPE,
                CARDINALITY,
                EGRESS,
                WORKFLOW
        );
        assertThat(decision.successfulSecurityBlock()).isTrue();
        assertThat(humanEvaluations).hasValue(0);
        assertThat(trustEvaluations).hasValue(0);
    }

    @Test
    void sequenceWrapsUnknownToolMisuseAtWorkflowWithoutLaterCalls() {
        PolicyWorkflowFacts facts = facts(
                "UNKNOWN_TOOL",
                DOCUMENT_REVIEW,
                List.of(DOCUMENT_REVIEW),
                baseCatalog()
        );
        AtomicInteger laterEvaluations = new AtomicInteger();

        assertThatThrownBy(() -> PolicyEvaluationSequence.evaluate(
                () -> StageOutcome.pass(PREFLIGHT),
                stage -> {
                    if (stage == WORKFLOW) {
                        return evaluator.evaluate(stage, facts);
                    }
                    if (stage == HUMAN_BOUNDARY || stage == TOOL_TRUST) {
                        laterEvaluations.incrementAndGet();
                    }
                    return StageOutcome.pass(stage);
                }
        ))
                .isInstanceOf(PolicyEvaluationException.class)
                .satisfies(exception -> assertThat(((PolicyEvaluationException) exception).stage())
                        .isEqualTo(WORKFLOW))
                .hasCauseInstanceOf(IllegalStateException.class);
        assertThat(laterEvaluations).hasValue(0);
    }

    @Test
    void repeatedPassDenialAndMisuseResultsAreDeterministic() {
        PolicyWorkflowFacts allowed = validFacts();
        PolicyWorkflowFacts denied = facts(
                CUSTOMER_DATA_READ,
                "CREDIT_REVIEW",
                List.of(DOCUMENT_REVIEW),
                baseCatalog()
        );
        PolicyWorkflowFacts unknown = facts(
                "UNKNOWN_TOOL",
                DOCUMENT_REVIEW,
                List.of(DOCUMENT_REVIEW),
                baseCatalog()
        );

        assertThat(evaluator.evaluate(WORKFLOW, allowed))
                .isEqualTo(evaluator.evaluate(WORKFLOW, allowed));
        assertThat(evaluator.evaluate(WORKFLOW, denied))
                .isEqualTo(evaluator.evaluate(WORKFLOW, denied));
        assertThatThrownBy(() -> evaluator.evaluate(WORKFLOW, unknown))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("requested tool must be resolved by the Tool stage before Workflow");
        assertThatThrownBy(() -> evaluator.evaluate(WORKFLOW, unknown))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("requested tool must be resolved by the Tool stage before Workflow");
    }

    private PolicyWorkflowFacts validFacts() {
        return facts(
                CUSTOMER_DATA_READ,
                DOCUMENT_REVIEW,
                List.of(DOCUMENT_REVIEW),
                baseCatalog()
        );
    }

    private PolicyWorkflowFacts facts(
            String requestedTool,
            String serverWorkflowStage,
            List<String> allowedStages,
            List<CatalogTool> catalogTools
    ) {
        return new PolicyWorkflowFacts(
                requestedTool,
                serverWorkflowStage,
                allowedStages,
                catalogTools
        );
    }

    private List<CatalogTool> baseCatalog() {
        return List.of(
                new CatalogTool(CASE_CONTEXT_READ, true),
                new CatalogTool(CUSTOMER_DATA_READ, false),
                new CatalogTool(CASE_CONTEXT_READER, false)
        );
    }
}
