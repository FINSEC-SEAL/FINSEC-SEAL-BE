package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEvaluationDecision.DecisionType.DENY;
import static com.finsecseal.policy.PolicyEvaluationReason.EXTERNAL_EGRESS_DENIED;
import static com.finsecseal.policy.PolicyEvaluationReason.HUMAN_ONLY_ACTION;
import static com.finsecseal.policy.PolicyEvaluationReason.OPERATION_NOT_ALLOWED;
import static com.finsecseal.policy.PolicyEvaluationReason.TOOL_NOT_ALLOWED;
import static com.finsecseal.policy.PolicyEvaluationStage.BUSINESS_CONTEXT;
import static com.finsecseal.policy.PolicyEvaluationStage.CARDINALITY;
import static com.finsecseal.policy.PolicyEvaluationStage.EGRESS;
import static com.finsecseal.policy.PolicyEvaluationStage.FIELD_SCOPE;
import static com.finsecseal.policy.PolicyEvaluationStage.HUMAN_BOUNDARY;
import static com.finsecseal.policy.PolicyEvaluationStage.OBJECT_SCOPE;
import static com.finsecseal.policy.PolicyEvaluationStage.OPERATION;
import static com.finsecseal.policy.PolicyEvaluationStage.PREFLIGHT;
import static com.finsecseal.policy.PolicyEvaluationStage.TOOL;
import static com.finsecseal.policy.PolicyEvaluationStage.WORKFLOW;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;
import com.finsecseal.policy.PolicyEvaluationSequence.PolicyEvaluationException;
import com.finsecseal.policy.PolicyToolAuthorizationFacts.CatalogTool;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class PolicyToolAuthorizationEvaluatorTest {

    private static final String CUSTOMER_DATA_READ = "CUSTOMER_DATA_READ";
    private static final String REVIEW_NOTE_WRITE = "REVIEW_NOTE_WRITE";
    private static final String EXTERNAL_HTTP = "EXTERNAL_HTTP";
    private static final String LOAN_DECISION_UPDATE = "LOAN_DECISION_UPDATE";

    private PolicyToolAuthorizationEvaluator evaluator;

    @BeforeEach
    void setUp() {
        evaluator = new PolicyToolAuthorizationEvaluator();
    }

    @Test
    void passesKnownAllowedToolAndExactOperation() {
        PolicyToolAuthorizationFacts facts = facts(
                CUSTOMER_DATA_READ,
                "READ",
                baseCatalog(),
                List.of(CUSTOMER_DATA_READ),
                true,
                List.of(LOAN_DECISION_UPDATE)
        );

        assertThat(evaluator.evaluate(TOOL, facts)).isEqualTo(StageOutcome.pass(TOOL));
        assertThat(evaluator.evaluate(OPERATION, facts)).isEqualTo(StageOutcome.pass(OPERATION));
    }

    @Test
    void deniesUnknownToolEvenWhenCallerSuppliesAllowAndDeferralFacts() {
        PolicyToolAuthorizationFacts facts = facts(
                "UNKNOWN_TOOL",
                "READ",
                baseCatalog(),
                List.of("UNKNOWN_TOOL"),
                true,
                List.of("UNKNOWN_TOOL")
        );

        assertThat(evaluator.evaluate(TOOL, facts))
                .isEqualTo(StageOutcome.deny(TOOL, TOOL_NOT_ALLOWED));
    }

    @Test
    void deniesOrdinaryCatalogToolOutsideAllowlist() {
        PolicyToolAuthorizationFacts facts = facts(
                REVIEW_NOTE_WRITE,
                "CREATE",
                baseCatalog(),
                List.of(CUSTOMER_DATA_READ),
                true,
                List.of()
        );

        assertThat(evaluator.evaluate(TOOL, facts))
                .isEqualTo(StageOutcome.deny(TOOL, TOOL_NOT_ALLOWED));
    }

    @ParameterizedTest
    @ValueSource(strings = {"customer_data_read", "CUSTOMER_DATA_READ "})
    void toolIdentityComparisonIsExact(String requestedTool) {
        PolicyToolAuthorizationFacts facts = facts(
                requestedTool,
                "READ",
                baseCatalog(),
                List.of(CUSTOMER_DATA_READ),
                true,
                List.of()
        );

        assertThat(evaluator.evaluate(TOOL, facts))
                .isEqualTo(StageOutcome.deny(TOOL, TOOL_NOT_ALLOWED));
    }

    @ParameterizedTest
    @ValueSource(strings = {"read", "READ "})
    void operationComparisonIsExact(String requestedOperation) {
        PolicyToolAuthorizationFacts facts = facts(
                CUSTOMER_DATA_READ,
                requestedOperation,
                baseCatalog(),
                List.of(CUSTOMER_DATA_READ),
                true,
                List.of()
        );

        assertThat(evaluator.evaluate(OPERATION, facts))
                .isEqualTo(StageOutcome.deny(OPERATION, OPERATION_NOT_ALLOWED));
    }

    @Test
    void unknownCatalogOperationFailsClosed() {
        PolicyToolAuthorizationFacts facts = facts(
                "UNKNOWN_TOOL",
                "READ",
                baseCatalog(),
                List.of(),
                true,
                List.of()
        );

        assertThat(evaluator.evaluate(OPERATION, facts))
                .isEqualTo(StageOutcome.deny(OPERATION, OPERATION_NOT_ALLOWED));
    }

    @Test
    void defersCatalogKnownExternalToolToSpecificEgressDenial() {
        PolicyToolAuthorizationFacts facts = facts(
                EXTERNAL_HTTP,
                "POST",
                baseCatalog(),
                List.of(CUSTOMER_DATA_READ),
                true,
                List.of()
        );

        PolicyEvaluationDecision decision = evaluateWithSpecificDenial(
                facts,
                EGRESS
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
    }

    @Test
    void externalToolDoesNotDeferWithoutExplicitDenyRule() {
        PolicyToolAuthorizationFacts facts = facts(
                EXTERNAL_HTTP,
                "POST",
                baseCatalog(),
                List.of(CUSTOMER_DATA_READ),
                false,
                List.of()
        );

        assertThat(evaluator.evaluate(TOOL, facts))
                .isEqualTo(StageOutcome.deny(TOOL, TOOL_NOT_ALLOWED));
    }

    @Test
    void toolNameDoesNotCreateExternalClassification() {
        PolicyToolAuthorizationFacts facts = facts(
                EXTERNAL_HTTP,
                "POST",
                List.of(new CatalogTool(EXTERNAL_HTTP, "POST", false)),
                List.of(),
                true,
                List.of()
        );

        assertThat(evaluator.evaluate(TOOL, facts))
                .isEqualTo(StageOutcome.deny(TOOL, TOOL_NOT_ALLOWED));
    }

    @Test
    void defersCatalogKnownExplicitHumanOnlyToolToSpecificHumanDenial() {
        PolicyToolAuthorizationFacts facts = facts(
                LOAN_DECISION_UPDATE,
                "UPDATE",
                baseCatalog(),
                List.of(CUSTOMER_DATA_READ),
                true,
                List.of(LOAN_DECISION_UPDATE)
        );

        PolicyEvaluationDecision decision = evaluateWithSpecificDenial(
                facts,
                HUMAN_BOUNDARY
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
    }

    @Test
    void humanBoundaryToolDoesNotDeferWithoutExplicitHumanOnlyMapping() {
        PolicyToolAuthorizationFacts facts = facts(
                LOAN_DECISION_UPDATE,
                "UPDATE",
                baseCatalog(),
                List.of(CUSTOMER_DATA_READ),
                true,
                List.of()
        );

        assertThat(evaluator.evaluate(TOOL, facts))
                .isEqualTo(StageOutcome.deny(TOOL, TOOL_NOT_ALLOWED));
    }

    @Test
    void earlierToolFailureSuppressesOperationEvaluation() {
        PolicyToolAuthorizationFacts facts = facts(
                REVIEW_NOTE_WRITE,
                "WRONG_OPERATION",
                baseCatalog(),
                List.of(CUSTOMER_DATA_READ),
                true,
                List.of()
        );
        AtomicInteger operationEvaluations = new AtomicInteger();

        PolicyEvaluationDecision decision = PolicyEvaluationSequence.evaluate(
                () -> StageOutcome.pass(PREFLIGHT),
                stage -> {
                    if (stage == OPERATION) {
                        operationEvaluations.incrementAndGet();
                    }
                    if (stage == TOOL || stage == OPERATION) {
                        return evaluator.evaluate(stage, facts);
                    }
                    return StageOutcome.pass(stage);
                }
        );

        assertThat(decision.decisionType()).isEqualTo(DENY);
        assertThat(decision.reason()).contains(TOOL_NOT_ALLOWED);
        assertThat(decision.failedStage()).contains(TOOL);
        assertThat(decision.evaluatedStages()).containsExactly(PREFLIGHT, TOOL);
        assertThat(operationEvaluations).hasValue(0);
    }

    @Test
    void rejectsUnsupportedStagesInsteadOfSilentlyPassingThem() {
        PolicyToolAuthorizationFacts facts = validFacts();

        assertThatThrownBy(() -> evaluator.evaluate(BUSINESS_CONTEXT, facts))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("PolicyToolAuthorizationEvaluator supports only TOOL and OPERATION");

        assertThatThrownBy(() -> PolicyEvaluationSequence.evaluate(
                () -> StageOutcome.pass(PREFLIGHT),
                stage -> evaluator.evaluate(stage, facts)
        ))
                .isInstanceOf(PolicyEvaluationException.class)
                .satisfies(exception -> assertThat(((PolicyEvaluationException) exception).stage())
                        .isEqualTo(BUSINESS_CONTEXT))
                .hasCauseInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsNullStageAndFacts() {
        assertThatThrownBy(() -> evaluator.evaluate(null, validFacts()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("stage must not be null");
        assertThatThrownBy(() -> evaluator.evaluate(TOOL, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("facts must not be null");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t"})
    void rejectsNullOrBlankRequestedTool(String requestedTool) {
        assertThatThrownBy(() -> facts(
                requestedTool,
                "READ",
                baseCatalog(),
                List.of(CUSTOMER_DATA_READ),
                true,
                List.of()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("requestedTool must not be blank");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t"})
    void rejectsNullOrBlankRequestedOperation(String requestedOperation) {
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                requestedOperation,
                baseCatalog(),
                List.of(CUSTOMER_DATA_READ),
                true,
                List.of()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("requestedOperation must not be blank");
    }

    @Test
    void rejectsNullCollectionsAndNullMembers() {
        assertThatThrownBy(() -> facts(CUSTOMER_DATA_READ, "READ", null, List.of(), true, List.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogTools must not be null");
        assertThatThrownBy(() -> facts(CUSTOMER_DATA_READ, "READ", baseCatalog(), null, true, List.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("allowedTools must not be null");
        assertThatThrownBy(() -> facts(CUSTOMER_DATA_READ, "READ", baseCatalog(), List.of(), true, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("humanOnlyTools must not be null");

        List<CatalogTool> catalogWithNull = new ArrayList<>(baseCatalog());
        catalogWithNull.add(null);
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                "READ",
                catalogWithNull,
                List.of(),
                true,
                List.of()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogTools must not contain null entries");

        List<String> allowedWithNull = new ArrayList<>();
        allowedWithNull.add(null);
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                "READ",
                baseCatalog(),
                allowedWithNull,
                true,
                List.of()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("allowedTools[0] must not be blank");

        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                "READ",
                baseCatalog(),
                List.of(" "),
                true,
                List.of()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("allowedTools[0] must not be blank");

        List<String> humanOnlyWithNull = new ArrayList<>();
        humanOnlyWithNull.add(null);
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                "READ",
                baseCatalog(),
                List.of(),
                true,
                humanOnlyWithNull
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("humanOnlyTools[0] must not be blank");

        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                "READ",
                baseCatalog(),
                List.of(),
                true,
                List.of("\t")
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("humanOnlyTools[0] must not be blank");
    }

    @Test
    void rejectsDuplicateFactsBeforeLookupConversion() {
        List<CatalogTool> duplicateCatalog = List.of(
                new CatalogTool(CUSTOMER_DATA_READ, "READ", false),
                new CatalogTool(CUSTOMER_DATA_READ, "WRITE", false)
        );
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                "READ",
                duplicateCatalog,
                List.of(),
                true,
                List.of()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogTools must not contain duplicate tool names");

        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                "READ",
                baseCatalog(),
                List.of(CUSTOMER_DATA_READ, CUSTOMER_DATA_READ),
                true,
                List.of()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("allowedTools must not contain duplicate values");

        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                "READ",
                baseCatalog(),
                List.of(),
                true,
                List.of(LOAN_DECISION_UPDATE, LOAN_DECISION_UPDATE)
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("humanOnlyTools must not contain duplicate values");
    }

    @Test
    void rejectsInvalidCatalogScalars() {
        assertThatThrownBy(() -> new CatalogTool(null, "READ", false))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalog tool name must not be blank");
        assertThatThrownBy(() -> new CatalogTool(" ", "READ", false))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalog tool name must not be blank");
        assertThatThrownBy(() -> new CatalogTool(CUSTOMER_DATA_READ, null, false))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalog tool operation must not be blank");
        assertThatThrownBy(() -> new CatalogTool(CUSTOMER_DATA_READ, "\t", false))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalog tool operation must not be blank");
    }

    @Test
    void defensivelyCopiesInputsAndExposesImmutableCollections() {
        List<CatalogTool> catalog = new ArrayList<>(baseCatalog());
        List<String> allowed = new ArrayList<>(List.of(CUSTOMER_DATA_READ));
        List<String> humanOnly = new ArrayList<>(List.of(LOAN_DECISION_UPDATE));
        PolicyToolAuthorizationFacts facts = facts(
                CUSTOMER_DATA_READ,
                "READ",
                catalog,
                allowed,
                true,
                humanOnly
        );

        catalog.clear();
        allowed.clear();
        humanOnly.clear();

        assertThat(facts.catalogTools()).containsExactlyElementsOf(baseCatalog());
        assertThat(facts.allowedTools()).containsExactly(CUSTOMER_DATA_READ);
        assertThat(facts.humanOnlyTools()).containsExactly(LOAN_DECISION_UPDATE);
        assertThat(evaluator.evaluate(TOOL, facts)).isEqualTo(StageOutcome.pass(TOOL));
        assertThatThrownBy(() -> facts.catalogTools().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> facts.allowedTools().add(REVIEW_NOTE_WRITE))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> facts.humanOnlyTools().clear())
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void repeatedEvaluationIsDeterministicAndDecisionEvidenceIsImmutable() {
        PolicyToolAuthorizationFacts facts = facts(
                EXTERNAL_HTTP,
                "POST",
                baseCatalog(),
                List.of(CUSTOMER_DATA_READ),
                true,
                List.of()
        );

        StageOutcome firstToolOutcome = evaluator.evaluate(TOOL, facts);
        StageOutcome repeatedToolOutcome = evaluator.evaluate(TOOL, facts);
        PolicyEvaluationDecision firstDecision = evaluateWithSpecificDenial(facts, EGRESS);
        PolicyEvaluationDecision repeatedDecision = evaluateWithSpecificDenial(facts, EGRESS);

        assertThat(repeatedToolOutcome).isEqualTo(firstToolOutcome);
        assertThat(repeatedDecision).isEqualTo(firstDecision);
        assertThatThrownBy(() -> firstDecision.evaluatedStages().add(WORKFLOW))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    private PolicyEvaluationDecision evaluateWithSpecificDenial(
            PolicyToolAuthorizationFacts facts,
            PolicyEvaluationStage terminalStage
    ) {
        return PolicyEvaluationSequence.evaluate(
                () -> StageOutcome.pass(PREFLIGHT),
                stage -> {
                    if (stage == TOOL || stage == OPERATION) {
                        return evaluator.evaluate(stage, facts);
                    }
                    if (stage == EGRESS && terminalStage == EGRESS) {
                        return StageOutcome.deny(EGRESS, EXTERNAL_EGRESS_DENIED);
                    }
                    if (stage == HUMAN_BOUNDARY && terminalStage == HUMAN_BOUNDARY) {
                        return StageOutcome.deny(HUMAN_BOUNDARY, HUMAN_ONLY_ACTION);
                    }
                    return StageOutcome.pass(stage);
                }
        );
    }

    private PolicyToolAuthorizationFacts validFacts() {
        return facts(
                CUSTOMER_DATA_READ,
                "READ",
                baseCatalog(),
                List.of(CUSTOMER_DATA_READ),
                true,
                List.of(LOAN_DECISION_UPDATE)
        );
    }

    private PolicyToolAuthorizationFacts facts(
            String requestedTool,
            String requestedOperation,
            List<CatalogTool> catalogTools,
            List<String> allowedTools,
            boolean externalEgressExplicitlyDenied,
            List<String> humanOnlyTools
    ) {
        return new PolicyToolAuthorizationFacts(
                requestedTool,
                requestedOperation,
                catalogTools,
                allowedTools,
                externalEgressExplicitlyDenied,
                humanOnlyTools
        );
    }

    private List<CatalogTool> baseCatalog() {
        return List.of(
                new CatalogTool(CUSTOMER_DATA_READ, "READ", false),
                new CatalogTool(REVIEW_NOTE_WRITE, "CREATE", false),
                new CatalogTool(EXTERNAL_HTTP, "POST", true),
                new CatalogTool(LOAN_DECISION_UPDATE, "UPDATE", false)
        );
    }
}
