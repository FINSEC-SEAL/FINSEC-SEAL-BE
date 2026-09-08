package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEvaluationStage.*;
import static com.finsecseal.policy.PolicyEvaluationReason.*;
import static com.finsecseal.policy.PolicyToolTrustFacts.TrustLevel.TRUSTED_INTERNAL;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

import com.finsecseal.policy.PolicyEvaluationDecision.DecisionType;
import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;
import com.finsecseal.policy.EnforcePolicyEvaluator.PolicyEvaluationTimeoutException;
import com.finsecseal.policy.PolicyEvaluationSequence.PolicyEvaluationException;
import com.finsecseal.policy.PolicyEvaluationSequence.PolicyStageEvaluator;
import com.finsecseal.policy.PolicyEvaluationSequence.PreflightEvaluator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InOrder;
import org.mockito.stubbing.Answer;

/** Judgment composition evidence only; the preflight stub is not production source verification. */
class EnforcePolicyEvaluatorTest {

    private static final String CUSTOMER = "CUSTOMER_DATA_READ";
    private static final String PURPOSE = "LOAN_DOCUMENT_COMPLETENESS_REVIEW";
    private static final String CASE = "CASE-1001";
    private static final String APPLICANT = "CUST-1001";
    private static final String WORKFLOW = "DOCUMENT_REVIEW";
    private static final List<String> DOCUMENTS = List.of("DOC-1001", "DOC-1002");
    private static final List<String> FIELDS = List.of("incomeBand", "employmentStatus");
    private static final String RELEASE_HASH = digest('c');
    private static final List<PolicyEvaluationStage> LAZY_EXPECTED_ORDER = List.of(
            PREFLIGHT, TOOL, OPERATION, BUSINESS_CONTEXT, OBJECT_SCOPE, FIELD_SCOPE,
            CARDINALITY, EGRESS, PolicyEvaluationStage.WORKFLOW, HUMAN_BOUNDARY, TOOL_TRUST);

    private PolicyToolAuthorizationEvaluator authorization;
    private PolicyBusinessContextEvaluator business;
    private PolicyObjectScopeEvaluator object;
    private PolicyFieldScopeEvaluator field;
    private PolicyCardinalityEvaluator cardinality;
    private PolicyEgressEvaluator egress;
    private PolicyWorkflowEvaluator workflow;
    private PolicyHumanBoundaryEvaluator human;
    private PolicyToolTrustEvaluator trust;
    private PreflightEvaluator preflight;
    private EnforcePolicyEvaluator evaluator;
    private AtomicLong nanos;

    @BeforeEach
    void setUp() {
        authorization = spy(new PolicyToolAuthorizationEvaluator());
        business = spy(new PolicyBusinessContextEvaluator());
        object = spy(new PolicyObjectScopeEvaluator());
        field = spy(new PolicyFieldScopeEvaluator());
        cardinality = spy(new PolicyCardinalityEvaluator());
        egress = spy(new PolicyEgressEvaluator());
        workflow = spy(new PolicyWorkflowEvaluator());
        human = spy(new PolicyHumanBoundaryEvaluator());
        trust = spy(new PolicyToolTrustEvaluator());
        preflight = mock(PreflightEvaluator.class);
        when(preflight.evaluate()).thenReturn(StageOutcome.pass(PREFLIGHT));
        nanos = new AtomicLong();
        evaluator = evaluatorWithClock(nanos::get);
    }

    @Test
    void normalRequestInvokesEveryRealStageOnceInOrder() {
        EnforcePolicyEvaluationFacts facts = new Fixture().build();

        PolicyEvaluationDecision decision = evaluator.evaluate(preflight, facts);

        assertThat(decision.decisionType()).isEqualTo(DecisionType.ALLOW);
        assertThat(decision.evaluatedStages()).isEqualTo(PolicyEvaluationStage.completeOrder());
        assertThat(decision.reason()).isEmpty();
        assertThat(decision.successfulSecurityBlock()).isFalse();
        verifyExactInvocations(facts, decision);
        assertThat(new EnforcePolicyEvaluator().evaluate(() -> StageOutcome.pass(PREFLIGHT), facts))
                .isEqualTo(decision);
        assertThatThrownBy(() -> decision.evaluatedStages().clear())
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("policyFailures")
    void preservesPrimaryReasonAndNeverInvokesLaterEvaluators(
            String name, Fixture fixture, PolicyEvaluationStage stage, PolicyEvaluationReason reason
    ) {
        EnforcePolicyEvaluationFacts facts = fixture.build();

        PolicyEvaluationDecision decision = evaluator.evaluate(preflight, facts);

        assertThat(decision.failedStage()).contains(stage);
        assertThat(decision.reason()).contains(reason);
        assertThat(decision.decisionType()).isEqualTo(
                reason.classification() == PolicyEvaluationReason.TerminalClassification.ERROR
                        ? DecisionType.ERROR : DecisionType.DENY
        );
        assertThat(decision.successfulSecurityBlock())
                .isEqualTo(decision.decisionType() == DecisionType.DENY);
        verifyExactInvocations(facts, decision);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("inconsistentFacts")
    void inconsistentRequestFactsFailBeforeAnyPolicyJudgment(String name, Consumer<Fixture> change) {
        Fixture fixture = new Fixture();
        change.accept(fixture);
        EnforcePolicyEvaluationFacts facts = fixture.build();

        PolicyEvaluationDecision decision = evaluator.evaluate(preflight, facts);

        assertThat(decision.decisionType()).isEqualTo(DecisionType.ERROR);
        assertThat(decision.reason()).contains(CONTEXT_INTEGRITY_FAILURE);
        assertThat(decision.failedStage()).contains(PREFLIGHT);
        assertThat(decision.evaluatedStages()).containsExactly(PREFLIGHT);
        assertThat(decision.successfulSecurityBlock()).isFalse();
        verifyExactInvocations(facts, decision);
    }

    @Test
    void preflightErrorHasPriorityOverInconsistentFactsAndPolicyViolations() {
        Fixture fixture = new Fixture();
        fixture.egress = new Fixture("EXTERNAL_HTTP", true, true, false).egress;
        when(preflight.evaluate()).thenReturn(StageOutcome.error(PREFLIGHT, POLICY_EVALUATION_TIMEOUT));
        EnforcePolicyEvaluationFacts facts = fixture.build();

        PolicyEvaluationDecision decision = evaluator.evaluate(preflight, facts);

        assertThat(decision.decisionType()).isEqualTo(DecisionType.ERROR);
        assertThat(decision.reason()).contains(POLICY_EVALUATION_TIMEOUT);
        assertThat(decision.evaluatedStages()).containsExactly(PREFLIGHT);
        assertThat(decision.successfulSecurityBlock()).isFalse();
        verifyExactInvocations(facts, decision);
    }

    @ParameterizedTest
    @MethodSource("malformedPreflight")
    void malformedPreflightCannotBecomeAllow(StageOutcome outcome) {
        when(preflight.evaluate()).thenReturn(outcome);

        assertThatThrownBy(() -> evaluator.evaluate(preflight, new Fixture().build()))
                .isInstanceOfSatisfying(PolicyEvaluationException.class,
                        error -> assertThat(error.stage()).isEqualTo(PREFLIGHT));
        verify(preflight).evaluate();
        verifyNoMoreInteractions(allEvaluators());
    }

    @Test
    void throwingPreflightDoesNotInvokePolicy() {
        when(preflight.evaluate()).thenThrow(new IllegalStateException("source unavailable"));

        assertThatThrownBy(() -> evaluator.evaluate(preflight, new Fixture().build()))
                .isInstanceOfSatisfying(PolicyEvaluationException.class,
                        error -> assertThat(error.stage()).isEqualTo(PREFLIGHT));
        verify(preflight).evaluate();
        verifyNoMoreInteractions(allEvaluators());
    }

    @Test
    void requiresExplicitPreflightAndFacts() {
        assertThatThrownBy(() -> evaluator.evaluate(null, new Fixture().build()))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> evaluator.evaluate(preflight, null))
                .isInstanceOf(NullPointerException.class);
        verifyNoMoreInteractions(allEvaluators());
    }

    @Test
    void unrelatedCatalogProjectionsAndDocumentOrderingDoNotChangeDecision() {
        Fixture fixture = new Fixture();
        fixture.object = new PolicyObjectScopeFacts(
                CUSTOMER, List.of(CUSTOMER, "DOCUMENT_LOOKUP"), fixture.object.scopePolicies(),
                fixture.object.requestedCaseId(), fixture.object.requestedDocumentIds(),
                fixture.object.requestedCustomerIds(), fixture.object.currentCaseId(),
                fixture.object.currentApplicantId(), Optional.of(List.of("DOC-1002", "DOC-1001")),
                fixture.object.documentOwnerships()
        );
        EnforcePolicyEvaluationFacts facts = fixture.build();

        PolicyEvaluationDecision decision = evaluator.evaluate(preflight, facts);

        assertThat(decision.decisionType()).isEqualTo(DecisionType.ALLOW);
        verifyExactInvocations(facts, decision);
    }

    @Test
    void expiredBeforePreflightInvokesNoCallbacks() {
        AtomicInteger reads = new AtomicInteger();
        evaluator = evaluatorWithClock(() -> reads.getAndIncrement() == 0 ? 0 : 100_000_000L);

        assertTimeout(new Fixture().build());

        verifyNoInteractions(allEvaluators());
    }

    @Test
    void slowPreflightCannotReturnPassOrInvokePolicy() {
        when(preflight.evaluate()).thenAnswer(call -> {
            nanos.set(100_000_000L);
            return StageOutcome.pass(PREFLIGHT);
        });
        EnforcePolicyEvaluationFacts facts = new Fixture().build();

        assertTimeout(facts);

        verifyInvocations(facts, List.of(PREFLIGHT));
    }

    @ParameterizedTest
    @EnumSource(value = PolicyEvaluationStage.class, names = "PREFLIGHT", mode = EnumSource.Mode.EXCLUDE)
    void latePassingStageCannotAllowOrInvokeLaterStages(PolicyEvaluationStage stage) {
        advanceClockAfterStage(stage, 100_000_000L);
        EnforcePolicyEvaluationFacts facts = new Fixture().build();

        assertTimeout(facts);

        verifyInvocations(facts, prefixThrough(stage));
    }

    @Test
    void lateDenialIsAnOperationalTimeoutWithoutSecurityBlockResult() {
        Fixture fixture = new Fixture();
        fixture.object = objectFacts(Optional.of(CASE), Optional.of(APPLICANT),
                Optional.of(DOCUMENTS), List.of("CUST-OTHER"));
        advanceClockAfterStage(OBJECT_SCOPE, 100_000_000L);
        EnforcePolicyEvaluationFacts facts = fixture.build();

        assertTimeout(facts);

        verifyInvocations(facts, prefixThrough(OBJECT_SCOPE));
    }

    @Test
    void timelyFirstDenialRetainsItsReasonAndExactPrefix() {
        Fixture fixture = new Fixture();
        fixture.object = objectFacts(Optional.of(CASE), Optional.of(APPLICANT),
                Optional.of(DOCUMENTS), List.of("CUST-OTHER"));
        fixture.field = fieldFacts(List.of("accountNumber"));
        advanceClockAfterStage(OBJECT_SCOPE, 99_999_999L);
        EnforcePolicyEvaluationFacts facts = fixture.build();

        PolicyEvaluationDecision decision = evaluator.evaluate(preflight, facts);

        assertThat(decision.decisionType()).isEqualTo(DecisionType.DENY);
        assertThat(decision.reason()).contains(CUSTOMER_SCOPE_VIOLATION);
        assertThat(decision.successfulSecurityBlock()).isTrue();
        assertThat(decision.evaluatedStages()).isEqualTo(prefixThrough(OBJECT_SCOPE));
        verifyExactInvocations(facts, decision);
    }

    @Test
    void finalReturnFenceRejectsExpiryAfterLastStagePostCheck() {
        AtomicBoolean trustFinished = new AtomicBoolean();
        AtomicInteger readsAfterTrust = new AtomicInteger();
        evaluator = evaluatorWithClock(() -> !trustFinished.get() ? 0
                : readsAfterTrust.getAndIncrement() == 0 ? 99_999_999L : 100_000_000L);
        doAnswer(call -> {
            StageOutcome outcome = (StageOutcome) call.callRealMethod();
            trustFinished.set(true);
            return outcome;
        }).when(trust).evaluate(eq(TOOL_TRUST), any());
        EnforcePolicyEvaluationFacts facts = new Fixture().build();

        assertTimeout(facts);

        verifyInvocations(facts, PolicyEvaluationStage.completeOrder());
        assertThat(readsAfterTrust).hasValue(2);
    }

    @ParameterizedTest
    @ValueSource(longs = {0, 17, -100_000_001L, Long.MIN_VALUE, Long.MAX_VALUE - 50_000_000L})
    void elapsedSubtractionSupportsArbitraryOriginsAndSignedWrap(long origin) {
        nanos.set(origin);
        doAnswer(call -> {
            nanos.set(origin + 99_999_999L);
            return StageOutcome.pass(PREFLIGHT);
        }).when(preflight).evaluate();
        assertThat(evaluator.evaluate(preflight, new Fixture().build()).decisionType()).isEqualTo(DecisionType.ALLOW);

        nanos.set(origin);
        doAnswer(call -> {
            nanos.set(origin + 100_000_000L);
            return StageOutcome.pass(PREFLIGHT);
        }).when(preflight).evaluate();
        assertTimeout(new Fixture().build());
    }

    @Test
    void eachInvocationStartsItsOwnBudget() {
        when(preflight.evaluate()).thenAnswer(call -> {
            nanos.addAndGet(50_000_000L);
            return StageOutcome.pass(PREFLIGHT);
        });
        assertThat(evaluator.evaluate(preflight, new Fixture().build()).decisionType()).isEqualTo(DecisionType.ALLOW);
        nanos.set(5_000_000_000L);
        assertThat(evaluator.evaluate(preflight, new Fixture().build()).decisionType()).isEqualTo(DecisionType.ALLOW);
    }

    @Test
    void lazyStagesPreserveTheIndependentElevenStageOrder() {
        List<PolicyEvaluationStage> calls = new ArrayList<>();

        PolicyEvaluationDecision decision = evaluator.evaluateStages(() -> {
            calls.add(PREFLIGHT);
            return StageOutcome.pass(PREFLIGHT);
        }, stage -> {
            calls.add(stage);
            return StageOutcome.pass(stage);
        });

        assertThat(calls).containsExactlyElementsOf(LAZY_EXPECTED_ORDER);
        assertThat(decision.evaluatedStages()).containsExactlyElementsOf(LAZY_EXPECTED_ORDER);
        assertThat(decision.decisionType()).isEqualTo(DecisionType.ALLOW);
        assertThat(decision.reason()).isEmpty();
        assertThat(decision.successfulSecurityBlock()).isFalse();
        verifyNoInteractions(allEvaluators());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("lazyEarlierTerminals")
    void lazyEarlierTerminalNeverConstructsInvalidDownstreamTrustFacts(
            String name, Fixture fixture, PolicyEvaluationStage terminal, PolicyEvaluationReason reason
    ) {
        Supplier<PolicyToolTrustFacts> invalidTrust = () -> new PolicyToolTrustFacts(
                fixture.authorization.requestedTool(), RELEASE_HASH, RELEASE_HASH, List.of(),
                List.of(new PolicyToolTrustFacts.ReleaseToolBinding(
                        "UNRELATED_TOOL", "1.0.0", true, digest('a'), digest('b'))),
                new PolicyToolTrustFacts.ToolTrustPolicy(true, List.of(TRUSTED_INTERNAL)));
        // Control: this is an actual invalid constructor, not a mock that merely throws.
        assertThatThrownBy(invalidTrust::get).isInstanceOf(IllegalArgumentException.class)
                .hasMessage("releaseBindings must reference registry Tool identities");
        AtomicInteger downstreamConstructions = new AtomicInteger();
        List<PolicyEvaluationStage> calls = new ArrayList<>();

        PolicyEvaluationDecision decision = evaluator.evaluateStages(() -> {
            calls.add(PREFLIGHT);
            return StageOutcome.pass(PREFLIGHT);
        }, stage -> {
            calls.add(stage);
            return switch (stage) {
                case TOOL, OPERATION -> authorization.evaluate(stage, fixture.authorization);
                case BUSINESS_CONTEXT -> business.evaluate(stage, fixture.business);
                case OBJECT_SCOPE -> object.evaluate(stage, fixture.object);
                case FIELD_SCOPE -> field.evaluate(stage, fixture.field);
                case CARDINALITY -> cardinality.evaluate(stage, fixture.cardinality);
                case EGRESS -> egress.evaluate(stage, fixture.egress);
                case WORKFLOW -> workflow.evaluate(stage, fixture.workflow);
                case HUMAN_BOUNDARY -> human.evaluate(stage, fixture.human);
                case TOOL_TRUST -> {
                    downstreamConstructions.incrementAndGet();
                    yield trust.evaluate(stage, invalidTrust.get());
                }
                case PREFLIGHT -> throw new AssertionError("preflight must use its own callback");
            };
        });

        List<PolicyEvaluationStage> expectedPrefix = LAZY_EXPECTED_ORDER.subList(
                0, LAZY_EXPECTED_ORDER.indexOf(terminal) + 1);
        assertThat(decision.decisionType()).isEqualTo(DecisionType.DENY);
        assertThat(decision.reason()).contains(reason);
        assertThat(decision.failedStage()).contains(terminal);
        assertThat(decision.evaluatedStages()).containsExactlyElementsOf(expectedPrefix);
        assertThat(calls).containsExactlyElementsOf(expectedPrefix);
        assertThat(downstreamConstructions).hasValue(0);
        verifyNoInteractions(trust);
    }

    @ParameterizedTest
    @ValueSource(longs = {99_999_999L, 100_000_000L})
    void lazyFactsConstructionSharesTheCumulativeBudgetAndSuppressesLatePass(long totalNanos) {
        AtomicInteger constructions = new AtomicInteger();
        List<PolicyEvaluationStage> calls = new ArrayList<>();
        Supplier<PolicyObjectScopeFacts> facts = () -> {
            constructions.incrementAndGet();
            PolicyObjectScopeFacts result = objectFacts(Optional.of(CASE), Optional.of(APPLICANT),
                    Optional.of(DOCUMENTS), List.of(APPLICANT));
            nanos.addAndGet(totalNanos - 50_000_000L);
            return result;
        };
        Supplier<PolicyEvaluationDecision> evaluate = () -> evaluator.evaluateStages(() -> {
            calls.add(PREFLIGHT);
            nanos.addAndGet(20_000_000L);
            return StageOutcome.pass(PREFLIGHT);
        }, stage -> {
            calls.add(stage);
            if (stage == TOOL) nanos.addAndGet(30_000_000L);
            return stage == OBJECT_SCOPE ? object.evaluate(stage, facts.get()) : StageOutcome.pass(stage);
        });

        if (totalNanos == 100_000_000L) {
            assertThatThrownBy(evaluate::get).isInstanceOfSatisfying(
                    PolicyEvaluationTimeoutException.class, error -> {
                        assertThat(error.reason()).isEqualTo(POLICY_EVALUATION_TIMEOUT);
                        assertThat(error.getCause()).isNull();
                    });
            assertThat(calls).containsExactly(PREFLIGHT, TOOL, OPERATION, BUSINESS_CONTEXT, OBJECT_SCOPE);
        } else {
            PolicyEvaluationDecision decision = evaluate.get();
            assertThat(decision.decisionType()).isEqualTo(DecisionType.ALLOW);
            assertThat(decision.evaluatedStages()).containsExactlyElementsOf(LAZY_EXPECTED_ORDER);
            assertThat(calls).containsExactlyElementsOf(LAZY_EXPECTED_ORDER);
        }
        assertThat(constructions).hasValue(1);
        assertThat(nanos).hasValue(totalNanos);
    }

    @Test
    void lazyLateDenialIsUnwrappedTimeoutAndNeverReachesLaterStages() {
        List<PolicyEvaluationStage> calls = new ArrayList<>();

        assertThatThrownBy(() -> evaluator.evaluateStages(() -> {
            calls.add(PREFLIGHT);
            nanos.addAndGet(20_000_000L);
            return StageOutcome.pass(PREFLIGHT);
        }, stage -> {
            calls.add(stage);
            if (stage != OBJECT_SCOPE) return StageOutcome.pass(stage);
            PolicyObjectScopeFacts facts = objectFacts(Optional.of(CASE), Optional.of(APPLICANT),
                    Optional.of(DOCUMENTS), List.of("CUST-OTHER"));
            StageOutcome denial = object.evaluate(stage, facts);
            assertThat(denial.reason()).contains(CUSTOMER_SCOPE_VIOLATION);
            nanos.addAndGet(80_000_000L);
            return denial;
        })).isInstanceOfSatisfying(PolicyEvaluationTimeoutException.class, error -> {
            assertThat(error.reason()).isEqualTo(POLICY_EVALUATION_TIMEOUT);
            assertThat(error.getMessage()).isEqualTo("POLICY_EVALUATION_TIMEOUT");
            assertThat(error.getCause()).isNull();
        });

        assertThat(calls).containsExactly(PREFLIGHT, TOOL, OPERATION, BUSINESS_CONTEXT, OBJECT_SCOPE);
        assertThat(nanos).hasValue(100_000_000L);
    }

    @ParameterizedTest
    @ValueSource(strings = {"null preflight", "null stages", "null outcome", "wrong stage", "throws"})
    void lazyMalformedCallbacksFailBeforeAnyLaterStage(String mode) {
        List<PolicyEvaluationStage> calls = new ArrayList<>();
        PreflightEvaluator source = "null preflight".equals(mode) ? null : () -> {
            calls.add(PREFLIGHT);
            return StageOutcome.pass(PREFLIGHT);
        };
        PolicyStageEvaluator stages = "null stages".equals(mode) ? null : stage -> {
            calls.add(stage);
            if (stage != OPERATION) return StageOutcome.pass(stage);
            return switch (mode) {
                case "null outcome" -> null;
                case "wrong stage" -> StageOutcome.pass(TOOL_TRUST);
                case "throws" -> throw new IllegalStateException("fixture construction failed");
                default -> throw new AssertionError("missing callback should fail before invocation");
            };
        };

        if (source == null || stages == null) {
            assertThatThrownBy(() -> evaluator.evaluateStages(source, stages))
                    .isInstanceOf(NullPointerException.class);
            assertThat(calls).isEmpty();
        } else {
            assertThatThrownBy(() -> evaluator.evaluateStages(source, stages))
                    .isInstanceOfSatisfying(PolicyEvaluationException.class, error -> {
                        assertThat(error.stage()).isEqualTo(OPERATION);
                        if ("throws".equals(mode)) {
                            assertThat(error.getCause()).isInstanceOf(IllegalStateException.class);
                        } else {
                            assertThat(error.getCause()).isNull();
                        }
                    });
            assertThat(calls).containsExactly(PREFLIGHT, TOOL, OPERATION);
        }
        verifyNoInteractions(allEvaluators());
    }

    private static Stream<Arguments> lazyEarlierTerminals() {
        Fixture customer = new Fixture();
        customer.object = objectFacts(Optional.of(CASE), Optional.of(APPLICANT),
                Optional.of(DOCUMENTS), List.of("CUST-OTHER"));
        customer.field = fieldFacts(List.of("accountNumber"));
        return Stream.of(
                Arguments.of("unknown tool", new Fixture("UNKNOWN_TOOL", false, false, false),
                        TOOL, TOOL_NOT_ALLOWED),
                Arguments.of("customer before field and trust", customer, OBJECT_SCOPE, CUSTOMER_SCOPE_VIOLATION),
                Arguments.of("human boundary", new Fixture("LOAN_DECISION_UPDATE", true, false, true),
                        HUMAN_BOUNDARY, HUMAN_ONLY_ACTION));
    }

    private EnforcePolicyEvaluator evaluatorWithClock(LongSupplier clock) {
        return new EnforcePolicyEvaluator(authorization, business, object, field, cardinality,
                egress, workflow, human, trust, clock);
    }

    private void assertTimeout(EnforcePolicyEvaluationFacts facts) {
        assertThatThrownBy(() -> evaluator.evaluate(preflight, facts))
                .isInstanceOfSatisfying(PolicyEvaluationTimeoutException.class, exception -> {
                    assertThat(exception.reason()).isEqualTo(POLICY_EVALUATION_TIMEOUT);
                    assertThat(exception.getMessage()).isEqualTo("POLICY_EVALUATION_TIMEOUT");
                    assertThat(exception.getCause()).isNull();
                });
    }

    private void advanceClockAfterStage(PolicyEvaluationStage stage, long time) {
        Answer<StageOutcome> answer = call -> {
            StageOutcome result = (StageOutcome) call.callRealMethod();
            nanos.set(time);
            return result;
        };
        switch (stage) {
            case TOOL, OPERATION -> doAnswer(answer).when(authorization).evaluate(eq(stage), any());
            case BUSINESS_CONTEXT -> doAnswer(answer).when(business).evaluate(eq(stage), any());
            case OBJECT_SCOPE -> doAnswer(answer).when(object).evaluate(eq(stage), any());
            case FIELD_SCOPE -> doAnswer(answer).when(field).evaluate(eq(stage), any());
            case CARDINALITY -> doAnswer(answer).when(cardinality).evaluate(eq(stage), any());
            case EGRESS -> doAnswer(answer).when(egress).evaluate(eq(stage), any());
            case WORKFLOW -> doAnswer(answer).when(workflow).evaluate(eq(stage), any());
            case HUMAN_BOUNDARY -> doAnswer(answer).when(human).evaluate(eq(stage), any());
            case TOOL_TRUST -> doAnswer(answer).when(trust).evaluate(eq(stage), any());
            case PREFLIGHT -> throw new IllegalArgumentException("Use preflight callback clock control");
        }
    }

    private static List<PolicyEvaluationStage> prefixThrough(PolicyEvaluationStage stage) {
        List<PolicyEvaluationStage> order = PolicyEvaluationStage.completeOrder();
        return order.subList(0, order.indexOf(stage) + 1);
    }

    private static Stream<StageOutcome> malformedPreflight() {
        return Stream.of(null, StageOutcome.pass(TOOL), StageOutcome.deny(TOOL, TOOL_NOT_ALLOWED));
    }

    private static Stream<Arguments> policyFailures() {
        Fixture unknown = new Fixture("UNKNOWN_TOOL", false, false, false);
        Fixture genericDeny = new Fixture();
        genericDeny.authorization = authorization(CUSTOMER, "READ", true, false, false, false, false);
        Fixture operation = new Fixture();
        operation.authorization = authorization(CUSTOMER, "WRITE", true, false, false, true, false);
        Fixture context = new Fixture();
        context.business = context(false, Optional.of(CASE), Optional.of(APPLICANT),
                Optional.of(WORKFLOW), Optional.of(DOCUMENTS));
        Fixture objectAndField = new Fixture();
        objectAndField.object = objectFacts(Optional.of(CASE), Optional.of(APPLICANT),
                Optional.of(DOCUMENTS), List.of("CUST-OTHER"));
        objectAndField.field = fieldFacts(List.of("accountNumber"));
        Fixture fieldAndWorkflow = new Fixture();
        fieldAndWorkflow.field = fieldFacts(List.of("accountNumber"));
        fieldAndWorkflow.workflow = workflow(CUSTOMER, WORKFLOW, List.of("ANOTHER_STAGE"), true);
        Fixture cardinality = new Fixture("DOCUMENT_LOOKUP", true, false, false);
        cardinality.cardinality = new PolicyCardinalityFacts("DOCUMENT_LOOKUP", 2,
                List.of("DOCUMENT_LOOKUP"), List.of(new PolicyCardinalityFacts.CardinalityPolicy("DOCUMENT_LOOKUP", 1)));
        Fixture workflow = new Fixture();
        workflow.workflow = workflow(CUSTOMER, WORKFLOW, List.of("ANOTHER_STAGE"), true);
        Fixture external = new Fixture("EXTERNAL_HTTP", true, true, false);
        Fixture absentExternalRule = new Fixture("EXTERNAL_HTTP", true, true, false);
        absentExternalRule.authorization = authorization("EXTERNAL_HTTP", "READ", true, true, false, false, false);
        Fixture human = new Fixture("LOAN_DECISION_UPDATE", true, false, true);
        Fixture trust = new Fixture();
        trust.trust = new PolicyToolTrustFacts(CUSTOMER, RELEASE_HASH, digest('d'),
                trust.trust.registryEntries(), trust.trust.releaseBindings(), trust.trust.trustPolicy());
        return Stream.of(
                Arguments.of("unknown tool", unknown, TOOL, TOOL_NOT_ALLOWED),
                Arguments.of("ordinary unlisted tool", genericDeny, TOOL, TOOL_NOT_ALLOWED),
                Arguments.of("operation", operation, OPERATION, OPERATION_NOT_ALLOWED),
                Arguments.of("server context", context, BUSINESS_CONTEXT, CONTEXT_INTEGRITY_FAILURE),
                Arguments.of("object precedes field", objectAndField, OBJECT_SCOPE, CUSTOMER_SCOPE_VIOLATION),
                Arguments.of("field precedes workflow", fieldAndWorkflow, FIELD_SCOPE, FIELD_SCOPE_VIOLATION),
                Arguments.of("cardinality", cardinality, CARDINALITY, RECORD_LIMIT_EXCEEDED),
                Arguments.of("external", external, EGRESS, EXTERNAL_EGRESS_DENIED),
                Arguments.of("no explicit external rule", absentExternalRule, TOOL, TOOL_NOT_ALLOWED),
                Arguments.of("workflow", workflow, PolicyEvaluationStage.WORKFLOW, INVALID_WORKFLOW_STAGE),
                Arguments.of("server-only human action", human, HUMAN_BOUNDARY, HUMAN_ONLY_ACTION),
                Arguments.of("trust integrity stays at trust", trust, TOOL_TRUST, TOOL_INTEGRITY_FAILURE)
        );
    }

    private static Stream<Arguments> inconsistentFacts() {
        Fixture other = new Fixture("DOCUMENT_LOOKUP", true, false, false);
        return Stream.of(
                mismatch("object request", f -> f.object = other.object),
                mismatch("field request", f -> f.field = other.field),
                mismatch("cardinality request", f -> f.cardinality = other.cardinality),
                mismatch("egress request", f -> f.egress = other.egress),
                mismatch("workflow request", f -> f.workflow = other.workflow),
                mismatch("human request", f -> f.human = other.human),
                mismatch("trust request", f -> f.trust = other.trust),
                mismatch("authorization catalog", f -> f.authorization = authorization(CUSTOMER, "READ", false, false, false, true, false)),
                mismatch("object catalog", f -> f.object = new PolicyObjectScopeFacts(CUSTOMER, List.of(), List.of(),
                        Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty())),
                mismatch("field catalog", f -> f.field = new PolicyFieldScopeFacts(CUSTOMER, Optional.empty(), List.of(), List.of())),
                mismatch("cardinality catalog", f -> f.cardinality = new PolicyCardinalityFacts(CUSTOMER, 1, List.of(), List.of())),
                mismatch("egress catalog", f -> f.egress = new PolicyEgressFacts(CUSTOMER, List.of(), false, List.of())),
                mismatch("workflow catalog", f -> f.workflow = workflow(CUSTOMER, WORKFLOW, List.of(WORKFLOW), false)),
                mismatch("human catalog", f -> f.human = new PolicyHumanBoundaryFacts(CUSTOMER, List.of(), List.of())),
                mismatch("authorization external classification", f -> f.authorization = authorization(CUSTOMER, "READ", true, true, false, true, true)),
                mismatch("egress external classification", f -> f.egress = egress(CUSTOMER, true, true)),
                mismatch("authorization human classification", f -> f.authorization = authorization(CUSTOMER, "READ", true, false, true, true, true)),
                mismatch("human classification", f -> f.human = human(CUSTOMER, true, true)),
                mismatch("case identity", f -> f.object = objectFacts(Optional.of("CASE-OTHER"), Optional.of(APPLICANT), Optional.of(DOCUMENTS), List.of(APPLICANT))),
                mismatch("missing business case", f -> f.business = context(true, Optional.empty(), Optional.of(APPLICANT), Optional.of(WORKFLOW), Optional.of(DOCUMENTS))),
                mismatch("applicant identity", f -> f.object = objectFacts(Optional.of(CASE), Optional.of("CUST-OTHER"), Optional.of(DOCUMENTS), List.of(APPLICANT))),
                mismatch("missing business applicant", f -> f.business = context(true, Optional.of(CASE), Optional.empty(), Optional.of(WORKFLOW), Optional.of(DOCUMENTS))),
                mismatch("document set", f -> f.object = objectFacts(Optional.of(CASE), Optional.of(APPLICANT), Optional.of(List.of("DOC-OTHER")), List.of(APPLICANT))),
                mismatch("missing business documents", f -> f.business = context(true, Optional.of(CASE), Optional.of(APPLICANT), Optional.of(WORKFLOW), Optional.empty())),
                mismatch("duplicate business documents", f -> f.business = context(true, Optional.of(CASE), Optional.of(APPLICANT), Optional.of(WORKFLOW), Optional.of(List.of("DOC-1001", "DOC-1001")))),
                mismatch("blank business document", f -> f.business = context(true, Optional.of(CASE), Optional.of(APPLICANT), Optional.of(WORKFLOW), Optional.of(List.of(" ")))),
                mismatch("null business document", f -> f.business = context(true, Optional.of(CASE), Optional.of(APPLICANT), Optional.of(WORKFLOW), Optional.of(Arrays.asList("DOC-1001", null)))),
                mismatch("workflow context", f -> f.workflow = workflow(CUSTOMER, "ANOTHER_STAGE", List.of(WORKFLOW), true)),
                mismatch("requested customer count", f -> f.cardinality = new PolicyCardinalityFacts(CUSTOMER, 2, List.of(CUSTOMER), f.cardinality.cardinalityPolicies()))
        );
    }

    private static Arguments mismatch(String name, Consumer<Fixture> change) {
        return Arguments.of(name, change);
    }

    private void verifyExactInvocations(EnforcePolicyEvaluationFacts facts, PolicyEvaluationDecision decision) {
        verifyInvocations(facts, decision.evaluatedStages());
    }

    private void verifyInvocations(EnforcePolicyEvaluationFacts facts, List<PolicyEvaluationStage> stages) {
        InOrder order = inOrder(allEvaluators());
        order.verify(preflight).evaluate();
        for (PolicyEvaluationStage stage : stages) {
            switch (stage) {
                case PREFLIGHT -> { }
                case TOOL, OPERATION -> order.verify(authorization).evaluate(stage, facts.authorization());
                case BUSINESS_CONTEXT -> order.verify(business).evaluate(stage, facts.businessContext());
                case OBJECT_SCOPE -> order.verify(object).evaluate(stage, facts.objectScope());
                case FIELD_SCOPE -> order.verify(field).evaluate(stage, facts.fieldScope());
                case CARDINALITY -> order.verify(cardinality).evaluate(stage, facts.cardinality());
                case EGRESS -> order.verify(egress).evaluate(stage, facts.egress());
                case WORKFLOW -> order.verify(workflow).evaluate(stage, facts.workflow());
                case HUMAN_BOUNDARY -> order.verify(human).evaluate(stage, facts.humanBoundary());
                case TOOL_TRUST -> order.verify(trust).evaluate(stage, facts.toolTrust());
            }
        }
        verifyNoMoreInteractions(allEvaluators());
    }

    private Object[] allEvaluators() {
        return new Object[]{preflight, authorization, business, object, field, cardinality, egress, workflow, human, trust};
    }

    private static final class Fixture {
        PolicyToolAuthorizationFacts authorization;
        PolicyBusinessContextFacts business;
        PolicyObjectScopeFacts object;
        PolicyFieldScopeFacts field;
        PolicyCardinalityFacts cardinality;
        PolicyEgressFacts egress;
        PolicyWorkflowFacts workflow;
        PolicyHumanBoundaryFacts human;
        PolicyToolTrustFacts trust;

        Fixture() {
            this(CUSTOMER, true, false, false);
        }

        Fixture(String tool, boolean known, boolean external, boolean humanOnly) {
            authorization = authorization(tool, "READ", known, external, humanOnly, !external && !humanOnly, true);
            business = context(true, Optional.of(CASE), Optional.of(APPLICANT), Optional.of(WORKFLOW), Optional.of(DOCUMENTS));
            object = tool.equals(CUSTOMER)
                    ? objectFacts(Optional.of(CASE), Optional.of(APPLICANT), Optional.of(DOCUMENTS), List.of(APPLICANT))
                    : new PolicyObjectScopeFacts(tool, known ? List.of(tool) : List.of(), List.of(),
                            Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                            Optional.empty(), Optional.empty(), Optional.empty());
            field = tool.equals(CUSTOMER) ? fieldFacts(FIELDS)
                    : new PolicyFieldScopeFacts(tool, Optional.empty(), known
                            ? List.of(new PolicyFieldScopeFacts.ToolOutputSchema(tool, List.of())) : List.of(), List.of());
            cardinality = new PolicyCardinalityFacts(tool, tool.equals(CUSTOMER) ? 1 : 0,
                    known ? List.of(tool) : List.of(), tool.equals(CUSTOMER)
                            ? List.of(new PolicyCardinalityFacts.CardinalityPolicy(tool, 1)) : List.of());
            egress = egress(tool, known, external);
            workflow = workflow(tool, WORKFLOW, List.of(WORKFLOW), known);
            human = human(tool, known, humanOnly);
            trust = new PolicyToolTrustFacts(tool, RELEASE_HASH, RELEASE_HASH,
                    known && !external && !humanOnly ? List.of(new PolicyToolTrustFacts.ToolRegistryEntry(
                            tool, "1.0.0", TRUSTED_INTERNAL, digest('a'), digest('b'))) : List.of(),
                    known && !external && !humanOnly ? List.of(new PolicyToolTrustFacts.ReleaseToolBinding(
                            tool, "1.0.0", true, digest('a'), digest('b'))) : List.of(),
                    new PolicyToolTrustFacts.ToolTrustPolicy(true, List.of(TRUSTED_INTERNAL)));
        }

        EnforcePolicyEvaluationFacts build() {
            return new EnforcePolicyEvaluationFacts(authorization, business, object, field,
                    cardinality, egress, workflow, human, trust);
        }
    }

    private static PolicyToolAuthorizationFacts authorization(String tool, String operation, boolean known,
            boolean external, boolean human, boolean allowed, boolean explicitEgress) {
        return new PolicyToolAuthorizationFacts(tool, operation, known
                ? List.of(new PolicyToolAuthorizationFacts.CatalogTool(tool, "READ", external)) : List.of(),
                allowed ? List.of(tool) : List.of(), explicitEgress, human ? List.of(tool) : List.of());
    }

    private static PolicyBusinessContextFacts context(boolean resolved, Optional<String> caseId,
            Optional<String> applicant, Optional<String> stage, Optional<List<String>> documents) {
        return new PolicyBusinessContextFacts(resolved, Optional.of(PURPOSE), Optional.of(PURPOSE),
                Optional.of(PURPOSE), Optional.of(PURPOSE), Optional.of("namespace-1"),
                caseId, applicant, stage, documents);
    }

    private static PolicyObjectScopeFacts objectFacts(Optional<String> currentCase, Optional<String> applicant,
            Optional<List<String>> documents, List<String> requestedCustomers) {
        return new PolicyObjectScopeFacts(CUSTOMER, List.of(CUSTOMER),
                List.of(new PolicyObjectScopeFacts.ObjectScopePolicy(CUSTOMER, false, false, true)),
                Optional.empty(), Optional.empty(), Optional.of(requestedCustomers),
                currentCase, applicant, documents, Optional.empty());
    }

    private static PolicyFieldScopeFacts fieldFacts(List<String> requested) {
        return new PolicyFieldScopeFacts(CUSTOMER, Optional.of(requested),
                List.of(new PolicyFieldScopeFacts.ToolOutputSchema(CUSTOMER,
                        List.of("incomeBand", "employmentStatus", "accountNumber"))),
                List.of(new PolicyFieldScopeFacts.FieldPolicy(CUSTOMER, FIELDS, true)));
    }

    private static PolicyEgressFacts egress(String tool, boolean known, boolean external) {
        return new PolicyEgressFacts(tool, known ? List.of(new PolicyEgressFacts.CatalogTool(tool,
                external ? PolicyEgressFacts.EgressClassification.EXTERNAL
                        : PolicyEgressFacts.EgressClassification.INTERNAL)) : List.of(), false, List.of());
    }

    private static PolicyWorkflowFacts workflow(String tool, String stage, List<String> allowed, boolean known) {
        return new PolicyWorkflowFacts(tool, stage, allowed,
                known ? List.of(new PolicyWorkflowFacts.CatalogTool(tool, false)) : List.of());
    }

    private static PolicyHumanBoundaryFacts human(String tool, boolean known, boolean highImpact) {
        return new PolicyHumanBoundaryFacts(tool, known ? List.of(tool) : List.of(), highImpact
                ? List.of(new PolicyHumanBoundaryFacts.HighImpactAction(tool,
                        PolicyHumanBoundaryFacts.BoundaryMode.HUMAN_ONLY)) : List.of());
    }

    private static String digest(char value) {
        return "sha256:" + String.valueOf(value).repeat(64);
    }
}
