package com.finsecseal.policy;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.finsecseal.policy.PolicyEvaluationDecision.DecisionType;
import com.finsecseal.policy.PolicyEvaluationDecision.OutcomeType;
import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;
import com.finsecseal.policy.PolicyEvaluationSequence.PolicyEvaluationException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class PolicyEvaluationSequenceTest {

    private static final List<PolicyEvaluationStage> AUTHORITATIVE_ORDER = List.of(
            PolicyEvaluationStage.PREFLIGHT,
            PolicyEvaluationStage.TOOL,
            PolicyEvaluationStage.OPERATION,
            PolicyEvaluationStage.BUSINESS_CONTEXT,
            PolicyEvaluationStage.OBJECT_SCOPE,
            PolicyEvaluationStage.FIELD_SCOPE,
            PolicyEvaluationStage.CARDINALITY,
            PolicyEvaluationStage.EGRESS,
            PolicyEvaluationStage.WORKFLOW,
            PolicyEvaluationStage.HUMAN_BOUNDARY,
            PolicyEvaluationStage.TOOL_TRUST
    );

    @Test
    void evaluatesPreflightFirstThenEveryPolicyStageExactlyOnce() {
        List<PolicyEvaluationStage> calls = new ArrayList<>();
        AtomicInteger preflightCalls = new AtomicInteger();

        PolicyEvaluationDecision decision = PolicyEvaluationSequence.evaluate(
                () -> {
                    preflightCalls.incrementAndGet();
                    calls.add(PolicyEvaluationStage.PREFLIGHT);
                    return StageOutcome.pass(PolicyEvaluationStage.PREFLIGHT);
                },
                stage -> {
                    calls.add(stage);
                    return StageOutcome.pass(stage);
                }
        );

        assertEquals(DecisionType.ALLOW, decision.decisionType());
        assertEquals(1, preflightCalls.get());
        assertEquals(AUTHORITATIVE_ORDER, calls);
        assertEquals(AUTHORITATIVE_ORDER, decision.evaluatedStages());
        assertTrue(decision.reason().isEmpty());
        assertTrue(decision.failedStage().isEmpty());
        assertFalse(decision.successfulSecurityBlock());
    }

    @Test
    void productionOrderMatchesIndependentAuthoritativeOracle() {
        assertEquals(AUTHORITATIVE_ORDER, PolicyEvaluationStage.completeOrder());
        assertEquals(
                AUTHORITATIVE_ORDER.subList(1, AUTHORITATIVE_ORDER.size()),
                PolicyEvaluationStage.policyOrder()
        );
    }

    @ParameterizedTest(name = "{0} at {1} is {2}")
    @MethodSource("terminalMappings")
    void preservesEveryInScopeTerminalMapping(
            PolicyEvaluationReason reason,
            PolicyEvaluationStage terminalStage,
            DecisionType expectedDecision
    ) {
        List<PolicyEvaluationStage> calls = new ArrayList<>();

        PolicyEvaluationDecision decision = PolicyEvaluationSequence.evaluate(
                () -> {
                    calls.add(PolicyEvaluationStage.PREFLIGHT);
                    if (terminalStage == PolicyEvaluationStage.PREFLIGHT) {
                        return terminal(reason, terminalStage, expectedDecision);
                    }
                    return StageOutcome.pass(PolicyEvaluationStage.PREFLIGHT);
                },
                stage -> {
                    calls.add(stage);
                    if (stage == terminalStage) {
                        return terminal(reason, stage, expectedDecision);
                    }
                    return StageOutcome.pass(stage);
                }
        );

        List<PolicyEvaluationStage> expectedPrefix = prefixThrough(terminalStage);
        assertEquals(expectedDecision, decision.decisionType());
        assertEquals(Optional.of(reason), decision.reason());
        assertEquals(Optional.of(terminalStage), decision.failedStage());
        assertEquals(expectedPrefix, calls);
        assertEquals(expectedPrefix, decision.evaluatedStages());
        assertEquals(expectedDecision == DecisionType.DENY, decision.successfulSecurityBlock());
        assertEquals(expectedDecision.name(), reason.classification().name());
    }

    @Test
    void mappingCasesCoverEveryDeclaredReason() {
        Set<PolicyEvaluationReason> mappedReasons = EnumSet.noneOf(PolicyEvaluationReason.class);
        terminalMappings().forEach(arguments ->
                mappedReasons.add((PolicyEvaluationReason) arguments.get()[0])
        );

        assertEquals(EnumSet.allOf(PolicyEvaluationReason.class), mappedReasons);
    }

    @Test
    void stopsAtEarliestCompetingFailureAndDoesNotExposeLaterCandidates() {
        List<PolicyEvaluationStage> calls = new ArrayList<>();

        PolicyEvaluationDecision decision = PolicyEvaluationSequence.evaluate(
                () -> {
                    calls.add(PolicyEvaluationStage.PREFLIGHT);
                    return StageOutcome.pass(PolicyEvaluationStage.PREFLIGHT);
                },
                stage -> {
                    calls.add(stage);
                    if (stage == PolicyEvaluationStage.OBJECT_SCOPE) {
                        return StageOutcome.deny(
                                stage,
                                PolicyEvaluationReason.CUSTOMER_SCOPE_VIOLATION
                        );
                    }
                    if (stage == PolicyEvaluationStage.FIELD_SCOPE) {
                        fail("later candidate must not be evaluated");
                    }
                    return StageOutcome.pass(stage);
                }
        );

        List<PolicyEvaluationStage> expectedPrefix = prefixThrough(
                PolicyEvaluationStage.OBJECT_SCOPE
        );
        assertEquals(expectedPrefix, calls);
        assertEquals(expectedPrefix, decision.evaluatedStages());
        assertEquals(
                Optional.of(PolicyEvaluationReason.CUSTOMER_SCOPE_VIOLATION),
                decision.reason()
        );
        assertFalse(calls.contains(PolicyEvaluationStage.FIELD_SCOPE));
        assertFalse(decision.evaluatedStages().contains(PolicyEvaluationStage.FIELD_SCOPE));
    }

    @Test
    void preflightErrorSuppressesAllPolicyStagesAndIsNotASecurityBlock() {
        AtomicInteger policyCalls = new AtomicInteger();

        PolicyEvaluationDecision decision = PolicyEvaluationSequence.evaluate(
                () -> StageOutcome.error(
                        PolicyEvaluationStage.PREFLIGHT,
                        PolicyEvaluationReason.RELEASE_FINGERPRINT_MISMATCH
                ),
                stage -> {
                    policyCalls.incrementAndGet();
                    return StageOutcome.pass(stage);
                }
        );

        assertEquals(DecisionType.ERROR, decision.decisionType());
        assertEquals(List.of(PolicyEvaluationStage.PREFLIGHT), decision.evaluatedStages());
        assertEquals(0, policyCalls.get());
        assertFalse(decision.successfulSecurityBlock());
    }

    @Test
    void rejectsPreflightPolicyDenialAsFailClosedEvaluationError() {
        PolicyEvaluationException exception = assertThrows(
                PolicyEvaluationException.class,
                () -> PolicyEvaluationSequence.evaluate(
                        () -> StageOutcome.deny(
                                PolicyEvaluationStage.PREFLIGHT,
                                PolicyEvaluationReason.TOOL_NOT_ALLOWED
                        ),
                        StageOutcome::pass
                )
        );

        assertEquals(PolicyEvaluationStage.PREFLIGHT, exception.stage());
        assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }

    @Test
    void rejectsNullPreflightOutcomeWithoutCallingPolicy() {
        AtomicInteger policyCalls = new AtomicInteger();

        PolicyEvaluationException exception = assertThrows(
                PolicyEvaluationException.class,
                () -> PolicyEvaluationSequence.evaluate(
                        () -> null,
                        stage -> {
                            policyCalls.incrementAndGet();
                            return StageOutcome.pass(stage);
                        }
                )
        );

        assertEquals(PolicyEvaluationStage.PREFLIGHT, exception.stage());
        assertEquals(0, policyCalls.get());
    }

    @Test
    void rejectsNullPolicyOutcomeAtTheExpectedStage() {
        List<PolicyEvaluationStage> calls = new ArrayList<>();

        PolicyEvaluationException exception = assertThrows(
                PolicyEvaluationException.class,
                () -> PolicyEvaluationSequence.evaluate(
                        () -> StageOutcome.pass(PolicyEvaluationStage.PREFLIGHT),
                        stage -> {
                            calls.add(stage);
                            return null;
                        }
                )
        );

        assertEquals(PolicyEvaluationStage.TOOL, exception.stage());
        assertEquals(List.of(PolicyEvaluationStage.TOOL), calls);
    }

    @Test
    void wrapsThrownEvaluatorFailureAtItsStage() {
        IllegalStateException cause = new IllegalStateException("upstream evaluator failed");

        PolicyEvaluationException exception = assertThrows(
                PolicyEvaluationException.class,
                () -> PolicyEvaluationSequence.evaluate(
                        () -> StageOutcome.pass(PolicyEvaluationStage.PREFLIGHT),
                        stage -> {
                            if (stage == PolicyEvaluationStage.OPERATION) {
                                throw cause;
                            }
                            return StageOutcome.pass(stage);
                        }
                )
        );

        assertEquals(PolicyEvaluationStage.OPERATION, exception.stage());
        assertEquals(cause, exception.getCause());
    }

    @Test
    void rejectsOutcomeForDifferentStageAndSuppressesFollowingStages() {
        List<PolicyEvaluationStage> calls = new ArrayList<>();

        PolicyEvaluationException exception = assertThrows(
                PolicyEvaluationException.class,
                () -> PolicyEvaluationSequence.evaluate(
                        () -> StageOutcome.pass(PolicyEvaluationStage.PREFLIGHT),
                        stage -> {
                            calls.add(stage);
                            return StageOutcome.pass(PolicyEvaluationStage.FIELD_SCOPE);
                        }
                )
        );

        assertEquals(PolicyEvaluationStage.TOOL, exception.stage());
        assertEquals(List.of(PolicyEvaluationStage.TOOL), calls);
    }

    @Test
    void wrapsMalformedPassOutcomeAsFailClosedEvaluationError() {
        PolicyEvaluationException exception = assertThrows(
                PolicyEvaluationException.class,
                () -> PolicyEvaluationSequence.evaluate(
                        () -> new StageOutcome(
                                PolicyEvaluationStage.PREFLIGHT,
                                OutcomeType.PASS,
                                Optional.of(PolicyEvaluationReason.INVALID_REQUEST_SCHEMA)
                        ),
                        StageOutcome::pass
                )
        );

        assertEquals(PolicyEvaluationStage.PREFLIGHT, exception.stage());
        assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }

    @Test
    void rejectsWrongTerminalClassificationAndBusinessContextDenial() {
        PolicyEvaluationException wrongClassification = assertThrows(
                PolicyEvaluationException.class,
                () -> PolicyEvaluationSequence.evaluate(
                        () -> StageOutcome.pass(PolicyEvaluationStage.PREFLIGHT),
                        stage -> {
                            if (stage == PolicyEvaluationStage.TOOL_TRUST) {
                                return new StageOutcome(
                                        stage,
                                        OutcomeType.DENY,
                                        Optional.of(PolicyEvaluationReason.TOOL_INTEGRITY_FAILURE)
                                );
                            }
                            return StageOutcome.pass(stage);
                        }
                )
        );
        assertEquals(PolicyEvaluationStage.TOOL_TRUST, wrongClassification.stage());
        assertTrue(wrongClassification.getCause() instanceof IllegalArgumentException);

        PolicyEvaluationException businessContextDenial = assertThrows(
                PolicyEvaluationException.class,
                () -> PolicyEvaluationSequence.evaluate(
                        () -> StageOutcome.pass(PolicyEvaluationStage.PREFLIGHT),
                        stage -> {
                            if (stage == PolicyEvaluationStage.BUSINESS_CONTEXT) {
                                return StageOutcome.deny(
                                        stage,
                                        PolicyEvaluationReason.CUSTOMER_SCOPE_VIOLATION
                                );
                            }
                            return StageOutcome.pass(stage);
                        }
                )
        );
        assertEquals(PolicyEvaluationStage.BUSINESS_CONTEXT, businessContextDenial.stage());
        assertTrue(businessContextDenial.getCause() instanceof IllegalArgumentException);
    }

    @Test
    void producesDeterministicEqualDecisionsForEqualOutcomes() {
        PolicyEvaluationDecision first = denyAt(PolicyEvaluationStage.FIELD_SCOPE);
        PolicyEvaluationDecision second = denyAt(PolicyEvaluationStage.FIELD_SCOPE);

        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
        assertEquals(prefixThrough(PolicyEvaluationStage.FIELD_SCOPE), first.evaluatedStages());
    }

    @Test
    void defensivelyCopiesAndExposesOnlyImmutableCollections() {
        List<PolicyEvaluationStage> mutableStages = new ArrayList<>(
                AUTHORITATIVE_ORDER
        );
        PolicyEvaluationDecision decision = PolicyEvaluationDecision.allow(mutableStages);
        mutableStages.clear();

        assertEquals(AUTHORITATIVE_ORDER, decision.evaluatedStages());
        assertThrows(
                UnsupportedOperationException.class,
                () -> decision.evaluatedStages().add(PolicyEvaluationStage.TOOL)
        );
        assertThrows(
                UnsupportedOperationException.class,
                () -> PolicyEvaluationStage.policyOrder().clear()
        );
        assertThrows(
                UnsupportedOperationException.class,
                () -> PolicyEvaluationReason.CONTEXT_INTEGRITY_FAILURE
                        .allowedStages()
                        .remove(PolicyEvaluationStage.PREFLIGHT)
        );
    }

    @Test
    void rejectsNonPrefixAndIncompleteAllowDecisions() {
        assertThrows(
                IllegalArgumentException.class,
                () -> PolicyEvaluationDecision.allow(List.of(PolicyEvaluationStage.PREFLIGHT))
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> PolicyEvaluationDecision.terminal(
                        PolicyEvaluationReason.FIELD_SCOPE_VIOLATION,
                        PolicyEvaluationStage.FIELD_SCOPE,
                        List.of(
                                PolicyEvaluationStage.PREFLIGHT,
                                PolicyEvaluationStage.FIELD_SCOPE
                        )
                )
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new PolicyEvaluationDecision(
                        DecisionType.ERROR,
                        Optional.of(PolicyEvaluationReason.CONTEXT_INTEGRITY_FAILURE),
                        Optional.of(PolicyEvaluationStage.PREFLIGHT),
                        List.of(
                                PolicyEvaluationStage.PREFLIGHT,
                                PolicyEvaluationStage.PREFLIGHT
                        )
                )
        );
    }

    private static PolicyEvaluationDecision denyAt(PolicyEvaluationStage terminalStage) {
        return PolicyEvaluationSequence.evaluate(
                () -> StageOutcome.pass(PolicyEvaluationStage.PREFLIGHT),
                stage -> {
                    if (stage == terminalStage) {
                        return StageOutcome.deny(
                                stage,
                                PolicyEvaluationReason.FIELD_SCOPE_VIOLATION
                        );
                    }
                    return StageOutcome.pass(stage);
                }
        );
    }

    private static StageOutcome terminal(
            PolicyEvaluationReason reason,
            PolicyEvaluationStage stage,
            DecisionType expectedDecision
    ) {
        return switch (expectedDecision) {
            case DENY -> StageOutcome.deny(stage, reason);
            case ERROR -> StageOutcome.error(stage, reason);
            case ALLOW -> throw new IllegalArgumentException("terminal mapping cannot be ALLOW");
        };
    }

    private static List<PolicyEvaluationStage> prefixThrough(PolicyEvaluationStage stage) {
        int terminalIndex = AUTHORITATIVE_ORDER.indexOf(stage);
        assertTrue(terminalIndex >= 0);
        return AUTHORITATIVE_ORDER.subList(0, terminalIndex + 1);
    }

    private static Stream<Arguments> terminalMappings() {
        return Stream.of(
                mapping(
                        PolicyEvaluationReason.INVALID_REQUEST_SCHEMA,
                        PolicyEvaluationStage.PREFLIGHT,
                        DecisionType.ERROR
                ),
                mapping(
                        PolicyEvaluationReason.CONTEXT_INTEGRITY_FAILURE,
                        PolicyEvaluationStage.PREFLIGHT,
                        DecisionType.ERROR
                ),
                mapping(
                        PolicyEvaluationReason.CONTRACT_NOT_APPROVED,
                        PolicyEvaluationStage.PREFLIGHT,
                        DecisionType.ERROR
                ),
                mapping(
                        PolicyEvaluationReason.RELEASE_FINGERPRINT_MISMATCH,
                        PolicyEvaluationStage.PREFLIGHT,
                        DecisionType.ERROR
                ),
                mapping(
                        PolicyEvaluationReason.POLICY_EVALUATION_TIMEOUT,
                        PolicyEvaluationStage.PREFLIGHT,
                        DecisionType.ERROR
                ),
                mapping(
                        PolicyEvaluationReason.TOOL_NOT_ALLOWED,
                        PolicyEvaluationStage.TOOL,
                        DecisionType.DENY
                ),
                mapping(
                        PolicyEvaluationReason.OPERATION_NOT_ALLOWED,
                        PolicyEvaluationStage.OPERATION,
                        DecisionType.DENY
                ),
                mapping(
                        PolicyEvaluationReason.CONTEXT_INTEGRITY_FAILURE,
                        PolicyEvaluationStage.BUSINESS_CONTEXT,
                        DecisionType.ERROR
                ),
                mapping(
                        PolicyEvaluationReason.CASE_SCOPE_VIOLATION,
                        PolicyEvaluationStage.OBJECT_SCOPE,
                        DecisionType.DENY
                ),
                mapping(
                        PolicyEvaluationReason.DOCUMENT_SCOPE_VIOLATION,
                        PolicyEvaluationStage.OBJECT_SCOPE,
                        DecisionType.DENY
                ),
                mapping(
                        PolicyEvaluationReason.CUSTOMER_SCOPE_VIOLATION,
                        PolicyEvaluationStage.OBJECT_SCOPE,
                        DecisionType.DENY
                ),
                mapping(
                        PolicyEvaluationReason.FIELD_SCOPE_VIOLATION,
                        PolicyEvaluationStage.FIELD_SCOPE,
                        DecisionType.DENY
                ),
                mapping(
                        PolicyEvaluationReason.RECORD_LIMIT_EXCEEDED,
                        PolicyEvaluationStage.CARDINALITY,
                        DecisionType.DENY
                ),
                mapping(
                        PolicyEvaluationReason.EXTERNAL_EGRESS_DENIED,
                        PolicyEvaluationStage.EGRESS,
                        DecisionType.DENY
                ),
                mapping(
                        PolicyEvaluationReason.INVALID_WORKFLOW_STAGE,
                        PolicyEvaluationStage.WORKFLOW,
                        DecisionType.DENY
                ),
                mapping(
                        PolicyEvaluationReason.HUMAN_ONLY_ACTION,
                        PolicyEvaluationStage.HUMAN_BOUNDARY,
                        DecisionType.DENY
                ),
                mapping(
                        PolicyEvaluationReason.UNTRUSTED_TOOL,
                        PolicyEvaluationStage.TOOL_TRUST,
                        DecisionType.DENY
                ),
                mapping(
                        PolicyEvaluationReason.TOOL_INTEGRITY_FAILURE,
                        PolicyEvaluationStage.TOOL_TRUST,
                        DecisionType.ERROR
                )
        );
    }

    private static Arguments mapping(
            PolicyEvaluationReason reason,
            PolicyEvaluationStage stage,
            DecisionType expectedDecision
    ) {
        return Arguments.of(reason, stage, expectedDecision);
    }
}
