package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEvaluationDecision.DecisionType.ALLOW;
import static com.finsecseal.policy.PolicyEvaluationDecision.DecisionType.DENY;
import static com.finsecseal.policy.PolicyEvaluationDecision.DecisionType.ERROR;
import static com.finsecseal.policy.PolicyEvaluationReason.HUMAN_ONLY_ACTION;
import static com.finsecseal.policy.PolicyEvaluationReason.TOOL_INTEGRITY_FAILURE;
import static com.finsecseal.policy.PolicyEvaluationReason.UNTRUSTED_TOOL;
import static com.finsecseal.policy.PolicyEvaluationStage.HUMAN_BOUNDARY;
import static com.finsecseal.policy.PolicyEvaluationStage.PREFLIGHT;
import static com.finsecseal.policy.PolicyEvaluationStage.TOOL_TRUST;
import static com.finsecseal.policy.PolicyToolTrustFacts.TrustLevel.MIXED;
import static com.finsecseal.policy.PolicyToolTrustFacts.TrustLevel.SANDBOXED;
import static com.finsecseal.policy.PolicyToolTrustFacts.TrustLevel.TRUSTED_INTERNAL;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;
import com.finsecseal.policy.PolicyToolTrustFacts.ReleaseToolBinding;
import com.finsecseal.policy.PolicyToolTrustFacts.ToolRegistryEntry;
import com.finsecseal.policy.PolicyToolTrustFacts.ToolTrustPolicy;
import com.finsecseal.policy.PolicyToolTrustFacts.TrustLevel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class PolicyToolTrustEvaluatorTest {

    private static final String TOOL = "CUSTOMER_DATA_READ";
    private static final String VERSION = "1.0.0";
    private static final String SCHEMA_DIGEST = digest('a');
    private static final String DESCRIPTION_DIGEST = digest('b');
    private static final String RELEASE_FINGERPRINT = digest('c');

    private final PolicyToolTrustEvaluator evaluator = new PolicyToolTrustEvaluator();

    @Test
    void exactTrustedRegistryAndReleaseBindingPasses() {
        StageOutcome outcome = evaluator.evaluate(TOOL_TRUST, trustedFacts());

        assertThat(outcome).isEqualTo(StageOutcome.pass(TOOL_TRUST));
    }

    @Test
    void disabledTrustRequirementPassesOnlyAfterIntegrityChecks() {
        PolicyToolTrustFacts facts = facts(
                TOOL,
                RELEASE_FINGERPRINT,
                RELEASE_FINGERPRINT,
                List.of(registry(TOOL, VERSION, MIXED)),
                List.of(binding(TOOL, VERSION, true)),
                new ToolTrustPolicy(false, List.of())
        );

        assertThat(evaluator.evaluate(TOOL_TRUST, facts))
                .isEqualTo(StageOutcome.pass(TOOL_TRUST));
    }

    @Test
    void disabledTrustRequirementCannotBypassIntegrityFailure() {
        PolicyToolTrustFacts facts = facts(
                TOOL,
                RELEASE_FINGERPRINT,
                digest('d'),
                List.of(registry(TOOL, VERSION, MIXED)),
                List.of(binding(TOOL, VERSION, true)),
                new ToolTrustPolicy(false, List.of())
        );

        PolicyEvaluationDecision decision = sequenceDecision(facts);

        assertThat(decision.decisionType()).isEqualTo(ERROR);
        assertThat(decision.reason()).contains(TOOL_INTEGRITY_FAILURE);
        assertThat(decision.failedStage()).contains(TOOL_TRUST);
        assertThat(decision.successfulSecurityBlock()).isFalse();
    }

    @Test
    void exactDisallowedRegistryTrustLevelIsDenied() {
        PolicyToolTrustFacts facts = facts(
                TOOL,
                RELEASE_FINGERPRINT,
                RELEASE_FINGERPRINT,
                List.of(registry(TOOL, VERSION, MIXED)),
                List.of(binding(TOOL, VERSION, true)),
                trustedOnlyPolicy()
        );

        StageOutcome outcome = evaluator.evaluate(TOOL_TRUST, facts);

        assertThat(outcome).isEqualTo(
                StageOutcome.deny(TOOL_TRUST, UNTRUSTED_TOOL)
        );
    }

    @ParameterizedTest
    @MethodSource("integrityFailures")
    void missingOrInconsistentRuntimeFactsAreOperationalIntegrityErrors(
            PolicyToolTrustFacts facts
    ) {
        StageOutcome outcome = evaluator.evaluate(TOOL_TRUST, facts);

        assertThat(outcome).isEqualTo(
                StageOutcome.error(TOOL_TRUST, TOOL_INTEGRITY_FAILURE)
        );
    }

    private static Stream<Arguments> integrityFailures() {
        return Stream.of(
                Arguments.of(facts(
                        TOOL,
                        RELEASE_FINGERPRINT,
                        digest('d'),
                        List.of(registry(TOOL, VERSION, TRUSTED_INTERNAL)),
                        List.of(binding(TOOL, VERSION, true)),
                        trustedOnlyPolicy()
                )),
                Arguments.of(facts(
                        TOOL,
                        RELEASE_FINGERPRINT,
                        RELEASE_FINGERPRINT,
                        List.of(),
                        List.of(binding(TOOL, VERSION, true)),
                        trustedOnlyPolicy()
                )),
                Arguments.of(facts(
                        TOOL,
                        RELEASE_FINGERPRINT,
                        RELEASE_FINGERPRINT,
                        List.of(registry(TOOL, VERSION, TRUSTED_INTERNAL)),
                        List.of(),
                        trustedOnlyPolicy()
                )),
                Arguments.of(facts(
                        TOOL,
                        RELEASE_FINGERPRINT,
                        RELEASE_FINGERPRINT,
                        List.of(registry(TOOL, VERSION, TRUSTED_INTERNAL)),
                        List.of(binding(TOOL, VERSION, false)),
                        trustedOnlyPolicy()
                )),
                Arguments.of(facts(
                        TOOL,
                        RELEASE_FINGERPRINT,
                        RELEASE_FINGERPRINT,
                        List.of(
                                registry(TOOL, VERSION, TRUSTED_INTERNAL),
                                registry(TOOL, "2.0.0", TRUSTED_INTERNAL)
                        ),
                        List.of(
                                binding(TOOL, VERSION, true),
                                binding(TOOL, "2.0.0", true)
                        ),
                        trustedOnlyPolicy()
                )),
                Arguments.of(facts(
                        TOOL,
                        RELEASE_FINGERPRINT,
                        RELEASE_FINGERPRINT,
                        List.of(registry(TOOL, VERSION, TRUSTED_INTERNAL)),
                        List.of(new ReleaseToolBinding(
                                TOOL,
                                VERSION,
                                true,
                                digest('d'),
                                DESCRIPTION_DIGEST
                        )),
                        trustedOnlyPolicy()
                )),
                Arguments.of(facts(
                        TOOL,
                        RELEASE_FINGERPRINT,
                        RELEASE_FINGERPRINT,
                        List.of(registry(TOOL, VERSION, TRUSTED_INTERNAL)),
                        List.of(new ReleaseToolBinding(
                                TOOL,
                                VERSION,
                                true,
                                SCHEMA_DIGEST,
                                digest('d')
                        )),
                        trustedOnlyPolicy()
                ))
        );
    }

    @Test
    void integrityFailureWinsOverDisallowedTrust() {
        PolicyToolTrustFacts facts = facts(
                TOOL,
                RELEASE_FINGERPRINT,
                digest('d'),
                List.of(registry(TOOL, VERSION, SANDBOXED)),
                List.of(binding(TOOL, VERSION, true)),
                trustedOnlyPolicy()
        );

        PolicyEvaluationDecision decision = sequenceDecision(facts);

        assertThat(decision.decisionType()).isEqualTo(ERROR);
        assertThat(decision.reason()).contains(TOOL_INTEGRITY_FAILURE);
        assertThat(decision.failedStage()).contains(TOOL_TRUST);
        assertThat(decision.evaluatedStages())
                .containsExactlyElementsOf(PolicyEvaluationStage.completeOrder());
        assertThat(decision.successfulSecurityBlock()).isFalse();
    }

    @Test
    void untrustedToolDenialCountsAsPolicySecurityBlock() {
        PolicyToolTrustFacts facts = facts(
                TOOL,
                RELEASE_FINGERPRINT,
                RELEASE_FINGERPRINT,
                List.of(registry(TOOL, VERSION, SANDBOXED)),
                List.of(binding(TOOL, VERSION, true)),
                trustedOnlyPolicy()
        );

        PolicyEvaluationDecision decision = sequenceDecision(facts);

        assertThat(decision.decisionType()).isEqualTo(DENY);
        assertThat(decision.reason()).contains(UNTRUSTED_TOOL);
        assertThat(decision.successfulSecurityBlock()).isTrue();
    }

    @Test
    void exactIdentityDoesNotTrimOrFoldCase() {
        for (String requested : List.of("customer_data_read", " " + TOOL, TOOL + " ")) {
            PolicyToolTrustFacts facts = facts(
                    requested,
                    RELEASE_FINGERPRINT,
                    RELEASE_FINGERPRINT,
                    List.of(registry(TOOL, VERSION, TRUSTED_INTERNAL)),
                    List.of(binding(TOOL, VERSION, true)),
                    trustedOnlyPolicy()
            );

            assertThat(evaluator.evaluate(TOOL_TRUST, facts))
                    .isEqualTo(StageOutcome.error(
                            TOOL_TRUST,
                            TOOL_INTEGRITY_FAILURE
                    ));
        }
    }

    @Test
    void exactIdentityDoesNotUnicodeNormalize() {
        String composed = "TOOL_CAF\u00c9";
        String decomposed = Normalizer.normalize(composed, Normalizer.Form.NFD);
        PolicyToolTrustFacts facts = facts(
                decomposed,
                RELEASE_FINGERPRINT,
                RELEASE_FINGERPRINT,
                List.of(registry(composed, VERSION, TRUSTED_INTERNAL)),
                List.of(binding(composed, VERSION, true)),
                trustedOnlyPolicy()
        );

        assertThat(decomposed).isNotEqualTo(composed);
        assertThat(evaluator.evaluate(TOOL_TRUST, facts))
                .isEqualTo(StageOutcome.error(
                        TOOL_TRUST,
                        TOOL_INTEGRITY_FAILURE
                ));
    }

    @Test
    void exactIdentityRejectsNonWhitespacePrefixAndSuperstringLookalikes() {
        for (String requested : List.of("CUSTOMER_DATA", TOOL + "_SHADOW")) {
            PolicyToolTrustFacts facts = facts(
                    requested,
                    RELEASE_FINGERPRINT,
                    RELEASE_FINGERPRINT,
                    List.of(registry(TOOL, VERSION, TRUSTED_INTERNAL)),
                    List.of(binding(TOOL, VERSION, true)),
                    trustedOnlyPolicy()
            );

            assertThat(evaluator.evaluate(TOOL_TRUST, facts))
                    .isEqualTo(StageOutcome.error(
                            TOOL_TRUST,
                            TOOL_INTEGRITY_FAILURE
                    ));
        }
    }

    @Test
    void factsDefensivelyCopyAllOrderedCollections() {
        List<ToolRegistryEntry> entries = new ArrayList<>(List.of(
                registry(TOOL, VERSION, TRUSTED_INTERNAL)
        ));
        List<ReleaseToolBinding> bindings = new ArrayList<>(List.of(
                binding(TOOL, VERSION, true)
        ));
        List<TrustLevel> levels = new ArrayList<>(List.of(TRUSTED_INTERNAL));

        PolicyToolTrustFacts facts = facts(
                TOOL,
                RELEASE_FINGERPRINT,
                RELEASE_FINGERPRINT,
                entries,
                bindings,
                new ToolTrustPolicy(true, levels)
        );
        entries.clear();
        bindings.clear();
        levels.clear();

        assertThat(facts.registryEntries()).hasSize(1);
        assertThat(facts.releaseBindings()).hasSize(1);
        assertThat(facts.trustPolicy().allowedTrustLevels())
                .containsExactly(TRUSTED_INTERNAL);
        assertThatThrownBy(() -> facts.registryEntries().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> facts.releaseBindings().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> facts.trustPolicy().allowedTrustLevels().clear())
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @ParameterizedTest
    @MethodSource("invalidFacts")
    void malformedTrustedConfigurationIsRejected(
            ThrowingConstruction construction,
            String message
    ) {
        assertThatThrownBy(construction::construct)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(message);
    }

    private static Stream<Arguments> invalidFacts() {
        ToolRegistryEntry entry = registry(TOOL, VERSION, TRUSTED_INTERNAL);
        ReleaseToolBinding binding = binding(TOOL, VERSION, true);
        return Stream.of(
                Arguments.of(
                        (ThrowingConstruction) () -> facts(
                                null,
                                RELEASE_FINGERPRINT,
                                RELEASE_FINGERPRINT,
                                List.of(entry),
                                List.of(binding),
                                trustedOnlyPolicy()
                        ),
                        "requestedTool"
                ),
                Arguments.of(
                        (ThrowingConstruction) () -> facts(
                                TOOL,
                                "sha256:ABC",
                                RELEASE_FINGERPRINT,
                                List.of(entry),
                                List.of(binding),
                                trustedOnlyPolicy()
                        ),
                        "expectedReleaseFingerprint"
                ),
                Arguments.of(
                        (ThrowingConstruction) () -> new ToolRegistryEntry(
                                TOOL,
                                VERSION,
                                TRUSTED_INTERNAL,
                                "bad",
                                DESCRIPTION_DIGEST
                        ),
                        "schemaDigest"
                ),
                Arguments.of(
                        (ThrowingConstruction) () -> new ReleaseToolBinding(
                                TOOL,
                                VERSION,
                                true,
                                SCHEMA_DIGEST,
                                "bad"
                        ),
                        "descriptionDigest"
                ),
                Arguments.of(
                        (ThrowingConstruction) () -> facts(
                                TOOL,
                                RELEASE_FINGERPRINT,
                                RELEASE_FINGERPRINT,
                                List.of(entry, entry),
                                List.of(binding),
                                trustedOnlyPolicy()
                        ),
                        "duplicate Tool identities"
                ),
                Arguments.of(
                        (ThrowingConstruction) () -> facts(
                                TOOL,
                                RELEASE_FINGERPRINT,
                                RELEASE_FINGERPRINT,
                                List.of(entry),
                                List.of(binding, binding),
                                trustedOnlyPolicy()
                        ),
                        "duplicate Tool identities"
                ),
                Arguments.of(
                        (ThrowingConstruction) () -> new ToolTrustPolicy(
                                true,
                                List.of(TRUSTED_INTERNAL, TRUSTED_INTERNAL)
                        ),
                        "duplicates"
                ),
                Arguments.of(
                        (ThrowingConstruction) () -> new ToolTrustPolicy(true, List.of()),
                        "at least one trust level"
                ),
                Arguments.of(
                        (ThrowingConstruction) () -> facts(
                                TOOL,
                                RELEASE_FINGERPRINT,
                                RELEASE_FINGERPRINT,
                                List.of(entry),
                                List.of(
                                        binding,
                                        binding("OTHER_TOOL", VERSION, true)
                                ),
                                trustedOnlyPolicy()
                        ),
                        "reference registry Tool identities"
                )
        );
    }

    @Test
    void nullEntriesAndNullPolicyAreRejected() {
        List<ToolRegistryEntry> nullRegistry = new ArrayList<>();
        nullRegistry.add(null);
        List<ReleaseToolBinding> nullBinding = new ArrayList<>();
        nullBinding.add(null);
        List<TrustLevel> nullLevel = new ArrayList<>();
        nullLevel.add(null);

        assertThatThrownBy(() -> facts(
                TOOL,
                RELEASE_FINGERPRINT,
                RELEASE_FINGERPRINT,
                nullRegistry,
                List.of(),
                trustedOnlyPolicy()
        )).hasMessageContaining("registryEntries");
        assertThatThrownBy(() -> facts(
                TOOL,
                RELEASE_FINGERPRINT,
                RELEASE_FINGERPRINT,
                List.of(),
                nullBinding,
                trustedOnlyPolicy()
        )).hasMessageContaining("releaseBindings");
        assertThatThrownBy(() -> new ToolTrustPolicy(true, nullLevel))
                .hasMessageContaining("allowedTrustLevels");
        assertThatThrownBy(() -> facts(
                TOOL,
                RELEASE_FINGERPRINT,
                RELEASE_FINGERPRINT,
                List.of(),
                List.of(),
                null
        )).hasMessageContaining("trustPolicy");
    }

    @Test
    void evaluatorRejectsNullAndEveryNonToolTrustStage() {
        assertThatThrownBy(() -> evaluator.evaluate(null, trustedFacts()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("stage must not be null");
        assertThatThrownBy(() -> evaluator.evaluate(TOOL_TRUST, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("facts must not be null");

        for (PolicyEvaluationStage stage : PolicyEvaluationStage.completeOrder()) {
            if (stage != TOOL_TRUST) {
                assertThatThrownBy(() -> evaluator.evaluate(stage, trustedFacts()))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessage(
                                "PolicyToolTrustEvaluator supports only TOOL_TRUST"
                        );
            }
        }
    }

    @Test
    void repeatedPassDenyAndErrorOutcomesAreDeterministic() {
        PolicyToolTrustFacts allowed = trustedFacts();
        PolicyToolTrustFacts denied = facts(
                TOOL,
                RELEASE_FINGERPRINT,
                RELEASE_FINGERPRINT,
                List.of(registry(TOOL, VERSION, MIXED)),
                List.of(binding(TOOL, VERSION, true)),
                trustedOnlyPolicy()
        );
        PolicyToolTrustFacts failed = facts(
                TOOL,
                RELEASE_FINGERPRINT,
                digest('d'),
                List.of(registry(TOOL, VERSION, TRUSTED_INTERNAL)),
                List.of(binding(TOOL, VERSION, true)),
                trustedOnlyPolicy()
        );

        for (int attempt = 0; attempt < 20; attempt++) {
            assertThat(evaluator.evaluate(TOOL_TRUST, allowed))
                    .isEqualTo(StageOutcome.pass(TOOL_TRUST));
            assertThat(evaluator.evaluate(TOOL_TRUST, denied))
                    .isEqualTo(StageOutcome.deny(TOOL_TRUST, UNTRUSTED_TOOL));
            assertThat(evaluator.evaluate(TOOL_TRUST, failed))
                    .isEqualTo(StageOutcome.error(
                            TOOL_TRUST,
                            TOOL_INTEGRITY_FAILURE
                    ));
        }
    }

    @Test
    void humanBoundaryDenialShortCircuitsBeforeToolTrust() {
        AtomicInteger trustEvaluations = new AtomicInteger();

        PolicyEvaluationDecision decision = PolicyEvaluationSequence.evaluate(
                () -> StageOutcome.pass(PREFLIGHT),
                stage -> {
                    if (stage == HUMAN_BOUNDARY) {
                        return StageOutcome.deny(HUMAN_BOUNDARY, HUMAN_ONLY_ACTION);
                    }
                    if (stage == TOOL_TRUST) {
                        trustEvaluations.incrementAndGet();
                        return evaluator.evaluate(stage, trustedFacts());
                    }
                    return StageOutcome.pass(stage);
                }
        );

        assertThat(decision.reason()).contains(HUMAN_ONLY_ACTION);
        assertThat(decision.evaluatedStages())
                .containsExactlyElementsOf(
                        PolicyEvaluationStage.completeOrder().subList(
                                0,
                                PolicyEvaluationStage.completeOrder().indexOf(
                                        HUMAN_BOUNDARY
                                ) + 1
                        )
                );
        assertThat(trustEvaluations).hasValue(0);
    }

    @Test
    void exactTrustedFactsCompleteTheFixedSequence() {
        PolicyEvaluationDecision decision = sequenceDecision(trustedFacts());

        assertThat(decision.decisionType()).isEqualTo(ALLOW);
        assertThat(decision.reason()).isEmpty();
        assertThat(decision.evaluatedStages())
                .containsExactlyElementsOf(PolicyEvaluationStage.completeOrder());
    }

    private PolicyEvaluationDecision sequenceDecision(PolicyToolTrustFacts facts) {
        return PolicyEvaluationSequence.evaluate(
                () -> StageOutcome.pass(PREFLIGHT),
                stage -> stage == TOOL_TRUST
                        ? evaluator.evaluate(stage, facts)
                        : StageOutcome.pass(stage)
        );
    }

    private static PolicyToolTrustFacts trustedFacts() {
        return facts(
                TOOL,
                RELEASE_FINGERPRINT,
                RELEASE_FINGERPRINT,
                List.of(registry(TOOL, VERSION, TRUSTED_INTERNAL)),
                List.of(binding(TOOL, VERSION, true)),
                trustedOnlyPolicy()
        );
    }

    private static PolicyToolTrustFacts facts(
            String requestedTool,
            String expectedFingerprint,
            String observedFingerprint,
            List<ToolRegistryEntry> registryEntries,
            List<ReleaseToolBinding> releaseBindings,
            ToolTrustPolicy trustPolicy
    ) {
        return new PolicyToolTrustFacts(
                requestedTool,
                expectedFingerprint,
                observedFingerprint,
                registryEntries,
                releaseBindings,
                trustPolicy
        );
    }

    private static ToolRegistryEntry registry(
            String toolName,
            String version,
            TrustLevel trustLevel
    ) {
        return new ToolRegistryEntry(
                toolName,
                version,
                trustLevel,
                SCHEMA_DIGEST,
                DESCRIPTION_DIGEST
        );
    }

    private static ReleaseToolBinding binding(
            String toolName,
            String version,
            boolean enabled
    ) {
        return new ReleaseToolBinding(
                toolName,
                version,
                enabled,
                SCHEMA_DIGEST,
                DESCRIPTION_DIGEST
        );
    }

    private static ToolTrustPolicy trustedOnlyPolicy() {
        return new ToolTrustPolicy(true, List.of(TRUSTED_INTERNAL));
    }

    private static String digest(char value) {
        return "sha256:" + String.valueOf(value).repeat(64);
    }

    @FunctionalInterface
    private interface ThrowingConstruction {
        void construct();
    }
}
