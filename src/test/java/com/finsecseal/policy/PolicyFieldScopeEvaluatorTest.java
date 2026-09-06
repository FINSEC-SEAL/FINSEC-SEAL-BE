package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEvaluationDecision.DecisionType.DENY;
import static com.finsecseal.policy.PolicyEvaluationReason.CUSTOMER_SCOPE_VIOLATION;
import static com.finsecseal.policy.PolicyEvaluationReason.FIELD_SCOPE_VIOLATION;
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
import com.finsecseal.policy.PolicyFieldScopeFacts.FieldPolicy;
import com.finsecseal.policy.PolicyFieldScopeFacts.ToolOutputSchema;
import com.finsecseal.policy.PolicyObjectScopeFacts.ObjectScopePolicy;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class PolicyFieldScopeEvaluatorTest {

    private static final String CUSTOMER_DATA_READ = "CUSTOMER_DATA_READ";
    private static final String CUSTOMER_DATA_READER = "CUSTOMER_DATA_READER";
    private static final String LOAN_POLICY_SEARCH = "LOAN_POLICY_SEARCH";
    private static final String INCOME_BAND = "incomeBand";
    private static final String EMPLOYMENT_STATUS = "employmentStatus";
    private static final String ACCOUNT_NUMBER = "accountNumber";

    private PolicyFieldScopeEvaluator evaluator;

    @BeforeEach
    void setUp() {
        evaluator = new PolicyFieldScopeEvaluator();
    }

    @Test
    void passesAllowedSubset() {
        assertThat(evaluator.evaluate(
                FIELD_SCOPE,
                facts(CUSTOMER_DATA_READ, Optional.of(List.of(INCOME_BAND)))
        )).isEqualTo(StageOutcome.pass(FIELD_SCOPE));
    }

    @Test
    void passesCompleteAllowedSetInCallerOrder() {
        assertThat(evaluator.evaluate(
                FIELD_SCOPE,
                facts(
                        CUSTOMER_DATA_READ,
                        Optional.of(List.of(EMPLOYMENT_STATUS, INCOME_BAND))
                )
        )).isEqualTo(StageOutcome.pass(FIELD_SCOPE));
    }

    @Test
    void tcGw004DeniesForbiddenSensitiveField() {
        assertThat(evaluator.evaluate(
                FIELD_SCOPE,
                facts(CUSTOMER_DATA_READ, Optional.of(List.of(ACCOUNT_NUMBER)))
        )).isEqualTo(StageOutcome.deny(
                FIELD_SCOPE,
                FIELD_SCOPE_VIOLATION
        ));
    }

    @Test
    void deniesMixedAllowedAndForbiddenFields() {
        assertThat(evaluator.evaluate(
                FIELD_SCOPE,
                facts(
                        CUSTOMER_DATA_READ,
                        Optional.of(List.of(INCOME_BAND, ACCOUNT_NUMBER))
                )
        )).isEqualTo(StageOutcome.deny(
                FIELD_SCOPE,
                FIELD_SCOPE_VIOLATION
        ));
    }

    @ParameterizedTest
    @ValueSource(strings = {"IncomeBand", "incomeBand ", " employmentStatus"})
    void exactFieldMatchingDoesNotNormalizeCaseOrWhitespace(String field) {
        assertThat(evaluator.evaluate(
                FIELD_SCOPE,
                facts(CUSTOMER_DATA_READ, Optional.of(List.of(field)))
        )).isEqualTo(StageOutcome.deny(
                FIELD_SCOPE,
                FIELD_SCOPE_VIOLATION
        ));
    }

    @Test
    void catalogToolWithoutFieldPolicyPassesWithoutRequestedFields() {
        assertThat(evaluator.evaluate(
                FIELD_SCOPE,
                facts(LOAN_POLICY_SEARCH, Optional.empty())
        )).isEqualTo(StageOutcome.pass(FIELD_SCOPE));
    }

    @Test
    void similarlyNamedCatalogToolDoesNotInheritPolicy() {
        assertThat(evaluator.evaluate(
                FIELD_SCOPE,
                facts(CUSTOMER_DATA_READER, Optional.empty())
        )).isEqualTo(StageOutcome.pass(FIELD_SCOPE));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "UNKNOWN_TOOL",
            "customer_data_read",
            "CUSTOMER_DATA_READ "
    })
    void unresolvedToolFailsCompositionWithoutPolicyDecision(String toolName) {
        PolicyFieldScopeFacts facts = facts(
                toolName,
                Optional.of(List.of(ACCOUNT_NUMBER))
        );

        assertThatThrownBy(() -> evaluator.evaluate(FIELD_SCOPE, facts))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage(
                        "requested tool must be resolved by the Tool stage before Field Scope"
                );
    }

    @Test
    void malformedCallerFieldListsUseDedicatedOperationalException() {
        assertThatThrownBy(() -> new PolicyFieldScopeFacts(
                CUSTOMER_DATA_READ,
                null,
                schemas(),
                policies()
        ))
                .isInstanceOf(InvalidPolicyScopeRequestException.class)
                .hasMessage("requestedFields must not be null");

        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                Optional.empty()
        ))
                .isInstanceOf(InvalidPolicyScopeRequestException.class)
                .hasMessage(
                        "requestedFields is required by the active field policy"
                );

        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                Optional.of(List.of())
        ))
                .isInstanceOf(InvalidPolicyScopeRequestException.class)
                .hasMessage(
                        "requestedFields must not be empty for the active field policy"
                );

        List<String> nullMember = new ArrayList<>();
        nullMember.add(null);
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                Optional.of(nullMember)
        ))
                .isInstanceOf(InvalidPolicyScopeRequestException.class)
                .hasMessage("requestedFields[0] must not be blank");

        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                Optional.of(List.of(" "))
        ))
                .isInstanceOf(InvalidPolicyScopeRequestException.class)
                .hasMessage("requestedFields[0] must not be blank");

        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                Optional.of(List.of(INCOME_BAND, INCOME_BAND))
        ))
                .isInstanceOf(InvalidPolicyScopeRequestException.class)
                .hasMessage("requestedFields must not contain duplicates");
    }

    @Test
    void rejectsMalformedCatalogAndPolicyCollections() {
        assertThatThrownBy(() -> new PolicyFieldScopeFacts(
                CUSTOMER_DATA_READ,
                Optional.of(List.of(INCOME_BAND)),
                null,
                policies()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogSchemas must not be null");

        List<ToolOutputSchema> nullSchema = new ArrayList<>();
        nullSchema.add(null);
        assertThatThrownBy(() -> new PolicyFieldScopeFacts(
                CUSTOMER_DATA_READ,
                Optional.of(List.of(INCOME_BAND)),
                nullSchema,
                policies()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalogSchemas must not contain null entries");

        assertThatThrownBy(() -> new PolicyFieldScopeFacts(
                CUSTOMER_DATA_READ,
                Optional.of(List.of(INCOME_BAND)),
                List.of(schemas().getFirst(), schemas().getFirst()),
                policies()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(
                        "catalogSchemas must not contain duplicate tool names"
                );

        assertThatThrownBy(() -> new PolicyFieldScopeFacts(
                CUSTOMER_DATA_READ,
                Optional.of(List.of(INCOME_BAND)),
                schemas(),
                null
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("fieldPolicies must not be null");

        List<FieldPolicy> nullPolicy = new ArrayList<>();
        nullPolicy.add(null);
        assertThatThrownBy(() -> new PolicyFieldScopeFacts(
                CUSTOMER_DATA_READ,
                Optional.of(List.of(INCOME_BAND)),
                schemas(),
                nullPolicy
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("fieldPolicies must not contain null entries");

        assertThatThrownBy(() -> new PolicyFieldScopeFacts(
                CUSTOMER_DATA_READ,
                Optional.of(List.of(INCOME_BAND)),
                schemas(),
                List.of(policies().getFirst(), policies().getFirst())
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(
                        "fieldPolicies must not contain duplicate tool names"
                );
    }

    @Test
    void rejectsDefectiveNestedTrustedFacts() {
        assertThatThrownBy(() -> new ToolOutputSchema(CUSTOMER_DATA_READ, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalog outputFields must not be null");
        assertThatThrownBy(() -> new ToolOutputSchema(
                CUSTOMER_DATA_READ,
                List.of(INCOME_BAND, INCOME_BAND)
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("catalog outputFields must not contain duplicates");
        assertThatThrownBy(() -> new FieldPolicy(
                CUSTOMER_DATA_READ,
                List.of(INCOME_BAND, INCOME_BAND),
                true
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("policy allowedFields must not contain duplicates");
        assertThatThrownBy(() -> new FieldPolicy(
                CUSTOMER_DATA_READ,
                List.of(INCOME_BAND),
                false
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("P0 field policy requires denyUnknown=true");
    }

    @Test
    void rejectsPolicyToolAndFieldCrossReferenceMismatchesExactly() {
        assertThatThrownBy(() -> new PolicyFieldScopeFacts(
                CUSTOMER_DATA_READ,
                Optional.of(List.of(INCOME_BAND)),
                schemas(),
                List.of(new FieldPolicy(
                        "CUSTOMER_DATA_UNKNOWN",
                        List.of(INCOME_BAND),
                        true
                ))
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("fieldPolicies must reference catalog tools");

        assertThatThrownBy(() -> new PolicyFieldScopeFacts(
                CUSTOMER_DATA_READ,
                Optional.of(List.of(INCOME_BAND)),
                schemas(),
                List.of(new FieldPolicy(
                        CUSTOMER_DATA_READ,
                        List.of("IncomeBand"),
                        true
                ))
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(
                        "fieldPolicies may allow only declared Tool output fields"
                );
    }

    @Test
    void nestedFactsAreDefensivelyCopiedAndUnmodifiable() {
        List<String> outputFields = new ArrayList<>(List.of(
                EMPLOYMENT_STATUS,
                INCOME_BAND,
                ACCOUNT_NUMBER
        ));
        List<String> allowedFields = new ArrayList<>(List.of(
                EMPLOYMENT_STATUS,
                INCOME_BAND
        ));
        List<String> requestedFields = new ArrayList<>(List.of(
                EMPLOYMENT_STATUS,
                INCOME_BAND
        ));
        ToolOutputSchema schema = new ToolOutputSchema(
                CUSTOMER_DATA_READ,
                outputFields
        );
        FieldPolicy policy = new FieldPolicy(
                CUSTOMER_DATA_READ,
                allowedFields,
                true
        );
        List<ToolOutputSchema> schemas = new ArrayList<>(List.of(schema));
        List<FieldPolicy> policies = new ArrayList<>(List.of(policy));

        PolicyFieldScopeFacts facts = new PolicyFieldScopeFacts(
                CUSTOMER_DATA_READ,
                Optional.of(requestedFields),
                schemas,
                policies
        );

        outputFields.clear();
        allowedFields.clear();
        requestedFields.clear();
        schemas.clear();
        policies.clear();

        assertThat(facts.catalogSchemas()).containsExactly(schema);
        assertThat(facts.catalogSchemas().getFirst().outputFields())
                .containsExactly(EMPLOYMENT_STATUS, INCOME_BAND, ACCOUNT_NUMBER);
        assertThat(facts.fieldPolicies()).containsExactly(policy);
        assertThat(facts.fieldPolicies().getFirst().allowedFields())
                .containsExactly(EMPLOYMENT_STATUS, INCOME_BAND);
        assertThat(facts.requestedFields().orElseThrow())
                .containsExactly(EMPLOYMENT_STATUS, INCOME_BAND);

        assertThatThrownBy(() -> facts.catalogSchemas().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> facts.catalogSchemas().getFirst()
                .outputFields().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> facts.fieldPolicies().getFirst()
                .allowedFields().add("mutation"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> facts.requestedFields().orElseThrow().clear())
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t"})
    void rejectsNullOrBlankRequestedTool(String toolName) {
        assertThatThrownBy(() -> facts(
                toolName,
                Optional.of(List.of(INCOME_BAND))
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("requestedTool must not be blank");
    }

    @ParameterizedTest
    @EnumSource(
            value = PolicyEvaluationStage.class,
            names = "FIELD_SCOPE",
            mode = EnumSource.Mode.EXCLUDE
    )
    void rejectsEveryUnsupportedStage(PolicyEvaluationStage stage) {
        assertThatThrownBy(() -> evaluator.evaluate(
                stage,
                facts(CUSTOMER_DATA_READ, Optional.of(List.of(INCOME_BAND)))
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(
                        "PolicyFieldScopeEvaluator supports only FIELD_SCOPE"
                );
    }

    @Test
    void rejectsNullStageAndFacts() {
        assertThatThrownBy(() -> evaluator.evaluate(
                null,
                facts(CUSTOMER_DATA_READ, Optional.of(List.of(INCOME_BAND)))
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("stage must not be null");
        assertThatThrownBy(() -> evaluator.evaluate(FIELD_SCOPE, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("facts must not be null");
    }

    @Test
    void realObjectScopeDenialPreventsFieldAndEveryLaterStage() {
        PolicyObjectScopeEvaluator objectEvaluator =
                new PolicyObjectScopeEvaluator();
        PolicyObjectScopeFacts objectFacts = new PolicyObjectScopeFacts(
                CUSTOMER_DATA_READ,
                List.of(CUSTOMER_DATA_READ),
                List.of(new ObjectScopePolicy(
                        CUSTOMER_DATA_READ,
                        false,
                        false,
                        true
                )),
                Optional.empty(),
                Optional.empty(),
                Optional.of(List.of("CUST-1002")),
                Optional.empty(),
                Optional.of("CUST-1001"),
                Optional.empty(),
                Optional.empty()
        );
        PolicyFieldScopeFacts fieldFacts = facts(
                CUSTOMER_DATA_READ,
                Optional.of(List.of(ACCOUNT_NUMBER))
        );
        AtomicInteger fieldAndLaterCalls = new AtomicInteger();

        PolicyEvaluationDecision decision = PolicyEvaluationSequence.evaluate(
                () -> StageOutcome.pass(PREFLIGHT),
                stage -> switch (stage) {
                    case TOOL, OPERATION, BUSINESS_CONTEXT ->
                            StageOutcome.pass(stage);
                    case OBJECT_SCOPE -> objectEvaluator.evaluate(
                            stage,
                            objectFacts
                    );
                    case FIELD_SCOPE -> {
                        fieldAndLaterCalls.incrementAndGet();
                        yield evaluator.evaluate(stage, fieldFacts);
                    }
                    case CARDINALITY, EGRESS, WORKFLOW, HUMAN_BOUNDARY,
                            TOOL_TRUST -> {
                        fieldAndLaterCalls.incrementAndGet();
                        yield StageOutcome.pass(stage);
                    }
                    case PREFLIGHT -> throw new AssertionError(
                            "preflight is evaluated separately"
                    );
                }
        );

        assertThat(decision.decisionType()).isEqualTo(DENY);
        assertThat(decision.reason()).contains(CUSTOMER_SCOPE_VIOLATION);
        assertThat(decision.failedStage()).contains(OBJECT_SCOPE);
        assertThat(decision.evaluatedStages()).containsExactly(
                PREFLIGHT,
                TOOL,
                OPERATION,
                BUSINESS_CONTEXT,
                OBJECT_SCOPE
        );
        assertThat(fieldAndLaterCalls).hasValue(0);
    }

    @Test
    void realFieldScopeDenialPreventsCardinalityAndEveryLaterStage() {
        PolicyObjectScopeEvaluator objectEvaluator =
                new PolicyObjectScopeEvaluator();
        PolicyObjectScopeFacts objectFacts = new PolicyObjectScopeFacts(
                CUSTOMER_DATA_READ,
                List.of(CUSTOMER_DATA_READ),
                List.of(new ObjectScopePolicy(
                        CUSTOMER_DATA_READ,
                        false,
                        false,
                        true
                )),
                Optional.empty(),
                Optional.empty(),
                Optional.of(List.of("CUST-1001")),
                Optional.empty(),
                Optional.of("CUST-1001"),
                Optional.empty(),
                Optional.empty()
        );
        PolicyFieldScopeFacts fieldFacts = facts(
                CUSTOMER_DATA_READ,
                Optional.of(List.of(ACCOUNT_NUMBER))
        );
        AtomicInteger laterCalls = new AtomicInteger();

        PolicyEvaluationDecision decision = PolicyEvaluationSequence.evaluate(
                () -> StageOutcome.pass(PREFLIGHT),
                stage -> switch (stage) {
                    case TOOL, OPERATION, BUSINESS_CONTEXT ->
                            StageOutcome.pass(stage);
                    case OBJECT_SCOPE -> objectEvaluator.evaluate(
                            stage,
                            objectFacts
                    );
                    case FIELD_SCOPE -> evaluator.evaluate(stage, fieldFacts);
                    case CARDINALITY, EGRESS, WORKFLOW, HUMAN_BOUNDARY,
                            TOOL_TRUST -> {
                        laterCalls.incrementAndGet();
                        yield StageOutcome.pass(stage);
                    }
                    case PREFLIGHT -> throw new AssertionError(
                            "preflight is evaluated separately"
                    );
                }
        );

        assertThat(decision.decisionType()).isEqualTo(DENY);
        assertThat(decision.reason()).contains(FIELD_SCOPE_VIOLATION);
        assertThat(decision.failedStage()).contains(FIELD_SCOPE);
        assertThat(decision.evaluatedStages()).containsExactly(
                PREFLIGHT,
                TOOL,
                OPERATION,
                BUSINESS_CONTEXT,
                OBJECT_SCOPE,
                FIELD_SCOPE
        );
        assertThat(laterCalls).hasValue(0);
    }

    @Test
    void evaluationIsDeterministic() {
        PolicyFieldScopeFacts facts = facts(
                CUSTOMER_DATA_READ,
                Optional.of(List.of(INCOME_BAND, ACCOUNT_NUMBER))
        );

        StageOutcome first = evaluator.evaluate(FIELD_SCOPE, facts);
        StageOutcome second = evaluator.evaluate(FIELD_SCOPE, facts);

        assertThat(second).isEqualTo(first);
    }

    private PolicyFieldScopeFacts facts(
            String requestedTool,
            Optional<List<String>> requestedFields
    ) {
        return new PolicyFieldScopeFacts(
                requestedTool,
                requestedFields,
                schemas(),
                policies()
        );
    }

    private List<ToolOutputSchema> schemas() {
        return List.of(
                new ToolOutputSchema(
                        LOAN_POLICY_SEARCH,
                        List.of("description", "ruleCode")
                ),
                new ToolOutputSchema(
                        CUSTOMER_DATA_READER,
                        List.of(ACCOUNT_NUMBER)
                ),
                new ToolOutputSchema(
                        CUSTOMER_DATA_READ,
                        List.of(EMPLOYMENT_STATUS, ACCOUNT_NUMBER, INCOME_BAND)
                )
        );
    }

    private List<FieldPolicy> policies() {
        return List.of(new FieldPolicy(
                CUSTOMER_DATA_READ,
                List.of(EMPLOYMENT_STATUS, INCOME_BAND),
                true
        ));
    }
}
