package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEvaluationDecision.DecisionType.DENY;
import static com.finsecseal.policy.PolicyEvaluationReason.CASE_SCOPE_VIOLATION;
import static com.finsecseal.policy.PolicyEvaluationReason.CUSTOMER_SCOPE_VIOLATION;
import static com.finsecseal.policy.PolicyEvaluationReason.DOCUMENT_SCOPE_VIOLATION;
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
import com.finsecseal.policy.PolicyObjectScopeFacts.DocumentOwnership;
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

class PolicyObjectScopeEvaluatorTest {

    private static final String DOCUMENT_READER = "DOCUMENT_READER";
    private static final String CUSTOMER_DATA_READ = "CUSTOMER_DATA_READ";
    private static final String COMBINED_SCOPE_READ = "COMBINED_SCOPE_READ";
    private static final String LOAN_POLICY_SEARCH = "LOAN_POLICY_SEARCH";
    private static final String CASE_1001 = "CASE-1001";
    private static final String CASE_1002 = "CASE-1002";
    private static final String DOC_1001 = "DOC-1001";
    private static final String DOC_1002 = "DOC-1002";
    private static final String CUST_1001 = "CUST-1001";
    private static final String CUST_1002 = "CUST-1002";

    private PolicyObjectScopeEvaluator evaluator;

    @BeforeEach
    void setUp() {
        evaluator = new PolicyObjectScopeEvaluator();
    }

    @Test
    void passesWhenEveryActiveExactScopeMatchesTrustedFacts() {
        assertThat(evaluator.evaluate(OBJECT_SCOPE, combinedFacts()))
                .isEqualTo(StageOutcome.pass(OBJECT_SCOPE));
    }

    @Test
    void deniesWrongCurrentCaseBeforeDocumentAndCustomerChecks() {
        PolicyObjectScopeFacts facts = facts(
                COMBINED_SCOPE_READ,
                Optional.of(CASE_1002),
                Optional.of(List.of("DOC-NOT-ALLOWED")),
                Optional.of(List.of(CUST_1002)),
                Optional.of(CASE_1001),
                Optional.of(CUST_1001),
                Optional.of(List.of(DOC_1001)),
                Optional.of(List.of(new DocumentOwnership(DOC_1001, CASE_1001)))
        );

        assertThat(evaluator.evaluate(OBJECT_SCOPE, facts))
                .isEqualTo(StageOutcome.deny(
                        OBJECT_SCOPE,
                        CASE_SCOPE_VIOLATION
                ));
    }

    @Test
    void deniesDocumentOutsideAllowlistBeforeCustomerCheck() {
        PolicyObjectScopeFacts facts = facts(
                COMBINED_SCOPE_READ,
                Optional.of(CASE_1001),
                Optional.of(List.of(DOC_1002)),
                Optional.of(List.of(CUST_1002)),
                Optional.of(CASE_1001),
                Optional.of(CUST_1001),
                Optional.of(List.of(DOC_1001)),
                Optional.of(List.of(new DocumentOwnership(DOC_1001, CASE_1001)))
        );

        assertThat(evaluator.evaluate(OBJECT_SCOPE, facts))
                .isEqualTo(StageOutcome.deny(
                        OBJECT_SCOPE,
                        DOCUMENT_SCOPE_VIOLATION
                ));
    }

    @Test
    void rejectsAllowlistedDocumentStoredOutsideCurrentCaseAsContextFailure() {
        assertThatThrownBy(() -> facts(
                DOCUMENT_READER,
                Optional.of(CASE_1001),
                Optional.of(List.of(DOC_1001)),
                Optional.empty(),
                Optional.of(CASE_1001),
                Optional.empty(),
                Optional.of(List.of(DOC_1001)),
                Optional.of(List.of(new DocumentOwnership(DOC_1001, CASE_1002)))
        ))
                .isInstanceOf(PolicyScopeContextIntegrityException.class)
                .hasMessage(
                        "allowlisted document ownership must match currentCaseId"
                );
    }

    @Test
    void resolvedEmptyDocumentAllowlistIsValidAndDeniesRequestedDocument() {
        PolicyObjectScopeFacts facts = facts(
                DOCUMENT_READER,
                Optional.of(CASE_1001),
                Optional.of(List.of(DOC_1001)),
                Optional.empty(),
                Optional.of(CASE_1001),
                Optional.empty(),
                Optional.of(List.of()),
                Optional.of(List.of())
        );

        assertThat(evaluator.evaluate(OBJECT_SCOPE, facts))
                .isEqualTo(StageOutcome.deny(
                        OBJECT_SCOPE,
                        DOCUMENT_SCOPE_VIOLATION
                ));
    }

    @Test
    void tcGw002DeniesCustomerOutsideCurrentApplicant() {
        PolicyObjectScopeFacts facts = facts(
                CUSTOMER_DATA_READ,
                Optional.empty(),
                Optional.empty(),
                Optional.of(List.of(CUST_1002)),
                Optional.empty(),
                Optional.of(CUST_1001),
                Optional.empty(),
                Optional.empty()
        );

        assertThat(evaluator.evaluate(OBJECT_SCOPE, facts))
                .isEqualTo(StageOutcome.deny(
                        OBJECT_SCOPE,
                        CUSTOMER_SCOPE_VIOLATION
                ));
    }

    @Test
    void mixedCurrentAndForeignApplicantsAreDenied() {
        PolicyObjectScopeFacts facts = facts(
                CUSTOMER_DATA_READ,
                Optional.empty(),
                Optional.empty(),
                Optional.of(List.of(CUST_1001, CUST_1002)),
                Optional.empty(),
                Optional.of(CUST_1001),
                Optional.empty(),
                Optional.empty()
        );

        assertThat(evaluator.evaluate(OBJECT_SCOPE, facts))
                .isEqualTo(StageOutcome.deny(
                        OBJECT_SCOPE,
                        CUSTOMER_SCOPE_VIOLATION
                ));
    }

    @Test
    void exactCatalogToolWithoutScopePolicyPassesWithoutUnrelatedFacts() {
        PolicyObjectScopeFacts facts = facts(
                LOAN_POLICY_SEARCH,
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty()
        );

        assertThat(evaluator.evaluate(OBJECT_SCOPE, facts))
                .isEqualTo(StageOutcome.pass(OBJECT_SCOPE));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "UNKNOWN_TOOL",
            "customer_data_read",
            "CUSTOMER_DATA_READ "
    })
    void unknownToolFailsCompositionWithoutNameInference(String toolName) {
        PolicyObjectScopeFacts facts = facts(
                toolName,
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty()
        );

        assertThatThrownBy(() -> evaluator.evaluate(OBJECT_SCOPE, facts))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage(
                        "requested tool must be resolved by the Tool stage before Object Scope"
                );
    }

    @Test
    void rejectsMalformedCallerIdentitiesWithDedicatedException() {
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.of(CUST_1001),
                Optional.empty(),
                Optional.empty()
        ))
                .isInstanceOf(InvalidPolicyScopeRequestException.class)
                .hasMessage(
                        "requestedCustomerIds is required by the active scope"
                );

        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                Optional.empty(),
                Optional.empty(),
                Optional.of(List.of()),
                Optional.empty(),
                Optional.of(CUST_1001),
                Optional.empty(),
                Optional.empty()
        ))
                .isInstanceOf(InvalidPolicyScopeRequestException.class)
                .hasMessage(
                        "requestedCustomerIds must not be empty for the active scope"
                );

        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                Optional.empty(),
                Optional.empty(),
                Optional.of(List.of(CUST_1001, CUST_1001)),
                Optional.empty(),
                Optional.of(CUST_1001),
                Optional.empty(),
                Optional.empty()
        ))
                .isInstanceOf(InvalidPolicyScopeRequestException.class)
                .hasMessage("requestedCustomerIds must not contain duplicates");

        List<String> nullMember = new ArrayList<>();
        nullMember.add(null);
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                Optional.empty(),
                Optional.empty(),
                Optional.of(nullMember),
                Optional.empty(),
                Optional.of(CUST_1001),
                Optional.empty(),
                Optional.empty()
        ))
                .isInstanceOf(InvalidPolicyScopeRequestException.class)
                .hasMessage("requestedCustomerIds[0] must not be blank");
    }

    @Test
    void duplicateRequestRemainsInvalidEvenWhenOneIdentityIsOutOfScope() {
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                Optional.empty(),
                Optional.empty(),
                Optional.of(List.of(CUST_1002, CUST_1002)),
                Optional.empty(),
                Optional.of(CUST_1001),
                Optional.empty(),
                Optional.empty()
        ))
                .isInstanceOf(InvalidPolicyScopeRequestException.class)
                .hasMessage("requestedCustomerIds must not contain duplicates");
    }

    @Test
    void rejectsMissingOrAmbiguousTrustedFactsWithDistinctException() {
        assertThatThrownBy(() -> facts(
                CUSTOMER_DATA_READ,
                Optional.empty(),
                Optional.empty(),
                Optional.of(List.of(CUST_1001)),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty()
        ))
                .isInstanceOf(PolicyScopeContextIntegrityException.class)
                .hasMessage("currentApplicantId is required by the active scope");

        assertThatThrownBy(() -> facts(
                DOCUMENT_READER,
                Optional.of(CASE_1001),
                Optional.of(List.of(DOC_1001)),
                Optional.empty(),
                Optional.of(CASE_1001),
                Optional.empty(),
                Optional.of(List.of(DOC_1001, DOC_1001)),
                Optional.of(List.of(new DocumentOwnership(DOC_1001, CASE_1001)))
        ))
                .isInstanceOf(PolicyScopeContextIntegrityException.class)
                .hasMessage("allowedDocumentIds must not contain duplicates");

        DocumentOwnership ownership = new DocumentOwnership(
                DOC_1001,
                CASE_1001
        );
        assertThatThrownBy(() -> facts(
                DOCUMENT_READER,
                Optional.of(CASE_1001),
                Optional.of(List.of(DOC_1001)),
                Optional.empty(),
                Optional.of(CASE_1001),
                Optional.empty(),
                Optional.of(List.of(DOC_1001)),
                Optional.of(List.of(ownership, ownership))
        ))
                .isInstanceOf(PolicyScopeContextIntegrityException.class)
                .hasMessage(
                        "documentOwnerships must not contain duplicate or conflicting rows"
                );

        assertThatThrownBy(() -> facts(
                DOCUMENT_READER,
                Optional.of(CASE_1001),
                Optional.of(List.of(DOC_1001)),
                Optional.empty(),
                Optional.of(CASE_1001),
                Optional.empty(),
                Optional.of(List.of(DOC_1001)),
                Optional.of(List.of(
                        new DocumentOwnership(DOC_1001, CASE_1001),
                        new DocumentOwnership(DOC_1001, CASE_1002)
                ))
        ))
                .isInstanceOf(PolicyScopeContextIntegrityException.class)
                .hasMessage(
                        "documentOwnerships must not contain duplicate or conflicting rows"
                );
    }

    @Test
    void activeAllowedDocumentRequiresResolvedOwnership() {
        assertThatThrownBy(() -> facts(
                DOCUMENT_READER,
                Optional.of(CASE_1001),
                Optional.of(List.of(DOC_1001)),
                Optional.empty(),
                Optional.of(CASE_1001),
                Optional.empty(),
                Optional.of(List.of(DOC_1001)),
                Optional.of(List.of())
        ))
                .isInstanceOf(PolicyScopeContextIntegrityException.class)
                .hasMessage(
                        "documentOwnerships must resolve every allowed requested document"
                );
    }

    @Test
    void preservesRawFactOrderAndDefensivelyCopiesEveryCollection() {
        List<String> catalog = new ArrayList<>(catalog());
        List<ObjectScopePolicy> policies = new ArrayList<>(policies());
        List<String> requestedDocuments = new ArrayList<>(
                List.of(DOC_1002, DOC_1001)
        );
        List<String> requestedCustomers = new ArrayList<>(List.of(CUST_1001));
        List<String> allowedDocuments = new ArrayList<>(
                List.of(DOC_1002, DOC_1001)
        );
        List<DocumentOwnership> ownerships = new ArrayList<>(List.of(
                new DocumentOwnership(DOC_1002, CASE_1001),
                new DocumentOwnership(DOC_1001, CASE_1001)
        ));

        PolicyObjectScopeFacts facts = new PolicyObjectScopeFacts(
                COMBINED_SCOPE_READ,
                catalog,
                policies,
                Optional.of(CASE_1001),
                Optional.of(requestedDocuments),
                Optional.of(requestedCustomers),
                Optional.of(CASE_1001),
                Optional.of(CUST_1001),
                Optional.of(allowedDocuments),
                Optional.of(ownerships)
        );

        catalog.clear();
        policies.clear();
        requestedDocuments.clear();
        requestedCustomers.clear();
        allowedDocuments.clear();
        ownerships.clear();

        assertThat(facts.catalogTools()).containsExactlyElementsOf(catalog());
        assertThat(facts.scopePolicies()).containsExactlyElementsOf(policies());
        assertThat(facts.requestedDocumentIds().orElseThrow())
                .containsExactly(DOC_1002, DOC_1001);
        assertThat(facts.requestedCustomerIds().orElseThrow())
                .containsExactly(CUST_1001);
        assertThat(facts.allowedDocumentIds().orElseThrow())
                .containsExactly(DOC_1002, DOC_1001);
        assertThat(facts.documentOwnerships().orElseThrow())
                .containsExactly(
                        new DocumentOwnership(DOC_1002, CASE_1001),
                        new DocumentOwnership(DOC_1001, CASE_1001)
                );

        assertThatThrownBy(() -> facts.catalogTools().add("MUTATION"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> facts.scopePolicies().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() ->
                facts.documentOwnerships().orElseThrow().clear())
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void rejectsMalformedPolicyConfigurationBeforeLookup() {
        assertThatThrownBy(() -> new ObjectScopePolicy(
                DOCUMENT_READER,
                false,
                false,
                false
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("object scope policy must enable at least one scope");

        assertThatThrownBy(() -> new PolicyObjectScopeFacts(
                DOCUMENT_READER,
                List.of(DOCUMENT_READER),
                List.of(new ObjectScopePolicy(
                        CUSTOMER_DATA_READ,
                        false,
                        false,
                        true
                )),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("scopePolicies must reference catalog tools");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t"})
    void rejectsNullOrBlankRequestedTool(String requestedTool) {
        assertThatThrownBy(() -> facts(
                requestedTool,
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("requestedTool must not be blank");
    }

    @ParameterizedTest
    @EnumSource(
            value = PolicyEvaluationStage.class,
            names = "OBJECT_SCOPE",
            mode = EnumSource.Mode.EXCLUDE
    )
    void rejectsEveryUnsupportedStage(PolicyEvaluationStage stage) {
        assertThatThrownBy(() -> evaluator.evaluate(stage, combinedFacts()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(
                        "PolicyObjectScopeEvaluator supports only OBJECT_SCOPE"
                );
    }

    @Test
    void rejectsNullStageAndFacts() {
        assertThatThrownBy(() -> evaluator.evaluate(null, combinedFacts()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("stage must not be null");
        assertThatThrownBy(() -> evaluator.evaluate(OBJECT_SCOPE, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("facts must not be null");
    }

    @Test
    void sequenceStopsAtRealCustomerScopeFailureBeforeFieldScope() {
        AtomicInteger fieldAndLaterCalls = new AtomicInteger();
        PolicyObjectScopeFacts facts = facts(
                CUSTOMER_DATA_READ,
                Optional.empty(),
                Optional.empty(),
                Optional.of(List.of(CUST_1002)),
                Optional.empty(),
                Optional.of(CUST_1001),
                Optional.empty(),
                Optional.empty()
        );

        PolicyEvaluationDecision decision = PolicyEvaluationSequence.evaluate(
                () -> StageOutcome.pass(PREFLIGHT),
                stage -> switch (stage) {
                    case TOOL, OPERATION, BUSINESS_CONTEXT ->
                            StageOutcome.pass(stage);
                    case OBJECT_SCOPE -> evaluator.evaluate(stage, facts);
                    case FIELD_SCOPE, CARDINALITY, EGRESS, WORKFLOW,
                            HUMAN_BOUNDARY, TOOL_TRUST -> {
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
        assertThat(decision.successfulSecurityBlock()).isTrue();
        assertThat(fieldAndLaterCalls).hasValue(0);
    }

    @Test
    void sequencePreservesOperationalExceptionCauseForPreflightTranslation() {
        InvalidPolicyScopeRequestException invalidRequest =
                new InvalidPolicyScopeRequestException("invalid request identity");

        assertThatThrownBy(() -> PolicyEvaluationSequence.evaluate(
                () -> StageOutcome.pass(PREFLIGHT),
                stage -> {
                    if (stage == OBJECT_SCOPE) {
                        throw invalidRequest;
                    }
                    return StageOutcome.pass(stage);
                }
        ))
                .isInstanceOf(PolicyEvaluationException.class)
                .hasMessage(
                        "policy evaluator failed before returning a valid outcome"
                )
                .hasCause(invalidRequest);
    }

    @Test
    void evaluationIsDeterministic() {
        PolicyObjectScopeFacts facts = facts(
                CUSTOMER_DATA_READ,
                Optional.empty(),
                Optional.empty(),
                Optional.of(List.of(CUST_1002)),
                Optional.empty(),
                Optional.of(CUST_1001),
                Optional.empty(),
                Optional.empty()
        );

        StageOutcome first = evaluator.evaluate(OBJECT_SCOPE, facts);
        StageOutcome second = evaluator.evaluate(OBJECT_SCOPE, facts);

        assertThat(second).isEqualTo(first);
    }

    private PolicyObjectScopeFacts combinedFacts() {
        return facts(
                COMBINED_SCOPE_READ,
                Optional.of(CASE_1001),
                Optional.of(List.of(DOC_1001)),
                Optional.of(List.of(CUST_1001)),
                Optional.of(CASE_1001),
                Optional.of(CUST_1001),
                Optional.of(List.of(DOC_1001)),
                Optional.of(List.of(new DocumentOwnership(DOC_1001, CASE_1001)))
        );
    }

    private PolicyObjectScopeFacts facts(
            String requestedTool,
            Optional<String> requestedCaseId,
            Optional<List<String>> requestedDocumentIds,
            Optional<List<String>> requestedCustomerIds,
            Optional<String> currentCaseId,
            Optional<String> currentApplicantId,
            Optional<List<String>> allowedDocumentIds,
            Optional<List<DocumentOwnership>> ownerships
    ) {
        return new PolicyObjectScopeFacts(
                requestedTool,
                catalog(),
                policies(),
                requestedCaseId,
                requestedDocumentIds,
                requestedCustomerIds,
                currentCaseId,
                currentApplicantId,
                allowedDocumentIds,
                ownerships
        );
    }

    private List<String> catalog() {
        return List.of(
                LOAN_POLICY_SEARCH,
                COMBINED_SCOPE_READ,
                CUSTOMER_DATA_READ,
                DOCUMENT_READER
        );
    }

    private List<ObjectScopePolicy> policies() {
        return List.of(
                new ObjectScopePolicy(
                        CUSTOMER_DATA_READ,
                        false,
                        false,
                        true
                ),
                new ObjectScopePolicy(
                        DOCUMENT_READER,
                        true,
                        true,
                        false
                ),
                new ObjectScopePolicy(
                        COMBINED_SCOPE_READ,
                        true,
                        true,
                        true
                )
        );
    }
}
