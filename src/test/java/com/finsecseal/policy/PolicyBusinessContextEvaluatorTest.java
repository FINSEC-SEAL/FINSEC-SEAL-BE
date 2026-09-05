package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEvaluationDecision.DecisionType.ERROR;
import static com.finsecseal.policy.PolicyEvaluationReason.CONTEXT_INTEGRITY_FAILURE;
import static com.finsecseal.policy.PolicyEvaluationStage.BUSINESS_CONTEXT;
import static com.finsecseal.policy.PolicyEvaluationStage.OPERATION;
import static com.finsecseal.policy.PolicyEvaluationStage.PREFLIGHT;
import static com.finsecseal.policy.PolicyEvaluationStage.TOOL;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

class PolicyBusinessContextEvaluatorTest {

    private static final String PURPOSE = "LOAN_DOCUMENT_COMPLETENESS_REVIEW";

    private PolicyBusinessContextEvaluator evaluator;

    @BeforeEach
    void setUp() {
        evaluator = new PolicyBusinessContextEvaluator();
    }

    @Test
    void passesCompleteServerResolvedContext() {
        assertThat(evaluator.evaluate(BUSINESS_CONTEXT, new FactsBuilder().build()))
                .isEqualTo(StageOutcome.pass(BUSINESS_CONTEXT));
    }

    @Test
    void returnsIntegrityErrorWhenContextWasNotResolvedFromServerState() {
        PolicyBusinessContextFacts facts = new FactsBuilder()
                .serverResolved(false)
                .build();

        assertIntegrityError(facts);
    }

    @ParameterizedTest
    @EnumSource(RequiredFact.class)
    void returnsIntegrityErrorForEachMissingRequiredFact(RequiredFact fact) {
        PolicyBusinessContextFacts facts = new FactsBuilder()
                .missing(fact)
                .build();

        assertIntegrityError(facts);
    }

    @ParameterizedTest
    @MethodSource("stringFacts")
    void returnsIntegrityErrorForEachBlankStringFact(RequiredFact fact) {
        PolicyBusinessContextFacts facts = new FactsBuilder()
                .blank(fact)
                .build();

        assertIntegrityError(facts);
    }

    @ParameterizedTest
    @MethodSource("purposeMismatches")
    void comparesEveryPurposeFactExactly(PurposeFact fact, String mismatchedValue) {
        PolicyBusinessContextFacts facts = new FactsBuilder()
                .purpose(fact, mismatchedValue)
                .build();

        assertIntegrityError(facts);
    }

    @Test
    void acceptsPresentEmptyAndCaseDistinctDocumentIdentifiers() {
        PolicyBusinessContextFacts emptyDocuments = new FactsBuilder()
                .documents(List.of())
                .build();
        PolicyBusinessContextFacts caseDistinctDocuments = new FactsBuilder()
                .documents(List.of("DOC-1001", "doc-1001"))
                .build();

        assertThat(evaluator.evaluate(BUSINESS_CONTEXT, emptyDocuments))
                .isEqualTo(StageOutcome.pass(BUSINESS_CONTEXT));
        assertThat(evaluator.evaluate(BUSINESS_CONTEXT, caseDistinctDocuments))
                .isEqualTo(StageOutcome.pass(BUSINESS_CONTEXT));
    }

    @Test
    void returnsIntegrityErrorForNullBlankOrDuplicateDocumentMembers() {
        List<String> nullMember = new ArrayList<>();
        nullMember.add(null);

        assertIntegrityError(new FactsBuilder().documents(nullMember).build());
        assertIntegrityError(new FactsBuilder().documents(List.of(" ")).build());
        assertIntegrityError(new FactsBuilder()
                .documents(List.of("DOC-1001", "DOC-1001"))
                .build());
    }

    @ParameterizedTest
    @EnumSource(RequiredFact.class)
    void rejectsEveryNullOptionalWrapper(RequiredFact fact) {
        FactsBuilder builder = new FactsBuilder().nullWrapper(fact);

        assertThatThrownBy(builder::build)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(fact.fieldName() + " must not be null");
    }

    @Test
    void defensivelyCopiesDocumentsAndExposesAnImmutableSnapshot() {
        List<String> source = new ArrayList<>(List.of("DOC-1001", "DOC-1002"));
        PolicyBusinessContextFacts facts = new FactsBuilder()
                .documents(source)
                .build();

        source.clear();
        source.add("CHANGED");

        assertThat(facts.allowedDocumentIds()).contains(List.of("DOC-1001", "DOC-1002"));
        assertThatThrownBy(() -> facts.allowedDocumentIds().orElseThrow().add("DOC-1003"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(evaluator.evaluate(BUSINESS_CONTEXT, facts))
                .isEqualTo(StageOutcome.pass(BUSINESS_CONTEXT));
    }

    @ParameterizedTest
    @EnumSource(
            value = PolicyEvaluationStage.class,
            mode = EnumSource.Mode.EXCLUDE,
            names = "BUSINESS_CONTEXT"
    )
    void rejectsEveryUnsupportedStage(PolicyEvaluationStage stage) {
        assertThatThrownBy(() -> evaluator.evaluate(stage, new FactsBuilder().build()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("PolicyBusinessContextEvaluator supports only BUSINESS_CONTEXT");
    }

    @Test
    void rejectsNullStageAndFacts() {
        assertThatThrownBy(() -> evaluator.evaluate(null, new FactsBuilder().build()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("stage must not be null");
        assertThatThrownBy(() -> evaluator.evaluate(BUSINESS_CONTEXT, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("facts must not be null");
    }

    @Test
    void sequenceClassifiesContextFailureAsOperationalErrorWithoutSecurityCredit() {
        PolicyBusinessContextFacts facts = new FactsBuilder()
                .serverResolved(false)
                .build();
        AtomicInteger laterStageEvaluations = new AtomicInteger();

        PolicyEvaluationDecision decision = PolicyEvaluationSequence.evaluate(
                () -> StageOutcome.pass(PREFLIGHT),
                stage -> {
                    if (stage == TOOL || stage == OPERATION) {
                        return StageOutcome.pass(stage);
                    }
                    if (stage == BUSINESS_CONTEXT) {
                        return evaluator.evaluate(stage, facts);
                    }
                    laterStageEvaluations.incrementAndGet();
                    return StageOutcome.pass(stage);
                }
        );

        assertThat(decision.decisionType()).isEqualTo(ERROR);
        assertThat(decision.reason()).contains(CONTEXT_INTEGRITY_FAILURE);
        assertThat(decision.failedStage()).contains(BUSINESS_CONTEXT);
        assertThat(decision.evaluatedStages()).containsExactly(
                PREFLIGHT,
                TOOL,
                OPERATION,
                BUSINESS_CONTEXT
        );
        assertThat(decision.successfulSecurityBlock()).isFalse();
        assertThat(laterStageEvaluations).hasValue(0);
    }

    @Test
    void repeatedValidAndInvalidEvaluationsAreDeterministic() {
        PolicyBusinessContextFacts valid = new FactsBuilder().build();
        PolicyBusinessContextFacts invalid = new FactsBuilder()
                .missing(RequiredFact.CURRENT_APPLICANT_ID)
                .build();

        assertThat(evaluator.evaluate(BUSINESS_CONTEXT, valid))
                .isEqualTo(evaluator.evaluate(BUSINESS_CONTEXT, valid));
        assertThat(evaluator.evaluate(BUSINESS_CONTEXT, invalid))
                .isEqualTo(evaluator.evaluate(BUSINESS_CONTEXT, invalid));
    }

    private void assertIntegrityError(PolicyBusinessContextFacts facts) {
        assertThat(evaluator.evaluate(BUSINESS_CONTEXT, facts))
                .isEqualTo(StageOutcome.error(BUSINESS_CONTEXT, CONTEXT_INTEGRITY_FAILURE));
    }

    private static Stream<RequiredFact> stringFacts() {
        return Stream.of(RequiredFact.values())
                .filter(fact -> fact != RequiredFact.ALLOWED_DOCUMENT_IDS);
    }

    private static Stream<Arguments> purposeMismatches() {
        return Stream.of(PurposeFact.values())
                .flatMap(fact -> Stream.of(
                        Arguments.of(fact, PURPOSE.toLowerCase()),
                        Arguments.of(fact, PURPOSE + " ")
                ));
    }

    private enum RequiredFact {
        CONTRACT_PURPOSE("contractPurpose"),
        RELEASE_PURPOSE("releasePurpose"),
        RUN_PURPOSE("runPurpose"),
        CASE_PURPOSE("casePurpose"),
        NAMESPACE_ID("namespaceId"),
        CASE_ID("caseId"),
        CURRENT_APPLICANT_ID("currentApplicantId"),
        WORKFLOW_STAGE("workflowStage"),
        ALLOWED_DOCUMENT_IDS("allowedDocumentIds");

        private final String fieldName;

        RequiredFact(String fieldName) {
            this.fieldName = fieldName;
        }

        String fieldName() {
            return fieldName;
        }
    }

    private enum PurposeFact {
        CONTRACT,
        RELEASE,
        RUN,
        CASE
    }

    private static final class FactsBuilder {

        private boolean serverResolved = true;
        private Optional<String> contractPurpose = Optional.of(PURPOSE);
        private Optional<String> releasePurpose = Optional.of(PURPOSE);
        private Optional<String> runPurpose = Optional.of(PURPOSE);
        private Optional<String> casePurpose = Optional.of(PURPOSE);
        private Optional<String> namespaceId = Optional.of("namespace-1");
        private Optional<String> caseId = Optional.of("CASE-1001");
        private Optional<String> currentApplicantId = Optional.of("CUST-1001");
        private Optional<String> workflowStage = Optional.of("DOCUMENT_REVIEW");
        private Optional<List<String>> allowedDocumentIds = Optional.of(
                List.of("DOC-1001", "DOC-1002")
        );

        FactsBuilder serverResolved(boolean value) {
            serverResolved = value;
            return this;
        }

        FactsBuilder missing(RequiredFact fact) {
            set(fact, Optional.empty());
            return this;
        }

        FactsBuilder blank(RequiredFact fact) {
            if (fact == RequiredFact.ALLOWED_DOCUMENT_IDS) {
                throw new IllegalArgumentException("documents are not a string fact");
            }
            set(fact, Optional.of(" "));
            return this;
        }

        FactsBuilder nullWrapper(RequiredFact fact) {
            set(fact, null);
            return this;
        }

        FactsBuilder purpose(PurposeFact fact, String value) {
            switch (fact) {
                case CONTRACT -> contractPurpose = Optional.of(value);
                case RELEASE -> releasePurpose = Optional.of(value);
                case RUN -> runPurpose = Optional.of(value);
                case CASE -> casePurpose = Optional.of(value);
            }
            return this;
        }

        FactsBuilder documents(List<String> values) {
            allowedDocumentIds = Optional.of(values);
            return this;
        }

        PolicyBusinessContextFacts build() {
            return new PolicyBusinessContextFacts(
                    serverResolved,
                    contractPurpose,
                    releasePurpose,
                    runPurpose,
                    casePurpose,
                    namespaceId,
                    caseId,
                    currentApplicantId,
                    workflowStage,
                    allowedDocumentIds
            );
        }

        @SuppressWarnings("unchecked")
        private void set(RequiredFact fact, Optional<?> value) {
            switch (fact) {
                case CONTRACT_PURPOSE -> contractPurpose = (Optional<String>) value;
                case RELEASE_PURPOSE -> releasePurpose = (Optional<String>) value;
                case RUN_PURPOSE -> runPurpose = (Optional<String>) value;
                case CASE_PURPOSE -> casePurpose = (Optional<String>) value;
                case NAMESPACE_ID -> namespaceId = (Optional<String>) value;
                case CASE_ID -> caseId = (Optional<String>) value;
                case CURRENT_APPLICANT_ID -> currentApplicantId = (Optional<String>) value;
                case WORKFLOW_STAGE -> workflowStage = (Optional<String>) value;
                case ALLOWED_DOCUMENT_IDS -> allowedDocumentIds = (Optional<List<String>>) value;
            }
        }
    }
}
