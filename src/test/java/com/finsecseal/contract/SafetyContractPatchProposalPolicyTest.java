package com.finsecseal.contract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.SourceBoundCatalog;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ContractVersionSnapshot;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionIdentity;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionState;
import com.finsecseal.contract.SafetyContractPatchOperation.NarrowSet;
import com.finsecseal.contract.SafetyContractPatchOperation.SetKind;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.FindingSourceFacts;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.Issue;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.ProposalDecision;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.ProposedPatch;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.Status;
import com.finsecseal.contract.SafetyContractSemanticValidator.ContractValidationCatalog;
import com.finsecseal.contract.SafetyContractSemanticValidator.EnabledTool;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationStatus;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

class SafetyContractPatchProposalPolicyTest {

    private static final UUID WORKSPACE = UUID.fromString("0198f200-0000-7000-8000-000000000202");
    private static final UUID RELEASE = UUID.fromString("0198f200-0000-7000-8000-000000000203");
    private static final UUID VERSION = UUID.fromString("0198f200-0000-7000-8000-000000000204");
    private static final UUID FINDING = UUID.fromString("0198f200-0000-7000-8000-000000000205");
    private static final UUID OTHER = UUID.fromString("0198f200-0000-7000-8000-000000000299");
    private static final List<String> MINIMUM_FIELDS = List.of("incomeBand", "employmentStatus");

    private ObjectMapper mapper;
    private SafetyContractCanonicalizer canonicalizer;
    private SafetyContractNarrowingValidator narrowing;
    private SafetyContractSemanticValidator semantic;
    private SafetyContractPatchProposalPolicy policy;
    private ObjectNode validPolicy;
    private ObjectNode broadPolicy;
    private ObjectNode narrowedPolicy;
    private SourceBoundCatalog catalog;

    @BeforeEach
    void setUp() throws Exception {
        mapper = new ObjectMapper();
        SafetyContractSchemaValidator schema = new SafetyContractSchemaValidator();
        canonicalizer = new SafetyContractCanonicalizer(schema, new CanonicalJsonService(mapper), new DigestService());
        narrowing = new SafetyContractNarrowingValidator(schema, canonicalizer);
        semantic = new SafetyContractSemanticValidator(schema);
        policy = new SafetyContractPatchProposalPolicy(canonicalizer, narrowing, semantic);
        try (var input = getClass().getResourceAsStream("/fixtures/loan-review-safety-contract.json")) {
            validPolicy = (ObjectNode) mapper.readTree(input);
        }
        broadPolicy = validPolicy.deepCopy();
        ((ArrayNode) broadPolicy.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed")).add("accountNumber");
        narrowedPolicy = validPolicy.deepCopy().put("version", 2);
        catalog = catalog(RELEASE);
    }

    @ParameterizedTest
    @CsvSource({"OPEN,SEED", "OPEN,MUTATION", "TRIAGED,SEED", "TRIAGED,MUTATION"})
    void acceptsExactNarrowingOfBroadCandidateAndPreservesEvidence(String findingStatus, String partition) {
        ContractVersionSnapshot base = snapshot(broadPolicy);
        FindingSourceFacts source = source(findingStatus, partition, false);

        ProposalDecision decision = policy.evaluate(source, base, candidate(narrowedPolicy, operations()), catalog);

        assertThat(base.state()).isEqualTo(VersionState.CANDIDATE);
        assertThat(semantic.validate(base.policy(), catalog.semanticCatalog()).status()).isEqualTo(ValidationStatus.INVALID);
        assertThat(decision.status()).isEqualTo(Status.PROPOSED);
        assertThat(decision.issues()).isEmpty();
        assertThat(decision.narrowing().orElseThrow().valid()).isTrue();
        assertThat(decision.semantic().orElseThrow().status()).isEqualTo(ValidationStatus.VALID);
        assertThat(decision.acceptedProposal()).hasValueSatisfying(accepted -> {
            assertThat(accepted.source()).isEqualTo(source);
            assertThat(accepted.baseIdentity()).isEqualTo(base.identity());
            assertThat(accepted.basePolicyHash()).isEqualTo(base.policyHash());
            assertThat(accepted.resultPolicy()).isEqualTo(canonicalizer.canonicalizeAndHash(narrowedPolicy));
            assertThat(accepted.operations()).isEqualTo(operations());
            assertThat(accepted.rootCause()).isEqualTo("Excessive customer fields");
            assertThat(accepted.normalWorkflowImpact()).isEqualTo("Required income and employment fields remain available");
            assertThat(accepted.rollback()).isEqualTo("Create a reviewed replacement version");
            assertThat(accepted.catalogBinding().releaseId()).isEqualTo(RELEASE);
            assertThat(accepted.catalogBinding().serverToolCatalogHash()).isEqualTo(digest('3'));
        });
        assertThat(base.policy()).isEqualTo(broadPolicy);
    }

    @Test
    void narrowerPatchStillFailsWhenItRemovesMinimumWorkflowPermission() {
        ObjectNode result = narrowedPolicy.deepCopy();
        ((ObjectNode) result.at("/fieldPolicy/CUSTOMER_DATA_READ"))
                .set("allowed", mapper.createArrayNode().add("incomeBand"));
        List<SafetyContractPatchOperation> operations = List.of(
                new NarrowSet(SetKind.ALLOWED_FIELDS, "CUSTOMER_DATA_READ", List.of("incomeBand")));

        ProposalDecision decision = policy.evaluate(source(), snapshot(broadPolicy), candidate(result, operations), catalog);

        assertInvalid(decision, "RESULT_SEMANTIC_INVALID");
        assertThat(decision.narrowing().orElseThrow().valid()).isTrue();
        assertThat(decision.semantic().orElseThrow().status()).isEqualTo(ValidationStatus.INVALID);
        assertThat(decision.semantic().orElseThrow().issues()).isNotEmpty();
    }

    @Test
    void onlyExactUnchangedValidPolicyProducesNoChangeNeeded() {
        ContractVersionSnapshot base = snapshot(validPolicy);

        ProposalDecision decision = policy.evaluate(source(), base, candidate(validPolicy, List.of()), catalog);

        assertThat(decision.status()).isEqualTo(Status.NO_CHANGE_NEEDED);
        assertThat(decision.narrowing()).isEmpty();
        assertThat(decision.semantic().orElseThrow().status()).isEqualTo(ValidationStatus.VALID);
        assertThat(decision.acceptedProposal()).hasValueSatisfying(accepted -> {
            assertThat(accepted.operations()).isEmpty();
            assertThat(accepted.resultPolicy().policyHash()).isEqualTo(base.policyHash());
            assertThat(accepted.basePolicyHash()).isEqualTo(base.policyHash());
        });
        assertInvalid(policy.evaluate(source(), snapshot(broadPolicy), candidate(broadPolicy, List.of()), catalog),
                "RESULT_SEMANTIC_INVALID");
        assertInvalid(policy.evaluate(source(), base, candidate(narrowedPolicy, List.of()), catalog),
                "EMPTY_PATCH_CHANGED_POLICY");
        assertInvalid(policy.evaluate(source(), base, candidate(narrowedPolicy, operations()), catalog), "PATCH_INVALID");
    }

    @Test
    void rejectsExpansionUndeclaredChangesAndWrongVersionsWithNarrowingIssues() {
        ObjectNode expanded = broadPolicy.deepCopy().put("version", 2);
        ProposalDecision expansion = policy.evaluate(source(), snapshot(validPolicy), candidate(expanded,
                List.of(new NarrowSet(SetKind.ALLOWED_FIELDS, "CUSTOMER_DATA_READ",
                        List.of("incomeBand", "employmentStatus", "accountNumber")))), catalog);
        ObjectNode hiddenChange = narrowedPolicy.deepCopy().put("purpose", "CHANGED");
        ProposalDecision undeclared = policy.evaluate(source(), snapshot(broadPolicy), candidate(hiddenChange, operations()), catalog);
        ObjectNode wrongVersion = narrowedPolicy.deepCopy().put("version", 3);
        ProposalDecision version = policy.evaluate(source(), snapshot(broadPolicy), candidate(wrongVersion, operations()), catalog);

        for (ProposalDecision decision : List.of(expansion, undeclared, version)) {
            assertInvalid(decision, "PATCH_INVALID");
            assertThat(decision.narrowing().orElseThrow().issues()).isNotEmpty();
            assertThat(decision.semantic()).isEmpty();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"rootCause", "impact", "rollback"})
    void rejectsMissingExplanations(String missing) {
        ProposedPatch candidate = new ProposedPatch(narrowedPolicy, operations(),
                missing.equals("rootCause") ? null : "Cause",
                missing.equals("impact") ? " " : "Impact",
                missing.equals("rollback") ? "" : "Rollback");

        assertInvalid(policy.evaluate(source(), snapshot(broadPolicy), candidate, catalog), "CANDIDATE_EXPLANATION_REQUIRED");
    }

    @ParameterizedTest
    @MethodSource("ineligibleSources")
    void rejectsIneligibleSourcesBeforeAnyValidatorCalls(FindingSourceFacts source) {
        SafetyContractCanonicalizer unusedCanonicalizer = mock(SafetyContractCanonicalizer.class);
        SafetyContractNarrowingValidator unusedNarrowing = mock(SafetyContractNarrowingValidator.class);
        SafetyContractSemanticValidator unusedSemantic = mock(SafetyContractSemanticValidator.class);
        SafetyContractPatchProposalPolicy guarded = new SafetyContractPatchProposalPolicy(
                unusedCanonicalizer, unusedNarrowing, unusedSemantic);

        assertInvalid(guarded.evaluate(source, null, null, null), "SOURCE_INELIGIBLE");
        verifyNoInteractions(unusedCanonicalizer, unusedNarrowing, unusedSemantic);
    }

    @Test
    void rejectsMissingOrMismatchedBindings() {
        ContractVersionSnapshot base = snapshot(broadPolicy);
        ProposedPatch candidate = candidate(narrowedPolicy, operations());
        FindingSourceFacts wrongWorkspace = new FindingSourceFacts(FINDING, OTHER, RELEASE,
                "OPEN", "SEED", false, digest('9'), "FIELD_SCOPE");
        FindingSourceFacts wrongRelease = new FindingSourceFacts(FINDING, WORKSPACE, OTHER,
                "OPEN", "SEED", false, digest('9'), "FIELD_SCOPE");

        assertInvalid(policy.evaluate(wrongWorkspace, base, candidate, catalog), "SOURCE_BINDING_INVALID");
        assertInvalid(policy.evaluate(wrongRelease, base, candidate, catalog), "SOURCE_BINDING_INVALID");
        assertInvalid(policy.evaluate(source(), base, candidate, catalog(OTHER)), "SOURCE_BINDING_INVALID");
        assertInvalid(policy.evaluate(source(), null, candidate, catalog), "SOURCE_BINDING_INVALID");
        assertInvalid(policy.evaluate(source(), base, candidate, null), "SOURCE_BINDING_INVALID");
        assertInvalid(policy.evaluate(source(), snapshot(broadPolicy, base.identity(), "malformed"), candidate, catalog),
                "SOURCE_BINDING_INVALID");
        assertInvalid(policy.evaluate(source(), snapshot(broadPolicy, null, base.policyHash()), candidate, catalog),
                "SOURCE_BINDING_INVALID");
        assertInvalid(policy.evaluate(source(), snapshot(broadPolicy, base.identity(), digest('8')), candidate, catalog),
                "BASE_POLICY_BINDING_INVALID");
        VersionIdentity otherVersion = new VersionIdentity(VERSION, WORKSPACE, RELEASE, "loan-review-default", 2);
        assertInvalid(policy.evaluate(source(), snapshot(broadPolicy, otherVersion, base.policyHash()), candidate, catalog),
                "BASE_POLICY_BINDING_INVALID");
        VersionIdentity otherKey = new VersionIdentity(VERSION, WORKSPACE, RELEASE, "another-contract", 1);
        assertInvalid(policy.evaluate(source(), snapshot(broadPolicy, otherKey, base.policyHash()), candidate, catalog),
                "BASE_POLICY_BINDING_INVALID");
    }

    @Test
    void rejectsMalformedPolicyAndMissingCandidateData() {
        ContractVersionSnapshot base = snapshot(broadPolicy);
        assertInvalid(policy.evaluate(source(), base, null, catalog), "CANDIDATE_INVALID");
        assertInvalid(policy.evaluate(source(), base, candidate(narrowedPolicy, null), catalog), "CANDIDATE_INVALID");
        assertInvalid(policy.evaluate(source(), base, candidate(null, operations()), catalog), "PATCH_INVALID");
        assertInvalid(policy.evaluate(source(), base, candidate(narrowedPolicy, Arrays.asList((SafetyContractPatchOperation) null)), catalog),
                "PATCH_INVALID");
        ObjectNode malformed = broadPolicy.deepCopy().put("unknownPolicy", true);
        ProposalDecision invalidBase = policy.evaluate(source(), snapshot(malformed, base.identity(), base.policyHash()),
                candidate(narrowedPolicy, operations()), catalog);
        assertInvalid(invalidBase, "STRUCTURAL_POLICY_INVALID");
        assertThat(invalidBase.issues()).anyMatch(issue -> issue.jsonPointer().equals("/unknownPolicy"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"canonicalizer", "narrowing", "semantic"})
    void dependencyFailureCannotProduceAcceptance(String dependency) {
        IllegalStateException failure = new IllegalStateException("dependency failed");
        SafetyContractCanonicalizer selectedCanonicalizer = canonicalizer;
        SafetyContractNarrowingValidator selectedNarrowing = narrowing;
        SafetyContractSemanticValidator selectedSemantic = semantic;
        if (dependency.equals("canonicalizer")) {
            selectedCanonicalizer = mock(SafetyContractCanonicalizer.class);
            when(selectedCanonicalizer.canonicalizeAndHash(any())).thenThrow(failure);
        } else if (dependency.equals("narrowing")) {
            selectedNarrowing = mock(SafetyContractNarrowingValidator.class);
            when(selectedNarrowing.validate(any(), any(), any())).thenThrow(failure);
        } else {
            selectedSemantic = mock(SafetyContractSemanticValidator.class);
            when(selectedSemantic.validate(any(), any())).thenThrow(failure);
        }
        SafetyContractPatchProposalPolicy failing = new SafetyContractPatchProposalPolicy(
                selectedCanonicalizer, selectedNarrowing, selectedSemantic);
        ContractVersionSnapshot base = snapshot(broadPolicy);

        assertThatThrownBy(() -> failing.evaluate(source(), base, candidate(narrowedPolicy, operations()), catalog))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Deterministic patch proposal evaluation failed").hasCause(failure);
    }

    @Test
    void mutableInputsCannotChangeAcceptedEvidence() {
        ObjectNode mutableResult = narrowedPolicy.deepCopy();
        List<SafetyContractPatchOperation> mutableOperations = new ArrayList<>(operations());
        ProposedPatch candidate = candidate(mutableResult, mutableOperations);
        mutableResult.put("purpose", "MUTATED");
        mutableOperations.clear();
        ((ObjectNode) candidate.resultPolicy()).put("purpose", "MUTATED_ACCESSOR_COPY");

        ProposalDecision decision = policy.evaluate(source(), snapshot(broadPolicy), candidate, catalog);

        assertThat(decision.status()).isEqualTo(Status.PROPOSED);
        assertThat(decision.acceptedProposal().orElseThrow().resultPolicy())
                .isEqualTo(canonicalizer.canonicalizeAndHash(narrowedPolicy));
        assertThatThrownBy(() -> candidate.operations().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> decision.acceptedProposal().orElseThrow().operations().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> decision.semantic().orElseThrow().issues().clear())
                .isInstanceOf(UnsupportedOperationException.class);
    }

    private static Stream<FindingSourceFacts> ineligibleSources() {
        return Stream.of(null, source("CLOSED", "SEED", false), source("OPEN", "HELD_OUT", false),
                source("OPEN", "NORMAL", false), source("OPEN", null, false), source(null, "SEED", false),
                source("OPEN", "SEED", true), source("OPEN", "SEED", null),
                new FindingSourceFacts(null, WORKSPACE, RELEASE, "OPEN", "SEED", false, digest('9'), "FIELD_SCOPE"),
                new FindingSourceFacts(FINDING, null, RELEASE, "OPEN", "SEED", false, digest('9'), "FIELD_SCOPE"),
                new FindingSourceFacts(FINDING, WORKSPACE, null, "OPEN", "SEED", false, digest('9'), "FIELD_SCOPE"),
                new FindingSourceFacts(FINDING, WORKSPACE, RELEASE, "OPEN", "SEED", false, "bad", "FIELD_SCOPE"),
                new FindingSourceFacts(FINDING, WORKSPACE, RELEASE, "OPEN", "SEED", false, digest('9'), " "));
    }

    private static FindingSourceFacts source() {
        return source("OPEN", "SEED", false);
    }

    private static FindingSourceFacts source(String status, String partition, Boolean hidden) {
        return new FindingSourceFacts(FINDING, WORKSPACE, RELEASE, status, partition, hidden, digest('9'), "FIELD_SCOPE");
    }

    private ContractVersionSnapshot snapshot(ObjectNode policy) {
        return snapshot(policy, new VersionIdentity(VERSION, WORKSPACE, RELEASE, "loan-review-default", 1),
                canonicalizer.canonicalizeAndHash(policy).policyHash());
    }

    private ContractVersionSnapshot snapshot(JsonNode policy, VersionIdentity identity, String policyHash) {
        return new ContractVersionSnapshot(identity, VersionState.CANDIDATE, policy, policyHash,
                digest('4'), Optional.empty(), Optional.empty());
    }

    private static ProposedPatch candidate(JsonNode policy, List<SafetyContractPatchOperation> operations) {
        return new ProposedPatch(policy, operations, "Excessive customer fields",
                "Required income and employment fields remain available", "Create a reviewed replacement version");
    }

    private static List<SafetyContractPatchOperation> operations() {
        return List.of(new NarrowSet(SetKind.ALLOWED_FIELDS, "CUSTOMER_DATA_READ", MINIMUM_FIELDS));
    }

    private static SourceBoundCatalog catalog(UUID releaseId) {
        return new SourceBoundCatalog(releaseId, "1.1", digest('1'), digest('2'), digest('3'),
                new ContractValidationCatalog(List.of(
                        new EnabledTool("CASE_CONTEXT_READ", List.of("caseId")),
                        new EnabledTool("CUSTOMER_DATA_READ", List.of("accountNumber", "employmentStatus", "incomeBand")),
                        new EnabledTool("DOCUMENT_READER", List.of("documents")),
                        new EnabledTool("LOAN_POLICY_SEARCH", List.of("policies")),
                        new EnabledTool("REVIEW_NOTE_WRITE", List.of("status"))), List.of("LOAN_DECISION_UPDATE")));
    }

    private static void assertInvalid(ProposalDecision decision, String code) {
        assertThat(decision.status()).isEqualTo(Status.INVALID);
        assertThat(decision.acceptedProposal()).isEmpty();
        assertThat(decision.issues()).extracting(Issue::code).contains(code);
    }

    private static String digest(char value) {
        return "sha256:" + String.valueOf(value).repeat(64);
    }
}
