package com.finsecseal.contract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.SourceBoundCatalog;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ApprovalTransitionCommand;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ContractVersionSnapshot;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.LifecyclePolicyException;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.RejectionCode;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.RejectionTransitionCommand;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.SourceBinding;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ValidationDecision;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ValidationProof;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionIdentity;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionState;
import com.finsecseal.contract.SafetyContractSemanticValidator.ContractValidationCatalog;
import com.finsecseal.contract.SafetyContractSemanticValidator.EnabledTool;
import com.finsecseal.contract.SafetyContractSemanticValidator.Issue;
import com.finsecseal.contract.SafetyContractSemanticValidator.IssueSeverity;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationResult;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationStatus;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import java.io.InputStream;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InOrder;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

class SafetyContractLifecyclePolicyTest {

    private static final UUID VERSION_ID = UUID.fromString(
            "0198f200-0000-7000-8000-000000000201"
    );
    private static final UUID WORKSPACE_ID = UUID.fromString(
            "0198f200-0000-7000-8000-000000000202"
    );
    private static final UUID RELEASE_ID = UUID.fromString(
            "0198f200-0000-7000-8000-000000000203"
    );
    private static final String CONTRACT_KEY = "loan-review-default";
    private static final String VALIDATOR_ACTOR = "validator:contract";
    private static final String CANDIDATE_RESOURCE_HASH = digest('4');
    private static final String VALIDATED_RESOURCE_HASH = digest('5');
    private static final String BASE_POLICY_HASH = digest('6');

    private ObjectMapper objectMapper;
    private SafetyContractSchemaValidator schemaValidator;
    private SafetyContractCanonicalizer canonicalizer;
    private SafetyContractSemanticValidator semanticValidator;
    private CanonicalJsonService canonicalJsonService;
    private DigestService digestService;
    private SafetyContractLifecyclePolicy lifecyclePolicy;
    private ObjectNode contract;
    private SourceBoundCatalog sourceCatalog;
    private AtomicInteger catalogLoads;

    @BeforeEach
    void setUp() throws Exception {
        objectMapper = new ObjectMapper();
        schemaValidator = new SafetyContractSchemaValidator();
        canonicalJsonService = new CanonicalJsonService(objectMapper);
        digestService = new DigestService();
        canonicalizer = new SafetyContractCanonicalizer(
                schemaValidator,
                canonicalJsonService,
                digestService
        );
        semanticValidator = new SafetyContractSemanticValidator(schemaValidator);
        contract = loadContract();
        sourceCatalog = source(RELEASE_ID, digest('2'));
        catalogLoads = new AtomicInteger();
        lifecyclePolicy = policy(semanticValidator);
    }

    @Test
    void validCandidateProducesSourceBoundCandidateToValidatedCommand() {
        ContractVersionSnapshot candidate = candidate(contract);

        ValidationDecision decision = lifecyclePolicy.validate(
                candidate,
                VALIDATOR_ACTOR
        );

        assertThat(decision.validationProof().result().status())
                .isEqualTo(ValidationStatus.VALID);
        assertThat(decision.validationProof().basePolicyHash())
                .contains(BASE_POLICY_HASH);
        assertThat(decision.transitionCommand()).hasValueSatisfying(command -> {
            assertThat(command.identity()).isEqualTo(candidate.identity());
            assertThat(command.expectedState()).isEqualTo(VersionState.CANDIDATE);
            assertThat(command.targetState()).isEqualTo(VersionState.VALIDATED);
            assertThat(command.expectedResourceHash())
                    .isEqualTo(CANDIDATE_RESOURCE_HASH);
            assertThat(command.policyHash()).isEqualTo(candidate.policyHash());
            assertThat(command.basePolicyHash()).contains(BASE_POLICY_HASH);
            assertThat(command.validationHash())
                    .isEqualTo(decision.validationProof().validationHash());
            assertThat(command.validationProof().sourceBinding().releaseId())
                    .isEqualTo(RELEASE_ID);
            assertThat(command.validationProof().sourceBinding().releaseFingerprint())
                    .isEqualTo(digest('2'));
        });
        assertThat(catalogLoads).hasValue(1);
    }

    @Test
    void semanticInvalidCandidateReturnsEvidenceWithoutMutationCommand() {
        ObjectNode invalid = contract.deepCopy();
        ((ArrayNode) invalid.path("allowedTools")).removeAll();

        ValidationDecision decision = lifecyclePolicy.validate(
                candidate(invalid),
                VALIDATOR_ACTOR
        );

        assertThat(decision.validationProof().result().status())
                .isEqualTo(ValidationStatus.INVALID);
        assertThat(decision.validationProof().result().issues())
                .extracting(Issue::code)
                .contains("REQUIRED_TOOL_MISSING");
        assertThat(decision.transitionCommand()).isEmpty();
        assertThat(catalogLoads).hasValue(1);
    }

    @Test
    void structuralFailureEmitsNoCommandAndDoesNotLoadCatalog() {
        ObjectNode invalid = contract.deepCopy();
        invalid.put("unknownPolicy", true);
        ContractVersionSnapshot snapshot = snapshot(
                VersionState.CANDIDATE,
                invalid,
                digest('9'),
                CANDIDATE_RESOURCE_HASH,
                Optional.empty()
        );

        assertRejected(
                RejectionCode.STRUCTURAL_POLICY_INVALID,
                () -> lifecyclePolicy.validate(snapshot, VALIDATOR_ACTOR)
        );
        assertThat(catalogLoads).hasValue(0);
    }

    @ParameterizedTest
    @MethodSource("nonCandidateStates")
    void validationRejectsEveryNonCandidateStateBeforeCatalogLoad(
            VersionState state
    ) {
        ContractVersionSnapshot snapshot = snapshot(
                state,
                contract,
                policyHash(contract),
                CANDIDATE_RESOURCE_HASH,
                Optional.empty()
        );

        assertRejected(
                RejectionCode.INVALID_STATE_TRANSITION,
                () -> lifecyclePolicy.validate(snapshot, VALIDATOR_ACTOR)
        );
        assertThat(catalogLoads).hasValue(0);
    }

    @Test
    void validationRejectsPolicyTamperingBeforeCatalogLoad() {
        ContractVersionSnapshot snapshot = snapshot(
                VersionState.CANDIDATE,
                contract,
                digest('9'),
                CANDIDATE_RESOURCE_HASH,
                Optional.empty()
        );

        assertRejected(
                RejectionCode.POLICY_HASH_MISMATCH,
                () -> lifecyclePolicy.validate(snapshot, VALIDATOR_ACTOR)
        );
        assertThat(catalogLoads).hasValue(0);
    }

    @Test
    void validationRejectsPolicyIdentityThatDoesNotMatchStoredVersion() {
        ObjectNode wrongKey = contract.deepCopy();
        wrongKey.put("contractId", "another-contract");
        ObjectNode wrongVersion = contract.deepCopy();
        wrongVersion.put("version", 2);

        assertRejected(
                RejectionCode.POLICY_IDENTITY_MISMATCH,
                () -> lifecyclePolicy.validate(candidate(wrongKey), VALIDATOR_ACTOR)
        );
        assertRejected(
                RejectionCode.POLICY_IDENTITY_MISMATCH,
                () -> lifecyclePolicy.validate(candidate(wrongVersion), VALIDATOR_ACTOR)
        );
        assertThat(catalogLoads).hasValue(0);
    }

    @Test
    void validationRejectsCatalogBoundToAnotherRelease() {
        sourceCatalog = source(
                UUID.fromString("0198f200-0000-7000-8000-000000000299"),
                digest('2')
        );

        assertRejected(
                RejectionCode.RELEASE_BINDING_MISMATCH,
                () -> lifecyclePolicy.validate(candidate(contract), VALIDATOR_ACTOR)
        );
        assertThat(catalogLoads).hasValue(1);
    }

    @Test
    void warningOnlyValidationRemainsEligible() {
        Issue warning = new Issue(
                "/metadata",
                "SAFE_WARNING",
                IssueSeverity.WARNING,
                "Safe warning"
        );
        SafetyContractSemanticValidator warningValidator =
                new SafetyContractSemanticValidator(schemaValidator) {
                    @Override
                    public ValidationResult validate(
                            tools.jackson.databind.JsonNode ignoredContract,
                            ContractValidationCatalog ignoredCatalog
                    ) {
                        return ValidationResult.fromIssues(List.of(warning));
                    }
                };

        ValidationDecision decision = policy(warningValidator).validate(
                candidate(contract),
                VALIDATOR_ACTOR
        );

        assertThat(decision.validationProof().result().status())
                .isEqualTo(ValidationStatus.WARN);
        assertThat(decision.transitionCommand()).isPresent();
    }

    @Test
    void identicalValidationInputsProduceIdenticalEvidenceAndCommands() {
        ContractVersionSnapshot candidate = candidate(contract);

        ValidationDecision first = lifecyclePolicy.validate(candidate, VALIDATOR_ACTOR);
        ValidationDecision second = lifecyclePolicy.validate(candidate, VALIDATOR_ACTOR);

        assertThat(second).isEqualTo(first);
        assertThat(second.validationProof().validationHash())
                .isEqualTo(first.validationProof().validationHash());
        assertThat(first.validationProof().validationHash()).isEqualTo(
                "sha256:a7dcb35b51dba519079479b407820b0c92bb0549bee3810cace6f9e500464aa3"
        );
        assertThat(catalogLoads).hasValue(2);
    }

    @Test
    void validationDerivesVersionFromCanonicalMetadataAndNeverTransitionsInvalidMetadata() {
        ObjectNode missingVersion = contract.deepCopy();
        ((ObjectNode) missingVersion.path("metadata")).remove("validatorVersion");
        ObjectNode mismatchedVersion = contract.deepCopy();
        ((ObjectNode) mismatchedVersion.path("metadata"))
                .put("validatorVersion", "9.9");

        ValidationDecision missing = lifecyclePolicy.validate(
                candidate(missingVersion),
                VALIDATOR_ACTOR
        );
        ValidationDecision mismatched = lifecyclePolicy.validate(
                candidate(mismatchedVersion),
                VALIDATOR_ACTOR
        );

        assertThat(missing.validationProof().validatorVersion()).isEmpty();
        assertThat(missing.validationProof().result().status())
                .isEqualTo(ValidationStatus.INVALID);
        assertThat(missing.transitionCommand()).isEmpty();
        assertThat(mismatched.validationProof().validatorVersion()).isEqualTo("9.9");
        assertThat(mismatched.validationProof().result().status())
                .isEqualTo(ValidationStatus.INVALID);
        assertThat(mismatched.transitionCommand()).isEmpty();
    }

    @Test
    void validationNormalizesIssueOrderBeforeHashing() {
        Issue firstIssue = new Issue(
                "/a",
                "FIRST_WARNING",
                IssueSeverity.WARNING,
                "First warning"
        );
        Issue secondIssue = new Issue(
                "/z",
                "SECOND_WARNING",
                IssueSeverity.WARNING,
                "Second warning"
        );
        SafetyContractSemanticValidator reverseOrder = warningValidator(
                List.of(secondIssue, firstIssue)
        );
        SafetyContractSemanticValidator forwardOrder = warningValidator(
                List.of(firstIssue, secondIssue)
        );

        ValidationProof reverseProof = policy(reverseOrder).validate(
                candidate(contract),
                VALIDATOR_ACTOR
        ).validationProof();
        ValidationProof forwardProof = policy(forwardOrder).validate(
                candidate(contract),
                VALIDATOR_ACTOR
        ).validationProof();

        assertThat(reverseProof).isEqualTo(forwardProof);
        assertThat(reverseProof.result().issues())
                .containsExactly(firstIssue, secondIssue);
    }

    @Test
    void lifecycleSupportsAbsentBasePolicyHashWithStableCanonicalNullBinding() {
        VersionIdentity identity = defaultIdentity();
        ContractVersionSnapshot candidate = new ContractVersionSnapshot(
                identity,
                VersionState.CANDIDATE,
                contract,
                policyHash(contract),
                CANDIDATE_RESOURCE_HASH,
                Optional.empty(),
                Optional.empty()
        );

        ValidationDecision first = lifecyclePolicy.validate(candidate, VALIDATOR_ACTOR);
        ValidationDecision second = lifecyclePolicy.validate(candidate, VALIDATOR_ACTOR);
        ContractVersionSnapshot validated = new ContractVersionSnapshot(
                identity,
                VersionState.VALIDATED,
                contract,
                candidate.policyHash(),
                VALIDATED_RESOURCE_HASH,
                Optional.empty(),
                Optional.of(first.validationProof())
        );
        ApprovalTransitionCommand approved = lifecyclePolicy.approve(
                validated,
                quote(VALIDATED_RESOURCE_HASH),
                trustedReviewer(),
                "Reviewed without a base policy"
        );

        assertThat(first.validationProof().basePolicyHash()).isEmpty();
        assertThat(first.validationProof().validationHash())
                .isEqualTo(second.validationProof().validationHash());
        assertThat(first.validationProof().validationHash()).isEqualTo(
                "sha256:beede00e8162c026a2530d07b0522558fde97b3d08d51c69fb6d000ccd599084"
        );
        assertThat(approved.basePolicyHash()).isEmpty();
    }

    @Test
    void approvalReproducesDeterministicValidationInsteadOfTrustingStoredProof() {
        AtomicInteger validations = new AtomicInteger();
        SafetyContractSemanticValidator countingValidator =
                new SafetyContractSemanticValidator(schemaValidator) {
                    @Override
                    public ValidationResult validate(
                            tools.jackson.databind.JsonNode selectedContract,
                            ContractValidationCatalog selectedCatalog
                    ) {
                        validations.incrementAndGet();
                        return super.validate(selectedContract, selectedCatalog);
                    }
                };
        SafetyContractLifecyclePolicy countingPolicy = policy(countingValidator);
        ContractVersionSnapshot validated = validatedSnapshot(countingPolicy, contract);

        countingPolicy.approve(
                validated,
                quote(VALIDATED_RESOURCE_HASH),
                trustedReviewer(),
                "Reviewed after deterministic revalidation"
        );

        assertThat(validations).hasValue(2);
    }

    @Test
    void approvalRejectsStoredProofWhenReproducedResultDiffers() {
        AtomicInteger validations = new AtomicInteger();
        Issue warning = new Issue(
                "/metadata",
                "REPRODUCED_WARNING",
                IssueSeverity.WARNING,
                "Reproduced result differs"
        );
        SafetyContractSemanticValidator changingValidator =
                new SafetyContractSemanticValidator(schemaValidator) {
                    @Override
                    public ValidationResult validate(
                            tools.jackson.databind.JsonNode selectedContract,
                            ContractValidationCatalog selectedCatalog
                    ) {
                        if (validations.incrementAndGet() == 1) {
                            return super.validate(selectedContract, selectedCatalog);
                        }
                        return ValidationResult.fromIssues(List.of(warning));
                    }
                };
        SafetyContractLifecyclePolicy changingPolicy = policy(changingValidator);
        ContractVersionSnapshot validated = validatedSnapshot(changingPolicy, contract);

        assertRejected(
                RejectionCode.VALIDATION_BINDING_MISMATCH,
                () -> changingPolicy.approve(
                        validated,
                        quote(VALIDATED_RESOURCE_HASH),
                        trustedReviewer(),
                        "Reviewed"
                )
        );
        assertThat(validations).hasValue(2);
    }

    @Test
    void approvalFailsClosedWhenAuthoritativeSemanticRevalidationThrows() {
        AtomicInteger validations = new AtomicInteger();
        SafetyContractSemanticValidator failingRevalidation =
                new SafetyContractSemanticValidator(schemaValidator) {
                    @Override
                    public ValidationResult validate(
                            tools.jackson.databind.JsonNode selectedContract,
                            ContractValidationCatalog selectedCatalog
                    ) {
                        if (validations.incrementAndGet() == 1) {
                            return super.validate(selectedContract, selectedCatalog);
                        }
                        throw new IllegalStateException("revalidation failed");
                    }
                };
        SafetyContractLifecyclePolicy failingPolicy = policy(failingRevalidation);
        ContractVersionSnapshot validated = validatedSnapshot(failingPolicy, contract);

        assertRejected(
                RejectionCode.VALIDATION_FAILURE,
                () -> failingPolicy.approve(
                        validated,
                        quote(VALIDATED_RESOURCE_HASH),
                        trustedReviewer(),
                        "Reviewed"
                )
        );
        assertThat(validations).hasValue(2);
        assertThat(catalogLoads).hasValue(2);
    }

    @Test
    void validationFailsClosedWhenCatalogIsUnavailableOrThrows() {
        SafetyContractLifecyclePolicy nullCatalog = policy(
                (releaseId, actorId) -> null,
                canonicalizer,
                semanticValidator
        );
        SafetyContractLifecyclePolicy throwingCatalog = policy(
                (releaseId, actorId) -> {
                    throw new IllegalStateException("source unavailable");
                },
                canonicalizer,
                semanticValidator
        );

        assertRejected(
                RejectionCode.CATALOG_SOURCE_UNAVAILABLE,
                () -> nullCatalog.validate(candidate(contract), VALIDATOR_ACTOR)
        );
        assertRejected(
                RejectionCode.CATALOG_SOURCE_FAILURE,
                () -> throwingCatalog.validate(candidate(contract), VALIDATOR_ACTOR)
        );
    }

    @Test
    void validationFailsClosedWhenCanonicalizerOrValidatorThrows() {
        SafetyContractCanonicalizer throwingCanonicalizer =
                new SafetyContractCanonicalizer(
                        schemaValidator,
                        canonicalJsonService,
                        digestService
                ) {
                    @Override
                    public CanonicalPolicy canonicalizeAndHash(
                            tools.jackson.databind.JsonNode ignored
                    ) {
                        throw new IllegalStateException("hash service failed");
                    }
                };
        SafetyContractSemanticValidator throwingValidator =
                new SafetyContractSemanticValidator(schemaValidator) {
                    @Override
                    public ValidationResult validate(
                            tools.jackson.databind.JsonNode ignoredContract,
                            ContractValidationCatalog ignoredCatalog
                    ) {
                        throw new IllegalStateException("validator failed");
                    }
                };

        assertRejected(
                RejectionCode.POLICY_CANONICALIZATION_FAILURE,
                () -> policy(
                        (releaseId, actorId) -> sourceCatalog,
                        throwingCanonicalizer,
                        semanticValidator
                ).validate(candidate(contract), VALIDATOR_ACTOR)
        );
        catalogLoads.set(0);
        assertRejected(
                RejectionCode.VALIDATION_FAILURE,
                () -> policy(throwingValidator).validate(
                        candidate(contract),
                        VALIDATOR_ACTOR
                )
        );
        assertThat(catalogLoads).hasValue(1);
    }

    @Test
    void proofHashCanonicalizationAndDigestFailuresFailClosedWithExactCode() {
        CanonicalJsonService throwingCanonicalJson = new CanonicalJsonService(objectMapper) {
            @Override
            public byte[] canonicalize(tools.jackson.databind.JsonNode ignored) {
                throw new IllegalStateException("proof canonicalization failed");
            }
        };
        DigestService throwingDigest = new DigestService() {
            @Override
            public String sha256(byte[] ignored) {
                throw new IllegalStateException("proof digest failed");
            }
        };
        SafetyContractLifecyclePolicy canonicalFailure = policy(
                throwingCanonicalJson,
                digestService,
                semanticValidator
        );
        SafetyContractLifecyclePolicy digestFailure = policy(
                canonicalJsonService,
                throwingDigest,
                semanticValidator
        );

        catalogLoads.set(0);
        assertRejected(
                RejectionCode.VALIDATION_FAILURE,
                () -> canonicalFailure.validate(candidate(contract), VALIDATOR_ACTOR)
        );
        assertThat(catalogLoads).hasValue(1);
        catalogLoads.set(0);
        assertRejected(
                RejectionCode.VALIDATION_FAILURE,
                () -> digestFailure.validate(candidate(contract), VALIDATOR_ACTOR)
        );
        assertThat(catalogLoads).hasValue(1);
    }

    @Test
    void approvalProofHashDependencyFailuresFailClosedBeforeCatalogReload() {
        ContractVersionSnapshot validated = validatedSnapshot();
        CanonicalJsonService throwingCanonicalJson = new CanonicalJsonService(objectMapper) {
            @Override
            public byte[] canonicalize(tools.jackson.databind.JsonNode ignored) {
                throw new IllegalStateException("proof canonicalization failed");
            }
        };
        DigestService throwingDigest = new DigestService() {
            @Override
            public String sha256(byte[] ignored) {
                throw new IllegalStateException("proof digest failed");
            }
        };
        List<SafetyContractLifecyclePolicy> failingPolicies = List.of(
                policy(throwingCanonicalJson, digestService, semanticValidator),
                policy(canonicalJsonService, throwingDigest, semanticValidator)
        );
        catalogLoads.set(0);

        for (SafetyContractLifecyclePolicy failingPolicy : failingPolicies) {
            assertRejected(
                    RejectionCode.VALIDATION_FAILURE,
                    () -> failingPolicy.approve(
                            validated,
                            quote(VALIDATED_RESOURCE_HASH),
                            trustedReviewer(),
                            "Reviewed"
                    )
            );
        }
        assertThat(catalogLoads).hasValue(0);
    }

    @Test
    void validationRejectsMissingSnapshotAndUnicodeBlankActor() {
        assertRejected(
                RejectionCode.INVALID_SNAPSHOT,
                () -> lifecyclePolicy.validate(null, VALIDATOR_ACTOR)
        );
        assertRejected(
                RejectionCode.INVALID_ACTOR,
                () -> lifecyclePolicy.validate(candidate(contract), null)
        );
        assertRejected(
                RejectionCode.INVALID_ACTOR,
                () -> lifecyclePolicy.validate(candidate(contract), "\u2003")
        );
        assertThat(catalogLoads).hasValue(0);
    }

    @Test
    void productionConstructorForwardsExactReleaseAndActorToAuthoritativeAdapter() {
        ReleaseToolCatalogContractAdapter adapter = mock(
                ReleaseToolCatalogContractAdapter.class
        );
        when(adapter.load(RELEASE_ID, VALIDATOR_ACTOR)).thenReturn(sourceCatalog);
        when(adapter.load(RELEASE_ID, "reviewer:security")).thenReturn(sourceCatalog);
        SafetyContractLifecyclePolicy productionPolicy = new SafetyContractLifecyclePolicy(
                adapter,
                canonicalizer,
                semanticValidator,
                canonicalJsonService,
                digestService,
                objectMapper
        );
        ContractVersionSnapshot candidate = candidate(contract);

        ValidationProof proof = productionPolicy.validate(
                candidate,
                VALIDATOR_ACTOR
        ).transitionCommand().orElseThrow().validationProof();
        ContractVersionSnapshot validated = snapshot(
                VersionState.VALIDATED,
                contract,
                candidate.policyHash(),
                VALIDATED_RESOURCE_HASH,
                Optional.of(proof)
        );
        productionPolicy.approve(
                validated,
                quote(VALIDATED_RESOURCE_HASH),
                trustedReviewer(),
                "Reviewed"
        );

        InOrder calls = inOrder(adapter);
        calls.verify(adapter).load(RELEASE_ID, VALIDATOR_ACTOR);
        calls.verify(adapter).load(RELEASE_ID, "reviewer:security");
        verifyNoMoreInteractions(adapter);
    }

    @Test
    void constructorsRejectEveryNullDependency() {
        ReleaseToolCatalogContractAdapter adapter = mock(
                ReleaseToolCatalogContractAdapter.class
        );
        SafetyContractLifecyclePolicy.VerifiedCatalogLoader loader =
                (releaseId, actorId) -> sourceCatalog;
        List<org.assertj.core.api.ThrowableAssert.ThrowingCallable> constructions = List.of(
                () -> new SafetyContractLifecyclePolicy(
                        (ReleaseToolCatalogContractAdapter) null,
                        canonicalizer,
                        semanticValidator,
                        canonicalJsonService,
                        digestService,
                        objectMapper
                ),
                () -> new SafetyContractLifecyclePolicy(
                        adapter, null, semanticValidator, canonicalJsonService,
                        digestService, objectMapper
                ),
                () -> new SafetyContractLifecyclePolicy(
                        adapter, canonicalizer, null, canonicalJsonService,
                        digestService, objectMapper
                ),
                () -> new SafetyContractLifecyclePolicy(
                        adapter, canonicalizer, semanticValidator, null,
                        digestService, objectMapper
                ),
                () -> new SafetyContractLifecyclePolicy(
                        adapter, canonicalizer, semanticValidator, canonicalJsonService,
                        null, objectMapper
                ),
                () -> new SafetyContractLifecyclePolicy(
                        adapter, canonicalizer, semanticValidator, canonicalJsonService,
                        digestService, null
                ),
                () -> new SafetyContractLifecyclePolicy(
                        (SafetyContractLifecyclePolicy.VerifiedCatalogLoader) null,
                        canonicalizer,
                        semanticValidator,
                        canonicalJsonService,
                        digestService,
                        objectMapper
                ),
                () -> new SafetyContractLifecyclePolicy(
                        loader, null, semanticValidator, canonicalJsonService,
                        digestService, objectMapper
                ),
                () -> new SafetyContractLifecyclePolicy(
                        loader, canonicalizer, null, canonicalJsonService,
                        digestService, objectMapper
                ),
                () -> new SafetyContractLifecyclePolicy(
                        loader, canonicalizer, semanticValidator, null,
                        digestService, objectMapper
                ),
                () -> new SafetyContractLifecyclePolicy(
                        loader, canonicalizer, semanticValidator, canonicalJsonService,
                        null, objectMapper
                ),
                () -> new SafetyContractLifecyclePolicy(
                        loader, canonicalizer, semanticValidator, canonicalJsonService,
                        digestService, null
                )
        );

        constructions.forEach(construction -> assertThatThrownBy(construction)
                .isInstanceOf(NullPointerException.class));
        verifyNoMoreInteractions(adapter);
    }

    @Test
    void approvalProducesValidatedToApprovedCasCommandWithProvenance() {
        ContractVersionSnapshot validated = validatedSnapshot();
        ReviewerContext reviewer = trustedReviewer();

        ApprovalTransitionCommand command = lifecyclePolicy.approve(
                validated,
                quote(VALIDATED_RESOURCE_HASH),
                reviewer,
                "Reviewed deterministic validation evidence"
        );

        assertThat(command.identity()).isEqualTo(validated.identity());
        assertThat(command.expectedState()).isEqualTo(VersionState.VALIDATED);
        assertThat(command.targetState()).isEqualTo(VersionState.APPROVED);
        assertThat(command.expectedResourceHash()).isEqualTo(VALIDATED_RESOURCE_HASH);
        assertThat(command.policyHash()).isEqualTo(validated.policyHash());
        assertThat(command.basePolicyHash()).contains(BASE_POLICY_HASH);
        assertThat(command.validationHash())
                .isEqualTo(validated.validationProof().orElseThrow().validationHash());
        assertThat(command.reviewer().actorId()).isEqualTo("reviewer:security");
        assertThat(command.reviewer().role()).isEqualTo("AI_SECURITY_REVIEWER");
        assertThat(command.reviewer().sessionId()).isEqualTo("session-123");
        assertThat(command.reviewer().authenticated()).isTrue();
        assertThat(command.reviewer().csrfVerified()).isTrue();
        assertThat(command.reviewer().demoMode()).isTrue();
        assertThat(command.comment())
                .isEqualTo("Reviewed deterministic validation evidence");
        assertThat(catalogLoads).hasValue(2);
    }

    @Test
    void approvalAcceptsWarningProofWhenItContainsZeroErrors() {
        Issue warning = new Issue(
                "/metadata",
                "SAFE_WARNING",
                IssueSeverity.WARNING,
                "Safe warning"
        );
        SafetyContractSemanticValidator warningValidator =
                new SafetyContractSemanticValidator(schemaValidator) {
                    @Override
                    public ValidationResult validate(
                            tools.jackson.databind.JsonNode ignoredContract,
                            ContractValidationCatalog ignoredCatalog
                    ) {
                        return ValidationResult.fromIssues(List.of(warning));
                    }
                };
        SafetyContractLifecyclePolicy warningPolicy = policy(warningValidator);
        ContractVersionSnapshot validated = validatedSnapshot(warningPolicy, contract);

        ApprovalTransitionCommand command = warningPolicy.approve(
                validated,
                quote(VALIDATED_RESOURCE_HASH),
                trustedReviewer(),
                "Warning reviewed"
        );

        assertThat(command.validationProof().result().status())
                .isEqualTo(ValidationStatus.WARN);
        assertThat(command.validationProof().result().issues())
                .allMatch(issue -> issue.severity() != IssueSeverity.ERROR);
    }

    @Test
    void approvalAcceptsAuthenticatedNonDemoReviewer() {
        ContractVersionSnapshot validated = validatedSnapshot();
        ReviewerContext nonDemoReviewer = new ReviewerContext(
                WORKSPACE_ID,
                "reviewer:security",
                "AI_SECURITY_REVIEWER",
                "session-123",
                true,
                true,
                false
        );

        ApprovalTransitionCommand command = lifecyclePolicy.approve(
                validated,
                quote(VALIDATED_RESOURCE_HASH),
                nonDemoReviewer,
                "Reviewed outside demo mode"
        );

        assertThat(command.reviewer().demoMode()).isFalse();
    }

    @Test
    void approvalRejectsMissingAndInvalidValidationProof() {
        ContractVersionSnapshot missingProof = snapshot(
                VersionState.VALIDATED,
                contract,
                policyHash(contract),
                VALIDATED_RESOURCE_HASH,
                Optional.empty()
        );
        Issue error = new Issue(
                "/allowedTools",
                "REQUIRED_TOOL_MISSING",
                IssueSeverity.ERROR,
                "Required Tool is missing"
        );
        SafetyContractSemanticValidator invalidValidator =
                new SafetyContractSemanticValidator(schemaValidator) {
                    @Override
                    public ValidationResult validate(
                            tools.jackson.databind.JsonNode ignoredContract,
                            ContractValidationCatalog ignoredCatalog
                    ) {
                        return ValidationResult.fromIssues(List.of(error));
                    }
                };
        ValidationProof invalidProof = policy(invalidValidator).validate(
                candidate(contract),
                VALIDATOR_ACTOR
        ).validationProof();
        ContractVersionSnapshot invalid = snapshot(
                VersionState.VALIDATED,
                contract,
                policyHash(contract),
                VALIDATED_RESOURCE_HASH,
                Optional.of(invalidProof)
        );
        catalogLoads.set(0);

        assertRejected(
                RejectionCode.VALIDATION_PROOF_REQUIRED,
                () -> lifecyclePolicy.approve(
                        missingProof,
                        quote(VALIDATED_RESOURCE_HASH),
                        trustedReviewer(),
                        "Reviewed"
                )
        );
        assertRejected(
                RejectionCode.VALIDATION_NOT_ELIGIBLE,
                () -> lifecyclePolicy.approve(
                        invalid,
                        quote(VALIDATED_RESOURCE_HASH),
                        trustedReviewer(),
                        "Reviewed"
                )
        );
        assertThat(catalogLoads).hasValue(0);
    }

    @Test
    void approvalRejectsSelfConsistentOldProofForNewlyHashedPolicy() {
        ContractVersionSnapshot validated = validatedSnapshot();
        ObjectNode changed = (ObjectNode) validated.policy();
        ((ObjectNode) changed.path("resourcePolicies")).set(
                "CASE_CONTEXT_READ",
                objectMapper.createObjectNode().put("caseScope", "CURRENT_CASE_ONLY")
        );
        String changedHash = policyHash(changed);
        assertThat(changedHash).isNotEqualTo(validated.policyHash());
        ContractVersionSnapshot staleProof = snapshot(
                VersionState.VALIDATED,
                changed,
                changedHash,
                VALIDATED_RESOURCE_HASH,
                validated.validationProof()
        );
        catalogLoads.set(0);

        assertRejected(
                RejectionCode.VALIDATION_BINDING_MISMATCH,
                () -> lifecyclePolicy.approve(
                        staleProof,
                        quote(VALIDATED_RESOURCE_HASH),
                        trustedReviewer(),
                        "Reviewed"
                )
        );
        assertThat(catalogLoads).hasValue(0);
    }

    @Test
    void approvalRejectsSelfConsistentProofForAnotherVersionIdentity() {
        VersionIdentity otherIdentity = new VersionIdentity(
                UUID.fromString("0198f200-0000-7000-8000-000000000297"),
                WORKSPACE_ID,
                RELEASE_ID,
                CONTRACT_KEY,
                1
        );
        ContractVersionSnapshot otherCandidate = snapshot(
                otherIdentity,
                VersionState.CANDIDATE,
                contract,
                policyHash(contract),
                CANDIDATE_RESOURCE_HASH,
                Optional.empty()
        );
        ValidationProof otherProof = lifecyclePolicy.validate(
                otherCandidate,
                VALIDATOR_ACTOR
        ).validationProof();
        ContractVersionSnapshot originalIdentity = snapshot(
                VersionState.VALIDATED,
                contract,
                policyHash(contract),
                VALIDATED_RESOURCE_HASH,
                Optional.of(otherProof)
        );
        catalogLoads.set(0);

        assertRejected(
                RejectionCode.VALIDATION_BINDING_MISMATCH,
                () -> lifecyclePolicy.approve(
                        originalIdentity,
                        quote(VALIDATED_RESOURCE_HASH),
                        trustedReviewer(),
                        "Reviewed"
                )
        );
        assertThat(catalogLoads).hasValue(0);
    }

    @Test
    void approvalNeverTreatsCanonicalPolicyHashAsResourceFreshnessTag() {
        ContractVersionSnapshot validated = validatedSnapshot();

        assertThat(validated.policyHash()).isNotEqualTo(validated.resourceHash());
        assertRejected(
                RejectionCode.STALE_RESOURCE,
                () -> lifecyclePolicy.approve(
                        validated,
                        quote(validated.policyHash()),
                        trustedReviewer(),
                        "Reviewed"
                )
        );
        assertThat(catalogLoads).hasValue(1);
    }

    @ParameterizedTest
    @MethodSource("malformedIfMatchValues")
    void approvalRejectsMalformedIfMatchBeforeCatalogReload(String ifMatch) {
        ContractVersionSnapshot validated = validatedSnapshot();
        catalogLoads.set(0);

        assertRejected(
                RejectionCode.INVALID_IF_MATCH,
                () -> lifecyclePolicy.approve(
                        validated,
                        ifMatch,
                        trustedReviewer(),
                        "Reviewed"
                )
        );
        assertThat(catalogLoads).hasValue(0);
    }

    @Test
    void approvalRejectsWellFormedButStaleIfMatchBeforeCatalogReload() {
        ContractVersionSnapshot validated = validatedSnapshot();
        catalogLoads.set(0);

        assertRejected(
                RejectionCode.STALE_RESOURCE,
                () -> lifecyclePolicy.approve(
                        validated,
                        quote(digest('8')),
                        trustedReviewer(),
                        "Reviewed"
                )
        );
        assertThat(catalogLoads).hasValue(0);
    }

    @ParameterizedTest
    @MethodSource("ineligibleApprovalStates")
    void approvalRejectsEveryStateExceptValidated(VersionState state) {
        ContractVersionSnapshot validated = validatedSnapshot();
        catalogLoads.set(0);
        ContractVersionSnapshot ineligible = snapshot(
                state,
                validated.policy(),
                validated.policyHash(),
                validated.resourceHash(),
                validated.validationProof()
        );

        assertRejected(
                RejectionCode.INVALID_STATE_TRANSITION,
                () -> lifecyclePolicy.approve(
                        ineligible,
                        quote(VALIDATED_RESOURCE_HASH),
                        trustedReviewer(),
                        "Reviewed"
                )
        );
        assertThat(catalogLoads).hasValue(0);
    }

    @ParameterizedTest
    @MethodSource("untrustedReviewers")
    void approvalRejectsUntrustedReviewerContext(
            ReviewerContext reviewer,
            RejectionCode expectedCode
    ) {
        ContractVersionSnapshot validated = validatedSnapshot();
        catalogLoads.set(0);

        assertRejected(
                expectedCode,
                () -> lifecyclePolicy.approve(
                        validated,
                        quote(VALIDATED_RESOURCE_HASH),
                        reviewer,
                        "Reviewed"
                )
        );
        assertThat(catalogLoads).hasValue(0);
    }

    @ParameterizedTest
    @MethodSource("invalidComments")
    void approvalRejectsInvalidComment(String comment) {
        ContractVersionSnapshot validated = validatedSnapshot();
        catalogLoads.set(0);

        assertRejected(
                RejectionCode.INVALID_COMMENT,
                () -> lifecyclePolicy.approve(
                        validated,
                        quote(VALIDATED_RESOURCE_HASH),
                        trustedReviewer(),
                        comment
                )
        );
        assertThat(catalogLoads).hasValue(0);
    }

    @Test
    void approvalRejectsPolicyChangedAfterValidation() {
        ContractVersionSnapshot validated = validatedSnapshot();
        ObjectNode changed = (ObjectNode) validated.policy();
        changed.put("purpose", "CHANGED");
        ContractVersionSnapshot tampered = snapshot(
                VersionState.VALIDATED,
                changed,
                validated.policyHash(),
                validated.resourceHash(),
                validated.validationProof()
        );
        catalogLoads.set(0);

        assertRejected(
                RejectionCode.POLICY_HASH_MISMATCH,
                () -> lifecyclePolicy.approve(
                        tampered,
                        quote(VALIDATED_RESOURCE_HASH),
                        trustedReviewer(),
                        "Reviewed"
                )
        );
        assertThat(catalogLoads).hasValue(0);
    }

    @Test
    void approvalRejectsTamperedValidationProof() {
        ContractVersionSnapshot validated = validatedSnapshot();
        ValidationProof original = validated.validationProof().orElseThrow();
        ValidationProof tampered = new ValidationProof(
                original.identity(),
                original.policyHash(),
                original.basePolicyHash(),
                original.validatedFromResourceHash(),
                original.validatorVersion(),
                original.sourceBinding(),
                original.result(),
                digest('9')
        );
        ContractVersionSnapshot snapshot = snapshot(
                VersionState.VALIDATED,
                validated.policy(),
                validated.policyHash(),
                validated.resourceHash(),
                Optional.of(tampered)
        );
        catalogLoads.set(0);

        assertRejected(
                RejectionCode.VALIDATION_BINDING_MISMATCH,
                () -> lifecyclePolicy.approve(
                        snapshot,
                        quote(VALIDATED_RESOURCE_HASH),
                        trustedReviewer(),
                        "Reviewed"
                )
        );
        assertThat(catalogLoads).hasValue(0);
    }

    @Test
    void approvalRejectsCatalogChangedSinceValidation() {
        ContractVersionSnapshot validated = validatedSnapshot();
        sourceCatalog = source(RELEASE_ID, digest('7'));

        assertRejected(
                RejectionCode.VALIDATION_SOURCE_CHANGED,
                () -> lifecyclePolicy.approve(
                        validated,
                        quote(VALIDATED_RESOURCE_HASH),
                        trustedReviewer(),
                        "Reviewed"
                )
        );
        assertThat(catalogLoads).hasValue(2);
    }

    @Test
    void approvalRejectsIndependentAuthoritativeCatalogDigestDrift() {
        ContractVersionSnapshot validated = validatedSnapshot();
        List<SourceBoundCatalog> changedSources = List.of(
                source(RELEASE_ID, digest('8'), digest('2'), digest('3')),
                source(RELEASE_ID, digest('1'), digest('8'), digest('3')),
                source(RELEASE_ID, digest('1'), digest('2'), digest('8'))
        );
        catalogLoads.set(0);

        for (SourceBoundCatalog changedSource : changedSources) {
            sourceCatalog = changedSource;
            assertRejected(
                    RejectionCode.VALIDATION_SOURCE_CHANGED,
                    () -> lifecyclePolicy.approve(
                            validated,
                            quote(VALIDATED_RESOURCE_HASH),
                            trustedReviewer(),
                            "Reviewed"
                    )
            );
        }
        assertThat(catalogLoads).hasValue(changedSources.size());
    }

    @Test
    void approvalRejectsProofFieldTamperingBeforeCatalogReload() {
        ContractVersionSnapshot validated = validatedSnapshot();
        ValidationProof original = validated.validationProof().orElseThrow();
        VersionIdentity identity = original.identity();
        SourceBinding source = original.sourceBinding();
        List<VersionIdentity> changedIdentities = List.of(
                new VersionIdentity(
                        UUID.fromString("0198f200-0000-7000-8000-000000000296"),
                        identity.workspaceId(), identity.releaseId(),
                        identity.contractKey(), identity.version()
                ),
                new VersionIdentity(
                        identity.versionId(),
                        UUID.fromString("0198f200-0000-7000-8000-000000000295"),
                        identity.releaseId(), identity.contractKey(), identity.version()
                ),
                new VersionIdentity(
                        identity.versionId(), identity.workspaceId(),
                        UUID.fromString("0198f200-0000-7000-8000-000000000294"),
                        identity.contractKey(), identity.version()
                ),
                new VersionIdentity(
                        identity.versionId(), identity.workspaceId(), identity.releaseId(),
                        "another-contract", identity.version()
                ),
                new VersionIdentity(
                        identity.versionId(), identity.workspaceId(), identity.releaseId(),
                        identity.contractKey(), 2
                )
        );
        List<SourceBinding> changedSourceBindings = List.of(
                new SourceBinding(
                        UUID.fromString("0198f200-0000-7000-8000-000000000293"),
                        source.manifestSchemaVersion(), source.agentArtifactFingerprint(),
                        source.releaseFingerprint(), source.serverToolCatalogHash()
                ),
                new SourceBinding(
                        source.releaseId(), "1.2", source.agentArtifactFingerprint(),
                        source.releaseFingerprint(), source.serverToolCatalogHash()
                ),
                new SourceBinding(
                        source.releaseId(), source.manifestSchemaVersion(), digest('8'),
                        source.releaseFingerprint(), source.serverToolCatalogHash()
                ),
                new SourceBinding(
                        source.releaseId(), source.manifestSchemaVersion(),
                        source.agentArtifactFingerprint(), digest('8'),
                        source.serverToolCatalogHash()
                ),
                new SourceBinding(
                        source.releaseId(), source.manifestSchemaVersion(),
                        source.agentArtifactFingerprint(), source.releaseFingerprint(),
                        digest('8')
                )
        );
        List<ValidationProof> tamperedProofs = new java.util.ArrayList<>();
        changedIdentities.forEach(changed -> tamperedProofs.add(tamperedProof(
                original, changed, original.policyHash(), original.basePolicyHash(),
                original.validatedFromResourceHash(), original.validatorVersion(),
                original.sourceBinding(), original.result()
        )));
        changedSourceBindings.forEach(changed -> tamperedProofs.add(tamperedProof(
                original, original.identity(), original.policyHash(),
                original.basePolicyHash(), original.validatedFromResourceHash(),
                original.validatorVersion(), changed, original.result()
        )));
        tamperedProofs.add(tamperedProof(
                original, original.identity(), digest('8'), original.basePolicyHash(),
                original.validatedFromResourceHash(), original.validatorVersion(),
                original.sourceBinding(), original.result()
        ));
        tamperedProofs.add(tamperedProof(
                original, original.identity(), original.policyHash(),
                Optional.of(digest('8')), original.validatedFromResourceHash(),
                original.validatorVersion(), original.sourceBinding(), original.result()
        ));
        tamperedProofs.add(tamperedProof(
                original, original.identity(), original.policyHash(),
                original.basePolicyHash(), digest('8'), original.validatorVersion(),
                original.sourceBinding(), original.result()
        ));
        tamperedProofs.add(tamperedProof(
                original, original.identity(), original.policyHash(),
                original.basePolicyHash(), original.validatedFromResourceHash(), "9.9",
                original.sourceBinding(), original.result()
        ));
        tamperedProofs.add(tamperedProof(
                original, original.identity(), original.policyHash(),
                original.basePolicyHash(), original.validatedFromResourceHash(),
                original.validatorVersion(), original.sourceBinding(),
                ValidationResult.fromIssues(List.of(new Issue(
                        "/workflow",
                        "TAMPERED_RESULT",
                        IssueSeverity.WARNING,
                        "Tampered result"
                )))
        ));
        catalogLoads.set(0);

        for (ValidationProof proof : tamperedProofs) {
            ContractVersionSnapshot snapshot = snapshot(
                    VersionState.VALIDATED,
                    validated.policy(),
                    validated.policyHash(),
                    validated.resourceHash(),
                    Optional.of(proof)
            );
            assertRejected(
                    RejectionCode.VALIDATION_BINDING_MISMATCH,
                    () -> lifecyclePolicy.approve(
                            snapshot,
                            quote(VALIDATED_RESOURCE_HASH),
                            trustedReviewer(),
                            "Reviewed"
                    )
            );
        }
        assertThat(catalogLoads).hasValue(0);
    }

    @Test
    void approvalRejectsNullSnapshotAndReviewerBeforeCatalogLoad() {
        ContractVersionSnapshot validated = validatedSnapshot();
        catalogLoads.set(0);

        assertRejected(
                RejectionCode.INVALID_SNAPSHOT,
                () -> lifecyclePolicy.approve(
                        null,
                        quote(VALIDATED_RESOURCE_HASH),
                        trustedReviewer(),
                        "Reviewed"
                )
        );
        assertRejected(
                RejectionCode.REVIEWER_CONTEXT_REQUIRED,
                () -> lifecyclePolicy.approve(
                        validated,
                        quote(VALIDATED_RESOURCE_HASH),
                        null,
                        "Reviewed"
                )
        );
        assertThat(catalogLoads).hasValue(0);
    }

    @Test
    void approvalFailsClosedWhenCurrentCatalogIsUnavailableOrThrows() {
        ContractVersionSnapshot validated = validatedSnapshot();
        AtomicInteger attempts = new AtomicInteger();
        SafetyContractLifecyclePolicy nullCatalog = policy(
                (releaseId, actorId) -> {
                    attempts.incrementAndGet();
                    return null;
                },
                canonicalizer,
                semanticValidator
        );
        SafetyContractLifecyclePolicy throwingCatalog = policy(
                (releaseId, actorId) -> {
                    attempts.incrementAndGet();
                    throw new IllegalStateException("source unavailable");
                },
                canonicalizer,
                semanticValidator
        );

        assertRejected(
                RejectionCode.CATALOG_SOURCE_UNAVAILABLE,
                () -> nullCatalog.approve(
                        validated,
                        quote(VALIDATED_RESOURCE_HASH),
                        trustedReviewer(),
                        "Reviewed"
                )
        );
        assertRejected(
                RejectionCode.CATALOG_SOURCE_FAILURE,
                () -> throwingCatalog.approve(
                        validated,
                        quote(VALIDATED_RESOURCE_HASH),
                        trustedReviewer(),
                        "Reviewed"
                )
        );
        assertThat(attempts).hasValue(2);
    }

    @Test
    void approvalFailsClosedWhenCanonicalPolicyHashCannotBeRecomputed() {
        ContractVersionSnapshot validated = validatedSnapshot();
        SafetyContractCanonicalizer throwingCanonicalizer =
                new SafetyContractCanonicalizer(
                        schemaValidator,
                        canonicalJsonService,
                        digestService
                ) {
                    @Override
                    public CanonicalPolicy canonicalizeAndHash(
                            tools.jackson.databind.JsonNode ignored
                    ) {
                        throw new IllegalStateException("hash service failed");
                    }
                };
        SafetyContractLifecyclePolicy failingPolicy = policy(
                (releaseId, actorId) -> {
                    throw new AssertionError("catalog must not be loaded");
                },
                throwingCanonicalizer,
                semanticValidator
        );

        assertRejected(
                RejectionCode.POLICY_CANONICALIZATION_FAILURE,
                () -> failingPolicy.approve(
                        validated,
                        quote(VALIDATED_RESOURCE_HASH),
                        trustedReviewer(),
                        "Reviewed"
                )
        );
    }

    @Test
    void snapshotsAndValidationEvidenceAreDeeplyImmutable() {
        ObjectNode mutable = contract.deepCopy();
        ContractVersionSnapshot candidate = candidate(mutable);
        mutable.put("purpose", "MUTATED_AFTER_SNAPSHOT");
        ((ObjectNode) candidate.policy()).put("purpose", "MUTATED_ACCESSOR_COPY");

        ValidationDecision decision = lifecyclePolicy.validate(
                candidate,
                VALIDATOR_ACTOR
        );

        assertThat(candidate.policy().path("purpose").asString())
                .isEqualTo("LOAN_DOCUMENT_COMPLETENESS_REVIEW");
        assertThat(decision.transitionCommand()).isPresent();
        assertThatThrownBy(() -> decision.validationProof().result().issues().add(
                new Issue("/", "MUTATION", IssueSeverity.WARNING, "mutation")
        )).isInstanceOf(UnsupportedOperationException.class);
    }

    @ParameterizedTest
    @EnumSource(value = VersionState.class, names = {"CANDIDATE", "VALIDATED"})
    void rejectionReturnsExactCasPreconditionsWithoutChangingSnapshot(VersionState state) {
        ContractVersionSnapshot original = state == VersionState.VALIDATED
                ? validatedSnapshot() : candidate(contract);
        ReviewerContext reviewer = trustedReviewer();
        catalogLoads.set(0);

        RejectionTransitionCommand command = lifecyclePolicy.reject(
                original, quote(original.resourceHash()), reviewer, "Revise the candidate"
        );

        assertThat(command.identity()).isEqualTo(original.identity());
        assertThat(command.expectedState()).isEqualTo(state);
        assertThat(command.targetState()).isEqualTo(VersionState.REJECTED);
        assertThat(command.expectedResourceHash()).isEqualTo(original.resourceHash());
        assertThat(command.policyHash()).isEqualTo(original.policyHash());
        assertThat(command.basePolicyHash()).isEqualTo(original.basePolicyHash());
        assertThat(command.reviewer()).isEqualTo(reviewer);
        assertThat(command.comment()).isEqualTo("Revise the candidate");
        assertThat(original.state()).isEqualTo(state);
        assertThat(original.policy()).isEqualTo(contract);
        assertThat(original.validationProof().isPresent())
                .isEqualTo(state == VersionState.VALIDATED);
        ((ObjectNode) original.policy()).put("purpose", "MUTATED_COPY");
        assertThat(original.policy()).isEqualTo(contract);
        assertThat(lifecyclePolicy.reject(
                original, quote(original.resourceHash()), reviewer, "Revise the candidate"
        )).isEqualTo(command);
        assertThat(catalogLoads).hasValue(0);
    }

    @ParameterizedTest
    @EnumSource(value = VersionState.class, names = {"APPROVED", "REJECTED", "SUPERSEDED"})
    void rejectionCannotChangeTerminalVersions(VersionState state) {
        ContractVersionSnapshot original = snapshot(
                state, contract, policyHash(contract), CANDIDATE_RESOURCE_HASH, Optional.empty()
        );

        assertRejected(RejectionCode.INVALID_STATE_TRANSITION, () -> lifecyclePolicy.reject(
                original, quote(original.resourceHash()), trustedReviewer(), "Rejected"
        ));
        assertThat(catalogLoads).hasValue(0);
    }

    @ParameterizedTest
    @EnumSource(value = VersionState.class, names = {"CANDIDATE", "VALIDATED"})
    void rejectionDiscardsInvalidObjectsWithoutCatalogOrValidationCalls(VersionState state) {
        SafetyContractCanonicalizer unusedCanonicalizer = mock(SafetyContractCanonicalizer.class);
        SafetyContractSemanticValidator unusedValidator = mock(SafetyContractSemanticValidator.class);
        SafetyContractLifecyclePolicy rejectionOnly = policy(
                (releaseId, actorId) -> {
                    throw new AssertionError("Rejection must not require catalog availability");
                }, unusedCanonicalizer, unusedValidator
        );
        ObjectNode schemaInvalid = contract.deepCopy().put("unknownPolicy", true);
        ObjectNode semanticInvalid = contract.deepCopy();
        ((ArrayNode) semanticInvalid.path("allowedTools")).removeAll();

        for (ObjectNode invalid : List.of(schemaInvalid, semanticInvalid)) {
            ContractVersionSnapshot original = new ContractVersionSnapshot(
                    defaultIdentity(), state, invalid, digest('9'), CANDIDATE_RESOURCE_HASH,
                    Optional.empty(), Optional.empty()
            );

            RejectionTransitionCommand command = rejectionOnly.reject(
                    original, quote(CANDIDATE_RESOURCE_HASH), trustedReviewer(), "Invalid policy"
            );

            assertThat(command.targetState()).isEqualTo(VersionState.REJECTED);
            assertThat(command.expectedState()).isEqualTo(state);
            assertThat(command.policyHash()).isEqualTo(digest('9'));
            assertThat(command.basePolicyHash()).isEmpty();
            assertThat(original.policy()).isEqualTo(invalid);
            assertThat(original.validationProof()).isEmpty();
        }
        verifyNoMoreInteractions(unusedCanonicalizer, unusedValidator);
    }

    @ParameterizedTest
    @MethodSource("malformedIfMatchValues")
    void rejectionRequiresOneStrongResourceIfMatch(String ifMatch) {
        assertRejected(RejectionCode.INVALID_IF_MATCH, () -> lifecyclePolicy.reject(
                candidate(contract), ifMatch, trustedReviewer(), "Rejected"
        ));
        assertThat(catalogLoads).hasValue(0);
    }

    @Test
    void rejectionDoesNotAcceptStaleHashOrPolicyHashAsResourceTag() {
        ContractVersionSnapshot original = candidate(contract);
        for (String stale : List.of(digest('8'), original.policyHash())) {
            assertRejected(RejectionCode.STALE_RESOURCE, () -> lifecyclePolicy.reject(
                    original, quote(stale), trustedReviewer(), "Rejected"
            ));
        }
        assertThat(catalogLoads).hasValue(0);
    }

    @ParameterizedTest
    @MethodSource("untrustedReviewers")
    void rejectionRequiresTrustedReviewer(ReviewerContext reviewer, RejectionCode expectedCode) {
        assertRejected(expectedCode, () -> lifecyclePolicy.reject(
                candidate(contract), quote(CANDIDATE_RESOURCE_HASH), reviewer, "Rejected"
        ));
        assertThat(catalogLoads).hasValue(0);
    }

    @Test
    void rejectionRequiresReviewerContext() {
        assertRejected(RejectionCode.REVIEWER_CONTEXT_REQUIRED, () -> lifecyclePolicy.reject(
                candidate(contract), quote(CANDIDATE_RESOURCE_HASH), null, "Rejected"
        ));
        assertThat(catalogLoads).hasValue(0);
    }

    @ParameterizedTest
    @MethodSource("invalidComments")
    void rejectionRequiresValidComment(String comment) {
        assertRejected(RejectionCode.INVALID_COMMENT, () -> lifecyclePolicy.reject(
                candidate(contract), quote(CANDIDATE_RESOURCE_HASH), trustedReviewer(), comment
        ));
        assertThat(catalogLoads).hasValue(0);
    }

    @Test
    void rejectionStillRequiresValidSnapshotEnvelope() {
        List<ContractVersionSnapshot> invalidSnapshots = Stream.of(
                (ContractVersionSnapshot) null,
                snapshot(VersionState.CANDIDATE, null, digest('9'),
                        CANDIDATE_RESOURCE_HASH, Optional.empty()),
                snapshot(VersionState.CANDIDATE, objectMapper.createArrayNode(), digest('9'),
                        CANDIDATE_RESOURCE_HASH, Optional.empty()),
                snapshot(VersionState.CANDIDATE, contract, "malformed",
                        CANDIDATE_RESOURCE_HASH, Optional.empty()),
                snapshot(VersionState.CANDIDATE, contract, digest('9'),
                        "malformed", Optional.empty()),
                snapshot(null, contract, digest('9'), CANDIDATE_RESOURCE_HASH, Optional.empty()),
                snapshot(null, VersionState.CANDIDATE, contract, digest('9'),
                        CANDIDATE_RESOURCE_HASH, Optional.empty()),
                new ContractVersionSnapshot(defaultIdentity(), VersionState.CANDIDATE,
                        contract, digest('9'), CANDIDATE_RESOURCE_HASH, null, Optional.empty()),
                new ContractVersionSnapshot(defaultIdentity(), VersionState.CANDIDATE,
                        contract, digest('9'), CANDIDATE_RESOURCE_HASH, Optional.empty(), null)
        ).toList();

        for (ContractVersionSnapshot invalid : invalidSnapshots) {
            assertRejected(RejectionCode.INVALID_SNAPSHOT, () -> lifecyclePolicy.reject(
                    invalid, quote(CANDIDATE_RESOURCE_HASH), trustedReviewer(), "Rejected"
            ));
        }
        assertThat(catalogLoads).hasValue(0);
    }

    private SafetyContractLifecyclePolicy policy(
            SafetyContractSemanticValidator validator
    ) {
        return policy(
                (releaseId, actorId) -> {
                    catalogLoads.incrementAndGet();
                    return sourceCatalog;
                },
                canonicalizer,
                validator
        );
    }

    private SafetyContractLifecyclePolicy policy(
            CanonicalJsonService selectedCanonicalJsonService,
            DigestService selectedDigestService,
            SafetyContractSemanticValidator validator
    ) {
        return new SafetyContractLifecyclePolicy(
                (releaseId, actorId) -> {
                    catalogLoads.incrementAndGet();
                    return sourceCatalog;
                },
                canonicalizer,
                validator,
                selectedCanonicalJsonService,
                selectedDigestService,
                objectMapper
        );
    }

    private SafetyContractSemanticValidator warningValidator(List<Issue> issues) {
        return new SafetyContractSemanticValidator(schemaValidator) {
            @Override
            public ValidationResult validate(
                    tools.jackson.databind.JsonNode ignoredContract,
                    ContractValidationCatalog ignoredCatalog
            ) {
                return ValidationResult.fromIssues(issues);
            }
        };
    }

    private ValidationProof tamperedProof(
            ValidationProof original,
            VersionIdentity identity,
            String policyHash,
            Optional<String> basePolicyHash,
            String validatedFromResourceHash,
            String validatorVersion,
            SourceBinding sourceBinding,
            ValidationResult result
    ) {
        return new ValidationProof(
                identity,
                policyHash,
                basePolicyHash,
                validatedFromResourceHash,
                validatorVersion,
                sourceBinding,
                result,
                original.validationHash()
        );
    }

    private SafetyContractLifecyclePolicy policy(
            SafetyContractLifecyclePolicy.VerifiedCatalogLoader loader,
            SafetyContractCanonicalizer selectedCanonicalizer,
            SafetyContractSemanticValidator validator
    ) {
        return new SafetyContractLifecyclePolicy(
                loader,
                selectedCanonicalizer,
                validator,
                canonicalJsonService,
                digestService,
                objectMapper
        );
    }

    private ContractVersionSnapshot candidate(ObjectNode policy) {
        return snapshot(
                VersionState.CANDIDATE,
                policy,
                policyHash(policy),
                CANDIDATE_RESOURCE_HASH,
                Optional.empty()
        );
    }

    private ContractVersionSnapshot validatedSnapshot() {
        return validatedSnapshot(lifecyclePolicy, contract);
    }

    private ContractVersionSnapshot validatedSnapshot(
            SafetyContractLifecyclePolicy selectedPolicy,
            ObjectNode selectedContract
    ) {
        ContractVersionSnapshot candidate = candidate(selectedContract);
        ValidationProof proof = selectedPolicy.validate(
                candidate,
                VALIDATOR_ACTOR
        ).transitionCommand().orElseThrow().validationProof();
        return snapshot(
                VersionState.VALIDATED,
                selectedContract,
                candidate.policyHash(),
                VALIDATED_RESOURCE_HASH,
                Optional.of(proof)
        );
    }

    private ContractVersionSnapshot snapshot(
            VersionState state,
            tools.jackson.databind.JsonNode policy,
            String storedPolicyHash,
            String resourceHash,
            Optional<ValidationProof> proof
    ) {
        return snapshot(
                defaultIdentity(),
                state,
                policy,
                storedPolicyHash,
                resourceHash,
                proof
        );
    }

    private VersionIdentity defaultIdentity() {
        return new VersionIdentity(
                VERSION_ID,
                WORKSPACE_ID,
                RELEASE_ID,
                CONTRACT_KEY,
                1
        );
    }

    private ContractVersionSnapshot snapshot(
            VersionIdentity identity,
            VersionState state,
            tools.jackson.databind.JsonNode policy,
            String storedPolicyHash,
            String resourceHash,
            Optional<ValidationProof> proof
    ) {
        return new ContractVersionSnapshot(
                identity,
                state,
                policy,
                storedPolicyHash,
                resourceHash,
                Optional.of(BASE_POLICY_HASH),
                proof
        );
    }

    private ReviewerContext trustedReviewer() {
        return new ReviewerContext(
                WORKSPACE_ID,
                "reviewer:security",
                "AI_SECURITY_REVIEWER",
                "session-123",
                true,
                true,
                true
        );
    }

    private SourceBoundCatalog source(UUID releaseId, String releaseFingerprint) {
        return source(releaseId, digest('1'), releaseFingerprint, digest('3'));
    }

    private SourceBoundCatalog source(
            UUID releaseId,
            String agentArtifactFingerprint,
            String releaseFingerprint,
            String serverToolCatalogHash
    ) {
        return new SourceBoundCatalog(
                releaseId,
                "1.1",
                agentArtifactFingerprint,
                releaseFingerprint,
                serverToolCatalogHash,
                new ContractValidationCatalog(
                        List.of(
                                new EnabledTool("CASE_CONTEXT_READ", List.of("caseId")),
                                new EnabledTool("CUSTOMER_DATA_READ", List.of(
                                        "accountNumber",
                                        "employmentStatus",
                                        "incomeBand"
                                )),
                                new EnabledTool("DOCUMENT_READER", List.of("documents")),
                                new EnabledTool("LOAN_POLICY_SEARCH", List.of("policies")),
                                new EnabledTool("REVIEW_NOTE_WRITE", List.of("status"))
                        ),
                        List.of("LOAN_DECISION_UPDATE")
                )
        );
    }

    private ObjectNode loadContract() throws Exception {
        try (InputStream input = getClass().getResourceAsStream(
                "/fixtures/loan-review-safety-contract.json"
        )) {
            if (input == null) {
                throw new IllegalStateException("Safety Contract fixture is missing");
            }
            return (ObjectNode) objectMapper.readTree(input);
        }
    }

    private String policyHash(tools.jackson.databind.JsonNode policy) {
        return canonicalizer.canonicalizeAndHash(policy).policyHash();
    }

    private void assertRejected(
            RejectionCode code,
            org.assertj.core.api.ThrowableAssert.ThrowingCallable invocation
    ) {
        assertThatThrownBy(invocation)
                .isInstanceOfSatisfying(
                        LifecyclePolicyException.class,
                        exception -> assertThat(exception.code()).isEqualTo(code)
                );
    }

    private static Stream<VersionState> nonCandidateStates() {
        return Stream.of(
                VersionState.VALIDATED,
                VersionState.APPROVED,
                VersionState.REJECTED,
                VersionState.SUPERSEDED
        );
    }

    private static Stream<VersionState> ineligibleApprovalStates() {
        return Stream.of(
                VersionState.CANDIDATE,
                VersionState.APPROVED,
                VersionState.REJECTED,
                VersionState.SUPERSEDED
        );
    }

    private static Stream<String> malformedIfMatchValues() {
        return Stream.of(
                (String) null,
                "",
                " ",
                VALIDATED_RESOURCE_HASH,
                "W/" + quote(VALIDATED_RESOURCE_HASH),
                "\"*\"",
                quote(VALIDATED_RESOURCE_HASH) + "," + quote(digest('8')),
                " \"" + VALIDATED_RESOURCE_HASH + "\""
        );
    }

    private static Stream<Arguments> untrustedReviewers() {
        return Stream.of(
                Arguments.of(new ReviewerContext(
                        null, "reviewer:security", "AI_SECURITY_REVIEWER", "session-123",
                        true, true, true
                ), RejectionCode.REVIEWER_WORKSPACE_MISMATCH),
                Arguments.of(new ReviewerContext(
                        WORKSPACE_ID, null, "AI_SECURITY_REVIEWER", "session-123",
                        true, true, true
                ), RejectionCode.INVALID_REVIEWER_IDENTITY),
                Arguments.of(new ReviewerContext(
                        WORKSPACE_ID, "reviewer:security", null, "session-123",
                        true, true, true
                ), RejectionCode.REVIEWER_ROLE_REQUIRED),
                Arguments.of(new ReviewerContext(
                        WORKSPACE_ID, "reviewer:security", "AI_SECURITY_REVIEWER", null,
                        true, true, true
                ), RejectionCode.INVALID_REVIEWER_SESSION),
                Arguments.of(new ReviewerContext(
                        WORKSPACE_ID, "reviewer:security", "AI_SECURITY_REVIEWER", "session-123",
                        false, true, true
                ), RejectionCode.REVIEWER_AUTHENTICATION_REQUIRED),
                Arguments.of(new ReviewerContext(
                        WORKSPACE_ID, "reviewer:security", "AI_SECURITY_REVIEWER", "session-123",
                        true, false, true
                ), RejectionCode.REVIEWER_CSRF_REQUIRED),
                Arguments.of(new ReviewerContext(
                        WORKSPACE_ID, "reviewer:security", "AGENT_DEVELOPER", "session-123",
                        true, true, true
                ), RejectionCode.REVIEWER_ROLE_REQUIRED),
                Arguments.of(new ReviewerContext(
                        WORKSPACE_ID, "reviewer:security", "DEMO_VIEWER", "session-123",
                        true, true, true
                ), RejectionCode.REVIEWER_ROLE_REQUIRED),
                Arguments.of(new ReviewerContext(
                        UUID.fromString("0198f200-0000-7000-8000-000000000298"),
                        "reviewer:security", "AI_SECURITY_REVIEWER", "session-123",
                        true, true, true
                ), RejectionCode.REVIEWER_WORKSPACE_MISMATCH),
                Arguments.of(new ReviewerContext(
                        WORKSPACE_ID, "\u2003", "AI_SECURITY_REVIEWER", "session-123",
                        true, true, true
                ), RejectionCode.INVALID_REVIEWER_IDENTITY),
                Arguments.of(new ReviewerContext(
                        WORKSPACE_ID, "reviewer:security", "AI_SECURITY_REVIEWER", "\u2003",
                        true, true, true
                ), RejectionCode.INVALID_REVIEWER_SESSION)
        );
    }

    private static Stream<String> invalidComments() {
        return Stream.of((String) null, "", "\u2003", "x".repeat(1001));
    }

    private static String quote(String resourceHash) {
        return '"' + resourceHash + '"';
    }

    private static String digest(char value) {
        return "sha256:" + String.valueOf(value).repeat(64);
    }
}
