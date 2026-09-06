package com.finsecseal.contract;

import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.SourceBoundCatalog;
import com.finsecseal.contract.SafetyContractCanonicalizer.CanonicalPolicy;
import com.finsecseal.contract.SafetyContractCanonicalizer.InvalidSafetyContractException;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ContractVersionSnapshot;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.SourceBinding;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionIdentity;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.AcceptedProposal;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.FindingSourceFacts;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.Issue;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.ProposalDecision;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.ProposedPatch;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.Status;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationStatus;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;
import tools.jackson.databind.JsonNode;

/**
 * Judges a generated typed patch without calling a model, querying findings, storing versions,
 * approving a policy or mutating runtime state. The caller supplies owner-authorized sources.
 */
public final class SafetyContractPatchProposalPolicy {

    private static final Pattern DIGEST = Pattern.compile("sha256:[0-9a-f]{64}");
    private final SafetyContractCanonicalizer canonicalizer;
    private final SafetyContractNarrowingValidator narrowingValidator;
    private final SafetyContractSemanticValidator semanticValidator;

    public SafetyContractPatchProposalPolicy(
            SafetyContractCanonicalizer canonicalizer,
            SafetyContractNarrowingValidator narrowingValidator,
            SafetyContractSemanticValidator semanticValidator
    ) {
        this.canonicalizer = Objects.requireNonNull(canonicalizer, "canonicalizer");
        this.narrowingValidator = Objects.requireNonNull(narrowingValidator, "narrowingValidator");
        this.semanticValidator = Objects.requireNonNull(semanticValidator, "semanticValidator");
    }

    public ProposalDecision evaluate(
            FindingSourceFacts source,
            ContractVersionSnapshot base,
            ProposedPatch candidate,
            SourceBoundCatalog catalog
    ) {
        if (!eligible(source)) {
            return invalid("SOURCE_INELIGIBLE", "Eligible owner-supplied finding source is required");
        }
        if (!bound(source, base, catalog)) {
            return invalid("SOURCE_BINDING_INVALID", "Source, base version and catalog must share scope");
        }
        if (candidate == null || candidate.operations() == null) {
            return invalid("CANDIDATE_INVALID", "Candidate and typed operations are required");
        }
        if (!hasText(candidate.rootCause()) || !hasText(candidate.normalWorkflowImpact())
                || !hasText(candidate.rollback())) {
            return invalid("CANDIDATE_EXPLANATION_REQUIRED", "Root cause, impact and rollback are required");
        }

        try {
            JsonNode basePolicy = base.policy();
            CanonicalPolicy canonicalBase = canonicalizer.canonicalizeAndHash(basePolicy);
            if (!canonicalBase.policyHash().equals(base.policyHash())
                    || !identityMatches(base.identity(), basePolicy)) {
                return invalid("BASE_POLICY_BINDING_INVALID", "Base policy must match its stored hash and identity");
            }

            JsonNode resultPolicy = candidate.resultPolicy();
            Optional<SafetyContractNarrowingValidator.ValidationResult> narrowing = Optional.empty();
            CanonicalPolicy canonicalResult;
            Status acceptedStatus;
            List<SafetyContractPatchOperation> operations;
            if (candidate.operations().isEmpty()) {
                canonicalResult = canonicalizer.canonicalizeAndHash(resultPolicy);
                if (!canonicalBase.canonicalJson().equals(canonicalResult.canonicalJson())) {
                    return invalid("EMPTY_PATCH_CHANGED_POLICY", "No-change suggestions must preserve the exact canonical policy");
                }
                operations = List.of();
                acceptedStatus = Status.NO_CHANGE_NEEDED;
            } else {
                SafetyContractNarrowingValidator.ValidationResult patch = Objects.requireNonNull(
                        narrowingValidator.validate(basePolicy, resultPolicy, candidate.operations()),
                        "narrowing result"
                );
                narrowing = Optional.of(patch);
                if (!patch.valid()) {
                    return invalid("PATCH_INVALID", "Typed patch must describe an exact narrowing change",
                            narrowing, Optional.empty());
                }
                canonicalResult = canonicalizer.canonicalizeAndHash(resultPolicy);
                operations = patch.validatedPatch().orElseThrow().operations();
                acceptedStatus = Status.PROPOSED;
            }

            SafetyContractSemanticValidator.ValidationResult semantic = Objects.requireNonNull(
                    semanticValidator.validate(resultPolicy, catalog.semanticCatalog()), "semantic result"
            );
            if (semantic.status() == ValidationStatus.INVALID) {
                return invalid("RESULT_SEMANTIC_INVALID", "Result must preserve the financial workflow and permission bounds",
                        narrowing, Optional.of(semantic));
            }
            AcceptedProposal accepted = new AcceptedProposal(
                    source, base.identity(), canonicalBase.policyHash(), canonicalResult, operations,
                    candidate.rootCause(), candidate.normalWorkflowImpact(), candidate.rollback(),
                    new SourceBinding(catalog.releaseId(), catalog.manifestSchemaVersion(),
                            catalog.agentArtifactFingerprint(), catalog.releaseFingerprint(), catalog.serverToolCatalogHash())
            );
            return new ProposalDecision(acceptedStatus, Optional.of(accepted), List.of(), narrowing, Optional.of(semantic));
        } catch (InvalidSafetyContractException exception) {
            List<Issue> issues = new ArrayList<>();
            issues.add(new Issue("/", "STRUCTURAL_POLICY_INVALID",
                    "Proposal snapshots must satisfy the closed Safety Contract schema"));
            exception.issues().forEach(issue -> issues.add(
                    new Issue(issue.jsonPointer(), issue.code(), issue.message())));
            return new ProposalDecision(Status.INVALID, Optional.empty(), issues, Optional.empty(), Optional.empty());
        } catch (RuntimeException exception) {
            throw new IllegalStateException("Deterministic patch proposal evaluation failed", exception);
        }
    }

    private static boolean eligible(FindingSourceFacts source) {
        return source != null && source.findingId() != null && source.workspaceId() != null
                && source.releaseId() != null
                && ("OPEN".equals(source.findingStatus()) || "TRIAGED".equals(source.findingStatus()))
                && ("SEED".equals(source.sourcePartition()) || "MUTATION".equals(source.sourcePartition()))
                && Boolean.FALSE.equals(source.hiddenFromPatchGenerator())
                && isDigest(source.evidenceDigest()) && hasText(source.violatedInvariant());
    }

    private static boolean bound(FindingSourceFacts source, ContractVersionSnapshot base, SourceBoundCatalog catalog) {
        if (base == null || base.identity() == null || catalog == null || !isDigest(base.policyHash())) {
            return false;
        }
        VersionIdentity identity = base.identity();
        return identity.versionId() != null && identity.version() > 0 && hasText(identity.contractKey())
                && source.workspaceId().equals(identity.workspaceId())
                && source.releaseId().equals(identity.releaseId()) && source.releaseId().equals(catalog.releaseId());
    }

    private static boolean identityMatches(VersionIdentity identity, JsonNode policy) {
        return policy.path("contractId").isString()
                && identity.contractKey().equals(policy.path("contractId").stringValue())
                && policy.path("version").isIntegralNumber()
                && BigInteger.valueOf(identity.version()).equals(policy.path("version").bigIntegerValue());
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private static boolean isDigest(String value) {
        return value != null && DIGEST.matcher(value).matches();
    }

    private static ProposalDecision invalid(String code, String message) {
        return invalid(code, message, Optional.empty(), Optional.empty());
    }

    private static ProposalDecision invalid(String code, String message,
            Optional<SafetyContractNarrowingValidator.ValidationResult> narrowing,
            Optional<SafetyContractSemanticValidator.ValidationResult> semantic) {
        return new ProposalDecision(Status.INVALID, Optional.empty(), List.of(new Issue("/", code, message)), narrowing, semantic);
    }
}
