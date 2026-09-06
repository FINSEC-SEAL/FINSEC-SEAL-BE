package com.finsecseal.contract;

import com.finsecseal.contract.SafetyContractCanonicalizer.CanonicalPolicy;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.SourceBinding;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionIdentity;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

/** Internal proposal judgment inputs and evidence; none of these records authorizes storage. */
public final class SafetyContractPatchProposalFacts {

    private SafetyContractPatchProposalFacts() {
    }

    /**
     * Must be supplied by A/D after source authorization and before forbidden evidence is read.
     * Local eligibility checks do not establish held-out repository isolation or provenance.
     */
    public record FindingSourceFacts(
            UUID findingId,
            UUID workspaceId,
            UUID releaseId,
            String findingStatus,
            String sourcePartition,
            Boolean hiddenFromPatchGenerator,
            String evidenceDigest,
            String violatedInvariant
    ) {
    }

    /** Untrusted candidate content; provider metadata stays in the owner's generation envelope. */
    public record ProposedPatch(
            JsonNode resultPolicy,
            List<SafetyContractPatchOperation> operations,
            String rootCause,
            String normalWorkflowImpact,
            String rollback
    ) {
        public ProposedPatch {
            resultPolicy = resultPolicy == null ? null : resultPolicy.deepCopy();
            operations = operations == null ? null
                    : Collections.unmodifiableList(new ArrayList<>(operations));
        }

        @Override
        public JsonNode resultPolicy() {
            return resultPolicy == null ? null : resultPolicy.deepCopy();
        }
    }

    public enum Status {
        PROPOSED,
        NO_CHANGE_NEEDED,
        INVALID
    }

    public record Issue(String jsonPointer, String code, String message) {
        public Issue {
            Objects.requireNonNull(jsonPointer, "jsonPointer");
            Objects.requireNonNull(code, "code");
            Objects.requireNonNull(message, "message");
        }
    }

    public record AcceptedProposal(
            FindingSourceFacts source,
            VersionIdentity baseIdentity,
            String basePolicyHash,
            CanonicalPolicy resultPolicy,
            List<SafetyContractPatchOperation> operations,
            String rootCause,
            String normalWorkflowImpact,
            String rollback,
            SourceBinding catalogBinding
    ) {
        public AcceptedProposal {
            Objects.requireNonNull(source, "source");
            Objects.requireNonNull(baseIdentity, "baseIdentity");
            Objects.requireNonNull(basePolicyHash, "basePolicyHash");
            Objects.requireNonNull(resultPolicy, "resultPolicy");
            operations = List.copyOf(operations);
            Objects.requireNonNull(rootCause, "rootCause");
            Objects.requireNonNull(normalWorkflowImpact, "normalWorkflowImpact");
            Objects.requireNonNull(rollback, "rollback");
            Objects.requireNonNull(catalogBinding, "catalogBinding");
        }
    }

    public record ProposalDecision(
            Status status,
            Optional<AcceptedProposal> acceptedProposal,
            List<Issue> issues,
            Optional<SafetyContractNarrowingValidator.ValidationResult> narrowing,
            Optional<SafetyContractSemanticValidator.ValidationResult> semantic
    ) {
        public ProposalDecision {
            Objects.requireNonNull(status, "status");
            Objects.requireNonNull(acceptedProposal, "acceptedProposal");
            issues = List.copyOf(issues);
            Objects.requireNonNull(narrowing, "narrowing");
            Objects.requireNonNull(semantic, "semantic");
            if ((status == Status.INVALID) == acceptedProposal.isPresent()
                    || (status == Status.INVALID) == issues.isEmpty()) {
                throw new IllegalArgumentException("proposal status and evidence must agree");
            }
            if (acceptedProposal.isPresent() && (semantic.isEmpty()
                    || semantic.orElseThrow().status() == SafetyContractSemanticValidator.ValidationStatus.INVALID)) {
                throw new IllegalArgumentException("accepted proposals require eligible semantic evidence");
            }
            if (status == Status.PROPOSED && (narrowing.isEmpty() || !narrowing.orElseThrow().valid())) {
                throw new IllegalArgumentException("proposed changes require narrowing evidence");
            }
            if (status == Status.NO_CHANGE_NEEDED && (narrowing.isPresent()
                    || !acceptedProposal.orElseThrow().operations().isEmpty()
                    || !acceptedProposal.orElseThrow().basePolicyHash()
                    .equals(acceptedProposal.orElseThrow().resultPolicy().policyHash()))) {
                throw new IllegalArgumentException("no-change evidence must preserve the base policy");
            }
        }
    }
}
