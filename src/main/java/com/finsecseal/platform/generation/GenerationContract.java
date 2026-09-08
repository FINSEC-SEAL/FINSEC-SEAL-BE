package com.finsecseal.platform.generation;

import com.finsecseal.contract.SafetyContractLifecyclePolicy.*;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.*;
import java.time.Instant;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

/** A-owned worker boundary. These inputs are server-owned; never deserialize them from HTTP. */
public final class GenerationContract {
    private GenerationContract() {}
    public enum Kind { CONTRACT, PATCH }
    public record Source(SourceBinding catalog, Instant analyzedAt, UUID findingId, UUID baseVersionId,
            String baseState, String basePolicyHash, String baseResourceHash, FindingSourceFacts finding,
            UUID sourceRunId, UUID sourceCaseId, UUID oracleResultId) {}
    public record Work(UUID operationId, UUID claimToken, Kind kind, VersionIdentity identity,
            String templateKey, ReviewerContext reviewer, Source expectedSource) {}
    public record Metadata(String templateKey, String promptVersion, String promptDigest, String provider,
            String model, long latencyMs, String sourceEvidenceDigest, String redactedEvidenceDigest) {}
    public record Generated(String outcome, JsonNode policy, ProposedPatch patch, Source observedSource,
            Metadata metadata, JsonNode issues) {}
    public record Operation(UUID operationId, Kind kind, String status, String statusUrl,
            UUID releaseId, String outcome, JsonNode result, String errorCode, String errorStage,
            boolean retryable, Instant createdAt, Instant startedAt, Instant finishedAt) {}
}
