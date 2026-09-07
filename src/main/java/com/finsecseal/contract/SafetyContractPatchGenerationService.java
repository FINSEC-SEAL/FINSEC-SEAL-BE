package com.finsecseal.contract;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.contract.SafetyContractGenerationSourceService.GenerationSourceException;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.SourceBinding;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionIdentity;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionState;
import com.finsecseal.contract.SafetyContractPatchGenerationSourceService.PatchGenerationSourceException;
import com.finsecseal.contract.SafetyContractPatchGenerationSourceService.PreparedPatchGenerationSource;
import com.finsecseal.contract.SafetyContractPatchPromptBuilder.PatchPrompt;
import com.finsecseal.contract.SafetyContractPatchPromptBuilder.PatchPromptException;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.FindingSourceFacts;
import com.finsecseal.contract.SafetyContractPatchResponseProcessor.PatchAssessment;
import com.finsecseal.contract.SafetyContractPatchResponseProcessor.PatchResponseException;
import com.finsecseal.runtime.ai.ContractCandidateAiClient;
import com.finsecseal.runtime.ai.ContractCandidateAiClient.CandidateModelResponse;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/** Generates an internal assessment; storage and approval require the owner's separate revalidation. */
@Service
@ConditionalOnProperty(name = "finsec.ai.enabled", havingValue = "true")
public final class SafetyContractPatchGenerationService {
    private final SafetyContractPatchGenerationSourceService sources;
    private final SafetyContractPatchPromptBuilder prompts;
    private final ContractCandidateAiClient models;
    private final SafetyContractPatchResponseProcessor responses;

    public SafetyContractPatchGenerationService(SafetyContractPatchGenerationSourceService sources,
            SafetyContractPatchPromptBuilder prompts, ContractCandidateAiClient models,
            SafetyContractPatchResponseProcessor responses) {
        this.sources = Objects.requireNonNull(sources);
        this.prompts = Objects.requireNonNull(prompts);
        this.models = Objects.requireNonNull(models);
        this.responses = Objects.requireNonNull(responses);
    }

    // Intentionally not transactional: source preparation owns its short transaction, never the model wait.
    public PatchGenerationResult generate(UUID findingId, UUID baseContractVersionId, ReviewerContext reviewer) {
        if (findingId == null || baseContractVersionId == null || reviewer == null) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
        requireNoTransaction();
        PreparedPatchGenerationSource source = prepare(findingId, baseContractVersionId, reviewer);
        requireNoTransaction();
        PatchPrompt prompt = prompt(source);
        requireNoTransaction();
        CandidateModelResponse model = model(prompt);
        PatchAssessment assessment = assess(source, model.content());
        return new PatchGenerationResult(source, prompt, model, assessment);
    }

    private PreparedPatchGenerationSource prepare(UUID findingId, UUID baseVersionId, ReviewerContext reviewer) {
        try {
            return Objects.requireNonNull(sources.prepare(findingId, baseVersionId, reviewer));
        } catch (PatchGenerationSourceException | GenerationSourceException | BusinessException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw failure(FailureCode.SOURCE_UNAVAILABLE);
        }
    }

    private PatchPrompt prompt(PreparedPatchGenerationSource source) {
        try {
            return Objects.requireNonNull(prompts.build(source));
        } catch (PatchPromptException exception) {
            throw exception;
        } catch (BusinessException exception) {
            if (exception.errorCode() == ErrorCode.SECRET_DETECTED) throw exception;
            throw failure(FailureCode.PROCESSING_FAILURE);
        } catch (RuntimeException exception) {
            throw failure(FailureCode.PROCESSING_FAILURE);
        }
    }

    private CandidateModelResponse model(PatchPrompt prompt) {
        CandidateModelResponse response;
        try {
            // Transport, timeout and retries remain in the existing B client.
            response = models.generate(prompt.promptVersion(), prompt.instructions(), prompt.inputJson());
        } catch (RuntimeException exception) {
            // Provider diagnostics may contain request/response content; do not retain their cause.
            throw failure(FailureCode.MODEL_CALL_FAILURE);
        }
        // Existing Python ContractCandidateResponse limits; preserve exact provider-reported strings.
        if (response == null || !metadataText(response.provider(), 80)
                || !metadataText(response.model(), 120) || response.latencyMs() < 0) {
            throw failure(FailureCode.MODEL_RESPONSE_INVALID);
        }
        return response;
    }

    private PatchAssessment assess(PreparedPatchGenerationSource source, String content) {
        try {
            return Objects.requireNonNull(responses.process(source.finding(), source.base(),
                    source.generation().catalog(), content));
        } catch (PatchResponseException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw failure(FailureCode.PROCESSING_FAILURE);
        }
    }

    private static boolean metadataText(String value, int maxCodePoints) {
        return value != null && !value.isBlank()
                && value.codePointCount(0, value.length()) <= maxCodePoints;
    }

    private static void requireNoTransaction() {
        if (TransactionSynchronizationManager.isActualTransactionActive()
                || TransactionSynchronizationManager.isSynchronizationActive()) {
            throw failure(FailureCode.UNSAFE_TRANSACTION);
        }
    }

    /**
     * Immutable generation-time evidence and assessment, including INVALID and NO_CHANGE_NEEDED.
     * Metadata is provider-reported, not an attestation. No raw evidence, prompt input or model
     * response envelope is retained. This result authorizes neither storage, approval nor execution.
     */
    public static final class PatchGenerationResult {
        private final PatchAssessment assessment;
        private final FindingSourceFacts finding;
        private final UUID sourceRunId;
        private final UUID sourceCaseId;
        private final UUID oracleResultId;
        private final VersionIdentity baseIdentity;
        private final VersionState baseState;
        private final String basePolicyHash;
        private final String baseResourceHash;
        private final SourceBinding catalogBinding;
        private final Instant analyzedAt;
        private final String templateKey;
        private final String promptVersion;
        private final String promptDigest;
        private final String sourceEvidenceDigest;
        private final String redactedEvidenceDigest;
        private final String provider;
        private final String model;
        private final long latencyMs;

        private PatchGenerationResult(PreparedPatchGenerationSource source, PatchPrompt prompt,
                CandidateModelResponse response, PatchAssessment assessment) {
            this.assessment = assessment;
            finding = source.finding();
            sourceRunId = source.sourceRunId();
            sourceCaseId = source.sourceCaseId();
            oracleResultId = source.oracleResultId();
            baseIdentity = source.base().identity();
            baseState = source.base().state();
            basePolicyHash = source.base().policyHash();
            baseResourceHash = source.base().resourceHash();
            var catalog = source.generation().catalog();
            catalogBinding = new SourceBinding(catalog.releaseId(), catalog.manifestSchemaVersion(),
                    catalog.agentArtifactFingerprint(), catalog.releaseFingerprint(), catalog.serverToolCatalogHash());
            analyzedAt = source.generation().analyzedAt();
            templateKey = source.generation().templateKey();
            promptVersion = prompt.promptVersion();
            promptDigest = prompt.promptDigest();
            sourceEvidenceDigest = prompt.sourceEvidenceDigest();
            redactedEvidenceDigest = prompt.redactedEvidenceDigest();
            provider = response.provider();
            model = response.model();
            latencyMs = response.latencyMs();
        }

        public PatchAssessment assessment() { return assessment; }
        public FindingSourceFacts finding() { return finding; }
        public UUID sourceRunId() { return sourceRunId; }
        public UUID sourceCaseId() { return sourceCaseId; }
        public UUID oracleResultId() { return oracleResultId; }
        public VersionIdentity baseIdentity() { return baseIdentity; }
        public VersionState baseState() { return baseState; }
        public String basePolicyHash() { return basePolicyHash; }
        public String baseResourceHash() { return baseResourceHash; }
        public SourceBinding catalogBinding() { return catalogBinding; }
        public Instant analyzedAt() { return analyzedAt; }
        public String templateKey() { return templateKey; }
        public String promptVersion() { return promptVersion; }
        public String promptDigest() { return promptDigest; }
        public String sourceEvidenceDigest() { return sourceEvidenceDigest; }
        public String redactedEvidenceDigest() { return redactedEvidenceDigest; }
        public String provider() { return provider; }
        public String model() { return model; }
        public long latencyMs() { return latencyMs; }
    }

    public enum FailureCode {
        INVALID_REQUEST, UNSAFE_TRANSACTION, SOURCE_UNAVAILABLE, MODEL_CALL_FAILURE,
        MODEL_RESPONSE_INVALID, PROCESSING_FAILURE
    }

    public static final class PatchGenerationException extends RuntimeException {
        private final FailureCode code;

        private PatchGenerationException(FailureCode code) {
            super("Contract patch generation failed: " + code.name(), null, false, true);
            this.code = code;
        }

        public FailureCode code() { return code; }
    }

    private static PatchGenerationException failure(FailureCode code) { return new PatchGenerationException(code); }
}
