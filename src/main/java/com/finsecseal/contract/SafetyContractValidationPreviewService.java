package com.finsecseal.contract;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.SourceBoundCatalog;
import com.finsecseal.contract.SafetyContractSemanticValidator.Issue;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationStatus;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;

/** Inspects an unsaved draft against a verified release, without granting approval or execution. */
@Service
public final class SafetyContractValidationPreviewService {

    private final ReleaseToolCatalogContractAdapter catalogAdapter;
    private final SafetyContractSemanticValidator validator;
    private final SafetyContractCanonicalizer canonicalizer;

    public SafetyContractValidationPreviewService(
            ReleaseToolCatalogContractAdapter catalogAdapter,
            SafetyContractSemanticValidator validator,
            SafetyContractCanonicalizer canonicalizer
    ) {
        this.catalogAdapter = Objects.requireNonNull(catalogAdapter);
        this.validator = Objects.requireNonNull(validator);
        this.canonicalizer = Objects.requireNonNull(canonicalizer);
    }

    public PreviewResult preview(UUID releaseId, JsonNode candidate, String actorId) {
        if (releaseId == null || !validActor(actorId)) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR,
                    "Release ID and an exact nonblank X-Actor-Id of at most 120 characters are required");
        }

        JsonNode snapshot;
        try {
            snapshot = candidate == null ? null : candidate.deepCopy();
        } catch (RuntimeException exception) {
            throw new PreviewProcessingException();
        }

        // Preserve A's verified read transaction and its access auditing.
        SourceBoundCatalog source = catalogAdapter.load(releaseId, actorId);
        try {
            var validation = validator.validate(snapshot, source.semanticCatalog());
            String policyHash = validation.status() == ValidationStatus.VALID
                    ? canonicalizer.canonicalizeAndHash(snapshot).policyHash()
                    : null;
            return new PreviewResult(true, validation.status(), validation.issues(),
                    new SourceBinding(source.releaseId(), source.manifestSchemaVersion(),
                            source.agentArtifactFingerprint(), source.releaseFingerprint(),
                            source.serverToolCatalogHash()),
                    policyHash);
        } catch (RuntimeException exception) {
            // Canonicalization errors may contain draft text. Never retain that text or cause.
            throw new PreviewProcessingException();
        }
    }

    static boolean validActor(String actorId) {
        return actorId != null && !actorId.isBlank() && actorId.length() <= 120
                && actorId.equals(actorId.strip());
    }

    public record PreviewResult(
            boolean previewOnly,
            ValidationStatus status,
            List<Issue> issues,
            SourceBinding source,
            String policyHash
    ) {
        public PreviewResult {
            issues = List.copyOf(issues);
        }
    }

    public record SourceBinding(
            UUID releaseId,
            String manifestSchemaVersion,
            String agentArtifactFingerprint,
            String releaseFingerprint,
            String serverToolCatalogHash
    ) {
    }

    public static final class PreviewProcessingException extends RuntimeException {
        public PreviewProcessingException() {
            super("Contract validation preview could not be completed");
        }
    }
}
