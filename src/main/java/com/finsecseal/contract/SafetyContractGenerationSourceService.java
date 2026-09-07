package com.finsecseal.contract;

import com.finsecseal.common.domain.ReleaseLifecycleState;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.SourceBoundCatalog;
import com.finsecseal.release.AgentReleaseEntity;
import com.finsecseal.release.ReleaseService;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/** Loads the verified, non-secret inputs for the original contract generation pipeline. */
@Service
public class SafetyContractGenerationSourceService {

    private static final List<String> OBJECT_FIELDS = List.of(
            "businessPurpose", "businessWorkflow", "networkRequirements", "serverToolCatalog");
    private static final List<String> ARRAY_FIELDS = List.of(
            "tools", "humanApprovalBoundaries", "runtimeContextRequirements");

    private final ReleaseToolCatalogContractAdapter catalogs;
    private final ReleaseService releases;
    private final LoanReviewFinancialTemplate template;
    private final ObjectMapper mapper;

    public SafetyContractGenerationSourceService(ReleaseToolCatalogContractAdapter catalogs,
            ReleaseService releases, LoanReviewFinancialTemplate template, ObjectMapper mapper) {
        this.catalogs = Objects.requireNonNull(catalogs);
        this.releases = Objects.requireNonNull(releases);
        this.template = Objects.requireNonNull(template);
        this.mapper = Objects.requireNonNull(mapper);
    }

    /**
     * A's catalog read joins this writable transaction, retaining its release lock through
     * the second read and projection. Its existing access audit also requires a write transaction.
     * No provider call or contract lifecycle mutation belongs in this transaction.
     */
    @Transactional
    public PreparedGenerationSource prepare(UUID releaseId, String templateKey, String actorId) {
        if (releaseId == null || actorId == null || actorId.isBlank()
                || actorId.length() > 120 || !actorId.equals(actorId.strip())) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
        if (!LoanReviewFinancialTemplate.KEY.equals(templateKey)) {
            throw failure(FailureCode.UNSUPPORTED_TEMPLATE);
        }

        try {
            SourceBoundCatalog catalog = catalogs.load(releaseId, actorId);
            if (catalog == null || !releaseId.equals(catalog.releaseId())) {
                throw failure(FailureCode.SOURCE_BINDING_MISMATCH);
            }
            // Keep A's entity confined to this method; getRequired alone is not a verified read.
            AgentReleaseEntity release = releases.getRequired(releaseId);
            requireBinding(releaseId, catalog, release);
            if (release.getAnalyzedAt() == null || release.getLifecycleState() == null
                    || release.getLifecycleState() == ReleaseLifecycleState.DRAFT) {
                throw failure(FailureCode.RELEASE_NOT_ANALYZED);
            }

            JsonNode manifest = release.getManifestJson();
            if (manifest == null || !manifest.isObject()
                    || !catalog.manifestSchemaVersion().equals(manifest.path("schemaVersion").asString())) {
                throw failure(FailureCode.SOURCE_BINDING_MISMATCH);
            }
            if (!LoanReviewFinancialTemplate.PURPOSE.equals(release.getBusinessPurpose())
                    || !LoanReviewFinancialTemplate.PURPOSE.equals(
                            manifest.at("/businessPurpose/code").asString())) {
                throw failure(FailureCode.UNSUPPORTED_PURPOSE);
            }

            ObjectNode projection = mapper.createObjectNode();
            for (String field : OBJECT_FIELDS) {
                JsonNode value = manifest.path(field);
                if (!value.isObject() || value.isEmpty()) {
                    throw failure(FailureCode.SOURCE_CONTENT_INVALID);
                }
                projection.set(field, value.deepCopy());
            }
            for (String field : ARRAY_FIELDS) {
                JsonNode value = manifest.path(field);
                if (!value.isArray() || value.isEmpty()) {
                    throw failure(FailureCode.SOURCE_CONTENT_INVALID);
                }
                projection.set(field, value.deepCopy());
            }
            return new PreparedGenerationSource(catalog, release.getAnalyzedAt(),
                    release.getLifecycleState(), projection, template.policyRules());
        } catch (GenerationSourceException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            // Source exceptions can contain stored text. Preserve failure, never its raw cause.
            throw failure(FailureCode.SOURCE_UNAVAILABLE);
        }
    }

    private void requireBinding(UUID requestedId, SourceBoundCatalog catalog, AgentReleaseEntity release) {
        if (release == null || !requestedId.equals(release.getId())
                || !catalog.manifestSchemaVersion().equals(release.getManifestSchemaVersion())
                || !catalog.agentArtifactFingerprint().equals(release.getAgentArtifactFingerprint())
                || !catalog.releaseFingerprint().equals(release.getReleaseFingerprint())) {
            throw failure(FailureCode.SOURCE_BINDING_MISMATCH);
        }
    }

    /** A source snapshot only: neither a generated candidate nor validation/approval evidence. */
    public static final class PreparedGenerationSource {
        private final SourceBoundCatalog catalog;
        private final Instant analyzedAt;
        private final ReleaseLifecycleState lifecycleState;
        private final JsonNode manifestContext;
        private final JsonNode templateRules;

        private PreparedGenerationSource(SourceBoundCatalog catalog, Instant analyzedAt,
                ReleaseLifecycleState lifecycleState, JsonNode manifestContext, JsonNode templateRules) {
            this.catalog = catalog;
            this.analyzedAt = analyzedAt;
            this.lifecycleState = lifecycleState;
            this.manifestContext = manifestContext.deepCopy();
            this.templateRules = templateRules.deepCopy();
        }

        public SourceBoundCatalog catalog() { return catalog; }
        public Instant analyzedAt() { return analyzedAt; }
        public ReleaseLifecycleState lifecycleState() { return lifecycleState; }
        public String templateKey() { return LoanReviewFinancialTemplate.KEY; }
        public JsonNode manifestContext() { return manifestContext.deepCopy(); }
        public JsonNode templateRules() { return templateRules.deepCopy(); }
    }

    public enum FailureCode {
        INVALID_REQUEST, UNSUPPORTED_TEMPLATE, RELEASE_NOT_ANALYZED,
        SOURCE_BINDING_MISMATCH, UNSUPPORTED_PURPOSE, SOURCE_CONTENT_INVALID, SOURCE_UNAVAILABLE
    }

    public static final class GenerationSourceException extends RuntimeException {
        private final FailureCode code;

        private GenerationSourceException(FailureCode code) {
            super("Contract generation source could not be prepared: " + code.name());
            this.code = code;
        }

        public FailureCode code() { return code; }
    }

    private static GenerationSourceException failure(FailureCode code) {
        return new GenerationSourceException(code);
    }
}
