package com.finsecseal.contract;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ReleaseLifecycleState;
import com.finsecseal.contract.SafetyContractCanonicalizer.CanonicalPolicy;
import com.finsecseal.contract.SafetyContractCandidatePromptBuilder.CandidatePrompt;
import com.finsecseal.contract.SafetyContractCandidatePromptBuilder.CandidatePromptException;
import com.finsecseal.contract.SafetyContractCandidateResponseProcessor.CandidateAssessment;
import com.finsecseal.contract.SafetyContractCandidateResponseProcessor.CandidateResponseException;
import com.finsecseal.contract.SafetyContractGenerationSourceService.GenerationSourceException;
import com.finsecseal.contract.SafetyContractGenerationSourceService.PreparedGenerationSource;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.SourceBinding;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionIdentity;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationResult;
import com.finsecseal.evidence.RedactionService;
import com.finsecseal.runtime.ai.ContractCandidateAiClient;
import com.finsecseal.runtime.ai.ContractCandidateAiClient.CandidateModelResponse;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Objects;
import java.util.Optional;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.StringNode;

/** Internal worker: A owns caller authorization, identity allocation/concurrency and result storage. */
@Service
@ConditionalOnProperty(name = "finsec.ai.enabled", havingValue = "true")
public final class ContractCandidateGenerationService {
    private final SafetyContractGenerationSourceService sources;
    private final SafetyContractCandidatePromptBuilder prompts;
    private final SafetyContractCandidateResponseProcessor responses;
    private final ContractCandidateAiClient models;
    private final ObjectMapper json;
    private final RedactionService redaction;

    public ContractCandidateGenerationService(SafetyContractGenerationSourceService sources,
            SafetyContractCandidatePromptBuilder prompts, SafetyContractCandidateResponseProcessor responses,
            ContractCandidateAiClient models, ObjectMapper json, RedactionService redaction) {
        this.sources = Objects.requireNonNull(sources);
        this.prompts = Objects.requireNonNull(prompts);
        this.responses = Objects.requireNonNull(responses);
        this.models = Objects.requireNonNull(models);
        this.json = Objects.requireNonNull(json);
        this.redaction = Objects.requireNonNull(redaction);
    }

    /**
     * A must authorize the release/workspace before calling. Supplied identity is not proof of
     * reservation or a stored version; this worker allocates nothing and exposes no HTTP endpoint.
     * Source preparation must use its Spring proxy, finish its transaction, then wait for B.
     */
    public CandidateGenerationResult generate(VersionIdentity identity, String templateKey, String actorId) {
        if (identity == null || identity.versionId() == null || identity.workspaceId() == null
                || identity.releaseId() == null || identity.version() <= 0
                || identity.contractKey() == null || identity.contractKey().isBlank()
                || identity.contractKey().length() > 100
                || !identity.contractKey().equals(identity.contractKey().strip())
                || actorId == null || actorId.isBlank() || actorId.length() > 120
                || !actorId.equals(actorId.strip())) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
        requireNoTransaction();
        String template = templateKey == null || templateKey.isBlank() ? LoanReviewFinancialTemplate.KEY : templateKey;
        PreparedGenerationSource source = prepare(identity, template, actorId);
        requireNoTransaction();
        CandidatePrompt prompt = prompt(source, identity);
        checkModelInput(prompt);
        requireNoTransaction();
        CandidateModelResponse model = model(prompt);
        try {
            CandidateAssessment assessment = Objects.requireNonNull(responses.process(prompt, model.content()));
            return new CandidateGenerationResult(identity, source, prompt, model, assessment);
        } catch (CandidateResponseException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw failure(FailureCode.PROCESSING_FAILURE);
        }
    }

    private PreparedGenerationSource prepare(VersionIdentity identity, String template, String actor) {
        try {
            return Objects.requireNonNull(sources.prepare(identity.releaseId(), template, actor));
        } catch (GenerationSourceException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw failure(FailureCode.SOURCE_UNAVAILABLE);
        }
    }

    private CandidatePrompt prompt(PreparedGenerationSource source, VersionIdentity identity) {
        try {
            return Objects.requireNonNull(prompts.build(source, identity));
        } catch (CandidatePromptException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw failure(FailureCode.PROCESSING_FAILURE);
        }
    }

    private void checkModelInput(CandidatePrompt prompt) {
        try {
            // Existing B/Python request limits, checked before any network call. Never truncate.
            if (prompt.promptVersion().codePointCount(0, prompt.promptVersion().length()) > 120
                    || prompt.instructions().codePointCount(0, prompt.instructions().length()) > 16_384
                    || prompt.inputJson().codePointCount(0, prompt.inputJson().length()) > 65_536) {
                throw failure(FailureCode.REQUEST_TOO_LARGE);
            }
            var envelope = json.createObjectNode().put("promptVersion", prompt.promptVersion())
                    .put("instructions", prompt.instructions()).put("inputJson", prompt.inputJson());
            if (json.writeValueAsBytes(envelope).length > 512 * 1024) {
                throw failure(FailureCode.REQUEST_TOO_LARGE);
            }
            // Validation-only projection, as at the patch boundary. A's ID tokenizer must not
            // receive schema objects; retain field names, strings and nullness for secret checks.
            var scan = json.createArrayNode();
            var pending = new ArrayDeque<JsonNode>();
            pending.add(json.readTree(prompt.inputJson()));
            while (!pending.isEmpty()) {
                JsonNode node = pending.removeFirst();
                if (node.isObject()) {
                    for (var field : node.properties()) {
                        JsonNode value = field.getValue();
                        scan.add(field.getKey());
                        scan.addObject().set(field.getKey(), value.isNull() || value.isString()
                                ? value : StringNode.valueOf("[NON_STRING_VALUE]"));
                        if (value.isObject() || value.isArray()) pending.addLast(value);
                    }
                } else if (node.isArray()) {
                    node.forEach(pending::addLast);
                } else if (node.isString()) {
                    scan.add(node);
                }
            }
            // Neither the scan nor A's transformed copy replaces the exact prompt or its digest.
            Objects.requireNonNull(redaction.redact(scan));
        } catch (CandidateGenerationException exception) {
            throw exception;
        } catch (BusinessException exception) {
            if (exception.errorCode() == ErrorCode.SECRET_DETECTED) throw exception;
            throw failure(FailureCode.PROCESSING_FAILURE);
        } catch (RuntimeException exception) {
            throw failure(FailureCode.PROCESSING_FAILURE);
        }
    }

    private CandidateModelResponse model(CandidatePrompt prompt) {
        CandidateModelResponse response;
        try {
            // B alone owns transport, timeout and retries. Its diagnostics can contain raw content.
            response = models.generate(prompt.promptVersion(), prompt.instructions(), prompt.inputJson());
        } catch (RuntimeException exception) {
            throw failure(FailureCode.MODEL_CALL_FAILURE);
        }
        if (response == null || !metadataText(response.provider(), 80)
                || !metadataText(response.model(), 120) || response.latencyMs() < 0) {
            throw failure(FailureCode.MODEL_RESPONSE_INVALID);
        }
        return response;
    }

    private static boolean metadataText(String value, int limit) {
        return value != null && !value.isBlank() && value.codePointCount(0, value.length()) <= limit;
    }

    private static void requireNoTransaction() {
        if (TransactionSynchronizationManager.isActualTransactionActive()
                || TransactionSynchronizationManager.isSynchronizationActive()) {
            throw failure(FailureCode.UNSAFE_TRANSACTION);
        }
    }

    /** Unpersisted assessment and generation-time binding; no prompt/source/raw response is retained. */
    public static final class CandidateGenerationResult {
        private final VersionIdentity identity;
        private final SourceBinding catalogBinding;
        private final Instant analyzedAt;
        private final ReleaseLifecycleState lifecycleState;
        private final String templateKey;
        private final String promptVersion;
        private final String promptDigest;
        private final String provider;
        private final String model;
        private final long latencyMs;
        private final JsonNode policy;
        private final ValidationResult validation;
        private final Optional<CanonicalPolicy> canonicalPolicy;

        private CandidateGenerationResult(VersionIdentity identity, PreparedGenerationSource source,
                CandidatePrompt prompt, CandidateModelResponse model, CandidateAssessment assessment) {
            this.identity = identity;
            var catalog = source.catalog();
            catalogBinding = new SourceBinding(catalog.releaseId(), catalog.manifestSchemaVersion(),
                    catalog.agentArtifactFingerprint(), catalog.releaseFingerprint(), catalog.serverToolCatalogHash());
            analyzedAt = source.analyzedAt();
            lifecycleState = source.lifecycleState();
            templateKey = source.templateKey();
            promptVersion = prompt.promptVersion();
            promptDigest = prompt.promptDigest();
            provider = model.provider();
            this.model = model.model();
            latencyMs = model.latencyMs();
            policy = assessment.policy();
            validation = assessment.validation();
            canonicalPolicy = assessment.canonicalPolicy();
        }

        public VersionIdentity identity() { return identity; }
        public SourceBinding catalogBinding() { return catalogBinding; }
        public Instant analyzedAt() { return analyzedAt; }
        public ReleaseLifecycleState lifecycleState() { return lifecycleState; }
        public String templateKey() { return templateKey; }
        public String promptVersion() { return promptVersion; }
        public String promptDigest() { return promptDigest; }
        public String provider() { return provider; }
        public String model() { return model; }
        public long latencyMs() { return latencyMs; }
        public JsonNode policy() { return policy.deepCopy(); }
        public ValidationResult validation() { return validation; }
        public Optional<CanonicalPolicy> canonicalPolicy() { return canonicalPolicy; }
    }

    public enum FailureCode {
        INVALID_REQUEST, UNSAFE_TRANSACTION, SOURCE_UNAVAILABLE, REQUEST_TOO_LARGE,
        MODEL_CALL_FAILURE, MODEL_RESPONSE_INVALID, PROCESSING_FAILURE
    }

    public static final class CandidateGenerationException extends RuntimeException {
        private final FailureCode code;

        private CandidateGenerationException(FailureCode code) {
            super("Contract candidate generation failed: " + code.name(), null, false, true);
            this.code = code;
        }

        public FailureCode code() { return code; }
    }

    private static CandidateGenerationException failure(FailureCode code) {
        return new CandidateGenerationException(code);
    }
}
