package com.finsecseal.contract;

import com.finsecseal.contract.SafetyContractCandidatePromptBuilder.CandidatePrompt;
import com.finsecseal.contract.SafetyContractCanonicalizer.CanonicalPolicy;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationResult;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationStatus;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Optional;
import org.springframework.stereotype.Component;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/** Assesses model content against captured C inputs; performs no provider call or lifecycle action. */
@Component
public final class SafetyContractCandidateResponseProcessor {

    // Local resource guards, not financial business rules. Reject rather than truncate or repair.
    public static final int MAX_RESPONSE_BYTES = 65_536;
    public static final int MAX_DEPTH = 32;
    public static final int MAX_STRING_LENGTH = 8_192;
    public static final int MAX_NAME_LENGTH = 256;
    public static final int MAX_NUMBER_LENGTH = 100;
    public static final int MAX_TOKEN_COUNT = 16_384;

    private static final ObjectMapper RESPONSE_MAPPER = JsonMapper.builder(JsonFactory.builder()
                    .streamReadConstraints(StreamReadConstraints.builder()
                            .maxNestingDepth(MAX_DEPTH)
                            .maxStringLength(MAX_STRING_LENGTH)
                            .maxNameLength(MAX_NAME_LENGTH)
                            .maxNumberLength(MAX_NUMBER_LENGTH)
                            .maxTokenCount(MAX_TOKEN_COUNT)
                            .build())
                    .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                    .disable(StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION)
                    .build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY)
            .enable(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS)
            .build();

    private final SafetyContractSemanticValidator validator;
    private final SafetyContractCanonicalizer canonicalizer;

    public SafetyContractCandidateResponseProcessor(SafetyContractSemanticValidator validator,
            SafetyContractCanonicalizer canonicalizer) {
        this.validator = Objects.requireNonNull(validator, "validator must not be null");
        this.canonicalizer = Objects.requireNonNull(canonicalizer, "canonicalizer must not be null");
    }

    public CandidateAssessment process(CandidatePrompt prompt, String content) {
        if (prompt == null || content == null) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
        // Bound allocation before counting actual UTF-8 bytes. Parse the original String exactly.
        if (content.length() > MAX_RESPONSE_BYTES
                || content.getBytes(StandardCharsets.UTF_8).length > MAX_RESPONSE_BYTES) {
            throw failure(FailureCode.RESPONSE_TOO_LARGE);
        }

        JsonNode policy;
        try {
            policy = RESPONSE_MAPPER.readTree(content);
        } catch (RuntimeException exception) {
            throw failure(FailureCode.MALFORMED_RESPONSE);
        }
        if (policy == null || !policy.isObject()) {
            throw failure(FailureCode.MALFORMED_RESPONSE);
        }
        JsonNode key = policy.path("contractId");
        JsonNode version = policy.path("version");
        if (!key.isString() || !prompt.identity().contractKey().equals(key.stringValue())
                || !version.isIntegralNumber()
                || !BigInteger.valueOf(prompt.identity().version()).equals(version.bigIntegerValue())) {
            throw failure(FailureCode.IDENTITY_MISMATCH);
        }

        try {
            ValidationResult validation = Objects.requireNonNull(
                    validator.validate(policy, prompt.source().catalog().semanticCatalog()));
            Optional<CanonicalPolicy> canonical = validation.status() == ValidationStatus.INVALID
                    ? Optional.empty()
                    : Optional.of(Objects.requireNonNull(canonicalizer.canonicalizeAndHash(policy)));
            return new CandidateAssessment(prompt, policy, validation, canonical);
        } catch (RuntimeException exception) {
            // Engine errors must not masquerade as policy invalidity or expose provider content.
            throw failure(FailureCode.PROCESSING_FAILURE);
        }
    }

    /**
     * An unpersisted assessment relative to the captured source. This is not a provider-call receipt,
     * authenticated identity reservation, source-freshness check, validation proof or approval.
     */
    public static final class CandidateAssessment {
        private final CandidatePrompt prompt;
        private final JsonNode policy;
        private final ValidationResult validation;
        private final Optional<CanonicalPolicy> canonicalPolicy;

        private CandidateAssessment(CandidatePrompt prompt, JsonNode policy, ValidationResult validation,
                Optional<CanonicalPolicy> canonicalPolicy) {
            this.prompt = prompt;
            // Keep the original exact identity even when canonical policy text normalizes Unicode.
            this.policy = policy.deepCopy();
            this.validation = validation;
            this.canonicalPolicy = canonicalPolicy;
        }

        public CandidatePrompt prompt() { return prompt; }
        public JsonNode policy() { return policy.deepCopy(); }
        public ValidationResult validation() { return validation; }
        public Optional<CanonicalPolicy> canonicalPolicy() { return canonicalPolicy; }
    }

    public enum FailureCode {
        INVALID_REQUEST, RESPONSE_TOO_LARGE, MALFORMED_RESPONSE, IDENTITY_MISMATCH, PROCESSING_FAILURE
    }

    public static final class CandidateResponseException extends RuntimeException {
        private final FailureCode code;

        private CandidateResponseException(FailureCode code) {
            super("Contract candidate response could not be processed: " + code.name());
            this.code = code;
        }

        public FailureCode code() { return code; }
    }

    private static CandidateResponseException failure(FailureCode code) {
        return new CandidateResponseException(code);
    }
}
