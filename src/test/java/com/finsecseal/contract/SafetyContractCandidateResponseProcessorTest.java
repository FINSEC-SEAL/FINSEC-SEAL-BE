package com.finsecseal.contract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.finsecseal.common.domain.ReleaseLifecycleState;
import com.finsecseal.contract.SafetyContractCandidatePromptBuilder.CandidatePrompt;
import com.finsecseal.contract.SafetyContractCandidateResponseProcessor.CandidateResponseException;
import com.finsecseal.contract.SafetyContractCandidateResponseProcessor.FailureCode;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionIdentity;
import com.finsecseal.contract.SafetyContractSemanticValidator.ContractValidationCatalog;
import com.finsecseal.contract.SafetyContractSemanticValidator.Issue;
import com.finsecseal.contract.SafetyContractSemanticValidator.IssueSeverity;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationResult;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationStatus;
import com.finsecseal.release.AgentReleaseEntity;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.ReleaseDto.ToolCatalogResponse;
import com.finsecseal.release.ReleaseService;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

class SafetyContractCandidateResponseProcessorTest {
    private static final UUID RELEASE = UUID.fromString("0198f200-0000-7000-8000-000000000301");
    private static final UUID WORKSPACE = UUID.fromString("0198f200-0000-7000-8000-000000000302");
    private static final UUID VERSION_ID = UUID.fromString("0198f200-0000-7000-8000-000000000303");
    private static final String ACTOR = "candidate-response-test";
    private static final String SECRET = "CANDIDATE-RAW-SECRET-CANARY";
    private static final VersionIdentity IDENTITY =
            new VersionIdentity(VERSION_ID, WORKSPACE, RELEASE, "review-contract", 7);

    private ObjectMapper mapper;
    private SafetyContractSemanticValidator semantic;
    private SafetyContractCanonicalizer canonicalizer;
    private SafetyContractCandidatePromptBuilder builder;
    private CandidatePrompt prompt;
    private SafetyContractCandidateResponseProcessor processor;

    @BeforeEach
    void prepareRealSourceAndPromptWithMockedOwnerPersistence() throws Exception {
        mapper = new ObjectMapper();
        CanonicalJsonService canonicalJson = new CanonicalJsonService(mapper);
        DigestService digests = new DigestService();
        ObjectNode manifest;
        try (var input = getClass().getResourceAsStream("/fixtures/valid-release-manifest-v1.1.json")) {
            manifest = (ObjectNode) mapper.readTree(input);
        }
        ((ObjectNode) manifest.path("systemPrompt")).put("text", SECRET);
        String artifact = "sha256:" + "a".repeat(64);
        String fingerprint = "sha256:" + "b".repeat(64);
        ObjectNode wrapper = mapper.createObjectNode();
        wrapper.set("serverToolCatalog", manifest.path("serverToolCatalog"));
        String catalogHash = digests.sha256(canonicalJson.canonicalize(
                canonicalJson.normalizeManifest(wrapper).path("serverToolCatalog")));

        // Unit evidence only: A's source boundary is mocked; C source/adapter/prompt/validators are real.
        ReleaseService releases = mock(ReleaseService.class);
        AgentReleaseEntity entity = mock(AgentReleaseEntity.class);
        when(releases.toolCatalog(RELEASE, ACTOR)).thenReturn(new ToolCatalogResponse(
                RELEASE, "1.1", artifact, fingerprint, catalogHash,
                manifest.path("tools"), manifest.path("serverToolCatalog")));
        when(releases.getRequired(RELEASE)).thenReturn(entity);
        when(entity.getId()).thenReturn(RELEASE);
        when(entity.getManifestSchemaVersion()).thenReturn("1.1");
        when(entity.getAgentArtifactFingerprint()).thenReturn(artifact);
        when(entity.getReleaseFingerprint()).thenReturn(fingerprint);
        when(entity.getBusinessPurpose()).thenReturn(LoanReviewFinancialTemplate.PURPOSE);
        when(entity.getAnalyzedAt()).thenReturn(Instant.parse("2026-09-07T00:00:00Z"));
        when(entity.getLifecycleState()).thenReturn(ReleaseLifecycleState.ANALYZED);
        when(entity.getManifestJson()).thenAnswer(ignored -> manifest.deepCopy());
        var sources = new SafetyContractGenerationSourceService(
                new ReleaseToolCatalogContractAdapter(releases, canonicalJson, digests, mapper),
                releases, new LoanReviewFinancialTemplate(mapper), mapper);
        builder = new SafetyContractCandidatePromptBuilder(mapper, digests);
        prompt = builder.build(sources.prepare(RELEASE, LoanReviewFinancialTemplate.KEY, ACTOR), IDENTITY);
        var schema = new SafetyContractSchemaValidator();
        semantic = new SafetyContractSemanticValidator(schema);
        canonicalizer = new SafetyContractCanonicalizer(schema, canonicalJson, digests);
        processor = new SafetyContractCandidateResponseProcessor(semantic, canonicalizer);
    }

    @Test
    void validatesActualCandidateAndRetainsOriginalPromptBinding() {
        ObjectNode candidate = candidate(prompt);
        String raw = mapper.writeValueAsString(candidate);

        var result = processor.process(prompt, raw);

        assertThat(result.validation().status()).isEqualTo(ValidationStatus.VALID);
        assertThat(result.validation().issues()).isEmpty();
        assertThat(mapper.writeValueAsString(result.policy())).isEqualTo(raw);
        assertThat(result.policy().path("version").bigIntegerValue()).isEqualTo(BigInteger.valueOf(7));
        assertThat(result.canonicalPolicy()).contains(canonicalizer.canonicalizeAndHash(candidate));
        assertThat(result.prompt()).isSameAs(prompt);
        assertThat(result.prompt().source()).isSameAs(prompt.source());
        assertThat(result.prompt().identity()).isEqualTo(IDENTITY);
        assertThat(result.prompt().promptDigest()).isEqualTo(prompt.promptDigest());
        assertThat(result.toString()).doesNotContain(raw, "review-contract", SECRET);
    }

    @Test
    void equivalentSetAndObjectOrderProducesOneCanonicalPolicyWithoutReorderingOriginal() {
        ObjectNode first = candidate(prompt);
        ObjectNode reordered = first.deepCopy();
        for (String pointer : List.of("/allowedTools", "/fieldPolicy/CUSTOMER_DATA_READ/allowed",
                "/outputPolicy/reviewStatusAllowed")) {
            reverse((ArrayNode) reordered.at(pointer));
        }
        JsonNode schemaVersion = reordered.remove("schemaVersion");
        reordered.set("schemaVersion", schemaVersion);
        String reorderedRaw = mapper.writeValueAsString(reordered);

        var originalResult = processor.process(prompt, mapper.writeValueAsString(first));
        var reorderedResult = processor.process(prompt, reorderedRaw);

        assertThat(reorderedResult.canonicalPolicy()).isEqualTo(originalResult.canonicalPolicy());
        assertThat(mapper.writeValueAsString(reorderedResult.policy())).isEqualTo(reorderedRaw);
    }

    @ParameterizedTest
    @ValueSource(strings = {"cafe\u0301", "line\r\nkey", "line\rkey"})
    void keepsExactIdentityInOriginalPolicyAlongsideNormalizedCanonicalPolicy(String key) {
        CandidatePrompt exactPrompt = builder.build(prompt.source(),
                new VersionIdentity(VERSION_ID, WORKSPACE, RELEASE, key, 7));

        var result = processor.process(exactPrompt, mapper.writeValueAsString(candidate(exactPrompt)));

        assertThat(result.policy().path("contractId").asString()).isEqualTo(key);
        assertThat(result.prompt()).isSameAs(exactPrompt);
        String normalized = Normalizer.normalize(key.replace("\r\n", "\n").replace('\r', '\n'),
                Normalizer.Form.NFC);
        JsonNode canonical = mapper.readTree(result.canonicalPolicy().orElseThrow().canonicalJson());
        assertThat(canonical.path("contractId").asString()).isEqualTo(normalized).isNotEqualTo(key);
        ObjectNode changedIdentity = candidate(exactPrompt);
        changedIdentity.put("contractId", normalized);
        expect(FailureCode.IDENTITY_MISMATCH, exactPrompt, mapper.writeValueAsString(changedIdentity));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "\n", "null", "[]", "true", "7", "\"text\"", "{",
            "{\"contractId\":", "{unquoted:true}", "{'contractId':'review-contract'}",
            "// comment\n{}", "/* comment */ {}", "```json\n{}\n```"})
    void malformedContentNeverBecomesAnAssessment(String raw) {
        expect(FailureCode.MALFORMED_RESPONSE, prompt, raw);
    }

    @ParameterizedTest
    @ValueSource(strings = {"duplicate", "escapedDuplicate", "nestedDuplicate", "trailingObject",
            "trailingScalar", "fenced", "trailingComma"})
    void rejectsAmbiguousOrDecoratedOtherwiseValidJson(String kind) {
        String raw = mapper.writeValueAsString(candidate(prompt));
        raw = switch (kind) {
            case "duplicate" -> raw.replace("\"contractId\":\"review-contract\"",
                    "\"contractId\":\"review-contract\",\"contractId\":\"review-contract\"");
            case "escapedDuplicate" -> raw.replace("\"contractId\":\"review-contract\"",
                    "\"contractId\":\"review-contract\",\"contract\\u0049d\":\"review-contract\"");
            case "nestedDuplicate" -> raw.replace("\"denyUnknown\":true",
                    "\"denyUnknown\":true,\"denyUnknown\":false");
            case "trailingObject" -> raw + " {}";
            case "trailingScalar" -> raw + " true";
            case "fenced" -> "```json\n" + raw + "\n```";
            case "trailingComma" -> raw.substring(0, raw.length() - 1) + ",}";
            default -> throw new AssertionError(kind);
        };
        expect(FailureCode.MALFORMED_RESPONSE, prompt, raw);
    }

    @Test
    void rejectsAbsentRequestWithoutParsingOrCallingDeterministicEngines() {
        var unusedSemantic = mock(SafetyContractSemanticValidator.class);
        var unusedCanonical = mock(SafetyContractCanonicalizer.class);
        var subject = new SafetyContractCandidateResponseProcessor(unusedSemantic, unusedCanonical);
        expect(subject, FailureCode.INVALID_REQUEST, null, "{}");
        expect(subject, FailureCode.INVALID_REQUEST, prompt, null);
        verifyNoInteractions(unusedSemantic, unusedCanonical);
    }

    @ParameterizedTest
    @ValueSource(strings = {"contractMissing", "contractWrong", "contractNull", "contractNumber",
            "versionMissing", "versionNull", "versionWrong", "versionString", "versionDecimal", "versionOverflow"})
    void requiresExactOwnerIdentityBeforeSemanticValidation(String change) {
        ObjectNode candidate = candidate(prompt);
        switch (change) {
            case "contractMissing" -> candidate.remove("contractId");
            case "contractWrong" -> candidate.put("contractId", "other-contract");
            case "contractNull" -> candidate.putNull("contractId");
            case "contractNumber" -> candidate.put("contractId", 7);
            case "versionMissing" -> candidate.remove("version");
            case "versionNull" -> candidate.putNull("version");
            case "versionWrong" -> candidate.put("version", 8);
            case "versionString" -> candidate.put("version", "7");
            case "versionDecimal" -> candidate.put("version", 7.0);
            case "versionOverflow" -> candidate.put("version", new BigInteger("4294967303"));
            default -> throw new AssertionError(change);
        }
        var unusedSemantic = mock(SafetyContractSemanticValidator.class);
        var unusedCanonical = mock(SafetyContractCanonicalizer.class);
        var subject = new SafetyContractCandidateResponseProcessor(unusedSemantic, unusedCanonical);

        expect(subject, FailureCode.IDENTITY_MISMATCH, prompt, mapper.writeValueAsString(candidate));

        verifyNoInteractions(unusedSemantic, unusedCanonical);
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', textBlock = """
            /schemaVersion | "2.0" | UNSUPPORTED_SCHEMA_VERSION
            /purpose | "LOAN_APPROVAL" | PURPOSE_MISMATCH
            /metadata/templateVersion | "loan-review/2" | TEMPLATE_VERSION_MISMATCH
            /metadata/validatorVersion | "2.0" | VALIDATOR_VERSION_MISMATCH
            /allowedTools | [] | REQUIRED_TOOL_MISSING
            /fieldPolicy/CUSTOMER_DATA_READ/allowed | ["incomeBand"] | REQUIRED_FIELD_MISSING
            /fieldPolicy/CUSTOMER_DATA_READ/allowed | ["incomeBand","employmentStatus","accountNumber"] | FIELD_EXCEEDS_TEMPLATE
            /cardinality/CUSTOMER_DATA_READ/maxRequestedRecords | 2 | CARDINALITY_EXCEEDS_TEMPLATE
            /cardinality/CUSTOMER_DATA_READ/maxReturnedRecords | 4294967297 | CARDINALITY_EXCEEDS_TEMPLATE
            /externalEgress/allowed | true | EXTERNAL_EGRESS_NOT_DENIED
            /highImpactActions/LOAN_DECISION_UPDATE | "AGENT_ALLOWED" | LOAN_DECISION_POLICY_INVALID
            /unexpected | true | UNKNOWN_FIELD
            /allowedTools | ["CASE_CONTEXT_READ","CASE_CONTEXT_READ"] | DUPLICATE_VALUE
            """)
    void invalidPolicyReturnsRealValidatorIssuesWithoutCanonicalHash(
            String pointer, String replacement, String expectedCode
    ) {
        ObjectNode candidate = candidate(prompt);
        replace(candidate, pointer, mapper.readTree(replacement));
        var unusedCanonical = mock(SafetyContractCanonicalizer.class);
        var subject = new SafetyContractCandidateResponseProcessor(semantic, unusedCanonical);

        var result = subject.process(prompt, mapper.writeValueAsString(candidate));

        assertThat(result.validation().status()).isEqualTo(ValidationStatus.INVALID);
        assertThat(result.validation().issues()).extracting(Issue::code).contains(expectedCode);
        assertThat(result.validation().issues()).anyMatch(issue -> issue.severity() == IssueSeverity.ERROR);
        assertThat(result.canonicalPolicy()).isEmpty();
        assertThat(result.prompt()).isSameAs(prompt);
        verifyNoInteractions(unusedCanonical);
    }

    @Test
    void missingMetadataIsInvalidPolicyInsteadOfAParserOrEngineFailure() {
        ObjectNode candidate = candidate(prompt);
        candidate.remove("metadata");

        var result = processor.process(prompt, mapper.writeValueAsString(candidate));

        assertThat(result.validation().status()).isEqualTo(ValidationStatus.INVALID);
        assertThat(result.validation().issues()).extracting(Issue::code)
                .contains("TEMPLATE_VERSION_REQUIRED", "VALIDATOR_VERSION_REQUIRED");
        assertThat(result.canonicalPolicy()).isEmpty();
    }

    @Test
    void acceptsExactByteBudgetAndRejectsCharacterAndMultibyteOverflow() {
        String raw = mapper.writeValueAsString(candidate(prompt));
        int maximum = SafetyContractCandidateResponseProcessor.MAX_RESPONSE_BYTES;
        String boundary = raw + " ".repeat(maximum - raw.getBytes(StandardCharsets.UTF_8).length);
        assertThat(boundary.getBytes(StandardCharsets.UTF_8)).hasSize(maximum);
        assertThat(processor.process(prompt, boundary).validation().status()).isEqualTo(ValidationStatus.VALID);
        expect(FailureCode.RESPONSE_TOO_LARGE, prompt, boundary + " ");

        ObjectNode multibyte = candidate(prompt);
        ArrayNode values = multibyte.putArray("unexpected");
        for (int index = 0; index < 4; index++) {
            values.add("한".repeat(6000));
        }
        String encoded = mapper.writeValueAsString(multibyte);
        assertThat(encoded.length()).isLessThan(maximum);
        assertThat(encoded.getBytes(StandardCharsets.UTF_8).length).isGreaterThan(maximum);
        expect(FailureCode.RESPONSE_TOO_LARGE, prompt, encoded);
    }

    @ParameterizedTest
    @ValueSource(strings = {"string", "name", "number", "depth", "tokens"})
    void enforcesEachParserLimitWithoutCanonicalizingInvalidData(String limit) {
        int stringLimit = SafetyContractCandidateResponseProcessor.MAX_STRING_LENGTH;
        int nameLimit = SafetyContractCandidateResponseProcessor.MAX_NAME_LENGTH;
        int numberLimit = SafetyContractCandidateResponseProcessor.MAX_NUMBER_LENGTH;
        int depthLimit = SafetyContractCandidateResponseProcessor.MAX_DEPTH;
        int tokenLimit = SafetyContractCandidateResponseProcessor.MAX_TOKEN_COUNT;
        ObjectNode accepted = candidate(prompt);
        ObjectNode rejected = candidate(prompt);
        String acceptedRaw;
        String rejectedRaw;
        switch (limit) {
            case "string" -> {
                accepted.put("unexpected", "x".repeat(stringLimit));
                rejected.put("unexpected", "x".repeat(stringLimit + 1));
                acceptedRaw = mapper.writeValueAsString(accepted);
                rejectedRaw = mapper.writeValueAsString(rejected);
            }
            case "name" -> {
                accepted.put("x".repeat(nameLimit), true);
                rejected.put("x".repeat(nameLimit + 1), true);
                acceptedRaw = mapper.writeValueAsString(accepted);
                rejectedRaw = mapper.writeValueAsString(rejected);
            }
            case "number" -> {
                ((ObjectNode) accepted.at("/cardinality/CUSTOMER_DATA_READ"))
                        .put("maxRequestedRecords", new BigInteger("9".repeat(numberLimit)));
                ((ObjectNode) rejected.at("/cardinality/CUSTOMER_DATA_READ"))
                        .put("maxRequestedRecords", new BigInteger("9".repeat(numberLimit + 1)));
                acceptedRaw = mapper.writeValueAsString(accepted);
                rejectedRaw = mapper.writeValueAsString(rejected);
            }
            case "depth" -> {
                acceptedRaw = nestedArrays(depthLimit - 1);
                rejectedRaw = nestedArrays(depthLimit);
            }
            case "tokens" -> {
                acceptedRaw = manyTokens(tokenLimit - 16);
                rejectedRaw = manyTokens(tokenLimit);
            }
            default -> throw new AssertionError(limit);
        }
        assertThat(rejectedRaw.getBytes(StandardCharsets.UTF_8).length)
                .isLessThan(SafetyContractCandidateResponseProcessor.MAX_RESPONSE_BYTES);
        var unusedCanonical = mock(SafetyContractCanonicalizer.class);
        var subject = new SafetyContractCandidateResponseProcessor(semantic, unusedCanonical);

        var belowLimit = subject.process(prompt, acceptedRaw);

        assertThat(belowLimit.validation().status()).isEqualTo(ValidationStatus.INVALID);
        assertThat(belowLimit.canonicalPolicy()).isEmpty();
        expect(subject, FailureCode.MALFORMED_RESPONSE, prompt, rejectedRaw);
        verifyNoInteractions(unusedCanonical);
    }

    @Test
    void warnWithoutErrorsCanHaveCanonicalPolicyUsingExplicitValidatorSeam() {
        // The current financial validator emits no warnings; this mocks only its documented WARN outcome.
        var warningValidator = mock(SafetyContractSemanticValidator.class);
        var warning = new Issue("/metadata", "FUTURE_WARNING", IssueSeverity.WARNING, "Review required");
        when(warningValidator.validate(any(JsonNode.class), any(ContractValidationCatalog.class)))
                .thenReturn(ValidationResult.fromIssues(List.of(warning)));
        var subject = new SafetyContractCandidateResponseProcessor(warningValidator, canonicalizer);

        var result = subject.process(prompt, mapper.writeValueAsString(candidate(prompt)));

        assertThat(result.validation().status()).isEqualTo(ValidationStatus.WARN);
        assertThat(result.validation().issues()).containsExactly(warning);
        assertThat(result.canonicalPolicy()).isPresent();
        verify(warningValidator, times(1)).validate(any(JsonNode.class), any(ContractValidationCatalog.class));
        verifyNoMoreInteractions(warningValidator);
    }

    @ParameterizedTest
    @ValueSource(strings = {"validatorThrows", "validatorNull", "canonicalizerThrows", "canonicalizerNull"})
    void engineFailuresRemainSafeOperationalFailuresWithNoRetries(String failure) {
        var engine = mock(SafetyContractSemanticValidator.class);
        var hashing = mock(SafetyContractCanonicalizer.class);
        var subject = new SafetyContractCandidateResponseProcessor(engine, hashing);
        when(engine.validate(any(JsonNode.class), any(ContractValidationCatalog.class)))
                .thenReturn(ValidationResult.fromIssues(List.of()));
        switch (failure) {
            case "validatorThrows" -> when(engine.validate(any(JsonNode.class), any(ContractValidationCatalog.class)))
                    .thenThrow(new IllegalStateException(SECRET));
            case "validatorNull" -> when(engine.validate(any(JsonNode.class), any(ContractValidationCatalog.class)))
                    .thenReturn(null);
            case "canonicalizerThrows" -> when(hashing.canonicalizeAndHash(any(JsonNode.class)))
                    .thenThrow(new IllegalStateException(SECRET));
            case "canonicalizerNull" -> when(hashing.canonicalizeAndHash(any(JsonNode.class))).thenReturn(null);
            default -> throw new AssertionError(failure);
        }

        expect(subject, FailureCode.PROCESSING_FAILURE, prompt, mapper.writeValueAsString(candidate(prompt)));

        verify(engine, times(1)).validate(any(JsonNode.class), any(ContractValidationCatalog.class));
        verifyNoMoreInteractions(engine);
        if (failure.startsWith("validator")) {
            verifyNoInteractions(hashing);
        } else {
            verify(hashing, times(1)).canonicalizeAndHash(any(JsonNode.class));
            verifyNoMoreInteractions(hashing);
        }
    }

    @Test
    void resultsExposeDefensivePoliciesAndImmutableIssuesWithoutRawToString() {
        ObjectNode candidate = candidate(prompt);
        candidate.put("purpose", SECRET);
        var result = processor.process(prompt, mapper.writeValueAsString(candidate));
        String original = mapper.writeValueAsString(result.policy());
        ((ObjectNode) result.policy()).put("contractId", "changed");
        ((ArrayNode) result.policy().path("allowedTools")).removeAll();
        ((ObjectNode) result.prompt().source().templateRules()).removeAll();

        assertThat(mapper.writeValueAsString(result.policy())).isEqualTo(original);
        assertThat(result.prompt().source().templateRules().size()).isGreaterThan(0);
        assertThatThrownBy(() -> result.validation().issues().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThat(result.toString()).doesNotContain(SECRET, original, "review-contract");
        assertThat(result.canonicalPolicy()).isEmpty();
        expect(FailureCode.MALFORMED_RESPONSE, prompt, "{\"secret\":\"" + SECRET + "\",");
    }

    private ObjectNode candidate(CandidatePrompt sourcePrompt) {
        return (ObjectNode) mapper.readTree(sourcePrompt.inputJson()).path("financialTemplate");
    }

    private void replace(ObjectNode root, String pointer, JsonNode value) {
        int separator = pointer.lastIndexOf('/');
        ((ObjectNode) root.at(pointer.substring(0, separator))).set(pointer.substring(separator + 1), value);
    }

    private static String nestedArrays(int arrayDepth) {
        return "{\"contractId\":\"review-contract\",\"version\":7,\"unexpected\":"
                + "[".repeat(arrayDepth) + "0" + "]".repeat(arrayDepth) + "}";
    }

    private static String manyTokens(int elements) {
        return "{\"contractId\":\"review-contract\",\"version\":7,\"unexpected\":["
                + "0,".repeat(elements - 1) + "0]}";
    }

    private static void reverse(ArrayNode array) {
        List<JsonNode> values = new ArrayList<>();
        array.forEach(values::add);
        Collections.reverse(values);
        array.removeAll();
        values.forEach(array::add);
    }

    private void expect(FailureCode code, CandidatePrompt sourcePrompt, String raw) {
        expect(processor, code, sourcePrompt, raw);
    }

    private void expect(SafetyContractCandidateResponseProcessor subject, FailureCode code,
            CandidatePrompt sourcePrompt, String raw) {
        assertThatThrownBy(() -> subject.process(sourcePrompt, raw))
                .isInstanceOfSatisfying(CandidateResponseException.class, exception -> {
                    assertThat(exception.code()).isEqualTo(code);
                    assertThat(exception.getCause()).isNull();
                    assertThat(exception.getSuppressed()).isEmpty();
                }).hasMessage("Contract candidate response could not be processed: " + code.name())
                .hasMessageNotContaining(SECRET);
    }
}
