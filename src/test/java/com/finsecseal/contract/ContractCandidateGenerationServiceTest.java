package com.finsecseal.contract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ReleaseLifecycleState;
import com.finsecseal.contract.ContractCandidateGenerationService.CandidateGenerationException;
import com.finsecseal.contract.ContractCandidateGenerationService.FailureCode;
import com.finsecseal.contract.SafetyContractCandidatePromptBuilder.CandidatePromptException;
import com.finsecseal.contract.SafetyContractCandidateResponseProcessor.CandidateResponseException;
import com.finsecseal.contract.SafetyContractGenerationSourceService.GenerationSourceException;
import com.finsecseal.contract.SafetyContractGenerationSourceService.PreparedGenerationSource;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionIdentity;
import com.finsecseal.contract.SafetyContractSemanticValidator.*;
import com.finsecseal.evidence.RedactionService;
import com.finsecseal.release.AgentReleaseEntity;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.ReleaseDto.ToolCatalogResponse;
import com.finsecseal.release.ReleaseService;
import com.finsecseal.runtime.ai.ContractCandidateAiClient;
import com.finsecseal.runtime.ai.ContractCandidateAiClient.CandidateModelResponse;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@ExtendWith(OutputCaptureExtension.class)
class ContractCandidateGenerationServiceTest {
    private static final UUID RELEASE = UUID.fromString("0198f200-0000-7000-8000-000000000301");
    private static final UUID WORKSPACE = UUID.fromString("0198f200-0000-7000-8000-000000000302");
    private static final UUID VERSION = UUID.fromString("0198f200-0000-7000-8000-000000000303");
    private static final VersionIdentity IDENTITY = new VersionIdentity(VERSION, WORKSPACE, RELEASE, "worker-contract", 7);
    private static final String ACTOR = "c-worker-test";
    private static final String CANARY = "WORKER-PRIVATE-CONTENT-CANARY";
    private static final Instant ANALYZED = Instant.parse("2026-09-07T00:00:00Z");
    private final ObjectMapper json = new ObjectMapper();
    private final DigestService digests = new DigestService();
    private SafetyContractGenerationSourceService sources;
    private SafetyContractGenerationSourceService actualSources;
    private SafetyContractCandidatePromptBuilder prompts;
    private SafetyContractCandidateResponseProcessor responses;
    private SafetyContractCanonicalizer canonicalizer;
    private ContractCandidateAiClient models;
    private RedactionService redaction;
    private ContractCandidateGenerationService service;
    private PreparedGenerationSource prepared;
    private ObjectNode manifest;

    @BeforeEach
    void realCComponentsWithExplicitOwnerAndModelDoubles() throws Exception {
        var canonical = new CanonicalJsonService(json);
        var schema = new SafetyContractSchemaValidator();
        canonicalizer = new SafetyContractCanonicalizer(schema, canonical, digests);
        redaction = spy(new RedactionService(json, canonical, digests, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        try (var input = getClass().getResourceAsStream("/fixtures/valid-release-manifest-v1.1.json")) {
            manifest = (ObjectNode) json.readTree(input);
        }
        ((ObjectNode) manifest.path("systemPrompt")).put("text", CANARY);
        ReleaseService releases = mock(ReleaseService.class);
        AgentReleaseEntity release = mock(AgentReleaseEntity.class);
        when(releases.toolCatalog(RELEASE, ACTOR)).thenAnswer(ignored -> {
            var wrapper = json.createObjectNode().set("serverToolCatalog", manifest.path("serverToolCatalog"));
            String hash = digests.sha256(canonical.canonicalize(canonical.normalizeManifest(wrapper).path("serverToolCatalog")));
            return new ToolCatalogResponse(RELEASE, "1.1", "sha256:" + "a".repeat(64), "sha256:" + "b".repeat(64),
                    hash, manifest.path("tools"), manifest.path("serverToolCatalog"));
        });
        when(releases.getRequired(RELEASE)).thenReturn(release);
        when(release.getId()).thenReturn(RELEASE);
        when(release.getManifestSchemaVersion()).thenReturn("1.1");
        when(release.getAgentArtifactFingerprint()).thenReturn("sha256:" + "a".repeat(64));
        when(release.getReleaseFingerprint()).thenReturn("sha256:" + "b".repeat(64));
        when(release.getBusinessPurpose()).thenReturn(LoanReviewFinancialTemplate.PURPOSE);
        when(release.getAnalyzedAt()).thenReturn(ANALYZED);
        when(release.getLifecycleState()).thenReturn(ReleaseLifecycleState.ANALYZED);
        when(release.getManifestJson()).thenAnswer(ignored -> manifest.deepCopy());
        actualSources = new SafetyContractGenerationSourceService(
                new ReleaseToolCatalogContractAdapter(releases, canonical, digests, json), releases,
                new LoanReviewFinancialTemplate(json), json);
        prepared = actualSources.prepare(RELEASE, LoanReviewFinancialTemplate.KEY, ACTOR);
        sources = mock(SafetyContractGenerationSourceService.class);
        when(sources.prepare(any(), any(), any())).thenReturn(prepared);
        prompts = spy(new SafetyContractCandidatePromptBuilder(json, digests));
        responses = spy(new SafetyContractCandidateResponseProcessor(new SafetyContractSemanticValidator(schema), canonicalizer));
        models = mock(ContractCandidateAiClient.class);
        when(models.generate(any(), any(), any())).thenAnswer(call -> new CandidateModelResponse(
                "local-provider", "local-model", json.readTree((String) call.getArgument(2)).path("financialTemplate").toString(), 7));
        service = subject(responses);
    }

    @AfterEach
    void releaseSyntheticTransactionState() {
        TransactionSynchronizationManager.clear();
    }

    @Test
    void exactIdentityPromptAndSourceBindingSurviveWithoutRawInputRetention(CapturedOutput output) {
        var identity = new VersionIdentity(VERSION, WORKSPACE, RELEASE, "review-e\u0301\r\ninside", 23);
        var result = service.generate(identity, null, ACTOR);
        var outbound = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(models).generate(any(), any(), outbound.capture());
        var input = json.readTree(outbound.getValue());
        assertThat(input.path("identity")).isEqualTo(json.valueToTree(identity));
        assertThat(input.path("manifest")).isEqualTo(prepared.manifestContext());
        assertThat(outbound.getValue()).doesNotContain(CANARY, "[SYNTH_ID:", "[NON_STRING_VALUE]");
        assertThat(result.identity()).isEqualTo(identity);
        assertThat(result.catalogBinding().releaseId()).isEqualTo(RELEASE);
        assertThat(result.catalogBinding().agentArtifactFingerprint()).isEqualTo(prepared.catalog().agentArtifactFingerprint());
        assertThat(result.catalogBinding().releaseFingerprint()).isEqualTo(prepared.catalog().releaseFingerprint());
        assertThat(result.catalogBinding().serverToolCatalogHash()).isEqualTo(prepared.catalog().serverToolCatalogHash());
        assertThat(result.catalogBinding().manifestSchemaVersion()).isEqualTo("1.1");
        assertThat(result.analyzedAt()).isEqualTo(ANALYZED);
        assertThat(result.lifecycleState()).isEqualTo(ReleaseLifecycleState.ANALYZED);
        assertThat(result.templateKey()).isEqualTo(LoanReviewFinancialTemplate.KEY);
        assertThat(result.promptVersion()).isEqualTo(SafetyContractCandidatePromptBuilder.PROMPT_VERSION);
        var expectedPrompt = new SafetyContractCandidatePromptBuilder(json, digests).build(prepared, identity);
        assertThat(result.promptDigest()).isEqualTo(expectedPrompt.promptDigest());
        assertThat(result.validation().status()).isEqualTo(ValidationStatus.VALID);
        assertThat(result.canonicalPolicy()).contains(canonicalizer.canonicalizeAndHash(result.policy()));
        assertThat(result.provider()).isEqualTo("local-provider");
        assertThat(result.model()).isEqualTo("local-model");
        assertThat(result.latencyMs()).isEqualTo(7);
        ((ObjectNode) result.policy()).put("contractId", CANARY);
        assertThat(result.policy().path("contractId").stringValue()).isEqualTo(identity.contractKey());
        assertThatThrownBy(() -> result.validation().issues().add(new Issue("/", "X", IssueSeverity.ERROR, CANARY)))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(result.toString()).doesNotContain(identity.contractKey(), "manifest", CANARY, "local-provider");
        assertThat(output.getAll()).doesNotContain(CANARY);
        verify(sources).prepare(RELEASE, LoanReviewFinancialTemplate.KEY, ACTOR);
        verifyNoMoreInteractions(models, sources);
    }

    // TC-CON-001 all-tools-deny, TC-CON-002 HUMAN_ONLY allowlist, TC-CON-003 undeclared output field.
    @ParameterizedTest
    @CsvSource(delimiter = '|', textBlock = """
            /allowedTools | [] | REQUIRED_TOOL_MISSING
            /allowedTools | ["CASE_CONTEXT_READ","CUSTOMER_DATA_READ","LOAN_POLICY_SEARCH","DOCUMENT_CONTENT_READ","REVIEW_NOTE_WRITE","LOAN_DECISION_UPDATE"] | HUMAN_ONLY_TOOL_ALLOWED
            /fieldPolicy/CUSTOMER_DATA_READ/allowed | ["incomeBand","employmentStatus","undeclaredOutputField"] | FIELD_NOT_IN_TOOL_OUTPUT
            /fieldPolicy/CUSTOMER_DATA_READ/allowed | ["incomeBand"] | REQUIRED_FIELD_MISSING
            /highImpactActions/LOAN_DECISION_UPDATE | "AGENT_ALLOWED" | LOAN_DECISION_POLICY_INVALID
            /unexpected | true | UNKNOWN_FIELD
            /allowedTools | ["CASE_CONTEXT_READ","CASE_CONTEXT_READ"] | DUPLICATE_VALUE
            """)
    void preservesNormativeInvalidPolicyIssues(String pointer, String replacement, String code) {
        var policy = policy();
        int slash = pointer.lastIndexOf('/');
        ((ObjectNode) policy.at(pointer.substring(0, slash))).set(pointer.substring(slash + 1), json.readTree(replacement));
        respond(policy.toString());
        var result = generate();
        assertThat(result.validation().status()).isEqualTo(ValidationStatus.INVALID);
        assertThat(result.validation().issues()).extracting(Issue::code).contains(code);
        assertThat(result.validation().issues()).anyMatch(issue -> issue.code().equals(code) && issue.severity() == IssueSeverity.ERROR);
        assertThat(result.canonicalPolicy()).isEmpty();
        verify(models).generate(any(), any(), any());
        verifyNoMoreInteractions(models);
    }

    @Test
    void supportsWarnThroughExplicitValidatorSeam() {
        // Current financial validator emits no WARN; this tests the documented result contract only.
        var validator = mock(SafetyContractSemanticValidator.class);
        var issue = new Issue("/metadata", "FUTURE_WARNING", IssueSeverity.WARNING, "Review required");
        when(validator.validate(any(), any())).thenReturn(ValidationResult.fromIssues(List.of(issue)));
        var result = subject(new SafetyContractCandidateResponseProcessor(validator, canonicalizer))
                .generate(IDENTITY, "", ACTOR);
        assertThat(result.validation().status()).isEqualTo(ValidationStatus.WARN);
        assertThat(result.validation().issues()).containsExactly(issue);
        assertThat(result.canonicalPolicy()).isPresent();
    }

    @Test
    void storageCompatibleKeyBoundaryAndMaximumIntegerVersionRemainExact() {
        // Worker and A create() use100 UTF-16 units; the standalone builder keeps its broader200 limit.
        var identity = new VersionIdentity(VERSION, WORKSPACE, RELEASE, "k".repeat(100), Integer.MAX_VALUE);
        var result = service.generate(identity, null, ACTOR);
        assertThat(result.identity()).isEqualTo(identity);
        assertThat(result.policy().path("contractId").stringValue()).isEqualTo(identity.contractKey());
        assertThat(result.policy().path("version").bigIntegerValue())
                .isEqualTo(java.math.BigInteger.valueOf(Integer.MAX_VALUE));
        var captured = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(models).generate(any(), any(), captured.capture());
        assertThat(json.readTree(captured.getValue()).path("identity")).isEqualTo(json.valueToTree(identity));
        clearInvocations(sources, prompts, models, responses, redaction);
        expect(() -> service.generate(new VersionIdentity(VERSION, WORKSPACE, RELEASE, "k".repeat(101), 1), null, ACTOR),
                FailureCode.INVALID_REQUEST);
        verifyNoInteractions(sources, prompts, models, responses, redaction);
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "versionId", "workspaceId", "releaseId", "zero", "keyNull", "keyBlank", "keySpace", "keyLong", "actorNull", "actorBlank", "actorSpace", "actorLong"})
    void rejectsBadOwnerInputsBeforeAnyDependency(String variation) {
        VersionIdentity identity = switch (variation) {
            case "null" -> null;
            case "versionId" -> new VersionIdentity(null, WORKSPACE, RELEASE, "key", 1);
            case "workspaceId" -> new VersionIdentity(VERSION, null, RELEASE, "key", 1);
            case "releaseId" -> new VersionIdentity(VERSION, WORKSPACE, null, "key", 1);
            case "zero" -> new VersionIdentity(VERSION, WORKSPACE, RELEASE, "key", 0);
            case "keyNull" -> new VersionIdentity(VERSION, WORKSPACE, RELEASE, null, 1);
            case "keyBlank" -> new VersionIdentity(VERSION, WORKSPACE, RELEASE, " ", 1);
            case "keySpace" -> new VersionIdentity(VERSION, WORKSPACE, RELEASE, " key", 1);
            case "keyLong" -> new VersionIdentity(VERSION, WORKSPACE, RELEASE, "x".repeat(101), 1);
            default -> IDENTITY;
        };
        String actor = switch (variation) {
            case "actorNull" -> null;
            case "actorBlank" -> " ";
            case "actorSpace" -> "actor ";
            case "actorLong" -> "x".repeat(121);
            default -> ACTOR;
        };
        expect(() -> service.generate(identity, null, actor), FailureCode.INVALID_REQUEST);
        verifyNoInteractions(sources, prompts, models, responses, redaction);
    }

    @Test
    void unsupportedTemplateAndMismatchedSourceFailBeforeModel() {
        doAnswer(call -> actualSources.prepare(call.getArgument(0), call.getArgument(1), call.getArgument(2)))
                .when(sources).prepare(any(), any(), any());
        assertThatThrownBy(() -> service.generate(IDENTITY, "unsupported", ACTOR))
                .isInstanceOfSatisfying(GenerationSourceException.class,
                        e -> assertThat(e.code().name()).isEqualTo("UNSUPPORTED_TEMPLATE"));
        doReturn(prepared).when(sources).prepare(any(), any(), any());
        var foreign = new VersionIdentity(VERSION, WORKSPACE, UUID.randomUUID(), "key", 1);
        assertThatThrownBy(() -> service.generate(foreign, null, ACTOR))
                .isInstanceOfSatisfying(CandidatePromptException.class,
                        e -> assertThat(e.code().name()).isEqualTo("RELEASE_BINDING_MISMATCH"));
        verifyNoInteractions(models, responses);
    }

    @ParameterizedTest
    @ValueSource(strings = {"transaction", "synchronization", "sourceLeavesTransaction", "promptLeavesSynchronization"})
    void rejectsAmbientAndLeakedTransactionsBeforeModel(String variation) {
        switch (variation) {
            case "transaction" -> TransactionSynchronizationManager.setActualTransactionActive(true);
            case "synchronization" -> TransactionSynchronizationManager.initSynchronization();
            case "sourceLeavesTransaction" -> doAnswer(call -> {
                TransactionSynchronizationManager.setActualTransactionActive(true); return prepared;
            }).when(sources).prepare(any(), any(), any());
            default -> doAnswer(call -> {
                var prompt = call.callRealMethod();
                TransactionSynchronizationManager.initSynchronization(); return prompt;
            }).when(prompts).build(any(), any());
        }
        expect(this::generate, FailureCode.UNSAFE_TRANSACTION);
        verifyNoInteractions(models, responses);
        if (variation.equals("transaction") || variation.equals("synchronization")) verifyNoInteractions(sources, prompts);
    }

    @ParameterizedTest
    @ValueSource(strings = {"sourceThrow", "sourceNull", "promptThrow", "promptNull", "modelThrow", "modelNull", "processorThrow", "processorNull", "redactorThrow", "redactorNull"})
    void normalizesDependencyFailuresWithoutContentOrRetries(String stage, CapturedOutput output) {
        var failure = new IllegalStateException(CANARY, new RuntimeException(CANARY));
        FailureCode expected = switch (stage) {
            case "sourceThrow", "sourceNull" -> FailureCode.SOURCE_UNAVAILABLE;
            case "modelThrow" -> FailureCode.MODEL_CALL_FAILURE;
            case "modelNull" -> FailureCode.MODEL_RESPONSE_INVALID;
            default -> FailureCode.PROCESSING_FAILURE;
        };
        switch (stage) {
            case "sourceThrow" -> doThrow(failure).when(sources).prepare(any(), any(), any());
            case "sourceNull" -> doReturn(null).when(sources).prepare(any(), any(), any());
            case "promptThrow" -> doThrow(failure).when(prompts).build(any(), any());
            case "promptNull" -> doReturn(null).when(prompts).build(any(), any());
            case "modelThrow" -> doThrow(failure).when(models).generate(any(), any(), any());
            case "modelNull" -> doReturn(null).when(models).generate(any(), any(), any());
            case "processorThrow" -> doThrow(failure).when(responses).process(any(), any());
            case "processorNull" -> doReturn(null).when(responses).process(any(), any());
            case "redactorThrow" -> doThrow(failure).when(redaction).redact(any());
            case "redactorNull" -> doReturn(null).when(redaction).redact(any());
        }
        expect(this::generate, expected);
        verify(models, times(stage.startsWith("model") || stage.startsWith("processor") ? 1 : 0)).generate(any(), any(), any());
        assertThat(output.getAll()).doesNotContain(CANARY);
    }

    @ParameterizedTest
    @ValueSource(strings = {"providerNull", "providerBlank", "providerLong", "modelNull", "modelBlank", "modelLong", "negativeLatency"})
    void rejectsBadModelMetadata(String variation) {
        String provider = switch (variation) { case "providerNull" -> null; case "providerBlank" -> " "; case "providerLong" -> "p".repeat(81); default -> "provider"; };
        String model = switch (variation) { case "modelNull" -> null; case "modelBlank" -> " "; case "modelLong" -> "m".repeat(121); default -> "model"; };
        doReturn(new CandidateModelResponse(provider, model, policy().toString(), variation.equals("negativeLatency") ? -1 : 0))
                .when(models).generate(any(), any(), any());
        expect(this::generate, FailureCode.MODEL_RESPONSE_INVALID);
        verifyNoInteractions(responses);
    }

    @Test
    void modelMetadataUsesCodePointsAndPreservesExactStrings() {
        String provider = "\ud83d\ude00".repeat(80), model = "\ud83d\ude00".repeat(120);
        doReturn(new CandidateModelResponse(provider, model, policy().toString(), 0)).when(models).generate(any(), any(), any());
        var result = generate();
        assertThat(result.provider()).isEqualTo(provider);
        assertThat(result.model()).isEqualTo(model);
    }

    @ParameterizedTest
    @ValueSource(strings = {"malformed", "oversized", "identity", "null"})
    void retainsStrictResponseFailureCodes(String kind) {
        String content = switch (kind) {
            case "malformed" -> "```json\n" + CANARY;
            case "oversized" -> "x".repeat(65_537);
            case "identity" -> policy().put("version", 8).toString();
            default -> null;
        };
        respond(content);
        String code = switch (kind) { case "malformed" -> "MALFORMED_RESPONSE"; case "oversized" -> "RESPONSE_TOO_LARGE"; case "identity" -> "IDENTITY_MISMATCH"; default -> "INVALID_REQUEST"; };
        assertThatThrownBy(this::generate).isInstanceOfSatisfying(CandidateResponseException.class, e -> {
            assertThat(e.code().name()).isEqualTo(code);
            assertThat(e.getMessage()).doesNotContain(CANARY);
            assertThat(e.getCause()).isNull();
        });
        verify(models).generate(any(), any(), any());
    }

    @ParameterizedTest
    @ValueSource(strings = {"secretValue", "secretField", "secretArray", "secretFieldName", "nullSecret", "oversized"})
    void guardsEntireOutboundManifestWithoutRewritingSchemas(String kind) {
        var purpose = (ObjectNode) manifest.path("businessPurpose");
        switch (kind) {
            case "secretValue" -> purpose.put("description", "Bearer " + CANARY);
            case "secretField" -> purpose.putObject("authorization");
            case "secretArray" -> purpose.putArray("notes").addArray().add("Bearer " + CANARY);
            case "secretFieldName" -> purpose.put("Bearer " + CANARY, "harmless");
            case "nullSecret" -> purpose.putNull("authorization");
            default -> purpose.put("description", "x".repeat(65_537));
        }
        prepared = actualSources.prepare(RELEASE, LoanReviewFinancialTemplate.KEY, ACTOR);
        doReturn(prepared).when(sources).prepare(any(), any(), any());
        if (kind.equals("nullSecret")) {
            assertThat(generate().validation().status()).isEqualTo(ValidationStatus.VALID);
        } else if (kind.equals("oversized")) {
            expect(this::generate, FailureCode.REQUEST_TOO_LARGE);
            verifyNoInteractions(models);
        } else {
            assertThatThrownBy(this::generate).isInstanceOfSatisfying(BusinessException.class,
                    e -> assertThat(e.errorCode()).isEqualTo(ErrorCode.SECRET_DETECTED));
            verifyNoInteractions(models);
        }
    }

    @Test
    void disabledConfigurationDoesNotRegisterWorker() {
        new ApplicationContextRunner().withUserConfiguration(ContractCandidateGenerationService.class)
                .withPropertyValues("finsec.ai.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(ContractCandidateGenerationService.class));
    }

    private ContractCandidateGenerationService subject(SafetyContractCandidateResponseProcessor processor) {
        return new ContractCandidateGenerationService(sources, prompts, processor, models, json, redaction);
    }

    private ContractCandidateGenerationService.CandidateGenerationResult generate() {
        return service.generate(IDENTITY, LoanReviewFinancialTemplate.KEY, ACTOR);
    }

    private ObjectNode policy() {
        return ((ObjectNode) prepared.templateRules()).put("contractId", IDENTITY.contractKey()).put("version", IDENTITY.version());
    }

    private void respond(String content) {
        doReturn(new CandidateModelResponse("local-provider", "local-model", content, 7)).when(models).generate(any(), any(), any());
    }

    private void expect(org.assertj.core.api.ThrowableAssert.ThrowingCallable action, FailureCode code) {
        assertThatThrownBy(action).isInstanceOfSatisfying(CandidateGenerationException.class, e -> {
            assertThat(e.code()).isEqualTo(code);
            assertThat(e.getMessage()).isEqualTo("Contract candidate generation failed: " + code.name());
            assertThat(e.getMessage()).doesNotContain(CANARY);
            assertThat(e.getCause()).isNull();
            assertThat(e.getSuppressed()).isEmpty();
        });
    }
}
