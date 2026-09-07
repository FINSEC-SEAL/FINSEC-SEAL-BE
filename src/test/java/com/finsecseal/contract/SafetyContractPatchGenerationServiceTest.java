package com.finsecseal.contract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ReleaseLifecycleState;
import com.finsecseal.contract.SafetyContractGenerationSourceService.GenerationSourceException;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.SourceBinding;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionState;
import com.finsecseal.contract.SafetyContractPatchGenerationService.FailureCode;
import com.finsecseal.contract.SafetyContractPatchGenerationService.PatchGenerationException;
import com.finsecseal.contract.SafetyContractPatchGenerationSourceService.PatchGenerationSourceException;
import com.finsecseal.contract.SafetyContractPatchGenerationSourceService.PreparedPatchGenerationSource;
import com.finsecseal.contract.SafetyContractPatchPromptBuilder.PatchPromptException;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.FindingSourceFacts;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.Status;
import com.finsecseal.contract.SafetyContractPatchResponseProcessor.PatchResponseException;
import com.finsecseal.evidence.RedactionService;
import com.finsecseal.platform.contract.ContractPersistenceService;
import com.finsecseal.platform.contract.ContractPersistenceService.Version;
import com.finsecseal.platform.contract.PatchSourceService;
import com.finsecseal.platform.contract.PatchSourceService.PatchSource;
import com.finsecseal.release.AgentReleaseEntity;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.ReleaseDto.ToolCatalogResponse;
import com.finsecseal.release.ReleaseService;
import com.finsecseal.runtime.ai.ContractCandidateAiClient;
import com.finsecseal.runtime.ai.ContractCandidateAiClient.CandidateModelResponse;
import java.sql.Connection;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/** Local composition tests; only the separate PostgreSQL suite proves physical commit and lock release. */
class SafetyContractPatchGenerationServiceTest {
    private static final UUID RELEASE = UUID.fromString("0198f200-0000-7000-8000-000000000601");
    private static final UUID WORKSPACE = UUID.fromString("0198f200-0000-7000-8000-000000000602");
    private static final UUID BASE = UUID.fromString("0198f200-0000-7000-8000-000000000603");
    private static final UUID FINDING = UUID.fromString("0198f200-0000-7000-8000-000000000604");
    private static final UUID RUN = UUID.fromString("0198f200-0000-7000-8000-000000000605");
    private static final UUID CASE = UUID.fromString("0198f200-0000-7000-8000-000000000606");
    private static final UUID ORACLE = UUID.fromString("0198f200-0000-7000-8000-000000000607");
    private static final String CANARY = "PATCH-GENERATION-PRIVATE-CANARY";
    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final String ARTIFACT = "sha256:" + "b".repeat(64);
    private static final String FINGERPRINT = "sha256:" + "c".repeat(64);
    private static final Instant ANALYZED = Instant.parse("2026-09-07T13:00:00Z");
    private static final ReviewerContext REVIEWER = new ReviewerContext(WORKSPACE, "patch-generation-test",
            "AI_SECURITY_REVIEWER", "PATCH-GENERATION-PRIVATE-SESSION", true, true, false);

    private ObjectMapper json;
    private CanonicalJsonService canonical;
    private DigestService digests;
    private SafetyContractCanonicalizer canonicalizer;
    private RedactionService redaction;
    private SafetyContractPatchPromptBuilder builder;
    private SafetyContractPatchResponseProcessor processor;
    private SafetyContractPatchGenerationSourceService sourceService;
    private SafetyContractPatchGenerationSourceService actualPreparation;
    private ContractCandidateAiClient client;
    private SafetyContractPatchGenerationService service;
    private PatchSourceService ownerSources;
    private ContractPersistenceService contracts;
    private ReleaseService releases;
    private ObjectNode policy;
    private ObjectNode evidence;
    private ObjectNode manifest;
    private PreparedPatchGenerationSource prepared;

    @BeforeEach
    void createRealLocalComponentsAndPreparedSourceWithExplicitOwnerDoubles() throws Exception {
        json = new ObjectMapper();
        canonical = new CanonicalJsonService(json);
        digests = new DigestService();
        var schema = new SafetyContractSchemaValidator();
        canonicalizer = new SafetyContractCanonicalizer(schema, canonical, digests);
        redaction = new RedactionService(json, canonical, digests, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        builder = spy(new SafetyContractPatchPromptBuilder(json, digests, redaction));
        processor = spy(new SafetyContractPatchResponseProcessor(new SafetyContractPatchProposalPolicy(
                canonicalizer, new SafetyContractNarrowingValidator(schema, canonicalizer), new SafetyContractSemanticValidator(schema))));
        sourceService = mock(SafetyContractPatchGenerationSourceService.class);
        client = mock(ContractCandidateAiClient.class);
        service = new SafetyContractPatchGenerationService(sourceService, builder, client, processor);
        try (var input = getClass().getResourceAsStream("/fixtures/loan-review-safety-contract.json")) {
            policy = ((ObjectNode) json.readTree(input)).put("contractId", "patch-review").put("version", 7);
        }
        try (var input = getClass().getResourceAsStream("/fixtures/valid-release-manifest-v1.1.json")) {
            manifest = (ObjectNode) json.readTree(input);
        }
        ((ObjectNode) manifest.path("systemPrompt")).put("text", CANARY);
        evidence = json.createObjectNode().put("customerId", "PRIVATE-APPLICANT");
        ownerSources = mock(PatchSourceService.class);
        contracts = mock(ContractPersistenceService.class);
        releases = mock(ReleaseService.class);
        AgentReleaseEntity release = mock(AgentReleaseEntity.class);
        when(releases.toolCatalog(RELEASE, REVIEWER.actorId())).thenAnswer(ignored -> new ToolCatalogResponse(
                RELEASE, "1.1", ARTIFACT, FINGERPRINT, catalogHash(), manifest.path("tools"), manifest.path("serverToolCatalog")));
        when(releases.getRequired(RELEASE)).thenReturn(release);
        when(release.getId()).thenReturn(RELEASE);
        when(release.getManifestSchemaVersion()).thenReturn("1.1");
        when(release.getAgentArtifactFingerprint()).thenReturn(ARTIFACT);
        when(release.getReleaseFingerprint()).thenReturn(FINGERPRINT);
        when(release.getBusinessPurpose()).thenReturn(LoanReviewFinancialTemplate.PURPOSE);
        when(release.getAnalyzedAt()).thenReturn(ANALYZED);
        when(release.getLifecycleState()).thenReturn(ReleaseLifecycleState.ANALYZED);
        when(release.getManifestJson()).thenAnswer(ignored -> manifest.deepCopy());
        var generation = new SafetyContractGenerationSourceService(
                new ReleaseToolCatalogContractAdapter(releases, canonical, digests, json),
                releases, new LoanReviewFinancialTemplate(json), json);
        actualPreparation = new SafetyContractPatchGenerationSourceService(ownerSources, contracts, generation, json);
        when(ownerSources.find(FINDING, REVIEWER)).thenAnswer(ignored -> new PatchSource(
                new FindingSourceFacts(FINDING, WORKSPACE, RELEASE, "OPEN", "SEED", false,
                        digests.sha256(canonical.canonicalize(evidence)), "INV-01"), RUN, CASE, ORACLE, evidence.deepCopy()));
        when(contracts.find(BASE, REVIEWER)).thenAnswer(ignored -> new Version(BASE, WORKSPACE, RELEASE,
                policy.path("contractId").stringValue(), policy.path("version").intValue(), "CANDIDATE", policy.deepCopy(),
                canonicalizer.canonicalizeAndHash(policy).policyHash(), HASH, null, json.createObjectNode(), json.createObjectNode()));
        bindPreparedSource();
        when(client.generate(any(), any(), any())).thenAnswer(ignored -> model(response(policy, json.createArrayNode())));
    }

    @AfterEach
    void clearUnitTransactionMetadata() { TransactionSynchronizationManager.clear(); }

    @Test
    void generatesAProposalUsingExactPromptAndPreparedBindingsWithoutAuthorityWrites() {
        ObjectNode narrow = policy.deepCopy().put("version", 8);
        ((ArrayNode) policy.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed")).add("accountNumber");
        bindPreparedSource();
        String content = response(narrow, narrowFields());
        var prompt = builder.build(prepared);
        clearInvocations(builder);
        when(client.generate(any(), any(), any())).thenAnswer(invocation -> {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isFalse();
            assertThat(invocation.getArgument(0, String.class)).isEqualTo(prompt.promptVersion());
            assertThat(invocation.getArgument(1, String.class)).isEqualTo(prompt.instructions());
            assertThat(invocation.getArgument(2, String.class)).isEqualTo(prompt.inputJson()).doesNotContain("PRIVATE-APPLICANT", CANARY);
            return model(content);
        });

        var result = service.generate(FINDING, BASE, REVIEWER);

        assertThat(result.assessment().decision().status()).isEqualTo(Status.PROPOSED);
        assertThat(result.assessment().decision().acceptedProposal()).hasValueSatisfying(accepted -> {
            assertThat(accepted.baseIdentity()).isEqualTo(prepared.base().identity());
            assertThat(accepted.basePolicyHash()).isEqualTo(prepared.base().policyHash());
            assertThat(accepted.resultPolicy()).isEqualTo(canonicalizer.canonicalizeAndHash(narrow));
        });
        assertThat(result.finding()).isEqualTo(prepared.finding());
        assertThat(result.sourceRunId()).isEqualTo(RUN);
        assertThat(result.sourceCaseId()).isEqualTo(CASE);
        assertThat(result.oracleResultId()).isEqualTo(ORACLE);
        assertThat(result.baseIdentity()).isEqualTo(prepared.base().identity());
        assertThat(result.baseState()).isEqualTo(VersionState.CANDIDATE);
        assertThat(result.basePolicyHash()).isEqualTo(prepared.base().policyHash());
        assertThat(result.baseResourceHash()).isEqualTo(prepared.base().resourceHash());
        assertThat(result.catalogBinding()).isEqualTo(new SourceBinding(RELEASE, "1.1", ARTIFACT, FINGERPRINT, catalogHash()));
        assertThat(result.analyzedAt()).isEqualTo(ANALYZED);
        assertThat(result.templateKey()).isEqualTo(LoanReviewFinancialTemplate.KEY);
        assertThat(result.promptVersion()).isEqualTo(prompt.promptVersion());
        assertThat(result.promptDigest()).isEqualTo(prompt.promptDigest());
        assertThat(result.sourceEvidenceDigest()).isEqualTo(prompt.sourceEvidenceDigest());
        assertThat(result.redactedEvidenceDigest()).isEqualTo(prompt.redactedEvidenceDigest());
        assertThat(result.provider()).isEqualTo("unit-provider");
        assertThat(result.model()).isEqualTo("unit-model");
        assertThat(result.latencyMs()).isEqualTo(37);
        verify(sourceService).prepare(FINDING, BASE, REVIEWER);
        verify(builder).build(prepared);
        verify(client).generate(prompt.promptVersion(), prompt.instructions(), prompt.inputJson());
        verify(processor).process(prepared.finding(), prepared.base(), prepared.generation().catalog(), content);
        verifyNoMoreInteractions(sourceService, builder, client, processor);
        verifyNoInteractions(ownerSources, contracts, releases);
        assertThat(result.toString()).doesNotContain(CANARY, content, prompt.inputJson(), "PRIVATE-APPLICANT", REVIEWER.sessionId());
    }

    @Test
    void noChangeKeepsVersionAndAssessmentCollectionsRemainImmutable() {
        var result = service.generate(FINDING, BASE, REVIEWER);
        assertThat(result.assessment().decision().status()).isEqualTo(Status.NO_CHANGE_NEEDED);
        assertThat(result.assessment().candidate().resultPolicy().path("version").intValue()).isEqualTo(7);
        String retainedPolicy = result.assessment().candidate().resultPolicy().toString();
        ((ObjectNode) result.assessment().candidate().resultPolicy()).put("purpose", CANARY);
        ((ObjectNode) prepared.evidence()).put("customerId", CANARY);
        policy.put("purpose", "later fixture mutation");
        assertThat(result.assessment().candidate().resultPolicy().toString()).isEqualTo(retainedPolicy);
        assertThatThrownBy(() -> result.assessment().candidate().operations().add(new SafetyContractPatchOperation.DenyTool("CUSTOMER_DATA_READ")))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> result.assessment().decision().issues().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThat(result.baseIdentity().contractKey()).isEqualTo("patch-review");
        verify(client).generate(any(), any(), any());
        verifyNoMoreInteractions(client);
        verifyNoInteractions(ownerSources, contracts, releases);
    }

    @ParameterizedTest
    @ValueSource(strings = {"TC-PAT-001", "TC-CON-001", "TC-CON-002", "TC-CON-003"})
    void composedGenerationPreservesOriginalSpecificationRejections(String requirement) {
        String expectedSemantic = null;
        String content;
        if (requirement.equals("TC-PAT-001")) {
            ObjectNode expanded = policy.deepCopy().put("version", 8);
            ((ArrayNode) expanded.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed")).add("accountNumber");
            ArrayNode operations = narrowFields();
            ((ArrayNode) operations.get(0).path("retainedValues")).add("accountNumber");
            content = response(expanded, operations);
        } else {
            switch (requirement) {
                case "TC-CON-001" -> {
                    policy.putArray("allowedTools");
                    expectedSemantic = "REQUIRED_TOOL_MISSING";
                }
                case "TC-CON-002" -> {
                    ((ArrayNode) policy.path("allowedTools")).add("LOAN_DECISION_UPDATE");
                    expectedSemantic = "HUMAN_ONLY_TOOL_ALLOWED";
                }
                case "TC-CON-003" -> {
                    ((ArrayNode) policy.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed")).add("undeclaredField");
                    expectedSemantic = "FIELD_NOT_IN_TOOL_OUTPUT";
                }
                default -> throw new AssertionError(requirement);
            }
            bindPreparedSource();
            content = response(policy, json.createArrayNode());
        }
        when(client.generate(any(), any(), any())).thenReturn(model(content));

        var result = service.generate(FINDING, BASE, REVIEWER);

        assertThat(result.assessment().decision().status()).isEqualTo(Status.INVALID);
        assertThat(result.assessment().decision().acceptedProposal()).isEmpty();
        if (expectedSemantic == null) {
            assertThat(result.assessment().decision().narrowing().orElseThrow().valid()).isFalse();
        } else {
            assertThat(result.assessment().decision().semantic().orElseThrow().issues())
                    .extracting(SafetyContractSemanticValidator.Issue::code).contains(expectedSemantic);
        }
        verify(client).generate(any(), any(), any());
        verifyNoMoreInteractions(client);
        verifyNoInteractions(ownerSources, contracts, releases);
    }

    @ParameterizedTest
    @ValueSource(strings = {"nullFinding", "nullBase", "nullReviewer"})
    void missingRequestInputsFailBeforeDependencies(String field) {
        expect(FailureCode.INVALID_REQUEST, () -> service.generate(field.equals("nullFinding") ? null : FINDING,
                field.equals("nullBase") ? null : BASE, field.equals("nullReviewer") ? null : REVIEWER));
        verifyNoInteractions(sourceService, builder, client, processor);
    }

    @ParameterizedTest
    @ValueSource(strings = {"entryActual", "entrySync", "sourceActual", "sourceSync", "promptActual", "promptSync"})
    void rejectsAmbientTransactionAtEachBoundaryBeforeTheNextDependency(String position) {
        Runnable activate = position.endsWith("Actual")
                ? () -> TransactionSynchronizationManager.setActualTransactionActive(true)
                : TransactionSynchronizationManager::initSynchronization;
        if (position.startsWith("entry")) {
            activate.run();
        } else if (position.startsWith("source")) {
            when(sourceService.prepare(FINDING, BASE, REVIEWER)).thenAnswer(ignored -> {
                activate.run();
                return prepared;
            });
        } else {
            doAnswer(invocation -> {
                Object prompt = invocation.callRealMethod();
                activate.run();
                return prompt;
            }).when(builder).build(prepared);
        }
        expect(FailureCode.UNSAFE_TRANSACTION, () -> service.generate(FINDING, BASE, REVIEWER));
        verifyNoInteractions(client, processor);
        if (position.startsWith("entry")) verifyNoInteractions(sourceService, builder);
        else {
            verify(sourceService).prepare(FINDING, BASE, REVIEWER);
            if (position.startsWith("source")) verifyNoInteractions(builder);
            else verify(builder).build(prepared);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"ownerBusiness", "sourceDomain", "generationDomain"})
    void preservesSafeSourceDomainFailuresWithoutPromptOrModelCalls(String kind) {
        RuntimeException failure;
        if (kind.equals("ownerBusiness")) {
            failure = new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "Eligible patch source not found");
        } else if (kind.equals("sourceDomain")) {
            failure = catchThrowableOfType(PatchGenerationSourceException.class,
                    () -> actualPreparation.prepare(FINDING, BASE, REVIEWER));
        } else {
            var invalidGeneration = new SafetyContractGenerationSourceService(mock(ReleaseToolCatalogContractAdapter.class),
                    mock(ReleaseService.class), new LoanReviewFinancialTemplate(json), json);
            failure = catchThrowableOfType(GenerationSourceException.class,
                    () -> invalidGeneration.prepare(RELEASE, "unsupported", REVIEWER.actorId()));
        }
        assertThat(failure).isNotNull();
        when(sourceService.prepare(FINDING, BASE, REVIEWER)).thenThrow(failure);
        assertThatThrownBy(() -> service.generate(FINDING, BASE, REVIEWER)).isSameAs(failure);
        verify(sourceService).prepare(FINDING, BASE, REVIEWER);
        verifyNoMoreInteractions(sourceService);
        verifyNoInteractions(builder, client, processor);
    }

    @ParameterizedTest
    @ValueSource(strings = {"exception", "null"})
    void unexpectedOrMissingSourceFailsSafelyWithoutFallback(String kind) {
        if (kind.equals("exception")) when(sourceService.prepare(FINDING, BASE, REVIEWER)).thenThrow(rawFailure());
        else when(sourceService.prepare(FINDING, BASE, REVIEWER)).thenReturn(null);
        expect(FailureCode.SOURCE_UNAVAILABLE, () -> service.generate(FINDING, BASE, REVIEWER));
        verify(sourceService).prepare(FINDING, BASE, REVIEWER);
        verifyNoMoreInteractions(sourceService);
        verifyNoInteractions(builder, client, processor);
    }

    @Test
    void realRedactionSecretAndPromptDomainFailureStopBeforeAI() {
        evidence.put("password", CANARY);
        bindPreparedSource();
        assertThatThrownBy(() -> service.generate(FINDING, BASE, REVIEWER)).isInstanceOfSatisfying(BusinessException.class, failure -> {
            assertThat(failure.errorCode()).isEqualTo(ErrorCode.SECRET_DETECTED);
            assertSafe(failure);
        });
        verifyNoInteractions(client, processor);
        PatchPromptException failure = catchThrowableOfType(PatchPromptException.class, () -> builder.build(null));
        doThrow(failure).when(builder).build(prepared);
        assertThatThrownBy(() -> service.generate(FINDING, BASE, REVIEWER)).isSameAs(failure);
        verifyNoInteractions(client, processor);
    }

    @ParameterizedTest
    @ValueSource(strings = {"exception", "null"})
    void unexpectedOrMissingPromptFailsWithoutAI(String kind) {
        if (kind.equals("exception")) doThrow(rawFailure()).when(builder).build(prepared);
        else doReturn(null).when(builder).build(prepared);
        expect(FailureCode.PROCESSING_FAILURE, () -> service.generate(FINDING, BASE, REVIEWER));
        verifyNoInteractions(client, processor);
    }

    @ParameterizedTest
    @ValueSource(strings = {"runtime", "business"})
    void modelFailuresAreSanitizedAndNeverRetriedByC(String kind) {
        RuntimeException failure = kind.equals("runtime") ? rawFailure()
                : new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, CANARY);
        when(client.generate(any(), any(), any())).thenThrow(failure);
        expect(FailureCode.MODEL_CALL_FAILURE, () -> service.generate(FINDING, BASE, REVIEWER));
        verify(client).generate(any(), any(), any());
        verifyNoMoreInteractions(client);
        verifyNoInteractions(processor);
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "nullProvider", "blankProvider", "longProvider", "nullModel", "blankModel", "longModel", "negativeLatency"})
    void invalidProviderReportedMetadataFailsBeforeResponseProcessing(String fault) {
        CandidateModelResponse model = switch (fault) {
            case "null" -> null;
            case "nullProvider" -> new CandidateModelResponse(null, "m", "{}", 0);
            case "blankProvider" -> new CandidateModelResponse(" \r\n", "m", "{}", 0);
            case "longProvider" -> new CandidateModelResponse("😀".repeat(81), "m", "{}", 0);
            case "nullModel" -> new CandidateModelResponse("p", null, "{}", 0);
            case "blankModel" -> new CandidateModelResponse("p", " \r\n", "{}", 0);
            case "longModel" -> new CandidateModelResponse("p", "😀".repeat(121), "{}", 0);
            case "negativeLatency" -> new CandidateModelResponse("p", "m", "{}", -1);
            default -> throw new AssertionError(fault);
        };
        when(client.generate(any(), any(), any())).thenReturn(model);
        expect(FailureCode.MODEL_RESPONSE_INVALID, () -> service.generate(FINDING, BASE, REVIEWER));
        verify(client).generate(any(), any(), any());
        verifyNoMoreInteractions(client);
        verifyNoInteractions(processor);
    }

    @Test
    void acceptsExactUnicodeMetadataAtTheWireLimitsAndPreservesZeroLatency() {
        String provider = "😀".repeat(80);
        String model = "😀".repeat(120);
        when(client.generate(any(), any(), any())).thenReturn(new CandidateModelResponse(provider, model,
                response(policy, json.createArrayNode()), 0));
        var boundary = service.generate(FINDING, BASE, REVIEWER);
        assertThat(boundary.provider()).isEqualTo(provider);
        assertThat(boundary.model()).isEqualTo(model);
        assertThat(boundary.latencyMs()).isZero();
        String exact = " provider-cafe\u0301\r\n";
        when(client.generate(any(), any(), any())).thenReturn(new CandidateModelResponse(exact, exact,
                response(policy, json.createArrayNode()), Long.MAX_VALUE));
        var preserved = service.generate(FINDING, BASE, REVIEWER);
        assertThat(preserved.provider()).isEqualTo(exact);
        assertThat(preserved.model()).isEqualTo(exact);
        assertThat(preserved.latencyMs()).isEqualTo(Long.MAX_VALUE);
    }

    @ParameterizedTest
    @ValueSource(strings = {"malformed", "oversized", "authority", "identity", "null", "blank", "plainPolicy"})
    void invalidModelContentKeepsTheActualProcessorFailureWithoutRepairOrRetry(String kind) {
        String content = switch (kind) {
            case "malformed" -> "```json\n{}\n```";
            case "oversized" -> "x".repeat(SafetyContractPatchResponseProcessor.MAX_RESPONSE_BYTES + 1);
            case "authority" -> {
                ObjectNode forged = (ObjectNode) json.readTree(response(policy, json.createArrayNode()));
                yield forged.put("status", "APPROVED").toString();
            }
            case "identity" -> response(policy.deepCopy().put("contractId", "forged"), json.createArrayNode());
            case "null" -> null;
            case "blank" -> " ";
            case "plainPolicy" -> policy.toString();
            default -> throw new AssertionError(kind);
        };
        PatchResponseException expected = catchThrowableOfType(PatchResponseException.class,
                () -> processor.process(prepared.finding(), prepared.base(), prepared.generation().catalog(), content));
        assertThat(expected).isNotNull();
        clearInvocations(processor);
        when(client.generate(any(), any(), any())).thenReturn(model(content));
        assertThatThrownBy(() -> service.generate(FINDING, BASE, REVIEWER)).isInstanceOfSatisfying(PatchResponseException.class,
                failure -> {
                    assertThat(failure.code()).isEqualTo(expected.code());
                    assertSafe(failure);
                });
        verify(client).generate(any(), any(), any());
        verifyNoMoreInteractions(client);
        verify(processor).process(prepared.finding(), prepared.base(), prepared.generation().catalog(), content);
    }

    @Test
    void actualPolicyEngineFailureKeepsTheProcessorDomainCode() {
        SafetyContractPatchProposalPolicy engine = mock(SafetyContractPatchProposalPolicy.class);
        when(engine.evaluate(any(), any(), any(), any())).thenThrow(rawFailure());
        var realProcessor = new SafetyContractPatchResponseProcessor(engine);
        var connected = new SafetyContractPatchGenerationService(sourceService, builder, client, realProcessor);
        assertThatThrownBy(() -> connected.generate(FINDING, BASE, REVIEWER)).isInstanceOfSatisfying(PatchResponseException.class,
                failure -> {
                    assertThat(failure.code()).isEqualTo(SafetyContractPatchResponseProcessor.FailureCode.PROCESSING_FAILURE);
                    assertSafe(failure);
                });
        verify(client).generate(any(), any(), any());
        verifyNoMoreInteractions(client);
    }

    @ParameterizedTest
    @ValueSource(strings = {"exception", "null"})
    void unexpectedOrMissingAssessmentFailsWithoutRetry(String kind) {
        if (kind.equals("exception")) doThrow(rawFailure()).when(processor).process(any(), any(), any(), any());
        else doReturn(null).when(processor).process(any(), any(), any(), any());
        expect(FailureCode.PROCESSING_FAILURE, () -> service.generate(FINDING, BASE, REVIEWER));
        verify(client).generate(any(), any(), any());
        verifyNoMoreInteractions(client);
    }

    @Test
    void conditionalServiceIsAbsentWithoutEnabledAIAndNeedsOnlyItsFourExistingDependencies() {
        // Narrow C activation test, not production B HTTP-client configuration or network startup evidence.
        new ApplicationContextRunner().withUserConfiguration(SafetyContractPatchGenerationService.class)
                .run(context -> assertThat(context).hasNotFailed().doesNotHaveBean(SafetyContractPatchGenerationService.class));
        new ApplicationContextRunner().withUserConfiguration(SafetyContractPatchGenerationService.class)
                .withPropertyValues("finsec.ai.enabled=false")
                .run(context -> assertThat(context).hasNotFailed().doesNotHaveBean(SafetyContractPatchGenerationService.class));
        new ApplicationContextRunner().withUserConfiguration(SafetyContractPatchGenerationService.class)
                .withPropertyValues("finsec.ai.enabled=true")
                .withBean(SafetyContractPatchGenerationSourceService.class, () -> sourceService)
                .withBean(SafetyContractPatchPromptBuilder.class, () -> builder)
                .withBean(ContractCandidateAiClient.class, () -> client)
                .withBean(SafetyContractPatchResponseProcessor.class, () -> processor)
                .run(context -> assertThat(context).hasNotFailed().hasSingleBean(SafetyContractPatchGenerationService.class));
        verifyNoInteractions(sourceService, builder, client, processor);
    }

    private void bindPreparedSource() {
        // Guard metadata enables the actual immutable C preparation path; it does not prove a real DB transaction.
        TransactionSynchronizationManager.setActualTransactionActive(true);
        TransactionSynchronizationManager.setCurrentTransactionReadOnly(false);
        TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(Connection.TRANSACTION_REPEATABLE_READ);
        try {
            prepared = actualPreparation.prepare(FINDING, BASE, REVIEWER);
        } finally {
            TransactionSynchronizationManager.clear();
        }
        when(sourceService.prepare(FINDING, BASE, REVIEWER)).thenReturn(prepared);
        clearInvocations(ownerSources, contracts, releases, sourceService);
    }

    private ArrayNode narrowFields() {
        ObjectNode operation = json.createObjectNode().put("type", "NARROW_SET")
                .put("setKind", "ALLOWED_FIELDS").put("toolName", "CUSTOMER_DATA_READ");
        operation.putArray("retainedValues").add("incomeBand").add("employmentStatus");
        return json.createArrayNode().add(operation);
    }

    private String response(JsonNode result, ArrayNode operations) {
        ObjectNode response = json.createObjectNode();
        response.set("resultPolicy", result);
        response.set("operations", operations);
        return response.put("rootCause", "Observed cross-customer response")
                .put("normalWorkflowImpact", "Keep required loan review fields")
                .put("rollback", "Create a separately reviewed replacement version").toString();
    }

    private CandidateModelResponse model(String content) { return new CandidateModelResponse("unit-provider", "unit-model", content, 37); }

    private String catalogHash() {
        ObjectNode wrapper = json.createObjectNode();
        wrapper.set("serverToolCatalog", manifest.path("serverToolCatalog"));
        return digests.sha256(canonical.canonicalize(canonical.normalizeManifest(wrapper).path("serverToolCatalog")));
    }

    private RuntimeException rawFailure() {
        var failure = new IllegalStateException(CANARY, new RuntimeException(REVIEWER.sessionId()));
        failure.addSuppressed(new RuntimeException(CANARY));
        return failure;
    }

    private void expect(FailureCode code, Runnable action) {
        assertThatThrownBy(action::run).isInstanceOfSatisfying(PatchGenerationException.class, failure -> {
            assertThat(failure.code()).isEqualTo(code);
            assertSafe(failure);
        });
    }

    private void assertSafe(Throwable failure) {
        assertThat(failure.getCause()).isNull();
        assertThat(failure.getSuppressed()).isEmpty();
        var stack = new java.io.StringWriter();
        failure.printStackTrace(new java.io.PrintWriter(stack));
        assertThat(stack.toString()).doesNotContain(CANARY, REVIEWER.sessionId());
    }
}
