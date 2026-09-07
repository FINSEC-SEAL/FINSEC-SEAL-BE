package com.finsecseal.contract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.finsecseal.common.domain.ReleaseLifecycleState;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.SourceBoundCatalog;
import com.finsecseal.contract.SafetyContractGenerationSourceService.FailureCode;
import com.finsecseal.contract.SafetyContractGenerationSourceService.GenerationSourceException;
import com.finsecseal.contract.SafetyContractSemanticValidator.ContractValidationCatalog;
import com.finsecseal.contract.SafetyContractSemanticValidator.EnabledTool;
import com.finsecseal.release.AgentReleaseEntity;
import com.finsecseal.release.ReleaseService;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

class SafetyContractGenerationSourceServiceTest {
    private static final UUID RELEASE = UUID.fromString("0198f200-0000-7000-8000-000000000301");
    private static final UUID OTHER = UUID.fromString("0198f200-0000-7000-8000-000000000399");
    private static final String ACTOR = "role-c-generation";
    private static final String ARTIFACT = "sha256:" + "a".repeat(64);
    private static final String FINGERPRINT = "sha256:" + "b".repeat(64);
    private static final String SECRET = "SOURCE-SECRET-CANARY";
    private static final Instant ANALYZED = Instant.parse("2026-09-07T00:00:00Z");

    private ObjectMapper mapper;
    private ObjectNode manifest;
    private ReleaseToolCatalogContractAdapter catalogs;
    private ReleaseService releases;
    private AgentReleaseEntity entity;
    private SafetyContractGenerationSourceService service;

    @BeforeEach
    void setup() throws Exception {
        mapper = new ObjectMapper();
        try (var input = getClass().getResourceAsStream("/fixtures/valid-release-manifest-v1.1.json")) {
            manifest = (ObjectNode) mapper.readTree(input);
        }
        ((ObjectNode) manifest.path("systemPrompt")).put("text", SECRET);
        catalogs = mock(ReleaseToolCatalogContractAdapter.class);
        releases = mock(ReleaseService.class);
        entity = mock(AgentReleaseEntity.class);
        when(catalogs.load(RELEASE, ACTOR)).thenReturn(catalog(RELEASE));
        when(releases.getRequired(RELEASE)).thenReturn(entity);
        when(entity.getId()).thenReturn(RELEASE);
        when(entity.getManifestSchemaVersion()).thenReturn("1.1");
        when(entity.getAgentArtifactFingerprint()).thenReturn(ARTIFACT);
        when(entity.getReleaseFingerprint()).thenReturn(FINGERPRINT);
        when(entity.getBusinessPurpose()).thenReturn(LoanReviewFinancialTemplate.PURPOSE);
        when(entity.getAnalyzedAt()).thenReturn(ANALYZED);
        when(entity.getLifecycleState()).thenReturn(ReleaseLifecycleState.ANALYZED);
        when(entity.getManifestJson()).thenAnswer(ignored -> manifest.deepCopy());
        service = new SafetyContractGenerationSourceService(catalogs, releases,
                new LoanReviewFinancialTemplate(mapper), mapper);
    }

    @Test
    void preservesActualPolicyInputsAndLoadsTheVerifiedCatalogBeforeTheEntity() {
        var result = prepare();

        assertThat(result.catalog()).isEqualTo(catalog(RELEASE));
        assertThat(result.analyzedAt()).isEqualTo(ANALYZED);
        assertThat(result.templateKey()).isEqualTo("loan-review/1");
        for (String field : List.of("businessPurpose", "businessWorkflow", "networkRequirements",
                "tools", "serverToolCatalog", "humanApprovalBoundaries", "runtimeContextRequirements")) {
            assertThat(result.manifestContext().path(field)).isEqualTo(manifest.path(field));
        }
        assertThat(result.manifestContext().size()).isEqualTo(7);
        assertThat(result.manifestContext().toString()).doesNotContain("systemPrompt", SECRET, "[ENCRYPTED]");
        assertThat(result.toString()).doesNotContain(SECRET);
        assertThat(result.templateRules().has("contractId")).isFalse();
        assertThat(result.templateRules().has("version")).isFalse();
        var order = inOrder(catalogs, releases);
        order.verify(catalogs).load(RELEASE, ACTOR);
        order.verify(releases).getRequired(RELEASE);
        verifyNoMoreInteractions(catalogs, releases);
    }

    @Test
    void callersCannotMutateRetainedSourceOrTemplate() {
        var result = prepare();
        JsonNode before = result.manifestContext();
        ((ObjectNode) result.manifestContext().path("businessPurpose")).put("description", "changed");
        ((ArrayNode) result.manifestContext().path("tools")).removeAll();
        ((ObjectNode) result.templateRules().path("externalEgress")).put("allowed", true);
        ((ObjectNode) manifest.path("businessPurpose")).put("description", "later source change");

        assertThat(result.manifestContext()).isEqualTo(before);
        assertThat(result.templateRules().at("/externalEgress/allowed").asBoolean()).isFalse();
    }

    @ParameterizedTest
    @EnumSource(value = ReleaseLifecycleState.class, names = "DRAFT", mode = EnumSource.Mode.EXCLUDE)
    void acceptsAlreadyAnalyzedLaterLifecycleStates(ReleaseLifecycleState state) {
        when(entity.getLifecycleState()).thenReturn(state);
        assertThat(prepare().lifecycleState()).isEqualTo(state);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", " role-c", "role-c ", "\n"})
    void invalidActorNeverLoadsSource(String actor) {
        expect(FailureCode.INVALID_REQUEST, () -> service.prepare(RELEASE, "loan-review/1", actor));
        verifyNoInteractions(catalogs, releases);
    }

    @Test
    void missingReleaseAndOversizedActorNeverLoadSource() {
        expect(FailureCode.INVALID_REQUEST, () -> service.prepare(null, "loan-review/1", ACTOR));
        expect(FailureCode.INVALID_REQUEST, () -> service.prepare(RELEASE, "loan-review/1", "x".repeat(121)));
        verifyNoInteractions(catalogs, releases);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"loan-review/2", " loan-review/1", "loan-review/1 "})
    void unsupportedTemplateNeverFallsBackOrLoadsSource(String key) {
        expect(FailureCode.UNSUPPORTED_TEMPLATE, () -> service.prepare(RELEASE, key, ACTOR));
        verifyNoInteractions(catalogs, releases);
    }

    @Test
    void invalidCatalogIdentityNeverReadsTheEntity() {
        when(catalogs.load(RELEASE, ACTOR)).thenReturn(catalog(OTHER));
        expect(FailureCode.SOURCE_BINDING_MISMATCH, this::prepare);
        verifyNoInteractions(releases);
    }

    @Test
    void absentCatalogNeverReadsTheEntity() {
        when(catalogs.load(RELEASE, ACTOR)).thenReturn(null);
        expect(FailureCode.SOURCE_BINDING_MISMATCH, this::prepare);
        verifyNoInteractions(releases);
    }

    @ParameterizedTest
    @ValueSource(strings = {"id", "schema", "artifact", "release", "manifestSchema", "absent"})
    void rejectsMixedOrMissingSourceBindings(String changed) {
        switch (changed) {
            case "id" -> when(entity.getId()).thenReturn(OTHER);
            case "schema" -> when(entity.getManifestSchemaVersion()).thenReturn("1.0");
            case "artifact" -> when(entity.getAgentArtifactFingerprint()).thenReturn(FINGERPRINT);
            case "release" -> when(entity.getReleaseFingerprint()).thenReturn(ARTIFACT);
            case "manifestSchema" -> manifest.put("schemaVersion", "1.0");
            case "absent" -> when(releases.getRequired(RELEASE)).thenReturn(null);
            default -> throw new AssertionError(changed);
        }
        expect(FailureCode.SOURCE_BINDING_MISMATCH, this::prepare);
    }

    @ParameterizedTest
    @ValueSource(strings = {"draft", "noTimestamp", "noState"})
    void refusesMissingAnalysisEvenIfOtherSourceFactsMatch(String changed) {
        switch (changed) {
            case "draft" -> when(entity.getLifecycleState()).thenReturn(ReleaseLifecycleState.DRAFT);
            case "noTimestamp" -> when(entity.getAnalyzedAt()).thenReturn(null);
            case "noState" -> when(entity.getLifecycleState()).thenReturn(null);
            default -> throw new AssertionError(changed);
        }
        expect(FailureCode.RELEASE_NOT_ANALYZED, this::prepare);
    }

    @ParameterizedTest
    @ValueSource(strings = {"manifest", "entity"})
    void refusesPurposeMismatchWithoutRewritingTheSource(String changed) {
        if (changed.equals("manifest")) {
            ((ObjectNode) manifest.path("businessPurpose")).put("code", "LOAN_APPROVAL");
        } else {
            when(entity.getBusinessPurpose()).thenReturn("LOAN_APPROVAL");
        }
        expect(FailureCode.UNSUPPORTED_PURPOSE, this::prepare);
    }

    @ParameterizedTest
    @ValueSource(strings = {"businessWorkflow", "networkRequirements", "serverToolCatalog", "tools",
            "humanApprovalBoundaries", "runtimeContextRequirements"})
    void incompleteProjectionDoesNotBecomeAGenerationInput(String field) {
        manifest.remove(field);
        expect(FailureCode.SOURCE_CONTENT_INVALID, this::prepare);
    }

    @Test
    void sourceFailuresAreBoundedAndDoNotExposeCauseTextOrRetry() {
        when(catalogs.load(RELEASE, ACTOR)).thenThrow(new IllegalStateException(SECRET));
        expect(FailureCode.SOURCE_UNAVAILABLE, this::prepare);
        verifyNoInteractions(releases);
        var order = inOrder(catalogs);
        order.verify(catalogs).load(RELEASE, ACTOR);
        verifyNoMoreInteractions(catalogs);
    }

    @Test
    void secondSourceReadFailureCannotProduceAnInputOrExposeItsCause() {
        when(releases.getRequired(RELEASE)).thenThrow(new IllegalStateException(SECRET));
        expect(FailureCode.SOURCE_UNAVAILABLE, this::prepare);
    }

    private SafetyContractGenerationSourceService.PreparedGenerationSource prepare() {
        return service.prepare(RELEASE, "loan-review/1", ACTOR);
    }

    private SourceBoundCatalog catalog(UUID id) {
        return new SourceBoundCatalog(id, "1.1", ARTIFACT, FINGERPRINT, "sha256:" + "c".repeat(64),
                new ContractValidationCatalog(List.of(new EnabledTool("CUSTOMER_DATA_READ",
                        List.of("incomeBand", "employmentStatus"))), List.of("LOAN_DECISION_UPDATE")));
    }

    private void expect(FailureCode code, org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).isInstanceOfSatisfying(GenerationSourceException.class, exception -> {
            assertThat(exception.code()).isEqualTo(code);
            assertThat(exception.getCause()).isNull();
            assertThat(exception.getSuppressed()).isEmpty();
        }).hasMessage("Contract generation source could not be prepared: " + code.name())
                .hasMessageNotContaining(SECRET);
    }
}
