package com.finsecseal.contract;

import static com.finsecseal.contract.ReleaseToolCatalogContractAdapter.FailureCode.CATALOG_ROLE_OVERLAP;
import static com.finsecseal.contract.ReleaseToolCatalogContractAdapter.FailureCode.INVALID_AGENT_ARTIFACT_FINGERPRINT;
import static com.finsecseal.contract.ReleaseToolCatalogContractAdapter.FailureCode.INVALID_ENABLED_TOOL_CATALOG;
import static com.finsecseal.contract.ReleaseToolCatalogContractAdapter.FailureCode.INVALID_HIGH_IMPACT_CATALOG;
import static com.finsecseal.contract.ReleaseToolCatalogContractAdapter.FailureCode.INVALID_RELEASE_FINGERPRINT;
import static com.finsecseal.contract.ReleaseToolCatalogContractAdapter.FailureCode.INVALID_REQUEST;
import static com.finsecseal.contract.ReleaseToolCatalogContractAdapter.FailureCode.INVALID_SERVER_CATALOG_HASH;
import static com.finsecseal.contract.ReleaseToolCatalogContractAdapter.FailureCode.SERVER_CATALOG_HASH_MISMATCH;
import static com.finsecseal.contract.ReleaseToolCatalogContractAdapter.FailureCode.SOURCE_IDENTITY_MISMATCH;
import static com.finsecseal.contract.ReleaseToolCatalogContractAdapter.FailureCode.SOURCE_LOAD_FAILURE;
import static com.finsecseal.contract.ReleaseToolCatalogContractAdapter.FailureCode.SOURCE_UNAVAILABLE;
import static com.finsecseal.contract.ReleaseToolCatalogContractAdapter.FailureCode.UNSUPPORTED_MANIFEST_VERSION;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.CatalogAdapterException;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.FailureCode;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.SourceBoundCatalog;
import com.finsecseal.contract.SafetyContractSemanticValidator.EnabledTool;
import com.finsecseal.contract.SafetyContractSemanticValidator.Issue;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationResult;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationStatus;
import com.finsecseal.policy.PolicyToolTrustFacts.ReleaseToolBinding;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.FingerprintService;
import com.finsecseal.release.ReleaseDto.ToolCatalogResponse;
import com.finsecseal.release.ReleaseService;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

class ReleaseToolCatalogContractAdapterTest {

    private static final UUID RELEASE_ID = UUID.fromString(
            "12345678-1234-4abc-8def-1234567890ab"
    );
    private static final UUID OTHER_RELEASE_ID = UUID.fromString(
            "87654321-4321-4abc-8def-ba0987654321"
    );
    private static final String ACTOR_ID = "role-c-contract-adapter";
    private static final String AGENT_FINGERPRINT = "sha256:" + "a".repeat(64);
    private static final String RELEASE_FINGERPRINT = "sha256:" + "b".repeat(64);
    private static final String AUTHORITATIVE_SERVER_CATALOG_HASH =
            "sha256:8d720bd3b28a0392d1e45a3ff9cf2a75c59db1baee86a37208dc9ba28642938e";
    private static final String RAW_SENTINEL = "RAW-CATALOG-SENTINEL-DO-NOT-EXPOSE";

    private ObjectMapper objectMapper;
    private CanonicalJsonService canonicalJsonService;
    private DigestService digestService;
    private FingerprintService roleAFingerprints;
    private SafetyContractSemanticValidator semanticValidator;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        canonicalJsonService = new CanonicalJsonService(objectMapper);
        digestService = new DigestService();
        roleAFingerprints = new FingerprintService(canonicalJsonService, digestService, objectMapper);
        semanticValidator = new SafetyContractSemanticValidator(
                new SafetyContractSchemaValidator()
        );
    }

    @Test
    void loadsAuthoritativeSourceOnceAndProducesBoundSemanticCatalog() throws IOException {
        ObjectNode manifest = fixture("valid-release-manifest-v1.1.json");
        ToolCatalogResponse source = authoritativeSource(manifest);
        ReleaseService releases = mock(ReleaseService.class);
        when(releases.toolCatalog(RELEASE_ID, ACTOR_ID)).thenReturn(source);

        SourceBoundCatalog result = subject(releases).load(RELEASE_ID, ACTOR_ID);

        assertThat(result.releaseId()).isEqualTo(RELEASE_ID);
        assertThat(result.manifestSchemaVersion()).isEqualTo("1.1");
        assertThat(result.agentArtifactFingerprint()).isEqualTo(AGENT_FINGERPRINT);
        assertThat(result.releaseFingerprint()).isEqualTo(RELEASE_FINGERPRINT);
        assertThat(result.serverToolCatalogHash())
                .isEqualTo(AUTHORITATIVE_SERVER_CATALOG_HASH);
        assertThat(result.semanticCatalog().enabledReleaseTools())
                .extracting(EnabledTool::toolName)
                .containsExactly(
                        "CASE_CONTEXT_READ",
                        "CUSTOMER_DATA_READ",
                        "DOCUMENT_READER",
                        "LOAN_POLICY_SEARCH",
                        "REVIEW_NOTE_WRITE"
                );
        assertThat(enabledTool(result, "CUSTOMER_DATA_READ").outputFields())
                .containsExactly("accountNumber", "employmentStatus", "incomeBand");
        assertThat(result.semanticCatalog().highImpactToolNames())
                .containsExactly("LOAN_DECISION_UPDATE");
        assertThat(result.releaseToolBindings())
                .extracting(ReleaseToolBinding::toolName)
                .containsExactly(
                        "CASE_CONTEXT_READ",
                        "CUSTOMER_DATA_READ",
                        "DOCUMENT_READER",
                        "LOAN_POLICY_SEARCH",
                        "REVIEW_NOTE_WRITE"
                );
        for (ReleaseToolBinding binding : result.releaseToolBindings()) {
            ObjectNode sourceTool = tool(manifest.path("tools"), binding.toolName());
            assertThat(binding.version()).isEqualTo(sourceTool.path("version").stringValue());
            assertThat(binding.enabled()).isTrue();
            assertThat(binding.schemaDigest()).isEqualTo(roleASchemaHash(sourceTool));
            assertThat(binding.descriptionDigest()).isEqualTo(roleADescriptionHash(sourceTool));
        }
        assertThat(semanticValidator.validate(
                fixture("loan-review-safety-contract.json"),
                result.semanticCatalog()
        ).status()).isEqualTo(ValidationStatus.VALID);
        verify(releases).toolCatalog(RELEASE_ID, ACTOR_ID);
        verifyNoMoreInteractions(releases);
    }

    @Test
    void pinsServerCatalogHashToExistingManifestNormalizationPipeline() throws IOException {
        ObjectNode manifest = fixture("valid-release-manifest-v1.1.json");

        assertThat(serverCatalogHash(manifest.path("serverToolCatalog")))
                .isEqualTo(AUTHORITATIVE_SERVER_CATALOG_HASH);
        assertThat(load(authoritativeSource(manifest)).serverToolCatalogHash())
                .isEqualTo(AUTHORITATIVE_SERVER_CATALOG_HASH);
    }

    @Test
    void authoritativeContractRemainsSemanticallyValidThroughProductionAdapter()
            throws IOException {
        SourceBoundCatalog source = load(authoritativeSource(
                fixture("valid-release-manifest-v1.1.json")
        ));

        ValidationResult result = semanticValidator.validate(
                fixture("loan-review-safety-contract.json"),
                source.semanticCatalog()
        );

        assertThat(result.status()).isEqualTo(ValidationStatus.VALID);
        assertThat(result.issues()).isEmpty();
    }

    @Test
    void tcCon001ReportsEveryRequiredToolThroughProductionAdapter() throws IOException {
        SourceBoundCatalog source = load(authoritativeSource(
                fixture("valid-release-manifest-v1.1.json")
        ));
        ObjectNode contract = fixture("loan-review-safety-contract.json");
        ((ArrayNode) contract.path("allowedTools")).removeAll();

        ValidationResult result = semanticValidator.validate(
                contract,
                source.semanticCatalog()
        );

        assertThat(result.status()).isEqualTo(ValidationStatus.INVALID);
        assertThat(result.issues())
                .filteredOn(issue -> issue.code().equals("REQUIRED_TOOL_MISSING"))
                .extracting(Issue::message)
                .containsExactly(
                        "Required loan-review Tool is missing: CASE_CONTEXT_READ",
                        "Required loan-review Tool is missing: CUSTOMER_DATA_READ",
                        "Required loan-review Tool is missing: DOCUMENT_READER",
                        "Required loan-review Tool is missing: LOAN_POLICY_SEARCH",
                        "Required loan-review Tool is missing: REVIEW_NOTE_WRITE"
                );
    }

    @Test
    void tcCon002RejectsExtractedHumanOnlyToolInAgentAllowlist() throws IOException {
        SourceBoundCatalog source = load(authoritativeSource(
                fixture("valid-release-manifest-v1.1.json")
        ));
        ObjectNode contract = fixture("loan-review-safety-contract.json");
        ((ArrayNode) contract.path("allowedTools")).add("LOAN_DECISION_UPDATE");

        ValidationResult result = semanticValidator.validate(
                contract,
                source.semanticCatalog()
        );

        assertThat(result.status()).isEqualTo(ValidationStatus.INVALID);
        assertThat(result.issues()).extracting(Issue::code)
                .contains("HUMAN_ONLY_TOOL_ALLOWED");
    }

    @Test
    void tcCon003RejectsFieldAbsentFromExactCustomerOutputPath() throws IOException {
        SourceBoundCatalog source = load(authoritativeSource(
                fixture("valid-release-manifest-v1.1.json")
        ));
        ObjectNode contract = fixture("loan-review-safety-contract.json");
        ((ArrayNode) contract.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed"))
                .add("notInOutput");

        ValidationResult result = semanticValidator.validate(
                contract,
                source.semanticCatalog()
        );

        assertThat(result.status()).isEqualTo(ValidationStatus.INVALID);
        assertThat(result.issues()).extracting(Issue::code)
                .contains("FIELD_NOT_IN_TOOL_OUTPUT");
    }

    @Test
    void accountNumberIsSchemaPresentButStillExceedsPolicyTemplate() throws IOException {
        SourceBoundCatalog source = load(authoritativeSource(
                fixture("valid-release-manifest-v1.1.json")
        ));
        assertThat(enabledTool(source, "CUSTOMER_DATA_READ").outputFields())
                .contains("accountNumber");
        ObjectNode contract = fixture("loan-review-safety-contract.json");
        ((ArrayNode) contract.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed"))
                .add("accountNumber");

        ValidationResult result = semanticValidator.validate(
                contract,
                source.semanticCatalog()
        );

        assertThat(result.status()).isEqualTo(ValidationStatus.INVALID);
        assertThat(result.issues()).extracting(Issue::code)
                .contains("FIELD_EXCEEDS_TEMPLATE")
                .doesNotContain("FIELD_NOT_IN_TOOL_OUTPUT");
    }

    @Test
    void extractionUsesOnlyTheDocumentedToolSpecificPaths() throws IOException {
        ObjectNode manifest = fixture("valid-release-manifest-v1.1.json");
        ObjectNode customer = tool(manifest.path("tools"), "CUSTOMER_DATA_READ");
        ((ObjectNode) customer.at("/outputSchema/properties"))
                .set("customerTopLevelDecoy", objectMapper.createObjectNode());
        ((ObjectNode) customer.at("/inputSchema/properties"))
                .set("customerInputDecoy", objectMapper.createObjectNode());
        ObjectNode document = tool(manifest.path("tools"), "DOCUMENT_READER");
        ((ObjectNode) document.at("/outputSchema/properties"))
                .set("documentTopLevelField", objectMapper.createObjectNode());
        ((ObjectNode) document.at("/outputSchema/properties/content"))
                .set("nestedDecoy", objectMapper.createObjectNode());

        SourceBoundCatalog result = load(authoritativeSource(manifest));

        assertThat(enabledTool(result, "CUSTOMER_DATA_READ").outputFields())
                .containsExactly("accountNumber", "employmentStatus", "incomeBand")
                .doesNotContain(
                        "status",
                        "rows",
                        "customerId",
                        "customerTopLevelDecoy",
                        "customerInputDecoy"
                );
        assertThat(enabledTool(result, "DOCUMENT_READER").outputFields())
                .contains("documentTopLevelField")
                .doesNotContain("nestedDecoy");
    }

    @Test
    void missingExactCustomerPathNeverFallsBackToDecoyProperties() throws IOException {
        ObjectNode manifest = fixture("valid-release-manifest-v1.1.json");
        ObjectNode customer = tool(manifest.path("tools"), "CUSTOMER_DATA_READ");
        ((ObjectNode) customer.at(
                "/outputSchema/properties/rows/items/properties/fields"
        )).remove("properties");
        ((ObjectNode) customer.at("/outputSchema/properties"))
                .set("fallbackDecoy", objectMapper.createObjectNode());

        CatalogAdapterException failure = failureFor(authoritativeSource(manifest));

        assertSafeFailure(failure, INVALID_ENABLED_TOOL_CATALOG);
    }

    @Test
    void snapshotsMutableTreesAndReturnsOnlyUnmodifiableCatalogValues() throws IOException {
        ObjectNode manifest = fixture("valid-release-manifest-v1.1.json");
        ArrayNode tools = (ArrayNode) manifest.path("tools");
        ObjectNode serverCatalog = (ObjectNode) manifest.path("serverToolCatalog");
        ToolCatalogResponse source = source(
                RELEASE_ID,
                "1.1",
                AGENT_FINGERPRINT,
                RELEASE_FINGERPRINT,
                AUTHORITATIVE_SERVER_CATALOG_HASH,
                tools,
                serverCatalog
        );

        SourceBoundCatalog result = load(source);
        SourceBoundCatalog beforeMutation = result;
        List<ReleaseToolBinding> bindingsBeforeMutation = List.copyOf(result.releaseToolBindings());
        tool(tools, "CUSTOMER_DATA_READ").put("description", RAW_SENTINEL);
        tool(tools, "CUSTOMER_DATA_READ").put("version", "2.0.0");
        ((ObjectNode) tool(tools, "CUSTOMER_DATA_READ").path("inputSchema")).removeAll();
        tools.removeAll();
        serverCatalog.removeAll();

        assertThat(result).isEqualTo(beforeMutation);
        assertThat(result.semanticCatalog().enabledReleaseTools()).hasSize(5);
        assertThat(result.releaseToolBindings()).containsExactlyElementsOf(bindingsBeforeMutation);
        assertThat(result.releaseToolBindings()).hasSize(5);
        assertThatThrownBy(() -> result.releaseToolBindings().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(result.semanticCatalog().highImpactToolNames())
                .containsExactly("LOAN_DECISION_UPDATE");
        assertThatThrownBy(() -> result.semanticCatalog().enabledReleaseTools()
                .add(new EnabledTool("EXTRA_TOOL", List.of("field"))))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> enabledTool(result, "CUSTOMER_DATA_READ")
                .outputFields().add("extra"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> result.semanticCatalog().highImpactToolNames()
                .add("EXTRA_TOOL"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void reorderedEquivalentSourcesProduceEqualSortedResults() throws IOException {
        ObjectNode firstManifest = fixture("valid-release-manifest-v1.1.json");
        ObjectNode secondManifest = firstManifest.deepCopy();
        reverse((ArrayNode) secondManifest.path("tools"));
        reverseProperties((ObjectNode) tool(
                secondManifest.path("tools"),
                "CUSTOMER_DATA_READ"
        ).at("/outputSchema/properties/rows/items/properties/fields/properties"));

        ObjectNode firstServerCatalog = (ObjectNode) firstManifest.path("serverToolCatalog");
        addSecondHumanOnlyTool(firstServerCatalog);
        ObjectNode secondServerCatalog = (ObjectNode) secondManifest.path("serverToolCatalog");
        addSecondHumanOnlyTool(secondServerCatalog);
        reverse((ArrayNode) secondServerCatalog.path("tools"));
        String normalizedHash = serverCatalogHash(firstServerCatalog);
        assertThat(serverCatalogHash(secondServerCatalog)).isEqualTo(normalizedHash);

        SourceBoundCatalog first = load(source(
                RELEASE_ID,
                "1.1",
                AGENT_FINGERPRINT,
                RELEASE_FINGERPRINT,
                normalizedHash,
                firstManifest.path("tools"),
                firstServerCatalog
        ));
        SourceBoundCatalog second = load(source(
                RELEASE_ID,
                "1.1",
                AGENT_FINGERPRINT,
                RELEASE_FINGERPRINT,
                normalizedHash,
                secondManifest.path("tools"),
                secondServerCatalog
        ));

        assertThat(second).isEqualTo(first);
        assertThat(second.semanticCatalog().highImpactToolNames())
                .containsExactly("ACCOUNT_OVERRIDE", "LOAN_DECISION_UPDATE");
    }

    @Test
    void repeatedLoadsAreStableAndEachPerformsOneSourceCall() throws IOException {
        ToolCatalogResponse source = authoritativeSource(
                fixture("valid-release-manifest-v1.1.json")
        );
        ReleaseService releases = mock(ReleaseService.class);
        when(releases.toolCatalog(RELEASE_ID, ACTOR_ID)).thenReturn(source);
        ReleaseToolCatalogContractAdapter adapter = subject(releases);

        SourceBoundCatalog first = adapter.load(RELEASE_ID, ACTOR_ID);
        SourceBoundCatalog second = adapter.load(RELEASE_ID, ACTOR_ID);

        assertThat(second).isEqualTo(first);
        verify(releases, times(2)).toolCatalog(RELEASE_ID, ACTOR_ID);
        verifyNoMoreInteractions(releases);
    }

    @ParameterizedTest
    @ValueSource(strings = {"inputSchema", "outputSchema", "description"})
    void tcGw008ExpectedBindingDetectsEachIndependentSourceChange(String field)
            throws IOException {
        ObjectNode baselineManifest = fixture("valid-release-manifest-v1.1.json");
        ObjectNode changedManifest = baselineManifest.deepCopy();
        ObjectNode changedTool = tool(changedManifest.path("tools"), "CUSTOMER_DATA_READ");
        if (field.equals("description")) {
            changedTool.put(field, "Changed synthetic customer lookup description");
        } else {
            ((ObjectNode) changedTool.path(field)).put("title", "Changed schema annotation");
        }

        SourceBoundCatalog baseline = load(authoritativeSource(baselineManifest));
        SourceBoundCatalog changed = load(authoritativeSource(changedManifest));
        ReleaseToolBinding before = binding(baseline, "CUSTOMER_DATA_READ");
        ReleaseToolBinding after = binding(changed, "CUSTOMER_DATA_READ");

        assertThat(after.schemaDigest()).isEqualTo(roleASchemaHash(changedTool));
        assertThat(after.descriptionDigest()).isEqualTo(roleADescriptionHash(changedTool));
        if (field.equals("description")) {
            assertThat(after.descriptionDigest()).isNotEqualTo(before.descriptionDigest());
            assertThat(after.schemaDigest()).isEqualTo(before.schemaDigest());
        } else {
            assertThat(after.schemaDigest()).isNotEqualTo(before.schemaDigest());
            assertThat(after.descriptionDigest()).isEqualTo(before.descriptionDigest());
        }
        assertThat(changed.releaseToolBindings().stream()
                .filter(value -> !value.toolName().equals("CUSTOMER_DATA_READ")).toList())
                .containsExactlyElementsOf(baseline.releaseToolBindings().stream()
                        .filter(value -> !value.toolName().equals("CUSTOMER_DATA_READ")).toList());
    }

    @ParameterizedTest
    @ValueSource(strings = {"inputSchema", "outputSchema"})
    void expectedSchemaDigestPreservesNonVacuousArrayOrder(String field) throws IOException {
        ObjectNode firstManifest = fixture("valid-release-manifest-v1.1.json");
        ObjectNode secondManifest = firstManifest.deepCopy();
        ObjectNode changedTool = tool(secondManifest.path("tools"), "CUSTOMER_DATA_READ");
        ArrayNode required = (ArrayNode) changedTool.path(field).path("required");
        assertThat(required.size()).isGreaterThan(1);
        reverse(required);

        ReleaseToolBinding first = binding(load(authoritativeSource(firstManifest)), "CUSTOMER_DATA_READ");
        ReleaseToolBinding second = binding(load(authoritativeSource(secondManifest)), "CUSTOMER_DATA_READ");

        assertThat(second.schemaDigest()).isEqualTo(roleASchemaHash(changedTool))
                .isNotEqualTo(first.schemaDigest());
        assertThat(second.descriptionDigest()).isEqualTo(first.descriptionDigest());
    }

    @Test
    void normalizesEquivalentUnicodeAndLineEndingsWithoutMutatingSourceStrings()
            throws IOException {
        ObjectNode firstManifest = fixture("valid-release-manifest-v1.1.json");
        ObjectNode secondManifest = firstManifest.deepCopy();
        ObjectNode firstTool = tool(firstManifest.path("tools"), "CUSTOMER_DATA_READ");
        ObjectNode secondTool = tool(secondManifest.path("tools"), "CUSTOMER_DATA_READ");
        firstTool.put("description", "Caf\u00e9\nsecond\nthird");
        secondTool.put("description", "Cafe\u0301\r\nsecond\rthird");
        for (String field : List.of("inputSchema", "outputSchema")) {
            ((ObjectNode) firstTool.path(field)).put("title", "Caf\u00e9\nvalue");
            ((ObjectNode) secondTool.path(field)).put("title", "Cafe\u0301\r\nvalue");
        }
        ObjectNode firstOriginal = firstManifest.deepCopy();
        ObjectNode secondOriginal = secondManifest.deepCopy();

        ReleaseToolBinding first = binding(load(authoritativeSource(firstManifest)), "CUSTOMER_DATA_READ");
        ReleaseToolBinding second = binding(load(authoritativeSource(secondManifest)), "CUSTOMER_DATA_READ");

        assertThat(second).isEqualTo(first);
        assertThat(second.schemaDigest()).isEqualTo(roleASchemaHash(secondTool));
        assertThat(second.descriptionDigest()).isEqualTo(roleADescriptionHash(secondTool));
        assertThat(firstManifest).isEqualTo(firstOriginal);
        assertThat(secondManifest).isEqualTo(secondOriginal);
        assertThat(secondTool.path("description").stringValue())
                .isEqualTo("Cafe\u0301\r\nsecond\rthird");
    }

    @ParameterizedTest
    @ValueSource(strings = {"inputSchema", "outputSchema", "description"})
    void meaningfulStringWhitespaceRemainsPartOfExpectedDigest(String field) throws IOException {
        ObjectNode firstManifest = fixture("valid-release-manifest-v1.1.json");
        ObjectNode secondManifest = firstManifest.deepCopy();
        ObjectNode firstTool = tool(firstManifest.path("tools"), "CUSTOMER_DATA_READ");
        ObjectNode secondTool = tool(secondManifest.path("tools"), "CUSTOMER_DATA_READ");
        if (field.equals("description")) {
            firstTool.put(field, "Synthetic value");
            secondTool.put(field, "  Synthetic value  ");
        } else {
            ((ObjectNode) firstTool.path(field)).put("title", "Synthetic value");
            ((ObjectNode) secondTool.path(field)).put("title", "  Synthetic value  ");
        }
        ObjectNode original = secondManifest.deepCopy();

        ReleaseToolBinding first = binding(load(authoritativeSource(firstManifest)), "CUSTOMER_DATA_READ");
        ReleaseToolBinding second = binding(load(authoritativeSource(secondManifest)), "CUSTOMER_DATA_READ");

        assertThat(secondManifest).isEqualTo(original);
        assertThat(second.schemaDigest()).isEqualTo(roleASchemaHash(secondTool));
        assertThat(second.descriptionDigest()).isEqualTo(roleADescriptionHash(secondTool));
        if (field.equals("description")) {
            assertThat(second.descriptionDigest()).isNotEqualTo(first.descriptionDigest());
            assertThat(second.schemaDigest()).isEqualTo(first.schemaDigest());
        } else {
            assertThat(second.schemaDigest()).isNotEqualTo(first.schemaDigest());
            assertThat(second.descriptionDigest()).isEqualTo(first.descriptionDigest());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"inputSchema", "outputSchema"})
    void expectedSchemaHashNormalizesNonCollidingObjectKeys(String field) throws IOException {
        ObjectNode firstManifest = fixture("valid-release-manifest-v1.1.json");
        ObjectNode secondManifest = firstManifest.deepCopy();
        ObjectNode firstTool = tool(firstManifest.path("tools"), "CUSTOMER_DATA_READ");
        ObjectNode secondTool = tool(secondManifest.path("tools"), "CUSTOMER_DATA_READ");
        ((ObjectNode) firstTool.path(field)).put("Caf\u00e9", "value");
        ((ObjectNode) secondTool.path(field)).put("Cafe\u0301", "value");
        reverseProperties((ObjectNode) secondTool.path(field));

        ReleaseToolBinding first = binding(load(authoritativeSource(firstManifest)), "CUSTOMER_DATA_READ");
        ReleaseToolBinding second = binding(load(authoritativeSource(secondManifest)), "CUSTOMER_DATA_READ");

        assertThat(second).isEqualTo(first);
        assertThat(second.schemaDigest()).isEqualTo(roleASchemaHash(secondTool));
        assertThat(secondTool.path(field).has("Cafe\u0301")).isTrue();
        assertThat(secondTool.path(field).has("Caf\u00e9")).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"inputSchema", "outputSchema"})
    void rejectsSchemaObjectKeyNormalizationCollisionWithSafeFailure(String field)
            throws IOException {
        ObjectNode manifest = fixture("valid-release-manifest-v1.1.json");
        ObjectNode schema = (ObjectNode) tool(manifest.path("tools"), "CUSTOMER_DATA_READ").path(field);
        schema.put("Caf\u00e9", RAW_SENTINEL);
        schema.put("Cafe\u0301", "other");

        assertSafeFailure(failureFor(authoritativeSource(manifest)), INVALID_ENABLED_TOOL_CATALOG);
    }

    @ParameterizedTest
    @ValueSource(strings = {"version", "description", "inputSchema", "outputSchema"})
    void rejectsMissingTrustBindingMetadata(String field) throws IOException {
        ObjectNode manifest = fixture("valid-release-manifest-v1.1.json");
        tool(manifest.path("tools"), "CUSTOMER_DATA_READ").remove(field);

        assertSafeFailure(failureFor(authoritativeSource(manifest)), INVALID_ENABLED_TOOL_CATALOG);
    }

    @ParameterizedTest
    @MethodSource("invalidTrustBindingMetadata")
    void rejectsMalformedTrustBindingMetadataWithoutFallback(String field, String valueJson)
            throws IOException {
        ObjectNode manifest = fixture("valid-release-manifest-v1.1.json");
        tool(manifest.path("tools"), "CUSTOMER_DATA_READ")
                .set(field, objectMapper.readTree(valueJson));

        assertSafeFailure(failureFor(authoritativeSource(manifest)), INVALID_ENABLED_TOOL_CATALOG);
    }

    @ParameterizedTest
    @ValueSource(strings = {" 1.1.0", "1.1.0 ", "\t1.1.0", "1.1.0\n"})
    void rejectsPaddedVersionsInsteadOfChangingTheirIdentity(String version) throws IOException {
        ObjectNode manifest = fixture("valid-release-manifest-v1.1.json");
        tool(manifest.path("tools"), "CUSTOMER_DATA_READ").put("version", version);

        assertSafeFailure(failureFor(authoritativeSource(manifest)), INVALID_ENABLED_TOOL_CATALOG);
    }

    @Test
    void preservesExactDeclaredPrereleaseVersion() throws IOException {
        ObjectNode manifest = fixture("valid-release-manifest-v1.1.json");
        ObjectNode customer = tool(manifest.path("tools"), "CUSTOMER_DATA_READ");
        customer.put("version", "2.1.3-preview.4");

        ReleaseToolBinding result = binding(load(authoritativeSource(manifest)), "CUSTOMER_DATA_READ");

        assertThat(result.version()).isEqualTo("2.1.3-preview.4");
        assertThat(result.schemaDigest()).isEqualTo(roleASchemaHash(customer));
        assertThat(result.descriptionDigest()).isEqualTo(roleADescriptionHash(customer));
    }

    @Test
    void extendedConstructorSnapshotsBindingsAndDoesNotExposeMutableCollection()
            throws IOException {
        SourceBoundCatalog actual = load(authoritativeSource(fixture("valid-release-manifest-v1.1.json")));
        List<ReleaseToolBinding> supplied = new ArrayList<>(actual.releaseToolBindings());
        SourceBoundCatalog copy = new SourceBoundCatalog(
                actual.releaseId(), actual.manifestSchemaVersion(), actual.agentArtifactFingerprint(),
                actual.releaseFingerprint(), actual.serverToolCatalogHash(), actual.semanticCatalog(), supplied
        );
        supplied.clear();

        assertThat(copy.releaseToolBindings()).containsExactlyElementsOf(actual.releaseToolBindings());
        assertThatThrownBy(() -> copy.releaseToolBindings().add(actual.releaseToolBindings().getFirst()))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void sixArgumentConstructorRetainsSemanticOnlyCompatibilityWithoutTrustDefaults()
            throws IOException {
        SourceBoundCatalog actual = load(authoritativeSource(fixture("valid-release-manifest-v1.1.json")));
        SourceBoundCatalog semanticOnly = new SourceBoundCatalog(
                actual.releaseId(), actual.manifestSchemaVersion(), actual.agentArtifactFingerprint(),
                actual.releaseFingerprint(), actual.serverToolCatalogHash(), actual.semanticCatalog()
        );

        assertThat(semanticOnly.releaseToolBindings()).isEmpty();
        assertThat(semanticOnly.semanticCatalog()).isEqualTo(actual.semanticCatalog());
        assertThat(semanticValidator.validate(fixture("loan-review-safety-contract.json"),
                semanticOnly.semanticCatalog()).status()).isEqualTo(ValidationStatus.VALID);
        assertThatThrownBy(() -> semanticOnly.releaseToolBindings().add(actual.releaseToolBindings().getFirst()))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void invalidRequestsNeverCallRoleASource() {
        ReleaseService releases = mock(ReleaseService.class);
        ReleaseToolCatalogContractAdapter adapter = subject(releases);

        assertSafeFailure(
                catchThrowableOfType(
                        CatalogAdapterException.class,
                        () -> adapter.load(null, ACTOR_ID)
                ),
                INVALID_REQUEST
        );
        assertSafeFailure(
                catchThrowableOfType(
                        CatalogAdapterException.class,
                        () -> adapter.load(RELEASE_ID, null)
                ),
                INVALID_REQUEST
        );
        assertSafeFailure(
                catchThrowableOfType(
                        CatalogAdapterException.class,
                        () -> adapter.load(RELEASE_ID, " actor-with-padding ")
                ),
                INVALID_REQUEST
        );
        verifyNoInteractions(releases);
    }

    @Test
    void upstreamFailureIsSanitizedAndNeverRetried() {
        ReleaseService releases = mock(ReleaseService.class);
        when(releases.toolCatalog(RELEASE_ID, ACTOR_ID))
                .thenThrow(new IllegalStateException(RAW_SENTINEL));

        CatalogAdapterException failure = catchThrowableOfType(
                CatalogAdapterException.class,
                () -> subject(releases).load(RELEASE_ID, ACTOR_ID)
        );

        assertSafeFailure(failure, SOURCE_LOAD_FAILURE);
        verify(releases).toolCatalog(RELEASE_ID, ACTOR_ID);
        verifyNoMoreInteractions(releases);
    }

    @Test
    void nullSourceIsTypedAndNotRetried() {
        ReleaseService releases = mock(ReleaseService.class);
        when(releases.toolCatalog(RELEASE_ID, ACTOR_ID)).thenReturn(null);

        CatalogAdapterException failure = catchThrowableOfType(
                CatalogAdapterException.class,
                () -> subject(releases).load(RELEASE_ID, ACTOR_ID)
        );

        assertSafeFailure(failure, SOURCE_UNAVAILABLE);
        verify(releases).toolCatalog(RELEASE_ID, ACTOR_ID);
        verifyNoMoreInteractions(releases);
    }

    @Test
    void rejectsMissingOrMismatchedSourceReleaseIdentity() throws IOException {
        ToolCatalogResponse valid = authoritativeSource(
                fixture("valid-release-manifest-v1.1.json")
        );

        assertSafeFailure(failureFor(copy(valid, null, valid.manifestSchemaVersion(),
                valid.agentArtifactFingerprint(), valid.releaseFingerprint(),
                valid.serverToolCatalogHash(), valid.tools(), valid.serverToolCatalog())),
                SOURCE_IDENTITY_MISMATCH);
        assertSafeFailure(failureFor(copy(valid, OTHER_RELEASE_ID, valid.manifestSchemaVersion(),
                valid.agentArtifactFingerprint(), valid.releaseFingerprint(),
                valid.serverToolCatalogHash(), valid.tools(), valid.serverToolCatalog())),
                SOURCE_IDENTITY_MISMATCH);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "1.0", "1.1 ", " 1.1", "V1.1"})
    void rejectsEveryNonExactManifestVersion(String version) throws IOException {
        ToolCatalogResponse valid = authoritativeSource(
                fixture("valid-release-manifest-v1.1.json")
        );

        CatalogAdapterException failure = failureFor(copy(
                valid,
                valid.releaseId(),
                version,
                valid.agentArtifactFingerprint(),
                valid.releaseFingerprint(),
                valid.serverToolCatalogHash(),
                valid.tools(),
                valid.serverToolCatalog()
        ));

        assertSafeFailure(failure, UNSUPPORTED_MANIFEST_VERSION);
    }

    @ParameterizedTest
    @MethodSource("invalidDigests")
    void rejectsMalformedAgentArtifactFingerprint(String digest) throws IOException {
        ToolCatalogResponse valid = authoritativeSource(
                fixture("valid-release-manifest-v1.1.json")
        );

        assertSafeFailure(failureFor(copy(valid, valid.releaseId(),
                valid.manifestSchemaVersion(), digest, valid.releaseFingerprint(),
                valid.serverToolCatalogHash(), valid.tools(), valid.serverToolCatalog())),
                INVALID_AGENT_ARTIFACT_FINGERPRINT);
    }

    @ParameterizedTest
    @MethodSource("invalidDigests")
    void rejectsMalformedReleaseFingerprint(String digest) throws IOException {
        ToolCatalogResponse valid = authoritativeSource(
                fixture("valid-release-manifest-v1.1.json")
        );

        assertSafeFailure(failureFor(copy(valid, valid.releaseId(),
                valid.manifestSchemaVersion(), valid.agentArtifactFingerprint(), digest,
                valid.serverToolCatalogHash(), valid.tools(), valid.serverToolCatalog())),
                INVALID_RELEASE_FINGERPRINT);
    }

    @ParameterizedTest
    @MethodSource("invalidDigests")
    void rejectsMalformedServerCatalogHash(String digest) throws IOException {
        ToolCatalogResponse valid = authoritativeSource(
                fixture("valid-release-manifest-v1.1.json")
        );

        assertSafeFailure(failureFor(copy(valid, valid.releaseId(),
                valid.manifestSchemaVersion(), valid.agentArtifactFingerprint(),
                valid.releaseFingerprint(), digest, valid.tools(), valid.serverToolCatalog())),
                INVALID_SERVER_CATALOG_HASH);
    }

    @Test
    void rejectsServerCatalogMutationUnderOriginalHash() throws IOException {
        ObjectNode manifest = fixture("valid-release-manifest-v1.1.json");
        ObjectNode serverCatalog = (ObjectNode) manifest.path("serverToolCatalog");
        serverCatalog.put("version", "loan-review-server/2.0");

        CatalogAdapterException failure = failureFor(source(
                RELEASE_ID,
                "1.1",
                AGENT_FINGERPRINT,
                RELEASE_FINGERPRINT,
                AUTHORITATIVE_SERVER_CATALOG_HASH,
                manifest.path("tools"),
                serverCatalog
        ));

        assertSafeFailure(failure, SERVER_CATALOG_HASH_MISMATCH);
    }

    @Test
    void rejectsMalformedEnabledToolTreesWithoutFallback() throws IOException {
        ObjectNode manifest = fixture("valid-release-manifest-v1.1.json");
        assertSafeFailure(failureFor(sourceWithTools(manifest, null)),
                INVALID_ENABLED_TOOL_CATALOG);
        assertSafeFailure(failureFor(sourceWithTools(
                manifest,
                objectMapper.createObjectNode()
        )), INVALID_ENABLED_TOOL_CATALOG);
        assertSafeFailure(failureFor(sourceWithTools(
                manifest,
                objectMapper.createArrayNode()
        )), INVALID_ENABLED_TOOL_CATALOG);

        ArrayNode scalarEntry = objectMapper.createArrayNode().add("invalid");
        assertSafeFailure(failureFor(sourceWithTools(manifest, scalarEntry)),
                INVALID_ENABLED_TOOL_CATALOG);

        ArrayNode missingName = copiedTools(manifest);
        ((ObjectNode) missingName.get(0)).remove("name");
        assertSafeFailure(failureFor(sourceWithTools(manifest, missingName)),
                INVALID_ENABLED_TOOL_CATALOG);

        ArrayNode nonTextName = copiedTools(manifest);
        ((ObjectNode) nonTextName.get(0)).put("name", 1);
        assertSafeFailure(failureFor(sourceWithTools(manifest, nonTextName)),
                INVALID_ENABLED_TOOL_CATALOG);

        for (String invalidName : List.of(
                " ",
                " CASE_CONTEXT_READ",
                "CASE_CONTEXT_READ ",
                "case_context_read",
                "Customer_DATA_READ"
        )) {
            ArrayNode invalidIdentifier = copiedTools(manifest);
            ((ObjectNode) invalidIdentifier.get(0)).put("name", invalidName);
            assertSafeFailure(failureFor(sourceWithTools(manifest, invalidIdentifier)),
                    INVALID_ENABLED_TOOL_CATALOG);
        }

        ArrayNode duplicate = copiedTools(manifest);
        duplicate.add(duplicate.get(0).deepCopy());
        assertSafeFailure(failureFor(sourceWithTools(manifest, duplicate)),
                INVALID_ENABLED_TOOL_CATALOG);
    }

    @Test
    void rejectsMissingMalformedAndEmptyOutputPropertyPaths() throws IOException {
        ObjectNode manifest = fixture("valid-release-manifest-v1.1.json");

        ArrayNode nonCustomerMissing = copiedTools(manifest);
        tool(nonCustomerMissing, "DOCUMENT_READER")
                .at("/outputSchema");
        ((ObjectNode) tool(nonCustomerMissing, "DOCUMENT_READER")
                .path("outputSchema")).remove("properties");
        assertSafeFailure(failureFor(sourceWithTools(manifest, nonCustomerMissing)),
                INVALID_ENABLED_TOOL_CATALOG);

        ArrayNode nonCustomerWrongType = copiedTools(manifest);
        ((ObjectNode) tool(nonCustomerWrongType, "DOCUMENT_READER")
                .path("outputSchema")).set(
                "properties",
                objectMapper.createArrayNode()
        );
        assertSafeFailure(failureFor(sourceWithTools(manifest, nonCustomerWrongType)),
                INVALID_ENABLED_TOOL_CATALOG);

        ArrayNode nonCustomerEmpty = copiedTools(manifest);
        ((ObjectNode) tool(nonCustomerEmpty, "DOCUMENT_READER")
                .path("outputSchema")).set(
                "properties",
                objectMapper.createObjectNode()
        );
        assertSafeFailure(failureFor(sourceWithTools(manifest, nonCustomerEmpty)),
                INVALID_ENABLED_TOOL_CATALOG);

        ArrayNode customerMissing = copiedTools(manifest);
        ((ObjectNode) tool(customerMissing, "CUSTOMER_DATA_READ")
                .at("/outputSchema/properties/rows/items/properties/fields"))
                .remove("properties");
        assertSafeFailure(failureFor(sourceWithTools(manifest, customerMissing)),
                INVALID_ENABLED_TOOL_CATALOG);

        ArrayNode customerWrongType = copiedTools(manifest);
        ((ObjectNode) tool(customerWrongType, "CUSTOMER_DATA_READ")
                .at("/outputSchema/properties/rows/items/properties/fields"))
                .set("properties", objectMapper.createArrayNode());
        assertSafeFailure(failureFor(sourceWithTools(manifest, customerWrongType)),
                INVALID_ENABLED_TOOL_CATALOG);

        ArrayNode customerEmpty = copiedTools(manifest);
        ((ObjectNode) tool(customerEmpty, "CUSTOMER_DATA_READ")
                .at("/outputSchema/properties/rows/items/properties/fields"))
                .set("properties", objectMapper.createObjectNode());
        assertSafeFailure(failureFor(sourceWithTools(manifest, customerEmpty)),
                INVALID_ENABLED_TOOL_CATALOG);

        ArrayNode paddedField = copiedTools(manifest);
        ((ObjectNode) tool(paddedField, "CUSTOMER_DATA_READ")
                .at("/outputSchema/properties/rows/items/properties/fields/properties"))
                .set(" " + RAW_SENTINEL + " ", objectMapper.createObjectNode());
        CatalogAdapterException paddedFailure = failureFor(sourceWithTools(
                manifest,
                paddedField
        ));
        assertSafeFailure(paddedFailure, INVALID_ENABLED_TOOL_CATALOG);
    }

    @Test
    void rejectsMalformedHighImpactCatalogWithoutFallback() throws IOException {
        ObjectNode manifest = fixture("valid-release-manifest-v1.1.json");
        assertSafeFailure(failureFor(sourceWithServerCatalog(manifest, null)),
                INVALID_HIGH_IMPACT_CATALOG);
        assertSafeFailure(failureFor(sourceWithServerCatalog(
                manifest,
                objectMapper.createArrayNode()
        )), INVALID_HIGH_IMPACT_CATALOG);

        ObjectNode missingVersion = copiedServerCatalog(manifest);
        missingVersion.remove("version");
        assertSafeFailure(failureFor(sourceWithServerCatalog(manifest, missingVersion)),
                INVALID_HIGH_IMPACT_CATALOG);

        for (JsonNode invalidVersion : List.of(
                objectMapper.nullNode(),
                objectMapper.valueToTree(1),
                objectMapper.valueToTree(" "),
                objectMapper.valueToTree("loan-review-server/1.0 "),
                objectMapper.valueToTree("LOAN-REVIEW-SERVER/1.0"),
                objectMapper.valueToTree("loan-review-server/2.0")
        )) {
            ObjectNode catalog = copiedServerCatalog(manifest);
            catalog.set("version", invalidVersion);
            assertSafeFailure(failureFor(sourceWithServerCatalog(manifest, catalog)),
                    INVALID_HIGH_IMPACT_CATALOG);
        }

        ObjectNode missingTools = copiedServerCatalog(manifest);
        missingTools.remove("tools");
        assertSafeFailure(failureFor(sourceWithServerCatalog(manifest, missingTools)),
                INVALID_HIGH_IMPACT_CATALOG);

        ObjectNode nonArrayTools = copiedServerCatalog(manifest);
        nonArrayTools.set("tools", objectMapper.createObjectNode());
        assertSafeFailure(failureFor(sourceWithServerCatalog(manifest, nonArrayTools)),
                INVALID_HIGH_IMPACT_CATALOG);

        ObjectNode emptyTools = copiedServerCatalog(manifest);
        emptyTools.set("tools", objectMapper.createArrayNode());
        assertSafeFailure(failureFor(sourceWithServerCatalog(manifest, emptyTools)),
                INVALID_HIGH_IMPACT_CATALOG);

        ObjectNode scalarTool = copiedServerCatalog(manifest);
        scalarTool.set("tools", objectMapper.createArrayNode().add("invalid"));
        assertSafeFailure(failureFor(sourceWithServerCatalog(manifest, scalarTool)),
                INVALID_HIGH_IMPACT_CATALOG);
    }

    @Test
    void rejectsMalformedHighImpactSecurityAttributesAndMixedCatalogs()
            throws IOException {
        ObjectNode manifest = fixture("valid-release-manifest-v1.1.json");

        for (String field : List.of("name", "agentExecutable", "executionBoundary")) {
            ObjectNode catalog = copiedServerCatalog(manifest);
            ((ObjectNode) catalog.at("/tools/0")).remove(field);
            assertSafeFailure(failureFor(sourceWithServerCatalog(manifest, catalog)),
                    INVALID_HIGH_IMPACT_CATALOG);
        }

        ObjectNode nonTextName = copiedServerCatalog(manifest);
        ((ObjectNode) nonTextName.at("/tools/0")).put("name", 1);
        assertSafeFailure(failureFor(sourceWithServerCatalog(manifest, nonTextName)),
                INVALID_HIGH_IMPACT_CATALOG);

        for (String invalidName : List.of(
                " ",
                " LOAN_DECISION_UPDATE",
                "LOAN_DECISION_UPDATE ",
                "loan_decision_update"
        )) {
            ObjectNode catalog = copiedServerCatalog(manifest);
            ((ObjectNode) catalog.at("/tools/0")).put("name", invalidName);
            assertSafeFailure(failureFor(sourceWithServerCatalog(manifest, catalog)),
                    INVALID_HIGH_IMPACT_CATALOG);
        }

        ObjectNode nonBooleanExecutable = copiedServerCatalog(manifest);
        ((ObjectNode) nonBooleanExecutable.at("/tools/0"))
                .put("agentExecutable", "false");
        assertSafeFailure(failureFor(sourceWithServerCatalog(
                manifest,
                nonBooleanExecutable
        )), INVALID_HIGH_IMPACT_CATALOG);

        ObjectNode executable = copiedServerCatalog(manifest);
        ((ObjectNode) executable.at("/tools/0")).put("agentExecutable", true);
        assertSafeFailure(failureFor(sourceWithServerCatalog(manifest, executable)),
                INVALID_HIGH_IMPACT_CATALOG);

        for (JsonNode invalidBoundary : List.of(
                objectMapper.nullNode(),
                objectMapper.valueToTree(1),
                objectMapper.valueToTree("human_only"),
                objectMapper.valueToTree(" HUMAN_ONLY"),
                objectMapper.valueToTree("HUMAN_ONLY "),
                objectMapper.valueToTree("AGENT_ALLOWED")
        )) {
            ObjectNode catalog = copiedServerCatalog(manifest);
            ((ObjectNode) catalog.at("/tools/0"))
                    .set("executionBoundary", invalidBoundary);
            assertSafeFailure(failureFor(sourceWithServerCatalog(manifest, catalog)),
                    INVALID_HIGH_IMPACT_CATALOG);
        }

        ObjectNode duplicate = copiedServerCatalog(manifest);
        ((ArrayNode) duplicate.path("tools")).add(duplicate.at("/tools/0").deepCopy());
        assertSafeFailure(failureFor(sourceWithServerCatalog(manifest, duplicate)),
                INVALID_HIGH_IMPACT_CATALOG);

        ObjectNode mixed = copiedServerCatalog(manifest);
        ObjectNode invalidSecond = ((ArrayNode) mixed.path("tools"))
                .addObject()
                .put("name", "SECOND_HIGH_IMPACT")
                .put("agentExecutable", true)
                .put("executionBoundary", "HUMAN_ONLY");
        invalidSecond.put("raw", RAW_SENTINEL);
        assertSafeFailure(failureFor(sourceWithServerCatalog(manifest, mixed)),
                INVALID_HIGH_IMPACT_CATALOG);
    }

    @Test
    void rejectsEnabledAndHighImpactIdentityOverlap() throws IOException {
        ObjectNode manifest = fixture("valid-release-manifest-v1.1.json");
        ObjectNode serverCatalog = copiedServerCatalog(manifest);
        ((ObjectNode) serverCatalog.at("/tools/0")).put("name", "CASE_CONTEXT_READ");

        CatalogAdapterException failure = failureFor(sourceWithServerCatalog(
                manifest,
                serverCatalog
        ));

        assertSafeFailure(failure, CATALOG_ROLE_OVERLAP);
    }

    @Test
    void localMalformedSourceFailureNeverExposesRawCatalogValue() throws IOException {
        ObjectNode manifest = fixture("valid-release-manifest-v1.1.json");
        ArrayNode tools = copiedTools(manifest);
        ((ObjectNode) tools.get(0)).put("name", " " + RAW_SENTINEL + " ");

        CatalogAdapterException failure = failureFor(sourceWithTools(manifest, tools));

        assertSafeFailure(failure, INVALID_ENABLED_TOOL_CATALOG);
        assertThat(failure.getMessage()).doesNotContain(RAW_SENTINEL);
        assertThat(failure.getCause()).isNull();
    }

    private ReleaseToolCatalogContractAdapter subject(ReleaseService releaseService) {
        return new ReleaseToolCatalogContractAdapter(
                releaseService,
                canonicalJsonService,
                digestService,
                objectMapper
        );
    }

    private SourceBoundCatalog load(ToolCatalogResponse source) {
        ReleaseService releases = mock(ReleaseService.class);
        when(releases.toolCatalog(RELEASE_ID, ACTOR_ID)).thenReturn(source);
        SourceBoundCatalog result = subject(releases).load(RELEASE_ID, ACTOR_ID);
        verify(releases).toolCatalog(RELEASE_ID, ACTOR_ID);
        verifyNoMoreInteractions(releases);
        return result;
    }

    private CatalogAdapterException failureFor(ToolCatalogResponse source) {
        ReleaseService releases = mock(ReleaseService.class);
        when(releases.toolCatalog(RELEASE_ID, ACTOR_ID)).thenReturn(source);
        CatalogAdapterException failure = catchThrowableOfType(
                CatalogAdapterException.class,
                () -> subject(releases).load(RELEASE_ID, ACTOR_ID)
        );
        verify(releases).toolCatalog(RELEASE_ID, ACTOR_ID);
        verifyNoMoreInteractions(releases);
        return failure;
    }

    private ToolCatalogResponse authoritativeSource(ObjectNode manifest) {
        return source(
                RELEASE_ID,
                "1.1",
                AGENT_FINGERPRINT,
                RELEASE_FINGERPRINT,
                AUTHORITATIVE_SERVER_CATALOG_HASH,
                manifest.path("tools"),
                manifest.path("serverToolCatalog")
        );
    }

    private ToolCatalogResponse sourceWithTools(ObjectNode manifest, JsonNode tools) {
        return source(
                RELEASE_ID,
                "1.1",
                AGENT_FINGERPRINT,
                RELEASE_FINGERPRINT,
                AUTHORITATIVE_SERVER_CATALOG_HASH,
                tools,
                manifest.path("serverToolCatalog")
        );
    }

    private ToolCatalogResponse sourceWithServerCatalog(
            ObjectNode manifest,
            JsonNode serverCatalog
    ) {
        String hash = serverCatalog == null || !serverCatalog.isObject()
                ? AUTHORITATIVE_SERVER_CATALOG_HASH
                : serverCatalogHash(serverCatalog);
        return source(
                RELEASE_ID,
                "1.1",
                AGENT_FINGERPRINT,
                RELEASE_FINGERPRINT,
                hash,
                manifest.path("tools"),
                serverCatalog
        );
    }

    private ToolCatalogResponse source(
            UUID releaseId,
            String manifestVersion,
            String agentFingerprint,
            String releaseFingerprint,
            String serverCatalogHash,
            JsonNode tools,
            JsonNode serverCatalog
    ) {
        return new ToolCatalogResponse(
                releaseId,
                manifestVersion,
                agentFingerprint,
                releaseFingerprint,
                serverCatalogHash,
                tools,
                serverCatalog
        );
    }

    private ToolCatalogResponse copy(
            ToolCatalogResponse source,
            UUID releaseId,
            String manifestVersion,
            String agentFingerprint,
            String releaseFingerprint,
            String serverCatalogHash,
            JsonNode tools,
            JsonNode serverCatalog
    ) {
        return source(
                releaseId,
                manifestVersion,
                agentFingerprint,
                releaseFingerprint,
                serverCatalogHash,
                tools,
                serverCatalog
        );
    }

    private String serverCatalogHash(JsonNode serverCatalog) {
        ObjectNode wrapper = objectMapper.createObjectNode();
        wrapper.set("serverToolCatalog", serverCatalog.deepCopy());
        JsonNode normalized = canonicalJsonService.normalizeManifest(wrapper)
                .path("serverToolCatalog");
        return digestService.sha256(canonicalJsonService.canonicalize(normalized));
    }

    // Role A's public hash path and the wrappers stored by ReleaseCatalogWriter are the oracle.
    private String roleASchemaHash(JsonNode sourceTool) {
        ObjectNode schemas = objectMapper.createObjectNode();
        schemas.set("inputSchema", sourceTool.path("inputSchema").deepCopy());
        schemas.set("outputSchema", sourceTool.path("outputSchema").deepCopy());
        return roleAFingerprints.hash(schemas);
    }

    private String roleADescriptionHash(JsonNode sourceTool) {
        ObjectNode description = objectMapper.createObjectNode();
        description.put("description", sourceTool.path("description").stringValue());
        return roleAFingerprints.hash(description);
    }

    private ReleaseToolBinding binding(SourceBoundCatalog source, String toolName) {
        return source.releaseToolBindings().stream()
                .filter(value -> value.toolName().equals(toolName))
                .findFirst()
                .orElseThrow();
    }

    private ArrayNode copiedTools(ObjectNode manifest) {
        return (ArrayNode) manifest.path("tools").deepCopy();
    }

    private ObjectNode copiedServerCatalog(ObjectNode manifest) {
        return (ObjectNode) manifest.path("serverToolCatalog").deepCopy();
    }

    private EnabledTool enabledTool(SourceBoundCatalog source, String toolName) {
        return source.semanticCatalog().enabledReleaseTools().stream()
                .filter(tool -> tool.toolName().equals(toolName))
                .findFirst()
                .orElseThrow();
    }

    private ObjectNode tool(JsonNode tools, String name) {
        for (JsonNode tool : tools) {
            if (name.equals(tool.path("name").asString())) {
                return (ObjectNode) tool;
            }
        }
        throw new IllegalArgumentException("Fixture Tool is missing");
    }

    private void addSecondHumanOnlyTool(ObjectNode serverCatalog) {
        ObjectNode second = (ObjectNode) serverCatalog.at("/tools/0").deepCopy();
        second.put("name", "ACCOUNT_OVERRIDE");
        ((ArrayNode) serverCatalog.path("tools")).add(second);
    }

    private void reverse(ArrayNode values) {
        List<JsonNode> copied = new ArrayList<>();
        values.forEach(value -> copied.add(value.deepCopy()));
        Collections.reverse(copied);
        values.removeAll();
        copied.forEach(values::add);
    }

    private void reverseProperties(ObjectNode properties) {
        List<FieldValue> copied = new ArrayList<>();
        properties.properties().forEach(entry -> copied.add(new FieldValue(
                entry.getKey(),
                entry.getValue().deepCopy()
        )));
        Collections.reverse(copied);
        properties.removeAll();
        copied.forEach(entry -> properties.set(entry.name(), entry.value()));
    }

    private ObjectNode fixture(String name) throws IOException {
        try (InputStream input = getClass().getResourceAsStream("/fixtures/" + name)) {
            if (input == null) {
                throw new IOException("Fixture is missing");
            }
            return (ObjectNode) objectMapper.readTree(input);
        }
    }

    private static void assertSafeFailure(
            CatalogAdapterException failure,
            FailureCode expectedCode
    ) {
        assertThat(failure).isNotNull();
        assertThat(failure.code()).isEqualTo(expectedCode);
        assertThat(failure.getMessage()).isEqualTo(expectedCode.safeMessage());
        assertThat(failure.getMessage()).doesNotContain(RAW_SENTINEL, "{", "[");
        assertThat(failure.getCause()).isNull();
    }

    private static Stream<String> invalidDigests() {
        return Stream.of(
                null,
                "",
                " ",
                "sha256:abc",
                "sha256:" + "a".repeat(63),
                "sha256:" + "a".repeat(65),
                "sha256:" + "A".repeat(64),
                "sha256:" + "g".repeat(64),
                "SHA256:" + "a".repeat(64),
                "sha512:" + "a".repeat(64),
                "sha256:" + "a".repeat(64) + " "
        );
    }

    private static Stream<Arguments> invalidTrustBindingMetadata() {
        Stream<Arguments> strings = Stream.of("version", "description")
                .flatMap(field -> Stream.of("null", "false", "42", "[]", "{}", "\"\"", "\"   \"")
                        .map(json -> Arguments.of(field, json)));
        Stream<Arguments> schemas = Stream.of("inputSchema", "outputSchema")
                .flatMap(field -> Stream.of("null", "false", "42", "[]", "\"schema\"")
                        .map(json -> Arguments.of(field, json)));
        return Stream.concat(strings, schemas);
    }

    private record FieldValue(String name, JsonNode value) {
    }
}
