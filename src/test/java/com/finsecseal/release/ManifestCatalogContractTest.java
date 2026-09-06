package com.finsecseal.release;

import static org.assertj.core.api.Assertions.assertThat;

import com.finsecseal.contract.SafetyContractSchemaValidator;
import com.finsecseal.contract.SafetyContractSemanticValidator;
import com.finsecseal.contract.SafetyContractSemanticValidator.ContractValidationCatalog;
import com.finsecseal.contract.SafetyContractSemanticValidator.EnabledTool;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationStatus;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

class ManifestCatalogContractTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final ManifestValidationService validator = new ManifestValidationService(new DigestService());
    private final FingerprintService fingerprints = new FingerprintService(
            new CanonicalJsonService(mapper), new DigestService(), mapper);
    private final SafetyContractSemanticValidator semantics =
            new SafetyContractSemanticValidator(new SafetyContractSchemaValidator());

    @Test
    void currentFixtureSatisfiesAValidationAndCCrossReferences() throws IOException {
        JsonNode manifest = fixture("valid-release-manifest-v1.1.json");
        assertThat(validator.validate(manifest).issues()).isEmpty();
        assertThat(semantics.validate(contract(), catalogFrom(manifest)).status()).isEqualTo(ValidationStatus.VALID);
        assertThat(tool(manifest, "DOCUMENT_READER").path("trustLevel").asString()).isEqualTo("TRUSTED_INTERNAL");
        assertThat(tool(manifest, "DOCUMENT_READER").at("/outputSchema/properties/content/x-trust-level").asString())
                .isEqualTo("UNTRUSTED");
        assertThat(catalogFrom(manifest).enabledReleaseTools()).extracting(EnabledTool::toolName)
                .doesNotContain("LOAN_DECISION_UPDATE");
        assertThat(manifest.at("/serverToolCatalog/tools/0/agentExecutable").booleanValue()).isFalse();
    }

    @Test
    void keepsLegacyManifestValidationAndPreChangeFingerprintVectors() throws IOException {
        JsonNode legacy = fixture("valid-release-manifest.json");
        assertThat(validator.validate(legacy).valid()).isTrue();
        var result = fingerprints.fingerprint(legacy, null);
        assertThat(result.agentArtifactFingerprint())
                .isEqualTo("sha256:00cdadad6bfa6837860b09ace144c2c4a28873e0b3375c5328ec10a517ca36bf");
        assertThat(result.releaseFingerprint())
                .isEqualTo("sha256:1edf8274cbc46c1c36d2500e9548949e4cf59c3b2fd0f00c21a1be62f4b08ca4");
        assertThat(result.componentDigests()).doesNotContainKey("serverToolCatalogHash");
    }

    @Test
    void rejectsLegacyTrustMissingFieldsAndInputSchemaDriftInNewVersion() throws IOException {
        ObjectNode manifest = fixture("valid-release-manifest-v1.1.json");
        tool(manifest, "DOCUMENT_READER").put("trustLevel", "MIXED");
        ObjectNode fields = (ObjectNode) tool(manifest, "CUSTOMER_DATA_READ")
                .at("/outputSchema/properties/rows/items/properties/fields/properties");
        fields.remove("employmentStatus");
        ((ObjectNode) tool(manifest, "CUSTOMER_DATA_READ").at("/inputSchema/properties/customerIds"))
                .put("maxItems", 1000);
        assertThat(validator.validate(manifest).valid()).isFalse();
        assertThat(validator.validate(manifest).issues()).extracting(ManifestValidationService.Issue::code)
                .contains("TOOL_CONTRACT_MISMATCH");
        assertThat(semantics.validate(contract(), catalogFrom(manifest)).issues())
                .extracting(SafetyContractSemanticValidator.Issue::code).contains("FIELD_NOT_IN_TOOL_OUTPUT");
    }

    @Test
    void rejectsMissingForgedOrExecutableServerCatalog() throws IOException {
        ObjectNode original = fixture("valid-release-manifest-v1.1.json");
        ObjectNode missing = original.deepCopy();
        missing.remove("serverToolCatalog");
        ObjectNode executable = original.deepCopy();
        ((ObjectNode) executable.at("/serverToolCatalog/tools/0")).put("agentExecutable", true);
        ObjectNode forged = original.deepCopy();
        ((ObjectNode) forged.path("serverToolCatalog")).put("version", "unregistered/99");
        for (JsonNode invalid : List.of(missing, executable, forged)) {
            assertThat(validator.validate(invalid).issues()).extracting(ManifestValidationService.Issue::code)
                    .contains("SERVER_CATALOG_MISMATCH");
        }
        var missingCatalog = new ContractValidationCatalog(catalogFrom(original).enabledReleaseTools(), List.of());
        assertThat(semantics.validate(contract(), missingCatalog).issues())
                .extracting(SafetyContractSemanticValidator.Issue::code).contains("HIGH_IMPACT_TOOL_NOT_IN_CATALOG");
    }

    @Test
    void cannotEnableHighImpactToolOrSmuggleCatalogIntoLegacyVersion() throws IOException {
        ObjectNode manifest = fixture("valid-release-manifest-v1.1.json");
        var enabled = (tools.jackson.databind.node.ArrayNode) manifest.path("tools");
        enabled.add(manifest.at("/serverToolCatalog/tools/0").deepCopy());
        assertThat(validator.validate(manifest).issues()).extracting(ManifestValidationService.Issue::code)
                .contains("NORMAL_TOOL_SCOPE");
        ObjectNode policy = contract();
        ((tools.jackson.databind.node.ArrayNode) policy.path("allowedTools")).add("LOAN_DECISION_UPDATE");
        assertThat(semantics.validate(policy, catalogFrom(manifest)).issues())
                .extracting(SafetyContractSemanticValidator.Issue::code).contains("HUMAN_ONLY_TOOL_ALLOWED");
        ObjectNode legacy = fixture("valid-release-manifest.json");
        legacy.set("serverToolCatalog", LoanReviewToolCatalog.serverToolCatalog());
        assertThat(validator.validate(legacy).issues()).extracting(ManifestValidationService.Issue::code)
                .contains("SCHEMA_VERSION");
    }

    @Test
    void hashesSchemaTrustAndNonExecutableCatalogWithoutMutatingInput() throws IOException {
        ObjectNode original = fixture("valid-release-manifest-v1.1.json");
        ObjectNode before = original.deepCopy();
        var baseline = fingerprints.fingerprint(original, null);
        assertThat(original).isEqualTo(before);
        assertThat(baseline.componentDigests()).containsKey("serverToolCatalogHash");
        ObjectNode schema = original.deepCopy();
        ((ObjectNode) tool(schema, "CUSTOMER_DATA_READ")
                .at("/outputSchema/properties/rows/items/properties/fields/properties/incomeBand"))
                .put("type", "integer");
        ObjectNode trust = original.deepCopy();
        tool(trust, "DOCUMENT_READER").put("trustLevel", "MIXED");
        ObjectNode highImpact = original.deepCopy();
        ((ObjectNode) highImpact.at("/serverToolCatalog/tools/0")).put("executionBoundary", "AGENT_ALLOWED");
        for (JsonNode changed : List.of(schema, trust, highImpact)) {
            var result = fingerprints.fingerprint(changed, null);
            assertThat(result.agentArtifactFingerprint()).isNotEqualTo(baseline.agentArtifactFingerprint());
            assertThat(result.releaseFingerprint()).isNotEqualTo(baseline.releaseFingerprint());
        }
        ((ObjectNode) LoanReviewToolCatalog.serverToolCatalog()).put("version", "tampered");
        assertThat(validator.validate(original).valid()).isTrue();
    }

    static ObjectNode tool(JsonNode manifest, String name) {
        for (JsonNode tool : manifest.path("tools")) {
            if (name.equals(tool.path("name").asString())) {
                return (ObjectNode) tool;
            }
        }
        throw new IllegalArgumentException(name);
    }

    /** Test-only example of C's future adapter; production policy ownership remains with C. */
    static ContractValidationCatalog catalogFrom(JsonNode manifest) {
        List<EnabledTool> tools = new ArrayList<>();
        for (JsonNode tool : manifest.path("tools")) {
            String path = "CUSTOMER_DATA_READ".equals(tool.path("name").asString())
                    ? "/outputSchema/properties/rows/items/properties/fields/properties"
                    : "/outputSchema/properties";
            List<String> fields = new ArrayList<>();
            JsonNode properties = tool.at(path);
            if (properties.isObject()) {
                properties.properties().forEach(field -> fields.add(field.getKey()));
            }
            tools.add(new EnabledTool(tool.path("name").asString(), fields));
        }
        List<String> highImpact = new ArrayList<>();
        manifest.at("/serverToolCatalog/tools").forEach(tool -> highImpact.add(tool.path("name").asString()));
        return new ContractValidationCatalog(tools, highImpact);
    }

    ObjectNode fixture(String name) throws IOException {
        return (ObjectNode) mapper.readTree(getClass().getResourceAsStream("/fixtures/" + name));
    }

    ObjectNode contract() throws IOException {
        return fixture("loan-review-safety-contract.json");
    }
}
