package com.finsecseal.release;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import tools.jackson.databind.node.ArrayNode;

class ManifestValidationServiceTest {

    private ObjectMapper objectMapper;
    private ManifestValidationService validationService;
    private JsonNode validManifest;

    @BeforeEach
    void setUp() throws IOException {
        objectMapper = new ObjectMapper();
        validationService = new ManifestValidationService(new DigestService());
        validManifest = objectMapper.readTree(
                getClass().getResourceAsStream("/fixtures/valid-release-manifest.json")
        );
    }

    @Test
    void acceptsValidManifest() {
        assertThat(validationService.validate(validManifest).valid()).isTrue();
    }

    @Test
    void rejectsUnknownFieldsAndExternalEgress() {
        ObjectNode invalid = (ObjectNode) validManifest.deepCopy();
        invalid.put("unexpected", true);
        ((ObjectNode) invalid.path("networkRequirements")).put("agentExternalEgress", true);

        ManifestValidationService.ValidationResult result = validationService.validate(invalid);

        assertThat(result.valid()).isFalse();
        assertThat(result.issues()).extracting(ManifestValidationService.Issue::code)
                .contains("UNKNOWN_FIELD", "EGRESS");
    }

    @Test
    void rejectsMissingRagDigestRemoteSchemaAndSpoofedContractReference() {
        ObjectNode invalid = (ObjectNode) validManifest.deepCopy();
        ((ObjectNode) invalid.path("ragSources").get(0)).remove("contentDigest");
        ((ObjectNode) invalid.path("tools").get(0).path("inputSchema"))
                .put("$ref", "https://example.invalid/schema.json");
        invalid.set("safetyContractRef", objectMapper.createObjectNode().put("id", "spoofed"));

        ManifestValidationService.ValidationResult result = validationService.validate(invalid);

        assertThat(result.valid()).isFalse();
        assertThat(result.issues()).extracting(ManifestValidationService.Issue::code)
                .contains("DIGEST", "REMOTE_REF", "SERVER_OWNED");
    }

    @Test
    void rejectsCrossWiredAndAttackOnlyTools() {
        ObjectNode invalid = (ObjectNode) validManifest.deepCopy();
        ((ObjectNode) invalid.path("tools").get(0)).put("adapterKey", "loan_decision_update");
        ObjectNode attackOnly = ((ObjectNode) invalid.path("tools").get(0)).deepCopy();
        attackOnly.put("name", "LOAN_DECISION_UPDATE");
        attackOnly.put("version", "1.0.0");
        attackOnly.put("operation", "UPDATE");
        attackOnly.put("riskLevel", "CRITICAL");
        attackOnly.put("sideEffectType", "HIGH_IMPACT_WRITE");
        attackOnly.put("adapterKey", "loan_decision_update");
        ((ArrayNode) invalid.path("tools")).add(attackOnly);

        ManifestValidationService.ValidationResult result = validationService.validate(invalid);

        assertThat(result.valid()).isFalse();
        assertThat(result.issues()).extracting(ManifestValidationService.Issue::code)
                .contains("TOOL_CONTRACT_MISMATCH", "NORMAL_TOOL_SCOPE");
    }

    @Test
    void rejectsNonStringPromptDigestAndUnconfiguredProviderHost() {
        ObjectNode invalid = (ObjectNode) validManifest.deepCopy();
        ((ObjectNode) invalid.path("systemPrompt")).put("declaredSha256", 123);
        ((ArrayNode) invalid.at("/networkRequirements/allowedHosts"))
                .removeAll()
                .add("another-provider-host");

        ManifestValidationService.ValidationResult result = validationService.validate(invalid);

        assertThat(result.valid()).isFalse();
        assertThat(result.issues()).extracting(ManifestValidationService.Issue::code)
                .contains("TYPE", "PROVIDER_HOST_SCOPE");
    }
}
