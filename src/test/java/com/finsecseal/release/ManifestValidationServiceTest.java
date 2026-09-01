package com.finsecseal.release;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

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
}
