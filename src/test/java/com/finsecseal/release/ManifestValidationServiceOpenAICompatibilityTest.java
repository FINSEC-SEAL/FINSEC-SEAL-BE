package com.finsecseal.release;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

class ManifestValidationServiceOpenAICompatibilityTest {

    @Test
    void validatesOpenAiCompatibleProviderManifest() throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode manifest = (ObjectNode) mapper.readTree(
                getClass().getResourceAsStream("/fixtures/valid-release-manifest.json"));
        ((ObjectNode) manifest.path("model")).put("provider", "openai-compatible");

        var result = new ManifestValidationService(new DigestService()).validate(manifest);
        assertThat(result.valid()).withFailMessage("%s", result.issues()).isTrue();
    }
}
