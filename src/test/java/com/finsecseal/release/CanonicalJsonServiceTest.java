package com.finsecseal.release;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

class CanonicalJsonServiceTest {

    private ObjectMapper objectMapper;
    private CanonicalJsonService canonicalJsonService;
    private FingerprintService fingerprintService;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        canonicalJsonService = new CanonicalJsonService(objectMapper);
        fingerprintService = new FingerprintService(canonicalJsonService, new DigestService(), objectMapper);
    }

    @Test
    void followsJcsObjectKeyOrderingAndNfcNormalization() {
        JsonNode input = objectMapper.readTree("{\"z\":\"e\\u0301\",\"a\":2,\"b\":1}");

        assertThat(canonicalJsonService.canonicalString(input))
                .isEqualTo("{\"a\":2,\"b\":1,\"z\":\"é\"}");
    }

    @Test
    void semanticSetOrderingDoesNotChangeFingerprint() {
        ObjectNode first = minimalManifest();
        ObjectNode second = first.deepCopy();
        ArrayNode contexts = (ArrayNode) second.path("runtimeContextRequirements");
        contexts.removeAll().add("z").add("a");
        ArrayNode firstContexts = (ArrayNode) first.path("runtimeContextRequirements");
        firstContexts.removeAll().add("a").add("z");

        assertThat(fingerprintService.fingerprint(first, null).agentArtifactFingerprint())
                .isEqualTo(fingerprintService.fingerprint(second, null).agentArtifactFingerprint());
    }

    @Test
    void meaningfulPromptChangeChangesAgentAndReleaseFingerprint() {
        ObjectNode before = minimalManifest();
        ObjectNode after = before.deepCopy();
        ((ObjectNode) after.path("systemPrompt")).put("text", "changed");

        FingerprintService.Result oldFingerprint = fingerprintService.fingerprint(before, null);
        FingerprintService.Result newFingerprint = fingerprintService.fingerprint(after, null);

        assertThat(newFingerprint.agentArtifactFingerprint()).isNotEqualTo(oldFingerprint.agentArtifactFingerprint());
        assertThat(newFingerprint.releaseFingerprint()).isNotEqualTo(oldFingerprint.releaseFingerprint());
    }

    private ObjectNode minimalManifest() {
        return (ObjectNode) objectMapper.readTree("""
                {
                  "businessPurpose":{"code":"LOAN_DOCUMENT_COMPLETENESS_REVIEW"},
                  "model":{"provider":"test","name":"m","parameters":{}},
                  "systemPrompt":{"text":"same"},
                  "tools":[],
                  "ragSources":[],
                  "networkRequirements":{"agentExternalEgress":false},
                  "businessWorkflow":{},
                  "humanApprovalBoundaries":[],
                  "runtimeContextRequirements":["a","z"]
                }
                """);
    }
}
