package com.finsecseal.release;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class FingerprintService {

    private final CanonicalJsonService canonicalJsonService;
    private final DigestService digestService;
    private final ObjectMapper objectMapper;

    public FingerprintService(
            CanonicalJsonService canonicalJsonService,
            DigestService digestService,
            ObjectMapper objectMapper
    ) {
        this.canonicalJsonService = canonicalJsonService;
        this.digestService = digestService;
        this.objectMapper = objectMapper;
    }

    public Result fingerprint(JsonNode manifest, String safetyContractHash) {
        JsonNode normalized = canonicalJsonService.normalizeManifest(manifest);
        Map<String, String> components = new LinkedHashMap<>();
        components.put("businessPurposeHash", hash(normalized.path("businessPurpose")));
        components.put("modelHash", hash(normalized.path("model")));
        components.put("systemPromptHash", digestService.sha256(normalized.at("/systemPrompt/text").asString("")));
        components.put("toolSetHash", hash(normalized.path("tools")));
        components.put("ragConfigHash", hash(normalized.path("ragSources")));
        components.put("networkRequirementsHash", hash(normalized.path("networkRequirements")));
        components.put("workflowHash", hash(normalized.path("businessWorkflow")));
        components.put("humanBoundaryHash", hash(normalized.path("humanApprovalBoundaries")));
        components.put("runtimeContextHash", hash(normalized.path("runtimeContextRequirements")));

        ObjectNode agentInput = objectMapper.createObjectNode();
        agentInput.put("fingerprintVersion", "finsec-agent-artifact/v1");
        components.forEach(agentInput::put);
        String agentFingerprint = hash(agentInput);
        String releaseFingerprint = releaseFingerprint(agentFingerprint, safetyContractHash);
        return new Result(agentFingerprint, releaseFingerprint, Map.copyOf(components), normalized);
    }

    public String releaseFingerprint(String agentArtifactFingerprint, String safetyContractHash) {
        ObjectNode releaseInput = objectMapper.createObjectNode();
        releaseInput.put("fingerprintVersion", "finsec-release/v1");
        releaseInput.put("agentArtifactFingerprint", agentArtifactFingerprint);
        if (safetyContractHash == null) {
            releaseInput.putNull("safetyContractHash");
        } else {
            releaseInput.put("safetyContractHash", safetyContractHash);
        }
        return hash(releaseInput);
    }

    public String hash(JsonNode value) {
        return digestService.sha256(canonicalJsonService.canonicalize(value));
    }

    public record Result(
            String agentArtifactFingerprint,
            String releaseFingerprint,
            Map<String, String> componentDigests,
            JsonNode normalizedManifest
    ) {
    }
}
