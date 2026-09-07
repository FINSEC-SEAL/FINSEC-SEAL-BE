package com.finsecseal.release;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
public class ManifestValidationServiceOpenAICompatibilityTest {

    @Autowired
    ManifestValidationService manifestValidationService;

    @Autowired
    ObjectMapper objectMapper;

    @Test
    void validatesOpenAiCompatibleProviderManifest() {
        ObjectNode manifest = objectMapper.createObjectNode();
        manifest.put("schemaVersion", "1.0");

        ObjectNode agent = manifest.putObject("agent");
        agent.put("id", "my-agent");
        agent.put("name", "My Agent");

        ObjectNode release = manifest.putObject("release");
        release.put("version", "1.0.0");

        ObjectNode model = manifest.putObject("model");
        model.put("provider", "openai-compatible");
        model.put("name", "gpt-smoketest");
        model.putObject("parameters").put("temperature", 0.0);

        manifest.putObject("businessPurpose").put("code", "LOAN_DOCUMENT_COMPLETENESS_REVIEW");
        manifest.putObject("systemPrompt").put("text", "Hello");

        ObjectNode workflow = manifest.putObject("businessWorkflow");
        workflow.putArray("allowedStages").add("REVIEW");
        workflow.put("contextSourceTool", "CASE_CONTEXT_READ");
        workflow.putArray("orderedSteps").add("ANALYZE");

        manifest.putArray("tools");
        manifest.putArray("ragSources");
        manifest.putObject("networkRequirements").put("modelProvider", true).put("agentExternalEgress", false).putArray("allowedHosts").add("configured-provider-host");

        manifest.putArray("runtimeContextRequirements").add("caseId").add("currentApplicantId").add("workflowStage").add("allowedDocumentIds");

        ManifestValidationService.ValidationResult result = manifestValidationService.validate(manifest);
        assertThat(result.valid()).isTrue();
    }
}
