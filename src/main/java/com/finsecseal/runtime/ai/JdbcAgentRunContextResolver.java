package com.finsecseal.runtime.ai;

import com.finsecseal.audit.PromptAccessAuditService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.EncryptionService;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Component
public class JdbcAgentRunContextResolver implements AgentRunContextResolver {

    private static final String SYSTEM_PROMPT_ARTIFACT_NAME = "system-prompt";
    private static final String RUNTIME_ACTOR = "system:agent-runtime";

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final EncryptionService encryptionService;
    private final DigestService digestService;
    private final PromptAccessAuditService promptAccessAuditService;

    public JdbcAgentRunContextResolver(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            EncryptionService encryptionService,
            DigestService digestService,
            PromptAccessAuditService promptAccessAuditService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.encryptionService = encryptionService;
        this.digestService = digestService;
        this.promptAccessAuditService = promptAccessAuditService;
    }

    /**
     * Legacy release-only lookup retained for source compatibility with existing callers.
     */
    @Override
    public ResolvedRunContext resolve(UUID testRunId) {
        if (testRunId == null) {
            throw evidenceIncomplete("TestRun id is required for AI context");
        }

        List<ResolvedRunContext> matches = jdbcTemplate.query(
                "select release_id from test_runs where id = ?",
                (resultSet, rowNumber) -> new ResolvedRunContext(
                        resultSet.getObject("release_id", UUID.class)
                ),
                testRunId
        );

        if (matches.size() != 1 || matches.getFirst().releaseId() == null) {
            throw evidenceIncomplete("Trusted AI run context is missing or duplicated");
        }
        return matches.getFirst();
    }

    @Override
    public ResolvedAgentExecutionContext resolve(
            UUID testRunId,
            String caseKey,
            String currentApplicantId
    ) {
        requireScope(testRunId, caseKey, currentApplicantId);

        ReleaseManifestRow release = requireReleaseManifest(testRunId);
        JsonNode manifest = parseObject(release.manifestJson(), "Agent release manifest");

        ModelContext model = resolveModel(manifest);
        BusinessContext businessContext = resolveBusinessContext(manifest);
        JsonNode workflow = requiredObject(
                manifest,
                "businessWorkflow",
                "Agent release manifest"
        ).deepCopy();
        List<ToolContext> tools = resolveTools(manifest);

        RuntimeCaseContext runtime = resolveRuntimeCase(
                testRunId,
                caseKey,
                currentApplicantId
        );
        List<DocumentContext> documents = resolveDocuments(
                testRunId,
                caseKey,
                runtime.allowedDocumentIds()
        );

        // Resolve the SECRET system prompt last so invalid sandbox scope never causes a decrypt/audit event.
        String systemPrompt = resolveSystemPrompt(release, manifest);

        return new ResolvedAgentExecutionContext(
                release.releaseId(),
                model,
                systemPrompt,
                businessContext,
                workflow,
                tools,
                runtime,
                documents
        );
    }

    private void requireScope(UUID testRunId, String caseKey, String currentApplicantId) {
        if (testRunId == null
                || caseKey == null || caseKey.isBlank()
                || currentApplicantId == null || currentApplicantId.isBlank()) {
            throw evidenceIncomplete("TestRun, caseKey, and currentApplicantId are required for AI context");
        }
    }

    private ReleaseManifestRow requireReleaseManifest(UUID testRunId) {
        List<ReleaseManifestRow> matches = jdbcTemplate.query("""
                select tr.release_id, agent.workspace_id, ar.manifest_json::text
                  from test_runs tr
                  join agent_releases ar on ar.id = tr.release_id
                  join agents agent on agent.id = ar.agent_id
                 where tr.id = ?
                """, (resultSet, rowNumber) -> new ReleaseManifestRow(
                resultSet.getObject("release_id", UUID.class),
                resultSet.getObject("workspace_id", UUID.class),
                resultSet.getString("manifest_json")
        ), testRunId);

        if (matches.size() != 1
                || matches.getFirst().releaseId() == null
                || matches.getFirst().workspaceId() == null
                || matches.getFirst().manifestJson() == null) {
            throw evidenceIncomplete("Trusted Agent release manifest is missing or duplicated");
        }
        return matches.getFirst();
    }

    private String resolveSystemPrompt(ReleaseManifestRow release, JsonNode manifest) {
        JsonNode promptNode = requiredObject(manifest, "systemPrompt", "Agent release manifest");
        String storedText = requiredText(promptNode, "text", "Agent release systemPrompt");
        if (!"[ENCRYPTED]".equals(storedText)) {
            throw evidenceIncomplete("Stored Agent release systemPrompt must remain encrypted at rest");
        }

        String storedSha256 = requiredText(
                promptNode,
                "storedSha256",
                "Agent release systemPrompt"
        );

        List<PromptArtifactRow> artifacts = jdbcTemplate.query("""
                select content_text_encrypted, sha256
                  from release_artifacts
                 where release_id = ?
                   and artifact_type = 'SYSTEM_PROMPT'
                   and name = ?
                """, (resultSet, rowNumber) -> new PromptArtifactRow(
                resultSet.getString("content_text_encrypted"),
                resultSet.getString("sha256")
        ), release.releaseId(), SYSTEM_PROMPT_ARTIFACT_NAME);

        if (artifacts.size() != 1) {
            throw evidenceIncomplete("Trusted system prompt artifact is missing or duplicated");
        }

        PromptArtifactRow artifact = artifacts.getFirst();
        if (artifact.encryptedText() == null || artifact.encryptedText().isBlank()
                || artifact.sha256() == null || !artifact.sha256().matches("sha256:[0-9a-f]{64}")) {
            throw evidenceIncomplete("Trusted system prompt artifact is incomplete");
        }
        if (!storedSha256.equals(artifact.sha256())) {
            throw evidenceIncomplete("Stored system prompt digest does not match its encrypted artifact");
        }

        String plaintext;
        try {
            plaintext = encryptionService.decrypt(artifact.encryptedText());
        } catch (BusinessException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw evidenceIncomplete("Trusted system prompt artifact could not be decrypted");
        }

        if (plaintext.isBlank()) {
            throw evidenceIncomplete("Trusted system prompt is empty");
        }
        if (!artifact.sha256().equals(digestService.sha256(plaintext))) {
            throw evidenceIncomplete("Decrypted system prompt digest does not match trusted artifact metadata");
        }

        ObjectNode auditMetadata = objectMapper.createObjectNode();
        auditMetadata.put("schemaVersion", "1.0");
        auditMetadata.put("purpose", "AGENT_RUNTIME_EXECUTION");
        auditMetadata.put("artifactType", "SYSTEM_PROMPT");
        auditMetadata.put("plaintextReturned", false);
        promptAccessAuditService.appendRollbackSafe(
                release.workspaceId(),
                RUNTIME_ACTOR,
                release.releaseId(),
                artifact.sha256(),
                auditMetadata
        );
        return plaintext;
    }

    private ModelContext resolveModel(JsonNode manifest) {
        JsonNode model = requiredObject(manifest, "model", "Agent release manifest");
        JsonNode parameters = requiredObject(model, "parameters", "Agent release model");
        return new ModelContext(
                requiredText(model, "provider", "Agent release model"),
                requiredText(model, "name", "Agent release model"),
                parameters
        );
    }

    private BusinessContext resolveBusinessContext(JsonNode manifest) {
        JsonNode businessPurpose = requiredObject(
                manifest,
                "businessPurpose",
                "Agent release manifest"
        );
        return new BusinessContext(
                requiredText(businessPurpose, "code", "Agent release businessPurpose"),
                requiredText(businessPurpose, "description", "Agent release businessPurpose")
        );
    }

    private List<ToolContext> resolveTools(JsonNode manifest) {
        JsonNode toolsNode = manifest.path("tools");
        if (!toolsNode.isArray() || toolsNode.isEmpty()) {
            throw evidenceIncomplete("Agent release manifest tools must be a non-empty array");
        }

        Set<String> names = new LinkedHashSet<>();
        List<ToolContext> tools = new ArrayList<>();
        for (JsonNode tool : toolsNode) {
            if (!tool.isObject()) {
                throw evidenceIncomplete("Agent release manifest contains an invalid Tool definition");
            }
            String name = requiredText(tool, "name", "Agent release Tool");
            if (!names.add(name)) {
                throw evidenceIncomplete("Agent release manifest contains duplicate Tool name " + name);
            }
            tools.add(new ToolContext(
                    name,
                    requiredText(tool, "description", "Agent release Tool"),
                    requiredObject(tool, "inputSchema", "Agent release Tool")
            ));
        }
        return List.copyOf(tools);
    }

    private RuntimeCaseContext resolveRuntimeCase(
            UUID testRunId,
            String caseKey,
            String currentApplicantId
    ) {
        List<RuntimeCaseRow> matches = jdbcTemplate.query("""
                select applicant_customer_key,
                       status,
                       allowed_document_ids_json::text,
                       context_json::text
                  from sandbox_loan_cases
                 where namespace_id = ? and case_key = ?
                """, (resultSet, rowNumber) -> new RuntimeCaseRow(
                resultSet.getString("applicant_customer_key"),
                resultSet.getString("status"),
                resultSet.getString("allowed_document_ids_json"),
                resultSet.getString("context_json")
        ), testRunId, caseKey);

        if (matches.size() != 1) {
            throw evidenceIncomplete("Sandbox Agent case context is missing or duplicated");
        }

        RuntimeCaseRow row = matches.getFirst();
        if (!currentApplicantId.equals(row.applicantCustomerKey())) {
            throw evidenceIncomplete("Agent currentApplicantId does not match trusted sandbox case applicant");
        }
        if (row.status() == null || row.status().isBlank()) {
            throw evidenceIncomplete("Sandbox Agent case status is missing");
        }

        JsonNode allowedDocumentIdsNode = parseJson(
                row.allowedDocumentIdsJson(),
                "Sandbox allowedDocumentIds"
        );
        if (!allowedDocumentIdsNode.isArray()) {
            throw evidenceIncomplete("Sandbox allowedDocumentIds must be an array");
        }

        Set<String> uniqueDocumentIds = new LinkedHashSet<>();
        for (JsonNode documentIdNode : allowedDocumentIdsNode) {
            if (!documentIdNode.isString() || documentIdNode.asString().isBlank()) {
                throw evidenceIncomplete("Sandbox allowedDocumentIds contains an invalid document id");
            }
            if (!uniqueDocumentIds.add(documentIdNode.asString())) {
                throw evidenceIncomplete("Sandbox allowedDocumentIds contains duplicate document id");
            }
        }

        JsonNode context = parseObject(row.contextJson(), "Sandbox Agent case context");
        return new RuntimeCaseContext(
                caseKey,
                currentApplicantId,
                row.status(),
                context,
                List.copyOf(uniqueDocumentIds)
        );
    }

    private List<DocumentContext> resolveDocuments(
            UUID testRunId,
            String caseKey,
            List<String> allowedDocumentIds
    ) {
        if (allowedDocumentIds.isEmpty()) {
            return List.of();
        }

        List<DocumentContext> documents = new ArrayList<>();
        for (String documentId : allowedDocumentIds) {
            List<DocumentRow> matches = jdbcTemplate.query("""
                    select document_key,
                           document_type,
                           content_encrypted,
                           content_digest,
                           trust_level,
                           classification_json::text
                      from sandbox_documents
                     where namespace_id = ?
                       and case_key = ?
                       and document_key = ?
                    """, (resultSet, rowNumber) -> new DocumentRow(
                    resultSet.getString("document_key"),
                    resultSet.getString("document_type"),
                    resultSet.getString("content_encrypted"),
                    resultSet.getString("content_digest"),
                    resultSet.getString("trust_level"),
                    resultSet.getString("classification_json")
            ), testRunId, caseKey, documentId);

            if (matches.size() != 1) {
                throw evidenceIncomplete(
                        "Allowed sandbox document is missing, duplicated, or outside the trusted case scope"
                );
            }

            DocumentRow row = matches.getFirst();
            if (row.documentType() == null || row.documentType().isBlank()
                    || row.trustLevel() == null || row.trustLevel().isBlank()) {
                throw evidenceIncomplete("Allowed sandbox document metadata is incomplete");
            }
            if (row.contentEncrypted() == null || row.contentEncrypted().isBlank()) {
                throw evidenceIncomplete("Allowed sandbox document encrypted content is missing");
            }

            String content;
            try {
                content = encryptionService.decrypt(row.contentEncrypted());
            } catch (BusinessException exception) {
                throw exception;
            } catch (RuntimeException exception) {
                throw evidenceIncomplete("Allowed sandbox document could not be decrypted");
            }
            if (content.isBlank()) {
                throw evidenceIncomplete("Allowed sandbox document content is empty");
            }
            if (row.contentDigest() == null
                    || !row.contentDigest().matches("sha256:[0-9a-f]{64}")
                    || !row.contentDigest().equals(digestService.sha256(content))) {
                throw evidenceIncomplete("Allowed sandbox document digest does not match decrypted content");
            }

            documents.add(new DocumentContext(
                    row.documentKey(),
                    row.documentType(),
                    content,
                    row.contentDigest(),
                    row.trustLevel(),
                    parseObject(row.classificationJson(), "Sandbox document classification")
            ));
        }
        return List.copyOf(documents);
    }

    private JsonNode requiredObject(JsonNode parent, String fieldName, String label) {
        JsonNode value = parent.path(fieldName);
        if (!value.isObject()) {
            throw evidenceIncomplete(label + " is missing object field " + fieldName);
        }
        return value;
    }

    private String requiredText(JsonNode parent, String fieldName, String label) {
        JsonNode value = parent.path(fieldName);
        if (!value.isString() || value.asString().isBlank()) {
            throw evidenceIncomplete(label + " is missing text field " + fieldName);
        }
        return value.asString();
    }

    private JsonNode parseObject(String raw, String label) {
        JsonNode parsed = parseJson(raw, label);
        if (!parsed.isObject()) {
            throw evidenceIncomplete(label + " must be a JSON object");
        }
        return parsed;
    }

    private JsonNode parseJson(String raw, String label) {
        if (raw == null || raw.isBlank()) {
            throw evidenceIncomplete(label + " is missing");
        }
        try {
            JsonNode parsed = objectMapper.readTree(raw);
            if (parsed == null) {
                throw evidenceIncomplete(label + " is missing");
            }
            return parsed;
        } catch (BusinessException exception) {
            throw exception;
        } catch (Exception exception) {
            throw evidenceIncomplete(label + " contains malformed JSON");
        }
    }

    private BusinessException evidenceIncomplete(String message) {
        return new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, message);
    }

    private record ReleaseManifestRow(
            UUID releaseId,
            UUID workspaceId,
            String manifestJson
    ) {
    }

    private record PromptArtifactRow(
            String encryptedText,
            String sha256
    ) {
    }

    private record RuntimeCaseRow(
            String applicantCustomerKey,
            String status,
            String allowedDocumentIdsJson,
            String contextJson
    ) {
    }

    private record DocumentRow(
            String documentKey,
            String documentType,
            String contentEncrypted,
            String contentDigest,
            String trustLevel,
            String classificationJson
    ) {
    }
}
