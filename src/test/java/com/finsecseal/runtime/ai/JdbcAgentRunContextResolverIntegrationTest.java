package com.finsecseal.runtime.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.EncryptionService;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Testcontainers
@SpringBootTest
class JdbcAgentRunContextResolverIntegrationTest {

    private static final String HASH_A = "sha256:" + "a".repeat(64);
    private static final String HASH_B = "sha256:" + "b".repeat(64);
    private static final UUID WORKSPACE_ID =
            UUID.fromString("0198f1e2-0000-7000-8000-000000000001");
    private static final String SYSTEM_PROMPT =
            "Review only the current applicant's allowed documents.";
    private static final String DOCUMENT_CONTENT = "synthetic document content";

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES =
            new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired JdbcTemplate jdbcTemplate;
    @Autowired ObjectMapper objectMapper;
    @Autowired EncryptionService encryptionService;
    @Autowired DigestService digestService;
    @Autowired TestRunPersistenceService runPersistenceService;
    @Autowired AgentRunContextResolver resolver;

    @Test
    void resolvesTrustedManifestAndSandboxContextWithoutServerToolCatalog() {
        Seed seed = seedRun(SeedOptions.normal(false));

        AgentRunContextResolver.ResolvedAgentExecutionContext context = resolver.resolve(
                seed.runId(),
                "CASE-1001",
                "CUST-1001"
        );

        assertThat(context.releaseId()).isEqualTo(seed.releaseId());
        assertThat(context.model().provider()).isEqualTo("openai-compatible");
        assertThat(context.model().name()).isEqualTo("configured-model-id");
        assertThat(context.systemPrompt()).isEqualTo(SYSTEM_PROMPT);
        assertThat(context.systemPrompt()).isNotEqualTo("[ENCRYPTED]");
        assertThat(context.businessContext().code()).isEqualTo("LOAN_DOCUMENT_COMPLETENESS_REVIEW");
        assertThat(context.runtime().caseKey()).isEqualTo("CASE-1001");
        assertThat(context.runtime().currentApplicantId()).isEqualTo("CUST-1001");
        assertThat(context.runtime().allowedDocumentIds()).isEmpty();
        assertThat(context.documents()).isEmpty();
        assertThat(context.tools())
                .extracting(AgentRunContextResolver.ToolContext::name)
                .containsExactly("CUSTOMER_DATA_READ")
                .doesNotContain("LOAN_DECISION_UPDATE");

        Integer promptAuditCount = jdbcTemplate.queryForObject("""
                select count(*)
                  from audit_records
                 where resource_type = 'AGENT_RELEASE'
                   and resource_id = ?
                   and action = 'SYSTEM_PROMPT_DECRYPTED_INTERNAL'
                """, Integer.class, seed.releaseId());
        assertThat(promptAuditCount).isEqualTo(1);
    }

    @Test
    void rejectsApplicantMismatchBeforeDecryptingSystemPrompt() {
        Seed seed = seedRun(SeedOptions.normal(false));

        assertThatThrownBy(() -> resolver.resolve(seed.runId(), "CASE-1001", "CUST-9999"))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE)
                );

        Integer promptAuditCount = jdbcTemplate.queryForObject("""
                select count(*)
                  from audit_records
                 where resource_type = 'AGENT_RELEASE'
                   and resource_id = ?
                   and action = 'SYSTEM_PROMPT_DECRYPTED_INTERNAL'
                """, Integer.class, seed.releaseId());
        assertThat(promptAuditCount).isZero();
    }

    @Test
    void resolvesAndDecryptsOnlyExplicitlyAllowedDocument() {
        Seed seed = seedRun(SeedOptions.normal(true));

        AgentRunContextResolver.ResolvedAgentExecutionContext context = resolver.resolve(
                seed.runId(),
                "CASE-1001",
                "CUST-1001"
        );

        assertThat(context.runtime().allowedDocumentIds()).containsExactly("DOC-1001");
        assertThat(context.documents()).hasSize(1);
        AgentRunContextResolver.DocumentContext document = context.documents().getFirst();
        assertThat(document.documentId()).isEqualTo("DOC-1001");
        assertThat(document.content()).isEqualTo(DOCUMENT_CONTENT);
        assertThat(document.contentDigest()).isEqualTo(digestService.sha256(DOCUMENT_CONTENT));
    }

    @Test
    void rejectsAllowedDocumentThatDoesNotExistInSameRunAndCase() {
        Seed seed = seedRun(new SeedOptions(
                false,
                true,
                false,
                PromptArtifactMode.VALID,
                false
        ));

        assertThatThrownBy(() -> resolver.resolve(seed.runId(), "CASE-1001", "CUST-1001"))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE)
                );
    }

    @Test
    void rejectsTamperedDocumentDigest() {
        Seed seed = seedRun(new SeedOptions(
                true,
                false,
                true,
                PromptArtifactMode.VALID,
                false
        ));

        assertThatThrownBy(() -> resolver.resolve(seed.runId(), "CASE-1001", "CUST-1001"))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE)
                );
    }

    @Test
    void rejectsMissingSystemPromptArtifact() {
        Seed seed = seedRun(new SeedOptions(
                false,
                false,
                false,
                PromptArtifactMode.MISSING,
                false
        ));

        assertThatThrownBy(() -> resolver.resolve(seed.runId(), "CASE-1001", "CUST-1001"))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE)
                );
    }

    @Test
    void rejectsTamperedSystemPromptDigest() {
        Seed seed = seedRun(new SeedOptions(
                false,
                false,
                false,
                PromptArtifactMode.TAMPERED_DIGEST,
                false
        ));

        assertThatThrownBy(() -> resolver.resolve(seed.runId(), "CASE-1001", "CUST-1001"))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE)
                );
    }

    @Test
    void rejectsMalformedRequiredManifestContext() {
        Seed seed = seedRun(new SeedOptions(
                false,
                false,
                false,
                PromptArtifactMode.VALID,
                true
        ));

        assertThatThrownBy(() -> resolver.resolve(seed.runId(), "CASE-1001", "CUST-1001"))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE)
                );
    }

    private Seed seedRun(SeedOptions options) {
        UUID agentId = UUID.randomUUID();
        UUID releaseId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        String suffix = agentId.toString().substring(0, 8);
        String promptDigest = digestService.sha256(SYSTEM_PROMPT);

        jdbcTemplate.update("""
                insert into agents
                    (id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'AI Context Agent', 'trusted Agent execution context test', 'ACTIVE')
                """, agentId, WORKSPACE_ID, "agent-context-" + suffix);

        ObjectNode manifest = options.malformedManifest()
                ? objectMapper.createObjectNode().putObject("model")
                : storedManifest(promptDigest);
        jdbcTemplate.update("""
                insert into agent_releases
                    (id, agent_id, version, business_purpose, manifest_schema_version, manifest_json,
                     agent_artifact_fingerprint, release_fingerprint, lifecycle_state, effective_status)
                values (?, ?, '1.0.0', 'LOAN_DOCUMENT_COMPLETENESS_REVIEW', '1.1', ?::jsonb,
                        ?, ?, 'DRAFT', 'DRAFT')
                """, releaseId, agentId, json(manifest), HASH_A, HASH_A);

        if (options.promptArtifactMode() != PromptArtifactMode.MISSING) {
            String artifactDigest = options.promptArtifactMode() == PromptArtifactMode.TAMPERED_DIGEST
                    ? HASH_A
                    : promptDigest;
            ObjectNode promptMetadata = objectMapper.createObjectNode();
            promptMetadata.put("length", SYSTEM_PROMPT.length());
            promptMetadata.put("sha256", artifactDigest);
            jdbcTemplate.update("""
                    insert into release_artifacts
                        (id, release_id, artifact_type, name, content_json, content_text_encrypted,
                         sha256, canonicalization_version, sensitivity)
                    values (?, ?, 'SYSTEM_PROMPT', 'system-prompt', ?::jsonb, ?, ?, ?, 'SECRET')
                    """,
                    UUID.randomUUID(),
                    releaseId,
                    json(promptMetadata),
                    encryptionService.encrypt(SYSTEM_PROMPT),
                    artifactDigest,
                    CanonicalJsonService.VERSION
            );
        }

        jdbcTemplate.update("""
                update agent_releases
                   set lifecycle_state = 'ANALYZED', effective_status = 'ANALYZED'
                 where id = ?
                """, releaseId);

        jdbcTemplate.update("""
                insert into test_suites
                    (id, workspace_id, suite_key, version, fixture_version, generation_config_json,
                     suite_hash, status)
                values (?, ?, ?, '1.0.0', 'golden-v1', '{}'::jsonb, ?, 'READY')
                """, suiteId, WORKSPACE_ID, "agent-context-suite-" + suffix, HASH_B);

        UUID runId = runPersistenceService.register(
                new TestRunPersistenceDto.RegisterRequest(
                        releaseId,
                        suiteId,
                        null,
                        TestRunMode.BASELINE,
                        UUID.randomUUID(),
                        objectMapper.createObjectNode().put("schemaVersion", "1.0"),
                        HASH_B,
                        HASH_B,
                        42L,
                        1
                ),
                "role-b"
        ).runId();

        jdbcTemplate.update("""
                insert into sandbox_namespaces
                    (id, fixture_version, fixture_digest, state, expires_at)
                values (?, 'golden-v1', ?, 'ACTIVE', ?)
                """, runId, HASH_B, Timestamp.from(Instant.now().plusSeconds(3600)));

        jdbcTemplate.update("""
                insert into sandbox_customers
                    (namespace_id, customer_key, display_name_token, profile_json, classification_json)
                values (?, 'CUST-1001', 'SYNTH-CUSTOMER-1001',
                        '{"incomeBand":"MIDDLE","employmentStatus":"EMPLOYED"}'::jsonb,
                        '{"sensitiveFields":[],"criticalFields":[],"syntheticOnly":true}'::jsonb)
                """, runId);

        String allowedDocuments;
        if (options.missingDocument()) {
            allowedDocuments = "[\"DOC-MISSING\"]";
        } else if (options.withDocument()) {
            allowedDocuments = "[\"DOC-1001\"]";
        } else {
            allowedDocuments = "[]";
        }
        jdbcTemplate.update("""
                insert into sandbox_loan_cases
                    (namespace_id, case_key, applicant_customer_key, status,
                     allowed_document_ids_json, context_json)
                values (?, 'CASE-1001', 'CUST-1001', 'IN_REVIEW', ?::jsonb,
                        '{"currentApplicantId":"CUST-1001","allowedFields":["incomeBand"]}'::jsonb)
                """, runId, allowedDocuments);

        if (options.withDocument()) {
            String documentDigest = options.tamperedDocumentDigest()
                    ? HASH_A
                    : digestService.sha256(DOCUMENT_CONTENT);
            jdbcTemplate.update("""
                    insert into sandbox_documents
                        (namespace_id, document_key, case_key, owner_customer_key, document_type,
                         content_encrypted, content_digest, trust_level, classification_json)
                    values (?, 'DOC-1001', 'CASE-1001', 'CUST-1001', 'INCOME_STATEMENT',
                            ?, ?, 'UNTRUSTED_EXTERNAL', '{"syntheticOnly":true}'::jsonb)
                    """,
                    runId,
                    encryptionService.encrypt(DOCUMENT_CONTENT),
                    documentDigest
            );
        }

        return new Seed(runId, releaseId);
    }

    private ObjectNode storedManifest(String promptDigest) {
        ObjectNode root = objectMapper.createObjectNode();

        ObjectNode model = root.putObject("model");
        model.put("provider", "openai-compatible");
        model.put("name", "configured-model-id");
        model.putObject("parameters").put("temperature", 0).put("maxTokens", 2048);

        root.putObject("systemPrompt")
                .put("text", "[ENCRYPTED]")
                .put("storedSha256", promptDigest);
        root.putObject("businessPurpose")
                .put("code", "LOAN_DOCUMENT_COMPLETENESS_REVIEW")
                .put("description", "Assist document completeness review only.");
        root.putObject("businessWorkflow").putArray("allowedStages").add("DOCUMENT_REVIEW");

        ObjectNode tool = root.putArray("tools").addObject();
        tool.put("name", "CUSTOMER_DATA_READ");
        tool.put("description", "Read explicitly allowed synthetic customer fields");
        tool.putObject("inputSchema").put("type", "object").putObject("properties");

        root.putObject("serverToolCatalog")
                .putArray("tools")
                .addObject()
                .put("name", "LOAN_DECISION_UPDATE");
        return root;
    }

    private String json(ObjectNode node) {
        try {
            return objectMapper.writeValueAsString(node);
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    private enum PromptArtifactMode {
        VALID,
        MISSING,
        TAMPERED_DIGEST
    }

    private record SeedOptions(
            boolean withDocument,
            boolean missingDocument,
            boolean tamperedDocumentDigest,
            PromptArtifactMode promptArtifactMode,
            boolean malformedManifest
    ) {
        static SeedOptions normal(boolean withDocument) {
            return new SeedOptions(
                    withDocument,
                    false,
                    false,
                    PromptArtifactMode.VALID,
                    false
            );
        }
    }

    private record Seed(UUID runId, UUID releaseId) {
    }
}
