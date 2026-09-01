package com.finsecseal.release;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.domain.ReleaseLifecycleState;
import jakarta.persistence.EntityManager;
import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Testcontainers
@SpringBootTest
@Transactional
class ReleaseIntegrationTest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired
    AgentService agentService;

    @Autowired
    ReleaseService releaseService;

    @Autowired
    JdbcTemplate jdbcTemplate;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    EntityManager entityManager;

    JsonNode manifest;

    @BeforeEach
    void loadManifest() throws IOException {
        manifest = objectMapper.readTree(getClass().getResourceAsStream("/fixtures/valid-release-manifest.json"));
    }

    @Test
    void createsValidatesFingerprintsAndAnalyzesReleaseWithoutPlaintextPrompt() {
        AgentDto.Response agent = agentService.create(new AgentDto.CreateRequest(
                "loan-document-review-agent",
                "Loan Review Agent",
                "Document completeness only"
        ));

        ReleaseDto.Response created = releaseService.create(agent.id(), manifest);

        assertThat(created.lifecycleState()).isEqualTo(ReleaseLifecycleState.DRAFT);
        assertThat(created.agentArtifactFingerprint()).matches("sha256:[0-9a-f]{64}");
        assertThat(releaseService.validate(created.id()).valid()).isTrue();
        assertThat(releaseService.fingerprint(created.id()).components())
                .containsKeys("modelHash", "systemPromptHash", "toolSetHash", "humanBoundaryHash");

        String storedManifest = jdbcTemplate.queryForObject(
                "select manifest_json::text from agent_releases where id = ?",
                String.class,
                created.id()
        );
        String encryptedPrompt = jdbcTemplate.queryForObject(
                "select content_text_encrypted from release_artifacts "
                        + "where release_id = ? and artifact_type = 'SYSTEM_PROMPT'",
                String.class,
                created.id()
        );
        assertThat(storedManifest)
                .doesNotContain("Review only document completeness")
                .contains("[ENCRYPTED]");
        assertThat(encryptedPrompt)
                .startsWith("aesgcm:v1:")
                .doesNotContain("Review only document completeness");
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from release_tools where release_id = ?",
                Integer.class,
                created.id()
        )).isEqualTo(5);
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from release_rag_sources where release_id = ?",
                Integer.class,
                created.id()
        )).isEqualTo(1);

        ReleaseDto.Response analyzed = releaseService.analyze(created.id());
        assertThat(analyzed.lifecycleState()).isEqualTo(ReleaseLifecycleState.ANALYZED);
        assertThat(releaseService.analyze(created.id()).lifecycleState())
                .isEqualTo(ReleaseLifecycleState.ANALYZED);
        entityManager.flush();
        entityManager.clear();
        assertThat(jdbcTemplate.queryForObject(
                "select manifest_json::text from agent_releases where id = ?",
                String.class,
                created.id()
        )).doesNotContain("Review only document completeness").contains("[ENCRYPTED]");
        assertThat(jdbcTemplate.queryForObject("""
                select count(*) from audit_records
                 where resource_type = 'AGENT_RELEASE' and resource_id = ?
                   and action = 'SYSTEM_PROMPT_DECRYPTED_INTERNAL'
                """, Integer.class, created.id())).isEqualTo(3);
    }

    @Test
    void rejectsManifestForDifferentAgentAndDuplicateVersion() {
        AgentDto.Response agent = agentService.create(new AgentDto.CreateRequest(
                "loan-document-review-agent",
                "Loan Review Agent",
                "Document completeness only"
        ));
        releaseService.create(agent.id(), manifest);

        JsonNode wrongAgent = manifest.deepCopy();
        ((tools.jackson.databind.node.ObjectNode) wrongAgent.path("agent")).put("id", "another-agent");
        assertThatThrownBy(() -> releaseService.create(agent.id(), wrongAgent))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("agent.id");

        assertThatThrownBy(() -> releaseService.create(agent.id(), manifest))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("already exists");
    }

    @Test
    void rejectsCatalogDefinitionDriftWithoutVersionChange() {
        AgentDto.Response agent = agentService.create(new AgentDto.CreateRequest(
                "loan-document-review-agent",
                "Loan Review Agent",
                "Document completeness only"
        ));
        releaseService.create(agent.id(), manifest);

        JsonNode drifted = manifest.deepCopy();
        ((tools.jackson.databind.node.ObjectNode) drifted.path("release")).put("version", "1.0.1");
        ((tools.jackson.databind.node.ObjectNode) drifted.path("tools").get(0))
                .put("description", "Changed without bumping the tool version");

        assertThatThrownBy(() -> releaseService.create(agent.id(), drifted))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("immutable catalog definition");
    }

    @Test
    void detectsDraftDerivedArtifactTamperingBeforeFingerprintOrAnalyze() {
        AgentDto.Response agent = agentService.create(new AgentDto.CreateRequest(
                "loan-document-review-agent",
                "Loan Review Agent",
                "Document completeness only"
        ));
        ReleaseDto.Response release = releaseService.create(agent.id(), manifest);
        jdbcTemplate.update("""
                update release_artifacts
                   set content_json = '{"tampered":true}'::jsonb
                 where release_id = ? and artifact_type = 'MODEL_CONFIG'
                """, release.id());
        entityManager.clear();

        assertThatThrownBy(() -> releaseService.fingerprint(release.id()))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("artifact differs");
    }

    @Test
    void detectsDraftToolCatalogTamperingBeforeAnalyze() {
        AgentDto.Response agent = agentService.create(new AgentDto.CreateRequest(
                "loan-document-review-agent",
                "Loan Review Agent",
                "Document completeness only"
        ));
        ReleaseDto.Response release = releaseService.create(agent.id(), manifest);
        jdbcTemplate.update("""
                update tool_definitions definition
                   set adapter_key = 'loan_decision_update'
                  from release_tools link
                 where link.tool_definition_id = definition.id
                   and link.release_id = ? and definition.tool_key = 'CASE_CONTEXT_READ'
                """, release.id());
        entityManager.clear();

        assertThatThrownBy(() -> releaseService.analyze(release.id()))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("Tool catalog differs");
    }

    @Test
    void manualInvalidationRecordsLatestDecisionEvidence() {
        AgentDto.Response agent = agentService.create(new AgentDto.CreateRequest(
                "loan-document-review-agent",
                "Loan Review Agent",
                "Document completeness only"
        ));
        ReleaseDto.Response release = releaseService.create(agent.id(), manifest);
        releaseService.analyze(release.id());
        jdbcTemplate.update("""
                update agent_releases set lifecycle_state = 'PASS', effective_status = 'PASS'
                 where id = ?
                """, release.id());
        jdbcTemplate.update("""
                insert into release_decisions
                    (id, release_id, decision, gate_policy_version, input_snapshot_json, input_digest,
                     proposed_at, confirmed_by, confirmed_at)
                values
                    ('0198f200-0000-7000-8000-000000009100', ?, 'PASS', '1.0', '{}'::jsonb,
                     'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     now(), 'reviewer', now())
                """, release.id());
        entityManager.clear();

        ReleaseDto.Response invalidated = releaseService.invalidate(
                release.id(),
                objectMapper.createObjectNode().put("code", "MANUAL_REVIEW")
        );

        assertThat(invalidated.lifecycleState()).isEqualTo(ReleaseLifecycleState.NEEDS_REVALIDATION);
        assertThat(jdbcTemplate.queryForObject("""
                select count(*) from decision_invalidations invalidation
                join release_decisions decision on decision.id = invalidation.release_decision_id
                where decision.release_id = ?
                """, Integer.class, release.id())).isEqualTo(1);
    }
}
