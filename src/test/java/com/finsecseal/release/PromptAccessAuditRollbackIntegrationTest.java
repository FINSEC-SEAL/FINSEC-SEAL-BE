package com.finsecseal.release;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.common.api.BusinessException;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Testcontainers
@SpringBootTest
class PromptAccessAuditRollbackIntegrationTest {

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

    @Test
    void preservesPromptAccessAuditWhenIntegrityFailureRollsBackTheCaller() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String agentKey = "prompt-audit-" + suffix;
        AgentDto.Response agent = agentService.create(new AgentDto.CreateRequest(
                agentKey,
                "Prompt Audit Agent",
                "Rollback-safe audit verification"
        ));
        JsonNode manifest = objectMapper.readTree(
                getClass().getResourceAsStream("/fixtures/valid-release-manifest.json")
        );
        ((ObjectNode) manifest.path("agent")).put("id", agentKey);
        ReleaseDto.Response release = releaseService.create(agent.id(), manifest, "prompt-audit-test");
        int before = promptAuditCount(release.id());
        jdbcTemplate.update("""
                update release_artifacts
                   set content_json = '{"tampered":true}'::jsonb
                 where release_id = ? and artifact_type = 'MODEL_CONFIG'
                """, release.id());

        assertThatThrownBy(() -> releaseService.fingerprint(release.id(), "prompt-audit-test"))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("artifact differs");

        assertThat(promptAuditCount(release.id())).isEqualTo(before + 1);
        assertThat(jdbcTemplate.queryForObject("""
                select metadata_json->>'purpose' from audit_records
                 where resource_type = 'AGENT_RELEASE' and resource_id = ?
                   and action = 'SYSTEM_PROMPT_DECRYPTED_INTERNAL'
                 order by occurred_at desc, id desc limit 1
                """, String.class, release.id())).isEqualTo("FINGERPRINT_INTEGRITY_CHECK");
    }

    private int promptAuditCount(UUID releaseId) {
        return jdbcTemplate.queryForObject("""
                select count(*) from audit_records
                 where resource_type = 'AGENT_RELEASE' and resource_id = ?
                   and action = 'SYSTEM_PROMPT_DECRYPTED_INTERNAL'
                """, Integer.class, releaseId);
    }
}
