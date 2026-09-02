package com.finsecseal.release;

import static org.assertj.core.api.Assertions.assertThat;

import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.common.api.BusinessException;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
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
@SpringBootTest(properties = "spring.datasource.hikari.maximum-pool-size=2")
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
    void twoConcurrentSuccessAndRollbackCallsDoNotStarvePoolAndPreserveAudits() throws Exception {
        ReleaseDto.Response first = createRelease();
        ReleaseDto.Response second = createRelease();
        int firstBefore = promptAuditCount(first.id());
        int secondBefore = promptAuditCount(second.id());

        try (var executor = Executors.newFixedThreadPool(2)) {
            var firstSuccess = executor.submit(() -> releaseService.fingerprint(first.id(), "prompt-audit-test"));
            var secondSuccess = executor.submit(() -> releaseService.fingerprint(second.id(), "prompt-audit-test"));
            assertThat(firstSuccess.get(5, TimeUnit.SECONDS).releaseFingerprint()).isNotBlank();
            assertThat(secondSuccess.get(5, TimeUnit.SECONDS).releaseFingerprint()).isNotBlank();

            tamper(first.id());
            tamper(second.id());
            var firstFailure = executor.submit(() -> fingerprintFailure(first.id()));
            var secondFailure = executor.submit(() -> fingerprintFailure(second.id()));
            assertThat(firstFailure.get(5, TimeUnit.SECONDS)).isInstanceOf(BusinessException.class);
            assertThat(secondFailure.get(5, TimeUnit.SECONDS)).isInstanceOf(BusinessException.class);
        }

        assertThat(promptAuditCount(first.id())).isEqualTo(firstBefore + 2);
        assertThat(promptAuditCount(second.id())).isEqualTo(secondBefore + 2);
        assertThat(latestPurpose(first.id())).isEqualTo("FINGERPRINT_INTEGRITY_CHECK");
        assertThat(latestPurpose(second.id())).isEqualTo("FINGERPRINT_INTEGRITY_CHECK");
    }

    private ReleaseDto.Response createRelease() throws Exception {
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
        return releaseService.create(agent.id(), manifest, "prompt-audit-test");
    }

    private void tamper(UUID releaseId) {
        jdbcTemplate.update("""
                update release_artifacts
                   set content_json = '{"tampered":true}'::jsonb
                 where release_id = ? and artifact_type = 'MODEL_CONFIG'
                """, releaseId);
    }

    private Throwable fingerprintFailure(UUID releaseId) {
        try {
            releaseService.fingerprint(releaseId, "prompt-audit-test");
            return null;
        } catch (Throwable throwable) {
            return throwable;
        }
    }

    private String latestPurpose(UUID releaseId) {
        return jdbcTemplate.queryForObject("""
                select metadata_json->>'purpose' from audit_records
                 where resource_type = 'AGENT_RELEASE' and resource_id = ?
                   and action = 'SYSTEM_PROMPT_DECRYPTED_INTERNAL'
                 order by occurred_at desc, id desc limit 1
                """, String.class, releaseId);
    }

    private int promptAuditCount(UUID releaseId) {
        return jdbcTemplate.queryForObject("""
                select count(*) from audit_records
                 where resource_type = 'AGENT_RELEASE' and resource_id = ?
                   and action = 'SYSTEM_PROMPT_DECRYPTED_INTERNAL'
                """, Integer.class, releaseId);
    }
}
