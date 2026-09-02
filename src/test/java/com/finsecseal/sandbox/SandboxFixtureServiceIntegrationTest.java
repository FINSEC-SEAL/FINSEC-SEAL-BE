package com.finsecseal.sandbox;

import static org.assertj.core.api.Assertions.assertThat;

import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
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

@Testcontainers
@SpringBootTest
class SandboxFixtureServiceIntegrationTest {

    private static final String HASH_A = "sha256:" + "a".repeat(64);
    private static final String HASH_B = "sha256:" + "b".repeat(64);
    private static final UUID WORKSPACE_ID = UUID.fromString("0198f1e2-0000-7000-8000-000000000001");

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired JdbcTemplate jdbcTemplate;
    @Autowired ObjectMapper objectMapper;
    @Autowired TestRunPersistenceService runPersistenceService;
    @Autowired SandboxFixtureService fixtureService;

    @Test
    void resetRestoresDeterministicGoldenFixtureAndDigest() {
        UUID runId = seedQueuedRun("sandbox-reset");

        SandboxFixtureService.Snapshot first = fixtureService.createOrReset(runId);
        assertThat(first.fixtureDigest()).isEqualTo(fixtureService.fixtureDigest());
        assertThat(fixtureService.verifyIntegrity(runId)).isTrue();
        assertThat(customerCount(runId)).isEqualTo(3);

        jdbcTemplate.update("""
                update sandbox_customers
                   set profile_json = '{"incomeBand":"BROKEN"}'::jsonb
                 where namespace_id = ? and customer_key = 'CUST-1002'
                """, runId);
        assertThat(fixtureService.verifyIntegrity(runId)).isFalse();

        SandboxFixtureService.Snapshot reset = fixtureService.createOrReset(runId);

        assertThat(reset.fixtureDigest()).isEqualTo(first.fixtureDigest());
        assertThat(customerCount(runId)).isEqualTo(3);
        assertThat(fixtureService.verifyIntegrity(runId)).isTrue();
        assertThat(jdbcTemplate.queryForObject("""
                select profile_json ->> 'incomeBand'
                  from sandbox_customers
                 where namespace_id = ? and customer_key = 'CUST-1002'
                """, String.class, runId)).isEqualTo("HIGH");
    }

    private int customerCount(UUID runId) {
        return jdbcTemplate.queryForObject(
                "select count(*) from sandbox_customers where namespace_id = ?",
                Integer.class,
                runId
        );
    }

    private UUID seedQueuedRun(String suffix) {
        UUID agentId = UUID.randomUUID();
        UUID releaseId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        String keySuffix = suffix + '-' + agentId.toString().substring(0, 8);

        jdbcTemplate.update("""
                insert into agents
                    (id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'Sandbox Agent', 'Sandbox integration test', 'ACTIVE')
                """, agentId, WORKSPACE_ID, "sandbox-agent-" + keySuffix);
        jdbcTemplate.update("""
                insert into agent_releases
                    (id, agent_id, version, business_purpose, manifest_schema_version, manifest_json,
                     agent_artifact_fingerprint, release_fingerprint, lifecycle_state, effective_status)
                values (?, ?, '1.0.0', 'LOAN_DOCUMENT_COMPLETENESS_REVIEW', '1.0', '{}'::jsonb,
                        ?, ?, 'ANALYZED', 'ANALYZED')
                """, releaseId, agentId, HASH_A, HASH_A);
        jdbcTemplate.update("""
                insert into test_suites
                    (id, workspace_id, suite_key, version, fixture_version, generation_config_json,
                     suite_hash, status)
                values (?, ?, ?, '1.0.0', 'golden-v1', '{}'::jsonb, ?, 'READY')
                """, suiteId, WORKSPACE_ID, "sandbox-suite-" + keySuffix, HASH_B);

        return runPersistenceService.register(
                new TestRunPersistenceDto.RegisterRequest(
                        releaseId,
                        suiteId,
                        null,
                        TestRunMode.BASELINE,
                        UUID.randomUUID(),
                        objectMapper.createObjectNode().put("schemaVersion", "1.0"),
                        fixtureService.fixtureDigest(),
                        HASH_B,
                        42L,
                        1
                ),
                "role-b"
        ).runId();
    }
}
