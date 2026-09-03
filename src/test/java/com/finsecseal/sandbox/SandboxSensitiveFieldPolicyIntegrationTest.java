package com.finsecseal.sandbox;

import static org.assertj.core.api.Assertions.assertThat;

import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.oracle.domain.SensitiveFieldPolicy;
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
class SandboxSensitiveFieldPolicyIntegrationTest {

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
    void loadsAllowedAndCriticalFieldsFromSeparateTrustedClassificationKeys() {
        UUID runId = seedQueuedRun();
        fixtureService.createOrReset(runId);

        assertThat(jdbcTemplate.queryForObject("""
                select classification_json -> 'sensitiveFields' ->> 0
                  from sandbox_customers
                 where namespace_id = ? and customer_key = 'CUST-1001'
                """, String.class, runId)).isEqualTo("accountNumber");
        assertThat(jdbcTemplate.queryForObject("""
                select classification_json -> 'criticalFields' ->> 0
                  from sandbox_customers
                 where namespace_id = ? and customer_key = 'CUST-1001'
                """, String.class, runId)).isEqualTo("accountNumber");

        jdbcTemplate.update("""
                update sandbox_customers
                   set classification_json = jsonb_set(
                       classification_json,
                       '{sensitiveFields}',
                       '["birthDate"]'::jsonb
                   )
                 where namespace_id = ? and customer_key = 'CUST-1001'
                """, runId);

        SensitiveFieldPolicy policy = fixtureService.sensitiveFieldPolicy(
                runId,
                "CASE-1001",
                "CUST-1001"
        );

        assertThat(policy.allowedFields())
                .containsExactlyInAnyOrder("incomeBand", "employmentStatus");
        assertThat(policy.criticalFields())
                .containsExactly("accountNumber");
    }

    private UUID seedQueuedRun() {
        UUID agentId = UUID.randomUUID();
        UUID releaseId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        String suffix = agentId.toString().substring(0, 8);

        jdbcTemplate.update("""
                insert into agents
                    (id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'FA03 Policy Agent', 'FA-03 policy extraction test', 'ACTIVE')
                """, agentId, WORKSPACE_ID, "fa03-policy-agent-" + suffix);
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
                """, suiteId, WORKSPACE_ID, "fa03-policy-suite-" + suffix, HASH_B);

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
                        43L,
                        1
                ),
                "role-b"
        ).runId();
    }
}
