package com.finsecseal.sandbox;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.sandbox.tool.CustomerDataReadToolAdapter;
import com.finsecseal.sandbox.tool.ToolAdapter;
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
class CustomerDataReadToolAdapterIntegrationTest {

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
    @Autowired CustomerDataReadToolAdapter adapter;

    @Test
    void rejectsUntrustedNamespaceArgument() {
        UUID runA = seedQueuedRun("namespace-reject");
        fixtureService.createOrReset(runA);

        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.put("namespaceId", UUID.randomUUID().toString());
        arguments.putArray("customerIds").add("CUST-1002");
        arguments.putArray("fields").add("incomeBand");

        SandboxExecutionContext context = new SandboxExecutionContext(
                runA,
                UUID.randomUUID(),
                UUID.randomUUID(),
                TestRunMode.BASELINE,
                "CASE-1001",
                "CUST-1001"
        );

        assertThatThrownBy(() -> adapter.execute(context, arguments))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("unknown arguments");
    }

    @Test
    void readsOnlyTrustedRunNamespaceWithoutClientNamespaceArgument() {
        UUID runA = seedQueuedRun("namespace-a");
        UUID runB = seedQueuedRun("namespace-b");

        fixtureService.createOrReset(runA);
        fixtureService.createOrReset(runB);

        jdbcTemplate.update("""
            update sandbox_customers
               set profile_json = jsonb_set(
                   profile_json,
                   '{incomeBand}',
                   '"B_ONLY"'::jsonb
               )
             where namespace_id = ?
               and customer_key = 'CUST-1002'
            """, runB);

        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.putArray("customerIds").add("CUST-1002");
        arguments.putArray("fields").add("incomeBand");

        SandboxExecutionContext context = new SandboxExecutionContext(
                runA,
                UUID.randomUUID(),
                UUID.randomUUID(),
                TestRunMode.BASELINE,
                "CASE-1001",
                "CUST-1001"
        );

        ToolAdapter.ToolExecutionResult result =
                adapter.execute(context, arguments);

        assertThat(
                result.output()
                        .path("rows")
                        .path(0)
                        .path("customerId")
                        .asString()
        ).isEqualTo("CUST-1002");

        assertThat(
                result.output()
                        .path("rows")
                        .path(0)
                        .path("fields")
                        .path("incomeBand")
                        .asString()
        ).isEqualTo("HIGH");
    }

    private UUID seedQueuedRun(String suffix) {
        UUID agentId = UUID.randomUUID();
        UUID releaseId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        String keySuffix = suffix + '-' + agentId.toString().substring(0, 8);
        jdbcTemplate.update("""
                insert into agents
                    (id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'Namespace Agent', 'Namespace isolation test', 'ACTIVE')
                """, agentId, WORKSPACE_ID, "namespace-agent-" + keySuffix);
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
                """, suiteId, WORKSPACE_ID, "namespace-suite-" + keySuffix, HASH_B);
        return runPersistenceService.register(
                new TestRunPersistenceDto.RegisterRequest(
                        releaseId, suiteId, null, TestRunMode.BASELINE, UUID.randomUUID(),
                        objectMapper.createObjectNode().put("schemaVersion", "1.0"),
                        fixtureService.fixtureDigest(), HASH_B, 42L, 1
                ),
                "role-b"
        ).runId();
    }
}
