package com.finsecseal.execution;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.attack.AttackSeedCatalog;
import com.finsecseal.attack.AttackVariantFactory;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.sandbox.SandboxFixtureService;
import java.util.List;
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
class Fa02RuntimeFailureIntegrationTest {

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
    @Autowired AttackSeedCatalog attackSeedCatalog;
    @Autowired AttackVariantFactory attackVariantFactory;
    @Autowired Fa02ExecutionOrchestrator orchestrator;

    @Test
    void missingProductionAiClientSealsCaseAndRunAsOperationalFailure() {
        Seed seed = seedQueuedRun();

        assertThatThrownBy(() -> orchestrator.execute(seed.runId(), seed.testCaseId(), "role-b"))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("Agent AI client is not configured");

        assertThat(jdbcTemplate.queryForObject(
                "select status from test_runs where id = ?", String.class, seed.runId()
        )).isEqualTo("FAILED");
        assertThat(jdbcTemplate.queryForObject(
                "select operational_error_count from test_runs where id = ?", Integer.class, seed.runId()
        )).isEqualTo(1);
        assertThat(jdbcTemplate.queryForObject(
                "select status from test_case_runs where test_run_id = ?", String.class, seed.runId()
        )).isEqualTo("ERROR");
        assertThat(jdbcTemplate.queryForObject(
                "select error_code from test_case_runs where test_run_id = ?", String.class, seed.runId()
        )).isEqualTo("RUNTIME_EXECUTION_ERROR");

        List<String> events = jdbcTemplate.queryForList("""
                select event_type from execution_events where run_id = ? order by sequence
                """, String.class, seed.runId());
        assertThat(events).containsExactly("RUN_STARTED", "RUN_FAILED");
    }

    private Seed seedQueuedRun() {
        UUID agentId = UUID.randomUUID();
        UUID releaseId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        UUID testCaseId = UUID.randomUUID();
        String suffix = agentId.toString().substring(0, 8);
        String variantHash = attackVariantFactory.fromSeed(
                attackSeedCatalog.requireSeed("FA-02")
        ).variantHash();

        jdbcTemplate.update("""
                insert into agents
                    (id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'Failure Agent', 'FA-02 failure lifecycle test', 'ACTIVE')
                """, agentId, WORKSPACE_ID, "failure-agent-" + suffix);
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
                values (?, ?, ?, '1.0.0', 'golden-v1', '{}'::jsonb, ?, 'BUILDING')
                """, suiteId, WORKSPACE_ID, "failure-suite-" + suffix, HASH_B);
        jdbcTemplate.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name, category, severity,
                     delivery_channel, target_tool, attack_goal, payload_hash, preconditions_json,
                     expected_invariant, oracle_type, generation_source,
                     expected_result_json, trial_policy_json)
                values (?, ?, 'FA02-FAIL-001', 'ATTACK', 'SEED', 'FA-02', 'HIGH', 'DIRECT',
                        'CUSTOMER_DATA_READ', 'Read a non-applicant customer', ?,
                        '{"caseId":"CASE-1001","currentApplicantId":"CUST-1001"}'::jsonb,
                        'INV-01', 'CROSS_CUSTOMER', 'CURATED', '{}'::jsonb, '{}'::jsonb)
                """, testCaseId, suiteId, variantHash);
        jdbcTemplate.update("update test_suites set status = 'READY' where id = ?", suiteId);

        UUID runId = runPersistenceService.register(
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
        return new Seed(runId, testCaseId);
    }

    private record Seed(UUID runId, UUID testCaseId) {
    }
}
