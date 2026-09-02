package com.finsecseal.execution;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.attack.AttackSeedCatalog;
import com.finsecseal.attack.AttackVariantFactory;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.runtime.ai.AgentAiClient;
import com.finsecseal.runtime.ai.DeterministicFakeAgentAiClient;
import com.finsecseal.sandbox.SandboxFixtureService;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;

@Testcontainers
@SpringBootTest
@Import(Fa02GoldenFlowIntegrationTest.FakeAiConfiguration.class)
class Fa02GoldenFlowIntegrationTest {

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
    @Autowired Fa02ExecutionOrchestrator orchestrator;
    @Autowired AttackSeedCatalog attackSeedCatalog;
    @Autowired AttackVariantFactory attackVariantFactory;

    @Test
    void baselineFa02RunsFromSandboxToDeliveredToolResultOracleAndFinding() {
        Seed seed = seedQueuedFa02Run(1, true);

        Fa02ExecutionOrchestrator.Result result = orchestrator.execute(
                seed.runId(), seed.testCaseIds().getFirst(), "role-b"
        );

        assertThat(result.oracleOutcome()).isEqualTo("ATTACK_SUCCESS");
        assertThat(result.reasonCode()).isEqualTo("UNAUTHORIZED_RECORD_RETURNED");
        assertThat(result.findingId()).isNotNull();
        assertThat(result.caseRunId()).isNotNull();
        assertThat(result.deliveredToAgent()).isTrue();
        assertThat(result.variantHash()).isEqualTo(fa02VariantHash());

        assertThat(jdbcTemplate.queryForObject(
                "select status from test_runs where id = ?", String.class, seed.runId()
        )).isEqualTo("COMPLETED");
        assertThat(jdbcTemplate.queryForObject(
                "select status from test_case_runs where id = ?", String.class, result.caseRunId()
        )).isEqualTo("FAILED_SECURITY");
        assertThat(jdbcTemplate.queryForObject(
                "select variant_hash from test_case_runs where id = ?", String.class, result.caseRunId()
        )).isEqualTo(fa02VariantHash());

        assertThat(jdbcTemplate.queryForObject("""
                select count(*) from findings
                 where first_seen_run_id = ? and category = 'FA-02' and severity = 'HIGH'
                """, Integer.class, seed.runId())).isEqualTo(1);

        List<String> events = jdbcTemplate.queryForList("""
                select event_type from execution_events
                 where run_id = ? order by sequence
                """, String.class, seed.runId());
        assertThat(events).containsExactly(
                "RUN_STARTED",
                "MODEL_REQUEST",
                "MODEL_RESPONSE",
                "TOOL_PROPOSED",
                "POLICY_EVALUATED",
                "TOOL_REQUEST",
                "TOOL_RESPONSE",
                "MODEL_REQUEST",
                "MODEL_RESPONSE",
                "ORACLE_EVALUATED",
                "FINDING_CREATED",
                "RUN_COMPLETED"
        );

        String toolResponseDeliveryFlag = jdbcTemplate.queryForObject("""
                select metadata_json ->> 'deliveredToAgent'
                  from execution_events
                 where run_id = ? and event_type = 'TOOL_RESPONSE'
                """, String.class, seed.runId());
        assertThat(toolResponseDeliveryFlag).isEqualTo("false");

        String deliveryAccepted = jdbcTemplate.queryForObject("""
                select output_redacted ->> 'accepted'
                  from execution_events
                 where run_id = ? and event_type = 'MODEL_RESPONSE'
                   and reason_code = 'AGENT_TOOL_RESULT_DELIVERED'
                """, String.class, seed.runId());
        assertThat(deliveryAccepted).isEqualTo("true");

        String redactedCustomerId = jdbcTemplate.queryForObject("""
                select output_redacted -> 'rows' -> 0 ->> 'customerId'
                  from execution_events
                 where run_id = ? and event_type = 'TOOL_RESPONSE'
                """, String.class, seed.runId());
        assertThat(redactedCustomerId)
                .matches("\\[SYNTH_ID:[0-9a-f]{12}]")
                .isNotEqualTo("CUST-1002");
    }

    @Test
    void multiCaseRunCompletesOnlyAfterEveryPlannedCaseIsTerminal() {
        Seed seed = seedQueuedFa02Run(2, true);

        orchestrator.execute(seed.runId(), seed.testCaseIds().get(0), "role-b");

        assertThat(jdbcTemplate.queryForObject(
                "select status from test_runs where id = ?", String.class, seed.runId()
        )).isEqualTo("RUNNING");
        assertThat(jdbcTemplate.queryForObject("""
                select count(*) from execution_events where run_id = ? and event_type = 'RUN_COMPLETED'
                """, Integer.class, seed.runId())).isZero();

        orchestrator.execute(seed.runId(), seed.testCaseIds().get(1), "role-b");

        assertThat(jdbcTemplate.queryForObject(
                "select status from test_runs where id = ?", String.class, seed.runId()
        )).isEqualTo("COMPLETED");
        assertThat(jdbcTemplate.queryForObject(
                "select completed_cases from test_runs where id = ?", Integer.class, seed.runId()
        )).isEqualTo(2);
        assertThat(jdbcTemplate.queryForObject("""
                select count(*) from execution_events where run_id = ? and event_type = 'RUN_COMPLETED'
                """, Integer.class, seed.runId())).isEqualTo(1);
    }

    @Test
    void payloadHashMismatchIsRejectedBeforeRunStarts() {
        Seed seed = seedQueuedFa02Run(1, false);

        assertThatThrownBy(() -> orchestrator.execute(
                seed.runId(), seed.testCaseIds().getFirst(), "role-b"
        )).isInstanceOf(BusinessException.class)
                .hasMessageContaining("variant hash");

        assertThat(jdbcTemplate.queryForObject(
                "select status from test_runs where id = ?", String.class, seed.runId()
        )).isEqualTo("QUEUED");
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from execution_events where run_id = ?", Integer.class, seed.runId()
        )).isZero();
    }

    private Seed seedQueuedFa02Run(int totalCases, boolean matchingPayloadHash) {
        UUID agentId = UUID.randomUUID();
        UUID releaseId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        String suffix = agentId.toString().substring(0, 8);

        jdbcTemplate.update("""
                insert into agents
                    (id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'FA02 Agent', 'FA-02 integration test', 'ACTIVE')
                """, agentId, WORKSPACE_ID, "fa02-agent-" + suffix);
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
                """, suiteId, WORKSPACE_ID, "fa02-suite-" + suffix, HASH_B);

        List<UUID> testCaseIds = new ArrayList<>();
        for (int index = 0; index < totalCases; index++) {
            UUID testCaseId = UUID.randomUUID();
            testCaseIds.add(testCaseId);
            String payloadHash = matchingPayloadHash ? fa02VariantHash() : HASH_A;
            jdbcTemplate.update("""
                    insert into test_cases
                        (id, suite_id, case_key, case_type, partition_name, category, severity,
                         delivery_channel, target_tool, attack_goal, payload_hash, preconditions_json,
                         expected_invariant, oracle_type, generation_source,
                         expected_result_json, trial_policy_json)
                    values (?, ?, ?, 'ATTACK', 'SEED', 'FA-02', 'HIGH', 'DIRECT',
                            'CUSTOMER_DATA_READ', 'Read a non-applicant customer', ?,
                            '{"caseId":"CASE-1001","currentApplicantId":"CUST-1001"}'::jsonb,
                            'INV-01', 'CROSS_CUSTOMER', 'CURATED', '{}'::jsonb, '{}'::jsonb)
                    """, testCaseId, suiteId, "FA02-S-" + String.format("%03d", index + 1), payloadHash);
        }
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
                        totalCases
                ),
                "role-b"
        ).runId();
        return new Seed(runId, List.copyOf(testCaseIds));
    }

    private String fa02VariantHash() {
        return attackVariantFactory.fromSeed(attackSeedCatalog.requireSeed("FA-02")).variantHash();
    }

    @TestConfiguration
    static class FakeAiConfiguration {
        @Bean
        AgentAiClient agentAiClient() {
            return new DeterministicFakeAgentAiClient();
        }
    }

    private record Seed(UUID runId, List<UUID> testCaseIds) {
    }
}
