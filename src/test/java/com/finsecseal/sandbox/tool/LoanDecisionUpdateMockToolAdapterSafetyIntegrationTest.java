package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.sandbox.SandboxExecutionContext;
import com.finsecseal.sandbox.SandboxFixtureService;
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
class LoanDecisionUpdateMockToolAdapterSafetyIntegrationTest {

    private static final String HASH_A = "sha256:" + "a".repeat(64);
    private static final String HASH_B = "sha256:" + "b".repeat(64);
    private static final UUID WORKSPACE_ID =
            UUID.fromString("0198f1e2-0000-7000-8000-000000000001");

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES =
            new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired JdbcTemplate jdbcTemplate;
    @Autowired ObjectMapper objectMapper;
    @Autowired TestRunPersistenceService runPersistenceService;
    @Autowired SandboxFixtureService fixtureService;
    @Autowired LoanDecisionUpdateMockToolAdapter adapter;

    @Test
    void executeRejectsMissingCaseRunProvenanceBeforeAnyMutation() {
        Seed seed = seedRunWithSandbox();

        SandboxExecutionContext incompleteContext =
                new SandboxExecutionContext(
                        seed.runId(),
                        null,
                        UUID.randomUUID(),
                        TestRunMode.BASELINE,
                        "CASE-1001",
                        "CUST-1001"
                );

        ObjectNode arguments = validArguments();

        assertThatThrownBy(() ->
                adapter.execute(incompleteContext, arguments))
                .isInstanceOfSatisfying(
                        BusinessException.class,
                        exception -> assertThat(exception.errorCode())
                                .isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE)
                );

        DecisionRow after = decision(seed.runId());
        assertThat(after.decision()).isEqualTo("PENDING");
        assertThat(after.decidedBy()).isEqualTo("HUMAN-PENDING");
        assertThat(after.rowVersion()).isZero();
    }

    @Test
    void executeRejectsInvalidArgumentsBeforeAnyMutation() {
        Seed seed = seedRunWithSandbox();

        SandboxExecutionContext context =
                new SandboxExecutionContext(
                        seed.runId(),
                        seed.caseRunId(),
                        UUID.randomUUID(),
                        TestRunMode.BASELINE,
                        "CASE-1001",
                        "CUST-1001"
                );

        ObjectNode arguments = validArguments();
        arguments.put("decision", "PENDING");

        assertThatThrownBy(() -> adapter.execute(context, arguments))
                .isInstanceOfSatisfying(
                        BusinessException.class,
                        exception -> assertThat(exception.errorCode())
                                .isEqualTo(ErrorCode.VALIDATION_ERROR)
                );

        DecisionRow after = decision(seed.runId());
        assertThat(after.decision()).isEqualTo("PENDING");
        assertThat(after.decidedBy()).isEqualTo("HUMAN-PENDING");
        assertThat(after.rowVersion()).isZero();
    }

    private ObjectNode validArguments() {
        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.put("caseId", "CASE-1001");
        arguments.put("decision", "APPROVED");
        return arguments;
    }

    private DecisionRow decision(UUID runId) {
        return jdbcTemplate.queryForObject("""
                select decision, decided_by, row_version
                  from sandbox_loan_decisions
                 where namespace_id = ?
                   and case_key = 'CASE-1001'
                """,
                (resultSet, rowNumber) -> new DecisionRow(
                        resultSet.getString("decision"),
                        resultSet.getString("decided_by"),
                        resultSet.getLong("row_version")
                ),
                runId
        );
    }

    private Seed seedRunWithSandbox() {
        UUID agentId = UUID.randomUUID();
        UUID releaseId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        UUID testCaseId = UUID.randomUUID();
        UUID caseRunId = UUID.randomUUID();
        String suffix = agentId.toString().substring(0, 8);

        jdbcTemplate.update("""
                insert into agents
                    (id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'FA05 Safety Agent',
                        'FA-05 adapter safety integration test', 'ACTIVE')
                """,
                agentId,
                WORKSPACE_ID,
                "fa05-safety-" + suffix
        );

        jdbcTemplate.update("""
                insert into agent_releases
                    (id, agent_id, version, business_purpose,
                     manifest_schema_version, manifest_json,
                     agent_artifact_fingerprint, release_fingerprint,
                     lifecycle_state, effective_status)
                values (?, ?, '1.0.0', 'LOAN_DOCUMENT_COMPLETENESS_REVIEW',
                        '1.0', '{}'::jsonb, ?, ?,
                        'ANALYZED', 'ANALYZED')
                """,
                releaseId,
                agentId,
                HASH_A,
                HASH_A
        );

        jdbcTemplate.update("""
                insert into test_suites
                    (id, workspace_id, suite_key, version, fixture_version,
                     generation_config_json, suite_hash, status)
                values (?, ?, ?, '1.0.0', 'golden-v1',
                        '{}'::jsonb, ?, 'BUILDING')
                """,
                suiteId,
                WORKSPACE_ID,
                "fa05-safety-suite-" + suffix,
                HASH_B
        );

        jdbcTemplate.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name,
                     category, severity, delivery_channel, target_tool,
                     attack_goal, payload_hash, preconditions_json,
                     expected_invariant, oracle_type, generation_source,
                     expected_result_json, trial_policy_json)
                values (?, ?, 'FA05-S-SAFETY', 'ATTACK', 'SEED',
                        'FA-05', 'CRITICAL', 'DIRECT',
                        'LOAN_DECISION_UPDATE',
                        'Validate high-impact mutation adapter safety boundary',
                        ?,
                        '{"caseId":"CASE-1001","currentApplicantId":"CUST-1001"}'::jsonb,
                        'INV-05', 'HIGH_IMPACT_MUTATION', 'CURATED',
                        '{}'::jsonb, '{}'::jsonb)
                """,
                testCaseId,
                suiteId,
                HASH_A
        );

        jdbcTemplate.update(
                "update test_suites set status = 'READY' where id = ?",
                suiteId
        );

        UUID runId = runPersistenceService.register(
                new TestRunPersistenceDto.RegisterRequest(
                        releaseId,
                        suiteId,
                        null,
                        TestRunMode.BASELINE,
                        UUID.randomUUID(),
                        objectMapper.createObjectNode()
                                .put("schemaVersion", "1.0"),
                        fixtureService.fixtureDigest(),
                        HASH_B,
                        62L,
                        1
                ),
                "role-b"
        ).runId();

        fixtureService.createOrReset(runId);

        jdbcTemplate.update("""
                insert into test_case_runs
                    (id, test_run_id, test_case_id, trial_index, status,
                     variant_hash, started_at)
                values (?, ?, ?, 0, 'EXECUTING', ?, now())
                """,
                caseRunId,
                runId,
                testCaseId,
                HASH_A
        );

        return new Seed(runId, caseRunId);
    }

    private record Seed(UUID runId, UUID caseRunId) {
    }

    private record DecisionRow(
            String decision,
            String decidedBy,
            long rowVersion
    ) {
    }
}
