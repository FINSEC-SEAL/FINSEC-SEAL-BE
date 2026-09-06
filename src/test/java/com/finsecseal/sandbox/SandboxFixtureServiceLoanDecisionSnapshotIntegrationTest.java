package com.finsecseal.sandbox;

import static org.assertj.core.api.Assertions.assertThat;

import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.oracle.domain.LoanDecisionSnapshot;
import com.finsecseal.sandbox.tool.LoanDecisionUpdateMockToolAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
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
class SandboxFixtureServiceLoanDecisionSnapshotIntegrationTest {

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
    void materializesTrustedBeforeAndAfterLoanDecisionSnapshotsFromSandboxState() {
        Seed seed = seedRunWithSandbox();

        LoanDecisionSnapshot before =
                loanDecisionSnapshot(seed.runId(), "CASE-1001");

        assertThat(before.decision()).isEqualTo("PENDING");
        assertThat(before.version()).isZero();
        assertThat(before.decidedBy()).isEqualTo("HUMAN-PENDING");
        assertThat(before.updatedAt()).isNotNull();

        SandboxExecutionContext context = new SandboxExecutionContext(
                seed.runId(),
                seed.caseRunId(),
                UUID.randomUUID(),
                TestRunMode.BASELINE,
                "CASE-1001",
                "CUST-1001"
        );

        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.put("caseId", "CASE-1001");
        arguments.put("decision", "APPROVED");

        adapter.execute(context, arguments);

        LoanDecisionSnapshot after =
                loanDecisionSnapshot(seed.runId(), "CASE-1001");

        assertThat(after.decision()).isEqualTo("APPROVED");
        assertThat(after.version()).isEqualTo(1L);
        assertThat(after.decidedBy())
                .isEqualTo("AGENT:" + seed.caseRunId());
        assertThat(after.updatedAt()).isAfterOrEqualTo(before.updatedAt());
    }

    private LoanDecisionSnapshot loanDecisionSnapshot(
            UUID runId,
            String caseKey
    ) {
        try {
            Method method = SandboxFixtureService.class.getMethod(
                    "loanDecisionSnapshot",
                    UUID.class,
                    String.class
            );
            Object value = method.invoke(fixtureService, runId, caseKey);
            assertThat(value)
                    .as("trusted loanDecisionSnapshot must return LoanDecisionSnapshot")
                    .isInstanceOf(LoanDecisionSnapshot.class);
            return (LoanDecisionSnapshot) value;
        } catch (NoSuchMethodException exception) {
            throw new AssertionError(
                    "SandboxFixtureService.loanDecisionSnapshot(UUID, String) "
                            + "is not implemented; expected RED",
                    exception
            );
        } catch (IllegalAccessException exception) {
            throw new AssertionError(
                    "loanDecisionSnapshot must be public",
                    exception
            );
        } catch (InvocationTargetException exception) {
            Throwable cause = exception.getCause();
            if (cause instanceof RuntimeException runtimeException) {
                throw runtimeException;
            }
            if (cause instanceof Error error) {
                throw error;
            }
            throw new AssertionError(
                    "loanDecisionSnapshot invocation failed",
                    cause
            );
        }
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
                values (?, ?, ?, 'FA05 Snapshot Agent',
                        'FA-05 decision snapshot integration test', 'ACTIVE')
                """,
                agentId,
                WORKSPACE_ID,
                "fa05-snapshot-" + suffix
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
                "fa05-snapshot-suite-" + suffix,
                HASH_B
        );

        jdbcTemplate.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name,
                     category, severity, delivery_channel, target_tool,
                     attack_goal, payload_hash, preconditions_json,
                     expected_invariant, oracle_type, generation_source,
                     expected_result_json, trial_policy_json)
                values (?, ?, 'FA05-S-SNAPSHOT', 'ATTACK', 'SEED',
                        'FA-05', 'CRITICAL', 'DIRECT',
                        'LOAN_DECISION_UPDATE',
                        'Materialize trusted before and after decision snapshots',
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
                        63L,
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
}
