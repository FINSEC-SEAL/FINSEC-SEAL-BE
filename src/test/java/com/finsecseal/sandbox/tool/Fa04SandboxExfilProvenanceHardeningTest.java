package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.sandbox.SandboxFixtureService;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;

@Testcontainers
@SpringBootTest
class Fa04SandboxExfilProvenanceHardeningTest {

    private static final String HASH_A = "sha256:" + "a".repeat(64);
    private static final String HASH_B = "sha256:" + "b".repeat(64);
    private static final String ACTOR = "role-b";
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

    @Test
    void collectorEventRejectsCaseRunFromDifferentNamespaceRun() {
        Seed seed = seedTwoRunsWithRunANamespaceAndRunBCaseRun();

        assertThatThrownBy(() -> jdbcTemplate.update("""
                insert into sandbox_exfil_events
                    (namespace_id, event_key, test_case_run_id, url_label,
                     body_redacted, sensitive_token_hashes_json, received_at)
                values (?, ?, ?, 'mock-exfil.invalid',
                        '{}'::jsonb, '{}'::jsonb, now())
                """,
                seed.runAId(),
                UUID.randomUUID(),
                seed.caseRunBId()
        )).isInstanceOf(DataIntegrityViolationException.class);
    }

    private Seed seedTwoRunsWithRunANamespaceAndRunBCaseRun() {
        UUID agentId = UUID.randomUUID();
        UUID releaseAId = UUID.randomUUID();
        UUID releaseBId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        UUID testCaseId = UUID.randomUUID();
        UUID caseRunBId = UUID.randomUUID();
        String suffix = agentId.toString().substring(0, 8);

        jdbcTemplate.update("""
                insert into agents
                    (id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'FA04 Provenance Agent',
                        'FA-04 provenance hardening test', 'ACTIVE')
                """,
                agentId,
                WORKSPACE_ID,
                "fa04-provenance-" + suffix
        );

        jdbcTemplate.update("""
                insert into agent_releases
                    (id, agent_id, version, business_purpose, manifest_schema_version,
                     manifest_json, agent_artifact_fingerprint, release_fingerprint,
                     lifecycle_state, effective_status)
                values (?, ?, '1.0.0', 'LOAN_DOCUMENT_COMPLETENESS_REVIEW', '1.0',
                        '{}'::jsonb, ?, ?, 'ANALYZED', 'ANALYZED')
                """,
                releaseAId,
                agentId,
                HASH_A,
                HASH_A
        );

        jdbcTemplate.update("""
                insert into agent_releases
                    (id, agent_id, version, business_purpose, manifest_schema_version,
                     manifest_json, agent_artifact_fingerprint, release_fingerprint,
                     lifecycle_state, effective_status)
                values (?, ?, '1.0.1', 'LOAN_DOCUMENT_COMPLETENESS_REVIEW', '1.0',
                        '{}'::jsonb, ?, ?, 'ANALYZED', 'ANALYZED')
                """,
                releaseBId,
                agentId,
                HASH_A,
                HASH_B
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
                "fa04-provenance-suite-" + suffix,
                HASH_B
        );

        jdbcTemplate.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name,
                     category, severity, delivery_channel, target_tool,
                     attack_goal, payload_hash, preconditions_json,
                     expected_invariant, oracle_type, generation_source,
                     expected_result_json, trial_policy_json)
                values (?, ?, 'FA04-PROVENANCE-B', 'ATTACK', 'SEED',
                        'FA-04', 'CRITICAL', 'DIRECT', 'EXTERNAL_HTTP',
                        'Cross-run provenance rejection',
                        ?, '{"caseId":"CASE-1001","currentApplicantId":"CUST-1001"}'::jsonb,
                        'INV-04', 'EXFILTRATION', 'CURATED',
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

        UUID runAId = registerRun(releaseAId, suiteId, 51L);
        UUID runBId = registerRun(releaseBId, suiteId, 52L);

        fixtureService.createOrReset(runAId);

        jdbcTemplate.update("""
                insert into test_case_runs
                    (id, test_run_id, test_case_id, trial_index, status,
                     variant_hash, started_at)
                values (?, ?, ?, 0, 'EXECUTING', ?, now())
                """,
                caseRunBId,
                runBId,
                testCaseId,
                HASH_A
        );

        return new Seed(runAId, runBId, caseRunBId);
    }

    private UUID registerRun(
            UUID releaseId,
            UUID suiteId,
            long randomSeed
    ) {
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
                        randomSeed,
                        1
                ),
                ACTOR
        ).runId();
    }

    private record Seed(
            UUID runAId,
            UUID runBId,
            UUID caseRunBId
    ) {
    }
}
