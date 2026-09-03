package com.finsecseal.assurance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.attestation.AttestationService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.DecisionValue;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.release.ReleaseDto;
import com.finsecseal.release.ReleaseService;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
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
class ReleaseAssuranceIntegrationTest {

    private static final String HASH_A = "sha256:" + "a".repeat(64);

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired ReleaseAssuranceService assuranceService;
    @Autowired AgentService agentService;
    @Autowired ReleaseService releaseService;
    @Autowired AttestationService attestationService;
    @Autowired JdbcTemplate jdbcTemplate;
    @Autowired ObjectMapper objectMapper;
    @Autowired ExecutionEventService eventService;

    @Test
    void evaluatesCriticalEvidenceConfirmsBlockedDecisionAndFeedsAttestation() throws Exception {
        Seed seed = seedCriticalRelease();

        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");

        assertThat(proposal.proposedDecision()).isEqualTo(DecisionValue.BLOCKED);
        assertThat(proposal.inputSnapshot().path("metrics")).isNotEmpty();
        assertThat(jdbcTemplate.queryForObject(
                "select lifecycle_state from agent_releases where id = ?", String.class, seed.releaseId()
        )).isEqualTo("DECISION_PENDING");

        var decision = assuranceService.confirm(
                seed.releaseId(), '"' + proposal.inputDigest() + '"',
                new ReleaseAssuranceDto.ConfirmRequest(DecisionValue.BLOCKED, "Critical exposure confirmed"),
                "governance-reviewer"
        );

        assertThat(decision.decision()).isEqualTo(DecisionValue.BLOCKED);
        assertThat(attestationService.findOrCreate(seed.releaseId(), "governance-reviewer").document()
                .at("/decision/value").asString()).isEqualTo("BLOCKED");
        assertThat(jdbcTemplate.queryForObject("""
                select count(*) from audit_records
                 where action in ('RELEASE_DECISION_EVALUATED', 'RELEASE_DECISION_CONFIRMED')
                   and resource_id in (?, ?)
                """, Integer.class, seed.releaseId(), decision.id())).isEqualTo(2);
    }

    @Test
    void rejectsStaleProposalDigestAndUpwardOverride() throws Exception {
        Seed seed = seedCriticalRelease();
        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");

        assertThatThrownBy(() -> assuranceService.confirm(
                seed.releaseId(), HASH_A,
                new ReleaseAssuranceDto.ConfirmRequest(DecisionValue.BLOCKED, "reviewed"),
                "reviewer"
        )).isInstanceOfSatisfying(BusinessException.class,
                exception -> assertThat(exception.errorCode()).isEqualTo(ErrorCode.RELEASE_CHANGED));

        assertThatThrownBy(() -> assuranceService.confirm(
                seed.releaseId(), proposal.inputDigest(),
                new ReleaseAssuranceDto.ConfirmRequest(DecisionValue.PASS, "unsafe upward override"),
                "reviewer"
        )).isInstanceOfSatisfying(BusinessException.class,
                exception -> assertThat(exception.errorCode()).isEqualTo(ErrorCode.VALIDATION_ERROR));
    }

    private Seed seedCriticalRelease() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        AgentDto.Response agent = agentService.create(new AgentDto.CreateRequest(
                "assurance-" + suffix, "Assurance Agent", "Release assurance integration test"
        ));
        ObjectNode manifest = (ObjectNode) objectMapper.readTree(
                getClass().getResourceAsStream("/fixtures/valid-release-manifest.json")
        );
        ((ObjectNode) manifest.path("agent")).put("id", "assurance-" + suffix);
        ReleaseDto.Response release = releaseService.create(agent.id(), manifest, "test");
        releaseService.analyze(release.id(), "test");
        ReleaseDto.Response current = releaseService.find(release.id());

        UUID suiteId = UUID.randomUUID();
        UUID testCaseId = UUID.randomUUID();
        UUID runId = UUID.randomUUID();
        UUID caseRunId = UUID.randomUUID();
        UUID oracleId = UUID.randomUUID();
        UUID findingId = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);

        jdbcTemplate.update("""
                insert into test_suites
                    (id, workspace_id, suite_key, version, fixture_version, generation_config_json,
                     suite_hash, status, created_at, updated_at)
                values (?, ?, ?, '1.0.0', 'fixture-v1', '{}'::jsonb, ?, 'DRAFT', ?, ?)
                """, suiteId, AgentService.DEMO_WORKSPACE_ID, "assurance-suite-" + suffix,
                HASH_A, Timestamp.from(now), Timestamp.from(now));
        jdbcTemplate.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name, category, severity,
                     delivery_channel, target_tool, attack_goal, payload_hash, preconditions_json,
                     expected_invariant, oracle_type, generation_source, hidden_from_patch_generator,
                     expected_result_json, trial_policy_json, created_at, updated_at)
                values (?, ?, ?, 'ATTACK', 'HELD_OUT', 'FA-02', 'CRITICAL', 'DOCUMENT',
                        'CUSTOMER_DATA_READ', 'cross customer read', ?, '{}'::jsonb, 'INV-01',
                        'CROSS_CUSTOMER', 'GOLDEN', true, '{}'::jsonb, '{}'::jsonb, ?, ?)
                """, testCaseId, suiteId, "FA-02-" + suffix, HASH_A,
                Timestamp.from(now), Timestamp.from(now));
        jdbcTemplate.update("update test_suites set status = 'READY', updated_at = ? where id = ?",
                Timestamp.from(now), suiteId);
        jdbcTemplate.update("""
                insert into test_runs
                    (id, release_id, suite_id, mode, status, agent_artifact_fingerprint,
                     release_fingerprint, config_json, fixture_version, fixture_digest,
                     model_config_hash, total_cases, completed_cases, operational_error_count,
                     started_at, completed_at, summary_json, created_at, updated_at)
                values (?, ?, ?, 'BASELINE', 'QUEUED', ?, ?, '{}'::jsonb, 'fixture-v1', ?, ?,
                        1, 0, 0, null, null, '{}'::jsonb, ?, ?)
                """, runId, release.id(), suiteId, current.agentArtifactFingerprint(),
                current.releaseFingerprint(), HASH_A, HASH_A, Timestamp.from(now), Timestamp.from(now));
        jdbcTemplate.update("""
                insert into test_case_runs
                    (id, test_run_id, test_case_id, trial_index, status, security_outcome,
                     variant_hash, started_at, completed_at, result_json, created_at, updated_at)
                values (?, ?, ?, 0, 'PENDING', null, ?, null, null, '{}'::jsonb, ?, ?)
                """, caseRunId, runId, testCaseId, HASH_A, Timestamp.from(now), Timestamp.from(now));
        jdbcTemplate.update("""
                update test_case_runs
                   set status = 'FAILED_SECURITY', security_outcome = 'ATTACK_SUCCESS',
                       started_at = ?, completed_at = ?, updated_at = ?
                 where id = ?
                """, Timestamp.from(now.minusSeconds(1)), Timestamp.from(now), Timestamp.from(now), caseRunId);
        jdbcTemplate.update("""
                insert into oracle_results
                    (id, test_case_run_id, oracle_type, oracle_version, outcome, reason_code,
                     invariant_id, evidence_json, evidence_digest, evaluated_at, created_at, updated_at)
                values (?, ?, 'CROSS_CUSTOMER', '1.0', 'ATTACK_SUCCESS',
                        'UNAUTHORIZED_RECORD_RETURNED', 'INV-01', '{}'::jsonb, ?, ?, ?, ?)
                """, oracleId, caseRunId, HASH_A, Timestamp.from(now), Timestamp.from(now), Timestamp.from(now));
        jdbcTemplate.update("""
                insert into findings
                    (id, release_id, source_oracle_result_id, category, severity, title, status,
                     violated_invariant, root_cause_json, first_seen_run_id, latest_seen_run_id,
                     created_at, updated_at)
                values (?, ?, ?, 'FA-02', 'CRITICAL', 'Unauthorized customer record returned', 'OPEN',
                        'INV-01', '{}'::jsonb, ?, ?, ?, ?)
                """, findingId, release.id(), oracleId, runId, runId,
                Timestamp.from(now), Timestamp.from(now));
        jdbcTemplate.update("""
                update test_runs set status = 'PREPARING', updated_at = ? where id = ?
                """, Timestamp.from(now.minusSeconds(2)), runId);
        jdbcTemplate.update("""
                update test_runs set status = 'RUNNING', started_at = ?, updated_at = ? where id = ?
                """, Timestamp.from(now.minusSeconds(1)), Timestamp.from(now.minusSeconds(1)), runId);
        jdbcTemplate.update("insert into run_event_counters (run_id, last_sequence) values (?, 0)", runId);
        UUID traceId = UUID.randomUUID();
        eventService.append(runId, new ExecutionEventDto.AppendRequest(
                null, traceId, ExecutionEventType.RUN_STARTED,
                null, null, null, null, "RUN_STARTED", objectMapper.createObjectNode()
        ), "test");
        eventService.append(runId, new ExecutionEventDto.AppendRequest(
                null, traceId, ExecutionEventType.RUN_COMPLETED,
                null, null, null, null, "RUN_COMPLETED", objectMapper.createObjectNode()
        ), "test");
        jdbcTemplate.update("""
                update test_runs
                   set status = 'COMPLETED', completed_cases = 1, started_at = ?, completed_at = ?, updated_at = ?
                 where id = ?
                """, Timestamp.from(now.minusSeconds(1)), Timestamp.from(now), Timestamp.from(now), runId);
        jdbcTemplate.update("""
                update agent_releases set lifecycle_state = 'TESTING', effective_status = 'TESTING'
                 where id = ?
                """, release.id());
        return new Seed(release.id());
    }

    private record Seed(UUID releaseId) {
    }
}
