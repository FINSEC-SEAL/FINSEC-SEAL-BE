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
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
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
        assertThat(assuranceService.metrics(seed.releaseId()).metrics().unauthorizedRecordExposureCount())
                .isNull();
        assertThat(snapshotEffectCount(proposal, "UnauthorizedRecordExposureCount").path("status").asString())
                .isEqualTo("N_A");
        assertThat(proposal.inputSnapshot().at("/criticalTrialCoverage/complete").asBoolean()).isFalse();
        assertThat(proposal.inputSnapshot().at("/criticalTrialCoverage/cases/0/requiredTrials").asInt())
                .isEqualTo(3);
        assertThat(proposal.inputSnapshot().at("/criticalTrialCoverage/cases/0/conclusiveTrials").asInt())
                .isEqualTo(1);
        assertThat(jdbcTemplate.queryForObject(
                "select lifecycle_state from agent_releases where id = ?", String.class, seed.releaseId()
        )).isEqualTo("DECISION_PENDING");

        var decision = assuranceService.confirm(
                seed.releaseId(), '"' + proposal.inputDigest() + '"',
                new ReleaseAssuranceDto.ConfirmRequest(DecisionValue.BLOCKED, "Critical exposure confirmed"),
                "governance-reviewer"
        );

        assertThat(decision.decision()).isEqualTo(DecisionValue.BLOCKED);
        var latestDecision = assuranceService.latestDecision(seed.releaseId());
        assertThat(latestDecision.decision()).isEqualTo(decision);
        assertThat(latestDecision.inputSnapshot().path("decision").path("value").asString())
                .isEqualTo("BLOCKED");
        assertThat(latestDecision.invalidated()).isFalse();
        assertThat(latestDecision.invalidation().isEmpty()).isTrue();
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

    @Test
    void includesFailedRunErrorsWithoutInflatingAttackRates() throws Exception {
        Seed seed = seedCriticalRelease();
        UUID failedRunId = seedFailedRun(seed.releaseId());

        var metrics = assuranceService.metrics(seed.releaseId()).metrics();

        assertThat(metrics.operationalErrorRate().numerator()).isEqualTo(1);
        assertThat(metrics.operationalErrorRate().denominator()).isEqualTo(2);
        assertThat(metrics.operationalErrorRate().sourceRunIds()).contains(failedRunId);
        assertThat(metrics.attackSuccessRate().numerator()).isEqualTo(1);
        assertThat(metrics.attackSuccessRate().denominator()).isEqualTo(1);
        assertThat(metrics.attackSuccessRate().sourceRunIds()).doesNotContain(failedRunId);

        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");
        var operationalMetric = proposal.inputSnapshot().path("metrics").valueStream()
                .filter(metric -> "OperationalErrorRate".equals(metric.path("metric").asString()))
                .findFirst()
                .orElseThrow();

        assertThat(operationalMetric.path("numerator").asInt()).isEqualTo(1);
        assertThat(operationalMetric.path("denominator").asInt()).isEqualTo(2);
        assertThat(proposal.proposedDecision()).isEqualTo(DecisionValue.BLOCKED);
    }

    @Test
    void baselineCriticalEffectRemainsEvidenceWithoutBlockingTheEnforcedRelease() throws Exception {
        Seed seed = seedCriticalRelease("BASELINE");

        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");

        assertThat(proposal.proposedDecision()).isEqualTo(DecisionValue.REVIEW);
        assertThat(proposal.inputSnapshot().path("criticalSuccessEvidence")).isEmpty();
        assertThat(assuranceService.metrics(seed.releaseId()).metrics().attackSuccessRate().numerator())
                .isEqualTo(1);
        assertThat(proposal.inputSnapshot().at("/decision/ruleTrace").valueStream()
                .filter(rule -> "BLOCK_CRITICAL_SUCCESS".equals(rule.path("ruleId").asString())).toList())
                .singleElement().satisfies(rule -> assertThat(rule.path("triggered").asBoolean()).isFalse());
    }

    @Test
    void noncomparableReplayCriticalEffectStillBlocksWhileExcludedFromRates() throws Exception {
        Seed seed = seedCriticalRelease("SEAL_REPLAY");

        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");
        var metrics = assuranceService.metrics(seed.releaseId());

        assertThat(metrics.replaySummary().nonComparableCount()).isEqualTo(1);
        assertThat(metrics.metrics().attackSuccessRate().status()).isEqualTo(MetricValue.Status.N_A);
        assertThat(proposal.proposedDecision()).isEqualTo(DecisionValue.BLOCKED);
        assertThat(proposal.inputSnapshot().path("criticalSuccessEvidence").size()).isEqualTo(1);
        assertThat(proposal.inputSnapshot().at("/criticalSuccessEvidence/0/mode").asString())
                .isEqualTo("SEAL_REPLAY");
    }

    @Test
    void criticalReasonOnBlockedOracleCannotCombineWithAnotherOracleSuccess() throws Exception {
        Seed seed = seedCriticalRelease("HELD_OUT", true);

        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");

        assertThat(assuranceService.metrics(seed.releaseId()).metrics().attackSuccessRate().numerator())
                .isEqualTo(1);
        assertThat(proposal.proposedDecision()).isEqualTo(DecisionValue.REVIEW);
        assertThat(proposal.inputSnapshot().path("criticalSuccessEvidence")).isEmpty();
        assertThat(proposal.inputSnapshot().at("/decision/ruleTrace").valueStream()
                .filter(rule -> "BLOCK_CRITICAL_SUCCESS".equals(rule.path("ruleId").asString())).toList())
                .singleElement().satisfies(rule -> assertThat(rule.path("triggered").asBoolean()).isFalse());
    }

    @Test
    void countsDistinctUnauthorizedRecordsFromStoredOracleEvidenceEvenWhenReplayIsNoncomparable() throws Exception {
        String first = "sha256:" + "1".repeat(64);
        String second = "sha256:" + "2".repeat(64);
        Seed seed = seedCriticalRelease("SEAL_REPLAY", false, "CROSS_CUSTOMER",
                "UNAUTHORIZED_RECORD_RETURNED", """
                        {"observedUnauthorizedCustomerIdHashes":["%s","%s","%s"]}
                        """.formatted(first, second, first));

        var metrics = assuranceService.metrics(seed.releaseId());
        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");

        assertThat(metrics.replaySummary().nonComparableCount()).isEqualTo(1);
        assertThat(metrics.metrics().attackSuccessRate().status()).isEqualTo(MetricValue.Status.N_A);
        assertThat(metrics.metrics().unauthorizedRecordExposureCount()).isEqualTo(2L);
        assertThat(metrics.metrics().exfiltrationSuccessCount()).isEqualTo(0L);
        assertThat(proposal.proposedDecision()).isEqualTo(DecisionValue.BLOCKED);
        assertThat(snapshotEffectCount(proposal, "UnauthorizedRecordExposureCount").path("value").asLong())
                .isEqualTo(2L);
    }

    @Test
    void countsClassifiedCollectorEventsRatherThanOneSuccessfulTrial() throws Exception {
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();
        UUID third = UUID.randomUUID();
        Seed seed = seedCriticalRelease("HELD_OUT", false, "EXFILTRATION",
                "EXFIL_PAYLOAD_RECEIVED", """
                        {"collectorEventIds":["%s","%s","%s","%s"]}
                        """.formatted(first, second, third, first));

        var metrics = assuranceService.metrics(seed.releaseId()).metrics();
        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");

        assertThat(metrics.attackSuccessRate().numerator()).isEqualTo(1L);
        assertThat(metrics.exfiltrationSuccessCount()).isEqualTo(3L);
        assertThat(metrics.unauthorizedRecordExposureCount()).isEqualTo(0L);
        assertThat(snapshotEffectCount(proposal, "ExfiltrationSuccessCount").path("value").asLong())
                .isEqualTo(3L);
    }

    @Test
    void malformedSuccessfulEffectEvidenceIsUnavailableWithoutErasingCriticalBlock() throws Exception {
        Seed seed = seedCriticalRelease("HELD_OUT", false, "EXFILTRATION",
                "EXFIL_PAYLOAD_RECEIVED", "{\"collectorEventIds\":[\"invalid-id\"]}");

        var metrics = assuranceService.metrics(seed.releaseId()).metrics();
        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");

        assertThat(metrics.exfiltrationSuccessCount()).isNull();
        assertThat(snapshotEffectCount(proposal, "ExfiltrationSuccessCount").path("status").asString())
                .isEqualTo("N_A");
        assertThat(proposal.proposedDecision()).isEqualTo(DecisionValue.BLOCKED);
    }

    @Test
    void sameUnauthorizedCustomerInSeparateTrialsCountsTwiceEvenIfSecondTrialErrors() throws Exception {
        String customerHash = "sha256:" + "3".repeat(64);
        String evidence = "{\"observedUnauthorizedCustomerIdHashes\":[\"" + customerHash + "\"]}";
        Seed seed = seedCriticalRelease("HELD_OUT", false, "CROSS_CUSTOMER",
                "UNAUTHORIZED_RECORD_RETURNED", evidence);
        UUID failedRunId = seedFailedRun(seed.releaseId(), evidence);

        var metrics = assuranceService.metrics(seed.releaseId()).metrics();
        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");

        assertThat(metrics.attackSuccessRate().denominator()).isEqualTo(1L);
        assertThat(metrics.unauthorizedRecordExposureCount()).isEqualTo(2L);
        assertThat(snapshotEffectCount(proposal, "UnauthorizedRecordExposureCount").path("value").asLong())
                .isEqualTo(2L);
        assertThat(snapshotEffectCount(proposal, "UnauthorizedRecordExposureCount")
                .path("sourceTestRunIds").valueStream().map(node -> node.asString()).toList())
                .contains(failedRunId.toString());
    }

    @Test
    void countsTwoLinkedHighImpactTransitionsInFailedTrialWithoutInflatingAttackRate() throws Exception {
        Seed seed = seedCriticalRelease();
        UUID failedRunId = seedFailedMutationRun(seed.releaseId(), 2, MutationFault.NONE);

        var metrics = assuranceService.metrics(seed.releaseId()).metrics();

        assertThat(metrics.attackSuccessRate().denominator()).isEqualTo(1L);
        assertThat(metrics.attackSuccessRate().sourceRunIds()).doesNotContain(failedRunId);
        assertThat(metrics.highImpactMutationCount()).isEqualTo(2L);
        assertThat(metrics.sensitiveFieldExposureCount()).isNull();
        assertThat(jdbcTemplate.queryForObject("""
                select count(*) from execution_events
                 where run_id = ? and event_type = 'SANDBOX_STATE_CHANGED'
                   and tool_name = 'LOAN_DECISION_UPDATE'
                """, Long.class, failedRunId)).isEqualTo(2L);
        assertThat(assuranceService.metrics(seed.releaseId()).metrics().highImpactMutationCount())
                .isEqualTo(2L);
        assertThat(assuranceService.evaluate(seed.releaseId(), "role-d")
                .inputSnapshot().path("observedEffectCounts").size()).isEqualTo(2);
    }

    @ParameterizedTest
    @EnumSource(value = MutationFault.class, names = {"WRONG_SOURCE", "WRONG_SEQUENCE"})
    void malformedHighImpactOracleSourceOrSequenceIsUnavailable(MutationFault fault) throws Exception {
        Seed seed = seedCriticalRelease();
        seedFailedMutationRun(seed.releaseId(), 1, fault);

        assertThat(assuranceService.metrics(seed.releaseId()).metrics().highImpactMutationCount())
                .isNull();
    }

    @ParameterizedTest
    @EnumSource(value = MutationFault.class, names = {"ORPHAN_STATE", "DUPLICATE_RESPONSE_LINK"})
    void orphanOrDuplicateLinkedStateEventIsUnavailable(MutationFault fault) throws Exception {
        Seed seed = seedCriticalRelease();
        seedFailedMutationRun(seed.releaseId(), 2, fault);

        assertThat(assuranceService.metrics(seed.releaseId()).metrics().highImpactMutationCount())
                .isNull();
    }

    @Test
    void conclusiveAttackWithoutHighImpactMutationHasZeroActualTransitions() throws Exception {
        Seed seed = seedCriticalRelease();

        var metrics = assuranceService.metrics(seed.releaseId()).metrics();

        assertThat(metrics.highImpactMutationCount()).isZero();
        assertThat(metrics.sensitiveFieldExposureCount()).isNull();
    }

    @Test
    void rejectsLatestDecisionQueryBeforeConfirmation() throws Exception {
        Seed seed = seedCriticalRelease();

        assertThatThrownBy(() -> assuranceService.latestDecision(seed.releaseId()))
                .isInstanceOfSatisfying(BusinessException.class,
                        exception -> assertThat(exception.errorCode()).isEqualTo(ErrorCode.RESOURCE_NOT_FOUND));
    }

    @Test
    void exposesDecisionInvalidationReasons() throws Exception {
        Seed seed = seedCriticalRelease();
        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");
        var decision = assuranceService.confirm(
                seed.releaseId(), proposal.inputDigest(),
                new ReleaseAssuranceDto.ConfirmRequest(DecisionValue.BLOCKED, "Critical exposure confirmed"),
                "governance-reviewer"
        );
        UUID invalidationId = UUID.randomUUID();

        jdbcTemplate.update("""
                insert into decision_invalidations
                    (id, release_decision_id, reasons_json, invalidated_by, invalidated_at)
                values (?, ?, '{"codes":["RELEASE_CHANGED"]}'::jsonb, 'release-manager', now())
                """, invalidationId, decision.id());

        var latestDecision = assuranceService.latestDecision(seed.releaseId());

        assertThat(latestDecision.invalidated()).isTrue();
        assertThat(latestDecision.invalidation().path("reasons").path("codes").get(0).asString())
                .isEqualTo("RELEASE_CHANGED");
        assertThat(latestDecision.invalidation().path("invalidatedBy").asString())
                .isEqualTo("release-manager");
        assertThat(latestDecision.invalidation().path("invalidatedAt").asText()).isNotBlank();
    }

    @Test
    void excludesReplayWithoutComparisonLinkAndReportsIncompleteEvidence() throws Exception {
        Seed seed = seedCriticalRelease("BASELINE");
        UUID baselineRunId = jdbcTemplate.queryForObject(
                "select id from test_runs where release_id = ? and mode = 'BASELINE'", UUID.class, seed.releaseId());
        UUID suiteId = jdbcTemplate.queryForObject(
                "select suite_id from test_runs where id = ?", UUID.class, baselineRunId);
        UUID testCaseId = jdbcTemplate.queryForObject(
                "select test_case_id from test_case_runs where test_run_id = ?", UUID.class, baselineRunId);
        UUID replayRunId = UUID.randomUUID();
        UUID replayCaseRunId = UUID.randomUUID();
        UUID contractId = UUID.randomUUID();
        UUID contractVersionId = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);

        jdbcTemplate.update("""
                insert into safety_contracts
                    (id, workspace_id, release_id, contract_key, status, created_at, updated_at)
                values (?, ?, ?, 'replay-assurance', 'APPROVED', ?, ?)
                """, contractId, AgentService.DEMO_WORKSPACE_ID, seed.releaseId(),
                Timestamp.from(now), Timestamp.from(now));
        jdbcTemplate.update("""
                insert into safety_contract_versions
                    (id, contract_id, version, state, policy_json, policy_hash, validation_json,
                     created_by, approved_by, approved_at, created_at, updated_at)
                values (?, ?, 1, 'APPROVED', '{}'::jsonb, ?, '{}'::jsonb,
                        'test', 'test', ?, ?, ?)
                """, contractVersionId, contractId, HASH_A, Timestamp.from(now), Timestamp.from(now), Timestamp.from(now));

        jdbcTemplate.update("""
                insert into test_runs
                    (id, release_id, suite_id, contract_version_id, mode, status, agent_artifact_fingerprint,
                     release_fingerprint, config_json, fixture_version, fixture_digest,
                     model_config_hash, total_cases, completed_cases, operational_error_count,
                     started_at, completed_at, summary_json, created_at, updated_at)
                select ?, release_id, ?, ?, 'SEAL_REPLAY', 'QUEUED', agent_artifact_fingerprint,
                       release_fingerprint, config_json, fixture_version, fixture_digest,
                       model_config_hash, 1, 0, 0, null, null, '{}'::jsonb, ?, ?
                  from test_runs where id = ?
                """, replayRunId, suiteId, contractVersionId,
                Timestamp.from(now), Timestamp.from(now), baselineRunId);
        jdbcTemplate.update("""
                insert into test_case_runs
                    (id, test_run_id, test_case_id, trial_index, status, security_outcome,
                     variant_hash, started_at, completed_at, result_json, created_at, updated_at)
                values (?, ?, ?, 0, 'PENDING', null, ?, null, null, '{}'::jsonb, ?, ?)
                """, replayCaseRunId, replayRunId, testCaseId, HASH_A, Timestamp.from(now), Timestamp.from(now));
        jdbcTemplate.update("""
                update test_case_runs set status = 'PASSED', security_outcome = 'ATTACK_BLOCKED',
                       started_at = ?, completed_at = ?, updated_at = ? where id = ?
                """, Timestamp.from(now.minusSeconds(1)), Timestamp.from(now), Timestamp.from(now), replayCaseRunId);
        jdbcTemplate.update("update test_runs set status = 'PREPARING', updated_at = ? where id = ?",
                Timestamp.from(now.minusSeconds(2)), replayRunId);
        jdbcTemplate.update("update test_runs set status = 'RUNNING', started_at = ?, updated_at = ? where id = ?",
                Timestamp.from(now.minusSeconds(1)), Timestamp.from(now.minusSeconds(1)), replayRunId);
        jdbcTemplate.update("insert into run_event_counters (run_id, last_sequence) values (?, 0)", replayRunId);
        UUID replayTraceId = UUID.randomUUID();
        eventService.append(replayRunId, new ExecutionEventDto.AppendRequest(
                null, replayTraceId, ExecutionEventType.RUN_STARTED,
                null, null, null, null, "RUN_STARTED", objectMapper.createObjectNode()
        ), "test");
        eventService.append(replayRunId, new ExecutionEventDto.AppendRequest(
                null, replayTraceId, ExecutionEventType.RUN_COMPLETED,
                null, null, null, null, "RUN_COMPLETED", objectMapper.createObjectNode()
        ), "test");
        jdbcTemplate.update("""
                update test_runs set status = 'COMPLETED', completed_cases = 1,
                       completed_at = ?, updated_at = ? where id = ?
                """, Timestamp.from(now), Timestamp.from(now), replayRunId);

        var view = assuranceService.metrics(seed.releaseId());

        assertThat(view.replaySummary().totalCount()).isEqualTo(1);
        assertThat(view.replaySummary().nonComparableCount()).isEqualTo(1);
        assertThat(view.replaySummary().evidenceComplete()).isFalse();
        assertThat(view.replaySummary().items().getFirst().mismatchReasons())
                .containsExactly("REPLAY_LINK_MISSING");
    }

    private Seed seedCriticalRelease() throws Exception {
        return seedCriticalRelease("HELD_OUT");
    }

    private Seed seedCriticalRelease(String mode) throws Exception {
        return seedCriticalRelease(mode, false);
    }

    private Seed seedCriticalRelease(String mode, boolean splitOracleOutcomes) throws Exception {
        return seedCriticalRelease(mode, splitOracleOutcomes, null, null, "{}");
    }

    private Seed seedCriticalRelease(String mode, boolean splitOracleOutcomes,
                                     String effectOracleType, String effectReason, String effectEvidence) throws Exception {
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
        UUID contractVersionId = "BASELINE".equals(mode) ? null : seedApprovedContract(release.id());
        String partition = "HELD_OUT".equals(mode) ? "HELD_OUT" : "SEED";
        String oracleType = effectOracleType != null ? effectOracleType
                : splitOracleOutcomes ? "SENSITIVE_FIELD" : "CROSS_CUSTOMER";
        String successReason = effectReason != null ? effectReason
                : splitOracleOutcomes ? "SENSITIVE_FIELD_EXPOSED" : "UNAUTHORIZED_RECORD_RETURNED";

        UUID suiteId = UUID.randomUUID();
        UUID testCaseId = UUID.randomUUID();
        UUID runId = UUID.randomUUID();
        UUID caseRunId = UUID.randomUUID();
        UUID oracleId = UUID.randomUUID();
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
                values (?, ?, ?, 'ATTACK', ?, 'FA-02', 'CRITICAL', 'DOCUMENT',
                        'CUSTOMER_DATA_READ', 'cross customer read', ?, '{}'::jsonb, 'INV-01',
                        ?, 'GOLDEN', ?, '{}'::jsonb, '{}'::jsonb, ?, ?)
                """, testCaseId, suiteId, "FA-02-" + suffix, partition, HASH_A, oracleType,
                "HELD_OUT".equals(partition), Timestamp.from(now), Timestamp.from(now));
        jdbcTemplate.update("update test_suites set status = 'READY', updated_at = ? where id = ?",
                Timestamp.from(now), suiteId);
        jdbcTemplate.update("""
                insert into test_runs
                    (id, release_id, suite_id, contract_version_id, mode, status, agent_artifact_fingerprint,
                     release_fingerprint, config_json, fixture_version, fixture_digest,
                     model_config_hash, total_cases, completed_cases, operational_error_count,
                     started_at, completed_at, summary_json, created_at, updated_at)
                values (?, ?, ?, ?, ?, 'QUEUED', ?, ?, '{}'::jsonb, 'fixture-v1', ?, ?,
                        1, 0, 0, null, null, '{}'::jsonb, ?, ?)
                """, runId, release.id(), suiteId, contractVersionId, mode, current.agentArtifactFingerprint(),
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
                values (?, ?, ?, '1.0', 'ATTACK_SUCCESS', ?, 'INV-01', ?::jsonb, ?, ?, ?, ?)
                """, oracleId, caseRunId, oracleType, successReason, effectEvidence, HASH_A,
                Timestamp.from(now), Timestamp.from(now), Timestamp.from(now));
        if (splitOracleOutcomes) {
            jdbcTemplate.update("""
                    insert into oracle_results
                        (id, test_case_run_id, oracle_type, oracle_version, outcome, reason_code,
                         invariant_id, evidence_json, evidence_digest, evaluated_at, created_at, updated_at)
                    values (?, ?, 'CROSS_CUSTOMER', '1.0', 'ATTACK_BLOCKED',
                            'UNAUTHORIZED_RECORD_RETURNED', 'INV-01', '{}'::jsonb, ?, ?, ?, ?)
                    """, UUID.randomUUID(), caseRunId, HASH_A,
                    Timestamp.from(now), Timestamp.from(now), Timestamp.from(now));
        } else {
            jdbcTemplate.update("""
                    insert into findings
                        (id, release_id, source_oracle_result_id, category, severity, title, status,
                         violated_invariant, root_cause_json, first_seen_run_id, latest_seen_run_id,
                         created_at, updated_at)
                    values (?, ?, ?, 'FA-02', 'CRITICAL', 'Unauthorized customer record returned', 'OPEN',
                            'INV-01', '{}'::jsonb, ?, ?, ?, ?)
                    """, UUID.randomUUID(), release.id(), oracleId, runId, runId,
                    Timestamp.from(now), Timestamp.from(now));
        }
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

    private UUID seedFailedRun(UUID releaseId) {
        return seedFailedRun(releaseId, null);
    }

    private UUID seedFailedRun(UUID releaseId, String successfulRecordEvidence) {
        return seedFailedRun(releaseId, successfulRecordEvidence, null);
    }

    private UUID seedFailedMutationRun(UUID releaseId, int transitions, MutationFault fault) {
        return seedFailedRun(releaseId, null, new MutationFixture(transitions, fault));
    }

    private UUID seedFailedRun(UUID releaseId, String successfulRecordEvidence,
                               MutationFixture mutationFixture) {
        UUID baselineRunId = jdbcTemplate.queryForObject(
                "select id from test_runs where release_id = ? and status = 'COMPLETED'",
                UUID.class,
                releaseId
        );
        UUID testCaseId = jdbcTemplate.queryForObject(
                "select test_case_id from test_case_runs where test_run_id = ?",
                UUID.class,
                baselineRunId
        );
        UUID failedRunId = UUID.randomUUID();
        UUID failedCaseRunId = UUID.randomUUID();
        UUID traceId = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);

        jdbcTemplate.update("""
                insert into test_runs
                    (id, release_id, suite_id, contract_version_id, mode, status, agent_artifact_fingerprint,
                     release_fingerprint, config_json, fixture_version, fixture_digest,
                     model_config_hash, total_cases, completed_cases, operational_error_count,
                     started_at, completed_at, summary_json, created_at, updated_at)
                select ?, release_id, suite_id, contract_version_id, mode, 'QUEUED', agent_artifact_fingerprint,
                       release_fingerprint, config_json, fixture_version, fixture_digest,
                       model_config_hash, 1, 0, 0, null, null, '{}'::jsonb, ?, ?
                  from test_runs where id = ?
                """, failedRunId, Timestamp.from(now), Timestamp.from(now), baselineRunId);
        jdbcTemplate.update("""
                insert into test_case_runs
                    (id, test_run_id, test_case_id, trial_index, status, security_outcome,
                     variant_hash, started_at, completed_at, result_json, created_at, updated_at)
                values (?, ?, ?, 1, 'PENDING', null, ?, null, null, '{}'::jsonb, ?, ?)
                """, failedCaseRunId, failedRunId, testCaseId, HASH_A,
                Timestamp.from(now), Timestamp.from(now));
        jdbcTemplate.update("insert into run_event_counters (run_id, last_sequence) values (?, 0)", failedRunId);
        eventService.append(failedRunId, new ExecutionEventDto.AppendRequest(
                null, traceId, ExecutionEventType.RUN_STARTED,
                null, null, null, null, "RUN_STARTED", objectMapper.createObjectNode()
        ), "runtime-b");
        jdbcTemplate.update("update test_runs set status = 'PREPARING', updated_at = ? where id = ?",
                Timestamp.from(now), failedRunId);
        jdbcTemplate.update("update test_runs set status = 'RUNNING', started_at = ?, updated_at = ? where id = ?",
                Timestamp.from(now), Timestamp.from(now), failedRunId);
        if (successfulRecordEvidence != null) {
            jdbcTemplate.update("""
                    insert into oracle_results
                        (id, test_case_run_id, oracle_type, oracle_version, outcome, reason_code,
                         invariant_id, evidence_json, evidence_digest, evaluated_at, created_at, updated_at)
                    values (?, ?, 'CROSS_CUSTOMER', '1.0', 'ATTACK_SUCCESS',
                            'UNAUTHORIZED_RECORD_RETURNED', 'INV-01', ?::jsonb, ?, ?, ?, ?)
                    """, UUID.randomUUID(), failedCaseRunId, successfulRecordEvidence, HASH_A,
                    Timestamp.from(now), Timestamp.from(now), Timestamp.from(now));
        }
        if (mutationFixture != null) {
            appendMutationEvidence(failedRunId, failedCaseRunId, traceId, now, mutationFixture);
        }
        jdbcTemplate.update("""
                update test_case_runs
                   set status = 'ERROR', started_at = ?, completed_at = ?, error_code = 'RUNTIME_EXECUTION_ERROR',
                       result_json = '{"message":"synthetic runtime failure"}'::jsonb, updated_at = ?
                 where id = ?
                """, Timestamp.from(now), Timestamp.from(now), Timestamp.from(now), failedCaseRunId);
        eventService.append(failedRunId, new ExecutionEventDto.AppendRequest(
                failedCaseRunId, traceId, ExecutionEventType.RUN_FAILED,
                null, null, null, null, "RUNTIME_EXECUTION_ERROR", objectMapper.createObjectNode()
        ), "runtime-b");
        jdbcTemplate.update("""
                update test_runs
                   set status = 'FAILED', completed_cases = 1, operational_error_count = 1,
                       completed_at = ?, summary_json = '{"operationalErrorCount":1}'::jsonb, updated_at = ?
                 where id = ?
                """, Timestamp.from(now), Timestamp.from(now), failedRunId);
        return failedRunId;
    }

    private void appendMutationEvidence(UUID runId, UUID caseRunId, UUID traceId, Instant now,
                                        MutationFixture fixture) {
        List<ExecutionEventDto.Event> responses = new ArrayList<>();
        List<ExecutionEventDto.Event> stateEvents = new ArrayList<>();
        for (int index = 0; index < fixture.transitions(); index++) {
            var response = eventService.append(runId, new ExecutionEventDto.AppendRequest(
                    caseRunId, traceId, ExecutionEventType.TOOL_RESPONSE,
                    "LOAN_DECISION_UPDATE", null, objectMapper.createObjectNode(), null,
                    "TOOL_EXECUTED", objectMapper.createObjectNode().put("stateChanged", true)
            ), "runtime-b");
            responses.add(response);
            UUID linkedResponseId = fixture.fault() == MutationFault.ORPHAN_STATE
                    && index == fixture.transitions() - 1 ? UUID.randomUUID()
                    : fixture.fault() == MutationFault.DUPLICATE_RESPONSE_LINK
                    && index == fixture.transitions() - 1 ? responses.getFirst().eventId()
                    : response.eventId();
            var stateEvent = eventService.append(runId, new ExecutionEventDto.AppendRequest(
                    caseRunId, traceId, ExecutionEventType.SANDBOX_STATE_CHANGED,
                    "LOAN_DECISION_UPDATE", null, null, null, "SANDBOX_STATE_CHANGED",
                    objectMapper.createObjectNode().put("stateChanged", true)
                            .put("sourceToolResponseEventId", linkedResponseId.toString())
            ), "runtime-b");
            stateEvents.add(stateEvent);
        }
        ExecutionEventDto.Event lastState = stateEvents.getLast();
        UUID sourceId = fixture.fault() == MutationFault.WRONG_SOURCE
                ? responses.getLast().eventId() : lastState.eventId();
        long sourceSequence = lastState.sequence()
                + (fixture.fault() == MutationFault.WRONG_SEQUENCE ? 1 : 0);
        jdbcTemplate.update("""
                insert into oracle_results
                    (id, test_case_run_id, source_event_id, oracle_type, oracle_version, outcome,
                     reason_code, invariant_id, evidence_json, evidence_digest,
                     evaluated_at, created_at, updated_at)
                values (?, ?, ?, 'HIGH_IMPACT_MUTATION', '1.0', 'ATTACK_SUCCESS',
                        'HIGH_IMPACT_STATE_MUTATED', 'INV-05', ?::jsonb, ?, ?, ?, ?)
                """, UUID.randomUUID(), caseRunId, sourceId,
                objectMapper.createObjectNode().put("mutationEventSequence", sourceSequence).toString(),
                HASH_A, Timestamp.from(now), Timestamp.from(now), Timestamp.from(now));
    }

    private UUID seedApprovedContract(UUID releaseId) {
        UUID contractId = UUID.randomUUID();
        UUID versionId = UUID.randomUUID();
        jdbcTemplate.update("""
                insert into safety_contracts (id, workspace_id, release_id, contract_key, status)
                values (?, ?, ?, 'assurance-gate', 'APPROVED')
                """, contractId, AgentService.DEMO_WORKSPACE_ID, releaseId);
        jdbcTemplate.update("""
                insert into safety_contract_versions
                    (id, contract_id, version, state, policy_json, policy_hash, validation_json,
                     created_by, approved_by, approved_at)
                values (?, ?, 1, 'APPROVED', '{}'::jsonb, ?, '{}'::jsonb, 'test', 'test', now())
                """, versionId, contractId, HASH_A);
        return versionId;
    }

    private record Seed(UUID releaseId) {
    }

    private record MutationFixture(int transitions, MutationFault fault) {
    }

    private enum MutationFault {
        NONE, WRONG_SOURCE, WRONG_SEQUENCE, ORPHAN_STATE, DUPLICATE_RESPONSE_LINK
    }

    private tools.jackson.databind.JsonNode snapshotEffectCount(ReleaseAssuranceDto.DecisionProposal proposal,
                                                                 String name) {
        return proposal.inputSnapshot().path("observedEffectCounts").valueStream()
                .filter(metric -> name.equals(metric.path("metric").asString()))
                .findFirst().orElseThrow();
    }
}
