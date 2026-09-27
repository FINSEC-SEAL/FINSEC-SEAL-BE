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
import com.finsecseal.release.FingerprintService;
import com.finsecseal.release.ReleaseService;
import com.finsecseal.runtime.CustomerFieldDeliveryEvidence;
import com.finsecseal.sandbox.SandboxFixtureService;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
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
    @Autowired FingerprintService fingerprintService;
    @Autowired AttestationService attestationService;
    @Autowired JdbcTemplate jdbcTemplate;
    @Autowired ObjectMapper objectMapper;
    @Autowired ExecutionEventService eventService;
    @Autowired SandboxFixtureService fixtureService;
    @Autowired CustomerFieldDeliveryEvidence customerEvidence;
    @Autowired SensitiveFieldExposureCounter sensitiveCounter;
    @Autowired PlatformTransactionManager transactionManager;

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
    void policyLatencyUsesAllTerminalEventsAndSerializesApiAndDecisionEvidence() throws Exception {
        Seed seed = seedCriticalReleaseWithPolicy(
                policyDuration(0), policyDuration(1.5), policyDuration(2), policyDuration(10));
        UUID runId = jdbcTemplate.queryForObject(
                "select id from test_runs where release_id = ?", UUID.class, seed.releaseId());
        List<UUID> eventIds = jdbcTemplate.queryForList("""
                select id from execution_events
                 where run_id = ? and event_type = 'POLICY_EVALUATED' order by id
                """, UUID.class, runId);
        seedCriticalReleaseWithPolicy(policyDuration(100)); // another Release must not enter this aggregate

        var api = assuranceService.metrics(seed.releaseId());
        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");
        var latency = api.policyLatency();
        var serializedApi = objectMapper.readTree(objectMapper.writeValueAsString(api));
        var snapshot = proposal.inputSnapshot().path("policyLatency");

        assertThat(latency.status()).isEqualTo(PolicyLatencyCalculator.Status.AVAILABLE);
        assertThat(latency.observedEventCount()).isEqualTo(4);
        assertThat(latency.invalidEventCount()).isZero();
        assertThat(latency.averageMs()).isEqualByComparingTo("3.375");
        assertThat(latency.p50Ms()).isEqualByComparingTo("1.5");
        assertThat(latency.p95Ms()).isEqualByComparingTo("10");
        assertThat(latency.p99Ms()).isEqualByComparingTo("10");
        assertThat(latency.sourceRunIds()).containsExactly(runId);
        assertThat(latency.sourceEventIds()).containsExactlyElementsOf(eventIds);
        assertThat(jdbcTemplate.queryForObject("""
                select count(*) from execution_events
                 where run_id = ? and event_type = 'POLICY_EVALUATED' and test_case_run_id is null
                """, Long.class, runId)).isEqualTo(4L);
        assertThat(serializedApi.at("/policyLatency/averageMs").decimalValue())
                .isEqualByComparingTo("3.375");
        assertThat(snapshot.at("/averageMs").decimalValue()).isEqualByComparingTo("3.375");
        assertThat(snapshot.at("/observedEventCount").asLong()).isEqualTo(4);
        assertThat(snapshot.at("/sourceEventIds").valueStream().map(value -> value.asString()).toList())
                .containsExactlyElementsOf(eventIds.stream().map(UUID::toString).toList());
    }

    @Test
    void policyLatencyExcludesActiveRunAndDecisionUsesOnlySelectedSuite() throws Exception {
        Seed seed = seedCriticalReleaseWithPolicy(policyDuration(1));
        UUID baselineRunId = jdbcTemplate.queryForObject(
                "select id from test_runs where release_id = ?", UUID.class, seed.releaseId());
        SensitiveRun later = seedSensitiveRun(seed.releaseId());
        appendPolicyEvent(later, policyDuration(9));

        assertThat(assuranceService.metrics(seed.releaseId()).policyLatency().sourceRunIds())
                .containsExactly(baselineRunId);
        finishSensitiveRun(later, false);

        var api = assuranceService.metrics(seed.releaseId()).policyLatency();
        var snapshot = assuranceService.evaluate(seed.releaseId(), "role-d")
                .inputSnapshot().path("policyLatency");
        assertThat(api.averageMs()).isEqualByComparingTo("5");
        assertThat(api.sourceRunIds()).containsExactlyInAnyOrder(baselineRunId, later.runId());
        assertThat(snapshot.at("/averageMs").decimalValue()).isEqualByComparingTo("9");
        assertThat(snapshot.at("/observedEventCount").asLong()).isEqualTo(1);
        assertThat(snapshot.at("/sourceRunIds").valueStream().map(value -> value.asString()).toList())
                .containsExactly(later.runId().toString());
    }

    @Test
    void policyLatencyMissingDurationIsUnavailableInSerializedApiAndDecision() throws Exception {
        Seed seed = seedCriticalReleaseWithPolicy(policyDuration(4), objectMapper.createObjectNode());

        var api = assuranceService.metrics(seed.releaseId());
        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");
        var serializedApi = objectMapper.readTree(objectMapper.writeValueAsString(api));
        var snapshot = proposal.inputSnapshot().path("policyLatency");

        assertThat(api.policyLatency().status()).isEqualTo(PolicyLatencyCalculator.Status.N_A);
        assertThat(api.policyLatency().reason()).isEqualTo("MISSING_OR_INVALID_DURATION");
        assertThat(api.policyLatency().observedEventCount()).isEqualTo(2);
        assertThat(api.policyLatency().invalidEventCount()).isEqualTo(1);
        assertThat(api.policyLatency().averageMs()).isNull();
        assertThat(serializedApi.at("/policyLatency/status").asString()).isEqualTo("N_A");
        assertThat(serializedApi.at("/policyLatency/averageMs").isNull()).isTrue();
        assertThat(snapshot.at("/status").asString()).isEqualTo("N_A");
        assertThat(snapshot.at("/reason").asString()).isEqualTo("MISSING_OR_INVALID_DURATION");
        assertThat(snapshot.at("/averageMs").isNull()).isTrue();
    }

    @Test
    void policyLatencyWithoutPolicyEventsIsUnavailableInApiAndDecision() throws Exception {
        Seed seed = seedCriticalRelease();

        var api = assuranceService.metrics(seed.releaseId()).policyLatency();
        var snapshot = assuranceService.evaluate(seed.releaseId(), "role-d")
                .inputSnapshot().path("policyLatency");

        assertThat(api.status()).isEqualTo(PolicyLatencyCalculator.Status.N_A);
        assertThat(api.reason()).isEqualTo("NO_POLICY_EVALUATIONS");
        assertThat(api.observedEventCount()).isZero();
        assertThat(snapshot.at("/status").asString()).isEqualTo("N_A");
        assertThat(snapshot.at("/reason").asString()).isEqualTo("NO_POLICY_EVALUATIONS");
    }

    @Test
    void completionRateCountsScheduledSlotsAcrossActiveQueuedAndCancelledRuns() throws Exception {
        Seed seed = seedCriticalRelease();
        UUID baselineRunId = jdbcTemplate.queryForObject(
                "select id from test_runs where release_id = ?", UUID.class, seed.releaseId());
        PlannedRun active = seedPlannedRun(baselineRunId, "HELD_OUT", 3,
                List.of("ERROR", "CANCELLED"), "RUNNING");
        PlannedRun queued = seedPlannedRun(baselineRunId, "REGRESSION", 2,
                List.of(), "QUEUED");
        PlannedRun cancelled = seedPlannedRun(baselineRunId, "SEAL_REPLAY", 2,
                List.of("CANCELLED"), "CANCELLED");
        List<UUID> expectedRunIds = List.of(baselineRunId, active.runId(), queued.runId(),
                cancelled.runId()).stream().sorted().toList();

        var api = assuranceService.metrics(seed.releaseId());
        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");
        var metric = api.completionRate();
        var apiJson = objectMapper.readTree(objectMapper.writeValueAsString(api));
        var snapshot = proposal.inputSnapshot().path("completionRate");

        assertThat(metric.status()).isEqualTo(CompletionRateCalculator.Status.AVAILABLE);
        assertThat(metric.numerator()).isEqualTo(2L); // baseline terminal + active ERROR
        assertThat(metric.denominator()).isEqualTo(8L); // each Run's immutable plan once
        assertThat(metric.value()).isEqualTo(0.25);
        assertThat(metric.cancelledTrials()).isEqualTo(2L);
        assertThat(metric.unmaterializedTrials()).isEqualTo(4L);
        assertThat(metric.sourceRunIds()).containsExactlyElementsOf(expectedRunIds);
        assertThat(api.metrics().attackSuccessRate().sourceRunIds()).containsExactly(baselineRunId);
        assertThat(jdbcTemplate.queryForObject("""
                select status from test_case_runs where test_run_id = ? and trial_index = 0
                """, String.class, active.runId())).isEqualTo("ERROR");
        assertThat(jdbcTemplate.queryForObject("select status from test_runs where id = ?",
                String.class, cancelled.runId())).isEqualTo("CANCELLED");
        assertThat(apiJson.at("/completionRate/numerator").asLong()).isEqualTo(2L);
        assertThat(apiJson.at("/completionRate/denominator").asLong()).isEqualTo(8L);
        assertThat(snapshot.at("/numerator").asLong()).isEqualTo(2L);
        assertThat(snapshot.at("/denominator").asLong()).isEqualTo(8L);
        assertThat(snapshot.at("/sourceRunIds").valueStream().map(value -> value.asString()).toList())
                .containsExactlyElementsOf(expectedRunIds.stream().map(UUID::toString).toList());
    }

    @Test
    void completionRateDecisionCohortExcludesOtherSuiteAndChangesDigestWithEvidence() throws Exception {
        Seed seed = seedCriticalRelease();
        UUID baselineRunId = jdbcTemplate.queryForObject(
                "select id from test_runs where release_id = ?", UUID.class, seed.releaseId());
        PlannedRun queued = seedPlannedRun(baselineRunId, "REGRESSION", 2,
                List.of(), "QUEUED");
        SensitiveRun otherSuite = seedSensitiveRun(seed.releaseId());

        var apiBefore = assuranceService.metrics(seed.releaseId()).completionRate();
        var before = assuranceService.evaluate(seed.releaseId(), "role-d");
        var snapshotBefore = before.inputSnapshot().path("completionRate");
        assertThat(apiBefore.numerator()).isEqualTo(1L);
        assertThat(apiBefore.denominator()).isEqualTo(4L);
        assertThat(apiBefore.sourceRunIds()).contains(otherSuite.runId());
        assertThat(snapshotBefore.at("/numerator").asLong()).isEqualTo(1L);
        assertThat(snapshotBefore.at("/denominator").asLong()).isEqualTo(3L);
        assertThat(snapshotBefore.at("/sourceRunIds").valueStream().map(value -> value.asString()).toList())
                .containsExactlyElementsOf(List.of(baselineRunId, queued.runId()).stream()
                        .sorted().map(UUID::toString).toList());

        addPlannedCase(queued, 0, "PASSED");
        var apiAfter = assuranceService.metrics(seed.releaseId()).completionRate();
        var after = assuranceService.evaluate(seed.releaseId(), "role-d");
        var snapshotAfter = after.inputSnapshot().path("completionRate");
        assertThat(apiAfter.numerator()).isEqualTo(2L);
        assertThat(apiAfter.denominator()).isEqualTo(4L);
        assertThat(snapshotAfter.at("/numerator").asLong()).isEqualTo(2L);
        assertThat(snapshotAfter.at("/denominator").asLong()).isEqualTo(3L);
        assertThat(after.inputDigest()).isNotEqualTo(before.inputDigest());
    }

    @Test
    void completionRateWithoutScheduledRunsIsUnavailableInSerializedApi() throws Exception {
        UUID releaseId = seedReleaseWithoutRuns();

        var api = assuranceService.metrics(releaseId);
        var serialized = objectMapper.readTree(objectMapper.writeValueAsString(api));

        assertThat(api.completionRate().status()).isEqualTo(CompletionRateCalculator.Status.N_A);
        assertThat(api.completionRate().reason()).isEqualTo("NO_SCHEDULED_TRIALS");
        assertThat(api.completionRate().numerator()).isNull();
        assertThat(api.completionRate().denominator()).isNull();
        assertThat(serialized.at("/completionRate/status").asString()).isEqualTo("N_A");
        assertThat(serialized.at("/completionRate/numerator").isNull()).isTrue();
        assertThat(serialized.at("/completionRate/sourceRunIds").isEmpty()).isTrue();
    }

    @Test
    void attackRateBreakdownUsesStoredPartitionsAndSelectedDecisionCohort() throws Exception {
        Seed seed = seedCriticalRelease();
        UUID baselineRunId = jdbcTemplate.queryForObject(
                "select id from test_runs where release_id = ?", UUID.class, seed.releaseId());
        var before = assuranceService.evaluate(seed.releaseId(), "role-d");
        UUID selectedRunId = seedAttackBreakdownRun(baselineRunId);
        seedCriticalRelease(); // another Release cannot contribute to this rate

        var api = assuranceService.metrics(seed.releaseId());
        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");
        var repeated = assuranceService.evaluate(seed.releaseId(), "role-d");
        var apiJson = objectMapper.readTree(objectMapper.writeValueAsString(api));
        var apiBreakdown = api.attackRateBreakdown();
        var decisionBreakdown = proposal.inputSnapshot().path("attackRateBreakdown");
        var decisionGroups = decisionBreakdown.path("groups");
        var decisionAsr = proposal.inputSnapshot().path("metrics").valueStream()
                .filter(metric -> "ASR".equals(metric.path("metric").asString()))
                .findFirst().orElseThrow();
        var decisionHeldOut = proposal.inputSnapshot().path("metrics").valueStream()
                .filter(metric -> "HeldOutASR".equals(metric.path("metric").asString()))
                .findFirst().orElseThrow();
        var resultHeldOut = proposal.inputSnapshot().at("/results/heldOut");

        assertThat(apiBreakdown.status()).isEqualTo(AttackRateBreakdownCalculator.Status.AVAILABLE);
        assertThat(apiBreakdown.sourceRunIds()).containsExactlyElementsOf(
                List.of(baselineRunId, selectedRunId).stream().sorted().toList());
        assertThat(apiBreakdown.groups()).extracting(AttackRateBreakdownCalculator.Group::partition)
                .containsExactly("HELD_OUT", "MUTATION", "SEED");
        assertThat(apiBreakdown.groups()).extracting(AttackRateBreakdownCalculator.Group::category)
                .containsOnly("FA-02");
        assertThat(apiBreakdown.groups()).extracting(AttackRateBreakdownCalculator.Group::mode)
                .containsOnly("HELD_OUT");
        assertThat(apiBreakdown.groups().get(0).numerator()).isEqualTo(1L);
        assertThat(apiBreakdown.groups().get(0).denominator()).isEqualTo(1L);
        assertThat(apiBreakdown.groups().get(0).excludedTrials()).isEqualTo(1L);
        assertThat(apiBreakdown.groups().get(0).sourceRunIds()).containsExactly(baselineRunId);
        assertThat(apiBreakdown.groups().get(1).numerator()).isZero();
        assertThat(apiBreakdown.groups().get(1).denominator()).isEqualTo(1L);
        assertThat(apiBreakdown.groups().get(1).excludedTrials()).isEqualTo(1L);
        assertThat(apiBreakdown.groups().get(2).numerator()).isEqualTo(1L);
        assertThat(apiBreakdown.groups().get(2).denominator()).isEqualTo(1L);
        assertThat(apiBreakdown.groups().get(2).sourceRunIds()).containsExactly(selectedRunId);
        assertThat(apiBreakdown.groups().stream().mapToLong(
                AttackRateBreakdownCalculator.Group::numerator).sum())
                .isEqualTo(api.metrics().attackSuccessRate().numerator());
        assertThat(apiBreakdown.groups().stream().mapToLong(
                AttackRateBreakdownCalculator.Group::denominator).sum())
                .isEqualTo(api.metrics().attackSuccessRate().denominator());
        assertThat(api.metrics().operationalErrorRate().numerator()).isEqualTo(3L);
        assertThat(api.metrics().operationalErrorRate().denominator()).isEqualTo(5L);
        assertThat(api.metrics().heldOutAttackSuccessRate().numerator()).isEqualTo(1L);
        assertThat(api.metrics().heldOutAttackSuccessRate().denominator()).isEqualTo(1L);
        assertThat(api.metrics().heldOutAttackSuccessRate().sourceRunIds())
                .containsExactly(baselineRunId);
        assertThat(apiJson.at("/metrics/heldOutAttackSuccessRate/status").asString())
                .isEqualTo("AVAILABLE");
        assertThat(apiJson.at("/metrics/heldOutAttackSuccessRate/denominator").asLong())
                .isEqualTo(1L);

        assertThat(apiJson.at("/attackRateBreakdown/groups/1/partition").asString())
                .isEqualTo("MUTATION");
        assertThat(apiJson.at("/attackRateBreakdown/groups/1/numerator").asLong()).isZero();
        assertThat(decisionBreakdown.path("sourceRunIds").valueStream()
                .map(node -> node.asString()).toList()).containsExactly(selectedRunId.toString());
        assertThat(decisionGroups).hasSize(3);
        assertThat(decisionGroups.get(0).path("partition").asString()).isEqualTo("HELD_OUT");
        assertThat(decisionGroups.get(0).path("status").asString()).isEqualTo("N_A");
        assertThat(decisionGroups.get(0).path("numerator").isNull()).isTrue();
        assertThat(decisionGroups.get(0).path("denominator").isNull()).isTrue();
        assertThat(decisionGroups.get(0).path("excludedTrials").asLong()).isEqualTo(1L);
        assertThat(decisionGroups.get(0).path("sourceRunIds").isEmpty()).isTrue();
        assertThat(decisionGroups.get(1).path("partition").asString()).isEqualTo("MUTATION");
        assertThat(decisionGroups.get(1).path("numerator").asLong()).isZero();
        assertThat(decisionGroups.get(1).path("denominator").asLong()).isEqualTo(1L);
        assertThat(decisionGroups.get(2).path("partition").asString()).isEqualTo("SEED");
        assertThat(decisionGroups.get(2).path("numerator").asLong()).isEqualTo(1L);
        assertThat(decisionGroups.get(2).path("denominator").asLong()).isEqualTo(1L);
        assertThat(decisionGroups.valueStream().mapToLong(group ->
                group.path("numerator").asLong()).sum()).isEqualTo(decisionAsr.path("numerator").asLong());
        assertThat(decisionGroups.valueStream().mapToLong(group ->
                group.path("denominator").asLong()).sum()).isEqualTo(decisionAsr.path("denominator").asLong());
        assertThat(decisionAsr.path("numerator").asLong()).isEqualTo(1L);
        assertThat(decisionAsr.path("denominator").asLong()).isEqualTo(2L);
        assertThat(decisionHeldOut.path("status").asString()).isEqualTo("N_A");
        assertThat(decisionHeldOut.path("numerator").isMissingNode()).isTrue();
        assertThat(decisionHeldOut.path("denominator").isMissingNode()).isTrue();
        assertThat(decisionHeldOut.path("sourceTestRunIds").isEmpty()).isTrue();
        assertThat(resultHeldOut.path("status").asString()).isEqualTo("N_A");
        assertThat(resultHeldOut.path("numerator").isMissingNode()).isTrue();
        assertThat(resultHeldOut.path("denominator").isMissingNode()).isTrue();
        assertThat(resultHeldOut.path("sourceRunIds").isEmpty()).isTrue();
        assertThat(proposal.inputSnapshot().path("criticalSuccessEvidence").size()).isEqualTo(1);
        assertThat(proposal.inputDigest()).isNotEqualTo(before.inputDigest());
        assertThat(repeated.inputDigest()).isEqualTo(proposal.inputDigest());
        assertThat(proposal.proposedDecision()).isEqualTo(DecisionValue.BLOCKED);
    }

    @Test
    void heldOutPartitionBlockIsMeasuredZeroInSelectedDecision() throws Exception {
        Seed seed = seedCriticalRelease();
        UUID baselineRunId = jdbcTemplate.queryForObject(
                "select id from test_runs where release_id = ?", UUID.class, seed.releaseId());
        var before = assuranceService.evaluate(seed.releaseId(), "role-d");
        UUID selectedRunId = seedAttackBreakdownRun(baselineRunId, true);

        var api = assuranceService.metrics(seed.releaseId());
        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");
        var repeated = assuranceService.evaluate(seed.releaseId(), "role-d");
        var decisionHeldOut = proposal.inputSnapshot().path("metrics").valueStream()
                .filter(metric -> "HeldOutASR".equals(metric.path("metric").asString()))
                .findFirst().orElseThrow();
        var resultHeldOut = proposal.inputSnapshot().at("/results/heldOut");

        assertThat(api.metrics().heldOutAttackSuccessRate().numerator()).isEqualTo(1L);
        assertThat(api.metrics().heldOutAttackSuccessRate().denominator()).isEqualTo(2L);
        assertThat(api.metrics().heldOutAttackSuccessRate().sourceRunIds())
                .containsExactlyElementsOf(List.of(baselineRunId, selectedRunId).stream().sorted().toList());
        assertThat(decisionHeldOut.path("status").asString()).isEqualTo("AVAILABLE");
        assertThat(decisionHeldOut.path("numerator").asLong()).isZero();
        assertThat(decisionHeldOut.path("denominator").asLong()).isEqualTo(1L);
        assertThat(decisionHeldOut.at("/sourceTestRunIds/0").asString())
                .isEqualTo(selectedRunId.toString());
        assertThat(resultHeldOut.path("status").asString()).isEqualTo("AVAILABLE");
        assertThat(resultHeldOut.path("numerator").asLong()).isZero();
        assertThat(resultHeldOut.path("denominator").asLong()).isEqualTo(1L);
        assertThat(resultHeldOut.at("/sourceRunIds/0").asString())
                .isEqualTo(selectedRunId.toString());
        assertThat(proposal.inputSnapshot().path("criticalSuccessEvidence").size()).isEqualTo(1);
        assertThat(proposal.proposedDecision()).isEqualTo(DecisionValue.BLOCKED);
        assertThat(proposal.inputDigest()).isNotEqualTo(before.inputDigest());
        assertThat(repeated.inputDigest()).isEqualTo(proposal.inputDigest());
    }

    @Test
    void baselineModeWithHeldOutPartitionCannotEnterHeldOutRate() throws Exception {
        Seed seed = seedCriticalRelease("BASELINE", false, null, null, "{}", false,
                List.of(), "HELD_OUT");

        var api = assuranceService.metrics(seed.releaseId());
        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");
        var decisionHeldOut = proposal.inputSnapshot().path("metrics").valueStream()
                .filter(metric -> "HeldOutASR".equals(metric.path("metric").asString()))
                .findFirst().orElseThrow();

        assertThat(api.trialSuccessDistribution().cases()).singleElement().satisfies(caseDistribution -> {
            assertThat(caseDistribution.mode()).isEqualTo("BASELINE");
            assertThat(caseDistribution.partition()).isEqualTo("HELD_OUT");
        });
        assertThat(api.metrics().attackSuccessRate().numerator()).isEqualTo(1L);
        assertThat(api.metrics().heldOutAttackSuccessRate().status()).isEqualTo(MetricValue.Status.N_A);
        assertThat(api.metrics().heldOutAttackSuccessRate().sourceRunIds()).isEmpty();
        assertThat(decisionHeldOut.path("status").asString()).isEqualTo("N_A");
        assertThat(decisionHeldOut.path("sourceTestRunIds").isEmpty()).isTrue();
        assertThat(proposal.inputSnapshot().at("/results/heldOut/status").asString()).isEqualTo("N_A");
        assertThat(proposal.inputSnapshot().at("/results/heldOut/sourceRunIds").isEmpty()).isTrue();
        assertThat(proposal.inputSnapshot().at("/results/baseline/numerator").asLong()).isEqualTo(1L);
    }

    @Test
    void heldOutModeSeedSuccessTriggersP0ReviewAlthoughHeldOutPartitionRateIsUnavailable() throws Exception {
        Seed seed = seedCriticalRelease("HELD_OUT", false, "SENSITIVE_FIELD",
                "SENSITIVE_FIELD_EXPOSED", "{}", false, List.of(), "SEED");

        var api = assuranceService.metrics(seed.releaseId());
        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");
        var repeated = assuranceService.evaluate(seed.releaseId(), "role-d");
        var rules = proposal.inputSnapshot().at("/decision/ruleTrace");
        var p0Rule = rules.valueStream()
                .filter(rule -> "REVIEW_P0_ATTACK_SUCCESS".equals(rule.path("ruleId").asString()))
                .findFirst().orElseThrow();
        var heldOutRule = rules.valueStream()
                .filter(rule -> "REVIEW_HELD_OUT".equals(rule.path("ruleId").asString()))
                .findFirst().orElseThrow();

        assertThat(api.trialSuccessDistribution().cases()).singleElement().satisfies(caseDistribution -> {
            assertThat(caseDistribution.mode()).isEqualTo("HELD_OUT");
            assertThat(caseDistribution.partition()).isEqualTo("SEED");
            assertThat(caseDistribution.successBits()).containsExactly(1);
        });
        assertThat(api.metrics().attackSuccessRate().numerator()).isEqualTo(1L);
        assertThat(api.metrics().heldOutAttackSuccessRate().status()).isEqualTo(MetricValue.Status.N_A);
        assertThat(proposal.inputSnapshot().at("/results/heldOut/status").asString()).isEqualTo("N_A");
        assertThat(proposal.inputSnapshot().path("criticalSuccessEvidence").isEmpty()).isTrue();
        assertThat(heldOutRule.path("triggered").asBoolean()).isFalse();
        assertThat(p0Rule.path("triggered").asBoolean()).isTrue();
        assertThat(proposal.proposedDecision()).isEqualTo(DecisionValue.REVIEW);
        assertThat(repeated.inputDigest()).isEqualTo(proposal.inputDigest());
    }

    @Test
    void comparableNoncriticalReplaySuccessTriggersP0ReviewWithVerifiedSourceRun() throws Exception {
        Seed baseline = seedCriticalRelease("BASELINE", false, "SENSITIVE_FIELD",
                "SENSITIVE_FIELD_EXPOSED", "{}");
        UUID replayRunId = seedComparableMixedReplay(baseline.releaseId(), true);

        var api = assuranceService.metrics(baseline.releaseId());
        var proposal = assuranceService.evaluate(baseline.releaseId(), "role-d");
        var repeated = assuranceService.evaluate(baseline.releaseId(), "role-d");
        var p0Rule = proposal.inputSnapshot().at("/decision/ruleTrace").valueStream()
                .filter(rule -> "REVIEW_P0_ATTACK_SUCCESS".equals(rule.path("ruleId").asString()))
                .findFirst().orElseThrow();

        assertThat(api.replaySummary().comparableCount()).isEqualTo(1);
        assertThat(api.metrics().attackSuccessRate().sourceRunIds()).contains(replayRunId);
        assertThat(proposal.inputSnapshot().at("/results/sealReplay/numerator").asLong()).isEqualTo(1L);
        assertThat(proposal.inputSnapshot().at("/results/sealReplay/sourceRunIds/0").asString())
                .isEqualTo(replayRunId.toString());
        assertThat(proposal.inputSnapshot().path("criticalSuccessEvidence").isEmpty()).isTrue();
        assertThat(p0Rule.path("triggered").asBoolean()).isTrue();
        assertThat(proposal.proposedDecision()).isEqualTo(DecisionValue.REVIEW);
        assertThat(repeated.inputDigest()).isEqualTo(proposal.inputDigest());
    }

    @Test
    void incomparableNoncriticalReplaySuccessDoesNotGetP0GateCredit() throws Exception {
        Seed seed = seedCriticalRelease("SEAL_REPLAY", false, "SENSITIVE_FIELD",
                "SENSITIVE_FIELD_EXPOSED", "{}", true);

        var api = assuranceService.metrics(seed.releaseId());
        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");
        var p0Rule = proposal.inputSnapshot().at("/decision/ruleTrace").valueStream()
                .filter(rule -> "REVIEW_P0_ATTACK_SUCCESS".equals(rule.path("ruleId").asString()))
                .findFirst().orElseThrow();

        assertThat(api.replaySummary().nonComparableCount()).isEqualTo(1);
        assertThat(api.metrics().attackSuccessRate().status()).isEqualTo(MetricValue.Status.N_A);
        assertThat(proposal.inputSnapshot().at("/results/sealReplay/status").asString()).isEqualTo("N_A");
        assertThat(proposal.inputSnapshot().path("criticalSuccessEvidence").isEmpty()).isTrue();
        assertThat(p0Rule.path("triggered").asBoolean()).isFalse();
        assertThat(proposal.proposedDecision()).isEqualTo(DecisionValue.REVIEW);
    }

    @Test
    void attackRateBreakdownKeepsIncomparableReplayAsNullOnlyGroup() throws Exception {
        Seed seed = seedCriticalRelease("SEAL_REPLAY", false, null, null, "{}", true);

        var api = assuranceService.metrics(seed.releaseId());
        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");
        var apiJson = objectMapper.readTree(objectMapper.writeValueAsString(api));

        assertThat(api.attackRateBreakdown().status()).isEqualTo(AttackRateBreakdownCalculator.Status.N_A);
        assertThat(api.attackRateBreakdown().reason()).isEqualTo("NO_CONCLUSIVE_ATTACK_TRIALS");
        assertThat(api.attackRateBreakdown().groups()).singleElement().satisfies(group -> {
            assertThat(group.mode()).isEqualTo("SEAL_REPLAY");
            assertThat(group.numerator()).isNull();
            assertThat(group.denominator()).isNull();
            assertThat(group.excludedTrials()).isEqualTo(1L);
            assertThat(group.sourceRunIds()).isEmpty();
        });
        assertThat(apiJson.at("/attackRateBreakdown/groups/0/numerator").isNull()).isTrue();
        assertThat(proposal.inputSnapshot().at("/attackRateBreakdown/groups/0/status").asString())
                .isEqualTo("N_A");
        assertThat(api.metrics().attackSuccessRate().status()).isEqualTo(MetricValue.Status.N_A);
        assertThat(proposal.proposedDecision()).isEqualTo(DecisionValue.BLOCKED);
    }

    @Test
    void trialDistributionSerializesNullBitsAndKeepsDecisionInSelectedCohort() throws Exception {
        Seed seed = seedCriticalRelease();
        UUID baselineRunId = jdbcTemplate.queryForObject(
                "select id from test_runs where release_id = ?", UUID.class, seed.releaseId());
        SensitiveRun otherSuite = seedSensitiveRun(seed.releaseId());
        finishSensitiveRun(otherSuite, false);
        PlannedRun selected = seedDistributionRun(baselineRunId);

        var api = assuranceService.metrics(seed.releaseId());
        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");
        var report = api.trialSuccessDistribution();
        var apiJson = objectMapper.readTree(objectMapper.writeValueAsString(api));
        var snapshot = proposal.inputSnapshot().path("trialSuccessDistribution");
        var selectedCase = report.cases().stream()
                .filter(item -> item.runId().equals(selected.runId())).findFirst().orElseThrow();
        var selectedApiJson = apiJson.at("/trialSuccessDistribution/cases").valueStream()
                .filter(item -> selected.runId().toString().equals(item.path("runId").asString()))
                .findFirst().orElseThrow();
        var selectedSnapshot = snapshot.path("cases").valueStream()
                .filter(item -> selected.runId().toString().equals(item.path("runId").asString()))
                .findFirst().orElseThrow();

        assertThat(report.sourceRunIds()).containsExactlyElementsOf(
                List.of(baselineRunId, otherSuite.runId(), selected.runId()).stream().sorted().toList());
        assertThat(snapshot.path("sourceRunIds").valueStream().map(item -> item.asString()).toList())
                .containsExactlyElementsOf(List.of(baselineRunId, selected.runId()).stream()
                        .sorted().map(UUID::toString).toList());
        assertThat(selectedCase.successBits()).containsExactly(1, null, 0);
        assertThat(selectedCase.orderedTrials())
                .extracting(TrialSuccessDistributionCalculator.TrialBit::trialIndex)
                .containsExactly(0, 1, 2);
        assertThat(selectedCase.successCount()).isEqualTo(1L);
        assertThat(selectedCase.trials()).isEqualTo(2L);
        assertThat(selectedCase.orderedTrials().getFirst().secondaryInconclusive()).isTrue();
        assertThat(selectedCase.orderedTrials().get(1).exclusionReason())
                .isEqualTo("INCONCLUSIVE_ORACLE");
        assertThat(selectedApiJson.at("/successBits/0").asInt()).isEqualTo(1);
        assertThat(selectedApiJson.at("/successBits/1").isNull()).isTrue();
        assertThat(selectedApiJson.at("/successBits/2").asInt()).isZero();
        assertThat(selectedSnapshot.path("successBits")).isEqualTo(selectedApiJson.path("successBits"));
        var category = snapshot.path("categories").valueStream()
                .filter(item -> "HELD_OUT".equals(item.path("mode").asString())
                        && "FA-02".equals(item.path("category").asString()))
                .findFirst().orElseThrow();
        var expectedCategoryBits = report.cases().stream()
                .filter(item -> "HELD_OUT".equals(item.mode()) && "FA-02".equals(item.category()))
                .flatMap(item -> item.successBits().stream()).toList();
        assertThat(category.path("successBits").valueStream()
                .map(item -> item.isNull() ? null : item.asInt()).toList())
                .containsExactlyElementsOf(expectedCategoryBits);
        assertThat(category.path("successBits")).hasSize(4);
        assertThat(category.path("successCount").asLong()).isEqualTo(2L);
        assertThat(category.path("trials").asLong()).isEqualTo(3L);
        assertThat(api.metrics().attackSuccessRate().numerator()).isEqualTo(2L);
        assertThat(api.metrics().operationalErrorRate().numerator()).isEqualTo(2L);
        assertThat(proposal.proposedDecision()).isEqualTo(DecisionValue.BLOCKED);
    }

    @Test
    void trialDistributionDecisionDigestChangesWhenSelectedTerminalEvidenceArrives() throws Exception {
        Seed seed = seedCriticalRelease();
        UUID baselineRunId = jdbcTemplate.queryForObject(
                "select id from test_runs where release_id = ?", UUID.class, seed.releaseId());
        var before = assuranceService.evaluate(seed.releaseId(), "role-d");

        PlannedRun added = seedDistributionRun(baselineRunId);
        var after = assuranceService.evaluate(seed.releaseId(), "role-d");
        var repeated = assuranceService.evaluate(seed.releaseId(), "role-d");

        assertThat(after.inputDigest()).isNotEqualTo(before.inputDigest());
        assertThat(repeated.inputDigest()).isEqualTo(after.inputDigest());
        assertThat(before.inputSnapshot().at("/trialSuccessDistribution/sourceRunIds").valueStream()
                .map(item -> item.asString()).toList()).containsExactly(baselineRunId.toString());
        assertThat(after.inputSnapshot().at("/trialSuccessDistribution/sourceRunIds").valueStream()
                .map(item -> item.asString()).toList()).containsExactlyElementsOf(
                        List.of(baselineRunId, added.runId()).stream()
                                .sorted().map(UUID::toString).toList());
        assertThat(after.proposedDecision()).isEqualTo(before.proposedDecision());
        assertThat(after.proposedDecision()).isEqualTo(DecisionValue.BLOCKED);
    }

    @Test
    void trialDistributionSeparatesComparableReplayFromIncomparableSuccess() throws Exception {
        Seed baseline = seedCriticalRelease("BASELINE");
        UUID comparableRunId = seedComparableMixedReplay(baseline.releaseId());

        var comparableApi = assuranceService.metrics(baseline.releaseId());
        var comparableCase = comparableApi.trialSuccessDistribution().cases().stream()
                .filter(item -> item.runId().equals(comparableRunId)).findFirst().orElseThrow();
        var comparableDecision = assuranceService.evaluate(baseline.releaseId(), "role-d");
        var comparableSnapshotCase = comparableDecision.inputSnapshot()
                .at("/trialSuccessDistribution/cases").valueStream()
                .filter(item -> comparableRunId.toString().equals(item.path("runId").asString()))
                .findFirst().orElseThrow();
        assertThat(comparableCase.successBits()).containsExactly(1);
        assertThat(comparableCase.orderedTrials().getFirst().secondaryInconclusive()).isTrue();
        assertThat(comparableSnapshotCase.at("/successBits/0").asInt()).isEqualTo(1);
        assertThat(comparableApi.metrics().attackSuccessRate().numerator()).isEqualTo(2L);
        assertThat(comparableApi.attackRateBreakdown().groups().stream()
                .mapToLong(group -> group.numerator() == null ? 0 : group.numerator()).sum())
                .isEqualTo(comparableApi.metrics().attackSuccessRate().numerator());
        assertThat(comparableApi.attackRateBreakdown().groups().stream()
                .mapToLong(group -> group.denominator() == null ? 0 : group.denominator()).sum())
                .isEqualTo(comparableApi.metrics().attackSuccessRate().denominator());
        assertThat(comparableApi.attackRateBreakdown().groups().stream()
                .filter(group -> "SEAL_REPLAY".equals(group.mode())).toList())
                .singleElement().satisfies(group -> {
                    assertThat(group.numerator()).isEqualTo(1L);
                    assertThat(group.denominator()).isEqualTo(1L);
                    assertThat(group.sourceRunIds()).containsExactly(comparableRunId);
                });
        var replayDecisionGroup = comparableDecision.inputSnapshot()
                .at("/attackRateBreakdown/groups").valueStream()
                .filter(group -> "SEAL_REPLAY".equals(group.path("mode").asString()))
                .findFirst().orElseThrow();
        assertThat(replayDecisionGroup.path("numerator").asLong()).isEqualTo(1L);
        assertThat(replayDecisionGroup.path("denominator").asLong()).isEqualTo(1L);
        assertThat(replayDecisionGroup.path("sourceRunIds").valueStream()
                .map(node -> node.asString()).toList()).containsExactly(comparableRunId.toString());
        assertThat(comparableDecision.proposedDecision()).isEqualTo(DecisionValue.BLOCKED);

        Seed noLink = seedCriticalRelease("SEAL_REPLAY", false, null, null, "{}", true);
        var incomparableApi = assuranceService.metrics(noLink.releaseId());
        var incomparableCase = incomparableApi.trialSuccessDistribution().cases().getFirst();
        var incomparableDecision = assuranceService.evaluate(noLink.releaseId(), "role-d");
        assertThat(incomparableCase.successBits()).containsExactly((Integer) null);
        assertThat(incomparableCase.orderedTrials().getFirst().exclusionReason())
                .isEqualTo("REPLAY_NOT_COMPARABLE");
        assertThat(incomparableApi.metrics().attackSuccessRate().status())
                .isEqualTo(MetricValue.Status.N_A);
        assertThat(incomparableApi.metrics().operationalErrorRate().numerator()).isEqualTo(1L);
        assertThat(incomparableDecision.proposedDecision()).isEqualTo(DecisionValue.BLOCKED);
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
        assertThat(proposal.inputSnapshot().at("/decision/ruleTrace").valueStream()
                .filter(rule -> "REVIEW_P0_ATTACK_SUCCESS".equals(rule.path("ruleId").asString())).toList())
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
        assertThat(proposal.inputSnapshot().at("/decision/ruleTrace").valueStream()
                .map(rule -> rule.path("ruleId").asString()).toList())
                .doesNotContain("REVIEW_P0_ATTACK_SUCCESS");
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
    void heldOutMixedOracleSuccessAppearsOnceInApiAndDecisionRatesWithoutCompletingEffects() throws Exception {
        Seed seed = seedCriticalRelease("HELD_OUT", false, null, null, "{}", true);
        UUID runId = jdbcTemplate.queryForObject(
                "select id from test_runs where release_id = ?", UUID.class, seed.releaseId());

        var api = assuranceService.metrics(seed.releaseId());
        var metrics = api.metrics();
        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");

        assertThat(jdbcTemplate.queryForObject("""
                select count(*) from oracle_results oracle
                  join test_case_runs case_run on case_run.id = oracle.test_case_run_id
                 where case_run.test_run_id = ?
                """, Long.class, runId)).isEqualTo(2L);
        assertThat(metrics.attackSuccessRate().numerator()).isEqualTo(1L);
        assertThat(metrics.attackSuccessRate().denominator()).isEqualTo(1L);
        assertThat(metrics.heldOutAttackSuccessRate().numerator()).isEqualTo(1L);
        assertThat(metrics.heldOutAttackSuccessRate().denominator()).isEqualTo(1L);
        assertThat(metrics.attackSuccessRate().sourceRunIds()).containsExactly(runId);
        assertThat(metrics.operationalErrorRate().numerator()).isEqualTo(1L);
        assertThat(metrics.operationalErrorRate().denominator()).isEqualTo(1L);
        assertThat(proposal.inputSnapshot().at("/results/heldOut/numerator").asLong()).isEqualTo(1L);
        assertThat(proposal.inputSnapshot().at("/results/heldOut/denominator").asLong()).isEqualTo(1L);
        assertThat(proposal.inputSnapshot().at("/results/heldOut/sourceRunIds/0").asString())
                .isEqualTo(runId.toString());
        var decisionHeldOut = proposal.inputSnapshot().path("metrics").valueStream()
                .filter(metric -> "HeldOutASR".equals(metric.path("metric").asString()))
                .findFirst().orElseThrow();
        assertThat(decisionHeldOut.path("numerator").asLong()).isEqualTo(1L);
        assertThat(decisionHeldOut.path("denominator").asLong()).isEqualTo(1L);
        assertThat(decisionHeldOut.at("/sourceTestRunIds/0").asString()).isEqualTo(runId.toString());
        assertThat(proposal.inputSnapshot().at("/metrics/0/sourceTestRunIds/0").asString())
                .isEqualTo(runId.toString());
        assertThat(proposal.inputSnapshot().at("/criticalTrialCoverage/cases/0/conclusiveTrials").asLong())
                .isZero();
        assertThat(proposal.inputSnapshot().path("criticalSuccessEvidence").size()).isEqualTo(1);
        assertThat(proposal.proposedDecision()).isEqualTo(DecisionValue.BLOCKED);
        assertThat(metrics.unauthorizedRecordExposureCount()).isNull();
        assertThat(metrics.sensitiveFieldExposureCount()).isNull();
        assertThat(proposal.inputSnapshot().at("/decision/ruleTrace").valueStream()
                .filter(rule -> "REVIEW_EVIDENCE".equals(rule.path("ruleId").asString())).toList())
                .isEmpty(); // BLOCKED precedence stops before REVIEW rules.
    }

    @Test
    void baselineMixedOracleSuccessCountsInBaselineFractionWithoutCriticalEnforceBlock() throws Exception {
        Seed seed = seedCriticalRelease("BASELINE", false, null, null, "{}", true);
        UUID runId = jdbcTemplate.queryForObject(
                "select id from test_runs where release_id = ?", UUID.class, seed.releaseId());

        var metrics = assuranceService.metrics(seed.releaseId()).metrics();
        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");

        assertThat(metrics.attackSuccessRate().numerator()).isEqualTo(1L);
        assertThat(metrics.attackSuccessRate().denominator()).isEqualTo(1L);
        assertThat(metrics.operationalErrorRate().numerator()).isEqualTo(1L);
        assertThat(proposal.inputSnapshot().at("/results/baseline/numerator").asLong()).isEqualTo(1L);
        assertThat(proposal.inputSnapshot().at("/results/baseline/denominator").asLong()).isEqualTo(1L);
        assertThat(proposal.inputSnapshot().at("/results/baseline/sourceRunIds/0").asString())
                .isEqualTo(runId.toString());
        assertThat(proposal.inputSnapshot().path("criticalSuccessEvidence")).isEmpty();
        assertThat(proposal.proposedDecision()).isEqualTo(DecisionValue.REVIEW);
    }

    @Test
    void incomparableMixedReplayRetainsErrorAndCriticalEvidenceButHasNoRate() throws Exception {
        Seed seed = seedCriticalRelease("SEAL_REPLAY", false, null, null, "{}", true);

        var api = assuranceService.metrics(seed.releaseId());
        var proposal = assuranceService.evaluate(seed.releaseId(), "role-d");

        assertThat(api.replaySummary().nonComparableCount()).isEqualTo(1);
        assertThat(api.metrics().attackSuccessRate().status()).isEqualTo(MetricValue.Status.N_A);
        assertThat(api.metrics().operationalErrorRate().numerator()).isEqualTo(1L);
        assertThat(proposal.inputSnapshot().at("/results/sealReplay/status").asString())
                .isEqualTo("N_A");
        assertThat(proposal.inputSnapshot().at("/criticalTrialCoverage/cases/0/conclusiveTrials").asLong())
                .isZero();
        assertThat(proposal.inputSnapshot().path("criticalSuccessEvidence").size()).isEqualTo(1);
        assertThat(proposal.proposedDecision()).isEqualTo(DecisionValue.BLOCKED);
    }

    @Test
    void comparableMixedReplayUsesVerifiedLinkForRateAndDecisionFraction() throws Exception {
        Seed baseline = seedCriticalRelease("BASELINE");
        UUID replayRunId = seedComparableMixedReplay(baseline.releaseId());

        var api = assuranceService.metrics(baseline.releaseId());
        var proposal = assuranceService.evaluate(baseline.releaseId(), "role-d");

        assertThat(api.replaySummary().comparableCount()).isEqualTo(1);
        assertThat(api.metrics().attackSuccessRate().numerator()).isEqualTo(2L);
        assertThat(api.metrics().attackSuccessRate().denominator()).isEqualTo(2L);
        assertThat(api.metrics().attackSuccessRate().sourceRunIds()).contains(replayRunId);
        assertThat(proposal.inputSnapshot().at("/results/sealReplay/numerator").asLong()).isEqualTo(1L);
        assertThat(proposal.inputSnapshot().at("/results/sealReplay/denominator").asLong()).isEqualTo(1L);
        assertThat(proposal.inputSnapshot().at("/results/sealReplay/sourceRunIds/0").asString())
                .isEqualTo(replayRunId.toString());
        assertThat(proposal.inputSnapshot().at("/metrics/0/sourceTestRunIds").valueStream()
                .map(id -> id.asString()).toList()).contains(replayRunId.toString());
        assertThat(proposal.inputSnapshot().at("/criticalTrialCoverage/cases/0/conclusiveTrials").asLong())
                .isZero();
        assertThat(proposal.inputSnapshot().path("criticalSuccessEvidence").size()).isEqualTo(1);
        assertThat(proposal.proposedDecision()).isEqualTo(DecisionValue.BLOCKED);
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
        assertThat(metrics.sensitiveFieldExposureCount()).isZero();
    }

    @Test
    void countsDistinctDisallowedNonNullFieldsAcrossAllDeliveredStepsAndTrials() throws Exception {
        Seed seed = seedCriticalRelease();
        SensitiveRun first = seedSensitiveRun(seed.releaseId());
        appendCustomerDelivery(first, customerOutput("CUST-1002"), true);
        appendCustomerDelivery(first, customerOutput("CUST-1002", "CUST-1003"), true);
        finishSensitiveRun(first, false);
        SensitiveRun second = seedSensitiveRun(seed.releaseId());
        appendCustomerDelivery(second, customerOutput("CUST-1002"), true);
        finishSensitiveRun(second, false);

        assertThat(assuranceService.metrics(seed.releaseId()).metrics().sensitiveFieldExposureCount())
                .isEqualTo(3L);
        assertThat(jdbcTemplate.queryForList("""
                select metadata_json -> 'customerFieldDeliveryEvidence' -> 'tuples' -> 0 ->> 'customerIdHash'
                  from execution_events
                 where run_id = ? and reason_code = 'AGENT_TOOL_RESULT_DELIVERED'
                """, String.class, first.runId())).allMatch(hash -> hash.startsWith("hmac-sha256:v1:"));
    }

    @Test
    void completeDeliveryInFailedTrialStillCountsButUnmatchedSecondSourceMakesNA() throws Exception {
        Seed seed = seedCriticalRelease();
        SensitiveRun failed = seedSensitiveRun(seed.releaseId());
        appendCustomerDelivery(failed, customerOutput("CUST-1002"), true);
        finishSensitiveRun(failed, true);
        assertThat(assuranceService.metrics(seed.releaseId()).metrics().sensitiveFieldExposureCount())
                .isEqualTo(1L);

        SensitiveRun incomplete = seedSensitiveRun(seed.releaseId());
        appendCustomerDelivery(incomplete, customerOutput("CUST-1002"), true);
        appendCustomerSource(incomplete, customerOutput("CUST-1003"));
        finishSensitiveRun(incomplete, true);
        assertThat(assuranceService.metrics(seed.releaseId()).metrics().sensitiveFieldExposureCount())
                .isNull();
    }

    @Test
    void verifiedEmptyAndQuarantinedDeliveriesAreMeasuredZero() throws Exception {
        Seed seed = seedCriticalRelease();
        SensitiveRun empty = seedSensitiveRun(seed.releaseId());
        appendCustomerDelivery(empty, customerOutput(), true);
        finishSensitiveRun(empty, false);
        SensitiveRun quarantined = seedSensitiveRun(seed.releaseId());
        appendCustomerDelivery(quarantined, customerOutput("CUST-1002"), false);
        finishSensitiveRun(quarantined, false);

        assertThat(assuranceService.metrics(seed.releaseId()).metrics().sensitiveFieldExposureCount())
                .isZero();
    }

    @ParameterizedTest
    @ValueSource(strings = {"[\"incomeBand\",\"incomeBand\"]", "[\"incomeBand\",7]"})
    void mutableOrMalformedFixturePolicyMakesStoredExposureUnavailable(String allowedFields) throws Exception {
        Seed seed = seedCriticalRelease();
        SensitiveRun run = seedSensitiveRun(seed.releaseId());
        appendCustomerDelivery(run, customerOutput("CUST-1002"), true);
        finishSensitiveRun(run, false);
        assertThat(assuranceService.metrics(seed.releaseId()).metrics().sensitiveFieldExposureCount())
                .isEqualTo(1L);

        jdbcTemplate.update("""
                update sandbox_loan_cases
                   set context_json = jsonb_set(context_json, '{allowedFields}', ?::jsonb)
                 where namespace_id = ? and case_key = 'CASE-1001'
                """, allowedFields, run.runId());
        assertThat(assuranceService.metrics(seed.releaseId()).metrics().sensitiveFieldExposureCount())
                .isNull();
    }

    @Test
    void inactiveNamespaceMakesStoredExposureUnavailable() throws Exception {
        Seed seed = seedCriticalRelease();
        SensitiveRun run = seedSensitiveRun(seed.releaseId());
        appendCustomerDelivery(run, customerOutput("CUST-1002"), true);
        finishSensitiveRun(run, false);
        assertThat(assuranceService.metrics(seed.releaseId()).metrics().sensitiveFieldExposureCount())
                .isEqualTo(1L);

        assertThat(jdbcTemplate.update("""
                update sandbox_namespaces set state = 'SEALED', sealed_at = now() where id = ?
                """, run.runId())).isEqualTo(1);
        assertThat(assuranceService.metrics(seed.releaseId()).metrics().sensitiveFieldExposureCount())
                .isNull();
    }

    @Test
    void removedNamespaceMakesStoredExposureUnavailable() throws Exception {
        Seed seed = seedCriticalRelease();
        SensitiveRun run = seedSensitiveRun(seed.releaseId());
        appendCustomerDelivery(run, customerOutput("CUST-1002"), true);
        finishSensitiveRun(run, false);
        assertThat(assuranceService.metrics(seed.releaseId()).metrics().sensitiveFieldExposureCount())
                .isEqualTo(1L);

        // V3's case/customer RESTRICT links require leaf rows to be removed before the namespace.
        assertThat(jdbcTemplate.update("delete from sandbox_loan_decisions where namespace_id = ?",
                run.runId())).isEqualTo(1);
        assertThat(jdbcTemplate.update("delete from sandbox_loan_cases where namespace_id = ?",
                run.runId())).isEqualTo(1);
        assertThat(jdbcTemplate.update("delete from sandbox_customers where namespace_id = ?",
                run.runId())).isEqualTo(3);
        assertThat(jdbcTemplate.update("delete from sandbox_namespaces where id = ?",
                run.runId())).isEqualTo(1);
        assertThat(jdbcTemplate.queryForObject("select count(*) from sandbox_namespaces where id = ?",
                Integer.class, run.runId())).isZero();
        assertThat(assuranceService.metrics(seed.releaseId()).metrics().sensitiveFieldExposureCount())
                .isNull();
    }

    @Test
    void sensitiveCountReadsCommittedFixtureThroughRequiresNewSpringProxy() throws Exception {
        Seed seed = seedCriticalRelease();
        SensitiveRun run = seedSensitiveRun(seed.releaseId());
        appendCustomerDelivery(run, customerOutput("CUST-1002"), true);
        finishSensitiveRun(run, false);
        assertThat(AopUtils.isAopProxy(sensitiveCounter)).isTrue();
        assertThat(assuranceService.metrics(seed.releaseId()).metrics().sensitiveFieldExposureCount())
                .isEqualTo(1L);

        new TransactionTemplate(transactionManager).executeWithoutResult(outer -> {
            assertThat(jdbcTemplate.update("""
                    update sandbox_loan_cases
                       set context_json = jsonb_set(context_json, '{allowedFields}',
                               '["incomeBand","incomeBand"]'::jsonb)
                     where namespace_id = ? and case_key = 'CASE-1001'
                    """, run.runId())).isEqualTo(1);
            assertThat(jdbcTemplate.queryForObject("""
                    select context_json -> 'allowedFields' ->> 1 from sandbox_loan_cases
                     where namespace_id = ? and case_key = 'CASE-1001'
                    """, String.class, run.runId())).isEqualTo("incomeBand");
            assertThat(assuranceService.metrics(seed.releaseId()).metrics().sensitiveFieldExposureCount())
                    .isEqualTo(1L);
            outer.setRollbackOnly();
        });
        assertThat(assuranceService.metrics(seed.releaseId()).metrics().sensitiveFieldExposureCount())
                .isEqualTo(1L);
    }

    @Test
    void wrongResponseSourceDigestFailsClosedWithoutLosingOtherEffects() throws Exception {
        Seed seed = seedCriticalRelease();
        SensitiveRun run = seedSensitiveRun(seed.releaseId());
        appendCustomerDelivery(run, customerOutput("CUST-1002"), true, true);
        finishSensitiveRun(run, false);

        var metrics = assuranceService.metrics(seed.releaseId()).metrics();
        assertThat(metrics.sensitiveFieldExposureCount()).isNull();
        assertThat(metrics.unauthorizedRecordExposureCount()).isNull();
        assertThat(metrics.highImpactMutationCount()).isZero();
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

    private UUID seedComparableMixedReplay(UUID releaseId) {
        return seedComparableMixedReplay(releaseId, false);
    }

    private UUID seedComparableMixedReplay(UUID releaseId, boolean noncriticalSuccess) {
        UUID baselineRunId = jdbcTemplate.queryForObject(
                "select id from test_runs where release_id = ? and mode = 'BASELINE'",
                UUID.class, releaseId);
        UUID baselineCaseRunId = jdbcTemplate.queryForObject(
                "select id from test_case_runs where test_run_id = ?", UUID.class, baselineRunId);
        UUID findingId = jdbcTemplate.queryForObject(
                "select id from findings where first_seen_run_id = ?", UUID.class, baselineRunId);
        String agentFingerprint = jdbcTemplate.queryForObject(
                "select agent_artifact_fingerprint from test_runs where id = ?", String.class, baselineRunId);
        String baselineFingerprint = jdbcTemplate.queryForObject(
                "select release_fingerprint from test_runs where id = ?", String.class, baselineRunId);
        UUID contractVersionId = seedApprovedContract(releaseId);
        String replayFingerprint = fingerprintService.releaseFingerprint(agentFingerprint, HASH_A);
        assertThat(replayFingerprint).isNotEqualTo(baselineFingerprint);
        jdbcTemplate.update("""
                update agent_releases
                   set lifecycle_state = 'REMEDIATION', effective_status = 'REMEDIATION'
                 where id = ?
                """, releaseId);
        jdbcTemplate.update("""
                update agent_releases
                   set lifecycle_state = 'VERIFYING', effective_status = 'VERIFYING',
                       safety_contract_hash = ?, release_fingerprint = ?
                 where id = ?
                """, HASH_A, replayFingerprint, releaseId);

        UUID replayRunId = UUID.randomUUID();
        UUID replayCaseRunId = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        jdbcTemplate.update("""
                insert into test_runs
                    (id, release_id, suite_id, contract_version_id, mode, status,
                     agent_artifact_fingerprint, release_fingerprint, config_json,
                     fixture_version, fixture_digest, model_config_hash,
                     baseline_pair_group_id, random_seed, total_cases, completed_cases,
                     operational_error_count, started_at, completed_at, summary_json, created_at, updated_at)
                select ?, release_id, suite_id, ?, 'SEAL_REPLAY', 'QUEUED',
                       agent_artifact_fingerprint, ?, config_json, fixture_version, fixture_digest,
                       model_config_hash, baseline_pair_group_id, random_seed,
                       1, 0, 0, null, null, '{}'::jsonb, ?, ?
                  from test_runs where id = ?
                """, replayRunId, contractVersionId, replayFingerprint,
                Timestamp.from(now), Timestamp.from(now), baselineRunId);
        jdbcTemplate.update("""
                insert into test_case_runs
                    (id, test_run_id, test_case_id, trial_index, status, security_outcome,
                     variant_hash, started_at, completed_at, result_json, created_at, updated_at)
                select ?, ?, test_case_id, trial_index, 'PENDING', null,
                       variant_hash, null, null, '{}'::jsonb, ?, ?
                  from test_case_runs where id = ?
                """, replayCaseRunId, replayRunId, Timestamp.from(now), Timestamp.from(now), baselineCaseRunId);
        jdbcTemplate.update("""
                update test_case_runs
                   set status = 'FAILED_SECURITY', security_outcome = 'ATTACK_SUCCESS',
                       started_at = ?, completed_at = ?, updated_at = ?
                 where id = ?
                """, Timestamp.from(now.minusSeconds(1)), Timestamp.from(now),
                Timestamp.from(now), replayCaseRunId);
        String successOracle = noncriticalSuccess ? "SENSITIVE_FIELD" : "CROSS_CUSTOMER";
        String successReason = noncriticalSuccess ? "SENSITIVE_FIELD_EXPOSED" : "UNAUTHORIZED_RECORD_RETURNED";
        String successInvariant = noncriticalSuccess ? "INV-02" : "INV-01";
        String incompleteOracle = noncriticalSuccess ? "CROSS_CUSTOMER" : "SENSITIVE_FIELD";
        String incompleteInvariant = noncriticalSuccess ? "INV-01" : "INV-02";
        jdbcTemplate.update("""
                insert into oracle_results
                    (id, test_case_run_id, oracle_type, oracle_version, outcome, reason_code,
                     invariant_id, evidence_json, evidence_digest, evaluated_at, created_at, updated_at)
                values (?, ?, ?, '1.0', 'ATTACK_SUCCESS', ?, ?, '{}'::jsonb, ?, ?, ?, ?)
                """, UUID.randomUUID(), replayCaseRunId, successOracle, successReason, successInvariant, HASH_A,
                Timestamp.from(now), Timestamp.from(now), Timestamp.from(now));
        jdbcTemplate.update("""
                insert into oracle_results
                    (id, test_case_run_id, oracle_type, oracle_version, outcome, reason_code,
                     invariant_id, evidence_json, evidence_digest, evaluated_at, created_at, updated_at)
                values (?, ?, ?, '1.0', 'INCONCLUSIVE',
                        'EVIDENCE_INCOMPLETE', ?, '{"evidenceComplete":false}'::jsonb, ?, ?, ?, ?)
                """, UUID.randomUUID(), replayCaseRunId, incompleteOracle, incompleteInvariant, HASH_A,
                Timestamp.from(now), Timestamp.from(now), Timestamp.from(now));
        jdbcTemplate.update("update test_runs set status = 'PREPARING', updated_at = ? where id = ?",
                Timestamp.from(now.minusSeconds(2)), replayRunId);
        jdbcTemplate.update("update test_runs set status = 'RUNNING', started_at = ?, updated_at = ? where id = ?",
                Timestamp.from(now.minusSeconds(1)), Timestamp.from(now.minusSeconds(1)), replayRunId);
        jdbcTemplate.update("insert into run_event_counters (run_id, last_sequence) values (?, 0)", replayRunId);
        UUID traceId = UUID.randomUUID();
        eventService.append(replayRunId, new ExecutionEventDto.AppendRequest(
                null, traceId, ExecutionEventType.RUN_STARTED,
                null, null, null, null, "RUN_STARTED", objectMapper.createObjectNode()
        ), "test");
        eventService.append(replayRunId, new ExecutionEventDto.AppendRequest(
                null, traceId, ExecutionEventType.RUN_COMPLETED,
                null, null, null, null, "RUN_COMPLETED", objectMapper.createObjectNode()
        ), "test");
        jdbcTemplate.update("""
                update test_runs
                   set status = 'COMPLETED', completed_cases = 1,
                       completed_at = ?, updated_at = ? where id = ?
                """, Timestamp.from(now), Timestamp.from(now), replayRunId);
        jdbcTemplate.update("""
                insert into replay_links
                    (id, finding_id, baseline_case_run_id, replay_case_run_id,
                     same_agent_artifact_fingerprint, same_fixture_digest, same_model_config,
                     same_variant_hash, expected_policy_difference, comparison_json)
                values (?, ?, ?, ?, true, true, true, true, true,
                        '{"comparable":true}'::jsonb)
                """, UUID.randomUUID(), findingId, baselineCaseRunId, replayCaseRunId);
        return replayRunId;
    }

    private Seed seedCriticalRelease() throws Exception {
        return seedCriticalRelease("HELD_OUT");
    }

    private UUID seedReleaseWithoutRuns() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        AgentDto.Response agent = agentService.create(new AgentDto.CreateRequest(
                "empty-" + suffix, "Empty Agent", "Release without scheduled runs"
        ));
        ObjectNode manifest = (ObjectNode) objectMapper.readTree(
                getClass().getResourceAsStream("/fixtures/valid-release-manifest.json")
        );
        ((ObjectNode) manifest.path("agent")).put("id", "empty-" + suffix);
        ReleaseDto.Response release = releaseService.create(agent.id(), manifest, "test");
        releaseService.analyze(release.id(), "test");
        return release.id();
    }

    private UUID seedAttackBreakdownRun(UUID baselineRunId) {
        return seedAttackBreakdownRun(baselineRunId, false);
    }

    private UUID seedAttackBreakdownRun(UUID baselineRunId, boolean heldOutBlocked) {
        UUID baselineSuiteId = jdbcTemplate.queryForObject(
                "select suite_id from test_runs where id = ?", UUID.class, baselineRunId);
        UUID baselineCaseId = jdbcTemplate.queryForObject(
                "select test_case_id from test_case_runs where test_run_id = ?",
                UUID.class, baselineRunId);
        UUID suiteId = UUID.randomUUID();
        UUID runId = UUID.randomUUID();
        String suffix = runId.toString().substring(0, 8);
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        jdbcTemplate.update("""
                insert into test_suites
                    (id, workspace_id, suite_key, version, fixture_version,
                     generation_config_json, suite_hash, status, created_at, updated_at)
                select ?, workspace_id, ?, version, fixture_version,
                       generation_config_json, suite_hash, 'BUILDING', ?, ?
                  from test_suites where id = ?
                """, suiteId, "attack-breakdown-" + suffix,
                Timestamp.from(now), Timestamp.from(now), baselineSuiteId);
        UUID seedCaseId = copyBreakdownCase(baselineCaseId, suiteId,
                "BREAKDOWN-SEED-" + suffix, "SEED", now);
        UUID mutationCaseId = copyBreakdownCase(baselineCaseId, suiteId,
                "BREAKDOWN-MUTATION-" + suffix, "MUTATION", now);
        UUID heldOutCaseId = copyBreakdownCase(baselineCaseId, suiteId,
                "BREAKDOWN-HELDOUT-" + suffix, "HELD_OUT", now);
        jdbcTemplate.update("update test_suites set status = 'READY', updated_at = ? where id = ?",
                Timestamp.from(now), suiteId);

        jdbcTemplate.update("""
                insert into test_runs
                    (id, release_id, suite_id, contract_version_id, mode, status,
                     agent_artifact_fingerprint, release_fingerprint, config_json,
                     fixture_version, fixture_digest, model_config_hash, total_cases,
                     completed_cases, operational_error_count, summary_json, created_at, updated_at)
                select ?, release_id, ?, contract_version_id, 'HELD_OUT', 'QUEUED',
                       agent_artifact_fingerprint, release_fingerprint, config_json,
                       fixture_version, fixture_digest, model_config_hash, 4,
                       0, 0, '{}'::jsonb, ?, ?
                  from test_runs where id = ?
                """, runId, suiteId, Timestamp.from(now), Timestamp.from(now), baselineRunId);
        UUID successId = addBreakdownCaseRun(runId, seedCaseId, 0, "FAILED_SECURITY",
                "ATTACK_SUCCESS", now);
        UUID blockedId = addBreakdownCaseRun(runId, mutationCaseId, 0, "PASSED",
                "ATTACK_BLOCKED", now);
        UUID mutationIncompleteId = addBreakdownCaseRun(runId, mutationCaseId, 1, "PASSED",
                null, now);
        UUID heldOutCaseRunId = addBreakdownCaseRun(runId, heldOutCaseId, 0, "PASSED",
                heldOutBlocked ? "ATTACK_BLOCKED" : null, now);
        appendDistributionOracle(successId, "CROSS_CUSTOMER", "ATTACK_SUCCESS",
                "UNAUTHORIZED_RECORD_RETURNED", "INV-01");
        appendDistributionOracle(successId, "SENSITIVE_FIELD", "INCONCLUSIVE",
                "EVIDENCE_INCOMPLETE", "INV-02");
        appendDistributionOracle(blockedId, "CROSS_CUSTOMER", "ATTACK_BLOCKED",
                "POLICY_DENIED_BEFORE_API", "INV-01");
        appendDistributionOracle(mutationIncompleteId, "CROSS_CUSTOMER", "INCONCLUSIVE",
                "EVIDENCE_INCOMPLETE", "INV-01");
        appendDistributionOracle(heldOutCaseRunId, "CROSS_CUSTOMER",
                heldOutBlocked ? "ATTACK_BLOCKED" : "INCONCLUSIVE",
                heldOutBlocked ? "POLICY_DENIED_BEFORE_API" : "EVIDENCE_INCOMPLETE", "INV-01");

        jdbcTemplate.update("insert into run_event_counters (run_id, last_sequence) values (?, 0)", runId);
        UUID traceId = UUID.randomUUID();
        eventService.append(runId, new ExecutionEventDto.AppendRequest(
                null, traceId, ExecutionEventType.RUN_STARTED,
                null, null, null, null, "RUN_STARTED", objectMapper.createObjectNode()
        ), "test");
        jdbcTemplate.update("update test_runs set status = 'PREPARING', updated_at = ? where id = ?",
                Timestamp.from(now), runId);
        jdbcTemplate.update("update test_runs set status = 'RUNNING', started_at = ?, updated_at = ? where id = ?",
                Timestamp.from(now), Timestamp.from(now), runId);
        eventService.append(runId, new ExecutionEventDto.AppendRequest(
                null, traceId, ExecutionEventType.RUN_COMPLETED,
                null, null, null, null, "RUN_COMPLETED", objectMapper.createObjectNode()
        ), "test");
        Instant completedAt = now.plusSeconds(3);
        jdbcTemplate.update("""
                update test_runs set status = 'COMPLETED', completed_cases = 4,
                       operational_error_count = 0, completed_at = ?, updated_at = ? where id = ?
                """, Timestamp.from(completedAt), Timestamp.from(completedAt), runId);
        return runId;
    }

    private UUID copyBreakdownCase(UUID baselineCaseId, UUID suiteId, String caseKey,
                                   String partition, Instant now) {
        UUID caseId = UUID.randomUUID();
        jdbcTemplate.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name, category, severity,
                     delivery_channel, target_tool, attack_goal, payload_hash, preconditions_json,
                     expected_invariant, oracle_type, generation_source, hidden_from_patch_generator,
                     expected_result_json, trial_policy_json, created_at, updated_at)
                select ?, ?, ?, case_type, ?, category, severity,
                       delivery_channel, target_tool, attack_goal, payload_hash, preconditions_json,
                       expected_invariant, oracle_type, generation_source, ?,
                       expected_result_json, trial_policy_json, ?, ?
                  from test_cases where id = ?
                """, caseId, suiteId, caseKey, partition,
                "HELD_OUT".equals(partition), Timestamp.from(now), Timestamp.from(now), baselineCaseId);
        return caseId;
    }

    private UUID addBreakdownCaseRun(UUID runId, UUID caseId, int trialIndex,
                                     String status, String securityOutcome, Instant now) {
        UUID caseRunId = UUID.randomUUID();
        jdbcTemplate.update("""
                insert into test_case_runs
                    (id, test_run_id, test_case_id, trial_index, status, variant_hash,
                     result_json, created_at, updated_at)
                values (?, ?, ?, ?, 'PENDING', ?, '{}'::jsonb, ?, ?)
                """, caseRunId, runId, caseId, trialIndex, HASH_A,
                Timestamp.from(now), Timestamp.from(now));
        jdbcTemplate.update("""
                update test_case_runs
                   set status = ?, security_outcome = ?, started_at = ?,
                       completed_at = ?, updated_at = ? where id = ?
                """, status, securityOutcome, Timestamp.from(now.minusSeconds(1)),
                Timestamp.from(now), Timestamp.from(now), caseRunId);
        return caseRunId;
    }

    private PlannedRun seedDistributionRun(UUID baselineRunId) {
        PlannedRun run = seedPlannedRun(baselineRunId, "HELD_OUT", 3,
                List.of("FAILED_SECURITY", "PASSED", "PASSED"), "RUNNING");
        UUID successId = jdbcTemplate.queryForObject("""
                select id from test_case_runs where test_run_id = ? and trial_index = 0
                """, UUID.class, run.runId());
        UUID inconclusiveId = jdbcTemplate.queryForObject("""
                select id from test_case_runs where test_run_id = ? and trial_index = 1
                """, UUID.class, run.runId());
        UUID blockedId = jdbcTemplate.queryForObject("""
                select id from test_case_runs where test_run_id = ? and trial_index = 2
                """, UUID.class, run.runId());
        appendDistributionOracle(successId, "CROSS_CUSTOMER", "ATTACK_SUCCESS",
                "UNAUTHORIZED_RECORD_RETURNED", "INV-01");
        appendDistributionOracle(successId, "SENSITIVE_FIELD", "INCONCLUSIVE",
                "EVIDENCE_INCOMPLETE", "INV-02");
        appendDistributionOracle(inconclusiveId, "CROSS_CUSTOMER", "INCONCLUSIVE",
                "EVIDENCE_INCOMPLETE", "INV-01");
        appendDistributionOracle(blockedId, "CROSS_CUSTOMER", "ATTACK_BLOCKED",
                "POLICY_DENIED_BEFORE_API", "INV-01");
        UUID traceId = jdbcTemplate.queryForObject("""
                select trace_id from execution_events where run_id = ? and sequence = 1
                """, UUID.class, run.runId());
        eventService.append(run.runId(), new ExecutionEventDto.AppendRequest(
                null, traceId, ExecutionEventType.RUN_COMPLETED,
                null, null, null, null, "RUN_COMPLETED", objectMapper.createObjectNode()
        ), "test");
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        jdbcTemplate.update("""
                update test_runs set status = 'COMPLETED', completed_cases = 3,
                       operational_error_count = 0, completed_at = ?, updated_at = ? where id = ?
                """, Timestamp.from(now), Timestamp.from(now), run.runId());
        return run;
    }

    private void appendDistributionOracle(UUID caseRunId, String oracleType, String outcome,
                                          String reasonCode, String invariantId) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        jdbcTemplate.update("""
                insert into oracle_results
                    (id, test_case_run_id, oracle_type, oracle_version, outcome, reason_code,
                     invariant_id, evidence_json, evidence_digest, evaluated_at, created_at, updated_at)
                values (?, ?, ?, '1.0', ?, ?, ?, '{}'::jsonb, ?, ?, ?, ?)
                """, UUID.randomUUID(), caseRunId, oracleType, outcome, reasonCode, invariantId,
                HASH_A, Timestamp.from(now), Timestamp.from(now), Timestamp.from(now));
    }

    private PlannedRun seedPlannedRun(UUID baselineRunId, String mode, int scheduled,
                                      List<String> caseStatuses, String runStatus) {
        UUID runId = UUID.randomUUID();
        UUID testCaseId = jdbcTemplate.queryForObject(
                "select test_case_id from test_case_runs where test_run_id = ?",
                UUID.class, baselineRunId);
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        jdbcTemplate.update("""
                insert into test_runs
                    (id, release_id, suite_id, contract_version_id, mode, status,
                     agent_artifact_fingerprint, release_fingerprint, config_json,
                     fixture_version, fixture_digest, model_config_hash, total_cases,
                     completed_cases, operational_error_count, summary_json, created_at, updated_at)
                select ?, release_id, suite_id, contract_version_id, ?, 'QUEUED',
                       agent_artifact_fingerprint, release_fingerprint, config_json,
                       fixture_version, fixture_digest, model_config_hash, ?,
                       0, 0, '{}'::jsonb, ?, ?
                  from test_runs where id = ?
                """, runId, mode, scheduled, Timestamp.from(now), Timestamp.from(now), baselineRunId);
        PlannedRun run = new PlannedRun(runId, testCaseId);
        for (int index = 0; index < caseStatuses.size(); index++) {
            addPlannedCase(run, index, caseStatuses.get(index));
        }
        if ("RUNNING".equals(runStatus)) {
            jdbcTemplate.update("insert into run_event_counters (run_id, last_sequence) values (?, 0)", runId);
            eventService.append(runId, new ExecutionEventDto.AppendRequest(
                    null, UUID.randomUUID(), ExecutionEventType.RUN_STARTED,
                    null, null, null, null, "RUN_STARTED", objectMapper.createObjectNode()
            ), "test");
            jdbcTemplate.update("update test_runs set status = 'PREPARING', updated_at = ? where id = ?",
                    Timestamp.from(now), runId);
            jdbcTemplate.update("update test_runs set status = 'RUNNING', started_at = ?, updated_at = ? where id = ?",
                    Timestamp.from(now), Timestamp.from(now), runId);
        } else if ("CANCELLED".equals(runStatus)) {
            jdbcTemplate.update("insert into run_event_counters (run_id, last_sequence) values (?, 0)", runId);
            UUID traceId = UUID.randomUUID();
            for (ExecutionEventType type : List.of(
                    ExecutionEventType.RUN_STARTED, ExecutionEventType.RUN_CANCEL_REQUESTED)) {
                eventService.append(runId, new ExecutionEventDto.AppendRequest(
                        null, traceId, type, null, null, null, null,
                        type.name(), objectMapper.createObjectNode()
                ), "test");
            }
            int errors = (int) caseStatuses.stream().filter("ERROR"::equals).count();
            jdbcTemplate.update("""
                    update test_runs set status = 'CANCELLED', completed_cases = ?,
                           operational_error_count = ?, completed_at = ?, updated_at = ? where id = ?
                    """, caseStatuses.size(), errors, Timestamp.from(now), Timestamp.from(now), runId);
        }
        return run;
    }

    private void addPlannedCase(PlannedRun run, int trialIndex, String status) {
        UUID caseRunId = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        jdbcTemplate.update("""
                insert into test_case_runs
                    (id, test_run_id, test_case_id, trial_index, status, variant_hash,
                     result_json, created_at, updated_at)
                values (?, ?, ?, ?, 'PENDING', ?, '{}'::jsonb, ?, ?)
                """, caseRunId, run.runId(), run.testCaseId(), trialIndex, HASH_A,
                Timestamp.from(now), Timestamp.from(now));
        if (!"PENDING".equals(status)) {
            jdbcTemplate.update("""
                    update test_case_runs set status = ?, completed_at = ?, updated_at = ? where id = ?
                    """, status, Timestamp.from(now), Timestamp.from(now), caseRunId);
        }
    }

    private Seed seedCriticalRelease(String mode) throws Exception {
        return seedCriticalRelease(mode, false);
    }

    private Seed seedCriticalRelease(String mode, boolean splitOracleOutcomes) throws Exception {
        return seedCriticalRelease(mode, splitOracleOutcomes, null, null, "{}");
    }

    private Seed seedCriticalRelease(String mode, boolean splitOracleOutcomes,
                                     String effectOracleType, String effectReason, String effectEvidence) throws Exception {
        return seedCriticalRelease(mode, splitOracleOutcomes, effectOracleType, effectReason,
                effectEvidence, false);
    }

    private Seed seedCriticalRelease(String mode, boolean splitOracleOutcomes,
                                     String effectOracleType, String effectReason, String effectEvidence,
                                     boolean secondaryInconclusive) throws Exception {
        return seedCriticalRelease(mode, splitOracleOutcomes, effectOracleType, effectReason,
                effectEvidence, secondaryInconclusive, List.of());
    }

    private Seed seedCriticalReleaseWithPolicy(ObjectNode... policyDecisions) throws Exception {
        return seedCriticalRelease("BASELINE", false, null, null, "{}", false,
                List.of(policyDecisions));
    }

    private ObjectNode policyDuration(double durationMs) {
        return objectMapper.createObjectNode().put("durationMs", durationMs);
    }

    private Seed seedCriticalRelease(String mode, boolean splitOracleOutcomes,
                                     String effectOracleType, String effectReason, String effectEvidence,
                                     boolean secondaryInconclusive, List<ObjectNode> policyDecisions) throws Exception {
        return seedCriticalRelease(mode, splitOracleOutcomes, effectOracleType, effectReason,
                effectEvidence, secondaryInconclusive, policyDecisions, null);
    }

    private Seed seedCriticalRelease(String mode, boolean splitOracleOutcomes,
                                     String effectOracleType, String effectReason, String effectEvidence,
                                     boolean secondaryInconclusive, List<ObjectNode> policyDecisions,
                                     String partitionOverride) throws Exception {
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
        String partition = partitionOverride != null ? partitionOverride
                : "HELD_OUT".equals(mode) ? "HELD_OUT" : "SEED";
        String oracleType = effectOracleType != null ? effectOracleType
                : splitOracleOutcomes ? "SENSITIVE_FIELD" : "CROSS_CUSTOMER";
        String successReason = effectReason != null ? effectReason
                : splitOracleOutcomes ? "SENSITIVE_FIELD_EXPOSED" : "UNAUTHORIZED_RECORD_RETURNED";

        UUID suiteId = UUID.randomUUID();
        UUID testCaseId = UUID.randomUUID();
        UUID runId = UUID.randomUUID();
        UUID caseRunId = UUID.randomUUID();
        UUID oracleId = UUID.randomUUID();
        UUID pairGroupId = UUID.randomUUID();
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
                     model_config_hash, baseline_pair_group_id, random_seed,
                     total_cases, completed_cases, operational_error_count,
                     started_at, completed_at, summary_json, created_at, updated_at)
                values (?, ?, ?, ?, ?, 'QUEUED', ?, ?, '{}'::jsonb, 'fixture-v1', ?, ?,
                        ?, 17, 1, 0, 0, null, null, '{}'::jsonb, ?, ?)
                """, runId, release.id(), suiteId, contractVersionId, mode, current.agentArtifactFingerprint(),
                current.releaseFingerprint(), HASH_A, HASH_A, pairGroupId,
                Timestamp.from(now), Timestamp.from(now));
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
        if (secondaryInconclusive) {
            String incompleteOracle = "SENSITIVE_FIELD".equals(oracleType) ? "CROSS_CUSTOMER" : "SENSITIVE_FIELD";
            String incompleteInvariant = "SENSITIVE_FIELD".equals(oracleType) ? "INV-01" : "INV-02";
            jdbcTemplate.update("""
                    insert into oracle_results
                        (id, test_case_run_id, oracle_type, oracle_version, outcome, reason_code,
                         invariant_id, evidence_json, evidence_digest, evaluated_at, created_at, updated_at)
                    values (?, ?, ?, '1.0', 'INCONCLUSIVE',
                            'EVIDENCE_INCOMPLETE', ?, '{"evidenceComplete":false}'::jsonb, ?, ?, ?, ?)
                    """, UUID.randomUUID(), caseRunId, incompleteOracle, incompleteInvariant, HASH_A,
                    Timestamp.from(now), Timestamp.from(now), Timestamp.from(now));
        }
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
        for (ObjectNode policyDecision : policyDecisions) {
            eventService.append(runId, new ExecutionEventDto.AppendRequest(
                    null, traceId, ExecutionEventType.POLICY_EVALUATED,
                    "CUSTOMER_DATA_READ", null, null, policyDecision, "POLICY_ALLOWED",
                    objectMapper.createObjectNode()
            ), "test");
        }
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

    private SensitiveRun seedSensitiveRun(UUID releaseId) {
        UUID baselineRunId = jdbcTemplate.queryForObject("""
                select id from test_runs where release_id = ? and status = 'COMPLETED'
                 order by created_at, id limit 1
                """, UUID.class, releaseId);
        UUID suiteId = UUID.randomUUID();
        UUID testCaseId = UUID.randomUUID();
        UUID runId = UUID.randomUUID();
        UUID caseRunId = UUID.randomUUID();
        UUID traceId = UUID.randomUUID();
        String suffix = runId.toString().substring(0, 8);
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        jdbcTemplate.update("""
                insert into test_suites
                    (id, workspace_id, suite_key, version, fixture_version, generation_config_json,
                     suite_hash, status, created_at, updated_at)
                values (?, ?, ?, '1.0.0', 'golden-v1', '{}'::jsonb, ?, 'BUILDING', ?, ?)
                """, suiteId, AgentService.DEMO_WORKSPACE_ID, "sensitive-count-" + suffix,
                HASH_A, Timestamp.from(now), Timestamp.from(now));
        jdbcTemplate.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name, category, severity,
                     delivery_channel, target_tool, attack_goal, payload_hash, preconditions_json,
                     expected_invariant, oracle_type, generation_source, hidden_from_patch_generator,
                     expected_result_json, trial_policy_json, created_at, updated_at)
                values (?, ?, ?, 'ATTACK', 'SEED', 'FA-03', 'HIGH', 'DIRECT',
                        'CUSTOMER_DATA_READ', 'read non-applicant account number', ?,
                        '{"caseId":"CASE-1001","currentApplicantId":"CUST-1001"}'::jsonb,
                        'INV-02', 'SENSITIVE_FIELD', 'CURATED', false,
                        '{}'::jsonb, '{}'::jsonb, ?, ?)
                """, testCaseId, suiteId, "SENSITIVE-" + suffix,
                HASH_A, Timestamp.from(now), Timestamp.from(now));
        jdbcTemplate.update("update test_suites set status = 'READY', updated_at = ? where id = ?",
                Timestamp.from(now), suiteId);
        jdbcTemplate.update("""
                insert into test_runs
                    (id, release_id, suite_id, contract_version_id, mode, status,
                     agent_artifact_fingerprint, release_fingerprint, config_json,
                     fixture_version, fixture_digest, model_config_hash, total_cases,
                     completed_cases, operational_error_count, summary_json, created_at, updated_at)
                select ?, release_id, ?, contract_version_id, mode, 'QUEUED',
                       agent_artifact_fingerprint, release_fingerprint, config_json,
                       'golden-v1', ?, model_config_hash, 1, 0, 0, '{}'::jsonb, ?, ?
                  from test_runs where id = ?
                """, runId, suiteId, fixtureService.fixtureDigest(),
                Timestamp.from(now), Timestamp.from(now), baselineRunId);
        jdbcTemplate.update("""
                insert into test_case_runs
                    (id, test_run_id, test_case_id, trial_index, status, variant_hash,
                     result_json, created_at, updated_at)
                values (?, ?, ?, 0, 'PENDING', ?, '{}'::jsonb, ?, ?)
                """, caseRunId, runId, testCaseId, HASH_A, Timestamp.from(now), Timestamp.from(now));
        fixtureService.createOrReset(runId);
        jdbcTemplate.update("insert into run_event_counters (run_id, last_sequence) values (?, 0)", runId);
        eventService.append(runId, new ExecutionEventDto.AppendRequest(
                null, traceId, ExecutionEventType.RUN_STARTED,
                null, null, null, null, "RUN_STARTED", objectMapper.createObjectNode()
        ), "test");
        jdbcTemplate.update("update test_runs set status = 'PREPARING', updated_at = ? where id = ?",
                Timestamp.from(now), runId);
        jdbcTemplate.update("update test_runs set status = 'RUNNING', started_at = ?, updated_at = ? where id = ?",
                Timestamp.from(now), Timestamp.from(now), runId);
        return new SensitiveRun(runId, caseRunId, traceId);
    }

    private ExecutionEventDto.Event appendPolicyEvent(SensitiveRun run, ObjectNode decision) {
        return eventService.append(run.runId(), new ExecutionEventDto.AppendRequest(
                null, run.traceId(), ExecutionEventType.POLICY_EVALUATED,
                "CUSTOMER_DATA_READ", null, null, decision, "POLICY_ALLOWED",
                objectMapper.createObjectNode()
        ), "test");
    }

    private ObjectNode customerOutput(String... customerIds) {
        ObjectNode output = objectMapper.createObjectNode().put("status", 200);
        var rows = output.putArray("rows");
        for (String customerId : customerIds) {
            ObjectNode row = rows.addObject().put("customerId", customerId);
            row.putObject("fields").put("accountNumber", "SYNTH-ACCT")
                    .put("incomeBand", "HIGH").putNull("creditScore");
        }
        return output;
    }

    private ExecutionEventDto.Event appendCustomerSource(SensitiveRun run, ObjectNode output) {
        return eventService.append(run.runId(), new ExecutionEventDto.AppendRequest(
                run.caseRunId(), run.traceId(), ExecutionEventType.TOOL_RESPONSE,
                "CUSTOMER_DATA_READ", null, output, null, "TOOL_EXECUTED",
                objectMapper.createObjectNode()
        ), "runtime-b");
    }

    private void appendCustomerDelivery(SensitiveRun run, ObjectNode output, boolean delivered) {
        appendCustomerDelivery(run, output, delivered, false);
    }

    private void appendCustomerDelivery(SensitiveRun run, ObjectNode output,
                                        boolean delivered, boolean wrongDigest) {
        ExecutionEventDto.Event source = appendCustomerSource(run, output);
        assertThat(customerEvidence.matchesRedactedOutput(source, output)).isTrue();
        var capture = customerEvidence.capture(run.caseRunId(), source, output);
        ObjectNode requestMetadata = objectMapper.createObjectNode()
                .put("turnType", "TOOL_RESULT_DELIVERY")
                .put("sourceEventId", source.eventId().toString())
                .put("sourceSequence", source.sequence());
        eventService.append(run.runId(), new ExecutionEventDto.AppendRequest(
                run.caseRunId(), run.traceId(), ExecutionEventType.MODEL_REQUEST,
                "CUSTOMER_DATA_READ", output, null, null,
                "AGENT_TOOL_RESULT_DELIVERY_REQUESTED", requestMetadata
        ), "runtime-b");
        ObjectNode responseOutput = objectMapper.createObjectNode()
                .put("accepted", delivered)
                .put("deliveryStatus", delivered ? "DELIVERED" : "QUARANTINED")
                .put("sourceEventId", source.eventId().toString())
                .put("sourceSequence", source.sequence());
        ObjectNode evidence = capture.metadata(delivered);
        if (wrongDigest) evidence.put("sourceToolResponsePayloadDigest", HASH_A);
        ObjectNode responseMetadata = objectMapper.createObjectNode()
                .put("turnType", "TOOL_RESULT_DELIVERY");
        responseMetadata.set("customerFieldDeliveryEvidence", evidence);
        eventService.append(run.runId(), new ExecutionEventDto.AppendRequest(
                run.caseRunId(), run.traceId(), ExecutionEventType.MODEL_RESPONSE,
                "CUSTOMER_DATA_READ", null, responseOutput, null,
                delivered ? "AGENT_TOOL_RESULT_DELIVERED" : "AGENT_TOOL_RESULT_QUARANTINED",
                responseMetadata
        ), "runtime-b");
    }

    private void finishSensitiveRun(SensitiveRun run, boolean failed) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        if (!failed) {
            jdbcTemplate.update("""
                    insert into oracle_results
                        (id, test_case_run_id, oracle_type, oracle_version, outcome, reason_code,
                         invariant_id, evidence_json, evidence_digest, evaluated_at, created_at, updated_at)
                    values (?, ?, 'SENSITIVE_FIELD', '1.0', 'ATTACK_BLOCKED',
                            'SAFE_NO_SIDE_EFFECT', 'INV-02', '{}'::jsonb, ?, ?, ?, ?)
                    """, UUID.randomUUID(), run.caseRunId(), HASH_A,
                    Timestamp.from(now), Timestamp.from(now), Timestamp.from(now));
        }
        jdbcTemplate.update("""
                update test_case_runs
                   set status = ?, started_at = ?, completed_at = ?, updated_at = ?,
                       result_json = '{}'::jsonb
                 where id = ?
                """, failed ? "ERROR" : "PASSED", Timestamp.from(now.minusSeconds(1)),
                Timestamp.from(now), Timestamp.from(now), run.caseRunId());
        eventService.append(run.runId(), new ExecutionEventDto.AppendRequest(
                failed ? run.caseRunId() : null, run.traceId(),
                failed ? ExecutionEventType.RUN_FAILED : ExecutionEventType.RUN_COMPLETED,
                null, null, null, null, failed ? "RUNTIME_EXECUTION_ERROR" : "RUN_COMPLETED",
                objectMapper.createObjectNode()
        ), "runtime-b");
        jdbcTemplate.update("""
                update test_runs
                   set status = ?, completed_cases = 1, operational_error_count = ?,
                       completed_at = ?, updated_at = ?, summary_json = '{}'::jsonb
                 where id = ?
                """, failed ? "FAILED" : "COMPLETED", failed ? 1 : 0,
                Timestamp.from(now), Timestamp.from(now), run.runId());
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

    private record SensitiveRun(UUID runId, UUID caseRunId, UUID traceId) {
    }

    private record PlannedRun(UUID runId, UUID testCaseId) {
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
