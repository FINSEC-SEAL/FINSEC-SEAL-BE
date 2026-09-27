package com.finsecseal.evidence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.agent.AgentService;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

@Testcontainers
@SpringBootTest
class TestRunSlotPlanIntegrationTest {
    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final String POLICY_TWO = """
            {"schemaVersion":"required-trials/1","configuredTrials":2}
            """;
    private static final String POLICY_ONE = """
            {"schemaVersion":"required-trials/1","configuredTrials":1}
            """;

    @Container @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired JdbcTemplate db;
    @Autowired DataSource dataSource;

    @Test
    void acceptsOnlyExactStoredVersionedIntegerTrialPolicy() {
        for (int count : List.of(1, 2, 3, 4, 5)) {
            assertThat(parsed("""
                    {"schemaVersion":"required-trials/1","configuredTrials":%d}
                    """.formatted(count))).isEqualTo(count);
        }
        for (String invalid : List.of(
                "{}", "null", "[]",
                "{\"configuredTrials\":1}",
                "{\"schemaVersion\":\"unknown\",\"configuredTrials\":1}",
                "{\"schemaVersion\":\"required-trials/1\",\"configuredTrials\":0}",
                "{\"schemaVersion\":\"required-trials/1\",\"configuredTrials\":6}",
                "{\"schemaVersion\":\"required-trials/1\",\"configuredTrials\":1.0}",
                "{\"schemaVersion\":\"required-trials/1\",\"configuredTrials\":1.5}",
                "{\"schemaVersion\":\"required-trials/1\",\"configuredTrials\":\"1\"}",
                "{\"schemaVersion\":\"required-trials/1\",\"configuredTrials\":1,\"critical\":false}")) {
            assertThat(parsed(invalid)).as(invalid).isNull();
        }
    }

    @Test
    void grantedQueuedRunKeepsOnlyUnverifiedImmutableSameSuiteSlots() {
        Seed seed = seed(2, true, POLICY_ONE);
        insertPlan(seed, 2);
        insertSlot(seed.runId(), seed.firstCaseId(), 0, 0);
        insertSlot(seed.runId(), seed.firstCaseId(), 1, 1);

        assertThat(db.queryForObject("select state from test_run_slot_plans where run_id = ?",
                String.class, seed.runId())).isEqualTo("UNVERIFIED");
        assertThat(slotCount(seed.runId())).isEqualTo(2);
        // The full-plan count guard rejects a third slot before its uniqueness check.
        assertSqlState("23514", () -> insertSlot(seed.runId(), seed.firstCaseId(), 0, 0));
        assertSqlState("55000", () -> db.update(
                "update test_run_slot_entries set ordinal = 1 where run_id = ? and ordinal = 0", seed.runId()));
        assertSqlState("55000", () -> db.update(
                "delete from test_run_slot_entries where run_id = ? and ordinal = 0", seed.runId()));
        assertSqlState("55000", () -> db.update(
                "update test_run_slot_plans set expected_slot_count = 1 where run_id = ?", seed.runId()));
        assertSqlState("55000", () -> db.update(
                "delete from test_run_slot_plans where run_id = ?", seed.runId()));
        assertSqlState("23514", () -> insertCaseRun(seed.runId(), seed.firstCaseId()));
        assertThat(db.queryForObject("select count(*) from test_case_runs where test_run_id = ?",
                Integer.class, seed.runId())).isZero();
    }

    @Test
    void deniesUngrantedMismatchedOrAlreadyStartedHeaderAndCertifiedForgery() {
        Seed noGrant = seed(1, false, POLICY_ONE);
        assertSqlState("23514", () -> insertPlan(noGrant, 1));

        Seed wrongTotal = seed(2, true, POLICY_ONE);
        assertSqlState("23514", () -> insertPlan(wrongTotal, 1));

        Seed otherSuite = seed(1, true, POLICY_ONE);
        Seed wrongSuite = seed(1, true, POLICY_ONE);
        assertSqlState("23514", () -> db.update("""
                insert into test_run_slot_plans
                    (run_id, suite_id, suite_version, suite_hash, expected_slot_count)
                values (?, ?, '1.0.0', ?, 1)
                """, wrongSuite.runId(), otherSuite.suiteId(), HASH));

        Seed started = seed(1, true, POLICY_ONE);
        db.update("update test_runs set status = 'PREPARING' where id = ?", started.runId());
        assertSqlState("23514", () -> insertPlan(started, 1));

        Seed forged = seed(1, true, POLICY_ONE);
        assertSqlState("23514", () -> db.update("""
                insert into test_run_slot_plans
                    (run_id, state, suite_id, suite_version, suite_hash, expected_slot_count)
                values (?, 'CERTIFIED', ?, '1.0.0', ?, 1)
                """, forged.runId(), forged.suiteId(), HASH));
        assertThat(db.queryForObject("select count(*) from test_run_slot_plans where run_id = ?",
                Integer.class, forged.runId())).isZero();
    }

    @Test
    void rejectsForeignLegacyDuplicateAndOutOfRangeSlots() {
        Seed seed = seed(2, true, "{}");
        Seed foreign = seed(1, true, POLICY_ONE);
        insertPlan(seed, 2);

        assertSqlState("23514", () -> insertSlot(seed.runId(), foreign.firstCaseId(), 0, 0));
        assertSqlState("23514", () -> insertSlot(seed.runId(), seed.secondCaseId(), 0, 0));
        assertSqlState("23514", () -> insertSlot(seed.runId(), seed.firstCaseId(), 2, 0));
        assertSqlState("23514", () -> insertSlot(seed.runId(), seed.firstCaseId(), 0, 2));
        insertSlot(seed.runId(), seed.firstCaseId(), 0, 0);
        assertSqlState("23505", () -> insertSlot(seed.runId(), seed.firstCaseId(), 1, 0));
        assertThat(slotCount(seed.runId())).isEqualTo(1);
    }

    @Test
    void legacyRunWithoutHeaderKeepsExistingCaseRunPath() {
        Seed legacy = seed(1, false, "{}");
        assertThat(db.queryForObject("select count(*) from test_run_slot_plans where run_id = ?",
                Integer.class, legacy.runId())).isZero();
        insertCaseRun(legacy.runId(), legacy.firstCaseId());
        assertThat(db.queryForObject("select count(*) from test_case_runs where test_run_id = ?",
                Integer.class, legacy.runId())).isEqualTo(1);
        // A provisional header cannot be attached to already materialized work.
        insertGrant(legacy.runId());
        assertSqlState("23514", () -> insertPlan(legacy, 1));
    }

    @Test
    void concurrentSlotsWithTheSameOrdinalLeaveOnlyOneRow() throws Exception {
        Seed seed = seed(2, true, POLICY_ONE);
        insertPlan(seed, 2);
        var executor = Executors.newFixedThreadPool(2);
        var release = new CountDownLatch(1);
        try {
            var first = executor.submit(() -> concurrentSlot(release, seed.runId(), seed.firstCaseId()));
            var second = executor.submit(() -> concurrentSlot(release, seed.runId(), seed.secondCaseId()));
            release.countDown();
            assertThat(List.of(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(true, false);
            assertThat(slotCount(seed.runId())).isEqualTo(1);
        } finally {
            release.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    void invalidSlotRollsBackHeaderAndEarlierSlotInTheSameTransaction() throws Exception {
        Seed seed = seed(2, true, "{}");
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                execute(connection, """
                        insert into test_run_slot_plans
                            (run_id, suite_id, suite_version, suite_hash, expected_slot_count)
                        values (?, ?, '1.0.0', ?, 2)
                        """, seed.runId(), seed.suiteId(), HASH);
                execute(connection, """
                        insert into test_run_slot_entries (run_id, test_case_id, trial_index, ordinal)
                        values (?, ?, 0, 0)
                        """, seed.runId(), seed.firstCaseId());
                assertThatThrownBy(() -> execute(connection, """
                        insert into test_run_slot_entries (run_id, test_case_id, trial_index, ordinal)
                        values (?, ?, 0, 1)
                        """, seed.runId(), seed.secondCaseId()))
                        .isInstanceOf(SQLException.class)
                        .extracting(error -> ((SQLException) error).getSQLState())
                        .isEqualTo("23514");
            } finally {
                connection.rollback();
            }
        }
        assertThat(db.queryForObject("select count(*) from test_run_slot_plans where run_id = ?",
                Integer.class, seed.runId())).isZero();
        assertThat(slotCount(seed.runId())).isZero();
    }

    private Integer parsed(String json) {
        return db.queryForObject("select finsec_configured_trials_v1(?::jsonb)", Integer.class, json);
    }

    private boolean concurrentSlot(CountDownLatch release, UUID runId, UUID caseId) throws Exception {
        release.await();
        try {
            insertSlot(runId, caseId, 0, 0);
            return true;
        } catch (DataAccessException exception) {
            assertThat(exception.getMostSpecificCause()).isInstanceOf(SQLException.class);
            assertThat(((SQLException) exception.getMostSpecificCause()).getSQLState()).isEqualTo("23505");
            return false;
        }
    }

    private Seed seed(int totalCases, boolean grant, String secondPolicy) {
        UUID agentId = UUID.randomUUID();
        UUID releaseId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        UUID firstCaseId = UUID.randomUUID();
        UUID secondCaseId = UUID.randomUUID();
        UUID runId = UUID.randomUUID();
        String suffix = agentId.toString().substring(0, 8);
        db.update("""
                insert into agents (id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'Plan Agent', 'Unverified slot plan test', 'ACTIVE')
                """, agentId, AgentService.DEMO_WORKSPACE_ID, "plan-agent-" + suffix);
        db.update("""
                insert into agent_releases
                    (id, agent_id, version, business_purpose, manifest_schema_version, manifest_json,
                     agent_artifact_fingerprint, release_fingerprint, lifecycle_state, effective_status)
                values (?, ?, '1.0.0', 'LOAN_DOCUMENT_COMPLETENESS_REVIEW', '1.0', '{}'::jsonb,
                        ?, ?, 'ANALYZED', 'ANALYZED')
                """, releaseId, agentId, HASH, HASH);
        db.update("""
                insert into test_suites
                    (id, workspace_id, suite_key, version, fixture_version, generation_config_json,
                     suite_hash, status)
                values (?, ?, ?, '1.0.0', 'fixture-v1', '{}'::jsonb, ?, 'BUILDING')
                """, suiteId, AgentService.DEMO_WORKSPACE_ID, "plan-suite-" + suffix, HASH);
        insertCase(suiteId, firstCaseId, "case-1", POLICY_TWO);
        insertCase(suiteId, secondCaseId, "case-2", secondPolicy);
        db.update("update test_suites set status = 'READY' where id = ?", suiteId);
        db.update("""
                insert into test_runs
                    (id, release_id, suite_id, mode, status, agent_artifact_fingerprint,
                     release_fingerprint, config_json, fixture_version, fixture_digest,
                     model_config_hash, total_cases)
                values (?, ?, ?, 'BASELINE', 'QUEUED', ?, ?, '{}'::jsonb, 'fixture-v1', ?, ?, ?)
                """, runId, releaseId, suiteId, HASH, HASH, HASH, HASH, totalCases);
        if (grant) insertGrant(runId);
        return new Seed(suiteId, firstCaseId, secondCaseId, runId);
    }

    private void insertCase(UUID suiteId, UUID caseId, String key, String policy) {
        db.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name, category, severity,
                     delivery_channel, payload_hash, preconditions_json, expected_invariant,
                     oracle_type, generation_source, expected_result_json, trial_policy_json)
                values (?, ?, ?, 'NORMAL', 'NORMAL', 'NORMAL', 'LOW', 'DIRECT', ?,
                        '{}'::jsonb, 'INV-NORMAL', 'NORMAL_TASK', 'CURATED', '{}'::jsonb, ?::jsonb)
                """, caseId, suiteId, key, HASH, policy);
    }

    private void insertGrant(UUID runId) {
        // Structural SQL fixture only; V19 does not treat this as fresh signed authority.
        db.update("""
                insert into test_run_reviewer_grants
                    (run_id, workspace_id, actor_id, reviewer_role, session_digest,
                     authority_stamp, authority_expires_at)
                values (?, ?, 'plan-reviewer', 'AI_SECURITY_REVIEWER', ?, 'plan-test-stamp', now() + interval '30 minutes')
                """, runId, AgentService.DEMO_WORKSPACE_ID, HASH);
    }

    private void insertPlan(Seed seed, int expected) {
        db.update("""
                insert into test_run_slot_plans
                    (run_id, suite_id, suite_version, suite_hash, expected_slot_count)
                values (?, ?, '1.0.0', ?, ?)
                """, seed.runId(), seed.suiteId(), HASH, expected);
    }

    private void insertSlot(UUID runId, UUID caseId, int trialIndex, int ordinal) {
        db.update("""
                insert into test_run_slot_entries (run_id, test_case_id, trial_index, ordinal)
                values (?, ?, ?, ?)
                """, runId, caseId, trialIndex, ordinal);
    }

    private void insertCaseRun(UUID runId, UUID caseId) {
        db.update("""
                insert into test_case_runs (id, test_run_id, test_case_id, trial_index, status, variant_hash)
                values (?, ?, ?, 0, 'PENDING', ?)
                """, UUID.randomUUID(), runId, caseId, HASH);
    }

    private int slotCount(UUID runId) {
        return db.queryForObject("select count(*) from test_run_slot_entries where run_id = ?",
                Integer.class, runId);
    }

    private void execute(Connection connection, String sql, Object... values) throws SQLException {
        try (var statement = connection.prepareStatement(sql)) {
            for (int index = 0; index < values.length; index++) statement.setObject(index + 1, values[index]);
            statement.executeUpdate();
        }
    }

    private void assertSqlState(String expected, Runnable operation) {
        assertThatThrownBy(operation::run)
                .rootCause()
                .isInstanceOf(SQLException.class)
                .extracting(error -> ((SQLException) error).getSQLState())
                .isEqualTo(expected);
    }

    private record Seed(UUID suiteId, UUID firstCaseId, UUID secondCaseId, UUID runId) { }
}
