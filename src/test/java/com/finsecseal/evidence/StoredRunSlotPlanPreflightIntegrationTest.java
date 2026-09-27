package com.finsecseal.evidence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.agent.AgentService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.evidence.StoredRunSlotPlanPreflight.Evidence;
import com.finsecseal.evidence.StoredRunSlotPlanPreflight.Reason;
import com.finsecseal.evidence.StoredRunSlotPlanPreflight.Report;
import com.finsecseal.evidence.StoredRunSlotPlanPreflight.Scope;
import com.finsecseal.evidence.StoredRunSlotPlanPreflight.Status;
import java.lang.reflect.Proxy;
import java.sql.SQLException;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

@Testcontainers
@SpringBootTest(properties = "finsec.scheduling.enabled=false")
class StoredRunSlotPlanPreflightIntegrationTest {
    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final String POLICY_ONE = """
            {"schemaVersion":"required-trials/1","configuredTrials":1}
            """;
    private static final String POLICY_TWO = """
            {"schemaVersion":"required-trials/1","configuredTrials":2}
            """;

    @Container @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired DataSource dataSource;
    @Autowired JdbcTemplate db;
    @Autowired StoredRunSlotPlanPreflight preflight;

    @Test
    void completeSelectedRosterRemainsUnverifiedWithoutProvenanceOrCriticality() {
        Fixture fixture = seed(POLICY_TWO, POLICY_ONE, 3, true);
        insertPlan(fixture);
        insertSlot(fixture.runId(), fixture.firstCaseId(), 0, 0);
        insertSlot(fixture.runId(), fixture.firstCaseId(), 1, 1);
        insertSlot(fixture.runId(), fixture.secondCaseId(), 0, 2);
        Counts before = counts(fixture.runId());

        Report report = inspect(fixture.runId());

        assertThat(report.status()).isEqualTo(Status.UNVERIFIED_STRUCTURALLY_VALID);
        assertThat(report.reason()).isEqualTo(Reason.NONE);
        assertThat(report.expectedSlots()).isEqualTo(3);
        assertThat(report.observedSlots()).isEqualTo(3);
        assertThat(report.provenance()).isEqualTo(Evidence.UNAVAILABLE);
        assertThat(report.criticality()).isEqualTo(Evidence.UNAVAILABLE);
        assertThat(report.scope()).isEqualTo(Scope.SELECTED_RUN_ONLY);
        assertThat(db.queryForObject("select state from test_run_slot_plans where run_id = ?",
                String.class, fixture.runId())).isEqualTo("UNVERIFIED");
        assertThat(counts(fixture.runId())).isEqualTo(before);
    }

    @Test
    void noHeaderOrLegacyPolicyNeverBecomesARequiredRoster() {
        Fixture legacy = seed("{}", POLICY_ONE, 1, false);
        Counts before = counts(legacy.runId());

        Report report = inspect(legacy.runId());

        assertThat(report.status()).isEqualTo(Status.LEGACY_UNCERTIFIED);
        assertThat(report.reason()).isEqualTo(Reason.HEADER_MISSING);
        assertThat(report.provenance()).isEqualTo(Evidence.UNAVAILABLE);
        assertThat(report.criticality()).isEqualTo(Evidence.UNAVAILABLE);
        assertThat(counts(legacy.runId())).isEqualTo(before);

        Fixture invalidPolicy = seed(POLICY_TWO, "{}", 2, true);
        insertPlan(invalidPolicy);
        insertSlot(invalidPolicy.runId(), invalidPolicy.firstCaseId(), 0, 0);
        assertSqlState("23514", () -> insertSlot(invalidPolicy.runId(), invalidPolicy.secondCaseId(), 0, 1));
        Report incomplete = inspect(invalidPolicy.runId());
        assertThat(incomplete.status()).isEqualTo(Status.UNVERIFIED_INCOMPLETE);
        assertThat(incomplete.reason()).isEqualTo(Reason.SLOT_COUNT_MISMATCH);
        assertThat(incomplete.provenance()).isEqualTo(Evidence.UNAVAILABLE);
    }

    @Test
    void legalPartialPlansExposeCountOrdinalAndPerCaseIndexGaps() {
        Fixture countGap = seed(POLICY_TWO, POLICY_ONE, 3, true);
        insertPlan(countGap);
        insertSlot(countGap.runId(), countGap.firstCaseId(), 0, 0);
        assertThat(inspect(countGap.runId()).reason()).isEqualTo(Reason.SLOT_COUNT_MISMATCH);

        Fixture ordinalGap = seed(POLICY_TWO, POLICY_ONE, 3, true);
        insertPlan(ordinalGap);
        insertSlot(ordinalGap.runId(), ordinalGap.firstCaseId(), 0, 0);
        insertSlot(ordinalGap.runId(), ordinalGap.firstCaseId(), 1, 2);
        assertThat(inspect(ordinalGap.runId()).reason()).isEqualTo(Reason.SLOT_ORDINAL_GAP);

        // Three rows match totalCases, but selected Case one still lacks trialIndex=1.
        Fixture caseGap = seed(POLICY_TWO, POLICY_TWO, 3, true);
        insertPlan(caseGap);
        insertSlot(caseGap.runId(), caseGap.firstCaseId(), 0, 0);
        insertSlot(caseGap.runId(), caseGap.secondCaseId(), 0, 1);
        insertSlot(caseGap.runId(), caseGap.secondCaseId(), 1, 2);
        Report report = inspect(caseGap.runId());
        assertThat(report.status()).isEqualTo(Status.UNVERIFIED_INCOMPLETE);
        assertThat(report.reason()).isEqualTo(Reason.CASE_TRIAL_SET_MISMATCH);
        assertThat(report.observedSlots()).isEqualTo(3);
    }

    @Test
    void existingV19GuardsDenyForeignOrOutOfRangeRowsWithoutABypass() {
        Fixture fixture = seed(POLICY_TWO, POLICY_ONE, 2, true);
        Fixture foreign = seed(POLICY_ONE, POLICY_ONE, 1, true);
        insertPlan(fixture);

        assertSqlState("23514", () -> insertSlot(fixture.runId(), foreign.firstCaseId(), 0, 0));
        assertSqlState("23514", () -> insertSlot(fixture.runId(), fixture.firstCaseId(), 2, 0));
        assertSqlState("23514", () -> insertSlot(fixture.runId(), fixture.firstCaseId(), 0, 2));
        Report report = inspect(fixture.runId());
        assertThat(report.status()).isEqualTo(Status.UNVERIFIED_INCOMPLETE);
        assertThat(report.reason()).isEqualTo(Reason.SLOT_COUNT_MISMATCH);
        assertThat(counts(fixture.runId()).slots()).isZero();
    }

    @Test
    void forgedDbGrantAndStartedRunNeverTurnStructuralReportIntoAuthority() {
        // The SQL fixture grant is deliberately not a signed reviewer admission.
        Fixture fixture = seed(POLICY_ONE, POLICY_ONE, 1, true);
        insertPlan(fixture);
        insertSlot(fixture.runId(), fixture.firstCaseId(), 0, 0);
        Report structurallyValid = inspect(fixture.runId());
        assertThat(structurallyValid.status()).isEqualTo(Status.UNVERIFIED_STRUCTURALLY_VALID);
        assertThat(structurallyValid.provenance()).isEqualTo(Evidence.UNAVAILABLE);
        assertThat(structurallyValid.criticality()).isEqualTo(Evidence.UNAVAILABLE);

        db.update("update test_runs set status = 'PREPARING' where id = ?", fixture.runId());
        Report started = inspect(fixture.runId());
        assertThat(started.status()).isEqualTo(Status.UNVERIFIED_INCOMPLETE);
        assertThat(started.reason()).isEqualTo(Reason.RUN_NOT_QUEUED);
    }

    @Test
    void repeatableReadKeepsOneSnapshotWhileAnotherTransactionFinishesSlots() throws Exception {
        Fixture fixture = seed(POLICY_TWO, POLICY_ONE, 3, true);
        insertPlan(fixture);
        insertSlot(fixture.runId(), fixture.firstCaseId(), 0, 0);
        var firstRead = new CountDownLatch(1);
        var writerFinished = new CountDownLatch(1);
        var executor = Executors.newSingleThreadExecutor();
        try {
            var reader = executor.submit(() -> transaction(true, TransactionDefinition.ISOLATION_REPEATABLE_READ)
                    .execute(ignored -> {
                        Report first = preflight.inspect(fixture.runId(), Duration.ofSeconds(5));
                        firstRead.countDown();
                        try {
                            if (!writerFinished.await(10, TimeUnit.SECONDS)) {
                                throw new AssertionError("writer did not finish");
                            }
                        } catch (InterruptedException interrupted) {
                            Thread.currentThread().interrupt();
                            throw new AssertionError(interrupted);
                        }
                        Report second = preflight.inspect(fixture.runId(), Duration.ofSeconds(5));
                        return new ReportPair(first, second);
                    }));
            assertThat(firstRead.await(10, TimeUnit.SECONDS)).isTrue();
            insertSlot(fixture.runId(), fixture.firstCaseId(), 1, 1);
            insertSlot(fixture.runId(), fixture.secondCaseId(), 0, 2);
            writerFinished.countDown();
            ReportPair sameSnapshot = reader.get(10, TimeUnit.SECONDS);
            assertThat(sameSnapshot.first().reason()).isEqualTo(Reason.SLOT_COUNT_MISMATCH);
            assertThat(sameSnapshot.second().reason()).isEqualTo(Reason.SLOT_COUNT_MISMATCH);
            assertThat(inspect(fixture.runId()).status()).isEqualTo(Status.UNVERIFIED_STRUCTURALLY_VALID);
        } finally {
            writerFinished.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    void callerMustSupplyBoundReadOnlyRepeatableReadConnectionAndFiniteBudget() {
        UUID runId = UUID.randomUUID();
        assertUnavailable(() -> preflight.inspect(runId, Duration.ofSeconds(5)));
        assertUnavailable(() -> transaction(false, TransactionDefinition.ISOLATION_REPEATABLE_READ)
                .execute(ignored -> preflight.inspect(runId, Duration.ofSeconds(5))));
        assertUnavailable(() -> transaction(true, TransactionDefinition.ISOLATION_READ_COMMITTED)
                .execute(ignored -> preflight.inspect(runId, Duration.ofSeconds(5))));
        assertUnavailable(() -> transaction(true, TransactionDefinition.ISOLATION_REPEATABLE_READ)
                .execute(ignored -> preflight.inspect(runId, Duration.ofSeconds(6))));
        assertUnavailable(() -> transaction(true, TransactionDefinition.ISOLATION_REPEATABLE_READ)
                .execute(ignored -> preflight.inspect(runId, Duration.ZERO)));

        AtomicInteger attemptedConnections = new AtomicInteger();
        DataSource unavailablePool = (DataSource) Proxy.newProxyInstance(DataSource.class.getClassLoader(),
                new Class<?>[]{DataSource.class}, (proxy, method, arguments) -> {
                    return switch (method.getName()) {
                        case "hashCode" -> System.identityHashCode(proxy);
                        case "equals" -> proxy == arguments[0];
                        case "toString" -> "UnavailablePool";
                        case "getConnection" -> {
                            attemptedConnections.incrementAndGet();
                            throw new AssertionError("preflight must not acquire an unbound connection");
                        }
                        default -> throw new AssertionError("unexpected DataSource call");
                    };
                });
        assertUnavailable(() -> new StoredRunSlotPlanPreflight(unavailablePool)
                .inspect(runId, Duration.ofSeconds(5)));
        assertThat(attemptedConnections).hasValue(0);
    }

    @Test
    void localStatementTimeoutIsRestoredAndReadDoesNotWriteEvidence() {
        Fixture fixture = seed(POLICY_ONE, POLICY_ONE, 1, true);
        insertPlan(fixture);
        insertSlot(fixture.runId(), fixture.firstCaseId(), 0, 0);
        Counts before = counts(fixture.runId());
        transaction(true, TransactionDefinition.ISOLATION_REPEATABLE_READ).execute(ignored -> {
            String original = db.queryForObject("show statement_timeout", String.class);
            assertThat(preflight.inspect(fixture.runId(), Duration.ofSeconds(5)).status())
                    .isEqualTo(Status.UNVERIFIED_STRUCTURALLY_VALID);
            assertThat(db.queryForObject("show statement_timeout", String.class)).isEqualTo(original);
            return null;
        });
        assertThat(counts(fixture.runId())).isEqualTo(before);
    }

    private Report inspect(UUID runId) {
        return transaction(true, TransactionDefinition.ISOLATION_REPEATABLE_READ)
                .execute(ignored -> preflight.inspect(runId, Duration.ofSeconds(5)));
    }

    private TransactionTemplate transaction(boolean readOnly, int isolation) {
        var template = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        template.setReadOnly(readOnly);
        template.setIsolationLevel(isolation);
        return template;
    }

    private Fixture seed(String firstPolicy, String secondPolicy, int totalCases, boolean grant) {
        UUID agentId = UUID.randomUUID();
        UUID releaseId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        UUID firstCaseId = UUID.randomUUID();
        UUID secondCaseId = UUID.randomUUID();
        UUID runId = UUID.randomUUID();
        String suffix = agentId.toString().substring(0, 8);
        db.update("""
                insert into agents (id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'Preflight Agent', 'Unverified slot preflight test', 'ACTIVE')
                """, agentId, AgentService.DEMO_WORKSPACE_ID, "preflight-agent-" + suffix);
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
                """, suiteId, AgentService.DEMO_WORKSPACE_ID, "preflight-suite-" + suffix, HASH);
        insertCase(suiteId, firstCaseId, "case-1", firstPolicy);
        insertCase(suiteId, secondCaseId, "case-2", secondPolicy);
        db.update("update test_suites set status = 'READY' where id = ?", suiteId);
        db.update("""
                insert into test_runs
                    (id, release_id, suite_id, mode, status, agent_artifact_fingerprint,
                     release_fingerprint, config_json, fixture_version, fixture_digest,
                     model_config_hash, total_cases)
                values (?, ?, ?, 'BASELINE', 'QUEUED', ?, ?, '{}'::jsonb, 'fixture-v1', ?, ?, ?)
                """, runId, releaseId, suiteId, HASH, HASH, HASH, HASH, totalCases);
        if (grant) db.update("""
                insert into test_run_reviewer_grants
                    (run_id, workspace_id, actor_id, reviewer_role, session_digest,
                     authority_stamp, authority_expires_at)
                values (?, ?, 'db-fixture', 'AI_SECURITY_REVIEWER', ?, 'not-a-signed-admission',
                        now() + interval '30 minutes')
                """, runId, AgentService.DEMO_WORKSPACE_ID, HASH);
        return new Fixture(runId, suiteId, firstCaseId, secondCaseId);
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

    private void insertPlan(Fixture fixture) {
        db.update("""
                insert into test_run_slot_plans
                    (run_id, suite_id, suite_version, suite_hash, expected_slot_count)
                values (?, ?, '1.0.0', ?, ?)
                """, fixture.runId(), fixture.suiteId(), HASH, db.queryForObject(
                "select total_cases from test_runs where id = ?", Integer.class, fixture.runId()));
    }

    private void insertSlot(UUID runId, UUID caseId, int index, int ordinal) {
        db.update("""
                insert into test_run_slot_entries (run_id, test_case_id, trial_index, ordinal)
                values (?, ?, ?, ?)
                """, runId, caseId, index, ordinal);
    }

    private Counts counts(UUID runId) {
        return new Counts(count("test_runs", "id", runId),
                count("test_run_reviewer_grants", "run_id", runId),
                count("test_run_slot_plans", "run_id", runId),
                count("test_run_slot_entries", "run_id", runId),
                count("test_case_runs", "test_run_id", runId),
                count("audit_records", "resource_id", runId));
    }

    private int count(String table, String field, UUID runId) {
        return db.queryForObject("select count(*) from " + table + " where " + field + " = ?",
                Integer.class, runId);
    }

    private void assertSqlState(String expected, Runnable write) {
        assertThatThrownBy(write::run).isInstanceOf(DataAccessException.class)
                .satisfies(failure -> {
                    Throwable cause = ((DataAccessException) failure).getMostSpecificCause();
                    assertThat(cause).isInstanceOf(SQLException.class);
                    assertThat(((SQLException) cause).getSQLState()).isEqualTo(expected);
                });
    }

    private void assertUnavailable(Runnable call) {
        assertThatThrownBy(call::run).isInstanceOf(BusinessException.class)
                .satisfies(failure -> {
                    BusinessException safe = (BusinessException) failure;
                    assertThat(safe.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE);
                    assertThat(safe.getMessage()).isEqualTo("Run slot preflight is unavailable");
                    assertThat(safe.getCause()).isNull();
                });
    }

    private record Fixture(UUID runId, UUID suiteId, UUID firstCaseId, UUID secondCaseId) { }
    private record Counts(int runs, int grants, int plans, int slots, int caseRuns, int audits) { }
    private record ReportPair(Report first, Report second) { }
}
