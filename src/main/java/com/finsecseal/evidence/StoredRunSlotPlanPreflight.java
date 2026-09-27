package com.finsecseal.evidence;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Structural inspection of one V19 provisional roster. A valid report is still UNVERIFIED:
 * this reader has no approved Case criticality, reviewer provenance, or GC-02 authority.
 * It is neither a certification source nor a Release/Gate input.
 */
@Component
public final class StoredRunSlotPlanPreflight {
    private static final String RUN_SQL = """
            select run.status run_status, run.suite_id run_suite_id, run.total_cases,
                   agent.workspace_id run_workspace_id,
                   suite.workspace_id suite_workspace_id, suite.status suite_status,
                   suite.version suite_version, suite.suite_hash suite_hash,
                   plan.suite_id plan_suite_id, plan.suite_version plan_suite_version,
                   plan.suite_hash plan_suite_hash, plan.expected_slot_count,
                   plan.state plan_state,
                   (select count(*) from test_case_runs case_run
                     where case_run.test_run_id = run.id) case_run_count
              from test_runs run
              join agent_releases release on release.id = run.release_id
              join agents agent on agent.id = release.agent_id
              join test_suites suite on suite.id = run.suite_id
              left join test_run_slot_plans plan on plan.run_id = run.id
             where run.id = ?
             limit 2
            """;
    private static final String SLOTS_SQL = """
            select slot.test_case_id, slot.trial_index, slot.ordinal,
                   test_case.suite_id case_suite_id,
                   finsec_configured_trials_v1(test_case.trial_policy_json) configured_trials
              from test_run_slot_entries slot
              left join test_cases test_case on test_case.id = slot.test_case_id
             where slot.run_id = ?
             order by slot.ordinal
             limit 10001
            """;

    private final DataSource dataSource;

    public StoredRunSlotPlanPreflight(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    /**
     * Caller starts the at-most-five-second budget before acquiring its bound read-only
     * REPEATABLE READ connection. This method does not initiate a pool acquisition.
     */
    public Report inspect(UUID runId, Duration remaining) {
        if (runId == null || remaining == null || remaining.isNegative() || remaining.isZero()
                || remaining.compareTo(Duration.ofSeconds(5)) > 0
                || !TransactionSynchronizationManager.isActualTransactionActive()
                || !TransactionSynchronizationManager.isCurrentTransactionReadOnly()
                || !Integer.valueOf(Connection.TRANSACTION_REPEATABLE_READ).equals(
                        TransactionSynchronizationManager.getCurrentTransactionIsolationLevel())
                || !TransactionSynchronizationManager.hasResource(dataSource)) {
            throw unavailable();
        }

        long deadline = System.nanoTime() + remaining.toNanos();
        Connection connection = null;
        try {
            connection = DataSourceUtils.getConnection(dataSource);
            if (connection.getAutoCommit() || !connection.isReadOnly()
                    || connection.getTransactionIsolation() != Connection.TRANSACTION_REPEATABLE_READ) {
                throw unavailable();
            }
            String originalTimeout = currentTimeout(connection, deadline);
            setLocalTimeout(connection, deadline, remainingMillis(deadline) + "ms");
            try {
                Report report = inspectStored(connection, deadline, runId);
                if (System.nanoTime() >= deadline) throw unavailable();
                return report;
            } finally {
                setLocalTimeout(connection, deadline, originalTimeout);
            }
        } catch (SQLException | RuntimeException failure) {
            // Keep SQL, case identity and fixture details out of callers and logs.
            throw unavailable();
        } finally {
            if (connection != null) DataSourceUtils.releaseConnection(connection, dataSource);
        }
    }

    private Report inspectStored(Connection connection, long deadline, UUID runId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(RUN_SQL)) {
            statement.setQueryTimeout(queryTimeoutSeconds(deadline));
            statement.setObject(1, runId);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) return incomplete(Reason.RUN_UNAVAILABLE, 0, 0);
                String runStatus = rows.getString("run_status");
                UUID suiteId = rows.getObject("run_suite_id", UUID.class);
                int totalCases = rows.getInt("total_cases");
                UUID runWorkspace = rows.getObject("run_workspace_id", UUID.class);
                UUID suiteWorkspace = rows.getObject("suite_workspace_id", UUID.class);
                String suiteStatus = rows.getString("suite_status");
                String suiteVersion = rows.getString("suite_version");
                String suiteHash = rows.getString("suite_hash");
                UUID planSuite = rows.getObject("plan_suite_id", UUID.class);
                String planState = rows.getString("plan_state");
                int expected = rows.getInt("expected_slot_count");
                String planVersion = rows.getString("plan_suite_version");
                String planHash = rows.getString("plan_suite_hash");
                long caseRunCount = rows.getLong("case_run_count");
                if (rows.next()) return incomplete(Reason.RUN_UNAVAILABLE, 0, 0);
                if (!"QUEUED".equals(runStatus)) return incomplete(Reason.RUN_NOT_QUEUED, expected, 0);
                if (!"READY".equals(suiteStatus) || suiteId == null) {
                    return incomplete(Reason.SUITE_NOT_READY, expected, 0);
                }
                if (runWorkspace == null || !runWorkspace.equals(suiteWorkspace)) {
                    return incomplete(Reason.WORKSPACE_MISMATCH, expected, 0);
                }
                if (planState == null) {
                    return new Report(Status.LEGACY_UNCERTIFIED, Reason.HEADER_MISSING, 0, 0,
                            Evidence.UNAVAILABLE, Evidence.UNAVAILABLE, Scope.SELECTED_RUN_ONLY);
                }
                if (!"UNVERIFIED".equals(planState) || expected < 1 || expected > 10000
                        || expected != totalCases || !suiteId.equals(planSuite)
                        || !suiteVersion.equals(planVersion) || !suiteHash.equals(planHash)) {
                    return incomplete(Reason.HEADER_MISMATCH, expected, 0);
                }
                if (caseRunCount != 0) return incomplete(Reason.CASE_RUN_PRESENT, expected, 0);
                return inspectSlots(connection, deadline, runId, suiteId, expected);
            }
        }
    }

    private Report inspectSlots(Connection connection, long deadline, UUID runId, UUID suiteId,
            int expected) throws SQLException {
        Map<UUID, CaseSlots> byCase = new HashMap<>();
        int count = 0;
        try (PreparedStatement statement = connection.prepareStatement(SLOTS_SQL)) {
            statement.setQueryTimeout(queryTimeoutSeconds(deadline));
            statement.setObject(1, runId);
            statement.setFetchSize(256);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    if (count >= expected) return incomplete(Reason.SLOT_COUNT_MISMATCH, expected, count + 1);
                    if (rows.getInt("ordinal") != count) {
                        return incomplete(Reason.SLOT_ORDINAL_GAP, expected, count + 1);
                    }
                    UUID caseId = rows.getObject("test_case_id", UUID.class);
                    UUID caseSuite = rows.getObject("case_suite_id", UUID.class);
                    if (caseId == null || !suiteId.equals(caseSuite)) {
                        return incomplete(Reason.CASE_SCOPE_MISMATCH, expected, count + 1);
                    }
                    Integer configured = (Integer) rows.getObject("configured_trials");
                    int index = rows.getInt("trial_index");
                    if (configured == null || configured < 1 || configured > 5
                            || index < 0 || index >= configured) {
                        return incomplete(Reason.POLICY_INVALID, expected, count + 1);
                    }
                    CaseSlots slots = byCase.computeIfAbsent(caseId, ignored -> new CaseSlots(configured));
                    if (slots.configured != configured || !slots.add(index)) {
                        return incomplete(Reason.CASE_TRIAL_SET_MISMATCH, expected, count + 1);
                    }
                    count++;
                }
            }
        }
        if (count != expected) return incomplete(Reason.SLOT_COUNT_MISMATCH, expected, count);
        for (CaseSlots slots : byCase.values()) {
            if (!slots.complete()) return incomplete(Reason.CASE_TRIAL_SET_MISMATCH, expected, count);
        }
        return new Report(Status.UNVERIFIED_STRUCTURALLY_VALID, Reason.NONE, expected, count,
                Evidence.UNAVAILABLE, Evidence.UNAVAILABLE, Scope.SELECTED_RUN_ONLY);
    }

    private String currentTimeout(Connection connection, long deadline) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("show statement_timeout")) {
            statement.setQueryTimeout(queryTimeoutSeconds(deadline));
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) throw unavailable();
                String timeout = rows.getString(1);
                if (timeout == null || timeout.isBlank() || rows.next()) throw unavailable();
                return timeout;
            }
        }
    }

    private void setLocalTimeout(Connection connection, long deadline, String value) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "select set_config('statement_timeout', ?, true)")) {
            statement.setQueryTimeout(queryTimeoutSeconds(deadline));
            statement.setString(1, value);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) throw unavailable();
            }
        }
    }

    private int queryTimeoutSeconds(long deadline) {
        long nanos = deadline - System.nanoTime();
        if (nanos <= 0) throw unavailable();
        return (int) Math.min(5, Math.max(1, TimeUnit.NANOSECONDS.toSeconds(nanos) + 1));
    }

    private long remainingMillis(long deadline) {
        long millis = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
        if (millis < 1) throw unavailable();
        return millis;
    }

    private static Report incomplete(Reason reason, int expected, int observed) {
        return new Report(Status.UNVERIFIED_INCOMPLETE, reason, expected, observed,
                Evidence.UNAVAILABLE, Evidence.UNAVAILABLE, Scope.SELECTED_RUN_ONLY);
    }

    private static BusinessException unavailable() {
        return new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE,
                "Run slot preflight is unavailable");
    }

    private static final class CaseSlots {
        private final int configured;
        private int seen;
        private int count;

        private CaseSlots(int configured) { this.configured = configured; }

        private boolean add(int index) {
            int bit = 1 << index;
            if ((seen & bit) != 0) return false;
            seen |= bit;
            count++;
            return true;
        }

        private boolean complete() {
            return count == configured && seen == (1 << configured) - 1;
        }
    }

    public enum Status { LEGACY_UNCERTIFIED, UNVERIFIED_STRUCTURALLY_VALID, UNVERIFIED_INCOMPLETE }
    public enum Reason { NONE, RUN_UNAVAILABLE, RUN_NOT_QUEUED, SUITE_NOT_READY,
        WORKSPACE_MISMATCH, HEADER_MISSING, HEADER_MISMATCH, CASE_RUN_PRESENT,
        SLOT_COUNT_MISMATCH, SLOT_ORDINAL_GAP, CASE_SCOPE_MISMATCH, POLICY_INVALID,
        CASE_TRIAL_SET_MISMATCH }
    public enum Evidence { UNAVAILABLE }
    public enum Scope { SELECTED_RUN_ONLY }
    public record Report(Status status, Reason reason, int expectedSlots, int observedSlots,
            Evidence provenance, Evidence criticality, Scope scope) { }
}
