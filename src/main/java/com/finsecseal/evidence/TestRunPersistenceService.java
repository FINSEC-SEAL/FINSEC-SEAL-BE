package com.finsecseal.evidence;

import com.finsecseal.audit.AuditService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.common.persistence.UuidV7;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Service
@Transactional(readOnly = true)
public class TestRunPersistenceService {

    private static final Set<String> RUNNABLE_RELEASE_STATES = Set.of(
            "ANALYZED", "TESTING", "REMEDIATION", "VERIFYING"
    );
    private static final Set<TestCaseRunStatus> TERMINAL_CASE_STATUSES = Set.of(
            TestCaseRunStatus.PASSED,
            TestCaseRunStatus.FAILED_SECURITY,
            TestCaseRunStatus.FAILED_FUNCTIONAL,
            TestCaseRunStatus.ERROR,
            TestCaseRunStatus.CANCELLED
    );
    private static final Map<TestRunStatus, Set<TestRunStatus>> RUN_TRANSITIONS = Map.of(
            TestRunStatus.QUEUED, Set.of(
                    TestRunStatus.PREPARING, TestRunStatus.CANCELLING,
                    TestRunStatus.FAILED, TestRunStatus.CANCELLED
            ),
            TestRunStatus.PREPARING, Set.of(
                    TestRunStatus.RUNNING, TestRunStatus.CANCELLING,
                    TestRunStatus.FAILED, TestRunStatus.CANCELLED
            ),
            TestRunStatus.RUNNING, Set.of(
                    TestRunStatus.CANCELLING, TestRunStatus.COMPLETED, TestRunStatus.FAILED
            ),
            TestRunStatus.CANCELLING, Set.of(TestRunStatus.CANCELLED, TestRunStatus.FAILED),
            TestRunStatus.COMPLETED, Set.of(),
            TestRunStatus.FAILED, Set.of(),
            TestRunStatus.CANCELLED, Set.of()
    );
    private static final Map<TestCaseRunStatus, Set<TestCaseRunStatus>> CASE_TRANSITIONS = Map.of(
            TestCaseRunStatus.PENDING, Set.of(
                    TestCaseRunStatus.EXECUTING, TestCaseRunStatus.EVALUATING,
                    TestCaseRunStatus.PASSED, TestCaseRunStatus.FAILED_SECURITY,
                    TestCaseRunStatus.FAILED_FUNCTIONAL, TestCaseRunStatus.ERROR,
                    TestCaseRunStatus.CANCELLED
            ),
            TestCaseRunStatus.EXECUTING, Set.of(
                    TestCaseRunStatus.EVALUATING, TestCaseRunStatus.PASSED,
                    TestCaseRunStatus.FAILED_SECURITY, TestCaseRunStatus.FAILED_FUNCTIONAL,
                    TestCaseRunStatus.ERROR, TestCaseRunStatus.CANCELLED
            ),
            TestCaseRunStatus.EVALUATING, Set.of(
                    TestCaseRunStatus.PASSED, TestCaseRunStatus.FAILED_SECURITY,
                    TestCaseRunStatus.FAILED_FUNCTIONAL, TestCaseRunStatus.ERROR,
                    TestCaseRunStatus.CANCELLED
            ),
            TestCaseRunStatus.PASSED, Set.of(),
            TestCaseRunStatus.FAILED_SECURITY, Set.of(),
            TestCaseRunStatus.FAILED_FUNCTIONAL, Set.of(),
            TestCaseRunStatus.ERROR, Set.of(),
            TestCaseRunStatus.CANCELLED, Set.of()
    );

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final RedactionService redactionService;
    private final CanonicalJsonService canonicalJsonService;
    private final DigestService digestService;
    private final AuditService auditService;
    private final TestRunProjectionService projectionService;

    public TestRunPersistenceService(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            RedactionService redactionService,
            CanonicalJsonService canonicalJsonService,
            DigestService digestService,
            AuditService auditService,
            TestRunProjectionService projectionService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.redactionService = redactionService;
        this.canonicalJsonService = canonicalJsonService;
        this.digestService = digestService;
        this.auditService = auditService;
        this.projectionService = projectionService;
    }

    @Transactional
    public TestRunPersistenceDto.Registered register(
            TestRunPersistenceDto.RegisterRequest request,
            String actorId
    ) {
        if (request == null || request.releaseId() == null || request.suiteId() == null
                || request.mode() == null || request.totalCases() < 1 || request.totalCases() > 10000) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "totalCases must be between 1 and 10000");
        }
        requireHash(request.fixtureDigest(), "fixtureDigest");
        requireHash(request.modelConfigHash(), "modelConfigHash");
        List<RegistrationSnapshot> snapshots = jdbcTemplate.query("""
                select agent.workspace_id, release.agent_artifact_fingerprint,
                       release.release_fingerprint, release.lifecycle_state,
                       suite.fixture_version, suite.status suite_status
                  from agent_releases release
                  join agents agent on agent.id = release.agent_id
                  join test_suites suite on suite.id = ?
                 where release.id = ?
                 for update of release, suite
                """, (resultSet, rowNumber) -> new RegistrationSnapshot(
                        resultSet.getObject("workspace_id", UUID.class),
                        resultSet.getString("agent_artifact_fingerprint"),
                        resultSet.getString("release_fingerprint"),
                        resultSet.getString("lifecycle_state"),
                        resultSet.getString("fixture_version"),
                        resultSet.getString("suite_status")
                ), request.suiteId(), request.releaseId());
        if (snapshots.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "Release or TestSuite not found");
        }
        RegistrationSnapshot snapshot = snapshots.getFirst();
        if (!RUNNABLE_RELEASE_STATES.contains(snapshot.releaseState())) {
            throw new BusinessException(ErrorCode.INVALID_STATE_TRANSITION, "Release is not ready for a TestRun");
        }
        if (!"READY".equals(snapshot.suiteStatus())) {
            throw new BusinessException(ErrorCode.INVALID_STATE_TRANSITION, "TestSuite must be READY");
        }
        RedactionService.Result safeConfig = redactionService.redact(
                request.config() == null ? objectMapper.createObjectNode() : request.config()
        );
        UUID runId = UuidV7.generate();
        try {
            jdbcTemplate.update("""
                    insert into test_runs
                        (id, release_id, suite_id, contract_version_id, mode, status,
                         baseline_pair_group_id, agent_artifact_fingerprint, release_fingerprint,
                         config_json, fixture_version, fixture_digest, model_config_hash, random_seed,
                         total_cases, completed_cases, operational_error_count)
                    values (?, ?, ?, ?, ?, 'QUEUED', ?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?, 0, 0)
                    """,
                    runId,
                    request.releaseId(),
                    request.suiteId(),
                    request.contractVersionId(),
                    request.mode().name(),
                    request.baselinePairGroupId(),
                    snapshot.agentFingerprint(),
                    snapshot.releaseFingerprint(),
                    json(safeConfig.redacted()),
                    snapshot.fixtureVersion(),
                    request.fixtureDigest(),
                    request.modelConfigHash(),
                    request.randomSeed(),
                    request.totalCases()
            );
        } catch (DataIntegrityViolationException exception) {
            throw new BusinessException(ErrorCode.RESOURCE_CONFLICT, "TestRun registration was rejected");
        }
        ObjectNode metadata = objectMapper.createObjectNode();
        metadata.put("schemaVersion", "1.0");
        metadata.put("mode", request.mode().name());
        metadata.put("totalCases", request.totalCases());
        metadata.put("configDigest", safeConfig.originalDigest());
        auditService.append(
                snapshot.workspaceId(), normalizeActor(actorId), "TEST_RUN_REGISTERED", "TEST_RUN", runId,
                null, digest(metadata), metadata
        );
        return new TestRunPersistenceDto.Registered(
                runId,
                TestRunStatus.QUEUED,
                "/api/v1/test-runs/" + runId,
                "/api/v1/test-runs/" + runId + "/events"
        );
    }

    @Transactional
    public TestRunDto.Projection updateStatus(
            UUID runId,
            TestRunPersistenceDto.StatusRequest request,
            String actorId
    ) {
        if (request == null || request.status() == null) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "status is required");
        }
        RunMutationSnapshot current = lockRun(runId);
        if (current.status().isTerminal()) {
            throw new BusinessException(ErrorCode.INVALID_STATE_TRANSITION, "Terminal TestRun is immutable");
        }
        if (request.status() != current.status()
                && !RUN_TRANSITIONS.getOrDefault(current.status(), Set.of()).contains(request.status())) {
            throw new BusinessException(
                    ErrorCode.INVALID_STATE_TRANSITION,
                    "Invalid TestRun transition " + current.status() + " -> " + request.status()
            );
        }
        requireBoundaryEvent(request.status(), current.latestEventType());
        int completedCases = request.completedCases() == null
                ? current.completedCases() : request.completedCases();
        int operationalErrors = request.operationalErrorCount() == null
                ? current.operationalErrorCount() : request.operationalErrorCount();
        if (completedCases < 0 || completedCases > current.totalCases() || operationalErrors < 0) {
            throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    "Run counters must be non-negative and completedCases must not exceed totalCases"
            );
        }
        requireTerminalCounters(request.status(), completedCases, operationalErrors, current);
        JsonNode summary = request.summary() == null
                ? current.summary()
                : redactionService.redact(request.summary()).redacted();
        String beforeDigest = digest(runStateDocument(
                current.status(), current.completedCases(), current.operationalErrorCount(), current.summary()
        ));
        try {
            jdbcTemplate.update("""
                    update test_runs
                       set status = ?, completed_cases = ?, operational_error_count = ?, summary_json = ?::jsonb,
                           started_at = case when ? = 'RUNNING' then coalesce(started_at, now()) else started_at end,
                           cancel_requested_at = case when ? = 'CANCELLING'
                                                      then coalesce(cancel_requested_at, now())
                                                      else cancel_requested_at end,
                           completed_at = case when ? in ('COMPLETED', 'FAILED', 'CANCELLED')
                                               then coalesce(completed_at, now()) else completed_at end,
                           updated_at = now()
                     where id = ?
                    """,
                    request.status().name(),
                    completedCases,
                    operationalErrors,
                    json(summary),
                    request.status().name(),
                    request.status().name(),
                    request.status().name(),
                    runId
            );
        } catch (DataIntegrityViolationException exception) {
            throw new BusinessException(ErrorCode.RESOURCE_CONFLICT, "TestRun status update was rejected");
        }
        String afterDigest = digest(runStateDocument(
                request.status(), completedCases, operationalErrors, summary
        ));
        ObjectNode metadata = objectMapper.createObjectNode();
        metadata.put("schemaVersion", "1.0");
        metadata.put("fromStatus", current.status().name());
        metadata.put("toStatus", request.status().name());
        auditService.append(
                current.workspaceId(), normalizeActor(actorId), "TEST_RUN_STATUS_UPDATED", "TEST_RUN", runId,
                beforeDigest, afterDigest, metadata
        );
        return projectionService.find(runId);
    }

    @Transactional
    public TestRunPersistenceDto.CaseRun registerCase(
            UUID runId,
            TestRunPersistenceDto.CaseRunRegisterRequest request,
            String actorId
    ) {
        if (request == null || request.testCaseId() == null || request.trialIndex() < 0) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "testCaseId and non-negative trialIndex are required");
        }
        requireHash(request.variantHash(), "variantHash");
        RunMutationSnapshot run = lockRun(runId);
        if (run.status().isTerminal()) {
            throw new BusinessException(ErrorCode.INVALID_STATE_TRANSITION, "Terminal TestRun cannot add CaseRuns");
        }
        UUID caseRunId = UuidV7.generate();
        try {
            jdbcTemplate.update("""
                    insert into test_case_runs
                        (id, test_run_id, test_case_id, trial_index, status, variant_hash)
                    values (?, ?, ?, ?, 'PENDING', ?)
                    """, caseRunId, runId, request.testCaseId(), request.trialIndex(), request.variantHash());
        } catch (DataIntegrityViolationException exception) {
            throw new BusinessException(ErrorCode.RESOURCE_CONFLICT, "TestCaseRun registration was rejected");
        }
        ObjectNode metadata = objectMapper.createObjectNode();
        metadata.put("schemaVersion", "1.0");
        metadata.put("runId", runId.toString());
        metadata.put("trialIndex", request.trialIndex());
        auditService.append(
                run.workspaceId(), normalizeActor(actorId), "TEST_CASE_RUN_REGISTERED", "TEST_CASE_RUN", caseRunId,
                null, request.variantHash(), metadata
        );
        return findCase(caseRunId);
    }

    @Transactional
    public TestRunPersistenceDto.CaseRun updateCaseStatus(
            UUID runId,
            UUID caseRunId,
            TestRunPersistenceDto.CaseRunStatusRequest request,
            String actorId
    ) {
        if (request == null || request.status() == null) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "CaseRun status is required");
        }
        CaseMutationSnapshot current = lockCase(runId, caseRunId);
        if (TERMINAL_CASE_STATUSES.contains(current.status())) {
            throw new BusinessException(ErrorCode.INVALID_STATE_TRANSITION, "Terminal TestCaseRun is immutable");
        }
        if (request.status() != current.status()
                && !CASE_TRANSITIONS.getOrDefault(current.status(), Set.of()).contains(request.status())) {
            throw new BusinessException(
                    ErrorCode.INVALID_STATE_TRANSITION,
                    "Invalid TestCaseRun transition " + current.status() + " -> " + request.status()
            );
        }
        String securityOutcome = request.securityOutcome() == null
                ? current.securityOutcome()
                : safeOptionalCode(request.securityOutcome(), "securityOutcome", 40);
        String functionalOutcome = request.functionalOutcome() == null
                ? current.functionalOutcome()
                : safeOptionalCode(request.functionalOutcome(), "functionalOutcome", 40);
        Long latencyMs = request.latencyMs() == null ? current.latencyMs() : request.latencyMs();
        if (latencyMs != null && latencyMs < 0) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "latencyMs must be non-negative");
        }
        JsonNode tokenUsage = request.tokenUsage() == null
                ? current.tokenUsage() : redactionService.redact(request.tokenUsage()).redacted();
        JsonNode result = request.result() == null
                ? current.result() : redactionService.redact(request.result()).redacted();
        String errorCode = request.errorCode() == null ? current.errorCode() : safeCode(request.errorCode());
        String beforeDigest = digest(caseStateDocument(
                current.status(), current.securityOutcome(), current.functionalOutcome(), current.latencyMs(),
                current.tokenUsage(), current.errorCode(), current.result()
        ));
        try {
            jdbcTemplate.update("""
                    update test_case_runs
                       set status = ?, security_outcome = ?, functional_outcome = ?, latency_ms = ?,
                           token_usage_json = ?::jsonb, error_code = ?, result_json = ?::jsonb,
                           started_at = case when ? = 'EXECUTING'
                                               then coalesce(started_at, now()) else started_at end,
                           completed_at = case when ? in (
                               'PASSED', 'FAILED_SECURITY', 'FAILED_FUNCTIONAL', 'ERROR', 'CANCELLED'
                           ) then coalesce(completed_at, now()) else completed_at end,
                           updated_at = now()
                     where id = ? and test_run_id = ?
                    """,
                    request.status().name(),
                    securityOutcome,
                    functionalOutcome,
                    latencyMs,
                    json(tokenUsage),
                    errorCode,
                    json(result),
                    request.status().name(),
                    request.status().name(),
                    caseRunId,
                    runId
            );
        } catch (DataIntegrityViolationException exception) {
            throw new BusinessException(ErrorCode.RESOURCE_CONFLICT, "TestCaseRun status update was rejected");
        }
        String afterDigest = digest(caseStateDocument(
                request.status(), securityOutcome, functionalOutcome, latencyMs, tokenUsage, errorCode, result
        ));
        ObjectNode metadata = objectMapper.createObjectNode();
        metadata.put("schemaVersion", "1.0");
        metadata.put("runId", runId.toString());
        metadata.put("fromStatus", current.status().name());
        metadata.put("toStatus", request.status().name());
        auditService.append(
                current.workspaceId(), normalizeActor(actorId), "TEST_CASE_RUN_STATUS_UPDATED",
                "TEST_CASE_RUN", caseRunId, beforeDigest, afterDigest, metadata
        );
        return findCase(caseRunId);
    }

    public TestRunPersistenceDto.CaseRun findCase(UUID caseRunId) {
        List<TestRunPersistenceDto.CaseRun> cases = jdbcTemplate.query("""
                select id, test_run_id, test_case_id, trial_index, status, security_outcome,
                       functional_outcome, variant_hash, latency_ms, token_usage_json::text,
                       error_code, result_json::text
                  from test_case_runs where id = ?
                """, (resultSet, rowNumber) -> new TestRunPersistenceDto.CaseRun(
                        resultSet.getObject("id", UUID.class),
                        resultSet.getObject("test_run_id", UUID.class),
                        resultSet.getObject("test_case_id", UUID.class),
                        resultSet.getInt("trial_index"),
                        TestCaseRunStatus.valueOf(resultSet.getString("status")),
                        resultSet.getString("security_outcome"),
                        resultSet.getString("functional_outcome"),
                        resultSet.getString("variant_hash"),
                        resultSet.getObject("latency_ms", Long.class),
                        parseJson(resultSet.getString("token_usage_json")),
                        resultSet.getString("error_code"),
                        parseJson(resultSet.getString("result_json"))
                ), caseRunId);
        if (cases.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "TestCaseRun not found");
        }
        return cases.getFirst();
    }

    private RunMutationSnapshot lockRun(UUID runId) {
        List<RunMutationSnapshot> runs = jdbcTemplate.query("""
                select agent.workspace_id, run.status, run.total_cases, run.completed_cases,
                       run.operational_error_count, run.summary_json::text, event.event_type,
                       counts.materialized_cases, counts.terminal_cases, counts.error_cases
                  from test_runs run
                  join agent_releases release on release.id = run.release_id
                  join agents agent on agent.id = release.agent_id
                  left join lateral (
                      select event_type from execution_events
                       where run_id = run.id order by sequence desc limit 1
                  ) event on true
                  left join lateral (
                      select count(*)::integer materialized_cases,
                             count(*) filter (where status in (
                                 'PASSED', 'FAILED_SECURITY', 'FAILED_FUNCTIONAL', 'ERROR', 'CANCELLED'
                             ))::integer terminal_cases,
                             count(*) filter (where status = 'ERROR')::integer error_cases
                        from test_case_runs where test_run_id = run.id
                  ) counts on true
                 where run.id = ?
                 for update of run
                """, (resultSet, rowNumber) -> new RunMutationSnapshot(
                        resultSet.getObject("workspace_id", UUID.class),
                        TestRunStatus.valueOf(resultSet.getString("status")),
                        resultSet.getInt("total_cases"),
                        resultSet.getInt("completed_cases"),
                        resultSet.getInt("operational_error_count"),
                        parseJson(resultSet.getString("summary_json")),
                        resultSet.getString("event_type") == null
                                ? null : ExecutionEventType.valueOf(resultSet.getString("event_type")),
                        resultSet.getInt("materialized_cases"),
                        resultSet.getInt("terminal_cases"),
                        resultSet.getInt("error_cases")
                ), runId);
        if (runs.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "TestRun not found");
        }
        return runs.getFirst();
    }

    private CaseMutationSnapshot lockCase(UUID runId, UUID caseRunId) {
        List<CaseMutationSnapshot> cases = jdbcTemplate.query("""
                select agent.workspace_id, case_run.status, case_run.security_outcome,
                       case_run.functional_outcome, case_run.latency_ms,
                       case_run.token_usage_json::text, case_run.error_code,
                       case_run.result_json::text, run.status run_status
                  from test_case_runs case_run
                  join test_runs run on run.id = case_run.test_run_id
                  join agent_releases release on release.id = run.release_id
                  join agents agent on agent.id = release.agent_id
                 where case_run.id = ? and run.id = ?
                 for update of run, case_run
                """, (resultSet, rowNumber) -> {
                    TestRunStatus runStatus = TestRunStatus.valueOf(resultSet.getString("run_status"));
                    if (runStatus.isTerminal()) {
                        throw new BusinessException(
                                ErrorCode.INVALID_STATE_TRANSITION,
                                "Terminal TestRun cannot update CaseRuns"
                        );
                    }
                    return new CaseMutationSnapshot(
                            resultSet.getObject("workspace_id", UUID.class),
                            TestCaseRunStatus.valueOf(resultSet.getString("status")),
                            resultSet.getString("security_outcome"),
                            resultSet.getString("functional_outcome"),
                            resultSet.getObject("latency_ms", Long.class),
                            parseJson(resultSet.getString("token_usage_json")),
                            resultSet.getString("error_code"),
                            parseJson(resultSet.getString("result_json"))
                    );
                }, caseRunId, runId);
        if (cases.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "TestCaseRun not found for TestRun");
        }
        return cases.getFirst();
    }

    private void requireBoundaryEvent(TestRunStatus status, ExecutionEventType latestEventType) {
        ExecutionEventType required = switch (status) {
            case CANCELLING, CANCELLED -> ExecutionEventType.RUN_CANCEL_REQUESTED;
            case COMPLETED -> ExecutionEventType.RUN_COMPLETED;
            case FAILED -> ExecutionEventType.RUN_FAILED;
            default -> null;
        };
        if (required != null && latestEventType != required) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    status + " requires " + required + " to be committed first"
            );
        }
    }

    private ObjectNode runStateDocument(
            TestRunStatus status,
            int completedCases,
            int operationalErrors,
            JsonNode summary
    ) {
        ObjectNode state = objectMapper.createObjectNode();
        state.put("schemaVersion", "1.0");
        state.put("status", status.name());
        state.put("completedCases", completedCases);
        state.put("operationalErrorCount", operationalErrors);
        state.set("summary", summary);
        return state;
    }

    private ObjectNode caseStateDocument(
            TestCaseRunStatus status,
            String securityOutcome,
            String functionalOutcome,
            Long latencyMs,
            JsonNode tokenUsage,
            String errorCode,
            JsonNode result
    ) {
        ObjectNode state = objectMapper.createObjectNode();
        state.put("schemaVersion", "1.0");
        state.put("status", status.name());
        putTextOrNull(state, "securityOutcome", securityOutcome);
        putTextOrNull(state, "functionalOutcome", functionalOutcome);
        if (latencyMs == null) {
            state.putNull("latencyMs");
        } else {
            state.put("latencyMs", latencyMs);
        }
        state.set("tokenUsage", tokenUsage);
        putTextOrNull(state, "errorCode", errorCode);
        state.set("result", result);
        return state;
    }

    private void requireTerminalCounters(
            TestRunStatus status,
            int completedCases,
            int operationalErrors,
            RunMutationSnapshot current
    ) {
        if (!status.isTerminal()) {
            return;
        }
        if (current.materializedCases() != current.terminalCases()
                || completedCases != current.terminalCases()) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Terminal TestRun requires every materialized CaseRun sealed and counters reconciled"
            );
        }
        if (status == TestRunStatus.COMPLETED && current.materializedCases() != current.totalCases()) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Completed TestRun requires every planned CaseRun materialized"
            );
        }
        if (operationalErrors != current.errorCases()) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "operationalErrorCount must match ERROR CaseRuns"
            );
        }
    }

    private void requireHash(String value, String field) {
        if (value == null || !value.matches("sha256:[0-9a-f]{64}")) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, field + " must be a sha256 digest");
        }
    }

    private void putTextOrNull(ObjectNode object, String field, String value) {
        if (value == null) {
            object.putNull(field);
        } else {
            object.put(field, value);
        }
    }

    private String safeCode(String value) {
        return safeOptionalCode(value, "errorCode", 80);
    }

    private String safeOptionalCode(String value, String field, int maximum) {
        if (value != null && (value.length() > maximum || !value.matches("[A-Z0-9._:-]+"))) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, field + " contains unsupported characters");
        }
        return value;
    }

    private String normalizeActor(String actorId) {
        if (actorId == null || actorId.isBlank()) {
            return "system:orchestrator";
        }
        if (actorId.length() > 120) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "X-Actor-Id exceeds 120 characters");
        }
        return actorId;
    }

    private String digest(JsonNode value) {
        return digestService.sha256(canonicalJsonService.canonicalize(value));
    }

    private String json(JsonNode value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception exception) {
            throw new IllegalArgumentException("TestRun JSON serialization failed", exception);
        }
    }

    private JsonNode parseJson(String value) {
        try {
            return objectMapper.readTree(value);
        } catch (Exception exception) {
            throw new IllegalStateException("Stored TestRun JSON is invalid", exception);
        }
    }

    private record RegistrationSnapshot(
            UUID workspaceId,
            String agentFingerprint,
            String releaseFingerprint,
            String releaseState,
            String fixtureVersion,
            String suiteStatus
    ) {
    }

    private record RunMutationSnapshot(
            UUID workspaceId,
            TestRunStatus status,
            int totalCases,
            int completedCases,
            int operationalErrorCount,
            JsonNode summary,
            ExecutionEventType latestEventType,
            int materializedCases,
            int terminalCases,
            int errorCases
    ) {
    }

    private record CaseMutationSnapshot(
            UUID workspaceId,
            TestCaseRunStatus status,
            String securityOutcome,
            String functionalOutcome,
            Long latencyMs,
            JsonNode tokenUsage,
            String errorCode,
            JsonNode result
    ) {
    }
}
