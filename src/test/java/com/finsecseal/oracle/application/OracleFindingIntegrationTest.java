package com.finsecseal.oracle.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.finding.FindingService;
import com.finsecseal.oracle.domain.CustomerDataRow;
import com.finsecseal.oracle.domain.CustomerResponseEvidence;
import com.finsecseal.oracle.domain.HighImpactMutationEvidence;
import com.finsecseal.oracle.domain.LoanDecisionSnapshot;
import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleReasonCode;
import com.finsecseal.oracle.domain.OracleResult;
import com.finsecseal.oracle.evaluator.CrossCustomerOracle;
import com.finsecseal.oracle.evaluator.HighImpactMutationOracle;
import java.time.Instant;
import java.util.List;
import java.util.Map;
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
class OracleFindingIntegrationTest {

    private static final String HASH_A = "sha256:" + "a".repeat(64);
    private static final String HASH_B = "sha256:" + "b".repeat(64);
    private static final UUID WORKSPACE_ID = UUID.fromString("0198f1e2-0000-7000-8000-000000000001");

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired
    JdbcTemplate jdbcTemplate;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    TestRunPersistenceService runPersistenceService;

    @Autowired
    ExecutionEventService eventService;

    @Autowired
    OracleAssessmentService assessmentService;

    @Autowired
    OracleResultService oracleResultService;

    @Autowired
    FindingService findingService;

    @Test
    void recordsAttackSuccessFindingAndCausalEvents() {
        Seed seed = seedRunningAttack("success", false);
        OracleResult result = successfulCrossCustomerResult();

        OracleAssessmentService.Assessment assessment = assessmentService.record(
                seed.runId(),
                seed.caseRunId(),
                seed.traceId(),
                seed.sourceEventId(),
                result,
                "role-d"
        );

        assertThat(assessment.created()).isTrue();
        assertThat(assessment.oracleResult().outcome()).isEqualTo(OracleOutcome.ATTACK_SUCCESS);
        assertThat(assessment.finding()).isNotNull();
        assertThat(assessment.finding().category()).isEqualTo("FA-02");
        assertThat(assessment.finding().severity()).isEqualTo("HIGH");
        assertThat(assessment.finding().status()).isEqualTo("OPEN");
        assertThat(assessment.finding().violatedInvariant()).isEqualTo("INV-01");

        assertThat(oracleResultService.findByRun(seed.runId(), seed.caseRunId()).items())
                .singleElement()
                .satisfies(stored -> {
                    assertThat(stored.sourceEventId()).isEqualTo(seed.sourceEventId());
                    assertThat(stored.reasonCode())
                            .isEqualTo(OracleReasonCode.UNAUTHORIZED_RECORD_RETURNED);
                });
        assertThat(findingService.findByRun(seed.runId()).items())
                .singleElement()
                .satisfies(finding -> assertThat(finding.sourceOracleResultId())
                        .isEqualTo(assessment.oracleResult().id()));

        List<String> eventTypes = jdbcTemplate.queryForList("""
                select event_type from execution_events
                 where run_id = ? order by sequence
                """, String.class, seed.runId());
        assertThat(eventTypes).containsExactly(
                "RUN_STARTED", "TOOL_RESPONSE", "ORACLE_EVALUATED", "FINDING_CREATED"
        );
        assertThat(jdbcTemplate.queryForObject("""
                select count(*) from audit_records
                 where resource_type in ('ORACLE_RESULT', 'FINDING')
                   and resource_id in (?, ?)
                """, Integer.class, assessment.oracleResult().id(), assessment.finding().id()))
                .isEqualTo(2);
    }

    @Test
    void recordsBlockedResultWithoutCreatingFinding() {
        Seed seed = seedRunningAttack("blocked", true);
        OracleResult result = new CrossCustomerOracle().evaluate(new CustomerResponseEvidence(
                "CUST-1001", false, false, true, true, null, List.of()
        ));

        OracleAssessmentService.Assessment assessment = assessmentService.record(
                seed.runId(), seed.caseRunId(), seed.traceId(), seed.sourceEventId(), result, "role-d"
        );

        assertThat(assessment.oracleResult().outcome()).isEqualTo(OracleOutcome.ATTACK_BLOCKED);
        assertThat(assessment.finding()).isNull();
        assertThat(findingService.findByRun(seed.runId()).items()).isEmpty();
        assertThat(jdbcTemplate.queryForList("""
                select event_type from execution_events
                 where run_id = ? order by sequence
                """, String.class, seed.runId())).containsExactly(
                "RUN_STARTED", "POLICY_EVALUATED", "ORACLE_EVALUATED"
        );
    }

    @Test
    void retriesSameEvaluationWithoutDuplicateRowsOrEvents() {
        Seed seed = seedRunningAttack("retry", false);
        OracleResult result = successfulCrossCustomerResult();

        OracleAssessmentService.Assessment first = assessmentService.record(
                seed.runId(), seed.caseRunId(), seed.traceId(), seed.sourceEventId(), result, "role-d"
        );
        OracleAssessmentService.Assessment retried = assessmentService.record(
                seed.runId(), seed.caseRunId(), seed.traceId(), seed.sourceEventId(), result, "role-d"
        );

        assertThat(first.created()).isTrue();
        assertThat(retried.created()).isFalse();
        assertThat(retried.oracleResult().id()).isEqualTo(first.oracleResult().id());
        assertThat(retried.finding().id()).isEqualTo(first.finding().id());
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from oracle_results where test_case_run_id = ?",
                Integer.class,
                seed.caseRunId()
        )).isEqualTo(1);
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from findings where source_oracle_result_id = ?",
                Integer.class,
                first.oracleResult().id()
        )).isEqualTo(1);
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from execution_events where run_id = ?",
                Integer.class,
                seed.runId()
        )).isEqualTo(4);
    }

    @Test
    void rejectsConflictingRetryForSameOracleIdentity() {
        Seed seed = seedRunningAttack("conflict", false);
        OracleResult success = successfulCrossCustomerResult();
        assessmentService.record(
                seed.runId(), seed.caseRunId(), seed.traceId(), seed.sourceEventId(), success, "role-d"
        );
        OracleResult blocked = new CrossCustomerOracle().evaluate(new CustomerResponseEvidence(
                "CUST-1001",
                true,
                true,
                false,
                true,
                2L,
                List.of(new CustomerDataRow("CUST-1001", Map.of("incomeBand", "MIDDLE")))
        ));

        assertThatThrownBy(() -> assessmentService.record(
                seed.runId(), seed.caseRunId(), seed.traceId(), seed.sourceEventId(), blocked, "role-d"
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.errorCode()).isEqualTo(ErrorCode.RESOURCE_CONFLICT));
    }

    private OracleResult successfulCrossCustomerResult() {
        return new CrossCustomerOracle().evaluate(new CustomerResponseEvidence(
                "CUST-1001",
                true,
                true,
                false,
                true,
                2L,
                List.of(
                        new CustomerDataRow("CUST-1001", Map.of("incomeBand", "MIDDLE")),
                        new CustomerDataRow("CUST-1002", Map.of("incomeBand", "HIGH"))
                )
        ));
    }

    @Test
    void rejectsAttackSuccessWithoutToolResponseEvidence() {
        Seed seed = seedRunningAttack("wrong-source", true);

        assertThatThrownBy(() -> assessmentService.record(
                seed.runId(), seed.caseRunId(), seed.traceId(), seed.sourceEventId(),
                successfulCrossCustomerResult(), "role-d"
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE));
    }

    @Test
    void recordsHighImpactMutationFromSandboxStateEvent() {
        Seed seed = seedRunningAttack(
                "high-impact", ExecutionEventType.SANDBOX_STATE_CHANGED,
                "FA-05", "CRITICAL", "LOAN_DECISION_UPDATE", "INV-05", "HIGH_IMPACT_MUTATION"
        );
        Instant beforeAt = Instant.parse("2026-09-01T00:00:00Z");
        OracleResult result = new HighImpactMutationOracle().evaluate(new HighImpactMutationEvidence(
                true,
                false,
                true,
                false,
                new LoanDecisionSnapshot("PENDING", 1, "HUMAN-PENDING", beforeAt),
                new LoanDecisionSnapshot("APPROVED", 2, "AGENT-001", beforeAt.plusSeconds(1)),
                2L
        ));

        OracleAssessmentService.Assessment assessment = assessmentService.record(
                seed.runId(), seed.caseRunId(), seed.traceId(), seed.sourceEventId(), result, "role-d"
        );

        assertThat(assessment.oracleResult().outcome()).isEqualTo(OracleOutcome.ATTACK_SUCCESS);
        assertThat(assessment.finding().category()).isEqualTo("FA-05");
        assertThat(assessment.finding().severity()).isEqualTo("CRITICAL");
        assertThat(assessment.finding().title()).isEqualTo("Human-only loan decision mutated");
    }

    private Seed seedRunningAttack(String suffix, boolean policyDeniedSource) {
        return seedRunningAttack(
                suffix,
                policyDeniedSource ? ExecutionEventType.POLICY_EVALUATED : ExecutionEventType.TOOL_RESPONSE,
                "FA-02",
                "HIGH",
                "CUSTOMER_DATA_READ",
                "INV-01",
                "CROSS_CUSTOMER"
        );
    }

    private Seed seedRunningAttack(
            String suffix,
            ExecutionEventType requestedSourceType,
            String category,
            String severity,
            String targetTool,
            String invariant,
            String oracleType
    ) {
        UUID agentId = UUID.randomUUID();
        UUID releaseId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        UUID testCaseId = UUID.randomUUID();
        String keySuffix = suffix + '-' + agentId.toString().substring(0, 8);
        jdbcTemplate.update("""
                insert into agents
                    (id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'Oracle Agent', 'Oracle integration test', 'ACTIVE')
                """, agentId, WORKSPACE_ID, "oracle-agent-" + keySuffix);
        jdbcTemplate.update("""
                insert into agent_releases
                    (id, agent_id, version, business_purpose, manifest_schema_version, manifest_json,
                     agent_artifact_fingerprint, release_fingerprint, lifecycle_state, effective_status)
                values (?, ?, '1.0.0', 'LOAN_DOCUMENT_COMPLETENESS_REVIEW', '1.0', '{}'::jsonb,
                        ?, ?, 'DRAFT', 'DRAFT')
                """, releaseId, agentId, HASH_A, HASH_A);
        jdbcTemplate.update("""
                update agent_releases set lifecycle_state = 'ANALYZED', effective_status = 'ANALYZED'
                 where id = ?
                """, releaseId);
        jdbcTemplate.update("""
                insert into test_suites
                    (id, workspace_id, suite_key, version, fixture_version, generation_config_json,
                     suite_hash, status)
                values (?, ?, ?, '1.0.0', 'fixture-v1', '{}'::jsonb, ?, 'BUILDING')
                """, suiteId, WORKSPACE_ID, "oracle-suite-" + keySuffix, HASH_B);
        jdbcTemplate.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name, category, severity,
                     delivery_channel, target_tool, payload_hash, preconditions_json,
                     expected_invariant, oracle_type, generation_source,
                     expected_result_json, trial_policy_json)
                values (?, ?, ?, 'ATTACK', 'SEED', ?, ?, 'DIRECT',
                        ?, ?, '{}'::jsonb, ?, ?,
                        'CURATED', '{}'::jsonb, '{}'::jsonb)
                """, testCaseId, suiteId, category.toLowerCase() + '-' + keySuffix,
                category, severity, targetTool, HASH_A, invariant, oracleType);
        jdbcTemplate.update("update test_suites set status = 'READY' where id = ?", suiteId);

        TestRunPersistenceDto.Registered run = runPersistenceService.register(
                new TestRunPersistenceDto.RegisterRequest(
                        releaseId,
                        suiteId,
                        null,
                        TestRunMode.BASELINE,
                        UUID.randomUUID(),
                        objectMapper.createObjectNode().put("schemaVersion", "1.0"),
                        HASH_A,
                        HASH_B,
                        42L,
                        1
                ),
                "orchestrator-b"
        );
        UUID traceId = UUID.randomUUID();
        eventService.append(
                run.runId(),
                new ExecutionEventDto.AppendRequest(
                        null, traceId, ExecutionEventType.RUN_STARTED, null,
                        null, null, null, "BASELINE", objectMapper.createObjectNode()
                ),
                "orchestrator-b"
        );
        runPersistenceService.updateStatus(
                run.runId(),
                new TestRunPersistenceDto.StatusRequest(TestRunStatus.PREPARING, 0, 0, null),
                "orchestrator-b"
        );
        runPersistenceService.updateStatus(
                run.runId(),
                new TestRunPersistenceDto.StatusRequest(TestRunStatus.RUNNING, 0, 0, null),
                "orchestrator-b"
        );
        TestRunPersistenceDto.CaseRun caseRun = runPersistenceService.registerCase(
                run.runId(),
                new TestRunPersistenceDto.CaseRunRegisterRequest(testCaseId, 0, HASH_A),
                "orchestrator-b"
        );
        ObjectNode output = null;
        ObjectNode policyDecision = null;
        ObjectNode metadata = objectMapper.createObjectNode();
        ExecutionEventType sourceType;
        String reasonCode = null;
        if (requestedSourceType == ExecutionEventType.POLICY_EVALUATED) {
            sourceType = requestedSourceType;
            policyDecision = objectMapper.createObjectNode()
                    .put("allowed", false)
                    .put("reasonCode", "CUSTOMER_SCOPE_VIOLATION");
            reasonCode = "CUSTOMER_SCOPE_VIOLATION";
        } else if (requestedSourceType == ExecutionEventType.TOOL_RESPONSE) {
            sourceType = requestedSourceType;
            output = objectMapper.createObjectNode();
            output.put("status", 200);
            output.putArray("rows").addObject()
                    .put("customerId", "CUST-1002")
                    .putObject("fields")
                    .put("incomeBand", "HIGH");
            metadata.put("deliveredToAgent", true);
        } else {
            sourceType = requestedSourceType;
            metadata.put("entityType", "LOAN_DECISION");
            metadata.put("beforeVersion", 1);
            metadata.put("afterVersion", 2);
        }
        ExecutionEventDto.Event sourceEvent = eventService.append(
                run.runId(),
                new ExecutionEventDto.AppendRequest(
                        caseRun.id(), traceId, sourceType,
                        targetTool, null, output, policyDecision, reasonCode, metadata
                ),
                "runtime-b"
        );
        return new Seed(run.runId(), caseRun.id(), traceId, sourceEvent.eventId());
    }

    private record Seed(UUID runId, UUID caseRunId, UUID traceId, UUID sourceEventId) {
    }
}
