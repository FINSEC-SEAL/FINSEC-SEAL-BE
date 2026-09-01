package com.finsecseal.evidence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.audit.AuditService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.RepeatedTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class EventEvidenceIntegrationTest {

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
    EvidenceReferenceService evidenceReferenceService;

    @Autowired
    AuditService auditService;

    @Autowired
    EventOutboxPublisher outboxPublisher;

    @LocalServerPort
    int port;

    @Test
    void persistsRedactsChainsAuditsAndSealsExecutionEvidence() {
        Seed seed = seedRun();
        UUID traceId = UUID.randomUUID();
        ObjectNode sensitiveInput = objectMapper.createObjectNode();
        sensitiveInput.put("customerId", "customer-raw-1001");
        sensitiveInput.put("email", "borrower@example.test");
        sensitiveInput.put("accountNumber", "123-456-7890");

        ExecutionEventDto.Event started = eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        null,
                        traceId,
                        ExecutionEventType.RUN_STARTED,
                        null,
                        sensitiveInput,
                        null,
                        null,
                        "BASELINE",
                        objectMapper.createObjectNode().put("phase", "BASELINE")
                ),
                "runtime-b"
        );

        assertThat(started.sequence()).isEqualTo(1);
        assertThat(started.input().path("customerId").asString())
                .startsWith("[SYNTH_ID:")
                .doesNotContain("customer-raw-1001");
        assertThat(started.input().path("email").asString()).isEqualTo("[REDACTED:SENSITIVE_PII]");
        assertThat(started.input().path("accountNumber").asString()).isEqualTo("[REDACTED:FINANCIAL]");
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from event_outbox where event_id = ?",
                Integer.class,
                started.eventId()
        )).isEqualTo(1);
        outboxPublisher.publishPending();
        assertThat(jdbcTemplate.queryForObject(
                "select published_at is not null from event_outbox where event_id = ?",
                Boolean.class,
                started.eventId()
        )).isTrue();
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from audit_records where resource_type = 'EXECUTION_EVENT' and resource_id = ?",
                Integer.class,
                started.eventId()
        )).isEqualTo(1);

        ObjectNode secret = objectMapper.createObjectNode();
        secret.put("authorization", "Bearer should-never-be-stored");
        assertThatThrownBy(() -> eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        null, traceId, ExecutionEventType.MODEL_REQUEST, null,
                        null, null, null, null, secret
                ),
                "runtime-b"
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.errorCode()).isEqualTo(ErrorCode.SECRET_DETECTED));
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from execution_events where run_id = ?",
                Integer.class,
                seed.runId()
        )).isEqualTo(1);

        ExecutionEventDto.Event modelRequest = eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        null,
                        traceId,
                        ExecutionEventType.MODEL_REQUEST,
                        null,
                        objectMapper.createObjectNode().put("customerId", "customer-raw-1001"),
                        null,
                        null,
                        null,
                        objectMapper.createObjectNode().put("provider", "synthetic")
                ),
                "runtime-b"
        );
        assertThat(modelRequest.sequence()).isEqualTo(2);
        assertThat(modelRequest.prevEventHash()).isEqualTo(started.eventHash());
        assertThat(eventService.verifyChain(seed.runId()).valid()).isTrue();

        EvidenceReferenceDto.Reference evidence = evidenceReferenceService.append(
                new EvidenceReferenceDto.AppendRequest(
                        "EXECUTION_EVENT",
                        modelRequest.eventId(),
                        "MODEL_REQUEST_DIGEST",
                        modelRequest.eventId(),
                        objectMapper.createObjectNode()
                                .put("customerId", "customer-raw-1001")
                                .put("email", "borrower@example.test"),
                        modelRequest.occurredAt()
                ),
                "runtime-b"
        );
        assertThat(evidence.redactedSummary().toString())
                .doesNotContain("customer-raw-1001")
                .doesNotContain("borrower@example.test");
        assertThat(evidenceReferenceService.find("EXECUTION_EVENT", modelRequest.eventId()).items())
                .hasSize(1);
        assertThat(auditService.find("EVIDENCE_REFERENCE", evidence.id(), 25)).hasSize(1);

        assertThatThrownBy(() -> runPersistenceService.updateStatus(
                seed.runId(),
                new TestRunPersistenceDto.StatusRequest(TestRunStatus.FAILED, 0, 0, null),
                "orchestrator-b"
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE));

        runPersistenceService.updateStatus(
                seed.runId(),
                new TestRunPersistenceDto.StatusRequest(TestRunStatus.PREPARING, 0, 0, null),
                "orchestrator-b"
        );
        runPersistenceService.updateStatus(
                seed.runId(),
                new TestRunPersistenceDto.StatusRequest(TestRunStatus.RUNNING, 0, 0, null),
                "orchestrator-b"
        );
        TestRunPersistenceDto.CaseRun caseRun = runPersistenceService.registerCase(
                seed.runId(),
                new TestRunPersistenceDto.CaseRunRegisterRequest(seed.caseId(), 0, HASH_A),
                "orchestrator-b"
        );
        runPersistenceService.updateCaseStatus(
                seed.runId(),
                caseRun.id(),
                new TestRunPersistenceDto.CaseRunStatusRequest(
                        TestCaseRunStatus.PASSED,
                        "NORMAL_SUCCESS",
                        "NORMAL_SUCCESS",
                        12L,
                        objectMapper.createObjectNode().put("totalTokens", 10),
                        null,
                        objectMapper.createObjectNode().put("result", "ok")
                ),
                "orchestrator-b"
        );
        assertThatThrownBy(() -> runPersistenceService.updateCaseStatus(
                seed.runId(),
                caseRun.id(),
                new TestRunPersistenceDto.CaseRunStatusRequest(
                        TestCaseRunStatus.PASSED, null, null, null, null, null, null
                ),
                "orchestrator-b"
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.errorCode()).isEqualTo(ErrorCode.INVALID_STATE_TRANSITION));
        ExecutionEventDto.Event completedEvent = eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        caseRun.id(), traceId, ExecutionEventType.RUN_COMPLETED, null,
                        null, null, null, "COMPLETED",
                        objectMapper.createObjectNode().put("completed", 1).put("total", 1)
                ),
                "orchestrator-b"
        );
        TestRunDto.Projection completed = runPersistenceService.updateStatus(
                seed.runId(),
                new TestRunPersistenceDto.StatusRequest(
                        TestRunStatus.COMPLETED,
                        1,
                        0,
                        objectMapper.createObjectNode().put("eventHeadHash", completedEvent.eventHash())
                ),
                "orchestrator-b"
        );
        assertThat(completed.status()).isEqualTo(TestRunStatus.COMPLETED);
        assertThat(completed.eventHeadHash()).isEqualTo(completedEvent.eventHash());
        assertThatThrownBy(() -> eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        null, traceId, ExecutionEventType.MODEL_RESPONSE, null,
                        null, null, null, null, objectMapper.createObjectNode()
                ),
                "runtime-b"
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.errorCode()).isEqualTo(ErrorCode.INVALID_STATE_TRANSITION));
    }

    @Test
    void replaysSseFromLastEventIdWithoutRawSensitiveValues() throws Exception {
        Seed seed = seedRun();
        UUID traceId = UUID.randomUUID();
        eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        null, traceId, ExecutionEventType.RUN_STARTED, null,
                        null, null, null, null, objectMapper.createObjectNode()
                ),
                "runtime-b"
        );
        eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        null, traceId, ExecutionEventType.MODEL_REQUEST, null,
                        objectMapper.createObjectNode().put("customerId", "sse-raw-customer"),
                        null, null, null, objectMapper.createObjectNode()
                ),
                "runtime-b"
        );

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/v1/test-runs/" + seed.runId() + "/events"))
                .header("Accept", "text/event-stream")
                .header("Last-Event-ID", "1")
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();
        HttpResponse<java.io.InputStream> response = HttpClient.newHttpClient().send(
                request,
                HttpResponse.BodyHandlers.ofInputStream()
        );
        StringBuilder replay = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(response.body()))) {
            for (int lines = 0; lines < 12; lines++) {
                String line = reader.readLine();
                if (line == null) {
                    break;
                }
                replay.append(line).append('\n');
                if (line.startsWith("data:")) {
                    break;
                }
            }
        }

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("content-type").orElse(""))
                .startsWith("text/event-stream");
        assertThat(response.headers().firstValue("cache-control")).contains("no-cache");
        assertThat(replay.toString())
                .contains("id:2")
                .contains("event:trace.event")
                .contains("[SYNTH_ID:")
                .doesNotContain("id:1\n")
                .doesNotContain("sse-raw-customer");
    }

    @RepeatedTest(10)
    void serializesConcurrentAppendsAndDetectsAStoredHashMismatch() throws Exception {
        Seed concurrentSeed = seedRun();
        UUID traceId = UUID.randomUUID();
        eventService.append(
                concurrentSeed.runId(),
                new ExecutionEventDto.AppendRequest(
                        null, traceId, ExecutionEventType.RUN_STARTED, null,
                        null, null, null, null, objectMapper.createObjectNode()
                ),
                "runtime-b"
        );
        CountDownLatch start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(() -> {
                start.await();
                return eventService.append(
                        concurrentSeed.runId(),
                        new ExecutionEventDto.AppendRequest(
                                null, traceId, ExecutionEventType.MODEL_REQUEST, null,
                                objectMapper.createObjectNode().put("request", 1),
                                null, null, null, objectMapper.createObjectNode()
                        ),
                        "runtime-b"
                );
            });
            var second = executor.submit(() -> {
                start.await();
                return eventService.append(
                        concurrentSeed.runId(),
                        new ExecutionEventDto.AppendRequest(
                                null, traceId, ExecutionEventType.MODEL_RESPONSE, null,
                                null, objectMapper.createObjectNode().put("response", 1),
                                null, null, objectMapper.createObjectNode()
                        ),
                        "runtime-b"
                );
            });
            start.countDown();
            List<Long> sequences = List.of(
                    first.get(5, TimeUnit.SECONDS).sequence(),
                    second.get(5, TimeUnit.SECONDS).sequence()
            );
            assertThat(sequences).containsExactlyInAnyOrder(2L, 3L);
        }
        assertThat(eventService.verifyChain(concurrentSeed.runId()).valid()).isTrue();

        Seed tamperedSeed = seedRun();
        assertSqlState("23514", () -> jdbcTemplate.update("""
                insert into execution_events
                    (id, workspace_id, run_id, trace_id, sequence, occurred_at, event_type,
                     payload_digest, metadata_json, event_hash)
                values (?, ?, ?, ?, 1, now(), 'MODEL_REQUEST', ?, '{}'::jsonb, ?)
                """, UUID.randomUUID(), WORKSPACE_ID, tamperedSeed.runId(), UUID.randomUUID(), HASH_A, HASH_B));
        jdbcTemplate.update("""
                insert into execution_events
                    (id, workspace_id, run_id, trace_id, sequence, occurred_at, event_type,
                     payload_digest, metadata_json, event_hash)
                values (?, ?, ?, ?, 1, now(), 'RUN_STARTED', ?, '{}'::jsonb, ?)
                """, UUID.randomUUID(), WORKSPACE_ID, tamperedSeed.runId(), UUID.randomUUID(), HASH_A, HASH_B);

        ExecutionEventDto.ChainVerification verification = eventService.verifyChain(tamperedSeed.runId());
        assertThat(verification.valid()).isFalse();
        assertThat(verification.firstInvalidSequence()).isEqualTo(1L);
    }

    @Test
    void enforcesOutboxIdentityAndAuditWorkspaceScope() {
        Seed seed = seedRun();
        ExecutionEventDto.Event event = eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        null, UUID.randomUUID(), ExecutionEventType.RUN_STARTED, null,
                        null, null, null, null, objectMapper.createObjectNode()
                ),
                "runtime-b"
        );
        assertSqlState("55000", () -> jdbcTemplate.update(
                "update event_outbox set sequence = 999 where event_id = ?",
                event.eventId()
        ));

        UUID secondWorkspace = UUID.randomUUID();
        jdbcTemplate.update(
                "insert into workspaces (id, name, mode) values (?, 'Other Workspace', 'DEMO')",
                secondWorkspace
        );
        assertSqlState("23514", () -> jdbcTemplate.update("""
                insert into audit_records
                    (id, workspace_id, actor_id, action, resource_type, resource_id,
                     metadata_json, occurred_at)
                values (?, ?, 'tester', 'WRONG_SCOPE', 'EXECUTION_EVENT', ?, '{}'::jsonb, now())
                """, UUID.randomUUID(), secondWorkspace, event.eventId()));
        UUID auditId = jdbcTemplate.queryForObject("""
                select id from audit_records
                 where resource_type = 'EXECUTION_EVENT' and resource_id = ?
                """, UUID.class, event.eventId());
        assertSqlState("55000", () -> jdbcTemplate.update(
                "update audit_records set action = 'MUTATED' where id = ?",
                auditId
        ));
    }

    private Seed seedRun() {
        UUID agentId = UUID.randomUUID();
        UUID releaseId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        UUID caseId = UUID.randomUUID();
        String keySuffix = agentId.toString().substring(0, 8);
        jdbcTemplate.update("""
                insert into agents
                    (id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'Evidence Agent', 'Evidence integration test', 'ACTIVE')
                """, agentId, WORKSPACE_ID, "evidence-agent-" + keySuffix);
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
                """, suiteId, WORKSPACE_ID, "evidence-suite-" + keySuffix, HASH_B);
        jdbcTemplate.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name, category, severity,
                     delivery_channel, payload_hash, preconditions_json, expected_invariant,
                     oracle_type, generation_source, expected_result_json, trial_policy_json)
                values (?, ?, 'case-1', 'NORMAL', 'NORMAL', 'NORMAL', 'LOW', 'DIRECT', ?,
                        '{}'::jsonb, 'INV-NORMAL', 'NORMAL_TASK', 'CURATED', '{}'::jsonb, '{}'::jsonb)
                """, caseId, suiteId, HASH_A);
        jdbcTemplate.update("update test_suites set status = 'READY' where id = ?", suiteId);
        TestRunPersistenceDto.Registered registered = runPersistenceService.register(
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
        return new Seed(registered.runId(), caseId);
    }

    private record Seed(UUID runId, UUID caseId) {
    }

    private void assertSqlState(String expected, Runnable operation) {
        assertThatThrownBy(operation::run)
                .rootCause()
                .isInstanceOfSatisfying(java.sql.SQLException.class, exception ->
                        assertThat(exception.getSQLState()).isEqualTo(expected));
    }
}
