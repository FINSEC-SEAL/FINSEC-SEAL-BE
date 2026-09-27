package com.finsecseal.evidence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.audit.AuditDto;
import com.finsecseal.audit.AuditService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.common.persistence.UuidV7;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
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
import tools.jackson.databind.JsonNode;
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
    CanonicalJsonService canonicalJsonService;

    @Autowired
    DigestService digestService;

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
    void rejectsEveryPublicEventWriteWithoutChangingEvidence() throws Exception {
        Seed seed = seedRun();
        URI eventsUri = URI.create("http://localhost:" + port + "/api/v1/test-runs/" + seed.runId() + "/events");
        HttpClient client = HttpClient.newHttpClient();
        long headBefore = eventService.history(seed.runId(), 0, 100).headSequence();
        int eventsBefore = jdbcTemplate.queryForObject(
                "select count(*) from execution_events where run_id = ?", Integer.class, seed.runId());
        int counterRowsBefore = jdbcTemplate.queryForObject(
                "select count(*) from run_event_counters where run_id = ?", Integer.class, seed.runId());
        assertThat(counterRowsBefore).isZero();
        int outboxBefore = jdbcTemplate.queryForObject(
                "select count(*) from event_outbox where run_id = ?", Integer.class, seed.runId());
        int auditsBefore = jdbcTemplate.queryForObject(
                "select count(*) from audit_records where action = 'EXECUTION_EVENT_APPENDED'",
                Integer.class);
        int idempotencyBefore = jdbcTemplate.queryForObject(
                "select count(*) from api_idempotency_records where request_path = ?",
                Integer.class, eventsUri.getPath());

        for (ExecutionEventType eventType : ExecutionEventType.values()) {
            assertPublicEventPostForbidden(client, eventsUri,
                    "{\"traceId\":\"" + UUID.randomUUID() + "\",\"eventType\":\""
                            + eventType.name() + "\",\"metadata\":{}}");
        }
        assertPublicEventPostForbidden(client, eventsUri,
                "{\"traceId\":\"" + UUID.randomUUID() + "\",\"eventType\":\"FUTURE_EVENT\"}");
        assertPublicEventPostForbidden(client, eventsUri, "{malformed-json");
        String proposal = "{\"traceId\":\"" + UUID.randomUUID() + "\",\"eventType\":\"TOOL_PROPOSED\"}";
        assertPublicEventPostForbidden(client, eventsUri, proposal, "event-forbidden-" + UUID.randomUUID());
        assertPublicEventPostForbidden(client, eventsUri, proposal, "invalid key");

        assertThat(eventService.history(seed.runId(), 0, 100).headSequence()).isEqualTo(headBefore);
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from execution_events where run_id = ?", Integer.class, seed.runId()))
                .isEqualTo(eventsBefore);
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from run_event_counters where run_id = ?", Integer.class, seed.runId()))
                .isEqualTo(counterRowsBefore);
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from event_outbox where run_id = ?", Integer.class, seed.runId()))
                .isEqualTo(outboxBefore);
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from audit_records where action = 'EXECUTION_EVENT_APPENDED'", Integer.class))
                .isEqualTo(auditsBefore);
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from api_idempotency_records where request_path = ?",
                Integer.class, eventsUri.getPath()))
                .isEqualTo(idempotencyBefore);

        ExecutionEventDto.Event internal = eventService.append(seed.runId(),
                new ExecutionEventDto.AppendRequest(null, UUID.randomUUID(), ExecutionEventType.RUN_STARTED,
                        null, null, null, null, null, objectMapper.createObjectNode()), "runtime-b");
        assertThat(internal.sequence()).isEqualTo(1);
        assertThat(jdbcTemplate.queryForObject(
                "select last_sequence from run_event_counters where run_id = ?", Long.class, seed.runId()))
                .isEqualTo(1L);
        HttpResponse<String> history = client.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port
                        + "/api/v1/test-runs/" + seed.runId() + "/event-history"))
                        .GET().build(), HttpResponse.BodyHandlers.ofString());
        assertThat(history.statusCode()).isEqualTo(200);
        assertThat(objectMapper.readTree(history.body()).path("data").path("items").size()).isEqualTo(1);
    }

    private void assertPublicEventPostForbidden(HttpClient client, URI uri, String body) throws Exception {
        assertPublicEventPostForbidden(client, uri, body, null);
    }

    private void assertPublicEventPostForbidden(HttpClient client, URI uri, String body, String idempotencyKey)
            throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                .header("Content-Type", "application/json")
                .header("X-Actor-Id", "runtime-b");
        if (idempotencyKey != null) {
            request.header("Idempotency-Key", idempotencyKey);
        }
        HttpResponse<String> response = client.send(request.POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(403);
        JsonNode problem = objectMapper.readTree(response.body());
        assertThat(problem.path("code").asString()).isEqualTo("EXECUTION_EVENT_INGEST_FORBIDDEN");
        assertThat(problem.path("retryable").isBoolean()).isTrue();
        assertThat(problem.path("retryable").booleanValue()).isFalse();
    }

    @Test
    void keepsIdempotencyAdmissionOnOtherRunMutations() throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        URI startUri = URI.create("http://localhost:" + port + "/api/v1/test-runs");
        HttpResponse<String> missingKey = client.send(HttpRequest.newBuilder(startUri)
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString("{}"))
                        .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(missingKey.statusCode()).isEqualTo(400);
        assertThat(objectMapper.readTree(missingKey.body()).path("code").asString())
                .isEqualTo("VALIDATION_ERROR");

        String key = "run-start-" + UUID.randomUUID();
        HttpResponse<String> admitted = client.send(HttpRequest.newBuilder(startUri)
                        .header("Content-Type", "application/json")
                        .header("Idempotency-Key", key)
                        .POST(HttpRequest.BodyPublishers.ofString("{}"))
                        .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(admitted.statusCode()).isEqualTo(400);
        assertThat(jdbcTemplate.queryForObject("""
                select count(*) from api_idempotency_records
                 where request_path = ? and idempotency_key = ?
                """, Integer.class, startUri.getPath(), key)).isEqualTo(1);

        URI malformedRunEvents = URI.create("http://localhost:" + port
                + "/api/v1/test-runs/not-a-uuid/events");
        HttpResponse<String> malformedPath = client.send(HttpRequest.newBuilder(malformedRunEvents)
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString("{}"))
                        .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(malformedPath.statusCode()).isEqualTo(400);
        assertThat(objectMapper.readTree(malformedPath.body()).path("code").asString())
                .isEqualTo("VALIDATION_ERROR");
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

    @Test
    void browserAfterStartsAtSelectedCursorAndReconnectHeaderTakesPrecedence() throws Exception {
        Seed seed = seedRun();
        UUID traceId = UUID.randomUUID();
        eventService.append(seed.runId(), new ExecutionEventDto.AppendRequest(
                null, traceId, ExecutionEventType.RUN_STARTED, null,
                null, null, null, null, objectMapper.createObjectNode()
        ), "runtime-b");
        eventService.append(seed.runId(), new ExecutionEventDto.AppendRequest(
                null, traceId, ExecutionEventType.MODEL_REQUEST, null,
                null, null, null, null, objectMapper.createObjectNode()
        ), "runtime-b");

        assertThat(firstSseEvent(seed.runId(), "?after=1", null))
                .contains("id:2\n", "event:trace.event")
                .doesNotContain("id:1\n");
        assertThat(firstSseEvent(seed.runId(), "?after=0", "1"))
                .contains("id:2\n", "event:trace.event")
                .doesNotContain("id:1\n");
        assertThat(firstSseEvent(seed.runId(), "", null))
                .contains("id:1\n", "event:run.status");
    }

    @Test
    void rejectsMalformedBrowserCursorBeforeOpeningAStream() throws Exception {
        Seed seed = seedRun();
        String base = "http://localhost:" + port + "/api/v1/test-runs/" + seed.runId() + "/events";
        for (String query : List.of("?after=", "?after=-1", "?after=abc",
                "?after=1&after=2", "?after=9223372036854775808")) {
            HttpResponse<String> response = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(URI.create(base + query))
                            .header("Accept", "text/event-stream")
                            .GET().build(),
                    HttpResponse.BodyHandlers.ofString()
            );
            assertThat(response.statusCode()).as(query).isEqualTo(400);
            assertThat(response.body()).as(query).contains("VALIDATION_ERROR");
        }
        HttpResponse<String> invalidHeader = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(base + "?after=0"))
                        .header("Accept", "text/event-stream")
                        .header("Last-Event-ID", "not-a-sequence")
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString()
        );
        assertThat(invalidHeader.statusCode()).isEqualTo(400);
        assertThat(invalidHeader.body()).contains("VALIDATION_ERROR");
    }

    @Test
    void expiresOldSseCursorWhileKeepingIntactCanonicalHistory() throws Exception {
        Seed seed = seedRun();
        UUID oldEventId = insertOldStartedEvent(seed.runId());
        assertThat(eventService.verifyChain(seed.runId()).valid()).isTrue();
        assertThat(eventService.history(seed.runId(), 0, 10).items())
                .extracting(ExecutionEventDto.Event::eventId)
                .containsExactly(oldEventId);

        String base = "http://localhost:" + port + "/api/v1/test-runs/" + seed.runId();
        HttpResponse<String> canonical = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(base + "/event-history?after=0&limit=10"))
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString()
        );
        assertThat(canonical.statusCode()).isEqualTo(200);
        assertThat(canonical.body()).contains(oldEventId.toString());

        HttpResponse<String> expired = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(base + "/events"))
                        .header("Accept", "text/event-stream")
                        .header("Last-Event-ID", "0")
                        .timeout(Duration.ofSeconds(5))
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString()
        );
        assertThat(expired.statusCode()).isEqualTo(410);
        assertThat(expired.body()).contains("STREAM_CURSOR_EXPIRED");
        HttpResponse<String> expiredQuery = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(base + "/events?after=0"))
                        .header("Accept", "text/event-stream")
                        .timeout(Duration.ofSeconds(5))
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString()
        );
        assertThat(expiredQuery.statusCode()).isEqualTo(410);
        assertThat(expiredQuery.body()).contains("STREAM_CURSOR_EXPIRED");
        assertThat(eventService.streamReplayHistory(seed.runId(), 1, 10).items()).isEmpty();

        Seed newRun = seedRun();
        assertThat(eventService.streamReplayHistory(newRun.runId(), 0, 10).items()).isEmpty();
    }

    @Test
    void streamReplayCountWindowKeepsExactlyTenThousandEvents() {
        assertThat(ExecutionEventService.firstStreamReplaySequence(1L, 10_000, null)).isEqualTo(1);
        assertThat(ExecutionEventService.firstStreamReplaySequence(1L, 10_001, null)).isEqualTo(2);
        assertThat(ExecutionEventService.firstStreamReplaySequence(1L, 10_001, 8_000L)).isEqualTo(8_001);
        assertThat(ExecutionEventService.firstStreamReplaySequence(9_000L, 10_001, null)).isEqualTo(9_000);
        assertThat(ExecutionEventService.firstStreamReplaySequence(null, 0, null)).isEqualTo(1);
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
        assertSqlState("55000", () -> jdbcTemplate.update(
                "delete from audit_records where id = ?",
                auditId
        ));
    }

    @Test
    void redactsAuditMetadataBeforeStorageAndReadback() throws Exception {
        Seed seed = seedRun();
        ObjectNode rawMetadata = objectMapper.createObjectNode()
                .put("accountNumber", "SYNTH-ACCT-9911")
                .put("email", "audit-borrower@example.test")
                .put("customerId", "audit-customer-9911")
                .put("purpose", "integration-check");

        AuditDto.Record appended = auditService.append(
                WORKSPACE_ID, "audit-tester", "METADATA_PRIVACY_CHECK", "TEST_RUN", seed.runId(),
                HASH_A, HASH_B, rawMetadata
        );
        assertThat(appended.afterDigest()).isEqualTo(HASH_B);
        assertThat(appended.actorId()).isEqualTo("audit-tester");
        assertThat(appended.metadata().path("accountNumber").asString()).isEqualTo("[REDACTED:FINANCIAL]");
        assertThat(appended.metadata().path("email").asString()).isEqualTo("[REDACTED:SENSITIVE_PII]");
        String customerToken = appended.metadata().path("customerId").asString();
        assertThat(customerToken).matches("\\[SYNTH_ID:[0-9a-f]{12}]");
        assertThat(appended.metadata().path("purpose").asString()).isEqualTo("integration-check");
        assertThat(rawMetadata.path("accountNumber").asString()).isEqualTo("SYNTH-ACCT-9911");

        String stored = jdbcTemplate.queryForObject(
                "select metadata_json::text from audit_records where id = ?", String.class, appended.id()
        );
        assertThat(stored)
                .contains("[REDACTED:FINANCIAL]", "[REDACTED:SENSITIVE_PII]", customerToken)
                .doesNotContain("SYNTH-ACCT-9911", "audit-borrower@example.test", "audit-customer-9911");
        assertThat(jdbcTemplate.queryForObject(
                "select after_digest from audit_records where id = ?", String.class, appended.id()
        )).isEqualTo(HASH_B);
        AuditDto.Record found = auditService.find("TEST_RUN", seed.runId(), 25).stream()
                .filter(record -> record.id().equals(appended.id()))
                .findFirst().orElseThrow();
        assertThat(found.metadata()).isEqualTo(appended.metadata());
        assertThat(found.afterDigest()).isEqualTo(HASH_B);

        HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + port
                        + "/api/v1/audit-records?resourceType=TEST_RUN&resourceId=" + seed.runId()))
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString()
        );
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body())
                .doesNotContain("SYNTH-ACCT-9911", "audit-borrower@example.test", "audit-customer-9911");
        JsonNode httpRecord = null;
        for (JsonNode candidate : objectMapper.readTree(response.body()).path("data")) {
            if (appended.id().toString().equals(candidate.path("id").asString())) {
                httpRecord = candidate;
                break;
            }
        }
        assertThat(httpRecord).isNotNull();
        assertThat(httpRecord.path("metadata")).isEqualTo(appended.metadata());
        assertThat(httpRecord.path("afterDigest").asString()).isEqualTo(HASH_B);

        AuditDto.Record empty = auditService.append(
                WORKSPACE_ID, "audit-tester", "METADATA_NULL_CHECK", "TEST_RUN", seed.runId(),
                null, null, null
        );
        assertThat(empty.metadata().isObject()).isTrue();
        assertThat(empty.metadata().isEmpty()).isTrue();
        assertThat(jdbcTemplate.queryForObject(
                "select metadata_json::text from audit_records where id = ?", String.class, empty.id()
        )).isEqualTo("{}");
    }

    @Test
    void rejectsSecretAuditMetadataAndActorBeforeInsertion() {
        Seed seed = seedRun();
        ObjectNode secretMetadata = objectMapper.createObjectNode()
                .put("clientSecret", "audit-secret-canary");
        assertThatThrownBy(() -> auditService.append(
                WORKSPACE_ID, "audit-tester", "PRIVACY_REJECTED", "TEST_RUN", seed.runId(),
                null, null, secretMetadata
        )).isInstanceOfSatisfying(BusinessException.class, exception -> {
            assertThat(exception.errorCode()).isEqualTo(ErrorCode.SECRET_DETECTED);
            assertThat(exception.getMessage()).doesNotContain("audit-secret-canary");
        });
        String secretActor = "Bearer audit-actor-secret-canary";
        assertThatThrownBy(() -> auditService.append(
                WORKSPACE_ID, secretActor, "PRIVACY_REJECTED", "TEST_RUN", seed.runId(),
                null, null, objectMapper.createObjectNode()
        )).isInstanceOfSatisfying(BusinessException.class, exception -> {
            assertThat(exception.errorCode()).isEqualTo(ErrorCode.SECRET_DETECTED);
            assertThat(exception.getMessage()).doesNotContain(secretActor);
        });
        assertThat(jdbcTemplate.queryForObject("""
                select count(*) from audit_records
                 where action = 'PRIVACY_REJECTED' and resource_id = ?
                """, Integer.class, seed.runId())).isZero();
    }

    @Test
    void rejectsForeignWorkspaceSuiteBeforeRunInsertWhileKeepingDatabaseScopeGuard() {
        Seed seed = seedRun();
        UUID releaseId = jdbcTemplate.queryForObject(
                "select release_id from test_runs where id = ?", UUID.class, seed.runId()
        );
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from test_runs where id = ?", Integer.class, seed.runId()
        )).isEqualTo(1);

        UUID foreignWorkspace = UUID.randomUUID();
        UUID foreignSuite = UuidV7.generate();
        jdbcTemplate.update(
                "insert into workspaces (id, name, mode) values (?, ?, 'DEMO')",
                foreignWorkspace, "Foreign Run Suite " + foreignSuite
        );
        jdbcTemplate.update("""
                insert into test_suites
                    (id, workspace_id, suite_key, version, fixture_version, generation_config_json,
                     suite_hash, status)
                values (?, ?, ?, '1.0.0', 'foreign-v1', '{}'::jsonb, ?, 'BUILDING')
                """, foreignSuite, foreignWorkspace, "foreign-suite-" + foreignSuite, HASH_A);
        jdbcTemplate.update("update test_suites set status = 'READY' where id = ?", foreignSuite);

        int runsBefore = jdbcTemplate.queryForObject(
                "select count(*) from test_runs where release_id = ?", Integer.class, releaseId
        );
        int auditsBefore = jdbcTemplate.queryForObject("""
                select count(*) from audit_records
                 where workspace_id = ? and action = 'TEST_RUN_REGISTERED'
                """, Integer.class, WORKSPACE_ID);
        assertThatThrownBy(() -> runPersistenceService.register(
                new TestRunPersistenceDto.RegisterRequest(
                        releaseId, foreignSuite, null, TestRunMode.BASELINE, null,
                        objectMapper.createObjectNode(), HASH_A, HASH_B, 42L, 1
                ),
                "orchestrator-b"
        )).isInstanceOfSatisfying(BusinessException.class, exception -> {
            assertThat(exception.errorCode()).isEqualTo(ErrorCode.RESOURCE_NOT_FOUND);
            assertThat(exception.getMessage())
                    .doesNotContain(foreignSuite.toString(), foreignWorkspace.toString());
        });
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from test_runs where release_id = ?", Integer.class, releaseId
        )).isEqualTo(runsBefore);
        assertThat(jdbcTemplate.queryForObject("""
                select count(*) from audit_records
                 where workspace_id = ? and action = 'TEST_RUN_REGISTERED'
                """, Integer.class, WORKSPACE_ID)).isEqualTo(auditsBefore);

        assertSqlState("23514", () -> jdbcTemplate.update("""
                insert into test_runs
                    (id, release_id, suite_id, mode, status, agent_artifact_fingerprint,
                     release_fingerprint, config_json, fixture_version, fixture_digest,
                     model_config_hash, total_cases)
                select ?, release_id, ?, mode, 'QUEUED', agent_artifact_fingerprint,
                       release_fingerprint, '{}'::jsonb, fixture_version, fixture_digest,
                       model_config_hash, 1
                  from test_runs where id = ?
                """, UuidV7.generate(), foreignSuite, seed.runId()));
    }

    private String firstSseEvent(UUID runId, String query, String lastEventId) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(
                        "http://localhost:" + port + "/api/v1/test-runs/" + runId + "/events" + query))
                .header("Accept", "text/event-stream")
                .timeout(Duration.ofSeconds(5));
        if (lastEventId != null) {
            request.header("Last-Event-ID", lastEventId);
        }
        HttpResponse<java.io.InputStream> response = HttpClient.newHttpClient().send(
                request.GET().build(), HttpResponse.BodyHandlers.ofInputStream()
        );
        assertThat(response.statusCode()).isEqualTo(200);
        StringBuilder first = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(response.body()))) {
            for (int lines = 0; lines < 12; lines++) {
                String line = reader.readLine();
                if (line == null) {
                    break;
                }
                first.append(line).append('\n');
                if (line.startsWith("data:")) {
                    break;
                }
            }
        }
        return first.toString();
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

    private UUID insertOldStartedEvent(UUID runId) {
        UUID eventId = UuidV7.generate();
        UUID traceId = UUID.randomUUID();
        Instant occurredAt = Instant.now().minus(Duration.ofDays(8)).truncatedTo(ChronoUnit.MICROS);
        ObjectNode canonical = objectMapper.createObjectNode();
        canonical.put("schemaVersion", "1.0");
        canonical.put("eventId", eventId.toString());
        canonical.put("traceId", traceId.toString());
        canonical.put("runId", runId.toString());
        canonical.putNull("testCaseRunId");
        canonical.put("sequence", 1);
        canonical.put("occurredAt", occurredAt.toString());
        canonical.put("eventType", "RUN_STARTED");
        canonical.putNull("toolName");
        canonical.putNull("input");
        canonical.putNull("output");
        canonical.put("payloadDigest", HASH_A);
        canonical.putNull("policyDecision");
        canonical.putNull("reasonCode");
        canonical.set("metadata", objectMapper.createObjectNode());
        String eventHash = digestService.sha256(canonicalJsonService.canonicalize(canonical));
        jdbcTemplate.update("""
                insert into execution_events
                    (id, workspace_id, run_id, trace_id, sequence, occurred_at, event_type,
                     payload_digest, metadata_json, event_hash)
                values (?, ?, ?, ?, 1, ?, 'RUN_STARTED', ?, '{}'::jsonb, ?)
                """, eventId, WORKSPACE_ID, runId, traceId, Timestamp.from(occurredAt), HASH_A, eventHash);
        return eventId;
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
