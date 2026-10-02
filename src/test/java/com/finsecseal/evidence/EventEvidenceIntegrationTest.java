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
import com.finsecseal.platform.contract.ContractReviewerCredentials;
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

// BEGIN A_SSE_PG_ADDITIVE_IMPORTS
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.sql.DataSource;
import org.mockito.stubbing.Answer;
import org.springframework.aop.support.AopUtils;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.datasource.ConnectionHolder;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
// END A_SSE_PG_ADDITIVE_IMPORTS

// BEGIN A_SSE_HTTP_ADDITIVE_IMPORTS
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.LockSupport;
// END A_SSE_HTTP_ADDITIVE_IMPORTS

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "finsec.contract-access.key=test-reviewer-key-at-least-32-bytes-long",
        "finsec.contract-access.actor=evidence-integration-reviewer",
        "finsec.contract-access.workspace=0198f1e2-0000-7000-8000-000000000001"
})
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
    ContractReviewerCredentials reviewerCredentials;

    @Autowired
    EventOutboxPublisher outboxPublisher;

    @LocalServerPort
    int port;

    // BEGIN A_SSE_PG_ADDITIVE_FIELDS
    @Autowired
    ExecutionEventStream executionEventStream;

    @Autowired
    PlatformTransactionManager eventTransactions;
    // END A_SSE_PG_ADDITIVE_FIELDS

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
        var reviewerSession = reviewerCredentials.issue();
        String reviewerCookie = ContractReviewerCredentials.COOKIE + "=" + reviewerSession.token();
        URI startUri = URI.create("http://localhost:" + port + "/api/v1/test-runs");
        HttpResponse<String> missingKey = client.send(HttpRequest.newBuilder(startUri)
                        .header("Content-Type", "application/json")
                        .header("Cookie", reviewerCookie)
                        .header("X-CSRF-Token", reviewerSession.csrfToken())
                        .POST(HttpRequest.BodyPublishers.ofString("{}"))
                        .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(missingKey.statusCode()).isEqualTo(400);
        assertThat(objectMapper.readTree(missingKey.body()).path("code").asString())
                .isEqualTo("VALIDATION_ERROR");

        String key = "run-start-" + UUID.randomUUID();
        HttpResponse<String> admitted = client.send(HttpRequest.newBuilder(startUri)
                        .header("Content-Type", "application/json")
                        .header("Cookie", reviewerCookie)
                        .header("X-CSRF-Token", reviewerSession.csrfToken())
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

    // BEGIN A_SSE_PG_ADDITIVE_CONTROLS
    @Test
    void commitsOwnOutboxDeliveryAfterIoDisconnectAndDoesNotRepublishIt() throws Exception {
        Seed seed = seedRun();
        ExecutionEventDto.Event started = appendPgControlEvent(seed, ExecutionEventType.RUN_STARTED);
        PgEvidenceState evidence = pgEvidenceState(seed.runId());
        Map<String, Object> pending = pgOutboxRow(started.eventId());
        assertThat(pending.get("published_at")).isNull();
        SseEmitter first = mock(SseEmitter.class);
        SseEmitter second = mock(SseEmitter.class);
        AtomicReference<SseEmitter> fault = new AtomicReference<>();
        AtomicReference<PgTxObservation> outer = new AtomicReference<>();
        List<ExecutionEventDto.Event> healthy = new ArrayList<>();
        Answer<Void> delivery = invocation -> {
            ExecutionEventDto.Event actual = pgEventFrom(invocation.getArgument(0));
            assertThat(actual).isEqualTo(started);
            assertSamePgTransaction(outer.get(), observePgTransaction());
            SseEmitter emitter = (SseEmitter) invocation.getMock();
            if (fault.compareAndSet(null, emitter)) {
                throw new IOException("owned disconnected subscriber");
            }
            healthy.add(actual);
            return null;
        };
        doAnswer(delivery).when(first).send(any(SseEmitter.SseEventBuilder.class));
        doAnswer(delivery).when(second).send(any(SseEmitter.SseEventBuilder.class));
        try (PgOwnedSubscribers owned = registerPgSubscribers(seed.runId(), first, second)) {
            writablePgTransaction().executeWithoutResult(status -> {
                outer.set(observePgTransaction());
                outboxPublisher.publishPending();
                assertThat(fault.get()).isNotNull();
                assertThat(healthy).containsExactly(started);
                assertThat(owned.emitters()).doesNotContain(fault.get()).hasSize(1);
                assertPgMarked(pending, pgOutboxRow(started.eventId()));
            });
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            assertPgMarked(pending, pgOutboxRow(started.eventId()));
            String committed = pgOutboxWholeRow(started.eventId());
            assertThat(pgEvidenceState(seed.runId())).isEqualTo(evidence);
            outboxPublisher.publishPending();
            assertThat(pgOutboxWholeRow(started.eventId())).isEqualTo(committed);
            assertThat(healthy).containsExactly(started);
            verify(first, times(1)).send(any(SseEmitter.SseEventBuilder.class));
            verify(second, times(1)).send(any(SseEmitter.SseEventBuilder.class));
            verify(first, never()).completeWithError(any());
            verify(second, never()).completeWithError(any());
            printPgControl("normal-io-commit-repeat", seed, started.eventId(), outer.get(), Map.of(
                    "ownSelected", true, "healthyDeliveries", healthy.size(), "ioCompletions", 0,
                    "publishedAttemptsBefore", pending.get("publish_attempts"),
                    "publishedAttemptsAfter", pgOutboxRow(started.eventId()).get("publish_attempts"),
                    "repeatWholeRowUnchanged", true, "evidenceUnchanged", true));
        }
    }

    @Test
    void rollsBackOwnEventAndEveryPendingMarkWhenPublishThrowsRawRuntime() throws Exception {
        assertPgRollbackForRawFault(new IllegalArgumentException("owned raw runtime"));
    }

    @Test
    void rollsBackOwnEventAndEveryPendingMarkWhenPublishThrowsRawError() throws Exception {
        assertPgRollbackForRawFault(new AssertionError("owned raw error"));
    }

    private void assertPgRollbackForRawFault(Throwable fault) throws Exception {
        Seed seed = seedRun();
        ExecutionEventDto.Event started = appendPgControlEvent(seed, ExecutionEventType.RUN_STARTED);
        PgEvidenceState evidence = pgEvidenceState(seed.runId());
        List<String> committedOutbox = pgAllOutboxWholeRows();
        Map<String, Object> pendingStarted = pgOutboxRow(started.eventId());
        assertThat(pendingStarted.get("published_at")).isNull();
        AtomicReference<UUID> newId = new AtomicReference<>();
        AtomicReference<PgTxObservation> outer = new AtomicReference<>();
        AtomicReference<PgTxObservation> callback = new AtomicReference<>();
        AtomicInteger startedSends = new AtomicInteger();
        AtomicInteger faultSends = new AtomicInteger();
        SseEmitter emitter = mock(SseEmitter.class);
        doAnswer(invocation -> {
            ExecutionEventDto.Event event = pgEventFrom(invocation.getArgument(0));
            if (event.eventId().equals(started.eventId())) {
                startedSends.incrementAndGet();
                return null;
            }
            assertThat(event.eventId()).isEqualTo(newId.get());
            assertThat(event.eventType()).isEqualTo(ExecutionEventType.MODEL_REQUEST);
            assertThat(startedSends.get()).isEqualTo(1);
            assertPgMarked(pendingStarted, pgOutboxRow(started.eventId()));
            callback.set(observePgTransaction());
            assertSamePgTransaction(outer.get(), callback.get());
            faultSends.incrementAndGet();
            throw fault;
        }).when(emitter).send(any(SseEmitter.SseEventBuilder.class));
        try (PgOwnedSubscribers owned = registerPgSubscribers(seed.runId(), emitter)) {
            Throwable thrown = catchThrowable(() -> writablePgTransaction().executeWithoutResult(status -> {
                outer.set(observePgTransaction());
                newId.set(appendPgControlEvent(seed, ExecutionEventType.MODEL_REQUEST).eventId());
                outboxPublisher.publishPending();
            }));
            assertThat(thrown).isSameAs(fault);
            assertThat(newId.get()).isNotNull();
            assertThat(faultSends.get()).isEqualTo(1);
            assertThat(callback.get()).isNotNull();
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            assertThat(jdbcTemplate.queryForObject("select count(*) from execution_events where id = ?", Integer.class, newId.get())).isZero();
            assertThat(jdbcTemplate.queryForObject("select count(*) from event_outbox where event_id = ?", Integer.class, newId.get())).isZero();
            assertThat(jdbcTemplate.queryForObject("select count(*) from audit_records where resource_type = 'EXECUTION_EVENT' and resource_id = ?", Integer.class, newId.get())).isZero();
            assertThat(pgEvidenceState(seed.runId())).isEqualTo(evidence);
            assertThat(pgAllOutboxWholeRows()).isEqualTo(committedOutbox);
            verify(emitter, times(2)).send(any(SseEmitter.SseEventBuilder.class));
            verify(emitter, never()).completeWithError(any());
            printPgControl("outer-rollback-" + fault.getClass().getSimpleName(), seed, newId.get(), callback.get(), Map.of(
                    "startedSendBeforeFault", startedSends.get(), "startedMarkedBeforeFault", true,
                    "ownNewFaultCallbacks", faultSends.get(), "sameCallerThrowable", true,
                    "newEventOutboxAuditRows", 0, "committedGlobalRowsRestored", committedOutbox.size(),
                    "ownEvidenceRestored", true));
        }
    }

    private ExecutionEventDto.Event appendPgControlEvent(Seed seed, ExecutionEventType type) {
        return eventService.append(seed.runId(), new ExecutionEventDto.AppendRequest(
                null, UUID.randomUUID(), type, null,
                objectMapper.createObjectNode().put("email", "sse-pg@example.test"), null, null,
                "BASELINE", objectMapper.createObjectNode().put("scope", "A_SSE_PG_TEST")), "runtime-b");
    }

    private TransactionTemplate writablePgTransaction() {
        assertThat(AopUtils.isAopProxy(eventService)).isTrue();
        assertThat(AopUtils.isAopProxy(auditService)).isTrue();
        assertThat(AopUtils.isAopProxy(outboxPublisher)).isTrue();
        TransactionTemplate transaction = new TransactionTemplate(eventTransactions);
        transaction.setReadOnly(false);
        return transaction;
    }

    private PgTxObservation observePgTransaction() {
        assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isTrue();
        assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isTrue();
        assertThat(TransactionSynchronizationManager.isCurrentTransactionReadOnly()).isFalse();
        DataSource dataSource = Objects.requireNonNull(jdbcTemplate.getDataSource());
        return jdbcTemplate.execute((ConnectionCallback<PgTxObservation>) connection -> {
            Object resource = TransactionSynchronizationManager.getResource(dataSource);
            assertThat(resource).isInstanceOf(ConnectionHolder.class);
            Connection bound = ((ConnectionHolder) resource).getConnection();
            Connection target = DataSourceUtils.getTargetConnection(connection);
            assertThat(target).isSameAs(DataSourceUtils.getTargetConnection(bound));
            assertThat(DataSourceUtils.isConnectionTransactional(bound, dataSource)).isTrue();
            assertThat(connection.getAutoCommit()).isFalse();
            assertThat(bound.getAutoCommit()).isFalse();
            int callbackPid = pgBackendPid(connection);
            assertThat(callbackPid).isEqualTo(pgBackendPid(bound));
            return new PgTxObservation(eventTransactions.getClass().getName(),
                    System.identityHashCode(eventTransactions), target, callbackPid);
        });
    }

    private int pgBackendPid(Connection connection) throws SQLException {
        try (var statement = connection.createStatement(); var result = statement.executeQuery("select pg_backend_pid()")) {
            assertThat(result.next()).isTrue();
            return result.getInt(1);
        }
    }

    private void assertSamePgTransaction(PgTxObservation expected, PgTxObservation actual) {
        assertThat(expected).isNotNull();
        assertThat(actual.managerClass()).isEqualTo(expected.managerClass());
        assertThat(actual.managerIdentity()).isEqualTo(expected.managerIdentity());
        assertThat(actual.target()).isSameAs(expected.target());
        assertThat(actual.backendPid()).isEqualTo(expected.backendPid());
    }

    private ExecutionEventDto.Event pgEventFrom(SseEmitter.SseEventBuilder builder) {
        return builder.build().stream().map(SseEmitter.DataWithMediaType::getData)
                .filter(ExecutionEventDto.Event.class::isInstance).map(ExecutionEventDto.Event.class::cast)
                .findFirst().orElseThrow();
    }

    @SuppressWarnings("unchecked")
    private PgOwnedSubscribers registerPgSubscribers(UUID runId, SseEmitter... emitters) {
        ConcurrentMap<UUID, Set<SseEmitter>> subscribers = (ConcurrentMap<UUID, Set<SseEmitter>>)
                ReflectionTestUtils.getField(executionEventStream, "subscribers");
        assertThat(subscribers).isNotNull();
        Set<SseEmitter> owned = ConcurrentHashMap.newKeySet();
        owned.addAll(List.of(emitters));
        assertThat(subscribers.putIfAbsent(runId, owned)).isNull();
        return new PgOwnedSubscribers(runId, subscribers, owned, List.of(emitters));
    }

    private Map<String, Object> pgOutboxRow(UUID eventId) {
        return jdbcTemplate.queryForMap("select * from event_outbox where event_id = ?", eventId);
    }

    private void assertPgMarked(Map<String, Object> before, Map<String, Object> marked) {
        for (String identity : List.of("event_id", "run_id", "sequence", "event_type", "created_at")) {
            assertThat(marked.get(identity)).isEqualTo(before.get(identity));
        }
        assertThat(((Number) marked.get("publish_attempts")).intValue())
                .isEqualTo(((Number) before.get("publish_attempts")).intValue() + 1);
        assertThat(marked.get("last_attempt_at")).isNotNull();
        assertThat(marked.get("published_at")).isNotNull();
    }

    private String pgOutboxWholeRow(UUID eventId) {
        return jdbcTemplate.queryForObject("select row_to_json(outbox)::text from event_outbox outbox where event_id = ?", String.class, eventId);
    }

    private List<String> pgAllOutboxWholeRows() {
        return jdbcTemplate.queryForList("select row_to_json(outbox)::text from event_outbox outbox order by event_id", String.class);
    }

    private PgEvidenceState pgEvidenceState(UUID runId) {
        return new PgEvidenceState(
                jdbcTemplate.queryForList("select row_to_json(event)::text from execution_events event where run_id = ? order by sequence", String.class, runId),
                jdbcTemplate.queryForList("select row_to_json(audit)::text from audit_records audit where resource_type = 'EXECUTION_EVENT' and resource_id in (select id from execution_events where run_id = ?) order by id", String.class, runId),
                jdbcTemplate.queryForList("select row_to_json(counter)::text from run_event_counters counter where run_id = ?", String.class, runId),
                jdbcTemplate.queryForObject("select row_to_json(run)::text from test_runs run where id = ?", String.class, runId),
                eventService.history(runId, 0, 100), eventService.verifyChain(runId));
    }

    private void printPgControl(String control, Seed seed, UUID eventId, PgTxObservation transaction,
                                Map<String, Object> result) throws Exception {
        System.out.println("A_SSE_PG_CONTROL " + objectMapper.writeValueAsString(Map.of(
                "control", control, "runId", seed.runId(), "eventId", eventId,
                "managerClass", transaction.managerClass(), "managerIdentity", transaction.managerIdentity(),
                "targetIdentity", System.identityHashCode(transaction.target()), "backendPid", transaction.backendPid(),
                "activeWritableSameJdbc", true, "result", result)));
    }

    private record PgTxObservation(String managerClass, int managerIdentity, Connection target, int backendPid) {
    }

    private record PgEvidenceState(List<String> events, List<String> audit, List<String> counter,
                                   String run, ExecutionEventDto.History history,
                                   ExecutionEventDto.ChainVerification verification) {
    }

    private record PgOwnedSubscribers(UUID runId, ConcurrentMap<UUID, Set<SseEmitter>> mapping,
                                      Set<SseEmitter> emitters, List<SseEmitter> identities) implements AutoCloseable {
        @Override
        public void close() {
            for (SseEmitter emitter : identities) {
                emitters.remove(emitter);
            }
            if (emitters.isEmpty()) {
                mapping.remove(runId, emitters);
            }
        }
    }
    // END A_SSE_PG_ADDITIVE_CONTROLS
    // BEGIN A_SSE_HTTP_ADDITIVE_CONTROLS
    @Test
    void keepsHealthyHttpReaderLiveAfterDisconnectAndReplaysFromHeaderCursor() throws Exception {
        Seed seed = seedRun();
        ExecutionEventDto.Event started = eventService.append(seed.runId(), new ExecutionEventDto.AppendRequest(
                null, UUID.randomUUID(), ExecutionEventType.RUN_STARTED, null,
                null, null, null, null, objectMapper.createObjectNode()), "runtime-b");
        Map<String, Object> pendingStarted = pgOutboxRow(started.eventId());
        outboxPublisher.publishPending();
        assertPgMarked(pendingStarted, pgOutboxRow(started.eventId()));
        List<HttpFullFrame> observed = new ArrayList<>();
        HttpReaders readers = new HttpReaders();
        try (readers) {
            HttpReader first = readers.open(seed.runId(), "?after=0", null);
            HttpReader healthy = readers.open(seed.runId(), "?after=0", null);
            assertHttpFrame(first.frame(), started, "run.status", observed);
            assertHttpFrame(healthy.frame(), started, "run.status", observed);
            awaitHttpRegistration(seed.runId(), 2, Math.min(first.deadline, healthy.deadline));
            first.closeBodyBeforeDeadline();
            ExecutionEventDto.Event model = eventService.append(seed.runId(), new ExecutionEventDto.AppendRequest(
                    null, UUID.randomUUID(), ExecutionEventType.MODEL_REQUEST, null,
                    objectMapper.createObjectNode().put("customerId", "http-raw-customer"),
                    null, null, null, objectMapper.createObjectNode()), "runtime-b");
            assertThat(model.sequence()).isEqualTo(2);
            assertThat(model.prevEventHash()).isEqualTo(started.eventHash());
            Map<String, Object> pendingModel = pgOutboxRow(model.eventId());
            outboxPublisher.publishPending();
            assertPgMarked(pendingModel, pgOutboxRow(model.eventId()));
            assertHttpFrame(healthy.frame(), model, "trace.event", observed);
            assertThat(observed.getLast().data()).contains("[SYNTH_ID:").doesNotContain("http-raw-customer");
            PgEvidenceState evidence = pgEvidenceState(seed.runId());
            String startedOutbox = pgOutboxWholeRow(started.eventId());
            String outbox = pgOutboxWholeRow(model.eventId());
            HttpReader reconnect = readers.open(seed.runId(), "?after=0", "1");
            assertHttpFrame(reconnect.frame(), model, "trace.event", observed);
            assertThat(pgEvidenceState(seed.runId())).isEqualTo(evidence);
            assertThat(pgOutboxWholeRow(model.eventId())).isEqualTo(outbox);
            assertThat(pgOutboxWholeRow(started.eventId())).isEqualTo(startedOutbox);
            assertThat(eventService.verifyChain(seed.runId()).valid()).isTrue();
        }
        assertThat(readers.terminated).isTrue();
        System.out.println("A_SSE_HTTP_CONTROL " + objectMapper.writeValueAsString(Map.of(
                "control", "twoReadersDisconnectHealthyHeaderReplay", "runId", seed.runId(),
                "frames", observed, "initialRegistration", 2, "closedBodies", readers.closedBodies.get(),
                "executorTerminated", readers.terminated, "ownMarked", true, "replayEvidenceUnchanged", true)));
    }

    @Test
    void recoversExpiredHttpCursorThroughHistoryAndReceivesNextLiveHeadFrame() throws Exception {
        Seed seed = seedRun();
        UUID oldId = insertOldStartedEvent(seed.runId());
        HttpReaders readers = new HttpReaders();
        List<HttpFullFrame> observed = new ArrayList<>();
        long head;
        try (readers) {
            HttpResponse<String> expired = readers.rest(seed.runId(), "/events?after=0");
            assertThat(expired.statusCode()).isEqualTo(410);
            assertThat(expired.body()).contains("STREAM_CURSOR_EXPIRED");
            assertThat(httpRegistrations(seed.runId())).isEmpty();
            HttpResponse<String> historyResponse = readers.rest(seed.runId(), "/event-history?after=0&limit=10");
            assertThat(historyResponse.statusCode()).isEqualTo(200);
            JsonNode history = objectMapper.readTree(historyResponse.body()).path("data");
            ExecutionEventDto.Event old = eventService.history(seed.runId(), 0, 10).items().getFirst();
            assertThat(old.eventId()).isEqualTo(oldId);
            assertThat(history.path("items")).isEqualTo(objectMapper.readTree(objectMapper.writeValueAsString(List.of(old))));
            head = history.path("headSequence").asLong();
            assertThat(head).isEqualTo(old.sequence()).isEqualTo(1);
            assertThat(history.has("nextCursor")).isTrue();
            assertThat(history.path("nextCursor").isNull()).isTrue();
            HttpResponse<String> verifyResponse = readers.rest(seed.runId(), "/events:verify");
            assertThat(verifyResponse.statusCode()).isEqualTo(200);
            JsonNode verification = objectMapper.readTree(verifyResponse.body()).path("data");
            assertThat(verification.path("valid").asBoolean()).isTrue();
            assertThat(verification.path("headHash").asString()).isEqualTo(old.eventHash());
            Map<String, Object> pendingOld = pgOutboxRow(oldId);
            outboxPublisher.publishPending();
            assertPgMarked(pendingOld, pgOutboxRow(oldId));
            HttpReader recovered = readers.open(seed.runId(), "?after=" + head, null);
            awaitHttpRegistration(seed.runId(), 1, recovered.deadline);
            ExecutionEventDto.Event model = eventService.append(seed.runId(), new ExecutionEventDto.AppendRequest(
                    null, UUID.randomUUID(), ExecutionEventType.MODEL_REQUEST, null,
                    null, null, null, null, objectMapper.createObjectNode()), "runtime-b");
            assertThat(model.sequence()).isEqualTo(head + 1);
            assertThat(model.prevEventHash()).isEqualTo(old.eventHash());
            Map<String, Object> pendingModel = pgOutboxRow(model.eventId());
            outboxPublisher.publishPending();
            assertPgMarked(pendingModel, pgOutboxRow(model.eventId()));
            assertHttpFrame(recovered.frame(), model, "trace.event", observed);
            HttpResponse<String> extendedHistory = readers.rest(seed.runId(), "/event-history?after=" + head + "&limit=10");
            assertThat(extendedHistory.statusCode()).isEqualTo(200);
            JsonNode extended = objectMapper.readTree(extendedHistory.body()).path("data");
            assertThat(extended.path("items")).isEqualTo(objectMapper.readTree(objectMapper.writeValueAsString(List.of(model))));
            assertThat(extended.path("headSequence").asLong()).isEqualTo(model.sequence());
            assertThat(extended.path("nextCursor").isNull()).isTrue();
            assertThat(eventService.history(seed.runId(), 0, 10).items().getFirst()).isEqualTo(old);
            HttpResponse<String> extendedVerify = readers.rest(seed.runId(), "/events:verify");
            assertThat(extendedVerify.statusCode()).isEqualTo(200);
            JsonNode chain = objectMapper.readTree(extendedVerify.body()).path("data");
            assertThat(chain.path("valid").asBoolean()).isTrue();
            assertThat(chain.path("headHash").asString()).isEqualTo(model.eventHash());
        }
        assertThat(readers.terminated).isTrue();
        System.out.println("A_SSE_HTTP_CONTROL " + objectMapper.writeValueAsString(Map.of(
                "control", "expiredHistoryHeadReconnectLive", "runId", seed.runId(), "oldEventId", oldId,
                "historyHead", head, "frames", observed, "closedBodies", readers.closedBodies.get(),
                "executorTerminated", readers.terminated, "expiredStatus", 410, "oldAndNewOwnMarked", true)));
    }

    private void assertHttpFrame(HttpFullFrame actual, ExecutionEventDto.Event expected, String event,
                                 List<HttpFullFrame> observed) throws Exception {
        assertThat(actual.id()).isEqualTo(Long.toString(expected.sequence()));
        assertThat(actual.event()).isEqualTo(event);
        assertThat(objectMapper.readTree(actual.data())).isEqualTo(objectMapper.readTree(objectMapper.writeValueAsString(expected)));
        observed.add(actual);
    }

    @SuppressWarnings("unchecked")
    private Set<SseEmitter> httpRegistrations(UUID runId) {
        ConcurrentMap<UUID, Set<SseEmitter>> mapping = (ConcurrentMap<UUID, Set<SseEmitter>>)
                ReflectionTestUtils.getField(executionEventStream, "subscribers");
        assertThat(mapping).isNotNull();
        Set<SseEmitter> registered = mapping.get(runId);
        return registered == null ? Set.of() : Set.copyOf(registered);
    }

    private void awaitHttpRegistration(UUID runId, int count, long deadline) throws Exception {
        while (httpRegistrations(runId).size() != count) {
            LockSupport.parkNanos(Math.min(TimeUnit.MILLISECONDS.toNanos(5), httpRemaining(deadline)));
        }
        httpRemaining(deadline);
    }

    private long httpRemaining(long deadline) throws java.util.concurrent.TimeoutException {
        long remaining = deadline - System.nanoTime();
        if (remaining <= 0) {
            throw new java.util.concurrent.TimeoutException("Owned HTTP deadline expired");
        }
        return remaining;
    }

    private record HttpFullFrame(String id, String event, String data) {
    }

    private final class HttpReaders implements AutoCloseable {
        final HttpClient client = HttpClient.newHttpClient();
        final ExecutorService executor = Executors.newCachedThreadPool();
        final List<HttpReader> readers = new ArrayList<>();
        final List<Future<?>> frameTasks = new ArrayList<>();
        final AtomicInteger closedBodies = new AtomicInteger();
        boolean terminated;

        HttpReader open(UUID runId, String query, String lastEventId) {
            HttpReader reader = new HttpReader(this, runId, query, lastEventId);
            readers.add(reader);
            return reader;
        }

        HttpResponse<String> rest(UUID runId, String suffix) throws Exception {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            CompletableFuture<HttpResponse<String>> response = client.sendAsync(HttpRequest.newBuilder(
                    URI.create("http://localhost:" + port + "/api/v1/test-runs/" + runId + suffix))
                    .timeout(Duration.ofSeconds(5)).GET().build(), HttpResponse.BodyHandlers.ofString());
            try {
                return response.get(httpRemaining(deadline), TimeUnit.NANOSECONDS);
            } finally {
                response.cancel(true);
            }
        }

        @Override
        public void close() throws Exception {
            long cleanupDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            try {
                for (HttpReader reader : readers) {
                    reader.closed.set(true);
                    reader.response.cancel(true);
                }
                for (HttpReader reader : readers) {
                    reader.admitted.get(httpRemaining(cleanupDeadline), TimeUnit.NANOSECONDS);
                    reader.scheduleBodyClose();
                }
                for (Future<?> task : frameTasks) {
                    task.cancel(true);
                }
                for (HttpReader reader : readers) {
                    Future<?> close = reader.bodyClose.get();
                    if (close != null) {
                        close.get(httpRemaining(cleanupDeadline), TimeUnit.NANOSECONDS);
                    }
                }
            } finally {
                executor.shutdownNow();
                terminated = executor.awaitTermination(httpRemaining(cleanupDeadline), TimeUnit.NANOSECONDS);
                assertThat(terminated).isTrue();
            }
        }
    }

    private final class HttpReader {
        final HttpReaders owner;
        final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        final AtomicBoolean closed = new AtomicBoolean();
        final AtomicBoolean closeScheduled = new AtomicBoolean();
        final AtomicReference<InputStream> body = new AtomicReference<>();
        final AtomicReference<Future<?>> bodyClose = new AtomicReference<>();
        final CompletableFuture<Void> admitted = new CompletableFuture<>();
        final CompletableFuture<HttpResponse<InputStream>> response;
        BufferedReader lines;

        HttpReader(HttpReaders owner, UUID runId, String query, String lastEventId) {
            this.owner = owner;
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(
                    "http://localhost:" + port + "/api/v1/test-runs/" + runId + "/events" + query))
                    .timeout(Duration.ofSeconds(5)).header("Accept", "text/event-stream");
            if (lastEventId != null) {
                request.header("Last-Event-ID", lastEventId);
            }
            response = owner.client.sendAsync(request.GET().build(), HttpResponse.BodyHandlers.ofInputStream());
            response.whenComplete((actual, failure) -> {
                try {
                    if (actual != null) {
                        body.set(actual.body());
                        if (closed.get()) {
                            scheduleBodyClose();
                        }
                    }
                    admitted.complete(null);
                } catch (RuntimeException exception) {
                    admitted.completeExceptionally(exception);
                }
            });
        }

        void scheduleBodyClose() {
            InputStream owned = body.get();
            if (owned != null && closeScheduled.compareAndSet(false, true)) {
                bodyClose.set(owner.executor.submit(() -> {
                    try {
                        owned.close();
                        owner.closedBodies.incrementAndGet();
                    } catch (IOException exception) {
                        throw new UncheckedIOException(exception);
                    }
                }));
            }
        }

        void closeBodyBeforeDeadline() throws Exception {
            closed.set(true);
            response.cancel(true);
            admitted.get(httpRemaining(deadline), TimeUnit.NANOSECONDS);
            scheduleBodyClose();
            assertThat(bodyClose.get()).isNotNull();
            bodyClose.get().get(httpRemaining(deadline), TimeUnit.NANOSECONDS);
        }

        HttpFullFrame frame() throws Exception {
            HttpResponse<InputStream> actual = response.get(httpRemaining(deadline), TimeUnit.NANOSECONDS);
            admitted.get(httpRemaining(deadline), TimeUnit.NANOSECONDS);
            assertThat(actual.statusCode()).isEqualTo(200);
            assertThat(actual.headers().firstValue("content-type").orElse("")).startsWith("text/event-stream");
            assertThat(actual.headers().firstValue("cache-control")).contains("no-cache");
            assertThat(body.get()).isSameAs(actual.body());
            if (lines == null) {
                lines = new BufferedReader(new InputStreamReader(body.get(), StandardCharsets.UTF_8));
            }
            Future<HttpFullFrame> next = owner.executor.submit(() -> {
                String id = null;
                String event = null;
                String data = null;
                for (int count = 0; count < 64; count++) {
                    String line = lines.readLine();
                    if (line == null) {
                        throw new IOException("EOF before complete owned SSE frame");
                    }
                    if (line.isEmpty()) {
                        if (id == null && event == null && data == null) {
                            continue;
                        }
                        if (id == null || event == null || data == null) {
                            throw new IOException("Incomplete owned SSE frame");
                        }
                        return new HttpFullFrame(id, event, data);
                    }
                    if (line.startsWith("id:")) {
                        id = line.substring(3).stripLeading();
                    } else if (line.startsWith("event:")) {
                        event = line.substring(6).stripLeading();
                    } else if (line.startsWith("data:")) {
                        if (data != null || line.length() > 65536) {
                            throw new IOException("Unexpected owned SSE data shape");
                        }
                        data = line.substring(5).stripLeading();
                    }
                }
                throw new IOException("No complete owned SSE frame within line bound");
            });
            owner.frameTasks.add(next);
            return next.get(httpRemaining(deadline), TimeUnit.NANOSECONDS);
        }
    }
    // END A_SSE_HTTP_ADDITIVE_CONTROLS
}
