package com.finsecseal.common.api;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import com.finsecseal.agent.AgentService;
import com.finsecseal.release.DigestService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Testcontainers
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
class IdempotencyIntegrationTest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @LocalServerPort
    int port;

    @Autowired
    JdbcTemplate jdbcTemplate;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    DigestService digestService;

    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    @Test
    void replaysSameMutationAndRejectsBodyConflict() throws Exception {
        String key = "agent-create-replay-1";
        String body = """
                {"agentKey":"idempotency-agent","name":"Idempotency Agent","purposeSummary":"test"}
                """;

        HttpResponse<String> first = post(body, key);
        HttpResponse<String> replay = post(body, key);

        assertThat(first.statusCode()).isEqualTo(201);
        assertThat(replay.statusCode()).isEqualTo(201);
        assertThat(replay.body()).isEqualTo(first.body());
        assertThat(replay.headers().firstValue("Idempotent-Replayed")).contains("true");
        assertThat(replay.headers().firstValue("Location"))
                .isEqualTo(first.headers().firstValue("Location"));
        assertThat(replay.headers().firstValue("X-Trace-Id"))
                .isEqualTo(first.headers().firstValue("X-Trace-Id"));
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from agents where agent_key = 'idempotency-agent'",
                Integer.class
        )).isEqualTo(1);

        HttpResponse<String> conflict = post("""
                {"agentKey":"idempotency-agent-other","name":"Other","purposeSummary":"test"}
                """, key);
        JsonNode problem = objectMapper.readTree(conflict.body());
        assertThat(conflict.statusCode()).isEqualTo(409);
        assertThat(problem.path("code").asString()).isEqualTo("IDEMPOTENCY_CONFLICT");
    }

    @Test
    void requiresIdempotencyKeyForMutation() throws Exception {
        HttpRequest request = HttpRequest.newBuilder(endpoint())
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("""
                        {"agentKey":"missing-key-agent","name":"Missing","purposeSummary":"test"}
                        """))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(objectMapper.readTree(response.body()).path("code").asString())
                .isEqualTo("VALIDATION_ERROR");
    }

    @Test
    void processingReservationFailsClosedWithoutRepeatingMutation() throws Exception {
        String body = """
                {"agentKey":"processing-agent","name":"Processing","purposeSummary":"test"}
                """;
        String key = "processing-reservation-1";
        jdbcTemplate.update("""
                insert into api_idempotency_records
                    (id, workspace_id, actor_id, http_method, request_path, idempotency_key,
                     request_digest, state, expires_at)
                values (?, ?, 'role-a-test', 'POST', '/api/v1/agents', ?, ?, 'PROCESSING', ?)
                """,
                UUID.fromString("0198f200-0000-7000-8000-000000009001"),
                AgentService.DEMO_WORKSPACE_ID,
                key,
                digestService.sha256(body.getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                java.sql.Timestamp.from(Instant.now().plus(Duration.ofHours(1)))
        );

        HttpResponse<String> response = post(body, key);

        assertThat(response.statusCode()).isEqualTo(409);
        assertThat(objectMapper.readTree(response.body()).path("code").asString())
                .isEqualTo("IDEMPOTENCY_IN_PROGRESS");
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from agents where agent_key = 'processing-agent'",
                Integer.class
        )).isZero();
    }

    private HttpResponse<String> post(String body, String key) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(endpoint())
                .header("Content-Type", "application/json")
                .header("Idempotency-Key", key)
                .header("X-Actor-Id", "role-a-test")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private URI endpoint() {
        return URI.create("http://127.0.0.1:" + port + "/api/v1/agents");
    }
}
