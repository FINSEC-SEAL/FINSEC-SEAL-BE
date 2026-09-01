package com.finsecseal.common.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.agent.AgentService;
import com.finsecseal.release.DigestService;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
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
import tools.jackson.databind.node.ObjectNode;

@Testcontainers
@SpringBootTest(
        webEnvironment = WebEnvironment.RANDOM_PORT,
        properties = "finsec.idempotency.recovery-key=role-a-operator-recovery-key-32-bytes"
)
class IdempotencyRecoveryIntegrationTest {

    private static final String RECOVERY_KEY = "role-a-operator-recovery-key-32-bytes";

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
    void releaseRequiresOperatorCredentialAndAllowsVerifiedOriginalRetry() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String originalKey = "recover-release-" + suffix;
        String originalBody = """
                {"agentKey":"recovered-agent-%s","name":"Recovered","purposeSummary":"test"}
                """.formatted(suffix);
        UUID recordId = seedExpired(originalKey, originalBody);
        ObjectNode recovery = recoveryRequest(originalKey, originalBody, "RELEASE", null);

        HttpResponse<String> pending = getPending();
        assertThat(pending.statusCode()).isEqualTo(200);
        assertThat(objectMapper.readTree(pending.body()).path("data"))
                .anySatisfy(item -> assertThat(item.path("idempotencyRecordId").asString())
                        .isEqualTo(recordId.toString()));

        HttpResponse<String> unauthorized = postRecovery(
                recovery,
                "recovery-auth-fail-" + suffix,
                "wrong-operator-recovery-key-value"
        );
        assertThat(unauthorized.statusCode()).isEqualTo(403);
        assertThat(recordCount(recordId)).isEqualTo(1);

        HttpResponse<String> recovered = postRecovery(
                recovery,
                "recovery-release-command-" + suffix,
                RECOVERY_KEY
        );
        assertThat(recovered.statusCode()).isEqualTo(201);
        assertThat(objectMapper.readTree(recovered.body()).at("/data/stateAfterRecovery").asString())
                .isEqualTo("RELEASED");
        assertThat(recordCount(recordId)).isZero();
        UUID recoveryId = UUID.fromString(
                objectMapper.readTree(recovered.body()).at("/data/id").asString()
        );
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from audit_records where resource_type = 'IDEMPOTENCY_RECOVERY' and resource_id = ?",
                Integer.class,
                recoveryId
        )).isEqualTo(1);
        assertSqlState("55000", () -> jdbcTemplate.update(
                "update idempotency_recoveries set recovered_by = 'tampered' where id = ?",
                recoveryId
        ));

        HttpResponse<String> retried = postOriginal(originalBody, originalKey);
        assertThat(retried.statusCode()).isEqualTo(201);
        assertThat(retried.headers().firstValue("Idempotent-Replayed")).isEmpty();
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from agents where agent_key = ?",
                Integer.class,
                "recovered-agent-" + suffix
        )).isEqualTo(1);
    }

    @Test
    void completeRegistersVerifiedResponseAndReplaysWithoutRepeatingMutation() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String originalKey = "recover-complete-" + suffix;
        String originalBody = """
                {"agentKey":"already-created-%s","name":"Already Created","purposeSummary":"test"}
                """.formatted(suffix);
        UUID recordId = seedExpired(originalKey, originalBody);
        UUID responseTraceId = UUID.randomUUID();
        String verifiedBody = "{\"operatorVerified\":true}";
        ObjectNode completion = objectMapper.createObjectNode()
                .put("status", 201)
                .put("contentType", "application/json")
                .put("location", "/api/v1/agents/operator-confirmed")
                .put("traceId", responseTraceId.toString())
                .put("bodyBase64", Base64.getEncoder().encodeToString(
                        verifiedBody.getBytes(StandardCharsets.UTF_8)
                ));
        ObjectNode recovery = recoveryRequest(originalKey, originalBody, "COMPLETE", completion);

        HttpResponse<String> recovered = postRecovery(
                recovery,
                "recovery-complete-command-" + suffix,
                RECOVERY_KEY
        );
        assertThat(recovered.statusCode()).isEqualTo(201);
        assertThat(objectMapper.readTree(recovered.body()).at("/data/stateAfterRecovery").asString())
                .isEqualTo("COMPLETED");
        assertThat(jdbcTemplate.queryForObject(
                "select state from api_idempotency_records where id = ?",
                String.class,
                recordId
        )).isEqualTo("COMPLETED");

        HttpResponse<String> replay = postOriginal(originalBody, originalKey);
        assertThat(replay.statusCode()).isEqualTo(201);
        assertThat(replay.body()).isEqualTo(verifiedBody);
        assertThat(replay.headers().firstValue("Idempotent-Replayed")).contains("true");
        assertThat(replay.headers().firstValue("X-Trace-Id")).contains(responseTraceId.toString());
        assertThat(replay.headers().firstValue("Location"))
                .contains("/api/v1/agents/operator-confirmed");
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from agents where agent_key = ?",
                Integer.class,
                "already-created-" + suffix
        )).isZero();
    }

    private UUID seedExpired(String key, String body) {
        UUID id = UUID.randomUUID();
        jdbcTemplate.update("""
                insert into api_idempotency_records
                    (id, workspace_id, actor_id, http_method, request_path, idempotency_key,
                     request_digest, state, expires_at)
                values (?, ?, 'role-a-test', 'POST', '/api/v1/agents', ?, ?, 'PROCESSING', ?)
                """,
                id,
                AgentService.DEMO_WORKSPACE_ID,
                key,
                semanticRequestDigest(body),
                java.sql.Timestamp.from(Instant.now().minusSeconds(60))
        );
        return id;
    }

    private ObjectNode recoveryRequest(
            String key,
            String body,
            String resolution,
            ObjectNode completedResponse
    ) {
        ObjectNode request = objectMapper.createObjectNode()
                .put("actorId", "role-a-test")
                .put("httpMethod", "POST")
                .put("requestPath", "/api/v1/agents")
                .put("idempotencyKey", key)
                .put("requestDigest", semanticRequestDigest(body))
                .put("resolution", resolution)
                .put("verificationReference", "ops:incident/FINSEC-2026-0001");
        if (completedResponse != null) {
            request.set("completedResponse", completedResponse);
        }
        return request;
    }

    private HttpResponse<String> postRecovery(ObjectNode body, String key, String recoveryKey) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(
                        URI.create("http://127.0.0.1:" + port + "/api/v1/platform/idempotency-recoveries")
                )
                .header("Content-Type", "application/json")
                .header("Idempotency-Key", key)
                .header("X-Actor-Id", "operator:platform")
                .header("X-Operator-Recovery-Key", recoveryKey)
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(body)))
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> getPending() throws Exception {
        HttpRequest request = HttpRequest.newBuilder(
                        URI.create("http://127.0.0.1:" + port
                                + "/api/v1/platform/idempotency-recoveries/pending")
                )
                .header("X-Actor-Id", "operator:platform")
                .header("X-Operator-Recovery-Key", RECOVERY_KEY)
                .GET()
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> postOriginal(String body, String key) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(
                        URI.create("http://127.0.0.1:" + port + "/api/v1/agents")
                )
                .header("Content-Type", "application/json")
                .header("Idempotency-Key", key)
                .header("X-Actor-Id", "role-a-test")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private String semanticRequestDigest(String body) {
        String value = body + "\ncontent-type:application/json\nif-match:";
        return digestService.sha256(value.getBytes(StandardCharsets.UTF_8));
    }

    private int recordCount(UUID recordId) {
        return jdbcTemplate.queryForObject(
                "select count(*) from api_idempotency_records where id = ?",
                Integer.class,
                recordId
        );
    }

    private void assertSqlState(String sqlState, SqlAction action) {
        assertThatThrownBy(action::run)
                .rootCause()
                .isInstanceOfSatisfying(SQLException.class, exception ->
                        assertThat(exception.getSQLState()).isEqualTo(sqlState));
    }

    @FunctionalInterface
    private interface SqlAction {
        void run();
    }
}
