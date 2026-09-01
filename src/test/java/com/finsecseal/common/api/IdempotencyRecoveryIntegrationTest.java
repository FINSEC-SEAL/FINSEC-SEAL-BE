package com.finsecseal.common.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.agent.AgentService;
import com.finsecseal.release.CanonicalJsonService;
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

    @Autowired
    CanonicalJsonService canonicalJsonService;

    @Autowired
    IdempotencyInstanceLease instanceLease;

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
        UUID recordId = seedRecoveryRequired(originalKey, originalBody);
        ObjectNode recovery = recoveryRequest(originalKey, originalBody, "RELEASE", null);

        HttpResponse<String> pending = getPending();
        assertThat(pending.statusCode()).isEqualTo(200);
        assertThat(objectMapper.readTree(pending.body()).path("data"))
                .anySatisfy(item -> assertThat(item.path("idempotencyRecordId").asString())
                        .isEqualTo(recordId.toString()));

        String recoveryCommandKey = "recovery-release-command-" + suffix;
        HttpResponse<String> unauthorized = postRecovery(
                recovery,
                recoveryCommandKey,
                "wrong-operator-recovery-key-value"
        );
        assertThat(unauthorized.statusCode()).isEqualTo(403);
        assertThat(recordCount(recordId)).isEqualTo(1);
        assertThat(jdbcTemplate.queryForObject("""
                select count(*) from api_idempotency_records
                 where request_path = '/api/v1/platform/idempotency-recoveries'
                   and idempotency_key = ?
                """, Integer.class, recoveryCommandKey)).isZero();

        HttpResponse<String> recovered = postRecovery(
                recovery,
                recoveryCommandKey,
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
        UUID recordId = seedRecoveryRequired(originalKey, originalBody);
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
        JsonNode recoveryResponse = objectMapper.readTree(recovered.body());
        assertThat(recoveryResponse.at("/data/stateAfterRecovery").asString())
                .isEqualTo("COMPLETED");
        ObjectNode responseEnvelope = objectMapper.createObjectNode()
                .put("status", 201)
                .put("contentType", "application/json")
                .put("location", "/api/v1/agents/operator-confirmed")
                .put("traceId", responseTraceId.toString())
                .put("bodyDigest", digestService.sha256(verifiedBody.getBytes(StandardCharsets.UTF_8)));
        String expectedResponseDigest = digestService.sha256(
                canonicalJsonService.canonicalize(responseEnvelope)
        );
        assertThat(recoveryResponse.at("/data/responseDigest").asString())
                .isEqualTo(expectedResponseDigest)
                .isNotEqualTo(digestService.sha256(verifiedBody.getBytes(StandardCharsets.UTF_8)));
        assertThat(jdbcTemplate.queryForObject(
                "select response_digest from idempotency_recoveries where idempotency_record_id = ?",
                String.class,
                recordId
        )).isEqualTo(expectedResponseDigest);
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

    @Test
    void databaseRejectsForgedRecoveryForActiveOrMismatchedReservation() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String body = "{\"active\":true}";
        UUID activeId = seedProcessing("active-" + suffix, body, instanceLease.instanceId(), false);

        assertSqlState("23514", () -> insertRecovery(
                activeId,
                "active-" + suffix,
                semanticRequestDigest(body),
                Instant.now().plusSeconds(60),
                "role-a-test"
        ));
        assertSqlState("55000", () -> jdbcTemplate.update(
                "delete from api_idempotency_records where id = ?",
                activeId
        ));
        assertSqlState("23514", () -> jdbcTemplate.update("""
                update api_idempotency_records
                   set state = 'RECOVERY_REQUIRED', execution_finished_at = now(),
                       recovery_reason = 'FORGED'
                 where id = ?
                """, activeId));
        assertSqlState("23514", () -> jdbcTemplate.update("""
                update api_idempotency_records
                   set state = 'RECOVERY_REQUIRED', execution_finished_at = now(),
                       recovery_reason = 'HTTP_5XX_RESPONSE'
                 where id = ?
                """, activeId));
        assertSqlState("23514", () -> jdbcTemplate.update("""
                with forged_proof as (
                    select set_config('finsec.idempotency_transition_secret', 'forged-secret', true)
                )
                update api_idempotency_records
                   set state = 'RECOVERY_REQUIRED', execution_finished_at = now(),
                       recovery_reason = 'HTTP_5XX_RESPONSE'
                  from forged_proof
                 where id = ?
                """, activeId));
        assertSqlState("55000", () -> jdbcTemplate.update("""
                update application_instance_leases
                   set transition_secret_hash = digest('attacker-chosen-secret', 'sha256')
                 where id = ?
                """, instanceLease.instanceId()));

        UUID readyId = seedRecoveryRequired("mismatch-" + suffix, body);
        Instant expiresAt = jdbcTemplate.queryForObject(
                "select expires_at from api_idempotency_records where id = ?",
                java.sql.Timestamp.class,
                readyId
        ).toInstant();
        assertSqlState("23514", () -> insertRecovery(
                readyId,
                "different-key-" + suffix,
                semanticRequestDigest(body),
                expiresAt,
                "role-a-test"
        ));
    }

    @Test
    void operatorCannotRecoverExpiredReservationWhileOwningInstanceIsStillActive() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String key = "still-active-" + suffix;
        String body = "{\"active\":true}";
        UUID recordId = seedProcessing(key, body, instanceLease.instanceId(), true);
        ObjectNode request = recoveryRequest(key, body, "RELEASE", null);

        HttpResponse<String> response = postRecovery(
                request,
                "active-recovery-command-" + suffix,
                RECOVERY_KEY
        );

        assertThat(response.statusCode()).isEqualTo(409);
        assertThat(objectMapper.readTree(response.body()).path("code").asString())
                .isEqualTo("IDEMPOTENCY_IN_PROGRESS");
        assertThat(jdbcTemplate.queryForObject(
                "select state from api_idempotency_records where id = ?",
                String.class,
                recordId
        )).isEqualTo("PROCESSING");
    }

    @Test
    void staleOwnerLeaseTransitionsExpiredProcessingToRecoveryRequired() {
        UUID staleInstance = UUID.randomUUID();
        Instant stale = Instant.now().minusSeconds(120);
        jdbcTemplate.update("""
                insert into application_instance_leases
                    (id, started_at, heartbeat_at, lease_expires_at, transition_secret_hash)
                values (?, ?, ?, ?, digest('stale-test-secret', 'sha256'))
                """,
                staleInstance,
                java.sql.Timestamp.from(stale),
                java.sql.Timestamp.from(stale),
                java.sql.Timestamp.from(stale.plusSeconds(30))
        );
        UUID recordId = seedProcessing(
                "stale-owner-" + UUID.randomUUID().toString().substring(0, 8),
                "{\"orphan\":true}",
                staleInstance,
                true
        );

        instanceLease.heartbeatAndReconcile();

        assertThat(jdbcTemplate.queryForMap("""
                select state, recovery_reason from api_idempotency_records where id = ?
                """, recordId)).containsEntry("state", "RECOVERY_REQUIRED")
                .containsEntry("recovery_reason", "OWNER_LEASE_EXPIRED");
    }

    private UUID seedRecoveryRequired(String key, String body) {
        UUID id = UUID.randomUUID();
        Instant finishedAt = Instant.now().minusSeconds(30);
        jdbcTemplate.update("""
                insert into api_idempotency_records
                    (id, workspace_id, actor_id, http_method, request_path, idempotency_key,
                     request_digest, state, expires_at, owner_instance_id,
                     execution_finished_at, recovery_reason)
                values (?, ?, 'role-a-test', 'POST', '/api/v1/agents', ?, ?,
                        'RECOVERY_REQUIRED', ?, ?, ?, 'HTTP_5XX_RESPONSE')
                """,
                id,
                AgentService.DEMO_WORKSPACE_ID,
                key,
                semanticRequestDigest(body),
                java.sql.Timestamp.from(Instant.now().minusSeconds(60)),
                instanceLease.instanceId(),
                java.sql.Timestamp.from(finishedAt)
        );
        return id;
    }

    private UUID seedProcessing(String key, String body, UUID owner, boolean expired) {
        UUID id = UUID.randomUUID();
        jdbcTemplate.update("""
                insert into api_idempotency_records
                    (id, workspace_id, actor_id, http_method, request_path, idempotency_key,
                     request_digest, state, expires_at, owner_instance_id)
                values (?, ?, 'role-a-test', 'POST', '/api/v1/agents', ?, ?, 'PROCESSING', ?, ?)
                """,
                id,
                AgentService.DEMO_WORKSPACE_ID,
                key,
                semanticRequestDigest(body),
                java.sql.Timestamp.from(expired
                        ? Instant.now().minusSeconds(60)
                        : Instant.now().plusSeconds(60)),
                owner
        );
        return id;
    }

    private void insertRecovery(
            UUID recordId,
            String key,
            String digest,
            Instant originalExpiry,
            String originalActor
    ) {
        jdbcTemplate.update("""
                insert into idempotency_recoveries
                    (id, workspace_id, idempotency_record_id, actor_id, http_method, request_path,
                     idempotency_key, request_digest, resolution, verification_reference,
                     recovered_by, original_expires_at, recovered_at)
                values (?, ?, ?, ?, 'POST', '/api/v1/agents', ?, ?, 'RELEASE',
                        'ops:incident/FORGED-0001', 'operator:forged', ?, now())
                """,
                UUID.randomUUID(),
                AgentService.DEMO_WORKSPACE_ID,
                recordId,
                originalActor,
                key,
                digest,
                java.sql.Timestamp.from(originalExpiry)
        );
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
