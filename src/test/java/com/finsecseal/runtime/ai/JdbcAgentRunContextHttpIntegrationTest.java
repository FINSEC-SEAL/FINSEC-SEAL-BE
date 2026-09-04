package com.finsecseal.runtime.ai;

import static org.assertj.core.api.Assertions.assertThat;

import com.finsecseal.attack.AttackVariant;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Testcontainers
@SpringBootTest
class JdbcAgentRunContextHttpIntegrationTest {

    private static final String HASH_A = "sha256:" + "a".repeat(64);
    private static final String HASH_B = "sha256:" + "b".repeat(64);
    private static final String VARIANT_HASH = "sha256:" + "c".repeat(64);
    private static final UUID WORKSPACE_ID =
            UUID.fromString("0198f1e2-0000-7000-8000-000000000001");

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES =
            new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired JdbcTemplate jdbcTemplate;
    @Autowired ObjectMapper objectMapper;
    @Autowired TestRunPersistenceService runPersistenceService;

    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void outboundAgentRequestUsesReleaseIdResolvedFromTestRunRow() throws Exception {
        Seed seed = seedRun();
        UUID unrelatedReleaseId = UUID.randomUUID();

        AtomicReference<JsonNode> capturedRequest = new AtomicReference<>();
        startServer(exchange -> {
            capturedRequest.set(readJson(exchange));
            respond(exchange, 200, """
                    {
                      "provider":"deterministic",
                      "model":"stateless-contract-v1",
                      "finishReason":"tool_call",
                      "action":{
                        "type":"TOOL_PROPOSAL",
                        "toolName":"CUSTOMER_DATA_READ",
                        "arguments":{"customerIds":["CUST-1002"],"fields":["incomeBand"]}
                      },
                      "latencyMs":1
                    }
                    """);
        });

        AgentRunContextResolver resolver = new JdbcAgentRunContextResolver(jdbcTemplate);
        HttpAgentAiClient client = new HttpAgentAiClient(
                HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(1))
                        .version(HttpClient.Version.HTTP_1_1)
                        .build(),
                objectMapper,
                resolver,
                URI.create("http://127.0.0.1:" + server.getAddress().getPort()),
                Duration.ofSeconds(2)
        );

        client.propose(new AgentAiClient.AgentTurnRequest(
                seed.runId(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                "CASE-1001",
                "CUST-1001",
                new AttackVariant(
                        "FA-02",
                        "HIGH",
                        "CUSTOMER_DATA_READ",
                        "INV-01",
                        "CROSS_CUSTOMER",
                        objectMapper.readTree("""
                                {"customerIds":["CUST-1002"],"fields":["incomeBand"]}
                                """),
                        VARIANT_HASH
                )
        ));

        JsonNode request = capturedRequest.get();
        assertThat(request).isNotNull();
        assertThat(request.path("testRunId").asString()).isEqualTo(seed.runId().toString());
        assertThat(request.path("releaseId").asString())
                .as("releaseId sent to Python must come from test_runs.release_id")
                .isEqualTo(seed.releaseId().toString())
                .isNotEqualTo(unrelatedReleaseId.toString());

        UUID persistedReleaseId = jdbcTemplate.queryForObject(
                "select release_id from test_runs where id = ?",
                UUID.class,
                seed.runId()
        );
        assertThat(persistedReleaseId).isEqualTo(seed.releaseId());
    }

    private Seed seedRun() {
        UUID agentId = UUID.randomUUID();
        UUID releaseId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        String suffix = agentId.toString().substring(0, 8);

        jdbcTemplate.update("""
                insert into agents
                    (id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'AI Context Agent', 'releaseId trust-boundary integration test', 'ACTIVE')
                """, agentId, WORKSPACE_ID, "ai-context-agent-" + suffix);

        jdbcTemplate.update("""
                insert into agent_releases
                    (id, agent_id, version, business_purpose, manifest_schema_version, manifest_json,
                     agent_artifact_fingerprint, release_fingerprint, lifecycle_state, effective_status)
                values (?, ?, '1.0.0', 'LOAN_DOCUMENT_COMPLETENESS_REVIEW', '1.0', '{}'::jsonb,
                        ?, ?, 'ANALYZED', 'ANALYZED')
                """, releaseId, agentId, HASH_A, HASH_A);

        jdbcTemplate.update("""
                insert into test_suites
                    (id, workspace_id, suite_key, version, fixture_version, generation_config_json,
                     suite_hash, status)
                values (?, ?, ?, '1.0.0', 'golden-v1', '{}'::jsonb, ?, 'READY')
                """, suiteId, WORKSPACE_ID, "ai-context-suite-" + suffix, HASH_B);

        UUID runId = runPersistenceService.register(
                new TestRunPersistenceDto.RegisterRequest(
                        releaseId,
                        suiteId,
                        null,
                        TestRunMode.BASELINE,
                        UUID.randomUUID(),
                        objectMapper.createObjectNode().put("schemaVersion", "1.0"),
                        HASH_B,
                        HASH_B,
                        42L,
                        1
                ),
                "role-b"
        ).runId();

        return new Seed(runId, releaseId);
    }

    private void startServer(ThrowingHandler handler) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/agent/steps", exchange -> {
            try {
                handler.handle(exchange);
            } catch (Exception exception) {
                exchange.close();
            }
        });
        server.start();
    }

    private JsonNode readJson(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        return objectMapper.readTree(new String(body, StandardCharsets.UTF_8));
    }

    private void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    @FunctionalInterface
    private interface ThrowingHandler {
        void handle(HttpExchange exchange) throws Exception;
    }

    private record Seed(UUID runId, UUID releaseId) {
    }
}
