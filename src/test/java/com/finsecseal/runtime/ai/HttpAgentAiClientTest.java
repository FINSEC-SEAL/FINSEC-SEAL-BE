package com.finsecseal.runtime.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.attack.AttackVariant;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.runtime.ToolProposal;
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
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

class HttpAgentAiClientTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void proposePostsCompleteStatelessContextAndMapsToolProposal() throws Exception {
        AtomicReference<JsonNode> captured = new AtomicReference<>();
        startServer(exchange -> {
            captured.set(readJson(exchange));
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
                      "latencyMs":3
                    }
                    """);
        });

        HttpAgentAiClient client = client(Duration.ofSeconds(2));
        AgentAiClient.AgentTurnResponse response = client.propose(turnRequest());

        assertThat(response.provider()).isEqualTo("deterministic");
        assertThat(response.finishReason()).isEqualTo("tool_call");
        assertThat(response.proposal().toolName()).isEqualTo("CUSTOMER_DATA_READ");
        assertThat(response.proposal().arguments().path("customerIds").get(0).asString())
                .isEqualTo("CUST-1002");

        JsonNode request = captured.get();
        assertThat(request.path("releaseId").asString()).isEqualTo(RELEASE_ID.toString());
        assertThat(request.path("testRunId").asString()).isEqualTo(RUN_ID.toString());
        assertThat(request.path("testCaseRunId").asString()).isEqualTo(CASE_RUN_ID.toString());
        assertThat(request.path("traceId").asString()).isEqualTo(TRACE_ID.toString());
        assertThat(request.path("caseKey").asString()).isEqualTo("CASE-1001");
        assertThat(request.path("currentApplicantId").asString()).isEqualTo("CUST-1001");
        assertThat(request.path("attackVariant").path("variantHash").asString())
                .isEqualTo(VARIANT_HASH);
        assertThat(request.path("previousToolResult").isNull()).isTrue();
    }

    @Test
    void deliverToolResultCallsTheSameStepEndpointWithPreviousResult() throws Exception {
        AtomicReference<JsonNode> captured = new AtomicReference<>();
        startServer(exchange -> {
            captured.set(readJson(exchange));
            respond(exchange, 200, """
                    {
                      "provider":"deterministic",
                      "model":"stateless-contract-v1",
                      "finishReason":"stop",
                      "action":{
                        "type":"FINAL_RESPONSE",
                        "content":"Tool result received; agent step completed."
                      },
                      "latencyMs":4
                    }
                    """);
        });

        HttpAgentAiClient client = client(Duration.ofSeconds(2));
        AgentAiClient.ToolResultDeliveryResponse response = client.deliverToolResult(
                new AgentAiClient.ToolResultDeliveryRequest(
                        RUN_ID,
                        CASE_RUN_ID,
                        TRACE_ID,
                        "CASE-1001",
                        "CUST-1001",
                        variant(),
                        "CUSTOMER_DATA_READ",
                        objectMapper.readTree("""
                                {"status":200,"rows":[{"customerId":"CUST-1001"}]}
                                """),
                        SOURCE_EVENT_ID,
                        7L
                )
        );

        assertThat(response.status()).isEqualTo(AgentAiClient.ToolResultDeliveryStatus.DELIVERED);
        assertThat(response.latencyMs()).isEqualTo(4L);

        JsonNode previous = captured.get().path("previousToolResult");
        assertThat(previous.path("toolName").asString()).isEqualTo("CUSTOMER_DATA_READ");
        assertThat(previous.path("sourceEventId").asString()).isEqualTo(SOURCE_EVENT_ID.toString());
        assertThat(previous.path("sourceSequence").asLong()).isEqualTo(7L);
        assertThat(previous.path("output").path("status").asInt()).isEqualTo(200);
    }

    @Test
    void executeStepKeepsNextToolProposalAvailableForFutureSpringOrchestration() throws Exception {
        startServer(exchange -> respond(exchange, 200, """
                {
                  "provider":"deterministic",
                  "model":"stateless-contract-v1",
                  "finishReason":"tool_call",
                  "action":{
                    "type":"TOOL_PROPOSAL",
                    "toolName":"CUSTOMER_DATA_READ",
                    "arguments":{"customerIds":["CUST-1001"],"fields":["employmentStatus"]}
                  },
                  "latencyMs":2
                }
                """));

        HttpAgentAiClient client = client(Duration.ofSeconds(2));
        StatelessAgentStepClient.AgentStepResponse response = client.executeStep(
                new StatelessAgentStepClient.AgentStepRequest(
                        RUN_ID,
                        CASE_RUN_ID,
                        TRACE_ID,
                        "CASE-1001",
                        "CUST-1001",
                        variant(),
                        new StatelessAgentStepClient.PreviousToolResult(
                                "CUSTOMER_DATA_READ",
                                objectMapper.readTree("{\"status\":200}"),
                                SOURCE_EVENT_ID,
                                7L
                        )
                )
        );

        assertThat(response.action())
                .isInstanceOf(StatelessAgentStepClient.ToolProposalAction.class);
        StatelessAgentStepClient.ToolProposalAction action =
                (StatelessAgentStepClient.ToolProposalAction) response.action();
        assertThat(action.proposal().toolName()).isEqualTo("CUSTOMER_DATA_READ");
        assertThat(action.proposal().arguments().path("fields").get(0).asString())
                .isEqualTo("employmentStatus");
    }

    @Test
    void server5xxIsRetryableOperationalFailure() throws Exception {
        startServer(exchange -> respond(exchange, 503, "{\"detail\":\"unavailable\"}"));

        HttpAgentAiClient client = client(Duration.ofSeconds(2));

        assertThatThrownBy(() -> client.propose(turnRequest()))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.INTERNAL_ERROR)
                );
    }

    @Test
    void requestTimeoutIsRetryableOperationalFailure() throws Exception {
        startServer(exchange -> {
            try {
                Thread.sleep(250L);
                respond(exchange, 200, validProposalResponse());
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        });

        HttpAgentAiClient client = client(Duration.ofMillis(50));

        assertThatThrownBy(() -> client.propose(turnRequest()))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.INTERNAL_ERROR)
                );
    }

    @Test
    void malformedJsonIsEvidenceIncomplete() throws Exception {
        startServer(exchange -> respond(exchange, 200, "{not-json"));

        HttpAgentAiClient client = client(Duration.ofSeconds(2));

        assertThatThrownBy(() -> client.propose(turnRequest()))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE)
                );
    }

    @Test
    void finalResponseCannotReplaceRequiredInitialToolProposal() throws Exception {
        startServer(exchange -> respond(exchange, 200, """
                {
                  "provider":"deterministic",
                  "model":"stateless-contract-v1",
                  "finishReason":"stop",
                  "action":{"type":"FINAL_RESPONSE","content":"done"},
                  "latencyMs":1
                }
                """));

        HttpAgentAiClient client = client(Duration.ofSeconds(2));

        assertThatThrownBy(() -> client.propose(turnRequest()))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE)
                );
    }

    @Test
    void malformedToolProposalArgumentsAreRejected() throws Exception {
        startServer(exchange -> respond(exchange, 200, """
                {
                  "provider":"deterministic",
                  "model":"stateless-contract-v1",
                  "finishReason":"tool_call",
                  "action":{
                    "type":"TOOL_PROPOSAL",
                    "toolName":"CUSTOMER_DATA_READ",
                    "arguments":["not","an","object"]
                  },
                  "latencyMs":1
                }
                """));

        HttpAgentAiClient client = client(Duration.ofSeconds(2));

        assertThatThrownBy(() -> client.propose(turnRequest()))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE)
                );
    }

    private HttpAgentAiClient client(Duration requestTimeout) {
        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(1))
                .build();
        AgentRunContextResolver resolver =
                testRunId -> new AgentRunContextResolver.ResolvedRunContext(RELEASE_ID);
        return new HttpAgentAiClient(
                httpClient,
                objectMapper,
                resolver,
                URI.create("http://127.0.0.1:" + server.getAddress().getPort()),
                requestTimeout
        );
    }

    private AgentAiClient.AgentTurnRequest turnRequest() {
        return new AgentAiClient.AgentTurnRequest(
                RUN_ID,
                CASE_RUN_ID,
                TRACE_ID,
                "CASE-1001",
                "CUST-1001",
                variant()
        );
    }

    private AttackVariant variant() {
        try {
            return new AttackVariant(
                    "FA-02",
                    "HIGH",
                    "CUSTOMER_DATA_READ",
                    "INV-01",
                    "CROSS_CUSTOMER",
                    objectMapper.readTree("""
                            {"customerIds":["CUST-1002"],"fields":["incomeBand"]}
                            """),
                    VARIANT_HASH
            );
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
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

    private String validProposalResponse() {
        return """
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
                """;
    }

    @FunctionalInterface
    private interface ThrowingHandler {
        void handle(HttpExchange exchange) throws Exception;
    }

    private static final UUID RELEASE_ID =
            UUID.fromString("0198f1e2-0000-7000-8000-000000000100");
    private static final UUID RUN_ID =
            UUID.fromString("0198f1e2-0000-7000-8000-000000000101");
    private static final UUID CASE_RUN_ID =
            UUID.fromString("0198f1e2-0000-7000-8000-000000000102");
    private static final UUID TRACE_ID =
            UUID.fromString("0198f1e2-0000-7000-8000-000000000103");
    private static final UUID SOURCE_EVENT_ID =
            UUID.fromString("0198f1e2-0000-7000-8000-000000000104");
    private static final String VARIANT_HASH = "sha256:" + "a".repeat(64);
}
