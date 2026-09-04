package com.finsecseal.runtime.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.attack.AttackVariant;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

class HttpAgentAiBoundaryGuardTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void requestLargerThan512KiBIsRejectedBeforeOutboundHttp() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        startServer(exchange -> {
            requests.incrementAndGet();
            respond(exchange, 200, validToolProposalResponse());
        });

        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.put("payload", "x".repeat(600 * 1024));

        HttpAgentAiClient client = client();

        assertThatThrownBy(() -> client.propose(turnRequest(arguments)))
                .isInstanceOfSatisfying(BusinessException.class, exception -> {
                    assertThat(exception.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE);
                    assertThat(exception.getMessage()).contains("512 KiB");
                });

        assertThat(requests)
                .as("oversized request must fail before any AI HTTP call")
                .hasValue(0);
    }

    @Test
    void responseLargerThan256KiBIsRejected() throws Exception {
        startServer(exchange -> {
            String oversized = """
                    {
                      "provider":"deterministic",
                      "model":"stateless-contract-v1",
                      "finishReason":"stop",
                      "action":{
                        "type":"FINAL_RESPONSE",
                        "content":"%s"
                      },
                      "latencyMs":1
                    }
                    """.formatted("x".repeat(300 * 1024));
            respond(exchange, 200, oversized);
        });

        HttpAgentAiClient client = client();

        assertThatThrownBy(() -> client.propose(turnRequest(validArguments())))
                .isInstanceOfSatisfying(BusinessException.class, exception -> {
                    assertThat(exception.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE);
                    assertThat(exception.getMessage()).contains("256 KiB");
                });
    }

    @Test
    void toolProposalRequiresToolCallFinishReason() throws Exception {
        startServer(exchange -> respond(exchange, 200, """
                {
                  "provider":"deterministic",
                  "model":"stateless-contract-v1",
                  "finishReason":"stop",
                  "action":{
                    "type":"TOOL_PROPOSAL",
                    "toolName":"CUSTOMER_DATA_READ",
                    "arguments":{"customerIds":["CUST-1002"],"fields":["incomeBand"]}
                  },
                  "latencyMs":1
                }
                """));

        HttpAgentAiClient client = client();

        assertThatThrownBy(() -> client.propose(turnRequest(validArguments())))
                .isInstanceOfSatisfying(BusinessException.class, exception -> {
                    assertThat(exception.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE);
                    assertThat(exception.getMessage())
                            .contains("TOOL_PROPOSAL")
                            .contains("finishReason=tool_call");
                });
    }

    @Test
    void finalResponseRequiresStopFinishReason() throws Exception {
        startServer(exchange -> respond(exchange, 200, """
                {
                  "provider":"deterministic",
                  "model":"stateless-contract-v1",
                  "finishReason":"tool_call",
                  "action":{
                    "type":"FINAL_RESPONSE",
                    "content":"done"
                  },
                  "latencyMs":1
                }
                """));

        HttpAgentAiClient client = client();

        assertThatThrownBy(() -> client.executeStep(new StatelessAgentStepClient.AgentStepRequest(
                RUN_ID,
                CASE_RUN_ID,
                TRACE_ID,
                "CASE-1001",
                "CUST-1001",
                variant(validArguments()),
                new StatelessAgentStepClient.PreviousToolResult(
                        "CUSTOMER_DATA_READ",
                        objectMapper.readTree("{\"status\":200}"),
                        SOURCE_EVENT_ID,
                        1L
                )
        ))).isInstanceOfSatisfying(BusinessException.class, exception -> {
            assertThat(exception.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE);
            assertThat(exception.getMessage())
                    .contains("FINAL_RESPONSE")
                    .contains("finishReason=stop");
        });
    }

    private HttpAgentAiClient client() {
        AgentRunContextResolver resolver =
                testRunId -> new AgentRunContextResolver.ResolvedRunContext(RELEASE_ID);

        return new HttpAgentAiClient(
                HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(1))
                        .version(HttpClient.Version.HTTP_1_1)
                        .build(),
                objectMapper,
                resolver,
                URI.create("http://127.0.0.1:" + server.getAddress().getPort()),
                Duration.ofSeconds(2)
        );
    }

    private AgentAiClient.AgentTurnRequest turnRequest(JsonNode arguments) {
        return new AgentAiClient.AgentTurnRequest(
                RUN_ID,
                CASE_RUN_ID,
                TRACE_ID,
                "CASE-1001",
                "CUST-1001",
                variant(arguments)
        );
    }

    private AttackVariant variant(JsonNode arguments) {
        return new AttackVariant(
                "FA-02",
                "HIGH",
                "CUSTOMER_DATA_READ",
                "INV-01",
                "CROSS_CUSTOMER",
                arguments,
                VALID_VARIANT_HASH
        );
    }

    private ObjectNode validArguments() {
        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.putArray("customerIds").add("CUST-1002");
        arguments.putArray("fields").add("incomeBand");
        return arguments;
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

    private void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private String validToolProposalResponse() {
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
            UUID.fromString("0198f1e2-0000-7000-8000-000000000300");
    private static final UUID RUN_ID =
            UUID.fromString("0198f1e2-0000-7000-8000-000000000301");
    private static final UUID CASE_RUN_ID =
            UUID.fromString("0198f1e2-0000-7000-8000-000000000302");
    private static final UUID TRACE_ID =
            UUID.fromString("0198f1e2-0000-7000-8000-000000000303");
    private static final UUID SOURCE_EVENT_ID =
            UUID.fromString("0198f1e2-0000-7000-8000-000000000304");
    private static final String VALID_VARIANT_HASH =
            "sha256:" + "abcdef0123456789".repeat(4);
}
