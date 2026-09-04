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
import tools.jackson.databind.ObjectMapper;

class HttpAgentAiRetryTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void http503IsRetriedAndSecondValidResponseSucceeds() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        startServer(exchange -> {
            int current = requests.incrementAndGet();
            if (current == 1) {
                respond(exchange, 503, "{\"detail\":\"temporarily unavailable\"}");
                return;
            }
            respond(exchange, 200, validProposalResponse());
        });

        AgentAiClient.AgentTurnResponse response = client().propose(turnRequest());

        assertThat(response.proposal().toolName()).isEqualTo("CUSTOMER_DATA_READ");
        assertThat(requests).hasValue(2);
    }

    @Test
    void http429IsRetriedAndSecondValidResponseSucceeds() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        startServer(exchange -> {
            int current = requests.incrementAndGet();
            if (current == 1) {
                respond(exchange, 429, "{\"detail\":\"rate limited\"}");
                return;
            }
            respond(exchange, 200, validProposalResponse());
        });

        AgentAiClient.AgentTurnResponse response = client().propose(turnRequest());

        assertThat(response.proposal().toolName()).isEqualTo("CUSTOMER_DATA_READ");
        assertThat(requests).hasValue(2);
    }

    @Test
    void http408IsRetriedAndSecondValidResponseSucceeds() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        startServer(exchange -> {
            int current = requests.incrementAndGet();
            if (current == 1) {
                respond(exchange, 408, "{\"detail\":\"request timeout\"}");
                return;
            }
            respond(exchange, 200, validProposalResponse());
        });

        AgentAiClient.AgentTurnResponse response = client().propose(turnRequest());

        assertThat(response.proposal().toolName()).isEqualTo("CUSTOMER_DATA_READ");
        assertThat(requests).hasValue(2);
    }

    @Test
    void retryable503StopsAfterExactlyThreeAttempts() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        startServer(exchange -> {
            requests.incrementAndGet();
            respond(exchange, 503, "{\"detail\":\"unavailable\"}");
        });

        assertThatThrownBy(() -> client().propose(turnRequest()))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.INTERNAL_ERROR)
                );

        assertThat(requests)
                .as("retry must be bounded")
                .hasValue(3);
    }

    @Test
    void http400IsNotRetried() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        startServer(exchange -> {
            requests.incrementAndGet();
            respond(exchange, 400, "{\"detail\":\"invalid request\"}");
        });

        assertThatThrownBy(() -> client().propose(turnRequest()))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE)
                );

        assertThat(requests).hasValue(1);
    }

    @Test
    void malformedJsonIsNotRetried() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        startServer(exchange -> {
            requests.incrementAndGet();
            respond(exchange, 200, "{not-json");
        });

        assertThatThrownBy(() -> client().propose(turnRequest()))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE)
                );

        assertThat(requests).hasValue(1);
    }

    @Test
    void invalidToolProposalIsNotRetried() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        startServer(exchange -> {
            requests.incrementAndGet();
            respond(exchange, 200, """
                    {
                      "provider":"deterministic",
                      "model":"stateless-contract-v1",
                      "finishReason":"tool_call",
                      "action":{
                        "type":"TOOL_PROPOSAL",
                        "toolName":"CUSTOMER_DATA_READ",
                        "arguments":["invalid"]
                      },
                      "latencyMs":1
                    }
                    """);
        });

        assertThatThrownBy(() -> client().propose(turnRequest()))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE)
                );

        assertThat(requests).hasValue(1);
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
        var arguments = objectMapper.createObjectNode();
        arguments.putArray("customerIds").add("CUST-1002");
        arguments.putArray("fields").add("incomeBand");
        return new AttackVariant(
                "FA-02",
                "HIGH",
                "CUSTOMER_DATA_READ",
                "INV-01",
                "CROSS_CUSTOMER",
                arguments,
                VARIANT_HASH
        );
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
            UUID.fromString("0198f1e2-0000-7000-8000-000000000500");
    private static final UUID RUN_ID =
            UUID.fromString("0198f1e2-0000-7000-8000-000000000501");
    private static final UUID CASE_RUN_ID =
            UUID.fromString("0198f1e2-0000-7000-8000-000000000502");
    private static final UUID TRACE_ID =
            UUID.fromString("0198f1e2-0000-7000-8000-000000000503");
    private static final String VARIANT_HASH =
            "sha256:" + "abcdef0123456789".repeat(4);
}
