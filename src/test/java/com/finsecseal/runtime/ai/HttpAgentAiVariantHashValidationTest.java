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
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import tools.jackson.databind.ObjectMapper;

class HttpAgentAiVariantHashValidationTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidVariantHashes")
    void malformedVariantHashIsRejectedBeforeAnyHttpRequest(
            String description,
            String malformedHash
    ) throws Exception {
        AtomicInteger requests = new AtomicInteger();
        startServer(exchange -> {
            requests.incrementAndGet();
            respond(exchange, 200, validProposalResponse());
        });

        HttpAgentAiClient client = client();

        assertThatThrownBy(() -> client.propose(turnRequest(malformedHash)))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode())
                                .isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE)
                );

        assertThat(requests)
                .as("malformed variantHash must fail closed before outbound AI HTTP")
                .hasValue(0);
    }

    @Test
    void exactLowercaseSha256VariantHashIsAccepted() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        startServer(exchange -> {
            requests.incrementAndGet();
            respond(exchange, 200, validProposalResponse());
        });

        HttpAgentAiClient client = client();

        AgentAiClient.AgentTurnResponse response = client.propose(
                turnRequest("sha256:" + "abcdef0123456789".repeat(4))
        );

        assertThat(response.proposal().toolName()).isEqualTo("CUSTOMER_DATA_READ");
        assertThat(requests).hasValue(1);
    }

    private static Stream<Arguments> invalidVariantHashes() {
        return Stream.of(
                Arguments.of("missing prefix", "a".repeat(64)),
                Arguments.of("uppercase algorithm prefix", "SHA256:" + "a".repeat(64)),
                Arguments.of("uppercase hex", "sha256:" + "A".repeat(64)),
                Arguments.of("too short", "sha256:" + "a".repeat(63)),
                Arguments.of("too long", "sha256:" + "a".repeat(65)),
                Arguments.of("non-hex character", "sha256:" + "g".repeat(64)),
                Arguments.of("leading whitespace", " sha256:" + "a".repeat(64)),
                Arguments.of("trailing whitespace", "sha256:" + "a".repeat(64) + " ")
        );
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

    private AgentAiClient.AgentTurnRequest turnRequest(String variantHash) throws Exception {
        return new AgentAiClient.AgentTurnRequest(
                RUN_ID,
                CASE_RUN_ID,
                TRACE_ID,
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
                        variantHash
                )
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
        byte[] bytes = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);
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
            UUID.fromString("0198f1e2-0000-7000-8000-000000000200");
    private static final UUID RUN_ID =
            UUID.fromString("0198f1e2-0000-7000-8000-000000000201");
    private static final UUID CASE_RUN_ID =
            UUID.fromString("0198f1e2-0000-7000-8000-000000000202");
    private static final UUID TRACE_ID =
            UUID.fromString("0198f1e2-0000-7000-8000-000000000203");
}
