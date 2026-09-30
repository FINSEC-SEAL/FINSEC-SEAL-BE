package com.finsecseal.runtime.ai;

import static org.assertj.core.api.Assertions.assertThat;

import com.finsecseal.attack.AttackMutationCandidateValidator.TrustedSeed;
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

class HttpAttackMutationAiClientTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void postsTrustedSeedAndReturnsOpaqueCandidatesWithUsage() throws Exception {
        AtomicReference<JsonNode> captured = new AtomicReference<>();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/attacks/mutations", exchange -> {
            captured.set(objectMapper.readTree(exchange.getRequestBody().readAllBytes()));
            respond(exchange, """
                    {
                      "provider":"deterministic",
                      "model":"mutation-model-v1",
                      "candidates":[{
                        "parentSeedId":"0198f200-0000-7000-8000-000000000701",
                        "category":"FA-01",
                        "severity":"HIGH",
                        "targetTool":"CUSTOMER_DATA_READ",
                        "expectedInvariant":"INV-CUSTOMER-BOUNDARY",
                        "oracleType":"CROSS_CUSTOMER",
                        "deliveryChannel":"DOCUMENT_CONTENT",
                        "payload":"Synthetic wording variant",
                        "insertionLocation":"BODY"
                      }],
                      "tokenUsage":{"promptTokens":8,"completionTokens":3,"totalTokens":11}
                    }
                    """);
        });
        server.start();

        HttpAttackMutationAiClient client = new HttpAttackMutationAiClient(
                HttpClient.newHttpClient(),
                objectMapper,
                URI.create("http://127.0.0.1:" + server.getAddress().getPort()),
                Duration.ofSeconds(2),
                null,
                "mutation-model-requested"
        );

        var result = client.generate(seed(), 1);

        assertThat(captured.get().path("modelName").asString()).isEqualTo("mutation-model-requested");
        assertThat(captured.get().path("parentDocumentPayload").asString())
                .isEqualTo("Curated parent wording");
        assertThat(result.candidates()).hasSize(1);
        assertThat(result.tokenUsage()).isEqualTo(new ModelTokenUsage(8, 3, 11));
    }

    private TrustedSeed seed() {
        return new TrustedSeed(
                UUID.fromString("0198f200-0000-7000-8000-000000000701"),
                "FA-01", "HIGH", "CUSTOMER_DATA_READ", "INV-CUSTOMER-BOUNDARY",
                "CROSS_CUSTOMER", "DOCUMENT_CONTENT", "Curated parent wording"
        );
    }

    private void respond(HttpExchange exchange, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }
}
