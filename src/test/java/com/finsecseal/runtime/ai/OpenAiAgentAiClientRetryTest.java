package com.finsecseal.runtime.ai;

import com.finsecseal.attack.AttackVariant;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

class OpenAiAgentAiClientRetryTest {

    @Test
    void executeStep_retriesOnIoAndEventuallySucceeds() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        HttpClient httpClient = mock(HttpClient.class);
        @SuppressWarnings("unchecked")
        HttpResponse<InputStream> response = (HttpResponse<InputStream>) mock(HttpResponse.class);

        String contentJson = "{\"provider\":\"openai\",\"model\":\"gpt-4o-mini\",\"finishReason\":\"stop\",\"latencyMs\":12,\"action\":{\"type\":\"FINAL_RESPONSE\",\"content\":\"ok\"}}";
        String openAiEnvelope = "{\"choices\":[{\"message\":{\"content\":" + mapper.writeValueAsString(contentJson) + "}}]}";

        when(response.statusCode()).thenReturn(200);
        when(response.body()).thenReturn(new ByteArrayInputStream(openAiEnvelope.getBytes(StandardCharsets.UTF_8)));

        doThrow(new IOException("net-1"))
                .doThrow(new IOException("net-2"))
                .doReturn(response)
                .when(httpClient)
                .send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));

        AgentRunContextResolver resolver = runId -> new AgentRunContextResolver.ResolvedRunContext(UUID.randomUUID());
        OpenAiAgentAiClient client = new OpenAiAgentAiClient(
                httpClient,
                mapper,
                resolver,
                "gpt-4o-mini",
                Duration.ofSeconds(1),
                "test-key"
        );

        ObjectNode arguments = mapper.createObjectNode();
        arguments.put("x", 1);
        AttackVariant variant = new AttackVariant(
                "FA-01",
                "HIGH",
                "CUSTOMER_DATA_READ",
                "INV-001",
                "POLICY",
                arguments,
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );

        StatelessAgentStepClient.AgentStepResponse step = client.executeStep(new StatelessAgentStepClient.AgentStepRequest(
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                "FA02-CROSS-CUSTOMER",
                "cust-1",
                variant,
                null
        ));

        assertNotNull(step);
        assertEquals("stop", step.finishReason());
    }

    @Test
    void executeStep_throwsInternalErrorWhenRetriesExhausted() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        HttpClient httpClient = mock(HttpClient.class);

        doThrow(new IOException("net-1"))
                .doThrow(new IOException("net-2"))
                .doThrow(new IOException("net-3"))
                .when(httpClient)
                .send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));

        AgentRunContextResolver resolver = runId -> new AgentRunContextResolver.ResolvedRunContext(UUID.randomUUID());
        OpenAiAgentAiClient client = new OpenAiAgentAiClient(
                httpClient,
                mapper,
                resolver,
                "gpt-4o-mini",
                Duration.ofSeconds(1),
                "test-key"
        );

        ObjectNode arguments = mapper.createObjectNode();
        arguments.put("x", 1);
        AttackVariant variant = new AttackVariant(
                "FA-01",
                "HIGH",
                "CUSTOMER_DATA_READ",
                "INV-001",
                "POLICY",
                arguments,
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );

        BusinessException ex = assertThrows(BusinessException.class, () -> client.executeStep(new StatelessAgentStepClient.AgentStepRequest(
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                "FA02-CROSS-CUSTOMER",
                "cust-1",
                variant,
                null
        )));

        assertEquals(ErrorCode.INTERNAL_ERROR, ex.errorCode());
    }
}
