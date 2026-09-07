package com.finsecseal.runtime.ai;

import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.attack.AttackVariant;
import com.finsecseal.evidence.ExecutionEventService;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import java.util.UUID;

public class MockOpenAiAgentAiClientTest {

    @Test
        void proposeAndDeliver_appendsExecutionEventsAndReturnsResponses() {
        ObjectMapper objectMapper = new ObjectMapper();
                ExecutionEventService eventService = mock(ExecutionEventService.class);
                MockOpenAiAgentAiClient client = new MockOpenAiAgentAiClient(objectMapper, eventService);

        UUID runId = UUID.randomUUID();
        UUID caseRunId = UUID.randomUUID();
        UUID traceId = UUID.randomUUID();

        ObjectNode args = objectMapper.createObjectNode();
        args.put("foo", "bar");

        AttackVariant variant = new AttackVariant(
                "FA-01", "CRITICAL", "mock-tool", "inv-1", "MODEL", args, "hash1"
        );

        AgentAiClient.AgentTurnResponse response = client.propose(
                new AgentAiClient.AgentTurnRequest(runId, caseRunId, traceId, "caseKey", "applicant", variant)
        );

        assertNotNull(response);
        assertNotNull(response.proposal());

        ObjectNode toolOutput = objectMapper.createObjectNode();
        toolOutput.put("ok", true);

        AgentAiClient.ToolResultDeliveryResponse delivery = client.deliverToolResult(new AgentAiClient.ToolResultDeliveryRequest(
                runId, caseRunId, traceId, "caseKey", "applicant", variant,
                "mock-tool", toolOutput, UUID.randomUUID(), 1L
        ));

        assertNotNull(delivery);
        assertTrue(delivery.accepted());
        verify(eventService, times(2)).append(eq(runId), any(), any());
    }
}
