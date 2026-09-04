package com.finsecseal.runtime.ai;

import static org.assertj.core.api.Assertions.assertThat;

import com.finsecseal.runtime.AgentRuntimeService;
import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class AgentAiStateMachineContractTest {

    @Test
    void agentAiClientOwnsTheCanonicalStatelessExecuteStepContract() {
        Set<String> methodNames = Arrays.stream(AgentAiClient.class.getMethods())
                .map(method -> method.getName())
                .collect(Collectors.toSet());

        assertThat(methodNames)
                .as("AgentAiClient must expose the canonical executeStep state-machine")
                .contains("executeStep");
    }

    @Test
    void toolResultDeliveryResponsePreservesTheNextAgentAction() {
        assertThat(recordComponentNames(AgentAiClient.ToolResultDeliveryResponse.class))
                .as("Tool-result delivery must not collapse TOOL_PROPOSAL/FINAL_RESPONSE into DELIVERED")
                .contains("nextAction");
    }

    @Test
    void runtimeDeliveryReceiptPreservesTheNextAgentAction() {
        assertThat(recordComponentNames(AgentRuntimeService.DeliveryReceipt.class))
                .as("Spring runtime must carry the next Agent action back to the orchestrator")
                .contains("nextAction");
    }

    private Set<String> recordComponentNames(Class<?> recordType) {
        RecordComponent[] components = recordType.getRecordComponents();
        assertThat(components)
                .as(recordType.getSimpleName() + " must remain a record")
                .isNotNull();

        return Arrays.stream(components)
                .map(RecordComponent::getName)
                .collect(Collectors.toSet());
    }
}
