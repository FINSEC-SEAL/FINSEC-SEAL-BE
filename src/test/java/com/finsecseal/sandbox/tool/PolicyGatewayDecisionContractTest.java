package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class PolicyGatewayDecisionContractTest {

    private static final String GATEWAY_DECISION =
            "com.finsecseal.sandbox.tool.PolicyGateway$PolicyDecision";

    @Test
    void sharedGatewayOwnsItsDecisionTypeInsteadOfLeakingLegacyPolicyType() {
        assertThatCode(() -> Class.forName(GATEWAY_DECISION))
                .as("The B-C boundary must own its ALLOW/DENY decision contract")
                .doesNotThrowAnyException();

        RecordComponent decisionComponent = Arrays.stream(
                        PolicyGateway.GatewayResult.class.getRecordComponents()
                )
                .filter(component -> component.getName().equals("policyDecision"))
                .findFirst()
                .orElseThrow();

        assertThat(decisionComponent.getType().getName())
                .as("GatewayResult must not expose ToolExecutionPolicy.PolicyDecision to C")
                .isEqualTo(GATEWAY_DECISION);
    }
}
