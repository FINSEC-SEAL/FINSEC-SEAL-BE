package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import com.finsecseal.evidence.ExecutionEventService;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

class TemporaryPolicyGatewayBridgeContractTest {

    private static final String BRIDGE_CLASS =
            "com.finsecseal.sandbox.tool.TemporaryPolicyGatewayBridge";

    @Test
    void temporaryBridgeExistsAndImplementsPolicyGateway() {
        assertThatCode(() -> Class.forName(BRIDGE_CLASS))
                .as("B needs a temporary Gateway implementation until C provides the real Policy Gateway")
                .doesNotThrowAnyException();

        Class<?> bridge = loadBridge();

        assertThat(PolicyGateway.class.isAssignableFrom(bridge))
                .as("Temporary bridge must be replaceable by C through the shared PolicyGateway port")
                .isTrue();
    }

    @Test
    void temporaryBridgeOwnsLegacyPoliciesAdaptersAndEvidenceDependencies() {
        Class<?> bridge = loadBridge();

        Set<String> fieldNames = Arrays.stream(bridge.getDeclaredFields())
                .map(Field::getName)
                .collect(Collectors.toSet());

        assertThat(fieldNames)
                .as("Legacy execution ownership must move behind the Gateway boundary")
                .contains("adapters", "policies", "eventService", "objectMapper");

        boolean hasExpectedConstructor = Arrays.stream(bridge.getDeclaredConstructors())
                .map(Constructor::getParameterTypes)
                .anyMatch(parameters ->
                        parameters.length == 4
                                && parameters[0] == List.class
                                && parameters[1] == List.class
                                && parameters[2] == ExecutionEventService.class
                                && parameters[3] == ObjectMapper.class
                );

        assertThat(hasExpectedConstructor)
                .as("Temporary bridge must receive adapters, legacy policies, event service, and ObjectMapper")
                .isTrue();
    }

    private Class<?> loadBridge() {
        try {
            return Class.forName(BRIDGE_CLASS);
        } catch (ClassNotFoundException exception) {
            throw new AssertionError("TemporaryPolicyGatewayBridge does not exist yet", exception);
        }
    }
}
