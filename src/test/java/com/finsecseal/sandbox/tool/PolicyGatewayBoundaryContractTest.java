package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class PolicyGatewayBoundaryContractTest {

    private static final String POLICY_GATEWAY_CLASS =
            "com.finsecseal.sandbox.tool.PolicyGateway";

    @Test
    void policyGatewayExistsAsTheSharedToolExecutionBoundary() {
        assertThatCode(() -> Class.forName(POLICY_GATEWAY_CLASS))
                .as("B and C need one stable PolicyGateway boundary before any Tool Adapter executes")
                .doesNotThrowAnyException();
    }

    @Test
    void toolDispatcherDependsOnGatewayInsteadOfOwningLegacyExecutionRegistries() {
        Set<String> fieldTypes = Arrays.stream(ToolDispatcher.class.getDeclaredFields())
                .map(Field::getType)
                .map(Class::getName)
                .collect(Collectors.toSet());

        Set<String> fieldNames = Arrays.stream(ToolDispatcher.class.getDeclaredFields())
                .map(Field::getName)
                .collect(Collectors.toSet());

        assertThat(fieldTypes)
                .as("ToolDispatcher must delegate the policy/execution boundary to PolicyGateway")
                .contains(POLICY_GATEWAY_CLASS);

        assertThat(fieldNames)
                .as("ToolDispatcher must no longer own direct adapter/policy registries")
                .doesNotContain("adapters", "policies");
    }
}
