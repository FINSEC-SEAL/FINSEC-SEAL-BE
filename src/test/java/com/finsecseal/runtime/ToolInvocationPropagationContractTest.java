package com.finsecseal.runtime;

import static org.assertj.core.api.Assertions.assertThat;

import com.finsecseal.sandbox.SandboxExecutionContext;
import com.finsecseal.sandbox.tool.PolicyGateway;
import com.finsecseal.sandbox.tool.ToolDispatcher;
import java.lang.reflect.Method;
import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ToolInvocationPropagationContractTest {

    @Test
    void springOwnedToolInvocationContractCarriesProposalEventIdentity() {
        Class<?> invocationType = requireToolInvocationType();

        assertThat(invocationType.isRecord()).isTrue();

        RecordComponent[] components = invocationType.getRecordComponents();
        assertThat(Arrays.stream(components)
                .map(RecordComponent::getName)
                .toList())
                .containsExactly(
                        "proposal",
                        "toolCallId",
                        "requestDigest"
                );

        assertThat(components[0].getType())
                .isEqualTo(ToolProposal.class);
        assertThat(components[1].getType())
                .isEqualTo(UUID.class);
        assertThat(components[2].getType())
                .isEqualTo(String.class);
    }

    @Test
    void dispatcherAndGatewayConsumeSpringOwnedInvocation() {
        Class<?> invocationType = requireToolInvocationType();

        assertMethod(
                ToolDispatcher.class,
                "dispatch",
                invocationType
        );

        assertMethod(
                PolicyGateway.class,
                "invoke",
                invocationType
        );
    }

    @Test
    void followUpProposalReturnsSpringOwnedInvocation() {
        Class<?> invocationType = requireToolInvocationType();

        Method method = Arrays.stream(
                        AgentRuntimeService.class.getMethods()
                )
                .filter(candidate ->
                        candidate.getName()
                                .equals("recordFollowUpToolProposal"))
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "recordFollowUpToolProposal contract is missing"
                ));

        assertThat(method.getReturnType())
                .as(
                        "Follow-up Tool proposals must return the "
                                + "persisted Spring-owned invocation identity"
                )
                .isEqualTo(invocationType);
    }

    private Class<?> requireToolInvocationType() {
        try {
            return Class.forName(
                    "com.finsecseal.runtime.ToolInvocation"
            );
        } catch (ClassNotFoundException exception) {
            throw new AssertionError(
                    "ToolInvocation does not exist yet; "
                            + "this is the expected Task 8-1 RED reason",
                    exception
            );
        }
    }

    private void assertMethod(
            Class<?> owner,
            String methodName,
            Class<?> invocationType
    ) {
        boolean found = Arrays.stream(owner.getMethods())
                .filter(method ->
                        method.getName().equals(methodName))
                .anyMatch(method -> {
                    Class<?>[] parameters =
                            method.getParameterTypes();
                    return parameters.length == 3
                            && parameters[0]
                            == SandboxExecutionContext.class
                            && parameters[1]
                            == invocationType
                            && parameters[2]
                            == String.class;
                });

        assertThat(found)
                .as(
                        owner.getSimpleName()
                                + "."
                                + methodName
                                + " must consume "
                                + "ToolInvocation as its second argument"
                )
                .isTrue();
    }
}
