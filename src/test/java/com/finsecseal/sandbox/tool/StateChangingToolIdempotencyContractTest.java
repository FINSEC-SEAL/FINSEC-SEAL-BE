package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThat;

import com.finsecseal.runtime.ToolInvocation;
import com.finsecseal.sandbox.SandboxExecutionContext;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.lang.reflect.RecordComponent;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class StateChangingToolIdempotencyContractTest {

    @Test
    void toolEffectContractDeclaresReadOnlyAndStateChanging() {
        Class<?> effectType = requireType(
                "com.finsecseal.sandbox.tool.ToolEffect",
                "ToolEffect does not exist yet; expected Task 8-2A RED"
        );

        assertThat(effectType.isEnum()).isTrue();

        assertThat(Arrays.stream(effectType.getEnumConstants())
                .map(Object::toString)
                .toList())
                .containsExactly(
                        "READ_ONLY",
                        "STATE_CHANGING"
                );
    }

    @Test
    void toolAdapterExposesStaticEffectClassification() {
        Class<?> effectType = requireType(
                "com.finsecseal.sandbox.tool.ToolEffect",
                "ToolEffect does not exist yet; expected Task 8-2A RED"
        );

        Method effect = Arrays.stream(ToolAdapter.class.getMethods())
                .filter(method -> method.getName().equals("effect"))
                .filter(method -> method.getParameterCount() == 0)
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "ToolAdapter.effect() is missing"
                ));

        assertThat(effect.getReturnType())
                .isEqualTo(effectType);

        assertDeclaresEffect(
                ExternalHttpMockToolAdapter.class,
                effectType
        );
        assertDeclaresEffect(
                LoanDecisionUpdateMockToolAdapter.class,
                effectType
        );
    }

    @Test
    void commonStateChangingExecutorHasStableInvocationBoundary() {
        Class<?> executorType = requireType(
                "com.finsecseal.sandbox.tool.StateChangingToolExecutionService",
                "StateChangingToolExecutionService does not exist yet; expected Task 8-2A RED"
        );

        Method execute = Arrays.stream(executorType.getMethods())
                .filter(method -> method.getName().equals("execute"))
                .filter(method -> Arrays.equals(
                        method.getParameterTypes(),
                        new Class<?>[] {
                                SandboxExecutionContext.class,
                                ToolInvocation.class,
                                ToolAdapter.class,
                                String.class
                        }
                ))
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "StateChangingToolExecutionService.execute("
                                + "SandboxExecutionContext, ToolInvocation, "
                                + "ToolAdapter, String) is missing"
                ));

        Class<?> resultType = execute.getReturnType();
        assertThat(resultType.isRecord()).isTrue();

        assertThat(Arrays.stream(resultType.getRecordComponents())
                .map(RecordComponent::getName)
                .toList())
                .containsExactly(
                        "requestEvent",
                        "responseEvent",
                        "stateEvent",
                        "result",
                        "replayed"
                );
    }

    @Test
    void flywayV13DefinesCaseRunAndToolCallUniqueIdempotency() throws Exception {
        String resource =
                "db/migration/V13__sandbox_tool_idempotency.sql";

        try (InputStream input = Thread.currentThread()
                .getContextClassLoader()
                .getResourceAsStream(resource)) {

            assertThat(input)
                    .as("V13 idempotency migration must exist")
                    .isNotNull();

            String sql = new String(
                    input.readAllBytes(),
                    StandardCharsets.UTF_8
            );

            assertThat(sql)
                    .contains("sandbox_tool_idempotency_records")
                    .contains("test_case_run_id")
                    .contains("tool_call_id")
                    .contains("PROCESSING")
                    .contains("COMPLETED")
                    .containsIgnoringCase(
                            "UNIQUE (test_case_run_id, tool_call_id)"
                    );
        }
    }

    private Class<?> requireType(
            String name,
            String message
    ) {
        try {
            return Class.forName(name);
        } catch (ClassNotFoundException exception) {
            throw new AssertionError(message, exception);
        }
    }

    private void assertDeclaresEffect(
            Class<?> adapterType,
            Class<?> effectType
    ) {
        Method effect = Arrays.stream(
                        adapterType.getDeclaredMethods()
                )
                .filter(method -> method.getName().equals("effect"))
                .filter(method -> method.getParameterCount() == 0)
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        adapterType.getSimpleName()
                                + " must explicitly declare STATE_CHANGING effect"
                ));

        assertThat(effect.getReturnType())
                .isEqualTo(effectType);
    }
}
