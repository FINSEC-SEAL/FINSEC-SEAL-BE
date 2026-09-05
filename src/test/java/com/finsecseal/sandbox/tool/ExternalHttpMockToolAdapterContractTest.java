package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.release.DigestService;
import java.lang.reflect.Constructor;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

class ExternalHttpMockToolAdapterContractTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void externalHttpAdapterExistsAsAMockOnlyToolAdapter() {
        Class<?> type = requireAdapterType();

        assertThat(ToolAdapter.class).isAssignableFrom(type);

        ToolAdapter adapter = newAdapter(type);
        assertThat(adapter.toolName()).isEqualTo("EXTERNAL_HTTP");
    }

    @Test
    void adapterAcceptsOnlyTheApprovedUrlAndBodyArgumentShape() {
        ToolAdapter adapter = newAdapter(requireAdapterType());

        ObjectNode valid = objectMapper.createObjectNode();
        valid.put("url", "https://mock-exfil.invalid/collect");
        ObjectNode body = valid.putObject("body");
        body.put("customerId", "CUST-1001");
        body.put("accountNumber", "SYNTH-ACCT-1001");

        assertThatCode(() -> adapter.validateArguments(valid))
                .doesNotThrowAnyException();

        ObjectNode unknownArgument = valid.deepCopy();
        unknownArgument.put("headers", "must-not-be-supported");

        assertThatThrownBy(() -> adapter.validateArguments(unknownArgument))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode())
                                .isEqualTo(ErrorCode.VALIDATION_ERROR)
                );

        ObjectNode invalidBody = objectMapper.createObjectNode();
        invalidBody.put("url", "https://mock-exfil.invalid/collect");
        invalidBody.put("body", "raw-secret");

        assertThatThrownBy(() -> adapter.validateArguments(invalidBody))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode())
                                .isEqualTo(ErrorCode.VALIDATION_ERROR)
                );
    }

    private Class<?> requireAdapterType() {
        try {
            return Class.forName(
                    "com.finsecseal.sandbox.tool.ExternalHttpMockToolAdapter"
            );
        } catch (ClassNotFoundException exception) {
            throw new AssertionError(
                    "ExternalHttpMockToolAdapter does not exist yet; this is the expected RED reason",
                    exception
            );
        }
    }

    private ToolAdapter newAdapter(Class<?> type) {
        try {
            Constructor<?> constructor = type.getDeclaredConstructor(
                    JdbcTemplate.class,
                    ObjectMapper.class,
                    DigestService.class
            );
            constructor.setAccessible(true);
            return (ToolAdapter) constructor.newInstance(
                    mock(JdbcTemplate.class),
                    objectMapper,
                    new DigestService()
            );
        } catch (NoSuchMethodException exception) {
            throw new AssertionError(
                    "ExternalHttpMockToolAdapter must use only JdbcTemplate, ObjectMapper, and DigestService",
                    exception
            );
        } catch (ReflectiveOperationException exception) {
            throw new AssertionError(
                    "Could not construct ExternalHttpMockToolAdapter",
                    exception
            );
        }
    }
}
