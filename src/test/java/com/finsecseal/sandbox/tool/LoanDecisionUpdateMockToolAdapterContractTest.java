package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

class LoanDecisionUpdateMockToolAdapterContractTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final LoanDecisionUpdateMockToolAdapter adapter =
            new LoanDecisionUpdateMockToolAdapter(
                    new JdbcTemplate(),
                    objectMapper
            );

    @Test
    void acceptsOnlyTheApprovedFa05MutationShape() {
        ObjectNode arguments = validArguments();

        assertThatCode(() -> adapter.validateArguments(arguments))
                .doesNotThrowAnyException();
    }

    @Test
    void rejectsUnknownArgumentsThatCouldSpoofTrustedContext() {
        ObjectNode arguments = validArguments();
        arguments.put("namespaceId", "attacker-controlled");

        assertValidationError(arguments);
    }

    @Test
    void rejectsBlankCaseId() {
        ObjectNode arguments = validArguments();
        arguments.put("caseId", " ");

        assertValidationError(arguments);
    }

    @Test
    void rejectsUnsupportedDecisionValue() {
        ObjectNode arguments = validArguments();
        arguments.put("decision", "PENDING");

        assertValidationError(arguments);
    }

    @Test
    void rejectsNonObjectArguments() {
        assertThatThrownBy(() ->
                adapter.validateArguments(objectMapper.createArrayNode()))
                .isInstanceOfSatisfying(
                        BusinessException.class,
                        exception -> org.assertj.core.api.Assertions
                                .assertThat(exception.errorCode())
                                .isEqualTo(ErrorCode.VALIDATION_ERROR)
                );
    }

    private ObjectNode validArguments() {
        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.put("caseId", "CASE-1001");
        arguments.put("decision", "APPROVED");
        return arguments;
    }

    private void assertValidationError(ObjectNode arguments) {
        assertThatThrownBy(() -> adapter.validateArguments(arguments))
                .isInstanceOfSatisfying(
                        BusinessException.class,
                        exception -> org.assertj.core.api.Assertions
                                .assertThat(exception.errorCode())
                                .isEqualTo(ErrorCode.VALIDATION_ERROR)
                );
    }
}
