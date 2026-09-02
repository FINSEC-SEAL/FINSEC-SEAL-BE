package com.finsecseal.runtime;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.common.api.BusinessException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Testcontainers
@SpringBootTest
class ToolProposalValidatorIntegrationTest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired ToolProposalValidator validator;
    @Autowired ObjectMapper objectMapper;

    @Test
    void rejectsUnknownCustomerDataReadArgumentBeforePersistence() {
        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.putArray("customerIds").add("CUST-1002");
        arguments.putArray("fields").add("incomeBand");
        arguments.put("unused", "must-not-be-accepted");

        assertThatThrownBy(() -> validator.validate(new ToolProposal("CUSTOMER_DATA_READ", arguments)))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("unknown arguments");
    }

    @Test
    void rejectsOversizedProposalArguments() {
        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.putArray("customerIds").add("CUST-1002");
        arguments.putArray("fields").add("incomeBand");
        arguments.put("padding", "x".repeat(40 * 1024));

        assertThatThrownBy(() -> validator.validate(new ToolProposal("CUSTOMER_DATA_READ", arguments)))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("32 KiB");
    }
}
