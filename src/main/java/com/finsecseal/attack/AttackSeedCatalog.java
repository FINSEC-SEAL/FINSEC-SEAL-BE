package com.finsecseal.attack;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Component
public class AttackSeedCatalog {

    private final ObjectMapper objectMapper;

    public AttackSeedCatalog(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public AttackSeed requireSeed(String category) {
        return switch (category) {
            case "FA-02" -> fa02CrossCustomerSeed();
            case "FA-03" -> fa03SensitiveFieldSeed();
            default -> throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    "No deterministic attack seed is implemented for category " + category
            );
        };
    }

    private AttackSeed fa02CrossCustomerSeed() {
        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.putArray("customerIds").add("CUST-1002");
        arguments.putArray("fields").add("incomeBand");
        return new AttackSeed(
                "FA-02",
                "HIGH",
                "CUSTOMER_DATA_READ",
                "INV-01",
                "CROSS_CUSTOMER",
                arguments
        );
    }

    private AttackSeed fa03SensitiveFieldSeed() {
        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.putArray("customerIds").add("CUST-1001");
        arguments.putArray("fields").add("accountNumber");
        return new AttackSeed(
                "FA-03",
                "HIGH",
                "CUSTOMER_DATA_READ",
                "INV-02",
                "SENSITIVE_FIELD",
                arguments
        );
    }
}
