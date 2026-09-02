package com.finsecseal.sandbox.tool;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.sandbox.SandboxExecutionContext;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

@Component
public final class CustomerDataReadToolAdapter implements ToolAdapter {

    public static final String TOOL_NAME = "CUSTOMER_DATA_READ";
    private static final int MAX_CUSTOMERS = 20;
    private static final int MAX_FIELDS = 20;
    private static final Set<String> ALLOWED_ARGUMENTS = Set.of("customerIds", "fields");

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public CustomerDataReadToolAdapter(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    @Override
    public String toolName() {
        return TOOL_NAME;
    }

    @Override
    public void validateArguments(JsonNode arguments) {
        if (arguments == null || !arguments.isObject()) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "CUSTOMER_DATA_READ arguments must be an object");
        }
        Set<String> actualFields = new HashSet<>();
        arguments.properties().forEach(entry -> actualFields.add(entry.getKey()));
        if (!ALLOWED_ARGUMENTS.containsAll(actualFields)) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "CUSTOMER_DATA_READ contains unknown arguments");
        }
        requireTextArray(arguments, "customerIds", MAX_CUSTOMERS);
        requireTextArray(arguments, "fields", MAX_FIELDS);
    }

    @Override
    public ToolExecutionResult execute(SandboxExecutionContext context, JsonNode arguments) {
        validateArguments(arguments);
        List<String> customerIds = requireTextArray(arguments, "customerIds", MAX_CUSTOMERS);
        List<String> fields = requireTextArray(arguments, "fields", MAX_FIELDS);

        ObjectNode output = objectMapper.createObjectNode();
        output.put("status", 200);
        ArrayNode rows = output.putArray("rows");

        for (String customerId : customerIds) {
            List<CustomerSnapshot> matches = jdbcTemplate.query("""
                    select customer_key, profile_json::text
                      from sandbox_customers
                     where namespace_id = ? and customer_key = ?
                    """, (resultSet, rowNumber) -> new CustomerSnapshot(
                    resultSet.getString("customer_key"),
                    parseJson(resultSet.getString("profile_json"))
            ), context.namespaceId(), customerId);
            if (matches.isEmpty()) {
                continue;
            }

            CustomerSnapshot customer = matches.getFirst();
            ObjectNode row = rows.addObject();
            row.put("customerId", customer.customerId());
            ObjectNode projectedFields = row.putObject("fields");
            for (String field : fields) {
                JsonNode value = customer.profile().get(field);
                if (value != null) {
                    projectedFields.set(field, value.deepCopy());
                }
            }
        }
        return new ToolExecutionResult(output, false);
    }

    private List<String> requireTextArray(JsonNode arguments, String field, int maximumSize) {
        if (arguments == null || !arguments.isObject() || !arguments.path(field).isArray()) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, field + " must be an array");
        }
        ArrayNode array = (ArrayNode) arguments.path(field);
        if (array.isEmpty() || array.size() > maximumSize) {
            throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    field + " must contain between 1 and " + maximumSize + " items"
            );
        }
        List<String> values = new ArrayList<>();
        array.forEach(node -> {
            if (!node.isString() || node.asString().isBlank() || node.asString().length() > 80) {
                throw new BusinessException(ErrorCode.VALIDATION_ERROR, field + " contains an invalid value");
            }
            values.add(node.asString());
        });
        return List.copyOf(values);
    }

    private JsonNode parseJson(String value) {
        try {
            return objectMapper.readTree(value);
        } catch (Exception exception) {
            throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, "Sandbox customer JSON is invalid");
        }
    }

    private record CustomerSnapshot(String customerId, JsonNode profile) {
    }
}
