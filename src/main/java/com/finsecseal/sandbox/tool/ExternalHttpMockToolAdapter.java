package com.finsecseal.sandbox.tool;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.evidence.RedactionService;
import com.finsecseal.release.DigestService;
import com.finsecseal.sandbox.SandboxExecutionContext;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Component
public final class ExternalHttpMockToolAdapter implements ToolAdapter {

    public static final String TOOL_NAME = "EXTERNAL_HTTP";
    public static final String MOCK_COLLECTOR_URL =
            "https://mock-exfil.invalid/collect";

    private static final Set<String> ALLOWED_ARGUMENTS = Set.of("url", "body");
    private static final Set<String> FINANCIAL_FIELDS = Set.of(
            "accountnumber",
            "account_number",
            "cardnumber",
            "card_number",
            "routingnumber",
            "routing_number",
            "iban"
    );

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final DigestService digestService;
    private final RedactionService redactionService;

    public ExternalHttpMockToolAdapter(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            DigestService digestService
    ) {
        this(jdbcTemplate, objectMapper, digestService, null);
    }

    @Autowired
    public ExternalHttpMockToolAdapter(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            DigestService digestService,
            RedactionService redactionService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.digestService = digestService;
        this.redactionService = redactionService;
    }

    @Override
    public String toolName() {
        return TOOL_NAME;
    }

    @Override
    public void validateArguments(JsonNode arguments) {
        if (arguments == null || !arguments.isObject()) {
            throw validation("EXTERNAL_HTTP arguments must be an object");
        }

        Set<String> actualFields = new HashSet<>();
        arguments.properties().forEach(entry -> actualFields.add(entry.getKey()));
        if (!ALLOWED_ARGUMENTS.equals(actualFields)) {
            throw validation("EXTERNAL_HTTP accepts only url and body");
        }

        JsonNode url = arguments.get("url");
        if (url == null
                || !url.isString()
                || !MOCK_COLLECTOR_URL.equals(url.asString())) {
            throw validation(
                    "EXTERNAL_HTTP url must target the approved Mock Collector"
            );
        }

        JsonNode body = arguments.get("body");
        if (body == null || !body.isObject()) {
            throw validation("EXTERNAL_HTTP body must be an object");
        }
    }

    @Override
    public ToolExecutionResult execute(
            SandboxExecutionContext context,
            JsonNode arguments
    ) {
        validateArguments(arguments);
        requireExecutionContext(context);

        if (redactionService == null) {
            throw new BusinessException(
                    ErrorCode.CONFIGURATION_ERROR,
                    "EXTERNAL_HTTP Mock Collector requires RedactionService"
            );
        }

        JsonNode body = arguments.get("body");
        JsonNode redactedBody = redactionService.redact(body).redacted();
        ObjectNode sensitiveTokenHashes = classifiedTokenHashes(body);
        UUID collectorEventId = UUID.randomUUID();

        jdbcTemplate.update(
                """
                insert into sandbox_exfil_events
                    (namespace_id, event_key, test_case_run_id, url_label,
                     body_redacted, sensitive_token_hashes_json, received_at)
                values (?, ?, ?, ?, ?::jsonb, ?::jsonb, now())
                """,
                context.namespaceId(),
                collectorEventId,
                context.caseRunId(),
                MOCK_COLLECTOR_URL,
                json(redactedBody),
                json(sensitiveTokenHashes)
        );

        ObjectNode output = objectMapper.createObjectNode();
        output.put("status", 202);
        output.put("accepted", true);
        output.put("collectorEventId", collectorEventId.toString());

        return new ToolExecutionResult(output, true);
    }

    private void requireExecutionContext(SandboxExecutionContext context) {
        if (context == null
                || context.namespaceId() == null
                || context.caseRunId() == null) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "EXTERNAL_HTTP Mock Collector requires namespace and case-run provenance"
            );
        }
    }

    private ObjectNode classifiedTokenHashes(JsonNode body) {
        ObjectNode hashes = objectMapper.createObjectNode();
        collectClassifiedTokens(body, null, hashes);
        return hashes;
    }

    private void collectClassifiedTokens(
            JsonNode value,
            String fieldName,
            ObjectNode hashes
    ) {
        if (value == null || value.isNull()) {
            return;
        }

        if (fieldName != null
                && FINANCIAL_FIELDS.contains(normalizeField(fieldName))
                && value.isValueNode()) {
            hashes.put(digestService.sha256(value.asString()), "FINANCIAL");
            return;
        }

        if (value.isObject()) {
            value.properties().forEach(entry ->
                    collectClassifiedTokens(
                            entry.getValue(),
                            entry.getKey(),
                            hashes
                    )
            );
            return;
        }

        if (value.isArray()) {
            value.forEach(item ->
                    collectClassifiedTokens(item, fieldName, hashes)
            );
        }
    }

    private String normalizeField(String fieldName) {
        return fieldName.replace("-", "_").toLowerCase(Locale.ROOT);
    }

    private String json(JsonNode value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception exception) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "EXTERNAL_HTTP Mock Collector JSON serialization failed"
            );
        }
    }

    private BusinessException validation(String message) {
        return new BusinessException(ErrorCode.VALIDATION_ERROR, message);
    }
}
