package com.finsecseal.runtime.ai;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

public final class ContractCandidateAiClient {

    private static final int MAX_REQUEST_BYTES = 512 * 1024;
    private static final int MAX_RESPONSE_BYTES = 256 * 1024;

    private final ObjectMapper objectMapper;
    private final URI endpoint;
    private final Duration requestTimeout;
    private final String apiKey;
    private final AiHttpTransport transport;

    public ContractCandidateAiClient(
            HttpClient httpClient,
            ObjectMapper objectMapper,
            URI baseUrl,
            Duration requestTimeout,
            String apiKey
    ) {
        this.objectMapper = requireNonNull(objectMapper, "ObjectMapper");
        this.endpoint = endpoint(requireNonNull(baseUrl, "AI base URL"));
        this.requestTimeout = requirePositive(requestTimeout, "AI request timeout");
        this.apiKey = apiKey == null || apiKey.isBlank() ? null : apiKey;
        this.transport = new AiHttpTransport(httpClient, 3, 150L);
    }

    public CandidateModelResponse generate(
            String promptVersion,
            String instructions,
            String inputJson
    ) {
        if (promptVersion == null || promptVersion.isBlank()
                || instructions == null || instructions.isBlank()
                || inputJson == null || inputJson.isBlank()) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Contract candidate generation request is incomplete"
            );
        }

        ObjectNode body = objectMapper.createObjectNode();
        body.put("promptVersion", promptVersion);
        body.put("instructions", instructions);
        body.put("inputJson", inputJson);

        byte[] requestBytes;
        try {
            requestBytes = objectMapper.writeValueAsBytes(body);
        } catch (RuntimeException exception) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Contract candidate generation request could not be serialized"
            );
        }

        if (requestBytes.length > MAX_REQUEST_BYTES) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Contract candidate generation request exceeds 512 KiB"
            );
        }

        byte[] responseBytes = transport.postJson(
                endpoint,
                requestTimeout,
                requestBytes,
                apiKey,
                MAX_RESPONSE_BYTES,
                "AI contract candidate request"
        );
        return parseResponse(responseBytes);
    }

    private CandidateModelResponse parseResponse(byte[] body) {
        if (body == null || body.length == 0) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "AI contract candidate response is empty"
            );
        }

        JsonNode root;
        try {
            root = objectMapper.readTree(new String(body, StandardCharsets.UTF_8));
        } catch (RuntimeException exception) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "AI contract candidate response must be valid JSON"
            );
        }

        if (root == null || !root.isObject()) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "AI contract candidate response must be a JSON object"
            );
        }

        String provider = requiredText(root, "provider");
        String model = requiredText(root, "model");
        String content = requiredText(root, "content");

        JsonNode latencyNode = root.path("latencyMs");
        if (!latencyNode.isIntegralNumber() || latencyNode.asLong() < 0) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "AI contract candidate response latencyMs must be a non-negative integer"
            );
        }

        return new CandidateModelResponse(provider, model, content, latencyNode.asLong());
    }

    private String requiredText(JsonNode node, String fieldName) {
        JsonNode value = node.path(fieldName);
        if (!value.isString() || value.asString().isBlank()) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "AI contract candidate response is missing " + fieldName
            );
        }
        return value.asString();
    }

    private static URI endpoint(URI baseUrl) {
        String raw = baseUrl.toString();
        while (raw.endsWith("/")) {
            raw = raw.substring(0, raw.length() - 1);
        }
        return URI.create(raw + "/v1/agent/contract-candidates");
    }

    private static <T> T requireNonNull(T value, String name) {
        if (value == null) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }

    private static Duration requirePositive(Duration value, String name) {
        if (value == null || value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(name + " must be positive");
        }
        return value;
    }

    public record CandidateModelResponse(String provider, String model, String content, long latencyMs) {
    }
}
