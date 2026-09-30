package com.finsecseal.runtime.ai;

import com.finsecseal.attack.AttackMutationCandidateValidator.TrustedSeed;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

public final class HttpAttackMutationAiClient implements AttackMutationAiClient {

    private static final int MAX_REQUEST_BYTES = 16 * 1024;
    private static final int MAX_RESPONSE_BYTES = 256 * 1024;

    private final ObjectMapper objectMapper;
    private final URI endpoint;
    private final Duration requestTimeout;
    private final String apiKey;
    private final String modelName;
    private final AiHttpTransport transport;

    public HttpAttackMutationAiClient(
            HttpClient httpClient,
            ObjectMapper objectMapper,
            URI baseUrl,
            Duration requestTimeout,
            String apiKey,
            String modelName
    ) {
        if (httpClient == null || objectMapper == null || baseUrl == null) {
            throw new IllegalArgumentException("HTTP client, ObjectMapper, and AI base URL are required");
        }
        if (requestTimeout == null || requestTimeout.isZero() || requestTimeout.isNegative()) {
            throw new IllegalArgumentException("AI request timeout must be positive");
        }
        if (modelName == null || modelName.isBlank()) {
            throw new IllegalArgumentException("Attack mutation model name is required");
        }
        this.objectMapper = objectMapper;
        this.endpoint = endpoint(baseUrl);
        this.requestTimeout = requestTimeout;
        this.apiKey = apiKey == null || apiKey.isBlank() ? null : apiKey;
        this.modelName = modelName;
        this.transport = new AiHttpTransport(httpClient, 3, 150L);
    }

    @Override
    public GenerationResponse generate(TrustedSeed seed, int count) {
        if (seed == null || count < 1 || count > 20) {
            throw incomplete("Attack mutation generation request is invalid");
        }

        ObjectNode body = objectMapper.createObjectNode();
        body.put("parentSeedId", seed.parentSeedId().toString());
        body.put("category", seed.category());
        body.put("severity", seed.severity());
        body.put("targetTool", seed.targetTool());
        body.put("expectedInvariant", seed.expectedInvariant());
        body.put("oracleType", seed.oracleType());
        body.put("deliveryChannel", seed.deliveryChannel());
        body.put("parentDocumentPayload", seed.parentDocumentPayload());
        body.put("count", count);
        body.put("modelName", modelName);

        byte[] request;
        try {
            request = objectMapper.writeValueAsBytes(body);
        } catch (RuntimeException exception) {
            throw incomplete("Attack mutation generation request could not be serialized");
        }
        if (request.length > MAX_REQUEST_BYTES) {
            throw incomplete("Attack mutation generation request exceeds 16 KiB");
        }

        byte[] response = transport.postJson(
                endpoint,
                requestTimeout,
                request,
                apiKey,
                MAX_RESPONSE_BYTES,
                "AI attack mutation request"
        );
        return parseResponse(response, count);
    }

    private GenerationResponse parseResponse(byte[] bytes, int expectedCount) {
        JsonNode root;
        try {
            root = objectMapper.readTree(new String(bytes, StandardCharsets.UTF_8));
        } catch (RuntimeException exception) {
            throw incomplete("AI attack mutation response must be valid JSON");
        }
        if (root == null || !root.isObject()) {
            throw incomplete("AI attack mutation response must be a JSON object");
        }
        String provider = requiredText(root, "provider");
        String model = requiredText(root, "model");
        JsonNode candidatesNode = root.path("candidates");
        if (!candidatesNode.isArray() || candidatesNode.size() != expectedCount) {
            throw incomplete("AI attack mutation response has an unexpected candidate count");
        }
        List<byte[]> candidates = new ArrayList<>(expectedCount);
        try {
            for (JsonNode candidate : candidatesNode) {
                if (!candidate.isObject()) {
                    throw incomplete("AI attack mutation candidate must be an object");
                }
                candidates.add(objectMapper.writeValueAsBytes(candidate));
            }
        } catch (BusinessException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw incomplete("AI attack mutation candidate could not be serialized");
        }

        return new GenerationResponse(
                provider,
                model,
                candidates,
                tokenUsage(root.path("tokenUsage"))
        );
    }

    private ModelTokenUsage tokenUsage(JsonNode node) {
        if (!node.isObject()) {
            throw incomplete("AI attack mutation response is missing token usage");
        }
        JsonNode prompt = node.path("promptTokens");
        JsonNode completion = node.path("completionTokens");
        JsonNode total = node.path("totalTokens");
        if (!prompt.isIntegralNumber() || !completion.isIntegralNumber() || !total.isIntegralNumber()) {
            throw incomplete("AI attack mutation token usage must contain integers");
        }
        try {
            return new ModelTokenUsage(prompt.asLong(), completion.asLong(), total.asLong());
        } catch (BusinessException exception) {
            throw incomplete("AI attack mutation token usage is invalid");
        }
    }

    private String requiredText(JsonNode node, String field) {
        JsonNode value = node.path(field);
        if (!value.isString() || value.asString().isBlank()) {
            throw incomplete("AI attack mutation response is missing " + field);
        }
        return value.asString();
    }

    private static URI endpoint(URI baseUrl) {
        String raw = baseUrl.toString();
        while (raw.endsWith("/")) {
            raw = raw.substring(0, raw.length() - 1);
        }
        return URI.create(raw + "/v1/attacks/mutations");
    }

    private static BusinessException incomplete(String message) {
        return new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, message);
    }
}
