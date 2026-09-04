package com.finsecseal.runtime.ai;

import com.finsecseal.attack.AttackVariant;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.runtime.ToolProposal;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

public final class HttpAgentAiClient implements AgentAiClient {

    private static final int MAX_REQUEST_BYTES = 512 * 1024;
    private static final int MAX_RESPONSE_BYTES = 256 * 1024;
    private static final int MAX_ATTEMPTS = 3;
    private static final long RETRY_BASE_DELAY_MS = 150L;
    private static final Set<String> ALLOWED_FINISH_REASONS = Set.of("tool_call", "stop");

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final AgentRunContextResolver runContextResolver;
    private final URI stepEndpoint;
    private final Duration requestTimeout;

    public HttpAgentAiClient(
            HttpClient httpClient,
            ObjectMapper objectMapper,
            AgentRunContextResolver runContextResolver,
            URI baseUrl,
            Duration requestTimeout
    ) {
        this.httpClient = requireNonNull(httpClient, "HTTP client");
        this.objectMapper = requireNonNull(objectMapper, "ObjectMapper");
        this.runContextResolver = requireNonNull(runContextResolver, "Agent run context resolver");
        this.stepEndpoint = stepEndpoint(requireNonNull(baseUrl, "AI base URL"));
        this.requestTimeout = requirePositive(requestTimeout, "AI request timeout");
    }

    @Override
    public AgentTurnResponse propose(AgentTurnRequest request) {
        AgentStepResponse response = executeStep(new AgentStepRequest(
                request.runId(),
                request.caseRunId(),
                request.traceId(),
                request.caseKey(),
                request.currentApplicantId(),
                request.attackVariant(),
                null
        ));

        if (!(response.action() instanceof ToolProposalAction toolProposalAction)) {
            throw evidenceIncomplete("AI returned FINAL_RESPONSE when a Tool Proposal was required");
        }
        return new AgentTurnResponse(
                response.provider(),
                response.model(),
                response.finishReason(),
                toolProposalAction.proposal(),
                response.latencyMs()
        );
    }

    @Override
    public ToolResultDeliveryResponse deliverToolResult(ToolResultDeliveryRequest request) {
        AgentStepResponse response = executeStep(new AgentStepRequest(
                request.runId(),
                request.caseRunId(),
                request.traceId(),
                request.caseKey(),
                request.currentApplicantId(),
                request.attackVariant(),
                new PreviousToolResult(
                        request.toolName(),
                        request.toolOutput(),
                        request.sourceEventId(),
                        request.sourceSequence()
                )
        ));

        return new ToolResultDeliveryResponse(
                response.provider(),
                response.model(),
                ToolResultDeliveryStatus.DELIVERED,
                response.action(),
                response.latencyMs()
        );
    }

    @Override
    public AgentStepResponse executeStep(AgentStepRequest request) {
        validateRequest(request);
        byte[] requestBody = serializeRequest(request);
        if (requestBody.length > MAX_REQUEST_BYTES) {
            throw evidenceIncomplete("AI step request exceeds 512 KiB");
        }

        HttpRequest httpRequest = HttpRequest.newBuilder(stepEndpoint)
                .timeout(requestTimeout)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(requestBody))
                .build();

        byte[] responseBody = sendStepRequest(httpRequest);
        return parseStepResponse(responseBody);
    }

    private byte[] sendStepRequest(HttpRequest httpRequest) {
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                HttpResponse<InputStream> response = httpClient.send(
                        httpRequest,
                        HttpResponse.BodyHandlers.ofInputStream()
                );
                int statusCode = response.statusCode();

                if (isRetryableStatus(statusCode)) {
                    closeQuietly(response.body());
                    if (attempt == MAX_ATTEMPTS) {
                        throw operationalFailure(
                                "AI service returned retryable HTTP "
                                        + statusCode
                                        + " after "
                                        + MAX_ATTEMPTS
                                        + " attempts",
                                null
                        );
                    }
                    sleepBeforeRetry(attempt);
                    continue;
                }

                if (statusCode >= 500) {
                    closeQuietly(response.body());
                    throw operationalFailure(
                            "AI service returned HTTP " + statusCode,
                            null
                    );
                }

                if (statusCode < 200 || statusCode >= 300) {
                    closeQuietly(response.body());
                    throw evidenceIncomplete(
                            "AI service rejected the step request with HTTP " + statusCode
                    );
                }

                try {
                    return readBoundedResponse(response.body());
                } finally {
                    closeQuietly(response.body());
                }
            } catch (java.net.http.HttpTimeoutException exception) {
                if (attempt == MAX_ATTEMPTS) {
                    throw operationalFailure(
                            "AI step request timed out after " + MAX_ATTEMPTS + " attempts",
                            exception
                    );
                }
                sleepBeforeRetry(attempt);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw operationalFailure("AI step request was interrupted", exception);
            } catch (IOException exception) {
                if (attempt == MAX_ATTEMPTS) {
                    throw operationalFailure(
                            "AI step request failed after " + MAX_ATTEMPTS + " attempts",
                            exception
                    );
                }
                sleepBeforeRetry(attempt);
            }
        }

        throw operationalFailure("AI step request exhausted retry attempts", null);
    }

    private boolean isRetryableStatus(int statusCode) {
        return statusCode == 408
                || statusCode == 429
                || statusCode == 502
                || statusCode == 503
                || statusCode == 504;
    }

    private byte[] readBoundedResponse(InputStream body) throws IOException {
        if (body == null) {
            return new byte[0];
        }
        byte[] bytes = body.readNBytes(MAX_RESPONSE_BYTES + 1);
        if (bytes.length > MAX_RESPONSE_BYTES) {
            throw evidenceIncomplete("AI step response exceeds 256 KiB");
        }
        return bytes;
    }

    private void sleepBeforeRetry(int failedAttempt) {
        long baseDelay = RETRY_BASE_DELAY_MS * (1L << (failedAttempt - 1));
        long jitterBound = Math.max(1L, baseDelay / 3L);
        long delayMs = baseDelay + ThreadLocalRandom.current().nextLong(jitterBound);

        try {
            Thread.sleep(delayMs);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw operationalFailure("AI step retry backoff was interrupted", exception);
        }
    }

    private void closeQuietly(InputStream body) {
        if (body == null) {
            return;
        }
        try {
            body.close();
        } catch (IOException ignored) {
            // The response is already being discarded or fully consumed.
        }
    }

    private byte[] serializeRequest(AgentStepRequest request) {
        AgentRunContextResolver.ResolvedRunContext trustedContext =
                runContextResolver.resolve(request.runId());

        ObjectNode root = objectMapper.createObjectNode();
        root.put("releaseId", trustedContext.releaseId().toString());
        root.put("testRunId", request.runId().toString());
        root.put("testCaseRunId", request.caseRunId().toString());
        root.put("traceId", request.traceId().toString());
        root.put("caseKey", request.caseKey());
        root.put("currentApplicantId", request.currentApplicantId());
        root.set("attackVariant", attackVariantJson(request.attackVariant()));

        if (request.previousToolResult() == null) {
            root.putNull("previousToolResult");
        } else {
            PreviousToolResult previous = request.previousToolResult();
            ObjectNode previousNode = root.putObject("previousToolResult");
            previousNode.put("toolName", previous.toolName());
            previousNode.set("output", previous.output().deepCopy());
            previousNode.put("sourceEventId", previous.sourceEventId().toString());
            previousNode.put("sourceSequence", previous.sourceSequence());
        }

        try {
            return objectMapper.writeValueAsBytes(root);
        } catch (Exception exception) {
            throw evidenceIncomplete("AI step request could not be serialized");
        }
    }

    private ObjectNode attackVariantJson(AttackVariant variant) {
        ObjectNode node = objectMapper.createObjectNode();
        node.put("category", variant.category());
        node.put("severity", variant.severity());
        node.put("targetTool", variant.targetTool());
        node.put("invariantId", variant.invariantId());
        node.put("oracleType", variant.oracleType());
        node.set("toolArguments", variant.toolArguments().deepCopy());
        node.put("variantHash", variant.variantHash());
        return node;
    }

    private AgentStepResponse parseStepResponse(byte[] body) {
        if (body == null || body.length == 0) {
            throw evidenceIncomplete("AI service returned an empty response body");
        }

        JsonNode root;
        try {
            root = objectMapper.readTree(new String(body, StandardCharsets.UTF_8));
        } catch (Exception exception) {
            throw evidenceIncomplete("AI service returned malformed JSON");
        }
        if (root == null || !root.isObject()) {
            throw evidenceIncomplete("AI step response must be a JSON object");
        }

        String provider = requiredText(root, "provider");
        String model = requiredText(root, "model");
        String finishReason = requiredText(root, "finishReason");
        if (!ALLOWED_FINISH_REASONS.contains(finishReason)) {
            throw evidenceIncomplete("AI step response contains an unsupported finishReason");
        }

        JsonNode latencyNode = root.path("latencyMs");
        if (!latencyNode.isIntegralNumber() || latencyNode.asLong() < 0) {
            throw evidenceIncomplete("AI step response latencyMs must be a non-negative integer");
        }

        JsonNode actionNode = root.path("action");
        if (!actionNode.isObject()) {
            throw evidenceIncomplete("AI step response action must be an object");
        }
        String actionType = requiredText(actionNode, "type");

        AgentAction action = switch (actionType) {
            case "TOOL_PROPOSAL" -> parseToolProposalAction(actionNode);
            case "FINAL_RESPONSE" -> parseFinalResponseAction(actionNode);
            default -> throw evidenceIncomplete("AI step response contains an unsupported action type");
        };

        if (action instanceof ToolProposalAction && !"tool_call".equals(finishReason)) {
            throw evidenceIncomplete("TOOL_PROPOSAL requires finishReason=tool_call");
        }
        if (action instanceof FinalResponseAction && !"stop".equals(finishReason)) {
            throw evidenceIncomplete("FINAL_RESPONSE requires finishReason=stop");
        }

        return new AgentStepResponse(
                provider,
                model,
                finishReason,
                action,
                latencyNode.asLong()
        );
    }

    private ToolProposalAction parseToolProposalAction(JsonNode actionNode) {
        String toolName = requiredText(actionNode, "toolName");
        JsonNode arguments = actionNode.path("arguments");
        if (!arguments.isObject()) {
            throw evidenceIncomplete("AI Tool Proposal arguments must be a JSON object");
        }
        return new ToolProposalAction(new ToolProposal(toolName, arguments.deepCopy()));
    }

    private FinalResponseAction parseFinalResponseAction(JsonNode actionNode) {
        String content = requiredText(actionNode, "content");
        if (content.length() > 8_192) {
            throw evidenceIncomplete("AI final response exceeds 8192 characters");
        }
        return new FinalResponseAction(content);
    }

    private String requiredText(JsonNode node, String fieldName) {
        JsonNode value = node.path(fieldName);
        if (!value.isString() || value.asString().isBlank()) {
            throw evidenceIncomplete("AI step response is missing " + fieldName);
        }
        return value.asString();
    }

    private void validateRequest(AgentStepRequest request) {
        if (request == null
                || request.runId() == null
                || request.caseRunId() == null
                || request.traceId() == null
                || request.caseKey() == null
                || request.caseKey().isBlank()
                || request.currentApplicantId() == null
                || request.currentApplicantId().isBlank()
                || request.attackVariant() == null) {
            throw evidenceIncomplete("AI step request is incomplete");
        }

        AttackVariant variant = request.attackVariant();
        if (variant.category() == null
                || variant.severity() == null
                || variant.targetTool() == null
                || variant.invariantId() == null
                || variant.oracleType() == null
                || variant.toolArguments() == null
                || !variant.toolArguments().isObject()
                || variant.variantHash() == null) {
            throw evidenceIncomplete("AI step attack variant is incomplete");
        }
        if (!variant.variantHash().matches("sha256:[0-9a-f]{64}")) {
            throw evidenceIncomplete("AI step attack variant variantHash must match sha256:[0-9a-f]{64}");
        }

        PreviousToolResult previous = request.previousToolResult();
        if (previous != null) {
            if (previous.toolName() == null
                    || previous.toolName().isBlank()
                    || previous.output() == null
                    || !previous.output().isObject()
                    || previous.sourceEventId() == null
                    || previous.sourceSequence() <= 0) {
                throw evidenceIncomplete("Previous Tool Result is incomplete");
            }
        }
    }

    private static URI stepEndpoint(URI baseUrl) {
        String raw = baseUrl.toString();
        while (raw.endsWith("/")) {
            raw = raw.substring(0, raw.length() - 1);
        }
        return URI.create(raw + "/v1/agent/steps");
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

    private BusinessException evidenceIncomplete(String message) {
        return new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, message);
    }

    private BusinessException operationalFailure(String message, Exception cause) {
        if (cause == null) {
            return new BusinessException(ErrorCode.INTERNAL_ERROR, message);
        }
        return new BusinessException(ErrorCode.INTERNAL_ERROR, message + ": " + cause.getClass().getSimpleName());
    }
}
