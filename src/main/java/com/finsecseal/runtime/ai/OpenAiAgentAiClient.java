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
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * Lightweight OpenAI-backed Agent client. This adapter asks the model to emit the
 * canonical AgentStepResponse JSON and parses it back into the in-process types.
 * Enable via property `finsec.ai.openai.enabled=true` and provide `OPENAI_API_KEY`.
 */
public final class OpenAiAgentAiClient implements AgentAiClient {

    private static final int MAX_REQUEST_BYTES = 512 * 1024;
    private static final int MAX_RESPONSE_BYTES = 512 * 1024;
    private static final int MAX_ATTEMPTS = 3;
    private static final long RETRY_BASE_DELAY_MS = 150L;
    private static final Set<String> ALLOWED_FINISH_REASONS = Set.of("tool_call", "stop");

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final AgentRunContextResolver runContextResolver;
    private final String apiKey;
    private final String model;
    private final Duration requestTimeout;

    public OpenAiAgentAiClient(
            HttpClient httpClient,
            ObjectMapper objectMapper,
            AgentRunContextResolver runContextResolver,
            String model,
            Duration requestTimeout,
            String apiKey
    ) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.runContextResolver = runContextResolver;
        this.model = model == null || model.isBlank() ? "gpt-4o-mini" : model;
        this.requestTimeout = requestTimeout == null ? Duration.ofSeconds(10) : requestTimeout;
        this.apiKey = apiKey == null || apiKey.isBlank() ? null : apiKey;
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

        byte[] requestBody = buildPayload(request);
        if (requestBody.length > MAX_REQUEST_BYTES) {
            throw evidenceIncomplete("AI step request exceeds size limits");
        }

        String prompt = "Respond with a single JSON object exactly matching the schema: {provider,model,finishReason,latencyMs,action} where action.type is either 'TOOL_PROPOSAL' with toolName and arguments object, or 'FINAL_RESPONSE' with content string. The JSON must be valid and no extra text.\nPAYLOAD:\n" + new String(requestBody, StandardCharsets.UTF_8);

        ObjectNode openaiRequest = objectMapper.createObjectNode();
        openaiRequest.put("model", model);
        ArrayNode messages = openaiRequest.putArray("messages");
        ObjectNode user = messages.addObject();
        user.put("role", "user");
        user.put("content", prompt);
        openaiRequest.put("temperature", 0.0);
        openaiRequest.put("max_tokens", 1500);

        HttpRequest httpRequest = HttpRequest.newBuilder(URI.create("https://api.openai.com/v1/chat/completions"))
                .timeout(requestTimeout)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("Authorization", "Bearer " + apiKey)
                .POST(HttpRequest.BodyPublishers.ofByteArray(serialize(openaiRequest)))
                .build();

        byte[] responseBody = sendRequestWithRetries(httpRequest);
        String content = parseOpenAiChatContent(responseBody);

        JsonNode root;
        try {
            root = objectMapper.readTree(content);
        } catch (Exception ex) {
            throw evidenceIncomplete("OpenAI response was not valid JSON: " + ex.getMessage());
        }

        return toAgentStepResponse(root);
    }

    private byte[] buildPayload(AgentStepRequest request) {
        AgentRunContextResolver.ResolvedAgentExecutionContext trustedContext = runContextResolver.resolve(
                request.runId(), request.caseKey(), request.currentApplicantId()
        );

        ObjectNode root = objectMapper.createObjectNode();
        root.put("releaseId", trustedContext.releaseId().toString());
        root.put("testRunId", request.runId().toString());
        root.put("testCaseRunId", request.caseRunId().toString());
        root.put("traceId", request.traceId().toString());
        root.put("caseKey", request.caseKey());
        root.put("currentApplicantId", request.currentApplicantId());
        root.set("agentContext", agentContextJson(trustedContext));
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

        return serialize(root);
    }

    private ObjectNode agentContextJson(AgentRunContextResolver.ResolvedAgentExecutionContext context) {
        ObjectNode node = objectMapper.createObjectNode();

        ObjectNode modelNode = node.putObject("model");
        modelNode.put("provider", context.model().provider());
        modelNode.put("name", context.model().name());
        modelNode.set("parameters", context.model().parameters().deepCopy());

        node.put("systemPrompt", context.systemPrompt());

        ObjectNode businessPurposeNode = node.putObject("businessPurpose");
        businessPurposeNode.put("code", context.businessContext().code());
        businessPurposeNode.put("description", context.businessContext().description());

        node.set("workflow", context.workflow().deepCopy());

        ArrayNode toolsNode = node.putArray("tools");
        for (AgentRunContextResolver.ToolContext tool : context.tools()) {
            ObjectNode toolNode = toolsNode.addObject();
            toolNode.put("name", tool.name());
            toolNode.put("description", tool.description());
            toolNode.set("inputSchema", tool.inputSchema().deepCopy());
        }

        AgentRunContextResolver.RuntimeCaseContext runtime = context.runtime();
        ObjectNode runtimeNode = node.putObject("runtime");
        runtimeNode.put("caseKey", runtime.caseKey());
        runtimeNode.put("currentApplicantId", runtime.currentApplicantId());
        runtimeNode.put("status", runtime.status());
        runtimeNode.set("context", runtime.context().deepCopy());
        ArrayNode allowedDocumentsNode = runtimeNode.putArray("allowedDocumentIds");
        runtime.allowedDocumentIds().forEach(allowedDocumentsNode::add);

        ArrayNode documentsNode = node.putArray("documents");
        for (AgentRunContextResolver.DocumentContext document : context.documents()) {
            ObjectNode documentNode = documentsNode.addObject();
            documentNode.put("documentId", document.documentId());
            documentNode.put("documentType", document.documentType());
            documentNode.put("content", document.content());
            documentNode.put("contentDigest", document.contentDigest());
            documentNode.put("trustLevel", document.trustLevel());
            documentNode.set("classification", document.classification().deepCopy());
        }

        return node;
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

    private byte[] serialize(JsonNode node) {
        try {
            return objectMapper.writeValueAsBytes(node);
        } catch (Exception ex) {
            throw evidenceIncomplete("AI step request could not be serialized");
        }
    }

    private byte[] sendRequestWithRetries(HttpRequest httpRequest) {
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                HttpResponse<InputStream> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofInputStream());
                int statusCode = response.statusCode();
                if (statusCode >= 500) {
                    closeQuietly(response.body());
                    throw operationalFailure("OpenAI returned HTTP " + statusCode, null);
                }
                if (statusCode < 200 || statusCode >= 300) {
                    closeQuietly(response.body());
                    throw evidenceIncomplete("OpenAI rejected the request with HTTP " + statusCode);
                }
                try {
                    byte[] body = response.body().readNBytes(MAX_RESPONSE_BYTES + 1);
                    if (body.length > MAX_RESPONSE_BYTES) {
                        throw evidenceIncomplete("OpenAI response too large");
                    }
                    return body;
                } finally {
                    closeQuietly(response.body());
                }
            } catch (java.net.http.HttpTimeoutException t) {
                if (attempt == MAX_ATTEMPTS) {
                    throw operationalFailure("OpenAI request timed out", t);
                }
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                throw operationalFailure("OpenAI request interrupted", ie);
            } catch (IOException ioe) {
                if (attempt == MAX_ATTEMPTS) {
                    throw operationalFailure("OpenAI request failed", ioe);
                }
            }
            sleepBeforeRetry(attempt);
        }
        throw operationalFailure("OpenAI request exhausted retries", null);
    }

    private void sleepBeforeRetry(int failedAttempt) {
        long baseDelay = RETRY_BASE_DELAY_MS * (1L << (failedAttempt - 1));
        long jitterBound = Math.max(1L, baseDelay / 3L);
        long delayMs = baseDelay + ThreadLocalRandom.current().nextLong(jitterBound);
        try {
            Thread.sleep(delayMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw operationalFailure("OpenAI retry interrupted", e);
        }
    }

    private void closeQuietly(InputStream body) {
        if (body == null) return;
        try { body.close(); } catch (IOException ignored) {}
    }

    private String parseOpenAiChatContent(byte[] body) {
        try {
            JsonNode root = objectMapper.readTree(new String(body, StandardCharsets.UTF_8));
            JsonNode choices = root.path("choices");
            if (!choices.isArray() || choices.size() == 0) {
                throw evidenceIncomplete("OpenAI response missing choices");
            }
            JsonNode message = choices.get(0).path("message");
            String content = message.path("content").asText(null);
            if (content == null) {
                content = choices.get(0).path("text").asText(null);
            }
            if (content == null) {
                throw evidenceIncomplete("OpenAI response did not contain textual content");
            }
            return content.trim();
        } catch (Exception ex) {
            throw evidenceIncomplete("Could not parse OpenAI response: " + ex.getMessage());
        }
    }

    private AgentStepResponse toAgentStepResponse(JsonNode root) {
        String provider = requiredText(root, "provider");
        String model = requiredText(root, "model");
        String finishReason = requiredText(root, "finishReason");
        if (!ALLOWED_FINISH_REASONS.contains(finishReason)) {
            throw evidenceIncomplete("unsupported finishReason from OpenAI: " + finishReason);
        }
        JsonNode latencyNode = root.path("latencyMs");
        long latency = latencyNode.isIntegralNumber() ? latencyNode.asLong() : 0L;

        JsonNode actionNode = root.path("action");
        if (!actionNode.isObject()) {
            throw evidenceIncomplete("action must be an object");
        }
        String actionType = requiredText(actionNode, "type");
        AgentAction action = switch (actionType) {
            case "TOOL_PROPOSAL" -> parseToolProposalAction(actionNode);
            case "FINAL_RESPONSE" -> parseFinalResponseAction(actionNode);
            default -> throw evidenceIncomplete("unsupported action type: " + actionType);
        };

        if (action instanceof ToolProposalAction && !"tool_call".equals(finishReason)) {
            throw evidenceIncomplete("TOOL_PROPOSAL requires finishReason=tool_call");
        }
        if (action instanceof FinalResponseAction && !"stop".equals(finishReason)) {
            throw evidenceIncomplete("FINAL_RESPONSE requires finishReason=stop");
        }

        return new AgentStepResponse(provider, model, finishReason, action, latency);
    }

    private ToolProposalAction parseToolProposalAction(JsonNode actionNode) {
        String toolName = requiredText(actionNode, "toolName");
        JsonNode arguments = actionNode.path("arguments");
        if (!arguments.isObject()) {
            throw evidenceIncomplete("Tool Proposal arguments must be an object");
        }
        return new ToolProposalAction(new ToolProposal(toolName, arguments.deepCopy()));
    }

    private FinalResponseAction parseFinalResponseAction(JsonNode actionNode) {
        String content = requiredText(actionNode, "content");
        return new FinalResponseAction(content);
    }

    private String requiredText(JsonNode node, String field) {
        JsonNode v = node.path(field);
        if (!v.isTextual() || v.asText().isBlank()) {
            throw evidenceIncomplete("Missing or invalid field: " + field);
        }
        return v.asText();
    }

    private byte[] serialize(ObjectNode node) {
        try {
            return objectMapper.writeValueAsBytes(node);
        } catch (Exception e) {
            throw evidenceIncomplete("OpenAI request serialization failed");
        }
    }

    private BusinessException operationalFailure(String message, Exception cause) {
        if (cause == null) {
            return new BusinessException(ErrorCode.INTERNAL_ERROR, message);
        }
        return new BusinessException(
                ErrorCode.INTERNAL_ERROR,
                message + ": " + cause.getClass().getSimpleName()
        );
    }

    private BusinessException evidenceIncomplete(String message) {
        return new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, message);
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
}
