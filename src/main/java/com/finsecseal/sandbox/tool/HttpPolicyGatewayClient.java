package com.finsecseal.sandbox.tool;

import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.runtime.ToolInvocation;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.sandbox.SandboxExecutionContext;
import com.finsecseal.common.domain.TestRunMode;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.client.RestTemplate;

import com.finsecseal.common.domain.ExecutionEventType;
import java.util.HashMap;
import java.util.List;

import java.util.Map;
import org.springframework.beans.factory.ObjectProvider;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Component
@ConditionalOnProperty(prefix = "policy.gateway", name = "enabled", havingValue = "true", matchIfMissing = false)
public class HttpPolicyGatewayClient implements PolicyGateway {

    private final RestTemplate restTemplate;
    private final String gatewayUrl;
    private final Map<String, ToolAdapter> adapters;
    private final ExecutionEventService eventService;
    private final ObjectMapper objectMapper;
    private final StateChangingToolExecutionService stateChangingToolExecutionService;

    public HttpPolicyGatewayClient(
            RestTemplate restTemplate,
            List<ToolAdapter> adapters,
            ExecutionEventService eventService,
            ObjectMapper objectMapper,
            ObjectProvider<StateChangingToolExecutionService> stateChangingToolExecutionService
    ) {
        this.restTemplate = restTemplate;
        this.gatewayUrl = System.getProperty("policy.gateway.url", "http://policy-gateway.local/evaluate");
        this.adapters = indexAdapters(adapters);
        this.eventService = eventService;
        this.objectMapper = objectMapper;
        this.stateChangingToolExecutionService = stateChangingToolExecutionService.getIfAvailable();
    }

    @Override
    public GatewayResult invoke(SandboxExecutionContext context, ToolInvocation invocation, String actorId) {
        requireBaselineMode(context);
        Map response = evaluate(context, invocation, null, actorId);
        boolean allowed = response != null && Boolean.TRUE.equals(response.get("allowed"));
        String reason = response == null ? "UNKNOWN" : String.valueOf(response.get("reasonCode"));
        PolicyDecision decision = new PolicyDecision(allowed, reason);

        ObjectNode policyJson = objectMapper.createObjectNode();
        policyJson.put("allowed", decision.allowed());
        policyJson.put("reasonCode", decision.reasonCode());

        ExecutionEventDto.Event policyEvent = eventService.append(
            context.runId(),
            new ExecutionEventDto.AppendRequest(
                context.caseRunId(),
                context.traceId(),
                ExecutionEventType.POLICY_EVALUATED,
                invocation.proposal().toolName(),
                null,
                null,
                policyJson,
                decision.reasonCode(),
                objectMapper.createObjectNode().put("gateway", "http")
            ),
            actorId
        );

        if (!decision.allowed()) {
            return new GatewayResult(decision, policyEvent, null, null, null);
        }

        ToolAdapter adapter = requireAdapter(invocation.proposal().toolName());
        if (adapter.effect() == ToolEffect.STATE_CHANGING) {
            if (stateChangingToolExecutionService == null) {
            throw new BusinessException(ErrorCode.CONFIGURATION_ERROR,
                "State-changing Tool invocation requires the common idempotent executor");
            }
            StateChangingToolExecutionService.Execution execution = stateChangingToolExecutionService.execute(
                context,
                invocation,
                adapter,
                actorId
            );
            return new GatewayResult(decision, policyEvent,
                execution.requestEvent(), execution.responseEvent(), execution.result());
        }

        ExecutionEventDto.Event requestEvent = eventService.append(
            context.runId(),
            new ExecutionEventDto.AppendRequest(
                context.caseRunId(),
                context.traceId(),
                ExecutionEventType.TOOL_REQUEST,
                invocation.proposal().toolName(),
                invocation.proposal().arguments(),
                null,
                null,
                null,
                objectMapper.createObjectNode().put("gateway", "http")
            ),
            actorId
        );
        ToolAdapter.ToolExecutionResult execution = adapter.execute(context, invocation.proposal().arguments());

        ObjectNode responseMetadata = objectMapper.createObjectNode();
        responseMetadata.put("gateway", "http");
        responseMetadata.put("deliveredToAgent", false);
        responseMetadata.put("deliveryState", "PENDING");
        responseMetadata.put("stateChanged", execution.stateChanged());

        ExecutionEventDto.Event responseEvent = eventService.append(
            context.runId(),
            new ExecutionEventDto.AppendRequest(
                context.caseRunId(),
                context.traceId(),
                ExecutionEventType.TOOL_RESPONSE,
                invocation.proposal().toolName(),
                null,
                execution.output(),
                null,
                "TOOL_EXECUTED",
                responseMetadata
            ),
            actorId
        );

        return new GatewayResult(decision, policyEvent, requestEvent, responseEvent, execution);
    }

    @Override
    public GatewayResult invoke(SandboxExecutionContext context, ToolProposal proposal, String actorId) {
        requireBaselineMode(context);
        Map response = evaluate(context, null, proposal, actorId);
        boolean allowed = response != null && Boolean.TRUE.equals(response.get("allowed"));
        String reason = response == null ? "UNKNOWN" : String.valueOf(response.get("reasonCode"));
        PolicyDecision decision = new PolicyDecision(allowed, reason);

        ObjectNode policyJson = objectMapper.createObjectNode();
        policyJson.put("allowed", decision.allowed());
        policyJson.put("reasonCode", decision.reasonCode());

        ExecutionEventDto.Event policyEvent = eventService.append(
                context.runId(),
                new ExecutionEventDto.AppendRequest(
                        context.caseRunId(),
                        context.traceId(),
                        ExecutionEventType.POLICY_EVALUATED,
                        proposal.toolName(),
                        null,
                        null,
                        policyJson,
                        decision.reasonCode(),
                        objectMapper.createObjectNode().put("gateway", "http")
                ),
                actorId
        );

        if (!decision.allowed()) {
            return new GatewayResult(decision, policyEvent, null, null, null);
        }

        ToolAdapter adapter = requireAdapter(proposal.toolName());
        ExecutionEventDto.Event requestEvent = eventService.append(
                context.runId(),
                new ExecutionEventDto.AppendRequest(
                        context.caseRunId(),
                        context.traceId(),
                        ExecutionEventType.TOOL_REQUEST,
                        proposal.toolName(),
                        proposal.arguments(),
                        null,
                        null,
                        null,
                        objectMapper.createObjectNode().put("gateway", "http")
                ),
                actorId
        );
        ToolAdapter.ToolExecutionResult execution = adapter.execute(context, proposal.arguments());

        ObjectNode responseMetadata = objectMapper.createObjectNode();
        responseMetadata.put("gateway", "http");
        responseMetadata.put("deliveredToAgent", false);
        responseMetadata.put("deliveryState", "PENDING");
        responseMetadata.put("stateChanged", execution.stateChanged());

        ExecutionEventDto.Event responseEvent = eventService.append(
                context.runId(),
                new ExecutionEventDto.AppendRequest(
                        context.caseRunId(),
                        context.traceId(),
                        ExecutionEventType.TOOL_RESPONSE,
                        proposal.toolName(),
                        null,
                        execution.output(),
                        null,
                        "TOOL_EXECUTED",
                        responseMetadata
                ),
                actorId
        );

        return new GatewayResult(decision, policyEvent, requestEvent, responseEvent, execution);
    }

    private Map evaluate(SandboxExecutionContext context, ToolInvocation invocation, ToolProposal proposal, String actorId) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("context", context);
        if (invocation != null) {
            body.put("invocation", invocation);
        }
        if (proposal != null) {
            body.put("proposal", proposal);
        }
        body.put("actorId", actorId);
        HttpEntity<Map<String, Object>> request = new HttpEntity<>(body, headers);

        RuntimeException last = null;
        for (int attempt = 1; attempt <= 3; attempt++) {
            try {
                return restTemplate.postForObject(gatewayUrl, request, Map.class);
            } catch (RuntimeException ex) {
                last = ex;
                if (attempt == 3) {
                    throw new BusinessException(ErrorCode.INTERNAL_ERROR,
                            "HTTP Policy Gateway call failed after retries: " + ex.getClass().getSimpleName());
                }
            }
        }
        throw last == null
                ? new BusinessException(ErrorCode.INTERNAL_ERROR, "HTTP Policy Gateway call failed")
                : last;
    }

    private void requireBaselineMode(SandboxExecutionContext context) {
        if (context.mode() != TestRunMode.BASELINE) {
            throw new BusinessException(ErrorCode.CONFIGURATION_ERROR,
                    "HTTP Policy Gateway only supports BASELINE");
        }
    }

    private ToolAdapter requireAdapter(String toolName) {
        ToolAdapter adapter = adapters.get(toolName);
        if (adapter == null) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR,
                    "Unknown tool proposal: " + toolName);
        }
        return adapter;
    }

    private Map<String, ToolAdapter> indexAdapters(List<ToolAdapter> adapters) {
        Map<String, ToolAdapter> indexed = new HashMap<>();
        for (ToolAdapter adapter : adapters) {
            ToolAdapter previous = indexed.put(adapter.toolName(), adapter);
            if (previous != null) {
                throw new IllegalStateException("Duplicate ToolAdapter for " + adapter.toolName());
            }
        }
        return Map.copyOf(indexed);
    }
}
