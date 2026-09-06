package com.finsecseal.sandbox.tool;

import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.runtime.ToolInvocation;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.sandbox.SandboxExecutionContext;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.client.RestTemplate;

import com.finsecseal.common.domain.ExecutionEventType;
import java.time.Instant;
import java.util.UUID;
import java.util.Map;

/**
 * Minimal C Policy Gateway HTTP client scaffold.
 * Disabled by default; enable with property `policy.gateway.c.enabled=true`.
 */
@Component
@ConditionalOnProperty(prefix = "policy.gateway.c", name = "enabled", havingValue = "true", matchIfMissing = false)
public class CPolicyGatewayClient implements PolicyGateway {

    private final RestTemplate restTemplate;
    private final String gatewayUrl;

    public CPolicyGatewayClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
        this.gatewayUrl = System.getProperty("policy.gateway.c.url", "http://policy-gateway-c.local/evaluate");
    }

    @Override
    public GatewayResult invoke(SandboxExecutionContext context, ToolInvocation invocation, String actorId) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        Map<String, Object> body = Map.of(
                "context", context,
                "invocation", invocation,
                "actorId", actorId
        );
        HttpEntity<Map<String, Object>> request = new HttpEntity<>(body, headers);
        Map response = restTemplate.postForObject(gatewayUrl, request, Map.class);

        boolean allowed = response != null && Boolean.TRUE.equals(response.get("allowed"));
        String reason = response == null ? "UNKNOWN" : String.valueOf(response.get("reasonCode"));
        PolicyDecision decision = new PolicyDecision(allowed, reason);

        ExecutionEventDto.Event policyEvent = new ExecutionEventDto.Event(
                "1.0",
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                0L,
                Instant.now(),
                ExecutionEventType.POLICY_EVALUATED,
                null,
                null,
                null,
                null,
                null,
                reason,
                null,
                null,
                null
        );

        return new GatewayResult(decision, policyEvent, null, null, null);
    }

    @Override
    public GatewayResult invoke(SandboxExecutionContext context, ToolProposal proposal, String actorId) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        Map<String, Object> body = Map.of(
                "context", context,
                "proposal", proposal,
                "actorId", actorId
        );
        HttpEntity<Map<String, Object>> request = new HttpEntity<>(body, headers);
        Map response = restTemplate.postForObject(gatewayUrl, request, Map.class);

        boolean allowed = response != null && Boolean.TRUE.equals(response.get("allowed"));
        String reason = response == null ? "UNKNOWN" : String.valueOf(response.get("reasonCode"));
        PolicyDecision decision = new PolicyDecision(allowed, reason);

        ExecutionEventDto.Event policyEvent = new ExecutionEventDto.Event(
                "1.0",
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                0L,
                Instant.now(),
                ExecutionEventType.POLICY_EVALUATED,
                null,
                null,
                null,
                null,
                null,
                reason,
                null,
                null,
                null
        );

        return new GatewayResult(decision, policyEvent, null, null, null);
    }
}
