package com.finsecseal.sandbox.tool;

import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.runtime.ToolInvocation;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.sandbox.SandboxExecutionContext;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Component
public class HttpPolicyGatewayClient implements PolicyGateway {

    private final RestTemplate restTemplate;
    private final String gatewayUrl = "http://policy-gateway.local/evaluate";

    public HttpPolicyGatewayClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
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

        // Minimal mapping: assume response contains "allowed" and "reasonCode"
        boolean allowed = response != null && Boolean.TRUE.equals(response.get("allowed"));
        String reason = response == null ? "UNKNOWN" : String.valueOf(response.get("reasonCode"));

        PolicyDecision decision = new PolicyDecision(allowed, reason);

        // For simplicity, return a GatewayResult with only a decision and null evidence.
        return new GatewayResult(decision, ExecutionEventDto.Event.empty(), null, null, null);
    }

    @Override
    public GatewayResult invoke(SandboxExecutionContext context, ToolProposal proposal, String actorId) {
        // Reuse same endpoint
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
        return new GatewayResult(decision, ExecutionEventDto.Event.empty(), null, null, null);
    }
}
