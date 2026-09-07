package com.finsecseal.platform.contract;

import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.common.api.TraceIdFilter;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

/** Server-provisioned, workspace-scoped API credential; no cookie or actor-header authentication. */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 5)
public class ContractAccessFilter extends OncePerRequestFilter {
    public static final String CONTEXT = ContractAccessFilter.class.getName() + ".reviewer";
    private final String key, actor, workspace;
    private final ObjectMapper json;
    public ContractAccessFilter(@Value("${finsec.contract-access.key:}") String key,
            @Value("${finsec.contract-access.actor:}") String actor,
            @Value("${finsec.contract-access.workspace:}") String workspace, ObjectMapper json) {
        this.key=key; this.actor=actor; this.workspace=workspace; this.json=json;
    }
    @Override protected boolean shouldNotFilter(HttpServletRequest r) {
        return org.springframework.web.cors.CorsUtils.isPreFlightRequest(r) || !r.getRequestURI().startsWith("/api/v1/platform/contracts")
                && !r.getRequestURI().startsWith("/api/v1/platform/patch-sources");
    }
    @Override protected void doFilterInternal(HttpServletRequest r, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String supplied = r.getHeader("X-Contract-Reviewer-Key");
        UUID workspaceId;
        try { workspaceId = UUID.fromString(workspace); } catch (RuntimeException e) { workspaceId = null; }
        String actorHeader = r.getHeader("X-Actor-Id");
        if (workspaceId == null || key.getBytes(StandardCharsets.UTF_8).length < 32 || actor.isBlank()
                || actor.length() > 120 || !actor.equals(actor.strip()) || supplied == null
                || !MessageDigest.isEqual(key.getBytes(StandardCharsets.UTF_8), supplied.getBytes(StandardCharsets.UTF_8))
                || (actorHeader != null && !actorHeader.equals(actor)) || r.getHeader("Cookie") != null) {
            response.setStatus(403); response.setContentType("application/problem+json");
            response.getOutputStream().write(json.writeValueAsBytes(json.createObjectNode()
                    .put("status",403).put("title","Forbidden").put("code","CONTRACT_AUTH_REQUIRED")
                    .put("detail","A configured workspace reviewer API credential is required")
                    .put("traceId",TraceIdFilter.currentTraceId())));
            return;
        }
        // A secret custom header, never an ambient cookie, authenticates the request. The
        // same proof supplies CSRF protection; a request-supplied boolean is never accepted.
        r.setAttribute(CONTEXT,new ReviewerContext(workspaceId,actor,"AI_SECURITY_REVIEWER",
                "credential-request:"+UUID.randomUUID(),true,true,false));
        chain.doFilter(new HttpServletRequestWrapper(r) {
            @Override public String getHeader(String name) {
                return name.equalsIgnoreCase("X-Actor-Id") ? actor : super.getHeader(name);
            }
        }, response);
    }
}
