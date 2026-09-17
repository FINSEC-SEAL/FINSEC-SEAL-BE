package com.finsecseal.platform.contract;

import com.finsecseal.common.api.TraceIdFilter;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.util.Set;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 5)
public class ContractAccessFilter extends OncePerRequestFilter {
    public static final String CONTEXT = ContractAccessFilter.class.getName() + ".reviewer";
    public static final String SESSION = ContractAccessFilter.class.getName() + ".session";
    private final ContractReviewerCredentials credentials;
    private final ObjectMapper json;

    public ContractAccessFilter(ContractReviewerCredentials credentials, ObjectMapper json) {
        this.credentials = credentials;
        this.json = json;
    }

    @Override protected boolean shouldNotFilter(HttpServletRequest request) {
        if (CorsUtils.isPreFlightRequest(request)) return true;
        String path;
        try { path = java.net.URLDecoder.decode(request.getRequestURI(), java.nio.charset.StandardCharsets.UTF_8); }
        catch (IllegalArgumentException exception) { path = request.getRequestURI(); }
        path = path.replaceAll(";[^/]*", "");
        // Prefix matching also protects malformed/encoded descendants before MVC routing.
        return !path.startsWith("/api/v1/platform/contracts") && !path.startsWith("/api/v1/platform/patch-sources")
                && !path.startsWith("/api/v1/contracts") && !path.startsWith("/api/v1/contract-versions")
                && !path.startsWith("/api/v1/reviewer-session")
                && !path.startsWith("/api/v1/operations")
                && !path.matches("/api/v1/releases/[^/]+/contracts:generate/?")
                && !path.matches("/api/v1/findings/[^/]+/patch-proposals/?");
    }

    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (request.getRequestURI().contains("%") || request.getRequestURI().contains(";")) {
            response.sendError(400, "Use the canonical contract API path");
            return;
        }
        ReviewerContext reviewer = null;
        var session = credentials.session(request);
        String supplied = request.getHeader("X-Contract-Reviewer-Key");
        boolean mutation = !Set.of("GET", "HEAD", "OPTIONS").contains(request.getMethod());
        // A cookie request must prove CSRF; a key header cannot downgrade this requirement.
        if (request.getHeader("Cookie") != null) {
            if (session != null && (supplied == null || credentials.keyValid(supplied))
                    && (!mutation || credentials.csrfValid(session, request))) reviewer = session.reviewer();
        } else if (credentials.keyValid(supplied)) {
            reviewer = credentials.keyReviewer();
        }
        String actorHeader = request.getHeader("X-Actor-Id");
        if (reviewer == null || (actorHeader != null && !actorHeader.equals(reviewer.actorId()))) {
            response.setStatus(403);
            response.setContentType("application/problem+json");
            response.getOutputStream().write(json.writeValueAsBytes(json.createObjectNode()
                    .put("status", 403).put("title", "Forbidden").put("code", "CONTRACT_AUTH_REQUIRED")
                    .put("detail", "A trusted reviewer credential or valid session and CSRF proof is required")
                    .put("traceId", TraceIdFilter.currentTraceId())));
            return;
        }
        request.setAttribute(CONTEXT, reviewer);
        request.setAttribute(com.finsecseal.common.api.IdempotencyFilter.WORKSPACE, reviewer.workspaceId());
        request.setAttribute(SESSION, session);
        String actor = reviewer.actorId();
        chain.doFilter(new HttpServletRequestWrapper(request) {
            @Override public String getHeader(String name) {
                return name.equalsIgnoreCase("X-Actor-Id") ? actor : super.getHeader(name);
            }
        }, response);
    }
}
