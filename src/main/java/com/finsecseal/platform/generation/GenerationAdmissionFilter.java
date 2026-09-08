package com.finsecseal.platform.generation;

import com.finsecseal.common.api.TraceIdFilter;
import com.finsecseal.platform.generation.GenerationContract.Kind;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

/** Availability rejection after authentication but before creating an idempotency reservation. */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE+6)
public class GenerationAdmissionFilter extends OncePerRequestFilter {
    private final GenerationEngine engine;
    private final ObjectMapper json;
    public GenerationAdmissionFilter(GenerationEngine engine,ObjectMapper json) {this.engine=engine;this.json=json;}
    @Override protected boolean shouldNotFilter(HttpServletRequest request) {
        return !"POST".equals(request.getMethod()) || !(request.getRequestURI().matches("/api/v1/releases/[^/]+/contracts:generate/?")
                || request.getRequestURI().matches("/api/v1/findings/[^/]+/patch-proposals/?"));
    }
    @Override protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response,FilterChain chain) throws ServletException,IOException {
        Kind kind=request.getRequestURI().contains("/findings/")?Kind.PATCH:Kind.CONTRACT;
        if(!engine.available(kind)) {
            response.setStatus(503);response.setContentType("application/problem+json");
            response.getOutputStream().write(json.writeValueAsBytes(json.createObjectNode().put("status",503).put("title","Service Unavailable")
                    .put("code","GENERATION_DISABLED").put("retryable",false).put("detail","Generation provider is disabled")
                    .put("traceId",TraceIdFilter.currentTraceId())));
            return;
        }
        chain.doFilter(request,response);
    }
}
