package com.finsecseal.common.api;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 5)
public class OperatorRecoveryAuthenticationFilter extends OncePerRequestFilter {

    private static final String PATH = "/api/v1/platform/idempotency-recoveries";

    private final OperatorRecoveryCredentialVerifier verifier;
    private final ObjectMapper objectMapper;

    public OperatorRecoveryAuthenticationFilter(
            OperatorRecoveryCredentialVerifier verifier,
            ObjectMapper objectMapper
    ) {
        this.verifier = verifier;
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith(PATH);
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        try {
            verifier.verify(
                    request.getHeader("X-Operator-Recovery-Key"),
                    request.getHeader("X-Actor-Id")
            );
        } catch (BusinessException exception) {
            writeProblem(response, exception.errorCode(), exception.getMessage());
            return;
        }
        filterChain.doFilter(request, response);
    }

    private void writeProblem(HttpServletResponse response, ErrorCode code, String detail) throws IOException {
        response.setStatus(code.status().value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        ObjectNode problem = objectMapper.createObjectNode();
        problem.put("type", "https://finsec-seal.local/problems/" + code.name().toLowerCase());
        problem.put("title", code.status().getReasonPhrase());
        problem.put("status", code.status().value());
        problem.put("detail", detail);
        problem.put("code", code.name());
        problem.put("traceId", TraceIdFilter.currentTraceId());
        problem.put("retryable", code.retryable());
        problem.putArray("errors");
        response.getOutputStream().write(objectMapper.writeValueAsBytes(problem));
    }
}
