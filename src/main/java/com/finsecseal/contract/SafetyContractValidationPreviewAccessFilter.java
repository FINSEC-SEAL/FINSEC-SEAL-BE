package com.finsecseal.contract;

import com.finsecseal.common.api.TraceIdFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Locale;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UrlPathHelper;
import tools.jackson.databind.ObjectMapper;

/** Guards even persisted preview responses before the platform idempotency filter can replay them. */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 4)
public final class SafetyContractValidationPreviewAccessFilter extends OncePerRequestFilter {

    static final String PATH = "/api/v1/contract-validation-previews";
    private final Environment environment;
    private final ObjectMapper mapper;
    private final boolean safeStartupTransport;

    public SafetyContractValidationPreviewAccessFilter(Environment environment, ObjectMapper mapper) {
        this.environment = environment;
        this.mapper = mapper;
        String address = environment.getProperty("server.address", "");
        safeStartupTransport = ("127.0.0.1".equals(address) || "::1".equals(address))
                && "none".equals(environment.getProperty("server.forward-headers-strategy", ""));
        if (enabled() && !safeStartupTransport) {
            throw new IllegalStateException("Contract validation preview requires an explicit loopback "
                    + "server.address and server.forward-headers-strategy=none");
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = UrlPathHelper.defaultInstance.getPathWithinApplication(request);
        return !(path.equals(PATH) || path.startsWith(PATH + "/"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {
        if (!enabled()) {
            reject(response, HttpStatus.NOT_FOUND, "CONTRACT_PREVIEW_DISABLED",
                    "Contract validation preview is not available");
            return;
        }
        if (!safeStartupTransport || !loopbackPeer(request.getRemoteAddr()) || forwarded(request)) {
            reject(response, HttpStatus.FORBIDDEN, "CONTRACT_PREVIEW_ACCESS_DENIED",
                    "Contract validation preview requires a direct local request");
            return;
        }

        // Shared idempotency and its size limit use the raw /api/v1/ prefix.
        // Reject aliases rather than letting a decoded route bypass those owner controls.
        String path = UrlPathHelper.defaultInstance.getPathWithinApplication(request);
        if (!request.getRequestURI().equals(path) || !path.startsWith(PATH + "/")) {
            reject(response, HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
                    "Use the canonical contract validation preview path at the root context");
            return;
        }
        if (!CorsUtils.isPreFlightRequest(request)
                && !SafetyContractValidationPreviewService.validActor(request.getHeader("X-Actor-Id"))) {
            reject(response, HttpStatus.BAD_REQUEST, "VALIDATION_ERROR",
                    "An exact nonblank X-Actor-Id of at most 120 characters is required");
            return;
        }
        chain.doFilter(request, response);
    }

    private boolean enabled() {
        return environment.acceptsProfiles(Profiles.of("local"))
                && "true".equals(environment.getProperty("finsec.contract-preview.enabled", "false"));
    }

    private boolean loopbackPeer(String address) {
        return "127.0.0.1".equals(address) || "::1".equals(address)
                || "0:0:0:0:0:0:0:1".equals(address);
    }

    private boolean forwarded(HttpServletRequest request) {
        var names = request.getHeaderNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement().toLowerCase(Locale.ROOT);
            if (name.equals("forwarded") || name.startsWith("x-forwarded-")) {
                return true;
            }
        }
        return false;
    }

    private void reject(HttpServletResponse response, HttpStatus status, String code, String detail)
            throws IOException {
        var problem = mapper.createObjectNode();
        problem.put("type", "https://finsec-seal.local/problems/" + code.toLowerCase(Locale.ROOT));
        problem.put("title", status.getReasonPhrase());
        problem.put("status", status.value());
        problem.put("detail", detail);
        problem.put("code", code);
        problem.put("traceId", TraceIdFilter.currentTraceId());
        problem.put("retryable", false);
        problem.putArray("errors");
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        mapper.writeValue(response.getOutputStream(), problem);
    }
}
