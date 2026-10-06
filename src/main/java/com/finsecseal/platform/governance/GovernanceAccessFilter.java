package com.finsecseal.platform.governance;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.api.IdempotencyFilter;
import com.finsecseal.common.api.TraceIdFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Locale;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.dao.DataAccessException;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

/** Authenticate before common reservation/replay; never extends C credentials or D decisions. */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 6)
public final class GovernanceAccessFilter extends OncePerRequestFilter {
    private static final String SESSION = GovernanceReviewerCredentials.SESSION_PATH;
    private static final String UUID_TEXT = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
    private static final Pattern RISK = Pattern.compile("^/api/v1/findings/(" + UUID_TEXT + "):accept-risk$");
    private static final Pattern LOGOUT = Pattern.compile("^" + SESSION + "/(" + UUID_TEXT + ")$");
    private static final Pattern KEY = Pattern.compile("[A-Za-z0-9._:-]{1,128}");
    private final GovernanceReviewerCredentials credentials;
    private final GovernanceReviewerSessionRevocations revocations;
    private final GovernanceAccess access;
    private final ObjectMapper json;

    public GovernanceAccessFilter(GovernanceReviewerCredentials credentials,
            GovernanceReviewerSessionRevocations revocations, GovernanceAccess access, ObjectMapper json) {
        this.credentials = credentials; this.revocations = revocations; this.access = access; this.json = json;
    }

    @Override protected boolean shouldNotFilter(HttpServletRequest request) {
        if (CorsUtils.isPreFlightRequest(request)) return true;
        // The container maps its decoded/normalized path separately from getRequestURI().
        // A raw unrelated prefix is not proof when dot/slash aliases map to an owned route.
        if (protectedPath(request.getServletPath())) return false;
        String path = request.getRequestURI();
        for (int depth = 0; ; depth++) {
            if (protectedPath(path)) return false;
            if (fixedUnrelatedNamespace(path)) return true;
            if (!path.contains("%")) return true;
            // Inspect the final decoded candidate above. Opaque deeper or malformed encodings
            // cannot establish that a request is unrelated: select, then reject its ORIGINAL URI.
            if (depth == 4) return false;
            try {
                String decoded = URLDecoder.decode(path, StandardCharsets.UTF_8);
                if (decoded.equals(path)) return false;
                path = decoded;
            } catch (IllegalArgumentException invalid) { return false; }
        }
    }

    private static boolean protectedPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        String withoutMatrix = lower.replaceAll(";[^/]*", "");
        return withoutMatrix.startsWith(SESSION) || (withoutMatrix.startsWith("/api/v1/findings/")
                && lower.contains("accept-risk"));
    }

    private static boolean fixedUnrelatedNamespace(String path) {
        String withoutMatrix = path.toLowerCase(Locale.ROOT).replaceAll(";[^/]*", "");
        if (!withoutMatrix.startsWith("/")) return false;
        String[] segments = withoutMatrix.substring(1).split("/", -1);
        // Stop at the first fixed mismatch in the owned namespace, without decoding its suffix.
        // The mapped-path check above already excludes container aliases into an owned route.
        for (int index = 0; index < Math.min(3, segments.length); index++) {
            String segment = segments[index];
            if (segment.isEmpty() || segment.contains("%")) return false;
            if (index == 0 && !segment.equals("api")) return true;
            if (index == 1 && !segment.equals("v1")) return true;
            if (index == 2) return !segment.equals("findings")
                    && !segment.startsWith("governance-reviewer-session");
        }
        return false;
    }

    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {
        response.setHeader("Cache-Control", "no-store");
        try {
            authenticate(request, response, chain);
        } catch (BusinessException denied) {
            problem(response, denied.errorCode(), "Current governance session authority required");
        } catch (DataAccessException unavailable) {
            String previousTrace = org.slf4j.MDC.get(TraceIdFilter.TRACE_ID);
            try {
                org.slf4j.MDC.remove(TraceIdFilter.TRACE_ID);
                // No owned diagnostic is emitted: a console delimiter can complete a supplied secret.
            } finally {
                if (previousTrace == null) org.slf4j.MDC.remove(TraceIdFilter.TRACE_ID);
                else org.slf4j.MDC.put(TraceIdFilter.TRACE_ID, previousTrace);
            }
            problem(response, ErrorCode.INTERNAL_ERROR, "Governance authority storage unavailable");
        }
    }

    private void authenticate(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        String method = request.getMethod();
        var risk = RISK.matcher(path);
        var logoutPath = LOGOUT.matcher(path);
        boolean get = "GET".equals(method) && SESSION.equals(path);
        boolean logout = "DELETE".equals(method) && logoutPath.matches();
        boolean mutation = "POST".equals(method) && risk.matches();
        if (path.contains("%") || path.contains(";") || request.getQueryString() != null
                || (!get && !logout && !mutation)) {
            problem(response, ErrorCode.VALIDATION_ERROR, "Use the exact canonical governance API path and method");
            return;
        }
        int cookies = 0;
        if (request.getCookies() != null) for (var cookie : request.getCookies())
            if (GovernanceReviewerCredentials.COOKIE.equals(cookie.getName())) cookies++;
        if (cookies > 1) { forbidden(response); return; }
        boolean authorization = request.getHeaders("Authorization") != null
                && request.getHeaders("Authorization").hasMoreElements();
        if (authorization && !get) { forbidden(response); return; }
        boolean issued = get && authorization;
        var session = issued ? credentials.exchange(request) : credentials.session(request);
        if (session == null) { forbidden(response); return; }
        var identity = get ? session.identity() : credentials.mutationContext(session, request);
        if (identity == null) { forbidden(response); return; }
        boolean exactOwnLogout = logout && identity.sessionId().toString().equals(logoutPath.group(1));
        if ((logout && !exactOwnLogout) || (revocations.isRevoked(identity) && !exactOwnLogout)) {
            forbidden(response); return;
        }
        Enumeration<String> actors = request.getHeaders("X-Actor-Id");
        if (actors != null && actors.hasMoreElements()) {
            String actor = actors.nextElement();
            if (actors.hasMoreElements() || !identity.actorId().equals(actor)) { forbidden(response); return; }
        }
        String key = null;
        if (!get) {
            key = GovernanceReviewerCredentials.singleHeader(request, "Idempotency-Key");
            if (key == null || !KEY.matcher(key).matches() || !credentials.safeIdempotencyKey(session, key)) {
                problem(response, ErrorCode.VALIDATION_ERROR, "A single safe Idempotency-Key is required"); return;
            }
        }
        UUID finding = mutation ? GovernanceReviewerCredentials.canonicalUuid(risk.group(1)) : null;
        if (mutation) access.requireFindingWorkspace(identity, finding);
        access.establish(request, session, identity, finding, key, logout, issued);
        request.setAttribute(IdempotencyFilter.WORKSPACE, identity.workspaceId());
        if (logout) response.addHeader("Set-Cookie", clearCookie());
        String actor = identity.actorId();
        chain.doFilter(new HttpServletRequestWrapper(request) {
            @Override public String getHeader(String name) {
                return "X-Actor-Id".equalsIgnoreCase(name) ? actor : super.getHeader(name);
            }
            @Override public Enumeration<String> getHeaders(String name) {
                return "X-Actor-Id".equalsIgnoreCase(name)
                        ? Collections.enumeration(java.util.List.of(actor)) : super.getHeaders(name);
            }
        }, response);
    }

    private static String clearCookie() {
        return ResponseCookie.from(GovernanceReviewerCredentials.COOKIE, "").httpOnly(true).secure(true)
                .sameSite("Lax").path("/").maxAge(0).build().toString();
    }

    private void forbidden(HttpServletResponse response) throws IOException {
        problem(response, ErrorCode.OPERATOR_AUTH_REQUIRED, "Current governance session authority required");
    }

    private void problem(HttpServletResponse response, ErrorCode code, String detail) throws IOException {
        response.setStatus(code.status().value());
        response.setContentType("application/problem+json");
        byte[] exactBody;
        try {
            exactBody = json.writeValueAsBytes(json.createObjectNode()
                    .put("status", code.status().value()).put("title", code.status().getReasonPhrase())
                    .put("code", code.name()).put("detail", detail).put("traceId", TraceIdFilter.currentTraceId()));
            if (!credentials.safeActualResponseFrame(exactBody)) {
                response.setContentLength(0);
                return;
            }
        } catch (RuntimeException unavailable) {
            // Preserve the selected status/no-store; do not echo or log a refused serialized frame.
            response.setContentLength(0);
            return;
        }
        response.getOutputStream().write(exactBody);
    }
}
