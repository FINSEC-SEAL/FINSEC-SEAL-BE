package com.finsecseal.platform.contract;

import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/** Server-issued, short-lived reviewer session. No request can supply a role or workspace. */
@Component
public class ContractReviewerCredentials {
    public static final String COOKIE = "__Host-FINSEC_REVIEWER";
    private final String key;
    private final String actor;
    private final UUID workspace;
    private final ObjectMapper json;
    public record Session(String token, String csrfToken, long expiresAt, ReviewerContext reviewer) {}

    public ContractReviewerCredentials(@Value("${finsec.contract-access.key:}") String key,
            @Value("${finsec.contract-access.actor:}") String actor,
            @Value("${finsec.contract-access.workspace:}") String workspace, ObjectMapper json) {
        this.key = key;
        this.actor = actor;
        UUID parsed;
        try { parsed = UUID.fromString(workspace); } catch (RuntimeException e) { parsed = null; }
        this.workspace = parsed;
        this.json = json;
    }

    private boolean configured() {
        return workspace != null && key.getBytes(StandardCharsets.UTF_8).length >= 32
                && !actor.isBlank() && actor.length() <= 120 && actor.equals(actor.strip());
    }

    public boolean keyValid(String supplied) {
        return configured() && supplied != null && equal(key, supplied);
    }

    public ReviewerContext keyReviewer() {
        return reviewer("credential-request:" + UUID.randomUUID());
    }

    public Session issue() {
        String sessionId = UUID.randomUUID().toString();
        String csrf = UUID.randomUUID() + ":" + UUID.randomUUID();
        long expires = Instant.now().plusSeconds(1800).getEpochSecond();
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(json.writeValueAsBytes(
                json.createObjectNode().put("sessionId", sessionId).put("csrf", csrf).put("expires", expires)
                        .put("actor", actor).put("workspace", workspace.toString())));
        return new Session(payload + "." + signature(payload), csrf, expires, reviewer(sessionId));
    }

    public Session session(HttpServletRequest request) {
        if (!configured() || request.getCookies() == null) return null;
        String token = null;
        for (var cookie : request.getCookies()) {
            if (COOKIE.equals(cookie.getName())) {
                if (token != null) return null;
                token = cookie.getValue();
            }
        }
        if (token == null || token.length() > 4096) return null;
        try {
            String[] parts = token.split("\\.", -1);
            if (parts.length != 2 || !equal(signature(parts[0]), parts[1])) return null;
            var body = json.readTree(Base64.getUrlDecoder().decode(parts[0]));
            long expires = body.path("expires").longValue();
            if (expires <= Instant.now().getEpochSecond() || !actor.equals(body.path("actor").stringValue())
                    || !workspace.toString().equals(body.path("workspace").stringValue())) return null;
            return new Session(token, body.path("csrf").stringValue(), expires, reviewer(body.path("sessionId").stringValue()));
        } catch (RuntimeException exception) { return null; }
    }

    public boolean csrfValid(Session session, HttpServletRequest request) {
        return session != null && equal(session.csrfToken(), request.getHeader("X-CSRF-Token"));
    }

    /** Non-secret stamp invalidated by credential/actor/workspace rotation; never persist the key. */
    public String authorityStamp(ReviewerContext reviewer) {
        if (!configured() || reviewer == null || !reviewer.authenticated() || !reviewer.csrfVerified()
                || !workspace.equals(reviewer.workspaceId()) || !actor.equals(reviewer.actorId())
                || !"AI_SECURITY_REVIEWER".equals(reviewer.role()) || reviewer.sessionId()==null || reviewer.sessionId().isBlank()) {
            throw new com.finsecseal.common.api.BusinessException(
                    com.finsecseal.common.api.ErrorCode.OPERATOR_AUTH_REQUIRED,"Trusted reviewer authority required");
        }
        return signature("GENERATION_AUTHORITY:"+workspace+":"+actor);
    }

    private ReviewerContext reviewer(String sessionId) {
        return new ReviewerContext(workspace, actor, "AI_SECURITY_REVIEWER", sessionId, true, true, false);
    }

    private String signature(String payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(
                    mac.doFinal(("FINSEC_REVIEWER_SESSION_V1:" + payload).getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.GeneralSecurityException exception) { throw new IllegalStateException(exception); }
    }

    private boolean equal(String expected, String actual) {
        return expected != null && actual != null && MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8), actual.getBytes(StandardCharsets.UTF_8));
    }
}
