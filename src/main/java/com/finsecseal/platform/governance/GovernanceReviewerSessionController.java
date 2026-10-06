package com.finsecseal.platform.governance;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.TraceIdFilter;
import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.ObjectMapper;

/** Separate governance cookie transport; never emits the signed cookie or bootstrap/signing keys in JSON. */
@RestController
public class GovernanceReviewerSessionController {
    private final GovernanceAccess access;
    private final GovernanceReviewerSessionRevocations revocations;
    private final ObjectMapper json;

    public GovernanceReviewerSessionController(GovernanceAccess access,
            GovernanceReviewerSessionRevocations revocations, ObjectMapper json) {
        this.access = access; this.revocations = revocations; this.json = json;
    }

    public record SessionView(String csrfToken, long expiresAt, String actorId, String workspaceId,
            String role, String sessionId, boolean demoMode) {}

    @GetMapping("/api/v1/governance-reviewer-session")
    public ResponseEntity<byte[]> current(HttpServletRequest request) {
        var session = access.currentSession(request);
        var identity = session.identity();
        byte[] exactBody;
        try {
            // Use the actual application mapper and one ApiResponse timestamp; never rebuild checked JSON.
            exactBody = json.writeValueAsBytes(ApiResponse.success(new SessionView(session.csrfToken(),
                    identity.expiresAt(), identity.actorId(), identity.workspaceId().toString(), identity.role(),
                    identity.sessionId().toString(), identity.demoMode()), TraceIdFilter.currentTraceId()));
            if (!session.safeActualResponseFrame(exactBody)) return refusedResponseBody();
        } catch (RuntimeException unavailable) {
            // No cause, message, unsafe JSON, or issuer capability enters a fallback response/log.
            return refusedResponseBody();
        }
        var response = ResponseEntity.ok().cacheControl(CacheControl.noStore()).contentType(MediaType.APPLICATION_JSON);
        if (access.issued(request)) response.header("Set-Cookie", session.issuanceCookieHeader());
        return response.body(exactBody);
    }

    private static ResponseEntity<byte[]> refusedResponseBody() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).cacheControl(CacheControl.noStore())
                .contentType(MediaType.APPLICATION_JSON).body(new byte[0]);
    }

    @Transactional
    @DeleteMapping("/api/v1/governance-reviewer-session/{sessionId}")
    public ResponseEntity<Void> revoke(@PathVariable UUID sessionId, HttpServletRequest request) {
        revocations.revoke(access.requireLogout(request, sessionId));
        return ResponseEntity.noContent().cacheControl(CacheControl.noStore()).build();
    }
}
