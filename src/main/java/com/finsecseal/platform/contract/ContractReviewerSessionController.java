package com.finsecseal.platform.contract;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.TraceIdFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/** Credential exchange for an HTTP-only reviewer cookie; does not create public reviewer authority. */
@RestController
public class ContractReviewerSessionController {
    private final ContractReviewerCredentials credentials;
    public ContractReviewerSessionController(ContractReviewerCredentials credentials) { this.credentials = credentials; }
    public record SessionView(String csrfToken, long expiresAt, String actorId, String workspaceId, String role) {}

    @GetMapping("/api/v1/reviewer-session")
    ResponseEntity<?> current(HttpServletRequest request) {
        var reviewerContext = ContractController.reviewer(request);
        if (reviewerContext == null) throw new com.finsecseal.common.api.BusinessException(
                com.finsecseal.common.api.ErrorCode.OPERATOR_AUTH_REQUIRED, "Trusted reviewer context is required");
        var session = (ContractReviewerCredentials.Session) request.getAttribute(ContractAccessFilter.SESSION);
        boolean issued = session == null;
        if (issued) session = credentials.issue();
        var response = ResponseEntity.ok().cacheControl(CacheControl.noStore());
        if (issued) response.header("Set-Cookie", ResponseCookie.from(ContractReviewerCredentials.COOKIE, session.token())
                .httpOnly(true).secure(true).sameSite("Lax").path("/").maxAge(1800).build().toString());
        var reviewer = session.reviewer();
        return response.body(ApiResponse.success(new SessionView(session.csrfToken(), session.expiresAt(), reviewer.actorId(),
                reviewer.workspaceId().toString(), reviewer.role()), TraceIdFilter.currentTraceId()));
    }
}
