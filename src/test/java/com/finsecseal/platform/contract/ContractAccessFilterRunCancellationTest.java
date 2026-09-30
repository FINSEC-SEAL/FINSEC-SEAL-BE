package com.finsecseal.platform.contract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.finsecseal.common.api.IdempotencyFilter;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import tools.jackson.databind.ObjectMapper;

class ContractAccessFilterRunCancellationTest {

    @Test
    void rejectsReviewerKeyOnlyCancellationBeforeIdempotencyAdmission() throws Exception {
        ContractReviewerCredentials credentials = mock(ContractReviewerCredentials.class);
        ContractReviewerSessionRevocations revocations = mock(ContractReviewerSessionRevocations.class);
        ContractAccessFilter filter = new ContractAccessFilter(credentials, revocations, new ObjectMapper());
        MockHttpServletRequest request = cancellationRequest();
        request.addHeader("X-Contract-Reviewer-Key", "trusted-key");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean called = new AtomicBoolean();
        when(credentials.keyValid("trusted-key")).thenReturn(true);

        filter.doFilter(request, response, (ignoredRequest, ignoredResponse) -> called.set(true));

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(called).isFalse();
        assertThat(request.getAttribute(IdempotencyFilter.WORKSPACE)).isNull();
    }

    @Test
    void admitsCookieSessionCancellationWithItsWorkspaceScope() throws Exception {
        ContractReviewerCredentials credentials = mock(ContractReviewerCredentials.class);
        ContractReviewerSessionRevocations revocations = mock(ContractReviewerSessionRevocations.class);
        ContractAccessFilter filter = new ContractAccessFilter(credentials, revocations, new ObjectMapper());
        UUID workspaceId = UUID.randomUUID();
        ReviewerContext reviewer = new ReviewerContext(
                workspaceId,
                "reviewer-b",
                "AI_SECURITY_REVIEWER",
                "session-1",
                true,
                true,
                false
        );
        ContractReviewerCredentials.Session session = new ContractReviewerCredentials.Session(
                "token",
                "csrf",
                Instant.now().plusSeconds(300).getEpochSecond(),
                reviewer
        );
        MockHttpServletRequest request = cancellationRequest();
        request.addHeader("Cookie", ContractReviewerCredentials.COOKIE + "=token");
        request.addHeader("X-CSRF-Token", "csrf");
        request.addHeader("X-Actor-Id", reviewer.actorId());
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean called = new AtomicBoolean();
        when(credentials.session(request)).thenReturn(session);
        when(credentials.csrfValid(eq(session), any())).thenReturn(true);

        filter.doFilter(request, response, (filteredRequest, ignoredResponse) -> {
            called.set(true);
            assertThat(filteredRequest.getAttribute(IdempotencyFilter.WORKSPACE)).isEqualTo(workspaceId);
            assertThat(((HttpServletRequest) filteredRequest).getHeader("X-Actor-Id"))
                    .isEqualTo(reviewer.actorId());
        });

        assertThat(called).isTrue();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    private MockHttpServletRequest cancellationRequest() {
        return new MockHttpServletRequest(
                "POST",
                "/api/v1/test-runs/0198f200-0000-7000-8000-000000000010:cancel"
        );
    }
}
