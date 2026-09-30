package com.finsecseal.execution;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.evidence.TestRunDto;
import com.finsecseal.evidence.TestRunProjectionService;
import com.finsecseal.platform.contract.ContractReviewerCredentials;
import com.finsecseal.platform.contract.ContractReviewerSessionRevocations;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.mock.web.MockHttpServletRequest;

class AuthenticatedTestRunCancellationServiceTest {

    @Test
    @SuppressWarnings("unchecked")
    void cancelsOnlyWithMatchingAdmittedReviewerAuthority() throws Exception {
        ContractReviewerCredentials credentials = mock(ContractReviewerCredentials.class);
        ContractReviewerSessionRevocations revocations = mock(ContractReviewerSessionRevocations.class);
        RunExecutionLifecycleService lifecycle = mock(RunExecutionLifecycleService.class);
        TestRunProjectionService projections = mock(TestRunProjectionService.class);
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        UUID workspaceId = UUID.randomUUID();
        UUID runId = UUID.randomUUID();
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
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Actor-Id", reviewer.actorId());
        request.addHeader("X-CSRF-Token", "csrf");
        TestRunDto.Projection cancelled = mock(TestRunDto.Projection.class);

        when(credentials.session(request)).thenReturn(session);
        when(credentials.csrfValid(session, request)).thenReturn(true);
        when(credentials.matchesCurrentAuthorityStamp(
                workspaceId,
                reviewer.actorId(),
                reviewer.role(),
                "authority-stamp"
        )).thenReturn(true);
        when(jdbcTemplate.query(anyString(), any(RowMapper.class), eq(runId)))
                .thenAnswer(invocation -> {
                    RowMapper<Object> mapper = invocation.getArgument(1);
                    ResultSet resultSet = mock(ResultSet.class);
                    when(resultSet.getObject("workspace_id", UUID.class)).thenReturn(workspaceId);
                    when(resultSet.getString("actor_id")).thenReturn(reviewer.actorId());
                    when(resultSet.getString("reviewer_role")).thenReturn(reviewer.role());
                    when(resultSet.getString("authority_stamp")).thenReturn("authority-stamp");
                    return List.of(mapper.mapRow(resultSet, 0));
                });
        when(projections.find(runId)).thenReturn(cancelled);

        AuthenticatedTestRunCancellationService service =
                new AuthenticatedTestRunCancellationService(
                        credentials, revocations, lifecycle, projections, jdbcTemplate);

        TestRunDto.Projection result = service.cancel(runId, request);

        assertThat(result).isSameAs(cancelled);
        verify(lifecycle).requestCancellation(eq(runId), any(UUID.class), eq(reviewer.actorId()));
    }

    @Test
    void rejectsForgedActorBeforeReadingRunAuthority() {
        ContractReviewerCredentials credentials = mock(ContractReviewerCredentials.class);
        ContractReviewerSessionRevocations revocations = mock(ContractReviewerSessionRevocations.class);
        RunExecutionLifecycleService lifecycle = mock(RunExecutionLifecycleService.class);
        TestRunProjectionService projections = mock(TestRunProjectionService.class);
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        ReviewerContext reviewer = new ReviewerContext(
                UUID.randomUUID(),
                "reviewer-b",
                "AI_SECURITY_REVIEWER",
                "session-1",
                true,
                true,
                false
        );
        ContractReviewerCredentials.Session session = new ContractReviewerCredentials.Session(
                "token", "csrf", Instant.now().plusSeconds(300).getEpochSecond(), reviewer);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Actor-Id", "forged-actor");
        request.addHeader("X-CSRF-Token", "csrf");
        when(credentials.session(request)).thenReturn(session);
        when(credentials.csrfValid(session, request)).thenReturn(true);

        AuthenticatedTestRunCancellationService service =
                new AuthenticatedTestRunCancellationService(
                        credentials, revocations, lifecycle, projections, jdbcTemplate);

        assertThatThrownBy(() -> service.cancel(UUID.randomUUID(), request))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.OPERATOR_AUTH_REQUIRED));
        verify(lifecycle, never()).requestCancellation(any(), any(), anyString());
    }
}
