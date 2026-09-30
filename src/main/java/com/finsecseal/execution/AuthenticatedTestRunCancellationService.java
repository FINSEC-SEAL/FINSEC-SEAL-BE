package com.finsecseal.execution;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.api.TraceIdFilter;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.evidence.TestRunDto;
import com.finsecseal.evidence.TestRunProjectionService;
import com.finsecseal.platform.contract.ContractReviewerCredentials;
import com.finsecseal.platform.contract.ContractReviewerSessionRevocations;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthenticatedTestRunCancellationService {

    private final ContractReviewerCredentials credentials;
    private final ContractReviewerSessionRevocations revocations;
    private final RunExecutionLifecycleService lifecycleService;
    private final TestRunProjectionService projectionService;
    private final JdbcTemplate jdbcTemplate;

    public AuthenticatedTestRunCancellationService(
            ContractReviewerCredentials credentials,
            ContractReviewerSessionRevocations revocations,
            RunExecutionLifecycleService lifecycleService,
            TestRunProjectionService projectionService,
            JdbcTemplate jdbcTemplate
    ) {
        this.credentials = credentials;
        this.revocations = revocations;
        this.lifecycleService = lifecycleService;
        this.projectionService = projectionService;
        this.jdbcTemplate = jdbcTemplate;
    }

    @Transactional
    public TestRunDto.Projection cancel(UUID runId, HttpServletRequest request) {
        ContractReviewerCredentials.Session session = requireSession(request);
        ReviewerContext reviewer = session.reviewer();
        List<RunAuthority> authorities = jdbcTemplate.query("""
                select agent.workspace_id, grant.actor_id, grant.reviewer_role,
                       grant.authority_stamp
                  from test_runs run
                  join agent_releases release on release.id = run.release_id
                  join agents agent on agent.id = release.agent_id
                  join test_run_reviewer_grants grant on grant.run_id = run.id
                 where run.id = ?
                """, (resultSet, rowNumber) -> new RunAuthority(
                resultSet.getObject("workspace_id", UUID.class),
                resultSet.getString("actor_id"),
                resultSet.getString("reviewer_role"),
                resultSet.getString("authority_stamp")
        ), runId);
        if (authorities.size() != 1) {
            throw authRequired();
        }
        RunAuthority authority = authorities.getFirst();
        if (!reviewer.workspaceId().equals(authority.workspaceId())
                || !reviewer.actorId().equals(authority.actorId())
                || !reviewer.role().equals(authority.role())
                || !credentials.matchesCurrentAuthorityStamp(
                authority.workspaceId(), authority.actorId(), authority.role(), authority.authorityStamp())) {
            throw authRequired();
        }

        String currentTraceId = TraceIdFilter.currentTraceId();
        UUID traceId = currentTraceId == null ? UUID.randomUUID() : UUID.fromString(currentTraceId);
        lifecycleService.requestCancellation(runId, traceId, reviewer.actorId());
        if (revocations.isRevoked(session) || expired(session)) {
            throw authRequired();
        }
        return projectionService.find(runId);
    }

    private ContractReviewerCredentials.Session requireSession(HttpServletRequest request) {
        if (request == null) {
            throw authRequired();
        }
        ContractReviewerCredentials.Session session = credentials.session(request);
        if (session == null || !credentials.csrfValid(session, request)
                || revocations.isRevoked(session) || expired(session)) {
            throw authRequired();
        }
        String suppliedActor = request.getHeader("X-Actor-Id");
        if (suppliedActor != null && !suppliedActor.equals(session.reviewer().actorId())) {
            throw authRequired();
        }
        return session;
    }

    private boolean expired(ContractReviewerCredentials.Session session) {
        return session.expiresAt() <= Instant.now().getEpochSecond();
    }

    private BusinessException authRequired() {
        return new BusinessException(
                ErrorCode.OPERATOR_AUTH_REQUIRED,
                "The admitted reviewer session is required to cancel this TestRun"
        );
    }

    private record RunAuthority(
            UUID workspaceId,
            String actorId,
            String role,
            String authorityStamp
    ) {
    }
}
