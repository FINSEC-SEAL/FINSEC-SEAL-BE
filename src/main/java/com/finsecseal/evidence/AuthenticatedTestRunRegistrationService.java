package com.finsecseal.evidence;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.platform.contract.ContractReviewerCredentials;
import com.finsecseal.platform.contract.ContractReviewerSessionRevocations;
import jakarta.servlet.http.HttpServletRequest;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Internal Run admission seam; public Run start is wired separately by its owner. */
@Service
public class AuthenticatedTestRunRegistrationService {
    private final ContractReviewerCredentials credentials;
    private final ContractReviewerSessionRevocations revocations;
    private final TestRunPersistenceService runs;
    private final JdbcTemplate db;

    public AuthenticatedTestRunRegistrationService(ContractReviewerCredentials credentials,
            ContractReviewerSessionRevocations revocations, TestRunPersistenceService runs, JdbcTemplate db) {
        this.credentials = credentials;
        this.revocations = revocations;
        this.runs = runs;
        this.db = db;
    }

    public record Admission(TestRunPersistenceDto.Registered run, String actorId) { }

    @Transactional
    public Admission register(TestRunPersistenceDto.RegisterRequest request, HttpServletRequest httpRequest) {
        if (httpRequest == null) throw authRequired();
        ContractReviewerCredentials.Session session = credentials.session(httpRequest);
        // The signed session's context already says csrfVerified; the request must prove it independently.
        if (session == null || !credentials.csrfValid(session, httpRequest)) throw authRequired();
        ReviewerContext reviewer = session.reviewer();
        String authorityStamp = credentials.authorityStamp(reviewer);
        if (revocations.isRevoked(session) || expired(session)) throw authRequired();
        String suppliedActor = httpRequest.getHeader("X-Actor-Id");
        if (suppliedActor != null && !suppliedActor.equals(reviewer.actorId())) throw authRequired();

        TestRunPersistenceDto.Registered registered = runs.register(request, reviewer.actorId());
        UUID runWorkspace = db.queryForObject("""
                select agent.workspace_id
                  from test_runs run
                  join agent_releases release on release.id = run.release_id
                  join agents agent on agent.id = release.agent_id
                 where run.id = ?
                """, UUID.class, registered.runId());
        if (!reviewer.workspaceId().equals(runWorkspace) || revocations.isRevoked(session) || expired(session)) {
            throw authRequired();
        }
        try {
            db.update("""
                    insert into test_run_reviewer_grants
                        (run_id, workspace_id, actor_id, reviewer_role, session_digest,
                         authority_stamp, authority_expires_at)
                    values (?, ?, ?, ?, ?, ?, ?)
                    """, registered.runId(), reviewer.workspaceId(), reviewer.actorId(), reviewer.role(),
                    revocations.sessionDigest(session), authorityStamp,
                    Timestamp.from(Instant.ofEpochSecond(session.expiresAt())));
        } catch (DataIntegrityViolationException exception) {
            throw new BusinessException(ErrorCode.RESOURCE_CONFLICT, "Authenticated TestRun grant was rejected");
        }
        return new Admission(registered, reviewer.actorId());
    }

    private boolean expired(ContractReviewerCredentials.Session session) {
        return session.expiresAt() <= Instant.now().getEpochSecond();
    }

    private BusinessException authRequired() {
        return new BusinessException(ErrorCode.OPERATOR_AUTH_REQUIRED, "A valid reviewer session is required");
    }
}
