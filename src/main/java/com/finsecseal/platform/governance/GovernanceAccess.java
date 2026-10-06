package com.finsecseal.platform.governance;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.api.IdempotencyFilter;
import com.finsecseal.common.api.IdempotencyInstanceLease;
import com.finsecseal.common.api.TraceIdFilter;
import jakarta.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Objects;
import java.util.UUID;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.ConnectionHolder;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/** Governance authority plus actual request admission; never a caller-supplied identity. */
@Component
public final class GovernanceAccess {
    private static final String FACTS = GovernanceAccess.class.getName() + ".filterFacts";
    private final JdbcTemplate db;
    private final GovernanceReviewerCredentials credentials;
    private final GovernanceReviewerSessionRevocations revocations;
    private final IdempotencyInstanceLease instance;

    public GovernanceAccess(JdbcTemplate db, GovernanceReviewerCredentials credentials,
            GovernanceReviewerSessionRevocations revocations, IdempotencyInstanceLease instance) {
        this.db = db;
        this.credentials = credentials;
        this.revocations = revocations;
        this.instance = instance;
    }

    void establish(HttpServletRequest request, GovernanceReviewerCredentials.Session session,
            GovernanceReviewerContext identity, UUID findingId, String key, boolean logout, boolean issued) {
        if (session == null || !credentials.current(identity, key != null)
                || !identity.sessionId().equals(session.identity().sessionId())) throw denied();
        String trace = TraceIdFilter.currentTraceId();
        try { UUID.fromString(trace); } catch (RuntimeException invalid) { throw denied(); }
        request.setAttribute(FACTS, new FilterFacts(this, session, identity, findingId, key,
                request.getMethod(), request.getRequestURI(), trace, logout, issued));
    }

    void requireFindingWorkspace(GovernanceReviewerContext identity, UUID findingId) {
        if (!credentials.current(identity, true) || findingId == null
                || !Boolean.TRUE.equals(db.queryForObject("""
                    select exists(select 1 from findings f
                        join agent_releases r on r.id=f.release_id
                        join agents a on a.id=r.agent_id
                        where f.id=? and a.workspace_id=?)
                    """, Boolean.class, findingId, identity.workspaceId()))) throw denied();
    }

    /** Public Admission is a raw record: private filter facts and its live DB reservation are also required. */
    public MutationContext requireMutationContext(HttpServletRequest request) {
        FilterFacts facts = facts(request);
        if (facts.logout || facts.findingId == null || !"POST".equals(facts.method)
                || !credentials.current(facts.identity, true) || revocations.isRevoked(facts.identity)) throw denied();
        IdempotencyFilter.Admission admission = admission(request, facts);
        return new MutationContext(this, facts, admission.recordId(), admission.requestDigest());
    }

    /** CPU-only privacy/request binding; not current authority or a transaction commit fence. */
    public void requireSafeAuditComment(MutationContext context, HttpServletRequest actualRequest,
            String exactFinalComment) {
        if (context == null || context.issuer != this || actualRequest == null
                || context.facts.logout || context.facts.findingId == null
                || !"POST".equals(context.facts.method)
                || !credentials.safeAuditComment(context.facts.session, context.facts.identity,
                        actualRequest, context.facts.key, exactFinalComment)
                || facts(actualRequest) != context.facts) throw denied();
    }

    /** Call after ALL consumer locks, immediately before the first write, including source TestRun locks. */
    public void verifyMutation(MutationContext context, UUID storedWorkspaceId, UUID lockedFindingId) {
        if (context == null || context.issuer != this
                || !Objects.equals(context.facts.findingId, lockedFindingId)
                || !Objects.equals(context.facts.identity.workspaceId(), storedWorkspaceId)
                || !Objects.equals(context.facts.trace, TraceIdFilter.currentTraceId())
                || !credentials.current(context.facts.identity, true)) throw denied();
        requireWritableReadCommitted();
        requireFindingWorkspace(context.facts.identity, lockedFindingId);
        requireReservation(context.facts, context.admissionId, context.requestDigest);
        if (revocations.isRevoked(context.facts.identity)
                || !credentials.current(context.facts.identity, true)) throw denied();
        // READ_COMMITTED observes revocations committed at the above statement. This is not a commit fence.
    }

    GovernanceReviewerCredentials.Session currentSession(HttpServletRequest request) {
        FilterFacts facts = facts(request);
        if (!"GET".equals(facts.method) || !credentials.current(facts.identity, false)
                || revocations.isRevoked(facts.identity)) throw denied();
        return facts.session;
    }

    boolean issued(HttpServletRequest request) { return facts(request).issued; }

    GovernanceReviewerContext requireLogout(HttpServletRequest request, UUID ownSessionId) {
        FilterFacts facts = facts(request);
        if (!facts.logout || !"DELETE".equals(facts.method)
                || !Objects.equals(facts.identity.sessionId(), ownSessionId)
                || !credentials.current(facts.identity, true)) throw denied();
        admission(request, facts);
        requireWritableReadCommitted();
        return facts.identity; // Already-revoked own sessions may repeat while current and CSRF-authenticated.
    }

    private FilterFacts facts(HttpServletRequest request) {
        if (!(request.getAttribute(FACTS) instanceof FilterFacts facts) || facts.issuer != this
                || !facts.method.equals(request.getMethod()) || !facts.path.equals(request.getRequestURI())
                || request.getQueryString() != null
                || !facts.trace.equals(TraceIdFilter.currentTraceId())
                || (facts.key != null && !facts.key.equals(
                        GovernanceReviewerCredentials.singleHeader(request, "Idempotency-Key")))) throw denied();
        return facts;
    }

    private IdempotencyFilter.Admission admission(HttpServletRequest request, FilterFacts facts) {
        if (!(request.getAttribute(IdempotencyFilter.ADMISSION) instanceof IdempotencyFilter.Admission value))
            throw denied();
        requireReservation(facts, value.recordId(), value.requestDigest());
        return value;
    }

    private void requireReservation(FilterFacts facts, UUID admissionId, String digest) {
        if (facts.key == null || admissionId == null || digest == null
                || !Boolean.TRUE.equals(db.queryForObject("""
                    select exists(select 1 from api_idempotency_records
                        where id=? and request_digest=? and workspace_id=? and actor_id=?
                        and http_method=? and request_path=? and idempotency_key=?
                        and state='PROCESSING' and owner_instance_id=? and expires_at>clock_timestamp())
                    """, Boolean.class, admissionId, digest, facts.identity.workspaceId(), facts.identity.actorId(),
                    facts.method, facts.path, facts.key, instance.instanceId()))) throw denied();
    }

    private void requireWritableReadCommitted() {
        DataSource source = db.getDataSource();
        if (source == null || !TransactionSynchronizationManager.isActualTransactionActive()
                || !TransactionSynchronizationManager.isSynchronizationActive()
                || TransactionSynchronizationManager.isCurrentTransactionReadOnly()
                || !(TransactionSynchronizationManager.getResource(source) instanceof ConnectionHolder holder)) throw denied();
        try {
            Connection connection = holder.getConnection();
            if (!DataSourceUtils.isConnectionTransactional(connection, source) || connection.getAutoCommit()
                    || connection.isReadOnly()
                    || connection.getTransactionIsolation() != Connection.TRANSACTION_READ_COMMITTED) throw denied();
            try (var statement = connection.createStatement()) {
                try (var isolation = statement.executeQuery("show transaction_isolation")) {
                    if (!isolation.next() || !"read committed".equals(isolation.getString(1))) throw denied();
                }
                try (var readOnly = statement.executeQuery("show transaction_read_only")) {
                    if (!readOnly.next() || !"off".equals(readOnly.getString(1))) throw denied();
                }
            }
        } catch (SQLException | IllegalStateException unavailable) { throw denied(); }
    }

    private static BusinessException denied() {
        return new BusinessException(ErrorCode.OPERATOR_AUTH_REQUIRED,
                "Current admitted governance mutation authority required");
    }

    private record FilterFacts(GovernanceAccess issuer, GovernanceReviewerCredentials.Session session,
            GovernanceReviewerContext identity, UUID findingId, String key, String method,
            String path, String trace, boolean logout, boolean issued) {
        @Override public String toString() { return "GovernanceFilterFacts[redacted]"; }
    }

    /** Issued only after the early filter and actual common reservation. Getters are non-secret audit facts. */
    public static final class MutationContext {
        private final GovernanceAccess issuer;
        private final FilterFacts facts;
        private final UUID admissionId;
        private final String requestDigest;
        private MutationContext(GovernanceAccess issuer, FilterFacts facts, UUID admissionId, String requestDigest) {
            this.issuer = issuer; this.facts = facts; this.admissionId = admissionId; this.requestDigest = requestDigest;
        }
        public UUID workspaceId() { return facts.identity.workspaceId(); }
        public String actorId() { return facts.identity.actorId(); }
        public String role() { return facts.identity.role(); }
        public UUID sessionId() { return facts.identity.sessionId(); }
        public long expiresAt() { return facts.identity.expiresAt(); }
        public boolean demoMode() { return facts.identity.demoMode(); }
        public UUID findingId() { return facts.findingId; }
        public String traceId() { return facts.trace; }
        public String idempotencyKey() { return facts.key; }
        public UUID idempotencyRecordId() { return admissionId; }
        public String requestDigest() { return requestDigest; }
        @Override public String toString() { return "GovernanceMutationContext[redacted]"; }
    }
}
