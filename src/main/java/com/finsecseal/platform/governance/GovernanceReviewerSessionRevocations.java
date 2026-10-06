package com.finsecseal.platform.governance;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.release.DigestService;
import java.sql.Timestamp;
import java.time.Instant;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/** Durable, one-way governance revocation; no cookie, CSRF or credential is persisted. */
@Component
public final class GovernanceReviewerSessionRevocations {
    private final JdbcTemplate db;
    private final DigestService digest;
    private final GovernanceReviewerCredentials credentials;

    public GovernanceReviewerSessionRevocations(JdbcTemplate db, DigestService digest,
            GovernanceReviewerCredentials credentials) {
        this.db = db;
        this.digest = digest;
        this.credentials = credentials;
    }

    boolean isRevoked(GovernanceReviewerContext identity) {
        requireCurrent(identity, false);
        return Boolean.TRUE.equals(db.queryForObject(
                "select exists(select 1 from reviewer_session_revocations where session_digest = ?)",
                Boolean.class, sessionDigest(identity)));
    }

    void revoke(GovernanceReviewerContext mutation) {
        requireCurrent(mutation, true);
        db.update("""
                insert into reviewer_session_revocations (session_digest, expires_at)
                values (?, ?) on conflict (session_digest) do nothing
                """, sessionDigest(mutation), Timestamp.from(Instant.ofEpochSecond(mutation.expiresAt())));
    }

    private void requireCurrent(GovernanceReviewerContext identity, boolean mutation) {
        if (!credentials.current(identity, mutation)) {
            throw new BusinessException(ErrorCode.OPERATOR_AUTH_REQUIRED,
                    "Current governance reviewer authority required");
        }
    }

    private String sessionDigest(GovernanceReviewerContext identity) {
        return digest.sha256("FINSEC_GOVERNANCE_SESSION_ID_V1:"
                + identity.workspaceId() + ":" + identity.sessionId());
    }
}
