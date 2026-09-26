package com.finsecseal.platform.contract;

import com.finsecseal.release.DigestService;
import java.sql.Timestamp;
import java.time.Instant;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/** Shared, durable revocation state for server-issued reviewer sessions. */
@Component
public class ContractReviewerSessionRevocations {
    private final JdbcTemplate db;
    private final DigestService digest;

    public ContractReviewerSessionRevocations(JdbcTemplate db, DigestService digest) {
        this.db = db;
        this.digest = digest;
    }

    public boolean isRevoked(ContractReviewerCredentials.Session session) {
        if (session == null) return false;
        Integer count = db.queryForObject("select count(*) from reviewer_session_revocations where session_digest = ?",
                Integer.class, digest(session));
        return count != null && count > 0;
    }

    public void revoke(ContractReviewerCredentials.Session session) {
        db.update("""
                insert into reviewer_session_revocations (session_digest, expires_at)
                values (?, ?)
                on conflict (session_digest) do nothing
                """, digest(session), Timestamp.from(Instant.ofEpochSecond(session.expiresAt())));
    }

    private String digest(ContractReviewerCredentials.Session session) {
        var reviewer = session.reviewer();
        return digest.sha256("FINSEC_REVIEWER_SESSION_ID_V1:" + reviewer.workspaceId() + ":" + reviewer.sessionId());
    }
}
