package com.finsecseal.platform.governance;

import java.util.UUID;

/** Issuer-sealed identity. Reading identity is not proof of a mutation admission. */
public final class GovernanceReviewerContext {
    public static final String ROLE = "AI_GOVERNANCE_REVIEWER";
    private final GovernanceReviewerCredentials.Proof proof;
    private final UUID workspaceId;
    private final String actorId;
    private final UUID sessionId;
    private final long issuedAt;
    private final long expiresAt;
    private final String generation;
    private final boolean csrfVerified;

    private GovernanceReviewerContext(GovernanceReviewerCredentials.Proof proof, UUID workspaceId,
            String actorId, UUID sessionId, long issuedAt, long expiresAt, String generation,
            boolean csrfVerified) {
        this.proof = proof;
        this.workspaceId = workspaceId;
        this.actorId = actorId;
        this.sessionId = sessionId;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.generation = generation;
        this.csrfVerified = csrfVerified;
    }

    static GovernanceReviewerContext issued(GovernanceReviewerCredentials.Proof proof, UUID workspace,
            String actor, UUID sessionId, long issuedAt, long expiresAt, String generation,
            boolean csrfVerified) {
        return new GovernanceReviewerContext(proof, workspace, actor, sessionId,
                issuedAt, expiresAt, generation, csrfVerified);
    }

    public UUID workspaceId() { return workspaceId; }
    public String actorId() { return actorId; }
    public String role() { return ROLE; }
    public UUID sessionId() { return sessionId; }
    public long expiresAt() { return expiresAt; }
    public boolean demoMode() { return true; }

    boolean belongsTo(GovernanceReviewerCredentials expectedIssuer) {
        return proof != null && proof.matches(expectedIssuer, workspaceId, actorId, sessionId,
                issuedAt, expiresAt, generation, csrfVerified);
    }
    long issuedAt() { return issuedAt; }
    String generation() { return generation; }
    boolean csrfVerified() { return csrfVerified; }

    @Override public String toString() { return "GovernanceReviewerContext[redacted]"; }
}
