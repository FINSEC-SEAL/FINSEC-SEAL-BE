package com.finsecseal.release;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.JsonNodeFactory;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ReleaseLifecycleState;
import com.finsecseal.common.persistence.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "agent_releases")
public class AgentReleaseEntity extends BaseEntity {

    @Column(name = "agent_id", nullable = false, updatable = false)
    private UUID agentId;

    @Column(nullable = false, length = 50)
    private String version;

    @Column(name = "business_purpose", nullable = false, length = 100)
    private String businessPurpose;

    @Column(name = "manifest_schema_version", nullable = false, length = 20)
    private String manifestSchemaVersion;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "manifest_json", nullable = false, columnDefinition = "jsonb")
    private JsonNode manifestJson;

    @Column(name = "agent_artifact_fingerprint", nullable = false, columnDefinition = "sha256_digest")
    private String agentArtifactFingerprint;

    @Column(name = "release_fingerprint", nullable = false, columnDefinition = "sha256_digest")
    private String releaseFingerprint;

    @Column(name = "safety_contract_hash", columnDefinition = "sha256_digest")
    private String safetyContractHash;

    @Enumerated(EnumType.STRING)
    @Column(name = "lifecycle_state", nullable = false, length = 30)
    private ReleaseLifecycleState lifecycleState;

    @Enumerated(EnumType.STRING)
    @Column(name = "effective_status", nullable = false, length = 30)
    private ReleaseLifecycleState effectiveStatus;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "revalidation_reason_json", nullable = false, columnDefinition = "jsonb")
    private JsonNode revalidationReasonJson;

    @Column(name = "analyzed_at")
    private Instant analyzedAt;

    @Column(name = "last_tested_at")
    private Instant lastTestedAt;

    protected AgentReleaseEntity() {
    }

    public AgentReleaseEntity(
            UUID agentId,
            String version,
            String businessPurpose,
            String manifestSchemaVersion,
            JsonNode manifestJson,
            String agentArtifactFingerprint,
            String releaseFingerprint
    ) {
        this.agentId = agentId;
        this.version = version;
        this.businessPurpose = businessPurpose;
        this.manifestSchemaVersion = manifestSchemaVersion;
        this.manifestJson = manifestJson.deepCopy();
        this.agentArtifactFingerprint = agentArtifactFingerprint;
        this.releaseFingerprint = releaseFingerprint;
        this.lifecycleState = ReleaseLifecycleState.DRAFT;
        this.effectiveStatus = ReleaseLifecycleState.DRAFT;
        this.revalidationReasonJson = JsonNodeFactory.instance.objectNode();
    }

    public void transitionTo(ReleaseLifecycleState target) {
        if (!lifecycleState.canTransitionTo(target)) {
            throw new BusinessException(
                    ErrorCode.INVALID_STATE_TRANSITION,
                    "Release cannot transition from " + lifecycleState + " to " + target
            );
        }
        lifecycleState = target;
        effectiveStatus = target;
        if (target == ReleaseLifecycleState.ANALYZED) {
            analyzedAt = Instant.now();
        }
    }

    public void applySafetyContract(String contractHash, String finalFingerprint, JsonNode reason) {
        this.safetyContractHash = contractHash;
        this.releaseFingerprint = finalFingerprint;
        if (lifecycleState.isTerminalDecision()) {
            lifecycleState = ReleaseLifecycleState.NEEDS_REVALIDATION;
            effectiveStatus = ReleaseLifecycleState.NEEDS_REVALIDATION;
            revalidationReasonJson = copyReason(reason);
        } else if (lifecycleState == ReleaseLifecycleState.REMEDIATION) {
            transitionTo(ReleaseLifecycleState.VERIFYING);
        }
    }

    public void invalidate(JsonNode reason) {
        if (!lifecycleState.isTerminalDecision()) {
            throw new BusinessException(ErrorCode.INVALID_STATE_TRANSITION, "Only a terminal Release can be invalidated");
        }
        lifecycleState = ReleaseLifecycleState.NEEDS_REVALIDATION;
        effectiveStatus = ReleaseLifecycleState.NEEDS_REVALIDATION;
        revalidationReasonJson = copyReason(reason);
    }

    public UUID getAgentId() {
        return agentId;
    }

    public String getVersion() {
        return version;
    }

    public String getBusinessPurpose() {
        return businessPurpose;
    }

    public String getManifestSchemaVersion() {
        return manifestSchemaVersion;
    }

    public JsonNode getManifestJson() {
        return manifestJson.deepCopy();
    }

    public String getAgentArtifactFingerprint() {
        return agentArtifactFingerprint;
    }

    public String getReleaseFingerprint() {
        return releaseFingerprint;
    }

    public String getSafetyContractHash() {
        return safetyContractHash;
    }

    public ReleaseLifecycleState getLifecycleState() {
        return lifecycleState;
    }

    public ReleaseLifecycleState getEffectiveStatus() {
        return effectiveStatus;
    }

    public JsonNode getRevalidationReasonJson() {
        return revalidationReasonJson.deepCopy();
    }

    public Instant getAnalyzedAt() {
        return analyzedAt;
    }

    public Instant getLastTestedAt() {
        return lastTestedAt;
    }

    private JsonNode copyReason(JsonNode reason) {
        return reason == null ? JsonNodeFactory.instance.objectNode() : reason.deepCopy();
    }
}
