package com.finsecseal.policy;

import com.finsecseal.audit.AuditDto;
import java.util.Objects;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/** Conservatively evicts local validation metadata without granting policy authority. */
@Component
public final class CommittedReleasePolicyCacheListener {

    private final GatewayApprovedPolicySourceService policySources;

    public CommittedReleasePolicyCacheListener(GatewayApprovedPolicySourceService policySources) {
        this.policySources = Objects.requireNonNull(policySources);
    }

    @EventListener
    public void onCommittedReleaseAudit(AuditDto.Record record) {
        if (record == null || record.id() == null || record.workspaceId() == null
                || record.resourceId() == null || record.occurredAt() == null
                || !"AGENT_RELEASE".equals(record.resourceType())
                || !("AGENT_RELEASE_INVALIDATED".equals(record.action())
                || "RELEASE_CONTRACT_FINGERPRINT_APPLIED".equals(record.action()))) {
            return;
        }
        policySources.invalidateRelease(record.resourceId());
    }
}
