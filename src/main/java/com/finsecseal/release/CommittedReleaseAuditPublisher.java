package com.finsecseal.release;

import com.finsecseal.audit.AuditDto;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.JsonNode;

@Component
final class CommittedReleaseAuditPublisher {

    private static final Logger LOG = LoggerFactory.getLogger(CommittedReleaseAuditPublisher.class);
    private static final Set<String> ACTIONS = Set.of(
            "AGENT_RELEASE_INVALIDATED", "RELEASE_CONTRACT_FINGERPRINT_APPLIED"
    );
    private static final int MAX_CAUSE_CLASS_LENGTH = 128;

    private final ApplicationEventPublisher publisher;

    CommittedReleaseAuditPublisher(ApplicationEventPublisher publisher) {
        this.publisher = Objects.requireNonNull(publisher, "publisher");
    }

    void requireWritableTransaction() {
        if (!TransactionSynchronizationManager.isActualTransactionActive()
                || !TransactionSynchronizationManager.isSynchronizationActive()
                || TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
            throw new IllegalStateException("Release audit notification requires a writable synchronized transaction");
        }
    }

    void register(AuditDto.Record receipt, UUID expectedWorkspace, UUID expectedRelease, String expectedAction) {
        requireWritableTransaction();
        if (receipt == null || receipt.id() == null || receipt.workspaceId() == null
                || receipt.resourceId() == null || receipt.occurredAt() == null
                || expectedWorkspace == null || expectedRelease == null || expectedAction == null
                || !expectedWorkspace.equals(receipt.workspaceId())
                || !expectedRelease.equals(receipt.resourceId())
                || !"AGENT_RELEASE".equals(receipt.resourceType())
                || !ACTIONS.contains(expectedAction) || !expectedAction.equals(receipt.action())) {
            throw new IllegalArgumentException("Release audit receipt does not match the owner mutation");
        }
        JsonNode metadata = receipt.metadata() == null ? null : receipt.metadata().deepCopy();
        AuditDto.Record snapshot = new AuditDto.Record(
                receipt.id(), receipt.workspaceId(), receipt.actorId(), receipt.action(), receipt.resourceType(),
                receipt.resourceId(), receipt.beforeDigest(), receipt.afterDigest(), metadata, receipt.occurredAt()
        );
        requireWritableTransaction();
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                try {
                    publisher.publishEvent(snapshot);
                } catch (RuntimeException failure) {
                    LOG.warn("Committed Release audit notification failed auditId={} releaseId={} action={} causeClass={}",
                            snapshot.id(), snapshot.resourceId(), snapshot.action(), boundedCauseClass(failure));
                }
            }
        });
    }

    private static String boundedCauseClass(RuntimeException failure) {
        String name = failure.getClass().getName().replaceAll("[^A-Za-z0-9_.$]", "_");
        return name.substring(0, Math.min(name.length(), MAX_CAUSE_CLASS_LENGTH));
    }
}
