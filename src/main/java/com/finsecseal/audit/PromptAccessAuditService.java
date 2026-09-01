package com.finsecseal.audit;

import java.util.UUID;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;

@Service
public class PromptAccessAuditService {

    private final AuditService auditService;
    private final ApplicationEventPublisher eventPublisher;

    public PromptAccessAuditService(
            AuditService auditService,
            ApplicationEventPublisher eventPublisher
    ) {
        this.auditService = auditService;
        this.eventPublisher = eventPublisher;
    }

    public void appendRollbackSafe(
            UUID workspaceId,
            String actorId,
            UUID releaseId,
            String artifactDigest,
            JsonNode metadata
    ) {
        JsonNode safeMetadata = metadata.deepCopy();
        auditService.append(
                workspaceId,
                actorId,
                "SYSTEM_PROMPT_DECRYPTED_INTERNAL",
                "AGENT_RELEASE",
                releaseId,
                null,
                artifactDigest,
                safeMetadata
        );
        eventPublisher.publishEvent(new PromptAccessRolledBackEvent(
                workspaceId,
                actorId,
                releaseId,
                artifactDigest,
                safeMetadata
        ));
    }
}
