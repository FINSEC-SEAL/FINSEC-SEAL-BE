package com.finsecseal.audit;

import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.JsonNode;

@Service
public class PromptAccessAuditService {

    private final AuditService auditService;
    private final JdbcTemplate jdbcTemplate;
    private final TransactionTemplate independentRead;

    public PromptAccessAuditService(
            AuditService auditService,
            JdbcTemplate jdbcTemplate,
            PlatformTransactionManager transactionManager
    ) {
        this.auditService = auditService;
        this.jdbcTemplate = jdbcTemplate;
        this.independentRead = new TransactionTemplate(transactionManager);
        this.independentRead.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.independentRead.setReadOnly(true);
    }

    public void appendRollbackSafe(
            UUID workspaceId,
            String actorId,
            UUID releaseId,
            String artifactDigest,
            JsonNode metadata
    ) {
        JsonNode safeMetadata = metadata.deepCopy();
        boolean releaseWasCommitted = independentlyCommitted(releaseId);
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
        if (releaseWasCommitted && TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCompletion(int status) {
                    if (status == TransactionSynchronization.STATUS_ROLLED_BACK) {
                        auditService.appendRequiresNew(
                                workspaceId,
                                actorId,
                                "SYSTEM_PROMPT_DECRYPTED_INTERNAL",
                                "AGENT_RELEASE",
                                releaseId,
                                null,
                                artifactDigest,
                                safeMetadata
                        );
                    }
                }
            });
        }
    }

    private boolean independentlyCommitted(UUID releaseId) {
        Boolean result = independentRead.execute(status -> jdbcTemplate.queryForObject(
                "select exists(select 1 from agent_releases where id = ?)",
                Boolean.class,
                releaseId
        ));
        return Boolean.TRUE.equals(result);
    }
}
