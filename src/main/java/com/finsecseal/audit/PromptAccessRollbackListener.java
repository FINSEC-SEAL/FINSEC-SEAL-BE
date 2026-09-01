package com.finsecseal.audit;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
public class PromptAccessRollbackListener {

    private final JdbcTemplate jdbcTemplate;
    private final AuditService auditService;

    public PromptAccessRollbackListener(JdbcTemplate jdbcTemplate, AuditService auditService) {
        this.jdbcTemplate = jdbcTemplate;
        this.auditService = auditService;
    }

    @Async("auditExecutor")
    @TransactionalEventListener(phase = TransactionPhase.AFTER_ROLLBACK)
    public void preserve(PromptAccessRolledBackEvent event) {
        Boolean releaseExists = jdbcTemplate.queryForObject(
                "select exists(select 1 from agent_releases where id = ?)",
                Boolean.class,
                event.releaseId()
        );
        if (!Boolean.TRUE.equals(releaseExists)) {
            return;
        }
        auditService.appendRequiresNew(
                event.workspaceId(),
                event.actorId(),
                "SYSTEM_PROMPT_DECRYPTED_INTERNAL",
                "AGENT_RELEASE",
                event.releaseId(),
                null,
                event.artifactDigest(),
                event.metadata()
        );
    }
}
