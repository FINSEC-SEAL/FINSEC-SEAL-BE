package com.finsecseal.audit;

import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
public class PromptAccessRollbackListener {

    private final RollbackAuditWriter rollbackAuditWriter;

    public PromptAccessRollbackListener(RollbackAuditWriter rollbackAuditWriter) {
        this.rollbackAuditWriter = rollbackAuditWriter;
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_ROLLBACK)
    public void preserve(PromptAccessRolledBackEvent event) {
        rollbackAuditWriter.append(event);
    }
}
