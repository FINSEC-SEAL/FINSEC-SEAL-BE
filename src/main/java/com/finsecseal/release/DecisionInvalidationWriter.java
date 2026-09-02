package com.finsecseal.release;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.persistence.UuidV7;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;

@Component
public class DecisionInvalidationWriter {

    private final JdbcTemplate jdbcTemplate;

    public DecisionInvalidationWriter(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public UUID invalidateLatest(UUID releaseId, JsonNode reasons, String actorId) {
        UUID decisionId = jdbcTemplate.query("""
                select id from release_decisions
                 where release_id = ?
                 order by confirmed_at desc, created_at desc, id desc
                 limit 1
                 for update
                """, resultSet -> resultSet.next() ? resultSet.getObject("id", UUID.class) : null, releaseId);
        if (decisionId == null) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Terminal Release has no Decision evidence to invalidate"
            );
        }
        UUID invalidationId = UuidV7.generate();
        try {
            jdbcTemplate.update("""
                    insert into decision_invalidations
                        (id, release_decision_id, reasons_json, invalidated_by, invalidated_at)
                    values (?, ?, cast(? as jsonb), ?, now())
                    """, invalidationId, decisionId, reasons.toString(), actorId);
        } catch (DataIntegrityViolationException exception) {
            throw new BusinessException(ErrorCode.RESOURCE_CONFLICT, "Latest Release Decision is already invalidated");
        }
        return invalidationId;
    }
}
