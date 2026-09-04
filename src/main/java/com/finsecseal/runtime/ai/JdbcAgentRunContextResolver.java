package com.finsecseal.runtime.ai;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class JdbcAgentRunContextResolver implements AgentRunContextResolver {

    private final JdbcTemplate jdbcTemplate;

    public JdbcAgentRunContextResolver(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public ResolvedRunContext resolve(UUID testRunId) {
        if (testRunId == null) {
            throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, "TestRun id is required for AI context");
        }

        List<ResolvedRunContext> matches = jdbcTemplate.query(
                "select release_id from test_runs where id = ?",
                (resultSet, rowNumber) -> new ResolvedRunContext(
                        resultSet.getObject("release_id", UUID.class)
                ),
                testRunId
        );

        if (matches.size() != 1 || matches.getFirst().releaseId() == null) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "Trusted AI run context is missing or duplicated"
            );
        }
        return matches.getFirst();
    }
}
