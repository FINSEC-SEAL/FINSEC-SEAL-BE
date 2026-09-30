package com.finsecseal.runtime;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.TestRunStatus;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class RunCancellationProbe {

    private final JdbcTemplate jdbcTemplate;

    public RunCancellationProbe(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public boolean isCancellationRequested(UUID runId) {
        List<TestRunStatus> statuses = jdbcTemplate.query(
                "select status from test_runs where id = ?",
                (resultSet, rowNumber) -> TestRunStatus.valueOf(resultSet.getString("status")),
                runId
        );
        if (statuses.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "TestRun not found");
        }
        TestRunStatus status = statuses.getFirst();
        return status == TestRunStatus.CANCELLING || status == TestRunStatus.CANCELLED;
    }

    public void throwIfCancellationRequested(UUID runId) {
        if (isCancellationRequested(runId)) {
            throw new BusinessException(
                    ErrorCode.INVALID_STATE_TRANSITION,
                    "TestRun cancellation was requested"
            );
        }
    }
}
