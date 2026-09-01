package com.finsecseal.evidence;

import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import java.time.Instant;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

public final class TestRunDto {

    private TestRunDto() {
    }

    public record Projection(
            UUID id,
            UUID releaseId,
            UUID suiteId,
            UUID contractVersionId,
            TestRunMode mode,
            TestRunStatus status,
            String agentArtifactFingerprint,
            String releaseFingerprint,
            String fixtureVersion,
            String fixtureDigest,
            int totalCases,
            int completedCases,
            int operationalErrorCount,
            long latestSequence,
            ExecutionEventType latestEventType,
            String eventHeadHash,
            JsonNode summary,
            Instant startedAt,
            Instant completedAt,
            Instant createdAt
    ) {
    }
}
