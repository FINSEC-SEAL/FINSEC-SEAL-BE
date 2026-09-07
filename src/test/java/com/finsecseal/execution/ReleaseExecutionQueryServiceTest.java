package com.finsecseal.execution;

import static org.assertj.core.api.Assertions.assertThat;

import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class ReleaseExecutionQueryServiceTest {

    @Test
    void derivesReplayMismatchReasonsFromStoredFlagsAndPayload() {
        ReleaseExecutionQueryService service = new ReleaseExecutionQueryService(null, new ObjectMapper());

        ReleaseExecutionQueryService.ReplayComparisonPayload payload = service.replayComparisonPayload(
                """
                {
                  "comparable": false,
                  "mismatches": [
                    { "code": "TRIAL_INDEX_MISMATCH" },
                    "RAG_CONFIG_MISMATCH"
                  ]
                }
                """,
                new ReleaseExecutionQueryService.ReplayFlags(true, false, true, false, true)
        );

        assertThat(payload.comparable()).isFalse();
        assertThat(payload.mismatchReasons()).containsExactly(
                "TRIAL_INDEX_MISMATCH",
                "RAG_CONFIG_MISMATCH",
                "FIXTURE_DIGEST_MISMATCH",
                "VARIANT_HASH_MISMATCH"
        );
    }

    @Test
    void marksReplayAsComparableWhenPayloadAndFlagsAreClean() {
        ReleaseExecutionQueryService service = new ReleaseExecutionQueryService(null, new ObjectMapper());

        ReleaseExecutionQueryService.ReplayComparisonPayload payload = service.replayComparisonPayload(
                "{\"comparable\":true,\"mismatchReasons\":[]}",
                new ReleaseExecutionQueryService.ReplayFlags(true, true, true, true, true)
        );

        assertThat(payload.comparable()).isTrue();
        assertThat(payload.mismatchReasons()).isEmpty();
    }
}