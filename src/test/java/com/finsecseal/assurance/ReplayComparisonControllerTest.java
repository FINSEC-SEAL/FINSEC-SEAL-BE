package com.finsecseal.assurance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ReplayComparisonControllerTest {

    @Test
    void returnsReplayComparisonDetail() {
        ReplayComparisonService service = mock(ReplayComparisonService.class);
        ReplayComparisonController controller = new ReplayComparisonController(service);
        UUID replayRunId = UUID.randomUUID();
        ReplayComparisonDto.Side baseline = side(TestRunMode.BASELINE);
        ReplayComparisonDto.Side replay = side(TestRunMode.SEAL_REPLAY);
        ReplayComparisonDto.Detail expected = new ReplayComparisonDto.Detail(
                replayRunId,
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                "FA-02",
                "CRITICAL",
                true,
                List.of(),
                baseline,
                replay,
                new ReplayComparisonDto.Difference(true, true, false, true, true)
        );
        when(service.find(replayRunId)).thenReturn(expected);

        ApiResponse<ReplayComparisonDto.Detail> response = controller.comparison(replayRunId);

        assertThat(response.data()).isEqualTo(expected);
        verify(service).find(replayRunId);
    }

    private ReplayComparisonDto.Side side(TestRunMode mode) {
        return new ReplayComparisonDto.Side(
                UUID.randomUUID(),
                UUID.randomUUID(),
                mode,
                TestRunStatus.COMPLETED,
                TestCaseRunStatus.PASSED,
                null,
                null,
                List.of(),
                List.of(),
                List.of(),
                List.of()
        );
    }
}
