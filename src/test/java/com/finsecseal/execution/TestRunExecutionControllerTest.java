package com.finsecseal.execution;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.evidence.TestRunPersistenceDto;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

class TestRunExecutionControllerTest {

    @Test
    void startsTestRunAndReturnsAcceptedResponse() {
        TestRunStartService startService = mock(TestRunStartService.class);
        TestRunExecutionController controller = new TestRunExecutionController(startService);

        UUID releaseId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        UUID firstCaseId = UUID.randomUUID();
        UUID secondCaseId = UUID.randomUUID();
        UUID runId = UUID.randomUUID();
        String actorId = "frontend-b";

        TestRunExecutionController.StartRequest request =
                new TestRunExecutionController.StartRequest(
                        releaseId,
                        suiteId,
                        TestRunMode.BASELINE,
                        null,
                        List.of(firstCaseId, secondCaseId),
                        1234L
                );

        TestRunPersistenceDto.Registered registered =
                new TestRunPersistenceDto.Registered(
                        runId,
                        TestRunStatus.QUEUED,
                        "/api/v1/test-runs/" + runId,
                        "/api/v1/test-runs/" + runId + "/events"
                );

        when(startService.start(
                new TestRunStartService.Request(
                        releaseId,
                        suiteId,
                        TestRunMode.BASELINE,
                        null,
                        List.of(firstCaseId, secondCaseId),
                        1234L
                ),
                actorId
        )).thenReturn(registered);

        ResponseEntity<ApiResponse<TestRunPersistenceDto.Registered>> response =
                controller.start(request, actorId);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().data()).isEqualTo(registered);

        verify(startService).start(
                new TestRunStartService.Request(
                        releaseId,
                        suiteId,
                        TestRunMode.BASELINE,
                        null,
                        List.of(firstCaseId, secondCaseId),
                        1234L
                ),
                actorId
        );
    }
}
