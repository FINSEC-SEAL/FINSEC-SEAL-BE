package com.finsecseal.execution;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

class ExecutionDispatchServiceTest {

    @Test
    void dispatchesFa02TestCaseToFa02Orchestrator() {
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        Fa02ExecutionOrchestrator fa02 = mock(Fa02ExecutionOrchestrator.class);
        Fa03ExecutionOrchestrator fa03 = mock(Fa03ExecutionOrchestrator.class);
        Fa04ExecutionOrchestrator fa04 = mock(Fa04ExecutionOrchestrator.class);
        Fa05ExecutionOrchestrator fa05 = mock(Fa05ExecutionOrchestrator.class);

        UUID runId = UUID.randomUUID();
        UUID testCaseId = UUID.randomUUID();
        UUID caseRunId = UUID.randomUUID();
        UUID traceId = UUID.randomUUID();
        UUID oracleResultId = UUID.randomUUID();
        UUID findingId = UUID.randomUUID();
        String actorId = "frontend-b";

        when(jdbcTemplate.queryForObject(
                anyString(), eq(String.class), eq(runId), eq(testCaseId)
        )).thenReturn("FA-02");

        Fa02ExecutionOrchestrator.Result orchestratorResult =
                new Fa02ExecutionOrchestrator.Result(
                        runId,
                        caseRunId,
                        traceId,
                        "ATTACK_BLOCKED",
                        "CUSTOMER_BOUNDARY_ENFORCED",
                        oracleResultId,
                        findingId,
                        "sha256:" + "a".repeat(64),
                        true
                );
        when(fa02.execute(runId, testCaseId, actorId)).thenReturn(orchestratorResult);

        ExecutionDispatchService service =
                new ExecutionDispatchService(jdbcTemplate, fa02, fa03, fa04, fa05);

        ExecutionDispatchService.Result result =
                service.execute(runId, testCaseId, actorId);

        assertThat(result.runId()).isEqualTo(runId);
        assertThat(result.caseRunId()).isEqualTo(caseRunId);
        assertThat(result.traceId()).isEqualTo(traceId);
        assertThat(result.oracleOutcome()).isEqualTo("ATTACK_BLOCKED");
        assertThat(result.reasonCode()).isEqualTo("CUSTOMER_BOUNDARY_ENFORCED");
        assertThat(result.oracleResultId()).isEqualTo(oracleResultId);
        assertThat(result.findingId()).isEqualTo(findingId);
        assertThat(result.variantHash()).isEqualTo("sha256:" + "a".repeat(64));
        assertThat(result.deliveredToAgent()).isTrue();

        verify(fa02).execute(runId, testCaseId, actorId);
        verifyNoInteractions(fa03, fa04, fa05);
    }
    @Test
    void dispatchesFa03TestCaseToFa03Orchestrator() {
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        Fa02ExecutionOrchestrator fa02 = mock(Fa02ExecutionOrchestrator.class);
        Fa03ExecutionOrchestrator fa03 = mock(Fa03ExecutionOrchestrator.class);
        Fa04ExecutionOrchestrator fa04 = mock(Fa04ExecutionOrchestrator.class);
        Fa05ExecutionOrchestrator fa05 = mock(Fa05ExecutionOrchestrator.class);

        UUID runId = UUID.randomUUID();
        UUID testCaseId = UUID.randomUUID();
        UUID caseRunId = UUID.randomUUID();
        UUID traceId = UUID.randomUUID();
        UUID oracleResultId = UUID.randomUUID();
        String actorId = "frontend-b";

        when(jdbcTemplate.queryForObject(
                anyString(), eq(String.class), eq(runId), eq(testCaseId)
        )).thenReturn("FA-03");

        Fa03ExecutionOrchestrator.Result orchestratorResult =
                new Fa03ExecutionOrchestrator.Result(
                        runId,
                        caseRunId,
                        traceId,
                        "ATTACK_BLOCKED",
                        "SENSITIVE_FIELD_BLOCKED",
                        oracleResultId,
                        null,
                        "sha256:" + "b".repeat(64),
                        true
                );
        when(fa03.execute(runId, testCaseId, actorId)).thenReturn(orchestratorResult);

        ExecutionDispatchService service =
                new ExecutionDispatchService(jdbcTemplate, fa02, fa03, fa04, fa05);

        ExecutionDispatchService.Result result =
                service.execute(runId, testCaseId, actorId);

        assertThat(result.runId()).isEqualTo(runId);
        assertThat(result.caseRunId()).isEqualTo(caseRunId);
        assertThat(result.traceId()).isEqualTo(traceId);
        assertThat(result.oracleOutcome()).isEqualTo("ATTACK_BLOCKED");
        assertThat(result.reasonCode()).isEqualTo("SENSITIVE_FIELD_BLOCKED");
        assertThat(result.oracleResultId()).isEqualTo(oracleResultId);
        assertThat(result.findingId()).isNull();
        assertThat(result.variantHash()).isEqualTo("sha256:" + "b".repeat(64));
        assertThat(result.deliveredToAgent()).isTrue();

        verify(fa03).execute(runId, testCaseId, actorId);
        verifyNoInteractions(fa02, fa04, fa05);
    }

    @Test
    void dispatchesFa04TestCaseToFa04Orchestrator() {
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        Fa02ExecutionOrchestrator fa02 = mock(Fa02ExecutionOrchestrator.class);
        Fa03ExecutionOrchestrator fa03 = mock(Fa03ExecutionOrchestrator.class);
        Fa04ExecutionOrchestrator fa04 = mock(Fa04ExecutionOrchestrator.class);
        Fa05ExecutionOrchestrator fa05 = mock(Fa05ExecutionOrchestrator.class);

        UUID runId = UUID.randomUUID();
        UUID testCaseId = UUID.randomUUID();
        UUID caseRunId = UUID.randomUUID();
        UUID traceId = UUID.randomUUID();
        UUID oracleResultId = UUID.randomUUID();
        UUID findingId = UUID.randomUUID();
        String actorId = "frontend-b";

        when(jdbcTemplate.queryForObject(
                anyString(), eq(String.class), eq(runId), eq(testCaseId)
        )).thenReturn("FA-04");

        Fa04ExecutionOrchestrator.Result orchestratorResult =
                new Fa04ExecutionOrchestrator.Result(
                        runId,
                        caseRunId,
                        traceId,
                        "ATTACK_BLOCKED",
                        "HIGH_IMPACT_TOOL_BLOCKED",
                        oracleResultId,
                        findingId,
                        "sha256:" + "c".repeat(64),
                        true
                );
        when(fa04.execute(runId, testCaseId, actorId)).thenReturn(orchestratorResult);

        ExecutionDispatchService service =
                new ExecutionDispatchService(jdbcTemplate, fa02, fa03, fa04, fa05);

        ExecutionDispatchService.Result result =
                service.execute(runId, testCaseId, actorId);

        assertThat(result.runId()).isEqualTo(runId);
        assertThat(result.caseRunId()).isEqualTo(caseRunId);
        assertThat(result.traceId()).isEqualTo(traceId);
        assertThat(result.oracleOutcome()).isEqualTo("ATTACK_BLOCKED");
        assertThat(result.reasonCode()).isEqualTo("HIGH_IMPACT_TOOL_BLOCKED");
        assertThat(result.oracleResultId()).isEqualTo(oracleResultId);
        assertThat(result.findingId()).isEqualTo(findingId);
        assertThat(result.variantHash()).isEqualTo("sha256:" + "c".repeat(64));
        assertThat(result.deliveredToAgent()).isTrue();

        verify(fa04).execute(runId, testCaseId, actorId);
        verifyNoInteractions(fa02, fa03, fa05);
    }

    @Test
    void dispatchesFa05TestCaseToFa05Orchestrator() {
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        Fa02ExecutionOrchestrator fa02 = mock(Fa02ExecutionOrchestrator.class);
        Fa03ExecutionOrchestrator fa03 = mock(Fa03ExecutionOrchestrator.class);
        Fa04ExecutionOrchestrator fa04 = mock(Fa04ExecutionOrchestrator.class);
        Fa05ExecutionOrchestrator fa05 = mock(Fa05ExecutionOrchestrator.class);

        UUID runId = UUID.randomUUID();
        UUID testCaseId = UUID.randomUUID();
        UUID caseRunId = UUID.randomUUID();
        UUID traceId = UUID.randomUUID();
        UUID oracleResultId = UUID.randomUUID();
        String actorId = "frontend-b";

        when(jdbcTemplate.queryForObject(
                anyString(), eq(String.class), eq(runId), eq(testCaseId)
        )).thenReturn("FA-05");

        Fa05ExecutionOrchestrator.Result orchestratorResult =
                new Fa05ExecutionOrchestrator.Result(
                        runId,
                        caseRunId,
                        traceId,
                        "ATTACK_BLOCKED",
                        "EXFILTRATION_BLOCKED",
                        oracleResultId,
                        null,
                        "sha256:" + "d".repeat(64),
                        true
                );
        when(fa05.execute(runId, testCaseId, actorId)).thenReturn(orchestratorResult);

        ExecutionDispatchService service =
                new ExecutionDispatchService(jdbcTemplate, fa02, fa03, fa04, fa05);

        ExecutionDispatchService.Result result =
                service.execute(runId, testCaseId, actorId);

        assertThat(result.runId()).isEqualTo(runId);
        assertThat(result.caseRunId()).isEqualTo(caseRunId);
        assertThat(result.traceId()).isEqualTo(traceId);
        assertThat(result.oracleOutcome()).isEqualTo("ATTACK_BLOCKED");
        assertThat(result.reasonCode()).isEqualTo("EXFILTRATION_BLOCKED");
        assertThat(result.oracleResultId()).isEqualTo(oracleResultId);
        assertThat(result.findingId()).isNull();
        assertThat(result.variantHash()).isEqualTo("sha256:" + "d".repeat(64));
        assertThat(result.deliveredToAgent()).isTrue();

        verify(fa05).execute(runId, testCaseId, actorId);
        verifyNoInteractions(fa02, fa03, fa04);
    }

}
