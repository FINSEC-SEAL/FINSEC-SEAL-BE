package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.runtime.ToolInvocation;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.sandbox.SandboxExecutionContext;
import com.finsecseal.sandbox.SandboxFixtureService;
import java.lang.reflect.Constructor;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Testcontainers
@SpringBootTest
class StateChangingToolIdempotencyIntegrationTest {

    private static final String HASH_A = "sha256:" + "a".repeat(64);
    private static final String HASH_B = "sha256:" + "b".repeat(64);
    private static final UUID WORKSPACE_ID =
            UUID.fromString("0198f1e2-0000-7000-8000-000000000001");
    private static final String ACTOR = "role-b";

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES =
            new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired
    JdbcTemplate jdbcTemplate;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    TestRunPersistenceService runPersistenceService;

    @Autowired
    SandboxFixtureService fixtureService;

    @Autowired
    ExecutionEventService eventService;

    @Autowired
    LoanDecisionUpdateMockToolAdapter adapter;

    @Autowired
    StateChangingToolExecutionService transactionalExecutor;

    @Autowired
    ToolDispatcher dispatcher;

    @Test
    void sameCaseRunAndToolCallMutatesLoanDecisionExactlyOnce() {
        Seed seed = seedRunWithSandbox();
        UUID traceId = UUID.randomUUID();

        SandboxExecutionContext context = new SandboxExecutionContext(
                seed.runId(),
                seed.caseRunId(),
                traceId,
                TestRunMode.BASELINE,
                "CASE-1001",
                "CUST-1001"
        );

        eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        null,
                        traceId,
                        ExecutionEventType.RUN_STARTED,
                        null,
                        null,
                        null,
                        null,
                        "RUN_STARTED",
                        objectMapper.createObjectNode()
                ),
                ACTOR
        );

        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.put("caseId", "CASE-1001");
        arguments.put("decision", "APPROVED");

        ToolProposal proposal = new ToolProposal(
                LoanDecisionUpdateMockToolAdapter.TOOL_NAME,
                arguments
        );

        ExecutionEventDto.Event proposalEvent = eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        seed.caseRunId(),
                        traceId,
                        ExecutionEventType.TOOL_PROPOSED,
                        proposal.toolName(),
                        proposal.arguments(),
                        null,
                        null,
                        "STRUCTURED_TOOL_PROPOSAL",
                        objectMapper.createObjectNode()
                ),
                ACTOR
        );

        ToolInvocation invocation = new ToolInvocation(
                proposal,
                proposalEvent.eventId(),
                proposalEvent.payloadDigest()
        );

        StateChangingToolExecutionService executor = executor();

        StateChangingToolExecutionService.Execution first =
                executor.execute(
                        context,
                        invocation,
                        adapter,
                        ACTOR
                );

        StateChangingToolExecutionService.Execution second =
                executor.execute(
                        context,
                        invocation,
                        adapter,
                        ACTOR
                );

        Long rowVersion = jdbcTemplate.queryForObject("""
                select row_version
                  from sandbox_loan_decisions
                 where namespace_id = ?
                   and case_key = 'CASE-1001'
                """, Long.class, seed.runId());

        assertThat(rowVersion)
                .as(
                        "same (test_case_run_id, tool_call_id) "
                                + "must mutate the sandbox exactly once"
                )
                .isEqualTo(1L);

        assertThat(first.replayed()).isFalse();
        assertThat(second.replayed())
                .as("the second identical invocation must replay the committed result")
                .isTrue();

        assertThat(first.responseEvent()).isNotNull();
        assertThat(second.responseEvent()).isNotNull();
        assertThat(second.responseEvent().eventId())
                .isEqualTo(first.responseEvent().eventId());

        Integer receiptCount = jdbcTemplate.queryForObject("""
                select count(*)
                  from sandbox_tool_idempotency_records
                 where test_case_run_id = ?
                   and tool_call_id = ?
                """, Integer.class, seed.caseRunId(), invocation.toolCallId());

        assertThat(receiptCount).isEqualTo(1);

        String receiptState = jdbcTemplate.queryForObject("""
                select state
                  from sandbox_tool_idempotency_records
                 where test_case_run_id = ?
                   and tool_call_id = ?
                """, String.class, seed.caseRunId(), invocation.toolCallId());

        assertThat(receiptState).isEqualTo("COMPLETED");

        assertEventCount(
                seed.runId(),
                seed.caseRunId(),
                ExecutionEventType.TOOL_REQUEST,
                1
        );
        assertEventCount(
                seed.runId(),
                seed.caseRunId(),
                ExecutionEventType.TOOL_RESPONSE,
                1
        );
        assertEventCount(
                seed.runId(),
                seed.caseRunId(),
                ExecutionEventType.SANDBOX_STATE_CHANGED,
                1
        );
    }

    @Test
    void sameToolCallIdWithDifferentRequestIsRejectedAsIdempotencyConflict() {
        Seed seed = seedRunWithSandbox();
        UUID traceId = UUID.randomUUID();

        SandboxExecutionContext context = new SandboxExecutionContext(
                seed.runId(),
                seed.caseRunId(),
                traceId,
                TestRunMode.BASELINE,
                "CASE-1001",
                "CUST-1001"
        );

        eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        null,
                        traceId,
                        ExecutionEventType.RUN_STARTED,
                        null,
                        null,
                        null,
                        null,
                        "RUN_STARTED",
                        objectMapper.createObjectNode()
                ),
                ACTOR
        );

        ObjectNode originalArguments = objectMapper.createObjectNode();
        originalArguments.put("caseId", "CASE-1001");
        originalArguments.put("decision", "APPROVED");

        ToolProposal originalProposal = new ToolProposal(
                LoanDecisionUpdateMockToolAdapter.TOOL_NAME,
                originalArguments
        );

        ExecutionEventDto.Event proposalEvent = eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        seed.caseRunId(),
                        traceId,
                        ExecutionEventType.TOOL_PROPOSED,
                        originalProposal.toolName(),
                        originalProposal.arguments(),
                        null,
                        null,
                        "STRUCTURED_TOOL_PROPOSAL",
                        objectMapper.createObjectNode()
                ),
                ACTOR
        );

        ToolInvocation originalInvocation = new ToolInvocation(
                originalProposal,
                proposalEvent.eventId(),
                proposalEvent.payloadDigest()
        );

        StateChangingToolExecutionService executor = executor();

        executor.execute(
                context,
                originalInvocation,
                adapter,
                ACTOR
        );

        ObjectNode conflictingArguments = objectMapper.createObjectNode();
        conflictingArguments.put("caseId", "CASE-1001");
        conflictingArguments.put("decision", "REJECTED");

        ToolInvocation conflictingInvocation = new ToolInvocation(
                new ToolProposal(
                        LoanDecisionUpdateMockToolAdapter.TOOL_NAME,
                        conflictingArguments
                ),
                originalInvocation.toolCallId(),
                "sha256:" + "d".repeat(64)
        );

        assertThatThrownBy(() ->
                executor.execute(
                        context,
                        conflictingInvocation,
                        adapter,
                        ACTOR
                )
        )
                .as(
                        "same toolCallId with a different request "
                                + "must never replay the original result"
                )
                .isInstanceOfSatisfying(
                        BusinessException.class,
                        exception -> assertThat(exception.errorCode())
                                .isEqualTo(ErrorCode.IDEMPOTENCY_CONFLICT)
                );

        Long rowVersion = jdbcTemplate.queryForObject("""
                select row_version
                  from sandbox_loan_decisions
                 where namespace_id = ?
                   and case_key = 'CASE-1001'
                """, Long.class, seed.runId());

        assertThat(rowVersion).isEqualTo(1L);

        String decision = jdbcTemplate.queryForObject("""
                select decision
                  from sandbox_loan_decisions
                 where namespace_id = ?
                   and case_key = 'CASE-1001'
                """, String.class, seed.runId());

        assertThat(decision).isEqualTo("APPROVED");

        Integer receiptCount = jdbcTemplate.queryForObject("""
                select count(*)
                  from sandbox_tool_idempotency_records
                 where test_case_run_id = ?
                   and tool_call_id = ?
                """,
                Integer.class,
                seed.caseRunId(),
                originalInvocation.toolCallId()
        );

        assertThat(receiptCount).isEqualTo(1);
    }

    @Test
    void concurrentSameToolCallIdMutatesExactlyOnceAndReplaysTheLoser()
            throws Exception {
        Seed seed = seedRunWithSandbox();
        UUID traceId = UUID.randomUUID();

        SandboxExecutionContext context = new SandboxExecutionContext(
                seed.runId(),
                seed.caseRunId(),
                traceId,
                TestRunMode.BASELINE,
                "CASE-1001",
                "CUST-1001"
        );

        eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        null,
                        traceId,
                        ExecutionEventType.RUN_STARTED,
                        null,
                        null,
                        null,
                        null,
                        "RUN_STARTED",
                        objectMapper.createObjectNode()
                ),
                ACTOR
        );

        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.put("caseId", "CASE-1001");
        arguments.put("decision", "APPROVED");

        ToolProposal proposal = new ToolProposal(
                LoanDecisionUpdateMockToolAdapter.TOOL_NAME,
                arguments
        );

        ExecutionEventDto.Event proposalEvent = eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        seed.caseRunId(),
                        traceId,
                        ExecutionEventType.TOOL_PROPOSED,
                        proposal.toolName(),
                        proposal.arguments(),
                        null,
                        null,
                        "STRUCTURED_TOOL_PROPOSAL",
                        objectMapper.createObjectNode()
                ),
                ACTOR
        );

        ToolInvocation invocation = new ToolInvocation(
                proposal,
                proposalEvent.eventId(),
                proposalEvent.payloadDigest()
        );

        BlockingToolAdapter blockingAdapter =
                new BlockingToolAdapter(adapter);

        ExecutorService pool = Executors.newFixedThreadPool(2);

        try {
            Future<ExecutionOutcome> first = pool.submit(() ->
                    captureExecution(
                            context,
                            invocation,
                            blockingAdapter
                    )
            );

            assertThat(
                    blockingAdapter.awaitEntered(
                            5,
                            TimeUnit.SECONDS
                    )
            )
                    .as("first invocation must reach the adapter")
                    .isTrue();

            Future<ExecutionOutcome> second = pool.submit(() ->
                    captureExecution(
                            context,
                            invocation,
                            blockingAdapter
                    )
            );

            assertThat(awaitBlockedDuplicateReservation())
                    .as(
                            "second invocation must overlap the first "
                                    + "at the idempotency reservation"
                    )
                    .isTrue();

            blockingAdapter.release();

            ExecutionOutcome firstOutcome =
                    first.get(10, TimeUnit.SECONDS);
            ExecutionOutcome secondOutcome =
                    second.get(10, TimeUnit.SECONDS);

            assertThat(firstOutcome.error())
                    .as("winning invocation must complete normally")
                    .isNull();

            assertThat(secondOutcome.error())
                    .as(
                            "concurrent duplicate must resolve through "
                                    + "idempotency replay, not leak a raw "
                                    + "database uniqueness failure"
                    )
                    .isNull();

            assertThat(firstOutcome.execution()).isNotNull();
            assertThat(secondOutcome.execution()).isNotNull();

            assertThat(firstOutcome.execution().replayed())
                    .isFalse();
            assertThat(secondOutcome.execution().replayed())
                    .isTrue();

            assertThat(
                    secondOutcome.execution()
                            .responseEvent()
                            .eventId()
            ).isEqualTo(
                    firstOutcome.execution()
                            .responseEvent()
                            .eventId()
            );

            Long rowVersion = jdbcTemplate.queryForObject("""
                    select row_version
                      from sandbox_loan_decisions
                     where namespace_id = ?
                       and case_key = 'CASE-1001'
                    """, Long.class, seed.runId());

            assertThat(rowVersion).isEqualTo(1L);

            Integer receiptCount = jdbcTemplate.queryForObject("""
                    select count(*)
                      from sandbox_tool_idempotency_records
                     where test_case_run_id = ?
                       and tool_call_id = ?
                    """,
                    Integer.class,
                    seed.caseRunId(),
                    invocation.toolCallId()
            );

            assertThat(receiptCount).isEqualTo(1);

            assertEventCount(
                    seed.runId(),
                    seed.caseRunId(),
                    ExecutionEventType.TOOL_REQUEST,
                    1
            );
            assertEventCount(
                    seed.runId(),
                    seed.caseRunId(),
                    ExecutionEventType.TOOL_RESPONSE,
                    1
            );
            assertEventCount(
                    seed.runId(),
                    seed.caseRunId(),
                    ExecutionEventType.SANDBOX_STATE_CHANGED,
                    1
            );
        } finally {
            blockingAdapter.release();
            pool.shutdownNow();
            pool.awaitTermination(5, TimeUnit.SECONDS);
        }
    }

    private ExecutionOutcome captureExecution(
            SandboxExecutionContext context,
            ToolInvocation invocation,
            ToolAdapter adapter
    ) {
        try {
            return new ExecutionOutcome(
                    transactionalExecutor.execute(
                            context,
                            invocation,
                            adapter,
                            ACTOR
                    ),
                    null
            );
        } catch (Throwable throwable) {
            return new ExecutionOutcome(null, throwable);
        }
    }

    private boolean awaitBlockedDuplicateReservation()
            throws InterruptedException {
        long deadline =
                System.nanoTime()
                        + TimeUnit.SECONDS.toNanos(5);

        while (System.nanoTime() < deadline) {
            Integer waiting = jdbcTemplate.queryForObject("""
                    select count(*)
                      from pg_stat_activity
                     where datname = current_database()
                       and pid <> pg_backend_pid()
                       and state = 'active'
                       and query ilike
                           '%insert into sandbox_tool_idempotency_records%'
                       and wait_event_type = 'Lock'
                    """, Integer.class);

            if (waiting != null && waiting > 0) {
                return true;
            }

            Thread.sleep(25);
        }

        return false;
    }

    @Test
    void stateChangingEvidenceCarriesCanonicalToolCallId() {
        Seed seed = seedRunWithSandbox();
        UUID traceId = UUID.randomUUID();

        SandboxExecutionContext context = new SandboxExecutionContext(
                seed.runId(),
                seed.caseRunId(),
                traceId,
                TestRunMode.BASELINE,
                "CASE-1001",
                "CUST-1001"
        );

        eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        null,
                        traceId,
                        ExecutionEventType.RUN_STARTED,
                        null,
                        null,
                        null,
                        null,
                        "RUN_STARTED",
                        objectMapper.createObjectNode()
                ),
                ACTOR
        );

        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.put("caseId", "CASE-1001");
        arguments.put("decision", "APPROVED");

        ToolProposal proposal = new ToolProposal(
                LoanDecisionUpdateMockToolAdapter.TOOL_NAME,
                arguments
        );

        ExecutionEventDto.Event proposalEvent = eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        seed.caseRunId(),
                        traceId,
                        ExecutionEventType.TOOL_PROPOSED,
                        proposal.toolName(),
                        proposal.arguments(),
                        null,
                        null,
                        "STRUCTURED_TOOL_PROPOSAL",
                        objectMapper.createObjectNode()
                ),
                ACTOR
        );

        ToolInvocation invocation = new ToolInvocation(
                proposal,
                proposalEvent.eventId(),
                proposalEvent.payloadDigest()
        );

        StateChangingToolExecutionService.Execution execution =
                transactionalExecutor.execute(
                        context,
                        invocation,
                        adapter,
                        ACTOR
                );

        assertToolCallIdMetadata(
                execution.requestEvent(),
                invocation.toolCallId()
        );
        assertToolCallIdMetadata(
                execution.responseEvent(),
                invocation.toolCallId()
        );
        assertToolCallIdMetadata(
                execution.stateEvent(),
                invocation.toolCallId()
        );

        assertThat(
                execution.stateEvent()
                        .metadata()
                        .path("sourceToolResponseEventId")
                        .asText()
        ).isEqualTo(
                execution.responseEvent()
                        .eventId()
                        .toString()
        );
    }

    private void assertToolCallIdMetadata(
            ExecutionEventDto.Event event,
            UUID expectedToolCallId
    ) {
        assertThat(event).isNotNull();
        assertThat(event.metadata()).isNotNull();

        assertThat(
                event.metadata()
                        .path("toolCallId")
                        .asText()
        )
                .as(
                        event.eventType()
                                + " must carry canonical metadata.toolCallId"
                )
                .isEqualTo(expectedToolCallId.toString());
    }

    @Test
    void dispatcherRoutesStateChangingInvocationThroughIdempotentExecutor() {
        Seed seed = seedRunWithSandbox();
        UUID traceId = UUID.randomUUID();

        SandboxExecutionContext context = new SandboxExecutionContext(
                seed.runId(),
                seed.caseRunId(),
                traceId,
                TestRunMode.BASELINE,
                "CASE-1001",
                "CUST-1001"
        );

        eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        null,
                        traceId,
                        ExecutionEventType.RUN_STARTED,
                        null,
                        null,
                        null,
                        null,
                        "RUN_STARTED",
                        objectMapper.createObjectNode()
                ),
                ACTOR
        );

        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.put("caseId", "CASE-1001");
        arguments.put("decision", "APPROVED");

        ToolProposal proposal = new ToolProposal(
                LoanDecisionUpdateMockToolAdapter.TOOL_NAME,
                arguments
        );

        ExecutionEventDto.Event proposalEvent = eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        seed.caseRunId(),
                        traceId,
                        ExecutionEventType.TOOL_PROPOSED,
                        proposal.toolName(),
                        proposal.arguments(),
                        null,
                        null,
                        "STRUCTURED_TOOL_PROPOSAL",
                        objectMapper.createObjectNode()
                ),
                ACTOR
        );

        ToolInvocation invocation = new ToolInvocation(
                proposal,
                proposalEvent.eventId(),
                proposalEvent.payloadDigest()
        );

        ToolDispatcher.DispatchResult first =
                dispatcher.dispatch(
                        context,
                        invocation,
                        ACTOR
                );

        ToolDispatcher.DispatchResult second =
                dispatcher.dispatch(
                        context,
                        invocation,
                        ACTOR
                );

        Long rowVersion = jdbcTemplate.queryForObject("""
                select row_version
                  from sandbox_loan_decisions
                 where namespace_id = ?
                   and case_key = 'CASE-1001'
                """, Long.class, seed.runId());

        assertThat(rowVersion)
                .as(
                        "dispatcher must not bypass state-changing "
                                + "Tool idempotency"
                )
                .isEqualTo(1L);

        Integer receiptCount = jdbcTemplate.queryForObject("""
                select count(*)
                  from sandbox_tool_idempotency_records
                 where test_case_run_id = ?
                   and tool_call_id = ?
                """,
                Integer.class,
                seed.caseRunId(),
                invocation.toolCallId()
        );

        assertThat(receiptCount)
                .as(
                        "dispatcher path must create the common "
                                + "state-changing idempotency receipt"
                )
                .isEqualTo(1);

        assertThat(first.responseEvent()).isNotNull();
        assertThat(second.responseEvent()).isNotNull();

        assertThat(second.responseEvent().eventId())
                .as(
                        "duplicate dispatcher invocation must replay "
                                + "the original TOOL_RESPONSE evidence"
                )
                .isEqualTo(first.responseEvent().eventId());

        assertEventCount(
                seed.runId(),
                seed.caseRunId(),
                ExecutionEventType.TOOL_REQUEST,
                1
        );
        assertEventCount(
                seed.runId(),
                seed.caseRunId(),
                ExecutionEventType.TOOL_RESPONSE,
                1
        );
        assertEventCount(
                seed.runId(),
                seed.caseRunId(),
                ExecutionEventType.SANDBOX_STATE_CHANGED,
                1
        );

        Integer correlatedEventCount = jdbcTemplate.queryForObject("""
                select count(*)
                  from execution_events
                 where run_id = ?
                   and test_case_run_id = ?
                   and event_type in (
                       'TOOL_REQUEST',
                       'TOOL_RESPONSE',
                       'SANDBOX_STATE_CHANGED'
                   )
                   and metadata_json ->> 'toolCallId' = ?
                """,
                Integer.class,
                seed.runId(),
                seed.caseRunId(),
                invocation.toolCallId().toString()
        );

        assertThat(correlatedEventCount)
                .as(
                        "all state-changing execution evidence must "
                                + "preserve canonical toolCallId"
                )
                .isEqualTo(3);
    }

    @Test
    void bareLoanDecisionUpdateFailsClosedBeforePolicyOrMutation() {
        Seed seed = seedRunWithSandbox();
        UUID traceId = UUID.randomUUID();

        SandboxExecutionContext context = new SandboxExecutionContext(
                seed.runId(), seed.caseRunId(), traceId,
                TestRunMode.BASELINE, "CASE-1001", "CUST-1001"
        );

        eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        null, traceId, ExecutionEventType.RUN_STARTED,
                        null, null, null, null, "RUN_STARTED",
                        objectMapper.createObjectNode()
                ),
                ACTOR
        );

        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.put("caseId", "CASE-1001");
        arguments.put("decision", "APPROVED");

        ToolProposal proposal = new ToolProposal(
                LoanDecisionUpdateMockToolAdapter.TOOL_NAME,
                arguments
        );

        assertThatThrownBy(() ->
                dispatcher.dispatch(context, proposal, ACTOR)
        ).isInstanceOfSatisfying(
                BusinessException.class,
                exception -> assertThat(exception.errorCode())
                        .isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE)
        );

        Long rowVersion = jdbcTemplate.queryForObject(
                """
                select row_version
                  from sandbox_loan_decisions
                 where namespace_id = ?
                   and case_key = 'CASE-1001'
                """,
                Long.class,
                seed.runId()
        );
        assertThat(rowVersion).isZero();

        Integer receiptCount = jdbcTemplate.queryForObject(
                """
                select count(*)
                  from sandbox_tool_idempotency_records
                 where test_case_run_id = ?
                """,
                Integer.class,
                seed.caseRunId()
        );
        assertThat(receiptCount).isZero();

        assertEventCount(seed.runId(), seed.caseRunId(),
                ExecutionEventType.POLICY_EVALUATED, 0);
        assertEventCount(seed.runId(), seed.caseRunId(),
                ExecutionEventType.TOOL_REQUEST, 0);
        assertEventCount(seed.runId(), seed.caseRunId(),
                ExecutionEventType.TOOL_RESPONSE, 0);
        assertEventCount(seed.runId(), seed.caseRunId(),
                ExecutionEventType.SANDBOX_STATE_CHANGED, 0);
    }

    @Test
    void bareExternalHttpFailsClosedWithoutCollectorSideEffect() {
        Seed seed = seedRunWithSandbox();
        UUID traceId = UUID.randomUUID();

        SandboxExecutionContext context = new SandboxExecutionContext(
                seed.runId(), seed.caseRunId(), traceId,
                TestRunMode.BASELINE, "CASE-1001", "CUST-1001"
        );

        eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        null, traceId, ExecutionEventType.RUN_STARTED,
                        null, null, null, null, "RUN_STARTED",
                        objectMapper.createObjectNode()
                ),
                ACTOR
        );

        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.put("url", ExternalHttpMockToolAdapter.MOCK_COLLECTOR_URL);
        arguments.putObject("body").put("message", "safe");

        ToolProposal proposal = new ToolProposal(
                ExternalHttpMockToolAdapter.TOOL_NAME,
                arguments
        );

        assertThatThrownBy(() ->
                dispatcher.dispatch(context, proposal, ACTOR)
        ).isInstanceOfSatisfying(
                BusinessException.class,
                exception -> assertThat(exception.errorCode())
                        .isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE)
        );

        Integer collectorRows = jdbcTemplate.queryForObject(
                """
                select count(*)
                  from sandbox_exfil_events
                 where namespace_id = ?
                   and test_case_run_id = ?
                """,
                Integer.class,
                seed.runId(),
                seed.caseRunId()
        );
        assertThat(collectorRows).isZero();

        assertEventCount(seed.runId(), seed.caseRunId(),
                ExecutionEventType.POLICY_EVALUATED, 0);
        assertEventCount(seed.runId(), seed.caseRunId(),
                ExecutionEventType.TOOL_REQUEST, 0);
    }

    @Test
    void bareReadOnlyCustomerDataReadKeepsCompatibility() {
        Seed seed = seedRunWithSandbox();
        UUID traceId = UUID.randomUUID();

        SandboxExecutionContext context = new SandboxExecutionContext(
                seed.runId(), seed.caseRunId(), traceId,
                TestRunMode.BASELINE, "CASE-1001", "CUST-1001"
        );

        eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        null, traceId, ExecutionEventType.RUN_STARTED,
                        null, null, null, null, "RUN_STARTED",
                        objectMapper.createObjectNode()
                ),
                ACTOR
        );

        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.putArray("customerIds").add("CUST-1001");
        arguments.putArray("fields").add("incomeBand");

        ToolDispatcher.DispatchResult dispatch = dispatcher.dispatch(
                context,
                new ToolProposal(CustomerDataReadToolAdapter.TOOL_NAME, arguments),
                ACTOR
        );

        assertThat(dispatch.policyDecision().allowed()).isTrue();
        assertThat(dispatch.toolInvoked()).isTrue();
        assertThat(dispatch.execution()).isNotNull();
        assertThat(dispatch.execution().stateChanged()).isFalse();

        Integer receiptCount = jdbcTemplate.queryForObject(
                """
                select count(*)
                  from sandbox_tool_idempotency_records
                 where test_case_run_id = ?
                """,
                Integer.class,
                seed.caseRunId()
        );
        assertThat(receiptCount).isZero();
    }

    @Test
    void stateChangingInvocationRejectsNonToolProposedToolCallIdBeforeMutation() {
        Seed seed = seedRunWithSandbox();
        UUID traceId = UUID.randomUUID();

        SandboxExecutionContext context = new SandboxExecutionContext(
                seed.runId(),
                seed.caseRunId(),
                traceId,
                TestRunMode.BASELINE,
                "CASE-1001",
                "CUST-1001"
        );

        ExecutionEventDto.Event runStartedEvent = eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        null,
                        traceId,
                        ExecutionEventType.RUN_STARTED,
                        null,
                        null,
                        null,
                        null,
                        "RUN_STARTED",
                        objectMapper.createObjectNode()
                ),
                ACTOR
        );

        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.put("caseId", "CASE-1001");
        arguments.put("decision", "APPROVED");

        ToolProposal proposal = new ToolProposal(
                LoanDecisionUpdateMockToolAdapter.TOOL_NAME,
                arguments
        );

        ToolInvocation forgedInvocation = new ToolInvocation(
                proposal,
                runStartedEvent.eventId(),
                runStartedEvent.payloadDigest()
        );

        assertThatThrownBy(() ->
                transactionalExecutor.execute(
                        context,
                        forgedInvocation,
                        adapter,
                        ACTOR
                )
        )
                .as(
                        "state-changing toolCallId must reference the canonical "
                                + "TOOL_PROPOSED event"
                )
                .isInstanceOfSatisfying(
                        BusinessException.class,
                        exception -> assertThat(exception.errorCode())
                                .isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE)
                );

        Long rowVersion = jdbcTemplate.queryForObject("""
                select row_version
                  from sandbox_loan_decisions
                 where namespace_id = ?
                   and case_key = 'CASE-1001'
                """, Long.class, seed.runId());

        assertThat(rowVersion)
                .as("forged provenance must be rejected before sandbox mutation")
                .isZero();

        Integer receiptCount = jdbcTemplate.queryForObject("""
                select count(*)
                  from sandbox_tool_idempotency_records
                 where test_case_run_id = ?
                """, Integer.class, seed.caseRunId());

        assertThat(receiptCount)
                .as("forged provenance must be rejected before idempotency reservation")
                .isZero();

        assertEventCount(
                seed.runId(),
                seed.caseRunId(),
                ExecutionEventType.TOOL_REQUEST,
                0
        );
    }

    @Test
    void stateChangingInvocationRejectsToolProposedFromAnotherRunAndCase() {
        Seed source = seedRunWithSandbox();
        Seed target = seedRunWithSandbox();
        UUID sourceTrace = UUID.randomUUID();
        UUID targetTrace = UUID.randomUUID();

        appendRunStarted(source, sourceTrace);
        appendRunStarted(target, targetTrace);

        ToolProposal proposal = loanDecisionProposal("APPROVED");
        ExecutionEventDto.Event proposalEvent = appendToolProposal(
                source,
                source.caseRunId(),
                sourceTrace,
                proposal,
                proposal.toolName()
        );

        ToolInvocation forged = new ToolInvocation(
                proposal,
                proposalEvent.eventId(),
                proposalEvent.payloadDigest()
        );

        SandboxExecutionContext targetContext = new SandboxExecutionContext(
                target.runId(),
                target.caseRunId(),
                targetTrace,
                TestRunMode.BASELINE,
                "CASE-1001",
                "CUST-1001"
        );

        assertRejectedBeforeMutation(target, targetContext, forged);
    }

    @Test
    void stateChangingInvocationRejectsToolProposedFromAnotherCaseRun() {
        Seed seed = seedRunWithSandbox(2);
        UUID traceId = UUID.randomUUID();
        appendRunStarted(seed, traceId);

        ToolProposal proposal = loanDecisionProposal("APPROVED");
        ExecutionEventDto.Event proposalEvent = appendToolProposal(
                seed,
                seed.caseRunId(),
                traceId,
                proposal,
                proposal.toolName()
        );

        UUID testCaseId = jdbcTemplate.queryForObject("""
                select test_case_id
                  from test_case_runs
                 where id = ?
                """, UUID.class, seed.caseRunId());

        UUID otherCaseRunId = UUID.randomUUID();
        jdbcTemplate.update("""
                insert into test_case_runs
                    (id, test_run_id, test_case_id, trial_index,
                     status, variant_hash, started_at)
                values (?, ?, ?, 1, 'EXECUTING', ?, now())
                """,
                otherCaseRunId,
                seed.runId(),
                testCaseId,
                HASH_A
        );

        ToolInvocation forged = new ToolInvocation(
                proposal,
                proposalEvent.eventId(),
                proposalEvent.payloadDigest()
        );

        SandboxExecutionContext otherCaseContext = new SandboxExecutionContext(
                seed.runId(),
                otherCaseRunId,
                traceId,
                TestRunMode.BASELINE,
                "CASE-1001",
                "CUST-1001"
        );

        assertRejectedBeforeMutation(
                new Seed(seed.runId(), otherCaseRunId),
                otherCaseContext,
                forged
        );
    }

    @Test
    void stateChangingInvocationRejectsToolProposedWithDifferentTrace() {
        Seed seed = seedRunWithSandbox();
        UUID proposalTrace = UUID.randomUUID();
        UUID executionTrace = UUID.randomUUID();
        appendRunStarted(seed, proposalTrace);

        ToolProposal proposal = loanDecisionProposal("APPROVED");
        ExecutionEventDto.Event proposalEvent = appendToolProposal(
                seed,
                seed.caseRunId(),
                proposalTrace,
                proposal,
                proposal.toolName()
        );

        ToolInvocation forged = new ToolInvocation(
                proposal,
                proposalEvent.eventId(),
                proposalEvent.payloadDigest()
        );

        SandboxExecutionContext context = new SandboxExecutionContext(
                seed.runId(),
                seed.caseRunId(),
                executionTrace,
                TestRunMode.BASELINE,
                "CASE-1001",
                "CUST-1001"
        );

        assertRejectedBeforeMutation(seed, context, forged);
    }

    @Test
    void stateChangingInvocationRejectsToolNameDifferentFromPersistedProposal() {
        Seed seed = seedRunWithSandbox();
        UUID traceId = UUID.randomUUID();
        appendRunStarted(seed, traceId);

        ToolProposal proposal = loanDecisionProposal("APPROVED");
        ExecutionEventDto.Event proposalEvent = appendToolProposal(
                seed,
                seed.caseRunId(),
                traceId,
                proposal,
                ExternalHttpMockToolAdapter.TOOL_NAME
        );

        ToolInvocation forged = new ToolInvocation(
                proposal,
                proposalEvent.eventId(),
                proposalEvent.payloadDigest()
        );

        SandboxExecutionContext context = new SandboxExecutionContext(
                seed.runId(),
                seed.caseRunId(),
                traceId,
                TestRunMode.BASELINE,
                "CASE-1001",
                "CUST-1001"
        );

        assertRejectedBeforeMutation(seed, context, forged);
    }

    @Test
    void stateChangingInvocationRejectsDigestDifferentFromPersistedProposal() {
        Seed seed = seedRunWithSandbox();
        UUID traceId = UUID.randomUUID();
        appendRunStarted(seed, traceId);

        ToolProposal proposal = loanDecisionProposal("APPROVED");
        ExecutionEventDto.Event proposalEvent = appendToolProposal(
                seed,
                seed.caseRunId(),
                traceId,
                proposal,
                proposal.toolName()
        );

        ToolInvocation forged = new ToolInvocation(
                proposal,
                proposalEvent.eventId(),
                "sha256:" + "d".repeat(64)
        );

        SandboxExecutionContext context = new SandboxExecutionContext(
                seed.runId(),
                seed.caseRunId(),
                traceId,
                TestRunMode.BASELINE,
                "CASE-1001",
                "CUST-1001"
        );

        assertRejectedBeforeMutation(seed, context, forged);
    }

    @Test
    void stateChangingInvocationRejectsArgumentsNotBoundToPersistedDigest() {
        Seed seed = seedRunWithSandbox();
        UUID traceId = UUID.randomUUID();
        appendRunStarted(seed, traceId);

        ToolProposal persistedProposal = loanDecisionProposal("APPROVED");
        ExecutionEventDto.Event proposalEvent = appendToolProposal(
                seed,
                seed.caseRunId(),
                traceId,
                persistedProposal,
                persistedProposal.toolName()
        );

        ToolProposal forgedProposal = loanDecisionProposal("REJECTED");
        ToolInvocation forged = new ToolInvocation(
                forgedProposal,
                proposalEvent.eventId(),
                proposalEvent.payloadDigest()
        );

        SandboxExecutionContext context = new SandboxExecutionContext(
                seed.runId(),
                seed.caseRunId(),
                traceId,
                TestRunMode.BASELINE,
                "CASE-1001",
                "CUST-1001"
        );

        assertRejectedBeforeMutation(seed, context, forged);
    }

    private void appendRunStarted(Seed seed, UUID traceId) {
        eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        null,
                        traceId,
                        ExecutionEventType.RUN_STARTED,
                        null,
                        null,
                        null,
                        null,
                        "RUN_STARTED",
                        objectMapper.createObjectNode()
                ),
                ACTOR
        );
    }

    private ExecutionEventDto.Event appendToolProposal(
            Seed seed,
            UUID caseRunId,
            UUID traceId,
            ToolProposal proposal,
            String persistedToolName
    ) {
        return eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        caseRunId,
                        traceId,
                        ExecutionEventType.TOOL_PROPOSED,
                        persistedToolName,
                        proposal.arguments(),
                        null,
                        null,
                        "STRUCTURED_TOOL_PROPOSAL",
                        objectMapper.createObjectNode()
                ),
                ACTOR
        );
    }

    private ToolProposal loanDecisionProposal(String decision) {
        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.put("caseId", "CASE-1001");
        arguments.put("decision", decision);
        return new ToolProposal(
                LoanDecisionUpdateMockToolAdapter.TOOL_NAME,
                arguments
        );
    }

    private void assertRejectedBeforeMutation(
            Seed target,
            SandboxExecutionContext context,
            ToolInvocation invocation
    ) {
        assertThatThrownBy(() ->
                transactionalExecutor.execute(
                        context,
                        invocation,
                        adapter,
                        ACTOR
                )
        )
                .isInstanceOfSatisfying(
                        BusinessException.class,
                        exception -> assertThat(exception.errorCode())
                                .isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE)
                );

        Long rowVersion = jdbcTemplate.queryForObject("""
                select row_version
                  from sandbox_loan_decisions
                 where namespace_id = ?
                   and case_key = 'CASE-1001'
                """, Long.class, target.runId());

        assertThat(rowVersion)
                .as("invalid canonical provenance must be rejected before mutation")
                .isZero();

        Integer receiptCount = jdbcTemplate.queryForObject("""
                select count(*)
                  from sandbox_tool_idempotency_records
                 where test_case_run_id = ?
                """, Integer.class, context.caseRunId());

        assertThat(receiptCount)
                .as("invalid provenance must be rejected before receipt reservation")
                .isZero();

        assertEventCount(
                target.runId(),
                context.caseRunId(),
                ExecutionEventType.TOOL_REQUEST,
                0
        );
    }

    @Test
    void idempotencyReceiptStoresRedactedToolResponse() throws Exception {
        Seed seed = seedRunWithSandbox();
        UUID traceId = UUID.randomUUID();

        SandboxExecutionContext context = new SandboxExecutionContext(
                seed.runId(),
                seed.caseRunId(),
                traceId,
                TestRunMode.BASELINE,
                "CASE-1001",
                "CUST-1001"
        );

        eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        null,
                        traceId,
                        ExecutionEventType.RUN_STARTED,
                        null,
                        null,
                        null,
                        null,
                        "RUN_STARTED",
                        objectMapper.createObjectNode()
                ),
                ACTOR
        );

        ObjectNode arguments = objectMapper.createObjectNode();
        arguments.put("operation", "emit-sensitive-output");

        ToolProposal proposal = new ToolProposal(
                "SENSITIVE_OUTPUT_TEST",
                arguments
        );

        ExecutionEventDto.Event proposalEvent = eventService.append(
                seed.runId(),
                new ExecutionEventDto.AppendRequest(
                        seed.caseRunId(),
                        traceId,
                        ExecutionEventType.TOOL_PROPOSED,
                        proposal.toolName(),
                        proposal.arguments(),
                        null,
                        null,
                        "STRUCTURED_TOOL_PROPOSAL",
                        objectMapper.createObjectNode()
                ),
                ACTOR
        );

        ToolInvocation invocation = new ToolInvocation(
                proposal,
                proposalEvent.eventId(),
                proposalEvent.payloadDigest()
        );

        ToolAdapter sensitiveOutputAdapter = new ToolAdapter() {
            @Override
            public String toolName() {
                return proposal.toolName();
            }

            @Override
            public ToolEffect effect() {
                return ToolEffect.STATE_CHANGING;
            }

            @Override
            public void validateArguments(
                    tools.jackson.databind.JsonNode value
            ) {
            }

            @Override
            public ToolExecutionResult execute(
                    SandboxExecutionContext executionContext,
                    tools.jackson.databind.JsonNode value
            ) {
                ObjectNode output = objectMapper.createObjectNode();
                output.put("email", "alice@example.com");
                output.put("status", "OK");
                return new ToolExecutionResult(output, false);
            }
        };

        StateChangingToolExecutionService.Execution execution =
                transactionalExecutor.execute(
                        context,
                        invocation,
                        sensitiveOutputAdapter,
                        ACTOR
                );

        assertThat(execution.responseEvent().output().path("email").asString())
                .isEqualTo("[REDACTED:SENSITIVE_PII]");

        String receiptJson = jdbcTemplate.queryForObject("""
                select response_json::text
                  from sandbox_tool_idempotency_records
                 where test_case_run_id = ?
                   and tool_call_id = ?
                """,
                String.class,
                seed.caseRunId(),
                invocation.toolCallId()
        );

        tools.jackson.databind.JsonNode receiptResponse =
                objectMapper.readTree(receiptJson);

        assertThat(receiptResponse)
                .as("receipt response_json must match the centrally redacted TOOL_RESPONSE payload")
                .isEqualTo(execution.responseEvent().output());
        assertThat(receiptResponse.path("email").asString())
                .isEqualTo("[REDACTED:SENSITIVE_PII]");
        assertThat(receiptJson)
                .doesNotContain("alice@example.com");
    }

    @Test
    void stateChangingInvocationRejectsSensitiveArgumentsNotBoundToOriginalDigest() {
        Seed seed = seedRunWithSandbox();
        UUID traceId = UUID.randomUUID();
        appendRunStarted(seed, traceId);

        ObjectNode persistedArguments = objectMapper.createObjectNode();
        persistedArguments.put("email", "alice@example.com");
        persistedArguments.put("operation", "review");
        ToolProposal persistedProposal = new ToolProposal(
                "SENSITIVE_PROVENANCE_TEST",
                persistedArguments
        );

        ExecutionEventDto.Event proposalEvent = appendToolProposal(
                seed,
                seed.caseRunId(),
                traceId,
                persistedProposal,
                persistedProposal.toolName()
        );

        ObjectNode forgedArguments = objectMapper.createObjectNode();
        forgedArguments.put("email", "mallory@example.com");
        forgedArguments.put("operation", "review");
        ToolProposal forgedProposal = new ToolProposal(
                persistedProposal.toolName(),
                forgedArguments
        );

        ToolInvocation forged = new ToolInvocation(
                forgedProposal,
                proposalEvent.eventId(),
                proposalEvent.payloadDigest()
        );

        SandboxExecutionContext context = new SandboxExecutionContext(
                seed.runId(),
                seed.caseRunId(),
                traceId,
                TestRunMode.BASELINE,
                "CASE-1001",
                "CUST-1001"
        );

        ToolAdapter sensitiveAdapter = new ToolAdapter() {
            @Override
            public String toolName() {
                return persistedProposal.toolName();
            }

            @Override
            public ToolEffect effect() {
                return ToolEffect.STATE_CHANGING;
            }

            @Override
            public void validateArguments(
                    tools.jackson.databind.JsonNode value
            ) {
            }

            @Override
            public ToolExecutionResult execute(
                    SandboxExecutionContext executionContext,
                    tools.jackson.databind.JsonNode value
            ) {
                return new ToolExecutionResult(
                        objectMapper.createObjectNode().put("status", "OK"),
                        false
                );
            }
        };

        assertThatThrownBy(() ->
                transactionalExecutor.execute(
                        context,
                        forged,
                        sensitiveAdapter,
                        ACTOR
                )
        )
                .isInstanceOfSatisfying(
                        BusinessException.class,
                        exception -> assertThat(exception.errorCode())
                                .isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE)
                );

        Integer receiptCount = jdbcTemplate.queryForObject("""
                select count(*)
                  from sandbox_tool_idempotency_records
                 where test_case_run_id = ?
                   and tool_call_id = ?
                """,
                Integer.class,
                seed.caseRunId(),
                proposalEvent.eventId()
        );
        assertThat(receiptCount)
                .as("forged sensitive arguments must fail before receipt reservation")
                .isZero();

        assertEventCount(
                seed.runId(),
                seed.caseRunId(),
                ExecutionEventType.TOOL_REQUEST,
                0
        );
    }

    private StateChangingToolExecutionService executor() {
        try {
            Constructor<?> noArg = Arrays.stream(
                            StateChangingToolExecutionService.class
                                    .getDeclaredConstructors()
                    )
                    .filter(constructor ->
                            constructor.getParameterCount() == 0)
                    .findFirst()
                    .orElse(null);

            if (noArg != null) {
                noArg.setAccessible(true);
                return (StateChangingToolExecutionService)
                        noArg.newInstance();
            }

            Constructor<StateChangingToolExecutionService> constructor =
                    StateChangingToolExecutionService.class
                            .getDeclaredConstructor(
                                    JdbcTemplate.class,
                                    ExecutionEventService.class,
                                    ObjectMapper.class
                            );
            constructor.setAccessible(true);
            return constructor.newInstance(
                    jdbcTemplate,
                    eventService,
                    objectMapper
            );
        } catch (ReflectiveOperationException exception) {
            throw new AssertionError(
                    "StateChangingToolExecutionService must expose either "
                            + "the Task 8-2A no-arg skeleton or the approved "
                            + "(JdbcTemplate, ExecutionEventService, ObjectMapper) "
                            + "implementation constructor",
                    exception
            );
        }
    }

    private void assertEventCount(
            UUID runId,
            UUID caseRunId,
            ExecutionEventType eventType,
            int expected
    ) {
        Integer count = jdbcTemplate.queryForObject("""
                select count(*)
                  from execution_events
                 where run_id = ?
                   and test_case_run_id = ?
                   and event_type = ?
                   and tool_name = ?
                """,
                Integer.class,
                runId,
                caseRunId,
                eventType.name(),
                LoanDecisionUpdateMockToolAdapter.TOOL_NAME
        );

        assertThat(count).isEqualTo(expected);
    }

    private Seed seedRunWithSandbox() {
        return seedRunWithSandbox(1);
    }

    private Seed seedRunWithSandbox(int plannedCases) {
        UUID agentId = UUID.randomUUID();
        UUID releaseId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        UUID testCaseId = UUID.randomUUID();
        UUID caseRunId = UUID.randomUUID();
        String suffix = agentId.toString().substring(0, 8);

        jdbcTemplate.update("""
                insert into agents
                    (id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'FA05 Agent',
                        'FA-05 idempotency integration test', 'ACTIVE')
                """,
                agentId,
                WORKSPACE_ID,
                "fa05-idempotency-" + suffix
        );

        jdbcTemplate.update("""
                insert into agent_releases
                    (id, agent_id, version, business_purpose,
                     manifest_schema_version, manifest_json,
                     agent_artifact_fingerprint, release_fingerprint,
                     lifecycle_state, effective_status)
                values (?, ?, '1.0.0',
                        'LOAN_DOCUMENT_COMPLETENESS_REVIEW', '1.0',
                        '{}'::jsonb, ?, ?,
                        'ANALYZED', 'ANALYZED')
                """,
                releaseId,
                agentId,
                HASH_A,
                HASH_A
        );

        jdbcTemplate.update("""
                insert into test_suites
                    (id, workspace_id, suite_key, version,
                     fixture_version, generation_config_json,
                     suite_hash, status)
                values (?, ?, ?, '1.0.0', 'golden-v1',
                        '{}'::jsonb, ?, 'BUILDING')
                """,
                suiteId,
                WORKSPACE_ID,
                "fa05-idempotency-suite-" + suffix,
                HASH_B
        );

        jdbcTemplate.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type,
                     partition_name, category, severity,
                     delivery_channel, target_tool, attack_goal,
                     payload_hash, preconditions_json,
                     expected_invariant, oracle_type,
                     generation_source, expected_result_json,
                     trial_policy_json)
                values (?, ?, 'FA05-IDEMPOTENCY-001',
                        'ATTACK', 'SEED', 'FA-05', 'CRITICAL',
                        'DIRECT', 'LOAN_DECISION_UPDATE',
                        'Mutate loan decision',
                        ?,
                        '{"caseId":"CASE-1001","currentApplicantId":"CUST-1001"}'::jsonb,
                        'INV-05', 'HIGH_IMPACT_MUTATION',
                        'CURATED', '{}'::jsonb, '{}'::jsonb)
                """,
                testCaseId,
                suiteId,
                HASH_A
        );

        jdbcTemplate.update(
                "update test_suites set status = 'READY' where id = ?",
                suiteId
        );

        UUID runId = runPersistenceService.register(
                new TestRunPersistenceDto.RegisterRequest(
                        releaseId,
                        suiteId,
                        null,
                        TestRunMode.BASELINE,
                        UUID.randomUUID(),
                        objectMapper.createObjectNode()
                                .put("schemaVersion", "1.0"),
                        fixtureService.fixtureDigest(),
                        HASH_B,
                        45L,
                        plannedCases
                ),
                ACTOR
        ).runId();

        fixtureService.createOrReset(runId);

        jdbcTemplate.update("""
                insert into test_case_runs
                    (id, test_run_id, test_case_id, trial_index,
                     status, variant_hash, started_at)
                values (?, ?, ?, 0, 'EXECUTING', ?, now())
                """,
                caseRunId,
                runId,
                testCaseId,
                HASH_A
        );

        return new Seed(runId, caseRunId);
    }

    private record ExecutionOutcome(
            StateChangingToolExecutionService.Execution execution,
            Throwable error
    ) {
    }

    private static final class BlockingToolAdapter
            implements ToolAdapter {

        private final ToolAdapter delegate;
        private final CountDownLatch entered =
                new CountDownLatch(1);
        private final CountDownLatch release =
                new CountDownLatch(1);

        private BlockingToolAdapter(ToolAdapter delegate) {
            this.delegate = delegate;
        }

        @Override
        public String toolName() {
            return delegate.toolName();
        }

        @Override
        public ToolEffect effect() {
            return ToolEffect.STATE_CHANGING;
        }

        @Override
        public void validateArguments(
                tools.jackson.databind.JsonNode arguments
        ) {
            delegate.validateArguments(arguments);
        }

        @Override
        public ToolExecutionResult execute(
                SandboxExecutionContext context,
                tools.jackson.databind.JsonNode arguments
        ) {
            entered.countDown();

            try {
                if (!release.await(10, TimeUnit.SECONDS)) {
                    throw new AssertionError(
                            "Timed out waiting to release blocking adapter"
                    );
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new AssertionError(
                        "Blocking adapter was interrupted",
                        exception
                );
            }

            return delegate.execute(context, arguments);
        }

        private boolean awaitEntered(
                long timeout,
                TimeUnit unit
        ) throws InterruptedException {
            return entered.await(timeout, unit);
        }

        private void release() {
            release.countDown();
        }
    }

    private record Seed(
            UUID runId,
            UUID caseRunId
    ) {
    }
}
