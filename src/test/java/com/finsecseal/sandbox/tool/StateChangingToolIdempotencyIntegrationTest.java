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
                        1
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
