package com.finsecseal.sandbox.tool;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.runtime.ToolInvocation;
import com.finsecseal.sandbox.SandboxExecutionContext;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Service
public class StateChangingToolExecutionService {

    private final JdbcTemplate jdbcTemplate;
    private final ExecutionEventService eventService;
    private final ObjectMapper objectMapper;

    public StateChangingToolExecutionService(
            JdbcTemplate jdbcTemplate,
            ExecutionEventService eventService,
            ObjectMapper objectMapper
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.eventService = eventService;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public Execution execute(
            SandboxExecutionContext context,
            ToolInvocation invocation,
            ToolAdapter adapter,
            String actorId
    ) {
        requireExecution(context, invocation, adapter, actorId);

        Receipt existing = findReceipt(
                context.caseRunId(),
                invocation.toolCallId()
        );

        if (existing != null) {
            requireSameIdentity(existing, invocation);

            if ("COMPLETED".equals(existing.state())) {
                return replay(existing);
            }

            throw idempotencyInProgress(invocation);
        }

        boolean reservationWon =
                reserve(context, invocation);

        if (!reservationWon) {
            Receipt concurrentWinner = findReceipt(
                    context.caseRunId(),
                    invocation.toolCallId()
            );

            if (concurrentWinner == null) {
                throw new BusinessException(
                        ErrorCode.EVIDENCE_INCOMPLETE,
                        "Concurrent Tool idempotency winner receipt is missing"
                );
            }

            requireSameIdentity(
                    concurrentWinner,
                    invocation
            );

            if ("COMPLETED".equals(
                    concurrentWinner.state()
            )) {
                return replay(concurrentWinner);
            }

            throw idempotencyInProgress(invocation);
        }

        ExecutionEventDto.Event requestEvent = eventService.append(
                context.runId(),
                new ExecutionEventDto.AppendRequest(
                        context.caseRunId(),
                        context.traceId(),
                        ExecutionEventType.TOOL_REQUEST,
                        invocation.proposal().toolName(),
                        invocation.proposal().arguments(),
                        null,
                        null,
                        null,
                        objectMapper.createObjectNode()
                ),
                actorId
        );

        ToolAdapter.ToolExecutionResult result =
                adapter.execute(
                        context,
                        invocation.proposal().arguments()
                );

        ObjectNode responseMetadata = objectMapper.createObjectNode();
        responseMetadata.put("deliveredToAgent", false);
        responseMetadata.put("deliveryState", "PENDING");
        responseMetadata.put("stateChanged", result.stateChanged());

        ExecutionEventDto.Event responseEvent = eventService.append(
                context.runId(),
                new ExecutionEventDto.AppendRequest(
                        context.caseRunId(),
                        context.traceId(),
                        ExecutionEventType.TOOL_RESPONSE,
                        invocation.proposal().toolName(),
                        null,
                        result.output(),
                        null,
                        "TOOL_EXECUTED",
                        responseMetadata
                ),
                actorId
        );

        ExecutionEventDto.Event stateEvent = null;
        if (result.stateChanged()) {
            ObjectNode stateMetadata = objectMapper.createObjectNode();
            stateMetadata.put("stateChanged", true);
            stateMetadata.put(
                    "sourceToolResponseEventId",
                    responseEvent.eventId().toString()
            );

            stateEvent = eventService.append(
                    context.runId(),
                    new ExecutionEventDto.AppendRequest(
                            context.caseRunId(),
                            context.traceId(),
                            ExecutionEventType.SANDBOX_STATE_CHANGED,
                            invocation.proposal().toolName(),
                            null,
                            null,
                            null,
                            "SANDBOX_STATE_CHANGED",
                            stateMetadata
                    ),
                    actorId
            );
        }

        complete(
                context.caseRunId(),
                invocation.toolCallId(),
                requestEvent,
                responseEvent,
                stateEvent,
                result
        );

        return new Execution(
                requestEvent,
                responseEvent,
                stateEvent,
                result,
                false
        );
    }

    private void requireExecution(
            SandboxExecutionContext context,
            ToolInvocation invocation,
            ToolAdapter adapter,
            String actorId
    ) {
        if (context == null
                || invocation == null
                || adapter == null
                || actorId == null
                || actorId.isBlank()) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "State-changing Tool execution requires complete invocation context"
            );
        }

        if (adapter.effect() != ToolEffect.STATE_CHANGING) {
            throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    "State-changing Tool executor requires a STATE_CHANGING adapter"
            );
        }
    }

    private Receipt findReceipt(
            UUID caseRunId,
            UUID toolCallId
    ) {
        List<Receipt> receipts = jdbcTemplate.query(
                """
                select state,
                       tool_name,
                       request_digest,
                       state_changed,
                       request_event_id,
                       response_event_id,
                       state_event_id
                  from sandbox_tool_idempotency_records
                 where test_case_run_id = ?
                   and tool_call_id = ?
                """,
                (resultSet, rowNumber) -> new Receipt(
                        resultSet.getString("state"),
                        resultSet.getString("tool_name"),
                        resultSet.getString("request_digest"),
                        resultSet.getObject("state_changed", Boolean.class),
                        resultSet.getObject("request_event_id", UUID.class),
                        resultSet.getObject("response_event_id", UUID.class),
                        resultSet.getObject("state_event_id", UUID.class)
                ),
                caseRunId,
                toolCallId
        );

        return receipts.isEmpty() ? null : receipts.getFirst();
    }

    private void requireSameIdentity(
            Receipt existing,
            ToolInvocation invocation
    ) {
        if (!java.util.Objects.equals(
                existing.toolName(),
                invocation.proposal().toolName()
        ) || !java.util.Objects.equals(
                existing.requestDigest(),
                invocation.requestDigest()
        )) {
            throw new BusinessException(
                    ErrorCode.IDEMPOTENCY_CONFLICT,
                    "toolCallId is already bound to a different Tool request"
            );
        }
    }

    private boolean reserve(
            SandboxExecutionContext context,
            ToolInvocation invocation
    ) {
        int inserted = jdbcTemplate.update(
                """
                insert into sandbox_tool_idempotency_records
                    (id, test_case_run_id, tool_call_id,
                     tool_name, request_digest, state)
                values (?, ?, ?, ?, ?, 'PROCESSING')
                on conflict (test_case_run_id, tool_call_id)
                do nothing
                """,
                UUID.randomUUID(),
                context.caseRunId(),
                invocation.toolCallId(),
                invocation.proposal().toolName(),
                invocation.requestDigest()
        );

        return inserted == 1;
    }

    private BusinessException idempotencyInProgress(
            ToolInvocation invocation
    ) {
        return new BusinessException(
                ErrorCode.IDEMPOTENCY_IN_PROGRESS,
                "Tool invocation is already processing: "
                        + invocation.toolCallId()
        );
    }

    private void complete(
            UUID caseRunId,
            UUID toolCallId,
            ExecutionEventDto.Event requestEvent,
            ExecutionEventDto.Event responseEvent,
            ExecutionEventDto.Event stateEvent,
            ToolAdapter.ToolExecutionResult result
    ) {
        int updated = jdbcTemplate.update(
                """
                update sandbox_tool_idempotency_records
                   set state = 'COMPLETED',
                       response_json = ?::jsonb,
                       state_changed = ?,
                       request_event_id = ?,
                       response_event_id = ?,
                       state_event_id = ?,
                       completed_at = ?
                 where test_case_run_id = ?
                   and tool_call_id = ?
                   and state = 'PROCESSING'
                """,
                json(result.output()),
                result.stateChanged(),
                requestEvent.eventId(),
                responseEvent.eventId(),
                stateEvent == null ? null : stateEvent.eventId(),
                Timestamp.from(Instant.now()),
                caseRunId,
                toolCallId
        );

        if (updated != 1) {
            throw new BusinessException(
                    ErrorCode.RESOURCE_CONFLICT,
                    "State-changing Tool idempotency completion was rejected"
            );
        }
    }

    private Execution replay(Receipt receipt) {
        ExecutionEventDto.Event requestEvent =
                eventService.findById(receipt.requestEventId());
        ExecutionEventDto.Event responseEvent =
                eventService.findById(receipt.responseEventId());
        ExecutionEventDto.Event stateEvent =
                receipt.stateEventId() == null
                        ? null
                        : eventService.findById(receipt.stateEventId());

        ToolAdapter.ToolExecutionResult result =
                new ToolAdapter.ToolExecutionResult(
                        responseEvent.output(),
                        Boolean.TRUE.equals(receipt.stateChanged())
                );

        return new Execution(
                requestEvent,
                responseEvent,
                stateEvent,
                result,
                true
        );
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception exception) {
            throw new BusinessException(
                    ErrorCode.EVIDENCE_INCOMPLETE,
                    "State-changing Tool response serialization failed"
            );
        }
    }

    public record Execution(
            ExecutionEventDto.Event requestEvent,
            ExecutionEventDto.Event responseEvent,
            ExecutionEventDto.Event stateEvent,
            ToolAdapter.ToolExecutionResult result,
            boolean replayed
    ) {
    }

    private record Receipt(
            String state,
            String toolName,
            String requestDigest,
            Boolean stateChanged,
            UUID requestEventId,
            UUID responseEventId,
            UUID stateEventId
    ) {
    }
}
