package com.finsecseal.evidence;

import com.finsecseal.audit.AuditService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.persistence.UuidV7;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Service
@Transactional(readOnly = true)
public class ExecutionEventService {

    private static final String SCHEMA_VERSION = "1.0";
    private static final Set<String> TERMINAL_RUN_STATUSES = Set.of("COMPLETED", "FAILED", "CANCELLED");
    private static final Set<ExecutionEventType> TERMINAL_EVENT_TYPES = Set.of(
            ExecutionEventType.RUN_COMPLETED,
            ExecutionEventType.RUN_FAILED
    );

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final RedactionService redactionService;
    private final CanonicalJsonService canonicalJsonService;
    private final DigestService digestService;
    private final AuditService auditService;

    public ExecutionEventService(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            RedactionService redactionService,
            CanonicalJsonService canonicalJsonService,
            DigestService digestService,
            AuditService auditService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.redactionService = redactionService;
        this.canonicalJsonService = canonicalJsonService;
        this.digestService = digestService;
        this.auditService = auditService;
    }

    @Transactional
    public ExecutionEventDto.Event append(UUID runId, ExecutionEventDto.AppendRequest request, String actorId) {
        requireAppendRequest(request);
        ExecutionEventDto.RunHead head = lockRunAndReadHead(runId);
        if (TERMINAL_RUN_STATUSES.contains(head.status())) {
            throw new BusinessException(ErrorCode.INVALID_STATE_TRANSITION, "Terminal TestRun cannot accept events");
        }
        if (head.eventType() != null && TERMINAL_EVENT_TYPES.contains(head.eventType())) {
            throw new BusinessException(
                    ErrorCode.INVALID_STATE_TRANSITION,
                    "A terminal execution event already seals this TestRun event stream"
            );
        }
        if (head.sequence() == 0 && request.eventType() != ExecutionEventType.RUN_STARTED) {
            throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, "The first event must be RUN_STARTED");
        }
        if (head.sequence() > 0 && request.eventType() == ExecutionEventType.RUN_STARTED) {
            throw new BusinessException(ErrorCode.INVALID_STATE_TRANSITION, "RUN_STARTED can only be the first event");
        }

        ObjectNode rawEnvelope = objectMapper.createObjectNode();
        rawEnvelope.set("input", nullToJson(request.input()));
        rawEnvelope.set("output", nullToJson(request.output()));
        rawEnvelope.set("policyDecision", nullToJson(request.policyDecision()));
        rawEnvelope.set("metadata", request.metadata() == null
                ? objectMapper.createObjectNode()
                : request.metadata());
        RedactionService.Result payload = redactionService.redact(rawEnvelope);
        JsonNode redacted = payload.redacted();

        UUID eventId = UuidV7.generate();
        long sequence = head.sequence() + 1;
        Instant occurredAt = Instant.now().truncatedTo(ChronoUnit.MICROS);
        JsonNode input = redacted.path("input");
        JsonNode output = redacted.path("output");
        JsonNode policyDecision = redacted.path("policyDecision");
        JsonNode metadata = redacted.path("metadata");
        ObjectNode canonicalEvent = canonicalEvent(
                eventId,
                request.traceId(),
                runId,
                request.testCaseRunId(),
                sequence,
                occurredAt,
                request.eventType(),
                request.toolName(),
                input,
                output,
                payload.originalDigest(),
                policyDecision,
                request.reasonCode(),
                metadata
        );
        String eventHash = chainHash(canonicalEvent, head.hash());

        try {
            jdbcTemplate.update("""
                    insert into execution_events
                        (id, workspace_id, run_id, test_case_run_id, trace_id, sequence, occurred_at,
                         event_type, tool_name, input_redacted, output_redacted, payload_digest,
                         policy_decision_json, reason_code, metadata_json, prev_event_hash, event_hash)
                    values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?, ?::jsonb, ?, ?::jsonb, ?, ?)
                    """,
                    eventId,
                    head.workspaceId(),
                    runId,
                    request.testCaseRunId(),
                    request.traceId(),
                    sequence,
                    Timestamp.from(occurredAt),
                    request.eventType().name(),
                    request.toolName(),
                    jsonOrNull(input),
                    jsonOrNull(output),
                    payload.originalDigest(),
                    jsonOrNull(policyDecision),
                    request.reasonCode(),
                    json(metadata),
                    head.hash(),
                    eventHash
            );
        } catch (DataIntegrityViolationException exception) {
            throw new BusinessException(ErrorCode.RESOURCE_CONFLICT, "Execution event append was rejected");
        }

        ObjectNode auditMetadata = objectMapper.createObjectNode();
        auditMetadata.put("schemaVersion", SCHEMA_VERSION);
        auditMetadata.put("runId", runId.toString());
        auditMetadata.put("sequence", sequence);
        auditMetadata.put("eventType", request.eventType().name());
        auditMetadata.put("requestTraceId", request.traceId().toString());
        auditService.append(
                head.workspaceId(),
                normalizeActor(actorId),
                "EXECUTION_EVENT_APPENDED",
                "EXECUTION_EVENT",
                eventId,
                head.hash(),
                eventHash,
                auditMetadata
        );
        return new ExecutionEventDto.Event(
                SCHEMA_VERSION,
                eventId,
                request.traceId(),
                runId,
                request.testCaseRunId(),
                sequence,
                occurredAt,
                request.eventType(),
                request.toolName(),
                input,
                output,
                payload.originalDigest(),
                policyDecision,
                request.reasonCode(),
                metadata,
                head.hash(),
                eventHash
        );
    }

    public ExecutionEventDto.Event findById(UUID eventId) {
        List<ExecutionEventDto.Event> events = jdbcTemplate.query(eventSelect() + " where event.id = ?",
                this::mapEvent, eventId);
        if (events.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "ExecutionEvent not found");
        }
        return events.getFirst();
    }

    public ExecutionEventDto.History history(UUID runId, long after, int limit) {
        if (after < 0 || limit < 1 || limit > 1000) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "after must be non-negative and limit 1..1000");
        }
        requireRun(runId);
        SequenceRange range = sequenceRange(runId);
        if (range.minimum() != null && after < range.minimum() - 1) {
            throw new BusinessException(ErrorCode.STREAM_CURSOR_EXPIRED, "Event cursor is outside replay retention");
        }
        if (after > range.maximum()) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "Event cursor is ahead of stream head");
        }
        List<ExecutionEventDto.Event> events = jdbcTemplate.query(
                eventSelect() + " where event.run_id = ? and event.sequence > ? order by event.sequence limit ?",
                this::mapEvent,
                runId,
                after,
                limit + 1
        );
        Long nextCursor = null;
        if (events.size() > limit) {
            events = new ArrayList<>(events.subList(0, limit));
            nextCursor = events.getLast().sequence();
        }
        return new ExecutionEventDto.History(List.copyOf(events), range.maximum(), nextCursor);
    }

    public ExecutionEventDto.ChainVerification verifyChain(UUID runId) {
        requireRun(runId);
        List<ExecutionEventDto.Event> events = jdbcTemplate.query(
                eventSelect() + " where event.run_id = ? order by event.sequence",
                this::mapEvent,
                runId
        );
        long expectedSequence = 1;
        String previousHash = null;
        for (ExecutionEventDto.Event event : events) {
            String recomputed = chainHash(canonicalEvent(event), previousHash);
            if (event.sequence() != expectedSequence
                    || !java.util.Objects.equals(event.prevEventHash(), previousHash)
                    || !event.eventHash().equals(recomputed)) {
                return new ExecutionEventDto.ChainVerification(
                        runId,
                        false,
                        events.size(),
                        event.sequence(),
                        previousHash
                );
            }
            expectedSequence++;
            previousHash = event.eventHash();
        }
        return new ExecutionEventDto.ChainVerification(runId, true, events.size(), null, previousHash);
    }

    private ExecutionEventDto.RunHead lockRunAndReadHead(UUID runId) {
        List<ExecutionEventDto.RunHead> runs = jdbcTemplate.query("""
                select agent.workspace_id, run.status
                  from test_runs run
                  join agent_releases release on release.id = run.release_id
                  join agents agent on agent.id = release.agent_id
                 where run.id = ?
                 for update of run
                """, (resultSet, rowNumber) -> new ExecutionEventDto.RunHead(
                        resultSet.getObject("workspace_id", UUID.class),
                        resultSet.getString("status"),
                        0,
                        null,
                        null
                ), runId);
        if (runs.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "TestRun not found");
        }
        ExecutionEventDto.RunHead run = runs.getFirst();
        List<LatestEvent> latestEvents = jdbcTemplate.query("""
                select sequence, event_hash, event_type
                  from execution_events
                 where run_id = ?
                 order by sequence desc
                 limit 1
                """, (resultSet, rowNumber) -> new LatestEvent(
                        resultSet.getLong("sequence"),
                        resultSet.getString("event_hash"),
                        ExecutionEventType.valueOf(resultSet.getString("event_type"))
                ), runId);
        if (latestEvents.isEmpty()) {
            return run;
        }
        LatestEvent latest = latestEvents.getFirst();
        return new ExecutionEventDto.RunHead(
                run.workspaceId(), run.status(), latest.sequence(), latest.hash(), latest.eventType()
        );
    }

    private void requireRun(UUID runId) {
        Integer count = jdbcTemplate.queryForObject("select count(*) from test_runs where id = ?", Integer.class, runId);
        if (count == null || count == 0) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "TestRun not found");
        }
    }

    private SequenceRange sequenceRange(UUID runId) {
        return jdbcTemplate.queryForObject("""
                select min(sequence) as minimum, coalesce(max(sequence), 0) as maximum
                  from execution_events where run_id = ?
                """, (resultSet, rowNumber) -> new SequenceRange(
                        resultSet.getObject("minimum", Long.class),
                        resultSet.getLong("maximum")
                ), runId);
    }

    private String eventSelect() {
        return """
                select event.id, event.trace_id, event.run_id, event.test_case_run_id, event.sequence,
                       event.occurred_at, event.event_type, event.tool_name,
                       event.input_redacted::text, event.output_redacted::text, event.payload_digest,
                       event.policy_decision_json::text, event.reason_code, event.metadata_json::text,
                       event.prev_event_hash, event.event_hash
                  from execution_events event
                """;
    }

    private ExecutionEventDto.Event mapEvent(java.sql.ResultSet resultSet, int rowNumber)
            throws java.sql.SQLException {
        return new ExecutionEventDto.Event(
                SCHEMA_VERSION,
                resultSet.getObject("id", UUID.class),
                resultSet.getObject("trace_id", UUID.class),
                resultSet.getObject("run_id", UUID.class),
                resultSet.getObject("test_case_run_id", UUID.class),
                resultSet.getLong("sequence"),
                resultSet.getTimestamp("occurred_at").toInstant(),
                ExecutionEventType.valueOf(resultSet.getString("event_type")),
                resultSet.getString("tool_name"),
                parseJson(resultSet.getString("input_redacted")),
                parseJson(resultSet.getString("output_redacted")),
                resultSet.getString("payload_digest"),
                parseJson(resultSet.getString("policy_decision_json")),
                resultSet.getString("reason_code"),
                parseJson(resultSet.getString("metadata_json")),
                resultSet.getString("prev_event_hash"),
                resultSet.getString("event_hash")
        );
    }

    private ObjectNode canonicalEvent(ExecutionEventDto.Event event) {
        return canonicalEvent(
                event.eventId(), event.traceId(), event.runId(), event.testCaseRunId(), event.sequence(),
                event.occurredAt(), event.eventType(), event.toolName(), event.input(), event.output(),
                event.payloadDigest(), event.policyDecision(), event.reasonCode(), event.metadata()
        );
    }

    private ObjectNode canonicalEvent(
            UUID eventId,
            UUID traceId,
            UUID runId,
            UUID testCaseRunId,
            long sequence,
            Instant occurredAt,
            ExecutionEventType eventType,
            String toolName,
            JsonNode input,
            JsonNode output,
            String payloadDigest,
            JsonNode policyDecision,
            String reasonCode,
            JsonNode metadata
    ) {
        ObjectNode event = objectMapper.createObjectNode();
        event.put("schemaVersion", SCHEMA_VERSION);
        event.put("eventId", eventId.toString());
        event.put("traceId", traceId.toString());
        event.put("runId", runId.toString());
        putUuidOrNull(event, "testCaseRunId", testCaseRunId);
        event.put("sequence", sequence);
        event.put("occurredAt", occurredAt.toString());
        event.put("eventType", eventType.name());
        putTextOrNull(event, "toolName", toolName);
        event.set("input", nullToJson(input));
        event.set("output", nullToJson(output));
        event.put("payloadDigest", payloadDigest);
        event.set("policyDecision", nullToJson(policyDecision));
        putTextOrNull(event, "reasonCode", reasonCode);
        event.set("metadata", metadata == null ? objectMapper.createObjectNode() : metadata);
        return event;
    }

    private String chainHash(ObjectNode event, String previousHash) {
        byte[] eventBytes = canonicalJsonService.canonicalize(event);
        byte[] previousBytes = previousHash == null
                ? new byte[0]
                : previousHash.getBytes(StandardCharsets.UTF_8);
        byte[] chained = Arrays.copyOf(eventBytes, eventBytes.length + previousBytes.length);
        System.arraycopy(previousBytes, 0, chained, eventBytes.length, previousBytes.length);
        return digestService.sha256(chained);
    }

    private void requireAppendRequest(ExecutionEventDto.AppendRequest request) {
        if (request == null || request.traceId() == null || request.eventType() == null) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "traceId and eventType are required");
        }
        requireSafeLabel(request.toolName(), "toolName", 100);
        requireSafeLabel(request.reasonCode(), "reasonCode", 100);
    }

    private void requireSafeLabel(String value, String name, int maximum) {
        if (value != null && (value.length() > maximum || !value.matches("[A-Za-z0-9._:-]*"))) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, name + " contains unsupported characters");
        }
    }

    private String normalizeActor(String actorId) {
        if (actorId == null || actorId.isBlank()) {
            return "system:runtime";
        }
        if (actorId.length() > 120) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "X-Actor-Id exceeds 120 characters");
        }
        return actorId;
    }

    private JsonNode nullToJson(JsonNode value) {
        return value == null || value.isMissingNode() ? objectMapper.nullNode() : value;
    }

    private String jsonOrNull(JsonNode value) {
        return value == null || value.isNull() ? null : json(value);
    }

    private String json(JsonNode value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception exception) {
            throw new IllegalArgumentException("Event JSON serialization failed", exception);
        }
    }

    private JsonNode parseJson(String value) {
        if (value == null) {
            return objectMapper.nullNode();
        }
        try {
            return objectMapper.readTree(value);
        } catch (Exception exception) {
            throw new IllegalStateException("Stored execution event JSON is invalid", exception);
        }
    }

    private void putTextOrNull(ObjectNode object, String field, String value) {
        if (value == null) {
            object.putNull(field);
        } else {
            object.put(field, value);
        }
    }

    private void putUuidOrNull(ObjectNode object, String field, UUID value) {
        putTextOrNull(object, field, value == null ? null : value.toString());
    }

    private record SequenceRange(Long minimum, long maximum) {
    }

    private record LatestEvent(long sequence, String hash, ExecutionEventType eventType) {
    }
}
