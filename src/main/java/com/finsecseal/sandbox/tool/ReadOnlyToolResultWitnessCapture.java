package com.finsecseal.sandbox.tool;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.evidence.RedactionService;
import com.finsecseal.policy.GatewayRuntimeObservations.InvocationKey;
import com.finsecseal.policy.GatewayRuntimeObservations.StateCapture;
import com.finsecseal.runtime.ToolInvocation;
import com.finsecseal.sandbox.SandboxExecutionContext;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.LongSupplier;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * In-process witness for the actual result of one read-only adapter attempt.
 *
 * <p>This is deliberately not a Spring bean or a Gateway observations provider. A production
 * caller also needs a durable per-invocation idempotency claim, trusted pre-call scope, bounded
 * adapter I/O, actual field classification, and complete namespace-state observations.
 */
public final class ReadOnlyToolResultWitnessCapture {

    static final int MAX_ENTRIES = 16; // Active entries and tombstones share this limit.
    static final long TTL_NANOS = Duration.ofSeconds(5).toNanos();
    static final int MAX_RESPONSE_BYTES = 1024 * 1024;
    static final int MAX_RESPONSE_DEPTH = 64;
    static final int MAX_RESPONSE_NODES = 65_536;
    private static final int MAX_CUSTOMER_ROWS = 20;
    private static final int MAX_CUSTOMER_FIELDS = 20;
    private static final int MAX_CUSTOMER_FIELD_NAME_LENGTH = 80;
    private static final int MAX_NUMERIC_DIGITS = 32 * 1024;
    private static final String FAILURE_MESSAGE = "Read-only Tool result witness is incomplete";

    private final RedactionService redactionService;
    private final LongSupplier nanoTime;
    private final Map<InvocationKey, Slot> slots = new HashMap<>();

    public ReadOnlyToolResultWitnessCapture(RedactionService redactionService) {
        this(redactionService, System::nanoTime);
    }

    ReadOnlyToolResultWitnessCapture(RedactionService redactionService, LongSupplier nanoTime) {
        this.redactionService = Objects.requireNonNull(redactionService);
        this.nanoTime = Objects.requireNonNull(nanoTime);
    }

    /**
     * Reserves the whole invocation key before entering the adapter. One successful reservation
     * calls execute once; this does not establish exactly-once execution across TTL or restarts.
     */
    public CapturedResult executeCaptured(InvocationKey key, StateCapture before,
            SandboxExecutionContext context, ToolInvocation invocation, ToolAdapter adapter) {
        requireEligible(key, before, context, invocation, adapter);
        Slot slot = reserve(key, before.captureId());
        try {
            ToolAdapter.ToolExecutionResult raw = adapter.execute(context, invocation.proposal().arguments());
            if (raw == null || raw.stateChanged() || raw.output() == null) {
                throw incomplete();
            }
            // Copy with limits before redaction or canonicalization can traverse adapter-owned data.
            JsonNode snapshot = boundedSnapshot(raw.output());
            CustomerFieldInventory customerFields = customerFields(adapter, snapshot);
            String digest = redactionService.redact(snapshot.deepCopy()).originalDigest();
            if (digest == null || !digest.matches("sha256:[0-9a-f]{64}")) {
                throw incomplete();
            }
            CapturedResult result = new CapturedResult(
                    new ToolAdapter.ToolExecutionResult(snapshot, false), slot.captureId);
            complete(key, slot, digest, customerFields);
            return result;
        } catch (RuntimeException exception) {
            fail(key, slot);
            throw incomplete();
        }
    }

    /** A cancelled capture remains a tombstone until its original reservation TTL expires. */
    public void cancel(InvocationKey key, UUID captureId) {
        synchronized (slots) {
            expire(nanoTime.getAsLong());
            Slot slot = slots.get(key);
            if (slot == null || !slot.captureId.equals(captureId)
                    || slot.state == State.CANCELLED || slot.state == State.FAILED
                    || slot.state == State.CONSUMED) {
                throw incomplete();
            }
            slot.digest = null;
            slot.customerFields = null;
            slot.state = State.CANCELLED;
        }
    }

    /** Consumes only the matching completed capture and retains a same-key tombstone. */
    public Witness consume(InvocationKey key, UUID captureId) {
        synchronized (slots) {
            expire(nanoTime.getAsLong());
            Slot slot = slots.get(key);
            if (slot == null || !slot.captureId.equals(captureId)
                    || slot.state != State.COMPLETE || slot.digest == null) {
                throw incomplete();
            }
            Witness witness = new Witness(key, captureId, slot.digest, false,
                    Optional.ofNullable(slot.customerFields));
            slot.digest = null;
            slot.customerFields = null;
            slot.state = State.CONSUMED;
            return witness;
        }
    }

    private void requireEligible(InvocationKey key, StateCapture before,
            SandboxExecutionContext context, ToolInvocation invocation, ToolAdapter adapter) {
        if (key == null || before == null || context == null || invocation == null || adapter == null
                || !key.equals(before.key()) || !before.complete()
                || !Objects.equals(before.namespaceId(), context.namespaceId())
                || !Objects.equals(key.runId(), context.runId())
                || !Objects.equals(key.caseRunId(), context.caseRunId())
                || !Objects.equals(key.traceId(), context.traceId())
                || context.mode() == null
                || !Objects.equals(key.toolCallId(), invocation.toolCallId())
                || !Objects.equals(key.requestDigest(), invocation.requestDigest())
                || invocation.proposal() == null
                || TransactionSynchronizationManager.isActualTransactionActive()
                || TransactionSynchronizationManager.isSynchronizationActive()) {
            throw incomplete();
        }
        try {
            if (adapter.effect() != ToolEffect.READ_ONLY
                    || !Objects.equals(adapter.toolName(), invocation.proposal().toolName())) {
                throw incomplete();
            }
        } catch (RuntimeException exception) {
            throw incomplete();
        }
    }

    private Slot reserve(InvocationKey key, UUID captureId) {
        synchronized (slots) {
            long now = nanoTime.getAsLong();
            expire(now);
            if (slots.containsKey(key) || slots.size() >= MAX_ENTRIES) {
                throw incomplete();
            }
            Slot slot = new Slot(captureId, now);
            slots.put(key, slot);
            return slot;
        }
    }

    private void complete(InvocationKey key, Slot slot, String digest,
            CustomerFieldInventory customerFields) {
        synchronized (slots) {
            expire(nanoTime.getAsLong());
            if (slots.get(key) != slot || slot.state != State.ACTIVE) {
                throw incomplete();
            }
            slot.digest = digest;
            slot.customerFields = customerFields;
            slot.state = State.COMPLETE;
        }
    }

    private void fail(InvocationKey key, Slot slot) {
        synchronized (slots) {
            expire(nanoTime.getAsLong());
            if (slots.get(key) == slot && slot.state == State.ACTIVE) {
                slot.digest = null;
                slot.customerFields = null;
                slot.state = State.FAILED;
            }
        }
    }

    private void expire(long now) {
        // Subtraction works across nanoTime's signed wrap for elapsed intervals shorter than 2^63 ns.
        slots.values().removeIf(slot -> now - slot.reservedAt >= TTL_NANOS);
    }

    private static JsonNode boundedSnapshot(JsonNode raw) {
        try {
            Budget budget = new Budget();
            JsonNode copy = copyNode(raw, 1, budget, new IdentityHashMap<>());
            if (copy.toString().getBytes(StandardCharsets.UTF_8).length > MAX_RESPONSE_BYTES) {
                throw incomplete();
            }
            return copy;
        } catch (RuntimeException exception) {
            throw incomplete();
        }
    }

    /** Only the concrete customer adapter's returned snapshot can yield this partial field fact. */
    private static CustomerFieldInventory customerFields(ToolAdapter adapter, JsonNode snapshot) {
        if (!(adapter instanceof CustomerDataReadToolAdapter)) return null;
        if (!snapshot.isObject() || snapshot.size() != 2
                || !snapshot.has("status") || !snapshot.has("rows")
                || !snapshot.path("status").isIntegralNumber()
                || !snapshot.path("status").canConvertToInt()
                || snapshot.path("status").intValue() != 200
                || !snapshot.path("rows").isArray()
                || snapshot.path("rows").size() > MAX_CUSTOMER_ROWS) {
            throw incomplete();
        }
        List<List<String>> fieldsByRow = new ArrayList<>();
        for (JsonNode row : snapshot.path("rows")) {
            if (!row.isObject() || row.size() != 2
                    || !row.path("customerId").isString()
                    || row.path("customerId").stringValue().isBlank()
                    || !row.path("fields").isObject()
                    || row.path("fields").size() > MAX_CUSTOMER_FIELDS) {
                throw incomplete();
            }
            List<String> fields = new ArrayList<>();
            Set<String> seen = new HashSet<>();
            for (var field : row.path("fields").properties()) {
                String name = field.getKey();
                if (name == null || name.isBlank() || name.length() > MAX_CUSTOMER_FIELD_NAME_LENGTH
                        || !name.equals(name.strip()) || !seen.add(name)) {
                    throw incomplete();
                }
                fields.add(name);
            }
            fieldsByRow.add(List.copyOf(fields));
        }
        return new CustomerFieldInventory(fieldsByRow);
    }

    private static JsonNode copyNode(JsonNode node, int depth, Budget budget,
            IdentityHashMap<JsonNode, Boolean> ancestors) {
        if (node == null || depth > MAX_RESPONSE_DEPTH) {
            throw incomplete();
        }
        budget.node();
        if (node.isObject() || node.isArray()) {
            if (ancestors.put(node, Boolean.TRUE) != null) {
                throw incomplete();
            }
            try {
                if (node.isObject()) {
                    ObjectNode object = JsonNodeFactory.instance.objectNode();
                    budget.bytes(2);
                    for (var property : node.properties()) {
                        String name = property.getKey();
                        budget.bytes(utf8Length(name) + 4L);
                        object.set(name, copyNode(property.getValue(), depth + 1, budget, ancestors));
                    }
                    return object;
                }
                ArrayNode array = JsonNodeFactory.instance.arrayNode();
                budget.bytes(2);
                for (JsonNode child : node) {
                    budget.bytes(1);
                    array.add(copyNode(child, depth + 1, budget, ancestors));
                }
                return array;
            } finally {
                ancestors.remove(node);
            }
        }
        if (node.isString()) {
            budget.bytes(utf8Length(node.stringValue()) + 2L);
        } else if (node.isNumber()) {
            Number number = node.numberValue();
            if (!safeNumber(number)) {
                throw incomplete();
            }
            String encoded = number.toString();
            budget.bytes(utf8Length(encoded));
            budget.numericWork(numericWork(number, encoded));
        } else if (node.isBoolean() || node.isNull()) {
            budget.bytes(5);
        } else {
            throw incomplete();
        }
        return node.deepCopy();
    }

    private static int utf8Length(String text) {
        if (text == null || text.length() > MAX_RESPONSE_BYTES) {
            throw incomplete();
        }
        return text.getBytes(StandardCharsets.UTF_8).length;
    }

    private static boolean safeNumber(Number number) {
        if (number == null) return false;
        if (number instanceof Double value) return Double.isFinite(value);
        if (number instanceof Float value) return Float.isFinite(value);
        if (number instanceof BigInteger value) return value.bitLength() <= MAX_NUMERIC_DIGITS * 4;
        if (number instanceof BigDecimal value) {
            return value.unscaledValue().bitLength() <= MAX_NUMERIC_DIGITS * 4
                    && value.precision() <= MAX_NUMERIC_DIGITS
                    && (value.signum() == 0
                            || (long) value.precision() - value.scale() <= MAX_NUMERIC_DIGITS)
                    && Math.abs((long) value.scale()) <= MAX_RESPONSE_BYTES;
        }
        return true;
    }

    private static long numericWork(Number number, String encoded) {
        long work = encoded.length();
        BigDecimal decimal = number instanceof BigDecimal value ? value
                : number instanceof Double || number instanceof Float ? new BigDecimal(encoded) : null;
        if (decimal != null && decimal.signum() != 0) {
            work = Math.max(work, Math.max(decimal.precision(),
                    (long) decimal.precision() - decimal.scale()));
        }
        return work;
    }

    private static BusinessException incomplete() {
        return new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, FAILURE_MESSAGE);
    }

    private enum State { ACTIVE, COMPLETE, CONSUMED, FAILED, CANCELLED }

    private static final class Slot {
        private final UUID captureId;
        private final long reservedAt;
        private State state = State.ACTIVE;
        private String digest;
        private CustomerFieldInventory customerFields;

        private Slot(UUID captureId, long reservedAt) {
            this.captureId = captureId;
            this.reservedAt = reservedAt;
        }
    }

    private static final class Budget {
        private int nodes;
        private long bytes;
        private long numericWork;

        private void node() {
            if (++nodes > MAX_RESPONSE_NODES) throw incomplete();
        }

        private void bytes(long count) {
            bytes += count;
            if (bytes > MAX_RESPONSE_BYTES) throw incomplete();
        }

        private void numericWork(long count) {
            numericWork += count;
            if (numericWork > MAX_RESPONSE_BYTES) throw incomplete();
        }
    }

    /** Created only by one successful consume; names are not Sensitivity classifications. */
    public static final class Witness {
        private final InvocationKey key;
        private final UUID captureId;
        private final String rawOutputDigest;
        private final boolean reportedStateChanged;
        private final Optional<CustomerFieldInventory> customerFields;

        private Witness(InvocationKey key, UUID captureId, String rawOutputDigest,
                boolean reportedStateChanged, Optional<CustomerFieldInventory> customerFields) {
            this.key = key;
            this.captureId = captureId;
            this.rawOutputDigest = rawOutputDigest;
            this.reportedStateChanged = reportedStateChanged;
            this.customerFields = customerFields;
        }

        public InvocationKey key() { return key; }
        public UUID captureId() { return captureId; }
        public String rawOutputDigest() { return rawOutputDigest; }
        public boolean reportedStateChanged() { return reportedStateChanged; }
        public Optional<CustomerFieldInventory> customerFields() { return customerFields; }

        @Override public String toString() { return "ReadOnlyToolResultWitness[redacted]"; }
    }

    /** Row positions and exact returned field names only; no customer ID or value is retained. */
    public static final class CustomerFieldInventory {
        private final List<List<String>> fieldNamesByRow;

        private CustomerFieldInventory(List<List<String>> fieldNamesByRow) {
            this.fieldNamesByRow = List.copyOf(fieldNamesByRow);
        }

        public int rowCount() { return fieldNamesByRow.size(); }
        public List<List<String>> fieldNamesByRow() { return fieldNamesByRow; }

        @Override public String toString() { return "CustomerFieldInventory[redacted]"; }
    }

    public record CapturedResult(ToolAdapter.ToolExecutionResult result, UUID captureId) {
        public CapturedResult {
            if (result == null || result.output() == null || result.stateChanged() || captureId == null) {
                throw incomplete();
            }
            result = new ToolAdapter.ToolExecutionResult(result.output().deepCopy(), false);
        }

        @Override
        public ToolAdapter.ToolExecutionResult result() {
            return new ToolAdapter.ToolExecutionResult(result.output().deepCopy(), false);
        }

        @Override public String toString() { return "CapturedToolResult[redacted]"; }
    }
}
