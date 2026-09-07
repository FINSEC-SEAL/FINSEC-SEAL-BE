package com.finsecseal.contract;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;

/** Displays supplied policy changes without judging patch safety, approval or stored provenance. */
@Component
public final class SafetyContractReviewDiff {
    private static final Comparator<String> SET_ORDER = Comparator
            .comparing(SafetyContractTextNormalizer::normalize).thenComparing(Comparator.naturalOrder());

    private final SafetyContractSchemaValidator schemaValidator;
    private final SafetyContractCanonicalizer canonicalizer;

    public SafetyContractReviewDiff(SafetyContractSchemaValidator schemaValidator,
            SafetyContractCanonicalizer canonicalizer) {
        this.schemaValidator = Objects.requireNonNull(schemaValidator, "schemaValidator must not be null");
        this.canonicalizer = Objects.requireNonNull(canonicalizer, "canonicalizer must not be null");
    }

    public Comparison compare(Optional<JsonNode> before, JsonNode after) {
        if (before == null) {
            throw failure(FailureCode.INVALID_REQUEST, InputSide.REQUEST);
        }
        JsonNode beforeSnapshot = before.isPresent() ? snapshot(before.orElseThrow(), InputSide.BEFORE) : null;
        JsonNode afterSnapshot = snapshot(after, InputSide.AFTER);
        Optional<String> beforeHash = beforeSnapshot == null
                ? Optional.empty() : Optional.of(hash(beforeSnapshot, InputSide.BEFORE));
        String afterHash = hash(afterSnapshot, InputSide.AFTER);

        // Canonical hashes can hide Unicode/newline and numeric rendering differences.
        // Compare original snapshots independently, including semantically invalid policy changes.
        List<Change> changes = new ArrayList<>();
        compareValues(beforeSnapshot, afterSnapshot, "", changes);
        return new Comparison(beforeHash, afterHash, changes);
    }

    private JsonNode snapshot(JsonNode value, InputSide side) {
        try {
            JsonNode copy = value == null ? null : value.deepCopy();
            var validation = Objects.requireNonNull(schemaValidator.validate(copy));
            if (!validation.valid()) {
                throw failure(FailureCode.INVALID_SNAPSHOT, side);
            }
            return copy;
        } catch (ComparisonException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw failure(FailureCode.COMPARISON_UNAVAILABLE, side);
        }
    }

    private String hash(JsonNode snapshot, InputSide side) {
        try {
            return Objects.requireNonNull(canonicalizer.canonicalizeAndHash(snapshot)).policyHash();
        } catch (RuntimeException exception) {
            throw failure(FailureCode.COMPARISON_UNAVAILABLE, side);
        }
    }

    private void compareValues(JsonNode before, JsonNode after, String pointer, List<Change> changes) {
        if (before == null) {
            changes.add(new Change(pointer, ChangeKind.ADDED, null, after));
        } else if (after == null) {
            changes.add(new Change(pointer, ChangeKind.REMOVED, before, null));
        } else if (before.isObject() && after.isObject()) {
            Set<String> keys = new TreeSet<>();
            before.properties().forEach(entry -> keys.add(entry.getKey()));
            after.properties().forEach(entry -> keys.add(entry.getKey()));
            for (String key : keys) {
                compareValues(before.get(key), after.get(key), pointer + "/" + escape(key), changes);
            }
        } else if (!equalValues(before, after)) {
            changes.add(new Change(pointer, ChangeKind.MODIFIED, before, after));
        }
    }

    private boolean equalValues(JsonNode before, JsonNode after) {
        if (before.isIntegralNumber() && after.isIntegralNumber()) {
            return before.bigIntegerValue().equals(after.bigIntegerValue());
        }
        if (before.isArray() && after.isArray()) {
            return sortedSet(before).equals(sortedSet(after));
        }
        return before.equals(after);
    }

    private List<String> sortedSet(JsonNode array) {
        // Every structurally valid Safety Contract array is a string set.
        List<String> values = new ArrayList<>();
        array.forEach(value -> values.add(value.stringValue()));
        values.sort(SET_ORDER);
        return values;
    }

    private static String escape(String key) {
        return key.replace("~", "~0").replace("/", "~1");
    }

    public enum ChangeKind { ADDED, REMOVED, MODIFIED }
    public enum InputSide { REQUEST, BEFORE, AFTER }
    public enum FailureCode { INVALID_REQUEST, INVALID_SNAPSHOT, COMPARISON_UNAVAILABLE }

    public static final class Comparison {
        private final Optional<String> beforeHash;
        private final String afterHash;
        private final List<Change> changes;

        private Comparison(Optional<String> beforeHash, String afterHash, List<Change> changes) {
            this.beforeHash = beforeHash;
            this.afterHash = afterHash;
            this.changes = List.copyOf(changes);
        }

        public Optional<String> beforeHash() { return beforeHash; }
        public String afterHash() { return afterHash; }
        public List<Change> changes() { return changes; }
    }

    public static final class Change {
        private final String pointer;
        private final ChangeKind kind;
        private final JsonNode before;
        private final JsonNode after;

        private Change(String pointer, ChangeKind kind, JsonNode before, JsonNode after) {
            this.pointer = pointer;
            this.kind = kind;
            this.before = before == null ? null : before.deepCopy();
            this.after = after == null ? null : after.deepCopy();
        }

        public String pointer() { return pointer; }
        public ChangeKind kind() { return kind; }
        public Optional<JsonNode> before() { return Optional.ofNullable(before).map(value -> value.deepCopy()); }
        public Optional<JsonNode> after() { return Optional.ofNullable(after).map(value -> value.deepCopy()); }
    }

    public static final class ComparisonException extends RuntimeException {
        private final FailureCode code;
        private final InputSide side;

        private ComparisonException(FailureCode code, InputSide side) {
            super("Contract review comparison unavailable: " + code.name() + " (" + side.name() + ")");
            this.code = code;
            this.side = side;
        }

        public FailureCode code() { return code; }
        public InputSide side() { return side; }
    }

    private static ComparisonException failure(FailureCode code, InputSide side) {
        return new ComparisonException(code, side);
    }
}
