package com.finsecseal.policy;

import com.finsecseal.policy.NonCustomerResponseSemanticsEvaluator.DocumentSource;
import com.finsecseal.policy.PolicyObjectScopeFacts.DocumentOwnership;
import com.finsecseal.policy.PolicyToolTrustFacts.ToolRegistryEntry;
import com.finsecseal.sandbox.SandboxExecutionContext;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

/**
 * Required observations from the actual runtime; this interface supplies no implementation or authority.
 * Implementations must honor the positive remaining timeout through finite JDBC/transport deadlines.
 * A callback signature or an elapsed-time check cannot interrupt arbitrary synchronous I/O.
 * Observations must come from the bound invocation, never from expected policy/catalog values.
 */
public interface GatewayRuntimeObservations {
    PreCall resolve(InvocationKey key, Duration timeout);

    /** Called only when policy evaluation reaches Tool Trust, not during context resolution. */
    RegistryObservation registry(InvocationKey key, Duration timeout);

    /** Capture the full namespace before execution; the returned value retains no open resources. */
    StateCapture begin(InvocationKey key, Duration timeout);

    /**
     * Observe the actual returned body and complete changes of this same call. The Gateway never
     * supplies an expected body digest to echo. Include changes outside the expected namespace;
     * filtering them out would hide a violation. Values retain no open connections, locks or streams.
     */
    Completion complete(InvocationKey key, StateCapture before, Duration timeout);

    /** Shared guard for implementations; callers must still configure their actual I/O deadline. */
    static Duration requireTimeout(Duration timeout) {
        if (timeout == null || timeout.isNegative() || timeout.isZero()
                || timeout.compareTo(Duration.ofSeconds(5)) > 0) {
            throw failure(FailureCode.INVALID_DEADLINE);
        }
        return timeout;
    }

    record InvocationKey(UUID runId, UUID caseRunId, UUID traceId, UUID toolCallId, String requestDigest) {
        public InvocationKey {
            required(runId); required(caseRunId); required(traceId); required(toolCallId);
            digest(requestDigest);
        }
    }

    /** Values read from the actual namespace row, not copied from the expected Run projection. */
    record NamespaceObservation(UUID namespaceId, String fixtureVersion, String fixtureDigest, String state) {
        public NamespaceObservation {
            required(namespaceId); text(fixtureVersion); digest(fixtureDigest);
            if (!"ACTIVE".equals(state)) throw invalid();
        }
    }

    record PreCall(InvocationKey key, SandboxExecutionContext serverContext, NamespaceObservation namespace,
            Optional<String> runPurpose, Optional<String> casePurpose, Optional<String> workflowStage,
            Optional<List<String>> allowedDocumentIds, Optional<List<DocumentOwnership>> documentOwnerships,
            Optional<DocumentSource> documentSource, String requestedOperation) {
        public PreCall {
            required(key); required(serverContext); required(namespace);
            runPurpose = optionalText(runPurpose); casePurpose = optionalText(casePurpose);
            workflowStage = optionalText(workflowStage);
            allowedDocumentIds = optionalList(allowedDocumentIds);
            allowedDocumentIds.ifPresent(ids -> ids.forEach(GatewayRuntimeObservations::text));
            documentOwnerships = optionalList(documentOwnerships);
            required(documentSource); text(requestedOperation);
        }

        @Override public String toString() { return "GatewayPreCall[" + key + "]"; }
    }

    record RegistryObservation(InvocationKey key, String observedReleaseFingerprint,
            List<ToolRegistryEntry> entries) {
        public RegistryObservation {
            required(key); digest(observedReleaseFingerprint); entries = copy(entries);
        }
    }

    /** complete=false represents missing coverage, not an empty or unchanged namespace. */
    record StateCapture(InvocationKey key, UUID captureId, UUID namespaceId,
            String beforeStateDigest, boolean complete) {
        public StateCapture {
            required(key); required(captureId); required(namespaceId); digest(beforeStateDigest);
        }
    }

    record Completion(InvocationKey key, UUID captureId, UUID namespaceId, String rawOutputDigest,
            JsonNode classificationMap, String afterStateDigest, boolean complete, List<StateChange> changes) {
        public Completion {
            required(key); required(captureId); required(namespaceId);
            digest(rawOutputDigest); digest(afterStateDigest);
            classificationMap = classificationSnapshot(classificationMap);
            changes = copy(changes);
        }

        @Override public JsonNode classificationMap() { return classificationMap.deepCopy(); }
        @Override public String toString() {
            return "GatewayCompletion[" + key + ",captureId=" + captureId + ",complete=" + complete + "]";
        }
    }

    record StateChange(StateEntity entityType, UUID namespaceId, String entityIdDigest, Optional<String> caseId,
            OptionalLong beforeVersion, OptionalLong afterVersion,
            Optional<String> beforeDigest, Optional<String> afterDigest) {
        public StateChange {
            required(entityType); required(namespaceId); digest(entityIdDigest); caseId = optionalText(caseId);
            required(beforeVersion); required(afterVersion);
            if (beforeVersion.isPresent() && beforeVersion.getAsLong() < 0
                    || afterVersion.isPresent() && afterVersion.getAsLong() < 0) throw invalid();
            beforeDigest = optionalDigest(beforeDigest); afterDigest = optionalDigest(afterDigest);
            if (beforeDigest.isEmpty() && afterDigest.isEmpty()) throw invalid();
        }
    }

    enum StateEntity { LOAN_CASE, CUSTOMER, DOCUMENT, LOAN_POLICY, REVIEW_NOTE, LOAN_DECISION, EXFIL_EVENT }

    enum FailureCode { INVALID_OBSERVATION, INVALID_DEADLINE }

    final class ObservationException extends RuntimeException {
        private final FailureCode code;
        private ObservationException(FailureCode code) {
            super(code.name(), null, false, true); this.code = code;
        }
        public FailureCode code() { return code; }
    }

    private static JsonNode classificationSnapshot(JsonNode value) {
        JsonNode snapshot = CatalogBoundInputSchemaEvaluator.snapshotResponse(value);
        if (snapshot == null || !snapshot.isObject()) throw invalid();
        return snapshot;
    }

    private static <T> List<T> copy(List<T> values) {
        required(values);
        for (T value : values) required(value);
        return List.copyOf(values);
    }

    private static <T> Optional<List<T>> optionalList(Optional<List<T>> value) {
        required(value);
        return value.map(GatewayRuntimeObservations::copy);
    }

    private static Optional<String> optionalText(Optional<String> value) {
        required(value); value.ifPresent(GatewayRuntimeObservations::text); return value;
    }

    private static Optional<String> optionalDigest(Optional<String> value) {
        required(value); value.ifPresent(GatewayRuntimeObservations::digest); return value;
    }

    private static void text(String value) {
        if (value == null || value.isBlank() || !value.equals(value.strip())) throw invalid();
    }

    private static void digest(String value) {
        if (value == null || !value.matches("sha256:[0-9a-f]{64}")) throw invalid();
    }

    private static void required(Object value) { if (value == null) throw invalid(); }
    private static ObservationException invalid() { return failure(FailureCode.INVALID_OBSERVATION); }
    private static ObservationException failure(FailureCode code) { return new ObservationException(code); }
}
