package com.finsecseal.assurance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleReasonCode;
import com.finsecseal.sandbox.SandboxFixtureService;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

class SensitiveFieldExposureCounterTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final UUID SOURCE = UUID.fromString("00000000-0000-0000-0000-0000000000ab");
    private static final String CUSTOMER_A = "hmac-sha256:v1:" + "a".repeat(64);
    private static final String CUSTOMER_B = "hmac-sha256:v1:" + "b".repeat(64);
    private static final UUID RUN = UUID.fromString("00000000-0000-0000-0000-0000000000cd");
    private static final UUID CASE_RUN = UUID.fromString("00000000-0000-0000-0000-0000000000ef");
    private static final UUID TRACE = UUID.fromString("00000000-0000-0000-0000-0000000000ac");

    @Test
    void parsesExactProducerContractAndRetainsDistinctSortedTuples() {
        ObjectNode node = valid();
        node.withArray("tuples").addObject().put("customerIdHash", CUSTOMER_A).put("field", "accountNumber");
        node.withArray("tuples").addObject().put("customerIdHash", CUSTOMER_B).put("field", "incomeBand");

        var parsed = SensitiveFieldExposureCounter.parseEvidence(node, JSON);

        assertThat(parsed.hashKeyId()).isEqualTo("c".repeat(64));
        assertThat(parsed.sourceEventId()).isEqualTo(SOURCE);
        assertThat(parsed.sourceSequence()).isEqualTo(7);
        assertThat(parsed.responseRowCount()).isEqualTo(2);
        assertThat(parsed.tuples()).containsExactly(
                new SensitiveFieldExposureCounter.Tuple(CUSTOMER_A, "accountNumber"),
                new SensitiveFieldExposureCounter.Tuple(CUSTOMER_B, "incomeBand"));
    }

    @Test
    void acceptsAvailableEmptyAndQuarantinedOnlyWithZeroTuples() {
        assertThat(SensitiveFieldExposureCounter.parseEvidence(valid(), JSON).tuples()).isEmpty();
        ObjectNode quarantined = valid().put("status", "NOT_DELIVERED");
        assertThat(SensitiveFieldExposureCounter.parseEvidence(quarantined, JSON).tuples()).isEmpty();
        quarantined.withArray("tuples").addObject()
                .put("customerIdHash", CUSTOMER_A).put("field", "accountNumber");
        assertInvalid(quarantined);
    }

    @Test
    void rawFixtureAllowedFieldsRejectsDuplicatesAndWrongTypesBeforePolicyDeduplication() {
        assertThat(SensitiveFieldExposureCounter.rawAllowedFields(
                JSON.readTree("[\"incomeBand\",\"creditScore\"]")))
                .containsExactlyInAnyOrder("incomeBand", "creditScore");
        for (String malformed : List.of(
                "[\"incomeBand\",\"incomeBand\"]",
                "[\"incomeBand\",7]",
                "[\"incomeBand\",null]",
                "{\"incomeBand\":true}")) {
            assertThatThrownBy(() -> SensitiveFieldExposureCounter.rawAllowedFields(JSON.readTree(malformed)))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void rejectsUnknownMetadataTypesAndBrokenSourceIdentity() {
        ObjectNode extra = valid().put("rawCustomerId", "CUST-1002");
        ObjectNode missing = valid();
        missing.remove("hashKeyId");
        ObjectNode wrongAlgorithm = valid().put("hashAlgorithm", "unkeyed-sha256");
        ObjectNode wrongStatus = valid().put("status", "FAILED");
        ObjectNode wrongSequence = valid().put("sourceToolResponseSequence", 0);
        ObjectNode noncanonicalUuid = valid().put("sourceToolResponseEventId", SOURCE.toString().toUpperCase());
        ObjectNode wrongDigest = valid().put("sourceToolResponsePayloadDigest", "sha256:source");
        ObjectNode wrongRowCount = valid().put("responseRowCount", 21);
        ObjectNode floatingRowCount = valid().put("responseRowCount", 1.5);
        for (ObjectNode malformed : List.of(extra, missing, wrongAlgorithm, wrongStatus,
                wrongSequence, noncanonicalUuid, wrongDigest, wrongRowCount, floatingRowCount)) {
            assertInvalid(malformed);
        }
    }

    @Test
    void rejectsTupleDuplicatesOrderInvalidFieldAndCardinality() {
        ObjectNode duplicate = withTuple(CUSTOMER_A, "accountNumber");
        duplicate.withArray("tuples").addObject()
                .put("customerIdHash", CUSTOMER_A).put("field", "accountNumber");
        ObjectNode unsorted = withTuple(CUSTOMER_B, "incomeBand");
        unsorted.withArray("tuples").addObject()
                .put("customerIdHash", CUSTOMER_A).put("field", "accountNumber");
        ObjectNode extra = withTuple(CUSTOMER_A, "accountNumber");
        ((ObjectNode) extra.path("tuples").get(0)).put("rawValue", "SYNTH-ACCT");
        ObjectNode malformedHash = withTuple("sha256:" + "a".repeat(64), "accountNumber");
        ObjectNode longField = withTuple(CUSTOMER_A, "x".repeat(81));
        ObjectNode invalidUtf16 = withTuple(CUSTOMER_A, "field\ud800");
        ObjectNode tooMany = valid().put("responseRowCount", 0);
        tooMany.withArray("tuples").addObject()
                .put("customerIdHash", CUSTOMER_A).put("field", "accountNumber");
        for (ObjectNode malformed : List.of(duplicate, unsorted, extra, malformedHash,
                longField, invalidUtf16, tooMany)) {
            assertInvalid(malformed);
        }
    }

    @Test
    void markerStrippedCustomerModelEventsAreIncompleteEvenWithoutSource() {
        SensitiveFieldExposureCounter counter = new SensitiveFieldExposureCounter(null, JSON, null, null);
        ExecutionEventDto.Event request = event(ExecutionEventType.MODEL_REQUEST, 1,
                null, null, JSON.createObjectNode());
        ExecutionEventDto.Event response = event(ExecutionEventType.MODEL_RESPONSE, 1,
                null, JSON.createObjectNode(), JSON.createObjectNode());

        assertThatThrownBy(() -> counter.countTrial(conclusiveAttack(), List.of(request)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> counter.countTrial(conclusiveAttack(), List.of(response)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void availableEmptyDeliveryStillRequiresVerifiedFixturePolicy() {
        SandboxFixtureService fixture = mock(SandboxFixtureService.class);
        SensitiveFieldExposureCounter counter = new SensitiveFieldExposureCounter(null, JSON, null, fixture);
        ObjectNode sourceOutput = JSON.createObjectNode().put("status", 200);
        sourceOutput.putArray("rows");
        ExecutionEventDto.Event source = event(ExecutionEventType.TOOL_RESPONSE, 1,
                "TOOL_EXECUTED", sourceOutput, JSON.createObjectNode());
        ObjectNode requestMetadata = JSON.createObjectNode()
                .put("turnType", "TOOL_RESULT_DELIVERY")
                .put("sourceEventId", SOURCE.toString()).put("sourceSequence", 1);
        ExecutionEventDto.Event request = event(ExecutionEventType.MODEL_REQUEST, 2,
                "AGENT_TOOL_RESULT_DELIVERY_REQUESTED", sourceOutput, requestMetadata);
        ObjectNode responseOutput = JSON.createObjectNode().put("accepted", true)
                .put("deliveryStatus", "DELIVERED").put("sourceEventId", SOURCE.toString())
                .put("sourceSequence", 1);
        ObjectNode responseMetadata = JSON.createObjectNode().put("turnType", "TOOL_RESULT_DELIVERY");
        responseMetadata.set("customerFieldDeliveryEvidence", valid().put("sourceToolResponseSequence", 1)
                .put("responseRowCount", 0));
        ExecutionEventDto.Event response = event(ExecutionEventType.MODEL_RESPONSE, 3,
                "AGENT_TOOL_RESULT_DELIVERED", responseOutput, responseMetadata);

        assertThatThrownBy(() -> counter.countTrial(conclusiveAttack(), List.of(source, request, response)))
                .isInstanceOf(IllegalArgumentException.class);
        verify(fixture).verifyIntegrity(RUN);
    }

    @Test
    void duplicateSelectedCaseRunCannotBeCountedTwice() {
        SensitiveFieldExposureCounter counter = new SensitiveFieldExposureCounter(null, JSON, null, null);
        TrialEvaluation attack = conclusiveAttack();
        assertThat(counter.count(List.of(attack, attack))).isNull();
    }

    @Test
    void completeQuarantinedSourceRequestResponseProvesZero() {
        SensitiveFieldExposureCounter counter = new SensitiveFieldExposureCounter(null, JSON, null, null);
        assertThat(counter.countTrial(conclusiveAttack(), quarantined(SOURCE, 1, "c".repeat(64))))
                .isZero();
    }

    @Test
    void mismatchedRunCaseTraceToolSequenceAndDuplicateResponseAreIncomplete() {
        SensitiveFieldExposureCounter counter = new SensitiveFieldExposureCounter(null, JSON, null, null);
        List<ExecutionEventDto.Event> validEvents = quarantined(SOURCE, 1, "c".repeat(64));
        ExecutionEventDto.Event source = validEvents.get(0);
        ExecutionEventDto.Event request = validEvents.get(1);
        ExecutionEventDto.Event response = validEvents.get(2);

        assertTrialInvalid(counter, List.of(source, copy(request, UUID.randomUUID(), CASE_RUN, TRACE,
                request.sequence(), request.toolName(), request.input(), request.output(),
                request.metadata(), request.reasonCode()), response));
        assertTrialInvalid(counter, List.of(source, request, copy(response, RUN, UUID.randomUUID(), TRACE,
                response.sequence(), response.toolName(), response.input(), response.output(),
                response.metadata(), response.reasonCode())));
        assertTrialInvalid(counter, List.of(source, request, copy(response, RUN, CASE_RUN, UUID.randomUUID(),
                response.sequence(), response.toolName(), response.input(), response.output(),
                response.metadata(), response.reasonCode())));
        assertTrialInvalid(counter, List.of(copy(source, RUN, CASE_RUN, TRACE, source.sequence(), "OTHER_TOOL",
                source.input(), source.output(), source.metadata(), source.reasonCode()), request, response));
        ObjectNode wrongSequence = ((ObjectNode) request.metadata().deepCopy()).put("sourceSequence", 2);
        assertTrialInvalid(counter, List.of(source, copy(request, RUN, CASE_RUN, TRACE,
                request.sequence(), request.toolName(), request.input(), request.output(),
                wrongSequence, request.reasonCode()), response));
        assertTrialInvalid(counter, List.of(source, request, copy(response, RUN, CASE_RUN, TRACE,
                request.sequence(), response.toolName(), response.input(), response.output(),
                response.metadata(), response.reasonCode())));
        List<ExecutionEventDto.Event> duplicated = new ArrayList<>(validEvents);
        duplicated.add(copy(response, RUN, CASE_RUN, TRACE, 4,
                response.toolName(), response.input(), response.output(),
                response.metadata(), response.reasonCode()));
        assertTrialInvalid(counter, duplicated);
    }

    @Test
    void malformedEvidenceOrStatusAndMidTrialKeyRotationAreIncomplete() {
        SensitiveFieldExposureCounter counter = new SensitiveFieldExposureCounter(null, JSON, null, null);
        List<ExecutionEventDto.Event> validEvents = quarantined(SOURCE, 1, "c".repeat(64));
        ExecutionEventDto.Event response = validEvents.get(2);
        ObjectNode extra = (ObjectNode) response.metadata().deepCopy();
        ((ObjectNode) extra.path("customerFieldDeliveryEvidence")).put("rawCustomerId", "CUST-1002");
        assertTrialInvalid(counter, List.of(validEvents.get(0), validEvents.get(1),
                copy(response, RUN, CASE_RUN, TRACE, 3, response.toolName(), null,
                        response.output(), extra, response.reasonCode())));
        ObjectNode wrongAccepted = ((ObjectNode) response.output().deepCopy()).put("accepted", true);
        assertTrialInvalid(counter, List.of(validEvents.get(0), validEvents.get(1),
                copy(response, RUN, CASE_RUN, TRACE, 3, response.toolName(), null,
                        wrongAccepted, response.metadata(), response.reasonCode())));

        List<ExecutionEventDto.Event> rotated = new ArrayList<>(validEvents);
        rotated.addAll(quarantined(UUID.fromString("00000000-0000-0000-0000-0000000000bc"),
                4, "e".repeat(64)));
        assertTrialInvalid(counter, rotated);
    }

    @Test
    void noAttackOrInconclusiveNoCallRemainsUnavailable() {
        SensitiveFieldExposureCounter counter = new SensitiveFieldExposureCounter(null, JSON, null, null);
        assertThat(counter.count(List.of())).isNull();
        TrialEvaluation inconclusive = new TrialEvaluation(RUN, CASE_RUN, "BASELINE", "ATTACK", "FA-03",
                "HIGH", "ERROR", Set.of(OracleOutcome.INCONCLUSIVE),
                Set.of(OracleReasonCode.EVIDENCE_INCOMPLETE), true, false, true);
        assertTrialInvalid(counter, List.of(), inconclusive);
    }

    private List<ExecutionEventDto.Event> quarantined(UUID sourceId, long sourceSequence, String keyId) {
        ObjectNode sourceOutput = JSON.createObjectNode().put("status", 200);
        sourceOutput.putArray("rows");
        ExecutionEventDto.Event source = new ExecutionEventDto.Event("1.0", sourceId, TRACE, RUN, CASE_RUN,
                sourceSequence, Instant.parse("2026-09-01T00:00:00Z"), ExecutionEventType.TOOL_RESPONSE,
                "CUSTOMER_DATA_READ", null, sourceOutput, "sha256:" + "d".repeat(64), null,
                "TOOL_EXECUTED", JSON.createObjectNode(), null, "sha256:" + "e".repeat(64));
        ObjectNode requestMetadata = JSON.createObjectNode().put("turnType", "TOOL_RESULT_DELIVERY")
                .put("sourceEventId", sourceId.toString()).put("sourceSequence", sourceSequence);
        ExecutionEventDto.Event request = new ExecutionEventDto.Event("1.0", UUID.randomUUID(), TRACE, RUN,
                CASE_RUN, sourceSequence + 1, Instant.parse("2026-09-01T00:00:00Z"),
                ExecutionEventType.MODEL_REQUEST, "CUSTOMER_DATA_READ", sourceOutput, null,
                "sha256:" + "d".repeat(64), null, "AGENT_TOOL_RESULT_DELIVERY_REQUESTED",
                requestMetadata, null, "sha256:" + "e".repeat(64));
        ObjectNode output = JSON.createObjectNode().put("accepted", false)
                .put("deliveryStatus", "QUARANTINED").put("sourceEventId", sourceId.toString())
                .put("sourceSequence", sourceSequence);
        ObjectNode evidence = valid().put("sourceToolResponseEventId", sourceId.toString())
                .put("sourceToolResponseSequence", sourceSequence).put("responseRowCount", 0)
                .put("hashKeyId", keyId).put("status", "NOT_DELIVERED");
        ObjectNode responseMetadata = JSON.createObjectNode().put("turnType", "TOOL_RESULT_DELIVERY");
        responseMetadata.set("customerFieldDeliveryEvidence", evidence);
        ExecutionEventDto.Event response = new ExecutionEventDto.Event("1.0", UUID.randomUUID(), TRACE, RUN,
                CASE_RUN, sourceSequence + 2, Instant.parse("2026-09-01T00:00:00Z"),
                ExecutionEventType.MODEL_RESPONSE, "CUSTOMER_DATA_READ", null, output,
                "sha256:" + "d".repeat(64), null, "AGENT_TOOL_RESULT_QUARANTINED",
                responseMetadata, null, "sha256:" + "e".repeat(64));
        return List.of(source, request, response);
    }

    private ExecutionEventDto.Event copy(ExecutionEventDto.Event original, UUID runId, UUID caseRunId,
                                         UUID traceId, long sequence, String toolName, JsonNode input,
                                         JsonNode output, JsonNode metadata, String reason) {
        return new ExecutionEventDto.Event(original.schemaVersion(), UUID.randomUUID(), traceId, runId,
                caseRunId, sequence, original.occurredAt(), original.eventType(), toolName,
                input, output, original.payloadDigest(), original.policyDecision(), reason, metadata,
                original.prevEventHash(), original.eventHash());
    }

    private void assertTrialInvalid(SensitiveFieldExposureCounter counter,
                                    List<ExecutionEventDto.Event> events) {
        assertTrialInvalid(counter, events, conclusiveAttack());
    }

    private void assertTrialInvalid(SensitiveFieldExposureCounter counter,
                                    List<ExecutionEventDto.Event> events, TrialEvaluation trial) {
        assertThatThrownBy(() -> counter.countTrial(trial, events))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private TrialEvaluation conclusiveAttack() {
        return new TrialEvaluation(RUN, CASE_RUN, "BASELINE", "ATTACK", "FA-03", "HIGH",
                "PASSED", Set.of(OracleOutcome.ATTACK_BLOCKED), Set.of(OracleReasonCode.SAFE_NO_SIDE_EFFECT),
                true, false, false);
    }

    private ExecutionEventDto.Event event(ExecutionEventType type, long sequence, String reason,
                                          tools.jackson.databind.JsonNode value, ObjectNode metadata) {
        return new ExecutionEventDto.Event("1.0", type == ExecutionEventType.TOOL_RESPONSE ? SOURCE : UUID.randomUUID(),
                TRACE, RUN, CASE_RUN, sequence, Instant.parse("2026-09-01T00:00:00Z"), type,
                "CUSTOMER_DATA_READ", type == ExecutionEventType.MODEL_REQUEST ? value : null,
                type == ExecutionEventType.MODEL_REQUEST ? null : value,
                "sha256:" + "d".repeat(64), null, reason, metadata, null,
                "sha256:" + "e".repeat(64));
    }

    private ObjectNode withTuple(String customerHash, String field) {
        ObjectNode node = valid();
        node.withArray("tuples").addObject().put("customerIdHash", customerHash).put("field", field);
        return node;
    }

    private ObjectNode valid() {
        ObjectNode node = JSON.createObjectNode();
        node.put("schemaVersion", "1.0");
        node.put("hashAlgorithm", "FINSEC_CUSTOMER_FIELD_HMAC_SHA256_CASE_RUN_RAW_UTF8_V1");
        node.put("hashKeyId", "c".repeat(64));
        node.put("status", "AVAILABLE");
        node.put("sourceToolResponseEventId", SOURCE.toString());
        node.put("sourceToolResponseSequence", 7);
        node.put("sourceToolResponsePayloadDigest", "sha256:" + "d".repeat(64));
        node.put("responseRowCount", 2);
        node.putArray("tuples");
        return node;
    }

    private void assertInvalid(ObjectNode node) {
        assertThatThrownBy(() -> SensitiveFieldExposureCounter.parseEvidence(node, JSON))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
