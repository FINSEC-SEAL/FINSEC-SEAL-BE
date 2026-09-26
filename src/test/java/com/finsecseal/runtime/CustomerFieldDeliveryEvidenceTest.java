package com.finsecseal.runtime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.finsecseal.attack.AttackVariant;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.evidence.RedactionService;
import com.finsecseal.runtime.ai.AgentAiClient;
import com.finsecseal.sandbox.SandboxExecutionContext;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.BinaryNode;
import tools.jackson.databind.node.ObjectNode;
import tools.jackson.databind.node.POJONode;

class CustomerFieldDeliveryEvidenceTest {

    private static final UUID RUN_ID = UUID.fromString("00000000-0000-0000-0000-000000000010");
    private static final UUID CASE_RUN_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID TRACE_ID = UUID.fromString("00000000-0000-0000-0000-000000000020");
    private static final UUID SOURCE_ID = UUID.fromString("00000000-0000-0000-0000-000000000030");
    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void keyedKnownAnswersAndRotationProduceOnlyPseudonymousMetadata() {
        ObjectNode output = output();
        JsonNode metadata = evidence(testKey()).capture(CASE_RUN_ID, source(output), output)
                .metadata(true);
        assertThat(metadata.size()).isEqualTo(9);
        assertThat(metadata.path("schemaVersion").asString()).isEqualTo("1.0");
        assertThat(metadata.path("hashAlgorithm").asString())
                .isEqualTo(CustomerFieldDeliveryEvidence.HASH_ALGORITHM);
        assertThat(metadata.path("hashKeyId").asString())
                .isEqualTo("f99be6d6ea5112f037df711d39e96ddaf6373b948187dd7a058ed5c0d64eeab3");
        assertThat(metadata.path("status").asString()).isEqualTo("AVAILABLE");
        assertThat(metadata.path("sourceToolResponseEventId").asString())
                .isEqualTo(SOURCE_ID.toString());
        assertThat(metadata.path("sourceToolResponseSequence").asLong()).isEqualTo(1L);
        assertThat(metadata.path("sourceToolResponsePayloadDigest").asString())
                .isEqualTo("sha256:source");
        assertThat(metadata.path("responseRowCount").asInt()).isEqualTo(1);
        assertThat(metadata.path("tuples")).hasSize(1);
        assertThat(metadata.path("tuples").get(0).path("customerIdHash").asString())
                .isEqualTo("hmac-sha256:v1:15a90cce1be11ff37605173d195a98471f308d11bcccff560e4cc54b5af6441d");
        assertThat(metadata.path("tuples").get(0).path("field").asString())
                .isEqualTo("incomeBand");
        assertThat(metadata.toString()).doesNotContain("CUST-1001", "HIGH", testKey());

        JsonNode rotated = evidence(rotatedKey()).capture(CASE_RUN_ID, source(output), output)
                .metadata(true);
        assertThat(rotated.path("hashKeyId").asString())
                .isEqualTo("137832a37d559a0a05f959b4498e259673dea6699d4c7a4d8efbe4cd947c9592");
        assertThat(rotated.path("tuples").get(0).path("customerIdHash").asString())
                .isEqualTo("hmac-sha256:v1:71095e4041c1ed9db57a1b306e9f5aa7f0960336caca8edd774c172fadc320c9");
    }

    @Test
    void exactRawIdentityAndCaseRunScopeRemainDistinct() {
        CustomerFieldDeliveryEvidence evidence = evidence(testKey());
        assertThat(hash(evidence, "CUST-CAFÉ", CASE_RUN_ID))
                .isNotEqualTo(hash(evidence, "CUST-CAFE\u0301", CASE_RUN_ID));
        assertThat(hash(evidence, "CUST-1001\r\nX", CASE_RUN_ID))
                .isNotEqualTo(hash(evidence, "CUST-1001\nX", CASE_RUN_ID));
        assertThat(hash(evidence, "CUST-1001", CASE_RUN_ID))
                .isEqualTo(hash(evidence, "CUST-1001", CASE_RUN_ID))
                .isNotEqualTo(hash(evidence, "CUST-1001", RUN_ID));
        ObjectNode invalid = output();
        ((ObjectNode) invalid.path("rows").get(0)).put("customerId", "CUST-\ud800");
        BusinessException failure = catchThrowableOfType(
                () -> evidence.capture(CASE_RUN_ID, source(invalid), invalid),
                BusinessException.class);
        assertThat(failure.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE);
    }

    @Test
    void nullAndDuplicateRowsKeepDeliveredZeroAndDeduplicateNonNullTuples() {
        ObjectNode output = output();
        ObjectNode fields = (ObjectNode) output.path("rows").get(0).path("fields");
        fields.putNull("creditScore");
        output.withArray("rows").add(output.path("rows").get(0).deepCopy());
        CustomerFieldDeliveryEvidence.Capture capture =
                evidence(testKey()).capture(CASE_RUN_ID, source(output), output);
        JsonNode available = capture.metadata(true);
        assertThat(available.path("responseRowCount").asInt()).isEqualTo(2);
        assertThat(available.path("tuples")).hasSize(1);
        JsonNode quarantined = capture.metadata(false);
        assertThat(quarantined.path("status").asString()).isEqualTo("NOT_DELIVERED");
        assertThat(quarantined.path("tuples")).isEmpty();

        fields.putNull("incomeBand");
        ((ObjectNode) output.path("rows").get(1).path("fields")).putNull("incomeBand");
        JsonNode zero = evidence(testKey()).capture(CASE_RUN_ID, source(output), output)
                .metadata(true);
        assertThat(zero.path("status").asString()).isEqualTo("AVAILABLE");
        assertThat(zero.path("tuples")).isEmpty();
    }

    @Test
    void rejectsInvalidKeysAndBoundedShapes() {
        for (String key : new String[]{null, "bad-base64", Base64.getEncoder()
                .encodeToString(new byte[16])}) {
            BusinessException failure = catchThrowableOfType(
                    () -> evidence(key), BusinessException.class);
            assertThat(failure.errorCode()).isEqualTo(ErrorCode.CONFIGURATION_ERROR);
        }

        CustomerFieldDeliveryEvidence evidence = evidence(testKey());
        ObjectNode tooManyRows = output();
        while (tooManyRows.path("rows").size() <= 20) {
            tooManyRows.withArray("rows").add(output().path("rows").get(0).deepCopy());
        }
        assertIncomplete(evidence, tooManyRows);
        ObjectNode longId = output();
        ((ObjectNode) longId.path("rows").get(0)).put("customerId", "x".repeat(81));
        assertIncomplete(evidence, longId);
        ObjectNode longField = output();
        ((ObjectNode) longField.path("rows").get(0).path("fields"))
                .put("x".repeat(81), "value");
        assertIncomplete(evidence, longField);
        ObjectNode tooManyFields = output();
        ObjectNode fields = (ObjectNode) tooManyFields.path("rows").get(0).path("fields");
        for (int index = 0; index < 20; index++) fields.put("f" + index, index);
        assertIncomplete(evidence, tooManyFields);
    }

    @Test
    void acceptsMaximumTupleShapeAndRejectsOversizedMetadata() {
        ObjectNode maximum = JSON.createObjectNode().put("status", 200);
        for (int row = 0; row < 20; row++) {
            ObjectNode fields = maximum.withArray("rows").addObject()
                    .put("customerId", "CUST-" + row).putObject("fields");
            for (int field = 0; field < 20; field++) {
                fields.put("field" + field, "value");
            }
        }
        JsonNode metadata = evidence(testKey()).capture(CASE_RUN_ID, source(maximum), maximum)
                .metadata(true);
        assertThat(metadata.path("responseRowCount").asInt()).isEqualTo(20);
        assertThat(metadata.path("tuples")).hasSize(400);

        ObjectNode small = output();
        CustomerFieldDeliveryEvidence.Capture oversized = evidence(testKey()).capture(
                CASE_RUN_ID, source(small, "sha256:" + "a".repeat(256 * 1024)), small);
        BusinessException failure = catchThrowableOfType(
                () -> oversized.metadata(true), BusinessException.class);
        assertThat(failure.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE);
    }

    @Test
    void rejectsEmbeddedAndNestedFieldValuesAsIncompleteEvidence() {
        CustomerFieldDeliveryEvidence evidence = evidence(testKey());
        JsonNode[] invalidValues = {
                BinaryNode.valueOf(new byte[]{1, 2}),
                new POJONode("embedded"),
                JSON.createObjectNode().put("nested", "value"),
                JSON.createArrayNode().add("nested")
        };

        for (JsonNode invalidValue : invalidValues) {
            ObjectNode output = output();
            ((ObjectNode) output.path("rows").get(0).path("fields"))
                    .set("creditScore", invalidValue);

            BusinessException failure = catchThrowableOfType(
                    () -> evidence.capture(CASE_RUN_ID, source(output), output),
                    BusinessException.class);
            assertThat(failure.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE);
        }
    }

    @Test
    void rejectsEmbeddedFieldBeforeAnyAiDeliveryOrDeliveryRequest() {
        ObjectNode output = output();
        ((ObjectNode) output.path("rows").get(0).path("fields"))
                .set("creditScore", BinaryNode.valueOf(new byte[]{1, 2}));
        ExecutionEventService events = mock(ExecutionEventService.class);
        when(events.findById(SOURCE_ID)).thenReturn(source(output));
        RedactionService redaction = mock(RedactionService.class);
        when(redaction.redact(any())).thenReturn(
                new RedactionService.Result(output.deepCopy(), "sha256:source"));
        AgentAiClient ai = mock(AgentAiClient.class);
        @SuppressWarnings("unchecked")
        ObjectProvider<AgentAiClient> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(ai);
        AgentRuntimeService runtime = new AgentRuntimeService(
                provider, events, JSON, mock(ToolProposalValidator.class),
                new CustomerFieldDeliveryEvidence(redaction, JSON, testKey()));

        BusinessException failure = catchThrowableOfType(
                () -> runtime.deliverToolResult(context(), variant(), "CUSTOMER_DATA_READ",
                        output, SOURCE_ID, 1L, "role-b"),
                BusinessException.class);

        assertThat(failure.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE);
        verify(ai, never()).deliverToolResult(any());
        verify(events, never()).append(any(), any(), any());
    }

    @Test
    void rejectsSourceRedactionMismatchBeforeAnyAiDeliveryOrDeliveryRequest() {
        ObjectNode rawOutput = output();
        ObjectNode storedOutput = output();
        ((ObjectNode) storedOutput.path("rows").get(0).path("fields"))
                .put("incomeBand", "DIFFERENT");
        ExecutionEventService events = mock(ExecutionEventService.class);
        when(events.findById(SOURCE_ID)).thenReturn(source(storedOutput));
        RedactionService redaction = mock(RedactionService.class);
        when(redaction.redact(any())).thenReturn(
                new RedactionService.Result(rawOutput.deepCopy(), "sha256:raw"));
        AgentAiClient ai = mock(AgentAiClient.class);
        @SuppressWarnings("unchecked")
        ObjectProvider<AgentAiClient> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(ai);
        AgentRuntimeService runtime = new AgentRuntimeService(
                provider, events, JSON, mock(ToolProposalValidator.class),
                new CustomerFieldDeliveryEvidence(redaction, JSON, testKey()));

        BusinessException failure = catchThrowableOfType(
                () -> runtime.deliverToolResult(context(), variant(), "CUSTOMER_DATA_READ",
                        rawOutput, SOURCE_ID, 1L, "role-b"), BusinessException.class);

        assertThat(failure.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE);
        verify(ai, never()).deliverToolResult(any());
        verify(events, never()).append(any(), any(), any());
    }

    @Test
    void directFourArgumentConstructionFailsClosedBeforeAiCustomerDelivery() {
        AgentAiClient ai = mock(AgentAiClient.class);
        @SuppressWarnings("unchecked")
        ObjectProvider<AgentAiClient> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(ai);
        ExecutionEventService events = mock(ExecutionEventService.class);
        AgentRuntimeService runtime = new AgentRuntimeService(
                provider, events, JSON, mock(ToolProposalValidator.class));

        BusinessException failure = catchThrowableOfType(
                () -> runtime.deliverToolResult(context(), variant(), "CUSTOMER_DATA_READ",
                        output(), SOURCE_ID, 1L, "role-b"),
                BusinessException.class);

        assertThat(failure.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE);
        verify(ai, never()).deliverToolResult(any());
        verify(events, never()).append(any(), any(), any());
    }

    private static CustomerFieldDeliveryEvidence evidence(String key) {
        return new CustomerFieldDeliveryEvidence(mock(RedactionService.class), JSON, key);
    }

    private static String hash(CustomerFieldDeliveryEvidence evidence, String customerId,
            UUID caseRunId) {
        ObjectNode output = output();
        ((ObjectNode) output.path("rows").get(0)).put("customerId", customerId);
        return evidence.capture(caseRunId, source(output), output).metadata(true)
                .path("tuples").get(0).path("customerIdHash").asString();
    }

    private static void assertIncomplete(CustomerFieldDeliveryEvidence evidence, ObjectNode output) {
        BusinessException failure = catchThrowableOfType(
                () -> evidence.capture(CASE_RUN_ID, source(output), output),
                BusinessException.class);
        assertThat(failure.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE);
    }

    private static String testKey() {
        byte[] key = new byte[32];
        for (int index = 0; index < key.length; index++) key[index] = (byte) index;
        return Base64.getEncoder().encodeToString(key);
    }

    private static String rotatedKey() {
        byte[] key = new byte[32];
        for (int index = 0; index < key.length; index++) key[index] = (byte) (index + 1);
        return Base64.getEncoder().encodeToString(key);
    }

    private static ObjectNode output() {
        ObjectNode result = JSON.createObjectNode().put("status", 200);
        result.putArray("rows").addObject().put("customerId", "CUST-1001")
                .putObject("fields").put("incomeBand", "HIGH");
        return result;
    }

    private static ExecutionEventDto.Event source(JsonNode output) {
        return source(output, "sha256:source");
    }

    private static ExecutionEventDto.Event source(JsonNode output, String digest) {
        return new ExecutionEventDto.Event("1.0", SOURCE_ID, TRACE_ID, RUN_ID, CASE_RUN_ID,
                1L, Instant.parse("2026-09-01T00:00:00Z"), ExecutionEventType.TOOL_RESPONSE,
                "CUSTOMER_DATA_READ", null, output, digest, null,
                "TOOL_EXECUTED", JSON.createObjectNode(), "sha256:previous", "sha256:event");
    }

    private static SandboxExecutionContext context() {
        return new SandboxExecutionContext(RUN_ID, CASE_RUN_ID, TRACE_ID,
                TestRunMode.BASELINE, "CASE-1001", "CUST-1001");
    }

    private static AttackVariant variant() {
        return new AttackVariant("FA-03", "HIGH", "CUSTOMER_DATA_READ", "INV-02",
                "SENSITIVE_FIELD", JSON.createObjectNode(), "sha256:variant");
    }
}
