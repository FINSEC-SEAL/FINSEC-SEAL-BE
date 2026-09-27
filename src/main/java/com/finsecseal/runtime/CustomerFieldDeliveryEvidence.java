package com.finsecseal.runtime;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.RedactionService;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.TreeSet;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/** B-owned evidence for every completed CUSTOMER_DATA_READ delivery attempt. */
@Component
public final class CustomerFieldDeliveryEvidence {

    static final String HASH_ALGORITHM = "FINSEC_CUSTOMER_FIELD_HMAC_SHA256_CASE_RUN_RAW_UTF8_V1";
    private static final String SCHEMA_VERSION = "1.0";
    private static final String HASH_PREFIX = "hmac-sha256:v1:";
    private static final byte[] CASE_KEY_LABEL =
            "finsec-seal/customer-field-exposure/v1\n".getBytes(StandardCharsets.UTF_8);
    private static final byte[] KEY_ID_LABEL =
            "finsec-seal/customer-field-exposure/key-id/v1".getBytes(StandardCharsets.UTF_8);
    private static final int MAX_ROWS = 20;
    private static final int MAX_FIELDS_PER_ROW = 20;
    private static final int MAX_TEXT_LENGTH = 80;
    private static final int MAX_TUPLES = MAX_ROWS * MAX_FIELDS_PER_ROW;
    private static final int MAX_EVIDENCE_BYTES = 256 * 1024;

    private final RedactionService redactionService;
    private final ObjectMapper objectMapper;
    private final byte[] masterKey;
    private final String hashKeyId;

    public CustomerFieldDeliveryEvidence(
            RedactionService redactionService,
            ObjectMapper objectMapper,
            @Value("${finsec.crypto.key-base64}") String keyBase64
    ) {
        this.redactionService = redactionService;
        this.objectMapper = objectMapper;
        try {
            this.masterKey = Base64.getDecoder().decode(keyBase64);
        } catch (IllegalArgumentException | NullPointerException exception) {
            throw new BusinessException(ErrorCode.CONFIGURATION_ERROR,
                    "Customer delivery evidence requires a valid 32-byte key");
        }
        if (masterKey.length != 32) {
            throw new BusinessException(ErrorCode.CONFIGURATION_ERROR,
                    "Customer delivery evidence requires a valid 32-byte key");
        }
        this.hashKeyId = HexFormat.of().formatHex(hmac(masterKey, KEY_ID_LABEL));
    }

    public boolean matchesRedactedOutput(ExecutionEventDto.Event source, JsonNode rawOutput) {
        return source != null && source.output() != null && rawOutput != null
                && source.output().equals(redactionService.redact(rawOutput).redacted());
    }

    public Capture capture(UUID caseRunId, ExecutionEventDto.Event source, JsonNode rawOutput) {
        if (caseRunId == null || source == null || source.eventId() == null
                || source.sequence() <= 0 || source.payloadDigest() == null
                || rawOutput == null || !rawOutput.isObject()
                || rawOutput.size() != 2 || !rawOutput.path("status").isIntegralNumber()
                || rawOutput.path("status").asInt() != 200
                || !rawOutput.path("rows").isArray()) {
            throw incomplete();
        }
        JsonNode rows = rawOutput.path("rows");
        if (rows.size() > MAX_ROWS) throw incomplete();

        byte[] caseKey = caseKey(caseRunId);
        TreeSet<Tuple> tuples = new TreeSet<>(Comparator
                .comparing(Tuple::customerIdHash).thenComparing(Tuple::field));
        rows.forEach(row -> {
            if (!row.isObject() || row.size() != 2
                    || !row.path("customerId").isString()
                    || !validText(row.path("customerId").asString())
                    || !row.path("fields").isObject()
                    || row.path("fields").size() > MAX_FIELDS_PER_ROW) {
                throw incomplete();
            }
            String customerIdHash = HASH_PREFIX + HexFormat.of().formatHex(
                    hmac(caseKey, row.path("customerId").asString().getBytes(StandardCharsets.UTF_8)));
            row.path("fields").properties().forEach(entry -> {
                JsonNode value = entry.getValue();
                if (!validText(entry.getKey()) || value == null
                        || !(value.isNull() || value.isString()
                        || value.isNumber() || value.isBoolean())) {
                    throw incomplete();
                }
                if (!value.isNull()) {
                    tuples.add(new Tuple(customerIdHash, entry.getKey()));
                }
            });
        });
        if (tuples.size() > MAX_TUPLES) throw incomplete();
        return new Capture(source.eventId(), source.sequence(), source.payloadDigest(),
                rows.size(), List.copyOf(tuples));
    }

    private boolean validText(String value) {
        if (value == null || value.isBlank() || value.length() > MAX_TEXT_LENGTH) return false;
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (Character.isHighSurrogate(current)) {
                if (++index >= value.length() || !Character.isLowSurrogate(value.charAt(index))) {
                    return false;
                }
            } else if (Character.isLowSurrogate(current)) {
                return false;
            }
        }
        return true;
    }

    private byte[] caseKey(UUID caseRunId) {
        byte[] caseId = caseRunId.toString().getBytes(StandardCharsets.UTF_8);
        byte[] input = new byte[CASE_KEY_LABEL.length + caseId.length];
        System.arraycopy(CASE_KEY_LABEL, 0, input, 0, CASE_KEY_LABEL.length);
        System.arraycopy(caseId, 0, input, CASE_KEY_LABEL.length, caseId.length);
        return hmac(masterKey, input);
    }

    private byte[] hmac(byte[] key, byte[] input) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(input);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("HMAC-SHA256 is unavailable", exception);
        }
    }

    private BusinessException incomplete() {
        return new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE,
                "CUSTOMER_DATA_READ delivery evidence is incomplete");
    }

    public final class Capture {
        private final UUID sourceEventId;
        private final long sourceSequence;
        private final String sourcePayloadDigest;
        private final int responseRowCount;
        private final List<Tuple> tuples;

        private Capture(UUID sourceEventId, long sourceSequence, String sourcePayloadDigest,
                int responseRowCount, List<Tuple> tuples) {
            this.sourceEventId = sourceEventId;
            this.sourceSequence = sourceSequence;
            this.sourcePayloadDigest = sourcePayloadDigest;
            this.responseRowCount = responseRowCount;
            this.tuples = tuples;
        }

        public ObjectNode metadata(boolean delivered) {
            ObjectNode evidence = objectMapper.createObjectNode();
            evidence.put("schemaVersion", SCHEMA_VERSION);
            evidence.put("hashAlgorithm", HASH_ALGORITHM);
            evidence.put("hashKeyId", hashKeyId);
            evidence.put("status", delivered ? "AVAILABLE" : "NOT_DELIVERED");
            evidence.put("sourceToolResponseEventId", sourceEventId.toString());
            evidence.put("sourceToolResponseSequence", sourceSequence);
            evidence.put("sourceToolResponsePayloadDigest", sourcePayloadDigest);
            evidence.put("responseRowCount", responseRowCount);
            ArrayNode items = evidence.putArray("tuples");
            if (delivered) {
                tuples.forEach(tuple -> items.addObject()
                        .put("customerIdHash", tuple.customerIdHash())
                        .put("field", tuple.field()));
            }
            try {
                if (objectMapper.writeValueAsBytes(evidence).length > MAX_EVIDENCE_BYTES) {
                    throw incomplete();
                }
            } catch (BusinessException exception) {
                throw exception;
            } catch (Exception exception) {
                throw incomplete();
            }
            return evidence;
        }
    }

    private record Tuple(String customerIdHash, String field) {
    }
}
