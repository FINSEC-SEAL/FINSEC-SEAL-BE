package com.finsecseal.attack;

import com.finsecseal.release.DigestService;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/** Validates untrusted wording candidates; acceptance is not persistence or attack execution. */
@Component
public final class AttackMutationCandidateValidator {

    public static final int MAX_PAYLOAD_BYTES = 4_096;
    public static final int MAX_CANDIDATE_BYTES = 8_192;
    public static final int MAX_BATCH_BYTES = 65_536;
    public static final int MAX_BATCH_SIZE = 20;

    private static final String MOCK_URI = "https://mock-exfil.invalid/collect";
    private static final Set<String> FIELDS = Set.of(
            "parentSeedId", "category", "severity", "targetTool", "expectedInvariant",
            "oracleType", "deliveryChannel", "payload", "insertionLocation");
    private static final Set<String> DOCUMENT_LOCATIONS = Set.of("BODY", "FOOTNOTE", "TABLE", "QUOTE");
    private static final Pattern WHITESPACE = Pattern.compile("(?U)\\s+");
    private static final Pattern URL_LIKE = Pattern.compile(
            "(?i)(?:\\b[a-z][a-z0-9+.-]{1,20}\\s*(?::|%3a|&#58;)|//|%2f%2f|www\\.|"
                    + "\\b[a-z0-9_-]+(?:\\.[a-z0-9_-]+)+\\.[a-z]{2,24}\\b|"
                    + "\\\\u[0-9a-f]{4}|%[0-9a-f]{2}|&#[0-9]{2,};)");
    private static final Pattern EMAIL = Pattern.compile("(?i)\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b");
    private static final Pattern RESIDENT_NUMBER = Pattern.compile("\\b\\d{6}[- ]?[1-4]\\d{6}\\b");
    private static final Pattern PHONE = Pattern.compile("\\b01[016789][- ]?\\d{3,4}[- ]?\\d{4}\\b");
    private static final Pattern LONG_DIGITS = Pattern.compile("(?<![A-Za-z])(?:\\d[ -]?){10,}(?![A-Za-z])");
    private static final Pattern SECRET = Pattern.compile(
            "(?i)(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\\bBearer\\s+[A-Za-z0-9._~+/-]{8,}|"
                    + "\\bsk-[A-Za-z0-9_-]{16,}|\\bAKIA[0-9A-Z]{16}\\b|"
                    + "\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b)");

    private static final ObjectMapper CANDIDATE_MAPPER = JsonMapper.builder(JsonFactory.builder()
                    .streamReadConstraints(StreamReadConstraints.builder()
                            .maxNestingDepth(2)
                            .maxStringLength(MAX_PAYLOAD_BYTES)
                            .maxNameLength(64)
                            .maxNumberLength(16)
                            .maxTokenCount(32)
                            .build())
                    .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                    .disable(StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION)
                    .build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY)
            .build();

    private final DigestService digestService;

    public AttackMutationCandidateValidator(DigestService digestService) {
        this.digestService = Objects.requireNonNull(digestService);
    }

    public List<ValidatedCandidate> validateBatch(TrustedSeed seed, List<byte[]> rawCandidates) {
        if (seed == null || rawCandidates == null || rawCandidates.isEmpty()
                || rawCandidates.size() > MAX_BATCH_SIZE) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
        int totalBytes = 0;
        for (byte[] raw : rawCandidates) {
            if (raw == null || raw.length == 0 || raw.length > MAX_CANDIDATE_BYTES
                    || totalBytes > MAX_BATCH_BYTES - raw.length) {
                throw failure(FailureCode.CANDIDATE_TOO_LARGE);
            }
            totalBytes += raw.length;
        }
        if (!"DOCUMENT_CONTENT".equals(seed.deliveryChannel())) {
            throw failure(FailureCode.UNSUPPORTED_DELIVERY);
        }

        String parentHash = normalizedHash(seed.parentDocumentPayload());
        Set<String> seen = new HashSet<>();
        List<ValidatedCandidate> accepted = new ArrayList<>(rawCandidates.size());
        for (byte[] raw : rawCandidates) {
            JsonNode node = parse(raw);
            String payload = validateIdentityAndPayloadType(seed, node);
            String location = boundedString(node, "insertionLocation", 16);
            if (!DOCUMENT_LOCATIONS.contains(location)) {
                throw failure(FailureCode.UNSUPPORTED_DELIVERY);
            }
            int length = utf8Length(payload);
            if (length < 1 || length > MAX_PAYLOAD_BYTES || normalized(payload).isEmpty()) {
                throw failure(FailureCode.UNSAFE_PAYLOAD);
            }
            rejectUnsafePayload(payload);
            String hash = normalizedHash(payload);
            if (parentHash.equals(hash) || !seen.add(hash)) {
                throw failure(FailureCode.DUPLICATE_PAYLOAD);
            }
            accepted.add(new ValidatedCandidate(payload, location, hash));
        }
        return List.copyOf(accepted);
    }

    private static JsonNode parse(byte[] raw) {
        try {
            String text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(raw)).toString();
            JsonNode node = CANDIDATE_MAPPER.readTree(text);
            if (node == null || !node.isObject() || node.size() != FIELDS.size()
                    || node.properties().stream().anyMatch(entry -> !FIELDS.contains(entry.getKey()))) {
                throw failure(FailureCode.MALFORMED_CANDIDATE);
            }
            return node;
        } catch (CharacterCodingException | RuntimeException exception) {
            // Never attach parser diagnostics: they may contain the candidate payload.
            throw failure(FailureCode.MALFORMED_CANDIDATE);
        }
    }

    private static String validateIdentityAndPayloadType(TrustedSeed seed, JsonNode node) {
        String parent = boundedString(node, "parentSeedId", 36);
        if (!seed.parentSeedId().toString().equals(parent)
                || !seed.category().equals(boundedString(node, "category", 80))
                || !seed.severity().equals(boundedString(node, "severity", 20))
                || !seed.targetTool().equals(boundedString(node, "targetTool", 100))
                || !seed.expectedInvariant().equals(boundedString(node, "expectedInvariant", 200))
                || !seed.oracleType().equals(boundedString(node, "oracleType", 80))
                || !seed.deliveryChannel().equals(boundedString(node, "deliveryChannel", 40))) {
            throw failure(FailureCode.IDENTITY_MISMATCH);
        }
        return boundedString(node, "payload", MAX_PAYLOAD_BYTES);
    }

    private static String boundedString(JsonNode node, String field, int maxLength) {
        JsonNode value = node.path(field);
        if (!value.isString() || value.stringValue().isEmpty()
                || value.stringValue().length() > maxLength) {
            throw failure(FailureCode.MALFORMED_CANDIDATE);
        }
        return value.stringValue();
    }

    private static void rejectUnsafePayload(String payload) {
        String withoutMock = removeExactMockUriTokens(payload);
        String normalizedDetectionView = Normalizer.normalize(withoutMock, Normalizer.Form.NFKC);
        if (unsafeText(withoutMock) || unsafeText(normalizedDetectionView)) {
            throw failure(FailureCode.UNSAFE_PAYLOAD);
        }
    }

    private static String removeExactMockUriTokens(String payload) {
        StringBuilder remaining = new StringBuilder(payload.length());
        int cursor = 0;
        int start;
        while ((start = payload.indexOf(MOCK_URI, cursor)) >= 0) {
            int after = start + MOCK_URI.length();
            // A literal mock URI is exempt only as an entire whitespace-delimited token.
            if ((start > 0 && !Character.isWhitespace(payload.charAt(start - 1)))
                    || (after < payload.length() && !Character.isWhitespace(payload.charAt(after)))) {
                throw failure(FailureCode.UNSAFE_PAYLOAD);
            }
            remaining.append(payload, cursor, start).append(' ');
            cursor = after;
        }
        return remaining.append(payload, cursor, payload.length()).toString();
    }

    private static boolean unsafeText(String text) {
        return URL_LIKE.matcher(text).find() || EMAIL.matcher(text).find()
                || RESIDENT_NUMBER.matcher(text).find() || PHONE.matcher(text).find()
                || LONG_DIGITS.matcher(text).find() || SECRET.matcher(text).find();
    }

    private String normalizedHash(String payload) {
        return digestService.sha256(normalized(payload));
    }

    private static String normalized(String payload) {
        return WHITESPACE.matcher(Normalizer.normalize(payload, Normalizer.Form.NFKC)
                .strip()).replaceAll(" ").toLowerCase(Locale.ROOT);
    }

    private static int utf8Length(String value) {
        try {
            return StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(value)).remaining();
        } catch (CharacterCodingException exception) {
            throw failure(FailureCode.UNSAFE_PAYLOAD);
        }
    }

    private static void requireIdentity(String value, int maxLength) {
        if (value == null || value.isBlank() || value.length() > maxLength) {
            throw failure(FailureCode.INVALID_TRUSTED_SEED);
        }
    }

    public record TrustedSeed(UUID parentSeedId, String category, String severity, String targetTool,
            String expectedInvariant, String oracleType, String deliveryChannel,
            String parentDocumentPayload) {
        public TrustedSeed {
            if (parentSeedId == null) {
                throw failure(FailureCode.INVALID_TRUSTED_SEED);
            }
            requireIdentity(category, 80);
            requireIdentity(severity, 20);
            requireIdentity(targetTool, 100);
            requireIdentity(expectedInvariant, 200);
            requireIdentity(oracleType, 80);
            requireIdentity(deliveryChannel, 40);
            if (parentDocumentPayload == null || utf8Length(parentDocumentPayload) < 1
                    || utf8Length(parentDocumentPayload) > MAX_PAYLOAD_BYTES) {
                throw failure(FailureCode.INVALID_TRUSTED_SEED);
            }
        }

        @Override
        public String toString() {
            return "TrustedSeed[redacted]";
        }
    }

    public record ValidatedCandidate(String payload, String insertionLocation,
            String normalizedPayloadHash) {
        @Override
        public String toString() {
            return "ValidatedCandidate[redacted]";
        }
    }

    public enum FailureCode {
        INVALID_REQUEST, INVALID_TRUSTED_SEED, CANDIDATE_TOO_LARGE,
        MALFORMED_CANDIDATE, IDENTITY_MISMATCH, UNSUPPORTED_DELIVERY,
        UNSAFE_PAYLOAD, DUPLICATE_PAYLOAD
    }

    public static final class ValidationException extends RuntimeException {
        private final FailureCode code;

        private ValidationException(FailureCode code) {
            super("Attack mutation candidate rejected: " + code.name(), null, false, true);
            this.code = code;
        }

        public FailureCode code() {
            return code;
        }
    }

    private static ValidationException failure(FailureCode code) {
        return new ValidationException(code);
    }
}
