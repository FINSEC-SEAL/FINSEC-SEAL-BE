package com.finsecseal.evidence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

class RedactionServiceTest {

    private ObjectMapper objectMapper;
    private CanonicalJsonService canonicalJsonService;
    private DigestService digestService;
    private RedactionService redactionService;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        canonicalJsonService = new CanonicalJsonService(objectMapper);
        digestService = new DigestService();
        redactionService = new RedactionService(
                objectMapper,
                canonicalJsonService,
                digestService,
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
    }

    @Test
    void tokenizesSyntheticIdsAndRedactsClassifiedValues() {
        ObjectNode raw = objectMapper.createObjectNode();
        raw.put("customerId", "customer-1001");
        raw.put("email", "borrower@example.test");
        raw.put("account_number", "123-456");
        raw.put("creditScore", 720);

        RedactionService.Result result = redactionService.redact(raw);

        assertThat(result.redacted().path("customerId").asString()).startsWith("[SYNTH_ID:");
        assertThat(result.redacted().path("email").asString()).isEqualTo("[REDACTED:SENSITIVE_PII]");
        assertThat(result.redacted().path("account_number").asString()).isEqualTo("[REDACTED:FINANCIAL]");
        assertThat(result.redacted().path("creditScore").asString()).isEqualTo("[REDACTED:CREDIT]");
        assertThat(result.originalDigest())
                .isEqualTo(digestService.sha256(canonicalJsonService.canonicalize(raw)));
    }

    @Test
    void normalizedEquivalentSyntheticIdsReceiveTheSameToken() {
        ObjectNode decomposed = objectMapper.createObjectNode().put("customerId", "cafe\u0301");
        ObjectNode composed = objectMapper.createObjectNode().put("customerId", "café");

        assertThat(redactionService.redact(decomposed).redacted().path("customerId"))
                .isEqualTo(redactionService.redact(composed).redacted().path("customerId"));
    }

    @Test
    void preservesAlreadyTokenizedSyntheticIds() {
        ObjectNode alreadyRedacted = objectMapper.createObjectNode()
                .put("customerId", "[SYNTH_ID:012345abcdef]");

        assertThat(redactionService.redact(alreadyRedacted).redacted())
                .isEqualTo(alreadyRedacted);
    }

    @Test
    void rejectsSecretFieldsAndSecretLikeValuesBeforePersistence() {
        ObjectNode secretField = objectMapper.createObjectNode().put("clientSecret", "canary-value");
        ObjectNode secretValue = objectMapper.createObjectNode()
                .put("note", "Bearer abcdefghijklmnopqrstuvwxyz.123");

        assertSecretDetected(secretField);
        assertSecretDetected(secretValue);
    }

    private void assertSecretDetected(ObjectNode value) {
        assertThatThrownBy(() -> redactionService.redact(value))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.SECRET_DETECTED));
    }
}
