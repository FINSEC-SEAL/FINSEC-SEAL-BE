package com.finsecseal.evidence;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.text.Normalizer;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;
import tools.jackson.databind.node.StringNode;

@Service
public class RedactionService {

    private static final Set<String> SECRET_FIELDS = Set.of(
            "password", "passwd", "secret", "apikey", "api_key", "accesstoken", "access_token",
            "refreshtoken", "refresh_token", "authorization", "cookie", "privatekey", "private_key",
            "clientsecret", "client_secret", "signingkey", "signing_key", "databasepassword",
            "database_password"
    );
    private static final Set<String> SYNTHETIC_ID_FIELDS = Set.of(
            "customerid", "customer_id", "customerids", "customer_ids", "customerkey", "customer_key",
            "applicantid", "applicant_id", "caseid", "case_id", "documentid", "document_id",
            "documentids", "document_ids"
    );
    private static final Set<String> SENSITIVE_PII_FIELDS = Set.of(
            "residentregistrationnumber", "resident_registration_number", "ssn", "email", "phone",
            "phonenumber", "phone_number", "address", "birthdate", "birth_date"
    );
    private static final Set<String> FINANCIAL_FIELDS = Set.of(
            "accountnumber", "account_number", "cardnumber", "card_number", "routingnumber",
            "routing_number", "iban"
    );
    private static final Set<String> CREDIT_FIELDS = Set.of(
            "creditscore", "credit_score", "creditreport", "credit_report"
    );
    private static final Pattern SECRET_VALUE = Pattern.compile(
            "(?is).*(-----BEGIN [A-Z ]*PRIVATE KEY-----|\\bBearer\\s+[A-Za-z0-9._~+\\-/]+=*"
                    + "|\\bsk-[A-Za-z0-9_-]{16,}|\\bAKIA[0-9A-Z]{16}\\b"
                    + "|\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b).*"
    );

    private final ObjectMapper objectMapper;
    private final CanonicalJsonService canonicalJsonService;
    private final DigestService digestService;
    private final byte[] tokenKey;

    public RedactionService(
            ObjectMapper objectMapper,
            CanonicalJsonService canonicalJsonService,
            DigestService digestService,
            @Value("${finsec.crypto.key-base64}") String encryptionKeyBase64
    ) {
        this.objectMapper = objectMapper;
        this.canonicalJsonService = canonicalJsonService;
        this.digestService = digestService;
        try {
            byte[] encryptionKey = Base64.getDecoder().decode(encryptionKeyBase64);
            if (encryptionKey.length != 32) {
                throw new IllegalArgumentException("FINSEC_DATA_ENCRYPTION_KEY_BASE64 must decode to 32 bytes");
            }
            MessageDigest derivation = MessageDigest.getInstance("SHA-256");
            derivation.update("finsec-seal/redaction-token/v1\n".getBytes(StandardCharsets.UTF_8));
            this.tokenKey = derivation.digest(encryptionKey);
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new IllegalStateException("Redaction token key configuration is invalid", exception);
        }
    }

    public Result redact(JsonNode raw) {
        JsonNode safeRaw = raw == null ? objectMapper.nullNode() : raw;
        rejectSecrets(safeRaw, null);
        String digest = digestService.sha256(canonicalJsonService.canonicalize(safeRaw));
        return new Result(redactNode(safeRaw, null), digest);
    }

    private void rejectSecrets(JsonNode value, String fieldName) {
        if (fieldName != null && SECRET_FIELDS.contains(normalizeField(fieldName)) && !value.isNull()) {
            throw secretDetected();
        }
        if (value.isString() && SECRET_VALUE.matcher(value.asString()).matches()) {
            throw secretDetected();
        }
        if (value.isObject()) {
            value.properties().forEach(entry -> rejectSecrets(entry.getValue(), entry.getKey()));
        } else if (value.isArray()) {
            value.forEach(item -> rejectSecrets(item, fieldName));
        }
    }

    private JsonNode redactNode(JsonNode value, String fieldName) {
        String normalized = fieldName == null ? "" : normalizeField(fieldName);
        if (SYNTHETIC_ID_FIELDS.contains(normalized)) {
            return tokenize(value);
        }
        if (SENSITIVE_PII_FIELDS.contains(normalized)) {
            return StringNode.valueOf("[REDACTED:SENSITIVE_PII]");
        }
        if (FINANCIAL_FIELDS.contains(normalized)) {
            return StringNode.valueOf("[REDACTED:FINANCIAL]");
        }
        if (CREDIT_FIELDS.contains(normalized)) {
            return StringNode.valueOf("[REDACTED:CREDIT]");
        }
        if (value.isObject()) {
            ObjectNode redacted = objectMapper.createObjectNode();
            value.properties().forEach(entry -> redacted.set(
                    entry.getKey(),
                    redactNode(entry.getValue(), entry.getKey())
            ));
            return redacted;
        }
        if (value.isArray()) {
            ArrayNode redacted = objectMapper.createArrayNode();
            value.forEach(item -> redacted.add(redactNode(item, fieldName)));
            return redacted;
        }
        return value.deepCopy();
    }

    private JsonNode tokenize(JsonNode value) {
        if (value.isArray()) {
            ArrayNode tokens = objectMapper.createArrayNode();
            value.forEach(item -> tokens.add(tokenize(item)));
            return tokens;
        }
        if (value.isNull()) {
            return value.deepCopy();
        }
        return StringNode.valueOf("[SYNTH_ID:" + hmac(value.asString()) + "]");
    }

    private String hmac(String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(tokenKey, "HmacSHA256"));
            String normalized = Normalizer.normalize(
                    value.replace("\r\n", "\n").replace('\r', '\n'),
                    Normalizer.Form.NFC
            );
            byte[] digest = mac.doFinal(normalized.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest, 0, 6);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("HMAC-SHA256 is unavailable", exception);
        }
    }

    private String normalizeField(String field) {
        return field.replace("-", "_").toLowerCase(Locale.ROOT);
    }

    private BusinessException secretDetected() {
        return new BusinessException(
                ErrorCode.SECRET_DETECTED,
                "Secret-like data is not permitted in event or evidence payloads"
        );
    }

    public record Result(JsonNode redacted, String originalDigest) {
    }
}
