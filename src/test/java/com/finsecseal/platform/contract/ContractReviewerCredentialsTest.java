package com.finsecseal.platform.contract;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

class ContractReviewerCredentialsTest {
    private static final String KEY = "test-reviewer-key-at-least-32-bytes-long";
    private final ObjectMapper json = new ObjectMapper();
    private final ContractReviewerCredentials credentials = new ContractReviewerCredentials(KEY, "reviewer",
            "0198f1e2-0000-7000-8000-000000000001", json);

    @Test void expirationScopeSignatureAndDuplicateCookiesAreEnforced() throws Exception {
        var session = credentials.issue();
        assertThat(credentials.session(request(session.token()))).isNotNull();
        assertThat(credentials.session(request(session.token() + "x"))).isNull();
        var duplicate = request(session.token());
        duplicate.setCookies(new Cookie(ContractReviewerCredentials.COOKIE, session.token()),
                new Cookie(ContractReviewerCredentials.COOKIE, session.token()));
        assertThat(credentials.session(duplicate)).isNull();
        ObjectNode payload = (ObjectNode) json.readTree(Base64.getUrlDecoder().decode(session.token().split("\\.")[0]));
        assertThat(credentials.session(request(sign(payload.deepCopy().put("expires", Instant.now().minusSeconds(1).getEpochSecond()))))).isNull();
        assertThat(credentials.session(request(sign(payload.deepCopy().put("workspace", "other"))))).isNull();
        assertThat(credentials.session(request(sign(payload.deepCopy().put("actor", "forged"))))).isNull();
        assertThat(new ContractReviewerCredentials("", "", "", json).session(request(session.token()))).isNull();
    }

    private MockHttpServletRequest request(String token) {
        var request = new MockHttpServletRequest();
        request.setCookies(new Cookie(ContractReviewerCredentials.COOKIE, token));
        return request;
    }

    private String sign(ObjectNode payload) throws Exception {
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(json.writeValueAsBytes(payload));
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return encoded + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(
                mac.doFinal(("FINSEC_REVIEWER_SESSION_V1:" + encoded).getBytes(StandardCharsets.UTF_8)));
    }
}
