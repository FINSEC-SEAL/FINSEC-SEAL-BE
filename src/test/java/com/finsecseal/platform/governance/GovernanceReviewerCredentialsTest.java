package com.finsecseal.platform.governance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import jakarta.servlet.http.Cookie;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Deque;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

class GovernanceReviewerCredentialsTest {
    private static final String BOOTSTRAP = "synthetic-governance-bootstrap-canary-32bytes";
    private static final String SIGNING = "synthetic-server-only-signing-canary-32bytes";
    private static final String ACTOR = "governance-reviewer";
    private static final String WORKSPACE = "0198f1e2-0000-7000-8000-000000000001";
    private static final String KNOWN_COOKIE_TRANSPORT_98 = "__Host-FINSEC_GOVERNANCE=eyJwdXJwb3NlIjoiRklOU0VDX0dPVkVSTkFOQ0VfU0VTU0lPTl9WMSIsInNlc3Npb25JZCI6I";
    private final ObjectMapper json = new ObjectMapper();
    private final MutableClock clock = new MutableClock();
    private final GovernanceReviewerCredentials issuer = issuer(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, "");

    @Test void issuedIdentityHasFixedAuthorityButCannotAuthorizeMutation() {
        var session = issue();
        var identity = session.identity();
        assertThat(identity.workspaceId().toString()).isEqualTo(WORKSPACE);
        assertThat(identity.actorId()).isEqualTo(ACTOR);
        assertThat(identity.role()).isEqualTo("AI_GOVERNANCE_REVIEWER");
        assertThat(identity.demoMode()).isTrue();
        assertThat(identity.expiresAt()).isEqualTo(clock.instant().getEpochSecond() + 1800);
        assertThat(issuer.current(identity, false)).isTrue();
        assertThat(issuer.current(identity, true)).isFalse();
        var mutation = issuer.mutationContext(session, csrfRequest(session.csrfToken()));
        assertThat(issuer.current(mutation, true)).isTrue();
        assertThat(issuer.current(identity, true)).isFalse();
        assertThat(mutation.sessionId()).isEqualTo(identity.sessionId());
        assertThat(issuer.session(cookie(session.token())).identity().sessionId()).isEqualTo(identity.sessionId());
    }

    @Test void absentShortSharedAndInvalidConfigurationNeverIssuesAuthority() {
        for (String key : new String[]{null, "", "a".repeat(31), " ".repeat(32), "\t".repeat(32), "\u2003".repeat(16)}) {
            assertDeniedConfiguration(key, SIGNING, ACTOR, WORKSPACE, "");
            assertDeniedConfiguration(BOOTSTRAP, key, ACTOR, WORKSPACE, "");
        }
        assertDeniedConfiguration(BOOTSTRAP, BOOTSTRAP, ACTOR, WORKSPACE, "");
        assertDeniedConfiguration(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, BOOTSTRAP);
        assertDeniedConfiguration(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, SIGNING);
        for (String actor : new String[]{null, "", " ", " reviewer", "reviewer ", "a".repeat(121), "bad\nactor"}) {
            assertDeniedConfiguration(BOOTSTRAP, SIGNING, actor, WORKSPACE, "");
        }
        for (String workspace : new String[]{null, "", "1-1-1-1-1", WORKSPACE.toUpperCase(), "other"}) {
            if (!WORKSPACE.equals(workspace)) assertDeniedConfiguration(BOOTSTRAP, SIGNING, ACTOR, workspace, "");
        }
    }

    @Test void keyLengthIsMeasuredInUtf8BytesAtTheActualBoundary() {
        String thirtyOneBytes = "é".repeat(15) + "a";
        String thirtyTwoBytes = "é".repeat(16);
        assertThat(thirtyOneBytes.getBytes(StandardCharsets.UTF_8)).hasSize(31);
        assertThat(thirtyTwoBytes.getBytes(StandardCharsets.UTF_8)).hasSize(32);
        assertDeniedConfiguration(thirtyOneBytes, SIGNING, ACTOR, WORKSPACE, "");
        assertDeniedConfiguration(BOOTSTRAP, thirtyOneBytes, ACTOR, WORKSPACE, "");
        assertThat(issuer(thirtyTwoBytes, SIGNING, ACTOR, WORKSPACE, "").exchange(exchange(thirtyTwoBytes))).isNotNull();
        assertThat(issuer(BOOTSTRAP, thirtyTwoBytes, ACTOR, WORKSPACE, "").exchange(exchange(BOOTSTRAP))).isNotNull();
    }

    @Test void matchingAsciiAndUtf8BootstrapBoundariesCannotHideBehindCredentialMismatch() {
        for (String shortKey : List.of("k".repeat(31), "é".repeat(15) + "a")) {
            assertThat(shortKey.getBytes(StandardCharsets.UTF_8)).hasSize(31);
            assertThat(issuer(shortKey, SIGNING, ACTOR, WORKSPACE, "").exchange(exchange(shortKey))).isNull();
            assertThat(issuer(BOOTSTRAP, shortKey, ACTOR, WORKSPACE, "").exchange(exchange(BOOTSTRAP))).isNull();
        }
        for (String safeKey : List.of("k".repeat(32), "é".repeat(16))) {
            assertThat(safeKey.getBytes(StandardCharsets.UTF_8)).hasSize(32);
            assertThat(issuer(safeKey, SIGNING, ACTOR, WORKSPACE, "").exchange(exchange(safeKey))).isNotNull();
            assertThat(issuer(BOOTSTRAP, safeKey, ACTOR, WORKSPACE, "").exchange(exchange(BOOTSTRAP))).isNotNull();
        }
    }

    @Test void validSuppliedSecretsCannotCollideWithOwnedFailureRepresentations() {
        for (String canary : ownedFixedFailureCanaries()) {
            assertThat(canary.getBytes(StandardCharsets.UTF_8).length).isGreaterThanOrEqualTo(32);
            assertUnsafeConfiguration(canary, SIGNING, ACTOR, WORKSPACE, "");
            assertUnsafeConfiguration(BOOTSTRAP, canary, ACTOR, WORKSPACE, "");
            assertUnsafeConfiguration(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, canary);
        }
        // The new policy does not reject a short key because it resembles its own generic error.
        String shortKey = "Unsafe governance config";
        assertThat(shortKey.getBytes(StandardCharsets.UTF_8).length).isLessThan(32);
        assertThat(issuer(shortKey, SIGNING, ACTOR, WORKSPACE, "").exchange(exchange(shortKey))).isNull();
        assertThat(issuer(BOOTSTRAP, shortKey, ACTOR, WORKSPACE, "").exchange(exchange(BOOTSTRAP))).isNull();
        assertThat(issuer(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, shortKey).exchange(exchange(BOOTSTRAP))).isNotNull();
        for (String safeKey : List.of("s".repeat(32), "é".repeat(16))) {
            assertThat(issuer(safeKey, SIGNING, ACTOR, WORKSPACE, "").exchange(exchange(safeKey))).isNotNull();
            assertThat(issuer(BOOTSTRAP, safeKey, ACTOR, WORKSPACE, "").exchange(exchange(BOOTSTRAP))).isNotNull();
            assertThat(issuer(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, safeKey).exchange(exchange(BOOTSTRAP))).isNotNull();
        }
    }

    @Test void suppliedSecretsCannotCollideWithActualCookieTransportBoundaries() {
        String clear = org.springframework.http.ResponseCookie.from(GovernanceReviewerCredentials.COOKIE, "")
                .httpOnly(true).secure(true).sameSite("Lax").path("/").maxAge(0).build().toString();
        assertThat(KNOWN_COOKIE_TRANSPORT_98.getBytes(StandardCharsets.UTF_8)).hasSize(98);
        List<String> canaries = List.of(GovernanceReviewerCredentials.COOKIE + "=eyJwdXJwb3NlIjoi",
                "; Secure; HttpOnly; SameSite=Lax", GovernanceReviewerCredentials.COOKIE + "=; Path=/; Max-Age=0", clear,
                KNOWN_COOKIE_TRANSPORT_98);
        assertThat(canaries.getFirst().getBytes(StandardCharsets.UTF_8)).hasSize(41);
        assertThat(canaries.get(1).getBytes(StandardCharsets.UTF_8)).hasSize(32);
        for (String key : canaries) {
            assertThat(key.getBytes(StandardCharsets.UTF_8).length).isGreaterThanOrEqualTo(32);
            assertUnsafeConfiguration(key, SIGNING, ACTOR, WORKSPACE, "");
            assertUnsafeConfiguration(BOOTSTRAP, key, ACTOR, WORKSPACE, "");
            assertUnsafeConfiguration(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, key);
            assertUnsafeConfiguration(key, "", "", "", "");
            assertUnsafeConfiguration("", key, "", "", "");
            assertUnsafeConfiguration("", "", "", "", key);
        }
    }

    @Test void safeIssuanceRetainsOneExactCookieHeaderButCookieReadsNeverRenewIt() throws Exception {
        for (String safeKey : List.of("k".repeat(32), "é".repeat(16))) {
            for (int position = 0; position < 3; position++) {
                String bootstrap = position == 0 ? safeKey : BOOTSTRAP;
                String signing = position == 1 ? safeKey : SIGNING;
                String cKey = position == 2 ? safeKey : "synthetic-distinct-cookie-control-C-reference";
                var guarded = issuer(bootstrap, signing, ACTOR, WORKSPACE, cKey);
                var issued = guarded.exchange(exchange(bootstrap));
                assertThat(issued).isNotNull();
                String header = issued.issuanceCookieHeader();
                assertThat(header).startsWith(GovernanceReviewerCredentials.COOKIE + "=" + issued.token() + "; Path=/; Max-Age=1800; Expires=")
                        .startsWith(KNOWN_COOKIE_TRANSPORT_98).endsWith("; Secure; HttpOnly; SameSite=Lax").doesNotContain("Domain=", bootstrap, signing, cKey);
                assertThat(issued.issuanceCookieHeader()).isSameAs(header);
                var read = guarded.session(cookie(issued.token()));
                assertThat(read).isNotNull();
                assertThat(read.issuanceCookieHeader()).isNull();
                assertThat(read.identity().sessionId()).isEqualTo(issued.identity().sessionId());
                assertThat(read.csrfToken()).isEqualTo(issued.csrfToken());
                assertThat(windowSize(guarded, "attempts")).isEqualTo(1);
                assertThat(windowSize(guarded, "issuances")).isEqualTo(1);
            }
        }
    }

    @Test void fixedUuidC99CookieIsDeniedByActualIssuanceBeforeSuccessAdmission() throws Exception {
        String c99 = KNOWN_COOKIE_TRANSPORT_98 + "j";
        assertThat(c99.getBytes(StandardCharsets.UTF_8)).hasSize(99);
        UUID fixed = UUID.fromString("00000000-0000-4000-8000-000000000001");
        var control = issuer(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, "");
        var guarded = issuer(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, c99);
        try (var uuids = org.mockito.Mockito.mockStatic(UUID.class, org.mockito.Mockito.CALLS_REAL_METHODS)) {
            uuids.when(UUID::randomUUID).thenReturn(fixed);
            var emitted = control.exchange(exchange(BOOTSTRAP));
            assertThat(emitted).isNotNull();
            assertThat(emitted.identity().sessionId()).isEqualTo(fixed);
            assertThat(emitted.issuanceCookieHeader()).startsWith(c99);
            assertThat(originalRaw(emitted)).doesNotContain(c99);
            assertThat(emitted.token()).doesNotContain(c99);
            assertThat(projectedActualView(payload(emitted))).doesNotContain(c99);
            assertThat(guarded.exchange(exchange(BOOTSTRAP))).isNull();
            assertThat(windowSize(guarded, "attempts")).isEqualTo(1);
            assertThat(windowSize(guarded, "issuances")).isZero();
            assertThat(windowSize(control, "issuances")).isEqualTo(1);
        }
    }

    @Test void privateCComparatorCoversExactUtf8WindowsWhitespacePartialSettingsAndFrameBounds() throws Exception {
        String c99 = KNOWN_COOKIE_TRANSPORT_98 + "j";
        for (String reference : List.of(c99, " ".repeat(32), "é".repeat(16))) {
            var active = issuer(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, reference);
            var partial = issuer("", "", "", "", reference);
            for (var guarded : List.of(active, partial)) {
                assertThat(privateCFrameSafe(guarded, "prefix-" + reference + "-suffix")).isFalse();
                assertThat(privateCByteFrameSafe(guarded, ("prefix-" + reference + "-suffix").getBytes(StandardCharsets.UTF_8))).isFalse();
                assertThat(privateCFrameSafe(guarded, "otherwise-safe-frame")).isTrue();
                assertThat(privateCFrameSafe(guarded, "x".repeat(6001))).isFalse();
                assertThat(privateCByteFrameSafe(guarded, new byte[6001])).isFalse();
            }
        }
        for (String absentOrShort : List.of("", " ".repeat(31))) {
            var unchanged = issuer(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, absentOrShort);
            assertThat(privateCFrameSafe(unchanged, "prefix-" + absentOrShort + "-suffix")).isTrue();
        }
    }

    @Test void suppliedUuidCReferencesCannotReachTraceEvenWithPartialDisabledSettings() {
        for (String key : List.of("abcdefab-1234-5678-9abc-def012345678", "00000000-0000-0000-0000-00000000")) {
            assertThat(key.getBytes(StandardCharsets.UTF_8).length).isGreaterThanOrEqualTo(32);
            assertUnsafeConfiguration(key, SIGNING, ACTOR, WORKSPACE, "");
            assertUnsafeConfiguration(BOOTSTRAP, key, ACTOR, WORKSPACE, "");
            assertUnsafeConfiguration(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, key);
            assertUnsafeConfiguration(key, "", "", "", "");
            assertUnsafeConfiguration("", key, "", "", "");
            assertUnsafeConfiguration("", "", "", "", key);
        }
    }

    @Test void wholeSerializedResponseFramesGuardCompositeTraceAcrossAllSuppliedSecretPositions() throws Exception {
        for (String[] vector : List.of(
                new String[]{"\"traceId\":\"abcdefab-1234-5678-9abc", "abcdefab-1234-5678-9abc-def012345678", "abcdefab-1234-5678-9abd-def012345678"},
                new String[]{"required\",\"traceId\":\"00000000-0000", "00000000-0000-4000-8000-000000000001", "00000000-0001-4000-8000-000000000001"})) {
            String composite = vector[0], trace = vector[1], nearMiss = vector[2];
            assertThat(composite.getBytes(StandardCharsets.UTF_8)).hasSize(34);
            assertThat(trace).doesNotContain(composite);
            byte[] unsafe = json.writeValueAsBytes(json.createObjectNode().put("status", 403).put("title", "Forbidden")
                    .put("code", "OPERATOR_AUTH_REQUIRED").put("detail", "Current governance session authority required")
                    .put("traceId", trace));
            byte[] safe = json.writeValueAsBytes(json.createObjectNode().put("status", 403).put("title", "Forbidden")
                    .put("code", "OPERATOR_AUTH_REQUIRED").put("detail", "Current governance session authority required")
                    .put("traceId", nearMiss));
            assertThat(new String(unsafe, StandardCharsets.UTF_8)).contains(composite);
            assertThat(new String(safe, StandardCharsets.UTF_8)).doesNotContain(composite);
            for (String[] cfg : List.of(new String[]{composite, SIGNING, ""},
                    new String[]{BOOTSTRAP, composite, ""}, new String[]{BOOTSTRAP, SIGNING, composite})) {
                var guarded = issuer(cfg[0], cfg[1], ACTOR, WORKSPACE, cfg[2]);
                // These dynamic-output references remain valid; no constructor-invalid shortcut.
                assertThat(guarded.safeActualResponseFrame(unsafe)).isFalse();
                assertThat(guarded.safeActualResponseFrame(safe)).isTrue();
                assertThat(guarded.safeActualResponseFrame(null)).isFalse();
                assertThat(guarded.safeActualResponseFrame(new byte[6001])).isFalse();
                var issued = guarded.exchange(exchange(cfg[0]));
                assertThat(issued).isNotNull();
                assertThat(issued.safeActualResponseFrame(unsafe)).isFalse();
                assertThat(issued.safeActualResponseFrame(safe)).isTrue();
                var read = guarded.session(cookie(issued.token()));
                assertThat(read).isNotNull();
                assertThat(read.issuanceCookieHeader()).isNull();
                assertThat(read.safeActualResponseFrame(unsafe)).isFalse();
                assertThat(windowSize(guarded, "attempts")).isEqualTo(1);
                assertThat(windowSize(guarded, "issuances")).isEqualTo(1);
            }
            var disabled = issuer("", "", "", "", "");
            assertThat(disabled.safeActualResponseFrame(unsafe)).isTrue(); // Empty keys cannot match every output.
            assertThat(disabled.exchange(exchange(""))).isNull();
        }
    }

    private boolean privateCFrameSafe(GovernanceReviewerCredentials guarded, String frame) throws Exception {
        var method = GovernanceReviewerCredentials.class.getDeclaredMethod("safeContractOutputFrame", String.class);
        method.setAccessible(true); return (boolean) method.invoke(guarded, frame);
    }
    private boolean privateCByteFrameSafe(GovernanceReviewerCredentials guarded, byte[] frame) throws Exception {
        var method = GovernanceReviewerCredentials.class.getDeclaredMethod("safeContractOutputFrame", byte[].class);
        method.setAccessible(true); return (boolean) method.invoke(guarded, (Object) frame);
    }

    @Test void configuredKnownCWhitespaceCannotBecomeGovernancePublicMetadata() {
        String cKey = " ".repeat(32);
        var actualC = new com.finsecseal.platform.contract.ContractReviewerCredentials(
                cKey, "security-reviewer", WORKSPACE, json);
        assertThat(actualC.keyValid(cKey)).isTrue(); // Existing C behavior, not a new C policy.
        String actor = "governance-" + cKey + "reviewer";
        assertThat(actor).isEqualTo(actor.strip());
        assertUnsafeConfiguration(BOOTSTRAP, SIGNING, actor, WORKSPACE, cKey);
        assertUnsafeConfiguration("", "", actor, "", cKey);
        assertUnsafeConfiguration("", "", "", "invalid-" + cKey + "-workspace", cKey);
        // The key is allowed as an ephemeral reference when it is absent from public A metadata.
        assertThat(issuer(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, cKey).exchange(exchange(BOOTSTRAP))).isNotNull();
        String shortC = " ".repeat(31);
        assertThat(new com.finsecseal.platform.contract.ContractReviewerCredentials(
                shortC, "security-reviewer", WORKSPACE, json).keyValid(shortC)).isFalse();
        assertThat(issuer(BOOTSTRAP, SIGNING, "governance-" + shortC + "reviewer", WORKSPACE, shortC)
                .exchange(exchange(BOOTSTRAP))).isNotNull();
    }

    @Test void suppliedAAndConstructorKnownCSecretsCannotBecomePublicMetadataEvenWithPartialConfig() {
        for (String secret : List.of(BOOTSTRAP, SIGNING)) {
            boolean bootstrap = secret.equals(BOOTSTRAP);
            for (String actor : List.of(secret, "reviewer-" + secret + "-public"))
                assertUnsafeConfiguration(BOOTSTRAP, SIGNING, actor, WORKSPACE, "");
            assertUnsafeConfiguration(BOOTSTRAP, SIGNING, ACTOR, "invalid-" + secret + "-workspace", "");
            assertUnsafeConfiguration(bootstrap ? secret : "", bootstrap ? "" : secret, secret, null, "");
        }
        String cKey = "synthetic-distinct-private-contract-key-32bytes";
        for (String actor : List.of(cKey, "reviewer-" + cKey + "-public"))
            assertUnsafeConfiguration(BOOTSTRAP, SIGNING, actor, WORKSPACE, cKey);
        assertUnsafeConfiguration("", "", null, "invalid-" + cKey + "-workspace", cKey);
        for (String shortC : List.of("reviewer", WORKSPACE, WORKSPACE.substring(0, 32))) {
            assertUnsafeConfiguration(BOOTSTRAP, SIGNING,
                    shortC.equals("reviewer") ? ACTOR : "safe-actor", WORKSPACE, shortC);
        }
        for (String blankC : new String[]{null, "", " ", "\t"})
            assertThat(issuer(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, blankC).exchange(exchange(BOOTSTRAP))).isNotNull();
        // Existing C authentication still accepts its valid UUID key; A privacy refuses that reference.
        String uuidC = "abcdefab-1234-5678-9abc-def012345678";
        assertThat(new com.finsecseal.platform.contract.ContractReviewerCredentials(
                uuidC, "security-reviewer", WORKSPACE, json).keyValid(uuidC)).isTrue();
        assertUnsafeConfiguration(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, uuidC);
        assertUnsafeConfiguration("", "", "", "", uuidC);
        String safeNonUuidC = "synthetic-distinct-private-contract-key-32bytes";
        assertThat(issuer(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, safeNonUuidC)
                .exchange(exchange(BOOTSTRAP))).isNotNull();
        assertUnsafeConfiguration("", "", "wrapped-private", "not-a-uuid", "private");
    }

    @Test void serializedClaimViewAndFixedRoleBoundariesRejectBothAKeysAndEphemeralC() {
        String actor = "02123456-1234-5678-9abc-def012345678";
        String claimsKey = actor + "\",\"workspace\":\"" + WORKSPACE;
        String viewKey = actor + "\",\"workspaceId\":\"" + WORKSPACE;
        String roleKey = "\"role\":\"AI_GOVERNANCE_REVIEWER\",\"demoMode\":true";
        String purposeKey = "\"purpose\":\"FINSEC_GOVERNANCE_SESSION_V1\"";
        assertThat(claimsKey.getBytes(StandardCharsets.UTF_8)).hasSize(87);
        assertThat(roleKey.getBytes(StandardCharsets.UTF_8)).hasSize(47);
        for (String key : List.of(claimsKey, viewKey, roleKey, purposeKey)) {
            assertThat(actor).doesNotContain(key);
            assertThat(WORKSPACE).doesNotContain(key);
            assertUnsafeSerializedConfiguration(key, SIGNING, actor, WORKSPACE, "");
            assertUnsafeSerializedConfiguration(BOOTSTRAP, key, actor, WORKSPACE, "");
            assertUnsafeSerializedConfiguration(BOOTSTRAP, SIGNING, actor, WORKSPACE, key);
        }
        // Fixed public claims stay unsafe even when another configuration field is missing.
        for (String key : List.of(roleKey, purposeKey)) {
            assertUnsafeSerializedConfiguration(key, "", null, null, "");
            assertUnsafeSerializedConfiguration("", key, null, null, "");
            assertUnsafeSerializedConfiguration("", "", null, null, key);
        }
    }

    @Test void actualRawPropertyOpeningsAndCompleteEncodedQuantaRejectAllThreeSuppliedKeys() {
        String purpose = "{\"purpose\":\"FINSEC_GOVERNANCE_SESSION_V1\",\"sessionId\":\"";
        String role = ",\"role\":\"AI_GOVERNANCE_REVIEWER\",\"demoMode\":true,\"generation\":\"";
        String view = ",\"role\":\"AI_GOVERNANCE_REVIEWER\",\"sessionId\":\"";
        List<String> keys = new ArrayList<>(List.of(purpose, purpose.substring(0, 41),
                purpose.substring(1), role, view));
        for (String span : List.of(purpose, role)) {
            byte[] bytes = span.getBytes(StandardCharsets.UTF_8);
            for (int start = 0; start < (span == purpose ? 1 : 3); start++) {
                int end = start + (bytes.length - start) / 3 * 3;
                keys.add(Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(java.util.Arrays.copyOfRange(bytes, start, end)));
            }
        }
        for (String key : keys) {
            assertUnsafeSerializedConfiguration(key, SIGNING, ACTOR, WORKSPACE, "");
            assertUnsafeSerializedConfiguration(BOOTSTRAP, key, ACTOR, WORKSPACE, "");
            assertUnsafeSerializedConfiguration(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, key);
        }
    }

    @Test void otherwiseValidEncodedJsonOnlyViewSpanIsAllowedInEverySuppliedKeyPosition() {
        // Original SUP077 literal: JSON-only view metadata is not a signed-claim encoding.
        String key = "LCJyb2xlIjoiQUlfR09WRVJOQU5DRV9SRVZJRVdFUiIsInNlc3Npb25JZCI6";
        assertThat(key.getBytes(StandardCharsets.UTF_8)).hasSize(60);
        for (int position = 0; position < 3; position++) {
            String bootstrap = position == 0 ? key : BOOTSTRAP;
            String signing = position == 1 ? key : SIGNING;
            var safe = issuer(bootstrap, signing, ACTOR, WORKSPACE, position == 2 ? key : "");
            var session = safe.exchange(exchange(bootstrap));
            assertThat(session).isNotNull();
            var current = safe.session(cookie(session.token()));
            assertThat(current).isNotNull();
            assertThat(current.token()).isEqualTo(session.token());
            assertThat(current.identity().sessionId()).isEqualTo(session.identity().sessionId());
            assertThat(current.identity().expiresAt()).isEqualTo(session.identity().expiresAt());
            String raw = new String(Base64.getUrlDecoder().decode(session.token().split("\\.")[0]),
                    StandardCharsets.UTF_8);
            var identity = session.identity();
            String view = json.writeValueAsString(json.createObjectNode()
                    .put("csrfToken", session.csrfToken()).put("expiresAt", identity.expiresAt())
                    .put("actorId", identity.actorId()).put("workspaceId", identity.workspaceId().toString())
                    .put("role", identity.role()).put("sessionId", identity.sessionId().toString())
                    .put("demoMode", identity.demoMode()));
            assertThat(raw).doesNotContain(key);
            assertThat(session.token()).doesNotContain(key);
            assertThat(view).doesNotContain(key);
        }
    }

    @Test void dynamicActualOutputDenialCountsAttemptWithoutConsumingIssuance() throws Exception {
        long now = clock.instant().getEpochSecond();
        String key = "\"issuedAt\":" + now + ",\"expiresAt\":" + (now + 1800);
        for (boolean bootstrapPosition : List.of(true, false)) {
            clock.set(Instant.ofEpochSecond(now));
            var guarded = issuer(bootstrapPosition ? key : BOOTSTRAP,
                    bootstrapPosition ? SIGNING : key, ACTOR, WORKSPACE, "");
            String bootstrap = bootstrapPosition ? key : BOOTSTRAP;
            assertThat(guarded.exchange(exchange(bootstrap))).isNull();
            assertThat(windowSize(guarded, "attempts")).isEqualTo(1);
            assertThat(windowSize(guarded, "issuances")).isZero();
            clock.advance(1);
            for (int i = 0; i < 32; i++) assertThat(guarded.exchange(exchange(bootstrap))).isNotNull();
            assertThat(guarded.exchange(exchange(bootstrap))).isNull();
            assertThat(windowSize(guarded, "issuances")).isEqualTo(32);
        }
    }

    @Test void originalSignedRawEscapingIsCheckedBeforeCookieContextAcceptance() throws Exception {
        String key = "\\u0067\\u006f\\u0076\\u0065\\u0072\\u006e";
        var guarded = issuer(key, SIGNING, ACTOR, WORKSPACE, "");
        var safe = guarded.exchange(exchange(key));
        assertThat(safe).isNotNull();
        String raw = new String(Base64.getUrlDecoder().decode(safe.token().split("\\.")[0]), StandardCharsets.UTF_8);
        String alternative = raw.replace("\"actor\":\"governance-reviewer\"",
                "\"actor\":\"" + key + "ance-reviewer\"");
        assertThat(alternative).isNotEqualTo(raw).contains(key);
        assertThat(json.readTree(alternative).path("actor").stringValue()).isEqualTo(ACTOR);
        assertThat(guarded.session(cookie(sign(raw)))).isNotNull();
        assertThat(guarded.session(cookie(sign(alternative)))).isNull();
        assertThat(windowSize(guarded, "issuances")).isEqualTo(1);
    }

    @Test void tokenOnlyActualTimespanCollisionDeniesIssuanceWithoutConsumingSuccessQuota() throws Exception {
        long now = clock.instant().getEpochSecond();
        var control = issue();
        String key = actualCompleteTokenTimeKey(control);
        String raw = originalRaw(control);
        assertThat(control.token()).contains(key);
        assertThat(raw).doesNotContain(key);
        assertThat(projectedActualView(payload(control))).doesNotContain(key);
        for (boolean bootstrapPosition : List.of(true, false)) {
            clock.set(Instant.ofEpochSecond(now));
            String bootstrap = bootstrapPosition ? key : BOOTSTRAP;
            String signing = bootstrapPosition ? SIGNING : key;
            var guarded = issuer(bootstrap, signing, ACTOR, WORKSPACE, "");
            // Independent generation/signing changes only the later generation field, not the measured offset.
            ObjectNode candidate = claimsForConfiguredKeys(payload(control), bootstrap, signing);
            String candidateRaw = json.writeValueAsString(candidate);
            String candidateToken = sign(candidateRaw, signing);
            assertThat(candidateToken).contains(key);
            assertThat(candidateRaw).doesNotContain(key);
            assertThat(projectedActualView(candidate)).doesNotContain(key);
            assertThat(guarded.exchange(exchange(bootstrap))).isNull();
            assertThat(windowSize(guarded, "attempts")).isEqualTo(1);
            assertThat(windowSize(guarded, "issuances")).isZero();
            clock.advance(1);
            var safe = guarded.exchange(exchange(bootstrap));
            assertThat(safe).isNotNull();
            assertThat(safe.token()).doesNotContain(key);
            assertThat(guarded.session(cookie(safe.token()))).isNotNull();
            assertThat(windowSize(guarded, "attempts")).isEqualTo(2);
            assertThat(windowSize(guarded, "issuances")).isEqualTo(1);
        }
    }

    @Test void viewOnlyActualExpiryActorBoundaryDeniesIssuanceWithoutConsumingSuccessQuota() throws Exception {
        long now = clock.instant().getEpochSecond();
        var control = issue();
        String key = actualViewTimeKey(now + 1800);
        assertThat(key.getBytes(StandardCharsets.UTF_8).length).isGreaterThanOrEqualTo(32);
        assertThat(projectedActualView(payload(control))).contains(key);
        assertThat(originalRaw(control)).doesNotContain(key);
        assertThat(control.token()).doesNotContain(key);
        for (boolean bootstrapPosition : List.of(true, false)) {
            clock.set(Instant.ofEpochSecond(now));
            String bootstrap = bootstrapPosition ? key : BOOTSTRAP;
            String signing = bootstrapPosition ? SIGNING : key;
            var guarded = issuer(bootstrap, signing, ACTOR, WORKSPACE, "");
            ObjectNode candidate = claimsForConfiguredKeys(payload(control), bootstrap, signing);
            String candidateRaw = json.writeValueAsString(candidate);
            assertThat(projectedActualView(candidate)).contains(key);
            assertThat(candidateRaw).doesNotContain(key);
            assertThat(sign(candidateRaw, signing)).doesNotContain(key);
            assertThat(guarded.exchange(exchange(bootstrap))).isNull();
            assertThat(windowSize(guarded, "attempts")).isEqualTo(1);
            assertThat(windowSize(guarded, "issuances")).isZero();
            clock.advance(1);
            var safe = guarded.exchange(exchange(bootstrap));
            assertThat(safe).isNotNull();
            assertThat(projectedActualView(payload(safe))).doesNotContain(key);
            assertThat(guarded.session(cookie(safe.token()))).isNotNull();
            assertThat(windowSize(guarded, "attempts")).isEqualTo(2);
            assertThat(windowSize(guarded, "issuances")).isEqualTo(1);
        }
    }

    @Test void independentlySignedTokenOnlyCollisionIsRejectedAfterAnOrdinaryCookieControl() throws Exception {
        long now = clock.instant().getEpochSecond();
        var control = issue();
        String key = actualCompleteTokenTimeKey(control);
        for (boolean bootstrapPosition : List.of(true, false)) {
            String bootstrap = bootstrapPosition ? key : BOOTSTRAP;
            String signing = bootstrapPosition ? SIGNING : key;
            var guarded = issuer(bootstrap, signing, ACTOR, WORKSPACE, "");
            ObjectNode bad = claimsForConfiguredKeys(payload(control), bootstrap, signing);
            // Still otherwise-valid lifetime1800, expires>now and issuedAt<=now; no config-invalid shortcut.
            ObjectNode good = bad.deepCopy().put("issuedAt", now - 1).put("expiresAt", now + 1799);
            String goodRaw = json.writeValueAsString(good), goodToken = sign(goodRaw, signing);
            assertThat(goodRaw).doesNotContain(key);
            assertThat(goodToken).doesNotContain(key);
            assertThat(projectedActualView(good)).doesNotContain(key);
            var accepted = guarded.session(cookie(goodToken));
            assertThat(accepted).isNotNull();
            assertThat(accepted.identity().actorId()).isEqualTo(ACTOR);
            assertThat(accepted.identity().workspaceId().toString()).isEqualTo(WORKSPACE);
            assertThat(accepted.identity().sessionId().toString()).isEqualTo(good.path("sessionId").stringValue());
            String badRaw = json.writeValueAsString(bad), badToken = sign(badRaw, signing);
            assertThat(badRaw).doesNotContain(key);
            assertThat(projectedActualView(bad)).doesNotContain(key);
            assertThat(badToken).contains(key);
            assertThat(guarded.session(cookie(badToken))).isNull();
            assertThat(windowSize(guarded, "attempts")).isZero();
            assertThat(windowSize(guarded, "issuances")).isZero();
        }
    }

    @Test void independentlySignedViewOnlyCollisionIsRejectedAfterAnOrdinaryCookieControl() throws Exception {
        long now = clock.instant().getEpochSecond();
        var control = issue();
        String key = actualViewTimeKey(now + 1800);
        for (boolean bootstrapPosition : List.of(true, false)) {
            String bootstrap = bootstrapPosition ? key : BOOTSTRAP;
            String signing = bootstrapPosition ? SIGNING : key;
            var guarded = issuer(bootstrap, signing, ACTOR, WORKSPACE, "");
            ObjectNode bad = claimsForConfiguredKeys(payload(control), bootstrap, signing);
            ObjectNode good = bad.deepCopy().put("issuedAt", now - 1).put("expiresAt", now + 1799);
            String goodRaw = json.writeValueAsString(good), goodToken = sign(goodRaw, signing);
            assertThat(goodRaw).doesNotContain(key);
            assertThat(goodToken).doesNotContain(key);
            assertThat(projectedActualView(good)).doesNotContain(key);
            var accepted = guarded.session(cookie(goodToken));
            assertThat(accepted).isNotNull();
            assertThat(accepted.identity().actorId()).isEqualTo(ACTOR);
            assertThat(accepted.identity().workspaceId().toString()).isEqualTo(WORKSPACE);
            assertThat(accepted.identity().sessionId().toString()).isEqualTo(good.path("sessionId").stringValue());
            String badRaw = json.writeValueAsString(bad), badToken = sign(badRaw, signing);
            assertThat(badRaw).doesNotContain(key);
            assertThat(badToken).doesNotContain(key);
            assertThat(projectedActualView(bad)).contains(key);
            assertThat(guarded.session(cookie(badToken))).isNull();
            assertThat(windowSize(guarded, "attempts")).isZero();
            assertThat(windowSize(guarded, "issuances")).isZero();
        }
    }

    @Test void actualJsonEscapingDoesNotHideCrossFieldSecretsOrRejectSafeUtf8Credentials() {
        String actor = "reviewer-\"quote\\slash-suffix";
        String scalar = json.writeValueAsString(actor);
        String escapedActor = scalar.substring(1, scalar.length() - 1);
        assertThat(escapedActor).isNotEqualTo(actor);
        for (String field : List.of("workspace", "workspaceId")) {
            String key = escapedActor + "\",\"" + field + "\":\"" + WORKSPACE;
            assertThat(actor).doesNotContain(key);
            assertThat(WORKSPACE).doesNotContain(key);
            assertUnsafeSerializedConfiguration(key, SIGNING, actor, WORKSPACE, "");
            assertUnsafeSerializedConfiguration(BOOTSTRAP, key, actor, WORKSPACE, "");
            assertUnsafeSerializedConfiguration(BOOTSTRAP, SIGNING, actor, WORKSPACE, key);
        }
        for (String bootstrap : List.of("k".repeat(32), "é".repeat(16))) {
            String signing = bootstrap.startsWith("k") ? "é".repeat(16) : "v".repeat(32);
            var safe = issuer(bootstrap, signing, actor, WORKSPACE, "private-distinct-contract-key-32bytes");
            var session = safe.exchange(exchange(bootstrap));
            assertThat(session).isNotNull();
            assertThat(payload(session).path("actor").stringValue()).isEqualTo(actor);
            assertThat(payload(session).path("workspace").stringValue()).isEqualTo(WORKSPACE);
            assertThat(safe.session(cookie(session.token()))).isNotNull();
        }
    }

    @Test void uuidContainingTraceCompletionRejectsBothAKeysAtEverySelectedParserBoundary() {
        String prefixOnly = "-" + "0".repeat(8) + "-" + "0".repeat(8) + "-" + "0".repeat(8) + "-" + "0".repeat(7);
        String suffixOnly = "0".repeat(7) + "-" + "0".repeat(8) + "-" + "0".repeat(8) + "-" + "0".repeat(8) + "-";
        String bothEdges = "-" + "0".repeat(10) + "-" + "0".repeat(10) + "-" + "0".repeat(10) + "-";
        List<String> unsafe = new ArrayList<>(List.of(WORKSPACE, WORKSPACE.toUpperCase(), "1-1-1-1-1",
                "+" + "0".repeat(22) + "1-0-0-0-0", "0".repeat(24) + "-0-0-0-+",
                "０".repeat(11), "Ｆ".repeat(11), "٠".repeat(16), "０".repeat(10) + "a",
                prefixOnly, suffixOnly, bothEdges));
        for (int hyphens = 0; hyphens <= 4; hyphens++) {
            List<String> groups = new ArrayList<>();
            for (int group = 0; group <= hyphens; group++) groups.add("０".repeat(Math.max(3, 11 / (hyphens + 1))));
            String key = String.join("-", groups);
            if (key.length() <= 36) unsafe.add(key);
        }
        for (String key : unsafe) {
            assertUnsafeConfiguration(key, SIGNING, ACTOR, WORKSPACE, "");
            assertUnsafeConfiguration(BOOTSTRAP, key, ACTOR, WORKSPACE, "");
            assertUnsafeConfiguration(key, "", null, null, "");
            assertUnsafeConfiguration("", key, "", "invalid", "");
        }
    }

    @Test void completionLimitsOverflowAndUnrepairableGroupsPreserveSafeConfiguration() {
        String needs37 = "-" + "0".repeat(10) + "-" + "0".repeat(10) + "-" + "0".repeat(11) + "-";
        for (String key : List.of(needs37, "8".repeat(24) + "-0-0-0-0", "0+0-0-0-0-0" + "0".repeat(21),
                "safe-key-has-five-dashes-12345678", "k".repeat(37), "é".repeat(16))) {
            assertThat(issuer(key, SIGNING, ACTOR, WORKSPACE, "").exchange(exchange(key))).isNotNull();
            assertThat(issuer(BOOTSTRAP, key, ACTOR, WORKSPACE, "").exchange(exchange(BOOTSTRAP))).isNotNull();
        }
        for (String missing : new String[]{null, "", " ", "\t"})
            assertThat(issuer(missing, missing, "", "", "").exchange(exchange(BOOTSTRAP))).isNull();
    }

    @Test void everyCredentialAndIdentityRotationRejectsTheOldCookieAndForeignIssuerContext() {
        var session = issue();
        for (var rotated : List.of(
                issuer(BOOTSTRAP + "rotated", SIGNING, ACTOR, WORKSPACE, ""),
                issuer(BOOTSTRAP, SIGNING + "rotated", ACTOR, WORKSPACE, ""),
                issuer(BOOTSTRAP, SIGNING, "another-reviewer", WORKSPACE, ""),
                issuer(BOOTSTRAP, SIGNING, ACTOR, "0198f1e2-0000-7000-8000-000000000002", ""))) {
            assertThat(rotated.session(cookie(session.token()))).isNull();
            assertThat(rotated.current(session.identity(), false)).isFalse();
        }
        var otherIssuer = issuer(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, "");
        assertThat(otherIssuer.session(cookie(session.token()))).isNotNull();
        assertThat(otherIssuer.current(session.identity(), false)).isFalse();
        assertThat(otherIssuer.mutationContext(session, csrfRequest(session.csrfToken()))).isNull();
    }

    @Test void unknownMissingDuplicateAndTrailingJsonCannotBecomeASession() throws Exception {
        ObjectNode original = payload(issue());
        assertRejected(original.deepCopy().put("extra", "unknown"));
        for (var field : original.properties()) {
            ObjectNode missing = original.deepCopy(); missing.remove(field.getKey()); assertRejected(missing);
        }
        String valid = json.writeValueAsString(original);
        assertThat(issuer.session(cookie(sign(valid.substring(0, valid.length() - 1)
                + ",\"actor\":\"governance-reviewer\"}")))).isNull();
        assertThat(issuer.session(cookie(sign(valid + " {}")))).isNull();
        assertThat(issuer.session(cookie(sign("[]")))).isNull();
        assertThat(issuer.session(cookie(sign("null")))).isNull();
        assertThat(issuer.session(cookie(sign("{not-json")))).isNull();
    }

    @Test void independentlySignedWrongTypesPurposeRoleAndAuthorityAreRejected() throws Exception {
        ObjectNode original = payload(issue());
        for (String field : List.of("purpose", "sessionId", "csrf", "actor", "workspace", "role", "generation")) {
            assertRejected(original.deepCopy().put(field, 1));
            assertRejected(original.deepCopy().putNull(field));
        }
        for (String field : List.of("issuedAt", "expiresAt")) {
            assertRejected(original.deepCopy().put(field, "123"));
            assertRejected(original.deepCopy().put(field, 1.5));
            assertRejected(original.deepCopy().put(field, false));
            assertRejected(original.deepCopy().put(field, new java.math.BigInteger("18446744073709551617")));
        }
        assertRejected(original.deepCopy().put("purpose", "FINSEC_REVIEWER_SESSION_V1"));
        assertRejected(original.deepCopy().put("role", "AI_SECURITY_REVIEWER"));
        assertRejected(original.deepCopy().put("actor", "caller"));
        assertRejected(original.deepCopy().put("workspace", "0198f1e2-0000-7000-8000-000000000002"));
        assertRejected(original.deepCopy().put("generation", "caller-generation"));
        assertRejected(original.deepCopy().put("demoMode", false));
        assertRejected(original.deepCopy().put("demoMode", "true"));
        assertThat(issuer.session(cookie(sign(json.writeValueAsString(original), BOOTSTRAP)))).isNull();
    }

    @Test void signedIdentifiersCsrfAndTimesMustBeCanonicalAndBounded() throws Exception {
        ObjectNode original = payload(issue());
        for (String id : List.of("1-1-1-1-1", "not-uuid", WORKSPACE.toUpperCase())) {
            assertRejected(original.deepCopy().put("sessionId", id));
        }
        for (String csrf : List.of("", "caller", "1-1-1-1-1:1-1-1-1-1",
                (WORKSPACE + ":" + WORKSPACE).toUpperCase(), original.path("csrf").stringValue() + "x")) {
            assertRejected(original.deepCopy().put("csrf", csrf));
        }
        long now = clock.instant().getEpochSecond();
        assertRejected(original.deepCopy().put("issuedAt", now + 1));
        assertRejected(original.deepCopy().put("issuedAt", -1));
        assertRejected(original.deepCopy().put("expiresAt", now));
        assertRejected(original.deepCopy().put("expiresAt", -1));
        assertRejected(original.deepCopy().put("expiresAt", now + 1801));
        assertRejected(original.deepCopy().put("issuedAt", now - 1800).put("expiresAt", now + 1));
        var session = issuer.session(cookie(sign(json.writeValueAsString(original.deepCopy().put("expiresAt", now + 1)))));
        assertThat(session).isNotNull();
        var mutation = issuer.mutationContext(session, csrfRequest(session.csrfToken()));
        clock.advance(1);
        assertThat(issuer.current(session.identity(), false)).isFalse();
        assertThat(issuer.current(mutation, true)).isFalse();
        assertThat(issuer.session(cookie(session.token()))).isNull();
        assertThat(issuer.mutationContext(session, csrfRequest(session.csrfToken()))).isNull();
    }

    @Test void duplicateCookiesAndCsrfCannotSelectAnAuthority() {
        var session = issue();
        var request = cookie(session.token());
        request.setCookies(new Cookie(GovernanceReviewerCredentials.COOKIE, session.token()),
                new Cookie(GovernanceReviewerCredentials.COOKIE, session.token()));
        assertThat(issuer.session(request)).isNull();
        assertThat(issuer.session(cookie(session.token() + "x"))).isNull();
        assertThat(issuer.session(cookie("x".repeat(2049)))).isNull();
        var cCookie = new MockHttpServletRequest();
        cCookie.setCookies(new Cookie("__Host-FINSEC_REVIEWER", session.token()));
        assertThat(issuer.session(cCookie)).isNull();
        assertThat(issuer.mutationContext(session, new MockHttpServletRequest())).isNull();
        assertThat(issuer.mutationContext(session, csrfRequest("wrong"))).isNull();
        var duplicate = csrfRequest(session.csrfToken()); duplicate.addHeader("X-CSRF-Token", session.csrfToken());
        assertThat(issuer.mutationContext(session, duplicate)).isNull();
        assertThat(issuer.mutationContext(session, csrfRequest(session.csrfToken() + "," + session.csrfToken()))).isNull();
    }

    @Test void packageFactoryAndRawJsonCannotMintIssuerProofOrUpgradeReadOnlyIdentity() {
        var identity = issue().identity();
        var forged = GovernanceReviewerContext.issued(null, identity.workspaceId(), identity.actorId(),
                identity.sessionId(), identity.issuedAt(), identity.expiresAt(), identity.generation(), true);
        assertThat(issuer.current(forged, false)).isFalse();
        assertThat(issuer.current(forged, true)).isFalse();
        assertThat(GovernanceReviewerCredentials.Proof.class.getConstructors()).isEmpty();
        assertThat(GovernanceReviewerCredentials.Proof.class.getDeclaredConstructors()).allSatisfy(
                constructor -> assertThat(Modifier.isPrivate(constructor.getModifiers())).isTrue());
        assertThat(GovernanceReviewerContext.class.getDeclaredMethods()).noneSatisfy(
                method -> assertThat(method.getReturnType()).isEqualTo(GovernanceReviewerCredentials.Proof.class));
        assertThat(issuer.current(identity, true)).isFalse();
    }

    @Test void noncanonicalBase64AndOversizedSignedPayloadsAreRejected() throws Exception {
        String payload = issue().token().split("\\.")[0];
        assertThat(issuer.session(cookie(signPayload(payload + "=", SIGNING)))).isNull();
        assertThat(issuer.session(cookie(signPayload(payload, SIGNING) + "="))).isNull();
        assertThat(issuer.session(cookie(sign("{\"actor\":\"" + "x".repeat(3000) + "\"}")))).isNull();
    }

    @Test void onlyExactGetAndOneWellFormedBootstrapHeaderCanIssue() {
        for (String method : List.of("HEAD", "OPTIONS", "POST", "DELETE", "PATCH")) {
            var request = exchange(BOOTSTRAP); request.setMethod(method); assertThat(issuer.exchange(request)).isNull();
        }
        for (String path : List.of(GovernanceReviewerCredentials.SESSION_PATH + "/",
                GovernanceReviewerCredentials.SESSION_PATH + ";x", "/api/v1/%67overnance-reviewer-session")) {
            var request = exchange(BOOTSTRAP); request.setRequestURI(path); assertThat(issuer.exchange(request)).isNull();
        }
        var query = exchange(BOOTSTRAP); query.setQueryString("actor=caller"); assertThat(issuer.exchange(query)).isNull();
        for (String value : List.of("Bearer " + BOOTSTRAP, "GovernanceBootstrap  " + BOOTSTRAP,
                "GovernanceBootstrap " + BOOTSTRAP + ",other", "GovernanceBootstrap " + BOOTSTRAP + "\n")) {
            var request = new MockHttpServletRequest("GET", GovernanceReviewerCredentials.SESSION_PATH);
            request.addHeader("Authorization", value); assertThat(issuer.exchange(request)).isNull();
        }
        var duplicate = exchange(BOOTSTRAP); duplicate.addHeader("Authorization", "GovernanceBootstrap " + BOOTSTRAP);
        assertThat(issuer.exchange(duplicate)).isNull();
        var caller = exchange(BOOTSTRAP); caller.addHeader("X-Actor-Id", "caller"); caller.addHeader("X-Role", "AI_SECURITY_REVIEWER");
        assertThat(issuer.exchange(caller).identity().actorId()).isEqualTo(ACTOR);
    }

    @Test void secretBearingAndAnyCanonicalCsrfKeySubstringAreRejectedWithoutSecretAccessors() {
        var current = issue();
        var old = issue();
        var different = issuer(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, "").exchange(exchange(BOOTSTRAP));
        assertThat(different).isNotNull();
        for (String secret : List.of(BOOTSTRAP, SIGNING, current.csrfToken(), old.csrfToken(), different.csrfToken(),
                UUID.randomUUID() + ":" + UUID.randomUUID())) {
            assertThat(issuer.safeIdempotencyKey(current, secret)).isFalse();
            assertThat(issuer.safeIdempotencyKey(current, "pre-" + secret + "-post")).isFalse();
        }
        assertThat(issuer.safeIdempotencyKey(current, current.token())).isFalse();
        assertThat(issuer.safeIdempotencyKey(current, "gov-" + UUID.randomUUID())).isTrue();
        assertThat(issuer.safeIdempotencyKey(old, "gov-" + UUID.randomUUID())).isTrue();
        assertThat(issuer.safeIdempotencyKey(different, "gov-" + UUID.randomUUID())).isFalse();
        assertThat(issuer.safeIdempotencyKey(null, "gov-safe")).isFalse();
    }

    @Test void fractionalAttemptWindowCannotRecoverBeforeSixtyElapsedSeconds() throws Exception {
        Instant origin = Instant.parse("2026-10-02T18:00:00.900000000Z");
        clock.set(origin);
        for (int n = 0; n < 59; n++) assertThat(issuer.exchange(exchange("invalid"))).isNull();
        assertThat(issue()).isNotNull();
        clock.set(origin.plusSeconds(59).plusMillis(100));
        assertThat(issuer.exchange(exchange(BOOTSTRAP))).isNull();
        clock.set(origin.plusSeconds(60).minusNanos(1));
        assertThat(issuer.exchange(exchange(BOOTSTRAP))).isNull();
        assertThat(windowSize(issuer, "attempts")).isEqualTo(60);
        assertThat(windowSize(issuer, "issuances")).isEqualTo(1);
        clock.set(origin.plusSeconds(60));
        assertThat(issuer.exchange(exchange(BOOTSTRAP))).isNotNull();
        assertThat(windowSize(issuer, "attempts")).isEqualTo(1);
        assertThat(windowSize(issuer, "issuances")).isEqualTo(2);
    }

    @Test void fractionalIssuanceWindowCannotRecoverBeforeEighteenHundredElapsedSeconds() throws Exception {
        Instant origin = Instant.parse("2026-10-02T18:00:00.900000000Z");
        clock.set(origin);
        for (int n = 0; n < 32; n++) assertThat(issue()).isNotNull();
        clock.set(origin.plusSeconds(1799).plusMillis(100));
        assertThat(issuer.exchange(exchange(BOOTSTRAP))).isNull();
        clock.set(origin.plusSeconds(1800).minusNanos(1));
        assertThat(issuer.exchange(exchange(BOOTSTRAP))).isNull();
        assertThat(windowSize(issuer, "attempts")).isEqualTo(2);
        assertThat(windowSize(issuer, "issuances")).isEqualTo(32);
        clock.set(origin.plusSeconds(1800));
        assertThat(issuer.exchange(exchange(BOOTSTRAP))).isNotNull();
        assertThat(windowSize(issuer, "attempts")).isEqualTo(3);
        assertThat(windowSize(issuer, "issuances")).isEqualTo(1);
    }

    @Test void mixedAttemptsAreBoundedAndRecoverAtExactWindowBoundary() {
        for (int n = 0; n < 59; n++) assertThat(issuer.exchange(exchange("invalid"))).isNull();
        assertThat(issue()).isNotNull();
        assertThat(issuer.exchange(exchange(BOOTSTRAP))).isNull();
        clock.advance(59); assertThat(issuer.exchange(exchange(BOOTSTRAP))).isNull();
        clock.advance(1); assertThat(issuer.exchange(exchange(BOOTSTRAP))).isNotNull();
    }

    @Test void issuanceWindowSurvivesAttemptRecoveryAndCookieReadsDoNotRenew() {
        var first = issue();
        for (int n = 1; n < 32; n++) assertThat(issue()).isNotNull();
        assertThat(issuer.exchange(exchange(BOOTSTRAP))).isNull();
        for (int n = 0; n < 100; n++) assertThat(issuer.session(cookie(first.token())).identity().sessionId()).isEqualTo(first.identity().sessionId());
        clock.advance(60); assertThat(issuer.exchange(exchange(BOOTSTRAP))).isNull();
        clock.advance(1739); assertThat(issuer.exchange(exchange(BOOTSTRAP))).isNull();
        clock.advance(1); assertThat(issuer.exchange(exchange(BOOTSTRAP))).isNotNull();
    }

    @Test void concurrentExchangesCannotExceedIssuanceOrMixedAttemptQuotas() throws Exception {
        assertThat(concurrentExchanges(issuer, 100)).isEqualTo(32);
        var mixed = issuer(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, "");
        for (int n = 0; n < 30; n++) assertThat(mixed.exchange(exchange("invalid"))).isNull();
        assertThat(concurrentExchanges(mixed, 100)).isEqualTo(30);
        for (int n = 0; n < 1000; n++) mixed.exchange(exchange("invalid"));
        assertThat(windowSize(mixed, "attempts")).isEqualTo(60);
        assertThat(windowSize(mixed, "issuances")).isEqualTo(30);
        var concurrentMixed = issuer(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, "");
        try (var workers = Executors.newFixedThreadPool(16)) {
            var jobs = new ArrayList<Callable<Boolean>>();
            for (int n = 0; n < 30; n++) {
                jobs.add(() -> concurrentMixed.exchange(exchange(BOOTSTRAP)) != null);
                jobs.add(() -> concurrentMixed.exchange(exchange("invalid")) != null);
            }
            int successes = 0;
            for (var result : workers.invokeAll(jobs, 10, TimeUnit.SECONDS)) if (result.get(2, TimeUnit.SECONDS)) successes++;
            assertThat(successes).isEqualTo(30);
        }
        assertThat(concurrentMixed.exchange(exchange(BOOTSTRAP))).isNull();
        assertThat(windowSize(concurrentMixed, "attempts")).isEqualTo(60);
        assertThat(windowSize(concurrentMixed, "issuances")).isEqualTo(30);
    }

    @Test void opaqueContextHasNoPublicConstructionAndRepresentationsExcludeSecrets() {
        var session = issue();
        assertThat(GovernanceReviewerContext.class.getConstructors()).isEmpty();
        assertThat(Modifier.isFinal(GovernanceReviewerContext.class.getModifiers())).isTrue();
        assertThat(GovernanceReviewerContext.class.getDeclaredFields()).allSatisfy(field -> {
            assertThat(Modifier.isPrivate(field.getModifiers()) || Modifier.isStatic(field.getModifiers())).isTrue();
            assertThat(Modifier.isFinal(field.getModifiers())).isTrue();
        });
        assertThatThrownBy(() -> json.readValue("{\"workspaceId\":\"" + WORKSPACE + "\",\"actorId\":\"caller\"}",
                GovernanceReviewerContext.class)).isInstanceOf(RuntimeException.class);
        assertThat(session.toString() + session.identity().toString()).doesNotContain(
                BOOTSTRAP, SIGNING, session.token(), session.csrfToken(), ACTOR, session.identity().sessionId().toString());
        assertThat(payload(session).toString()).doesNotContain(BOOTSTRAP, SIGNING);
    }

    private void assertUnsafeConfiguration(String bootstrap, String signing, String actor, String workspace, String cKey) {
        assertThatThrownBy(() -> issuer(bootstrap, signing, actor, workspace, cKey))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("Unsafe governance config").hasNoCause();
    }

    private void assertUnsafeSerializedConfiguration(String bootstrap, String signing, String actor,
            String workspace, String cKey) {
        // The request uses the exact supplied bootstrap; only constructor safety may stop it.
        assertThatThrownBy(() -> issuer(bootstrap, signing, actor, workspace, cKey).exchange(exchange(bootstrap)))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("Unsafe governance config").hasNoCause();
    }

    private List<String> ownedFixedFailureCanaries() {
        String raw = json.writeValueAsString(json.createObjectNode().put("status", 403).put("title", "Forbidden")
                .put("code", "OPERATOR_AUTH_REQUIRED").put("detail", "Current governance session authority required"));
        return List.of("Current governance session authority required",
                "GOVERNANCE_AUTHORITY_STORAGE_UNAVAILABLE",
                "category=AUTHORITY_STORAGE classification=DATA_ACCESS_EXCEPTION",
                "GOVERNANCE_AUTHORITY_STORAGE_UNAVAILABLE category=AUTHORITY_STORAGE classification=DATA_ACCESS_EXCEPTION trace=UNAVAILABLE",
                "com.finsecseal.platform.governance.GovernanceAccessFilter",
                "Use the exact canonical governance API path and method",
                "A single safe Idempotency-Key is required", "Governance authority storage unavailable",
                "Current admitted governance mutation authority required",
                "Current governance reviewer authority required", "Governance signature unavailable",
                "GovernanceReviewerContext[redacted]", "GovernanceMutationContext[redacted]",
                "\"code\":\"OPERATOR_AUTH_REQUIRED\",\"detail\":\"",
                raw.substring(0, raw.length() - 1) + ",\"traceId\":\"");
    }

    @Test void exactFinalAuditCommentKeepsWellFormedBoundsWithoutNormalizationOrClockAuthority() {
        var session = issue();
        var request = auditCommentRequest(session, "audit-comment-key");
        var mutation = issuer.mutationContext(session, request);
        for (String invalid : new String[]{null, "", " \t\n", "a".repeat(2001), "\uD800", "\uDC00", "x\uD800y"})
            assertThat(issuer.safeAuditComment(session, mutation, request, "audit-comment-key", invalid)).isFalse();
        for (String valid : List.of("a".repeat(2000), "한".repeat(2000), "😀".repeat(1000), "  reviewed rationale  ")) {
            assertThat(valid.getBytes(StandardCharsets.UTF_8).length).isLessThanOrEqualTo(6000);
            assertThat(issuer.safeAuditComment(session, mutation, request, "audit-comment-key", valid)).isTrue();
        }
        clock.now = Instant.ofEpochSecond(session.identity().expiresAt());
        assertThat(issuer.safeAuditComment(session, mutation, request, "audit-comment-key", "Reviewed rationale")).isTrue();
        assertThat(issuer.current(mutation, true)).isFalse();

        // Separate delegated clock: measuring this pure helper does not change MutableClock's contract.
        class CountingClock extends Clock {
            private final Clock delegate;
            private final java.util.concurrent.atomic.AtomicInteger calls;
            CountingClock(Clock delegate, java.util.concurrent.atomic.AtomicInteger calls) {
                this.delegate = delegate; this.calls = calls;
            }
            @Override public ZoneId getZone() { return delegate.getZone(); }
            @Override public Clock withZone(ZoneId zone) { return new CountingClock(delegate.withZone(zone), calls); }
            @Override public Instant instant() { calls.incrementAndGet(); return delegate.instant(); }
        }
        var clockCalls = new java.util.concurrent.atomic.AtomicInteger();
        var countedClock = new CountingClock(Clock.systemUTC(), clockCalls);
        var measured = new GovernanceReviewerCredentials(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, "", countedClock);
        var measuredSession = measured.exchange(exchange(BOOTSTRAP));
        assertThat(measuredSession).isNotNull();
        var measuredRequest = auditCommentRequest(measuredSession, "audit-comment-key");
        var measuredMutation = measured.mutationContext(measuredSession, measuredRequest);
        assertThat(clockCalls.get()).as("issuer setup observes delegated clock").isPositive();
        clockCalls.set(0);
        assertThat(measured.safeAuditComment(measuredSession, measuredMutation, measuredRequest,
                "audit-comment-key", "Reviewed rationale")).isTrue();
        assertThat(measured.safeAuditComment(measuredSession, measuredMutation, measuredRequest,
                "audit-comment-key", "Reviewed " + BOOTSTRAP)).isFalse();
        assertThat(clockCalls.get()).as("pure comment helper clock calls").isZero();
        assertThat(measured.current(measuredMutation, true)).isTrue();
        assertThat(clockCalls.get()).as("current authority positive clock control").isPositive();
    }

    @Test void auditCommentReusesPrivateReferenceWindowsAndRejectsActualSessionSecrets() {
        for (String cReference : List.of("synthetic-comment-private-C-reference-at-least-32", "é".repeat(16), " ".repeat(32))) {
            var selected = issuer(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, cReference);
            var session = selected.exchange(exchange(BOOTSTRAP));
            assertThat(session).isNotNull();
            var request = auditCommentRequest(session, "audit-comment-key");
            var mutation = selected.mutationContext(session, request);
            for (String reference : List.of(BOOTSTRAP, SIGNING, cReference, session.token(), session.csrfToken())) {
                for (String comment : List.of(reference + " suffix", "prefix " + reference + " suffix", "prefix " + reference))
                    assertThat(selected.safeAuditComment(session, mutation, request, "audit-comment-key", comment)).isFalse();
            }
            String nearMiss = cReference.substring(0, cReference.length() - 1) + "x";
            assertThat(selected.safeAuditComment(session, mutation, request, "audit-comment-key", "left[" + nearMiss + "]right")).isTrue();
            assertThat(selected.safeAuditComment(session, mutation, request, "audit-comment-key", "Reviewed rationale")).isTrue();
            assertThat(issuer.safeAuditComment(session, mutation, request, "audit-comment-key", "Reviewed rationale")).isFalse();
            assertThat(selected.safeAuditComment(session, session.identity(), request, "audit-comment-key", "Reviewed rationale")).isFalse();
        }
        for (String shortReference : List.of("q".repeat(31), "é".repeat(15) + "a")) {
            assertThat(shortReference.getBytes(StandardCharsets.UTF_8)).hasSize(31);
            var selected = issuer(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE, shortReference);
            var session = selected.exchange(exchange(BOOTSTRAP));
            assertThat(session).isNotNull();
            var request = auditCommentRequest(session, "audit-comment-key");
            assertThat(selected.safeAuditComment(session, selected.mutationContext(session, request), request,
                    "audit-comment-key", "prefix " + shortReference + " suffix")).isTrue();
        }
    }

    @Test void auditCommentBindsCookieCsrfAuthorizationAndBoundedHeaderCardinality() {
        var session = issue();
        // Otherwise-valid issuer proof: change only the contract boundary under test.
        String maximumKey = "k".repeat(128);
        var bounded = auditCommentRequest(session, maximumKey);
        var boundedMutation = issuer.mutationContext(session, bounded);
        assertThat(boundedMutation).isNotNull();
        assertThat(issuer.safeAuditComment(session, boundedMutation, bounded, maximumKey, "Reviewed rationale")).isTrue();
        bounded.removeHeader("Idempotency-Key"); bounded.addHeader("Idempotency-Key", maximumKey + "k");
        assertThat(issuer.safeAuditComment(session, boundedMutation, bounded, maximumKey + "k", "Reviewed rationale")).isFalse();
        bounded.removeHeader("Idempotency-Key"); bounded.addHeader("Idempotency-Key", maximumKey);
        String cookiePrefix = GovernanceReviewerCredentials.COOKIE + "=" + session.token() + "; other=";
        String maximumRawCookie = cookiePrefix + "x".repeat(6000 - cookiePrefix.length());
        assertThat(maximumRawCookie.getBytes(StandardCharsets.UTF_8)).hasSize(6000);
        bounded.removeHeader("Cookie"); bounded.addHeader("Cookie", maximumRawCookie);
        assertThat(issuer.safeAuditComment(session, boundedMutation, bounded, maximumKey, "Reviewed rationale")).isTrue();
        int rawCookieBudget = 6000 - cookiePrefix.length();
        String maximumMultibyteCookie = cookiePrefix + "한".repeat(rawCookieBudget / 3) + "x".repeat(rawCookieBudget % 3);
        assertThat(maximumMultibyteCookie.getBytes(StandardCharsets.UTF_8)).hasSize(6000);
        bounded.removeHeader("Cookie"); bounded.addHeader("Cookie", maximumMultibyteCookie);
        assertThat(issuer.safeAuditComment(session, boundedMutation, bounded, maximumKey, "Reviewed rationale")).isTrue();
        String oversizedUtf8Cookie = cookiePrefix + "한".repeat((6000 - cookiePrefix.length()) / 3 + 1);
        assertThat(oversizedUtf8Cookie.length()).isLessThanOrEqualTo(6000);
        assertThat(oversizedUtf8Cookie.getBytes(StandardCharsets.UTF_8).length).isGreaterThan(6000);
        for (String invalidRawCookie : List.of("", "\uD800", oversizedUtf8Cookie)) {
            bounded.removeHeader("Cookie"); bounded.addHeader("Cookie", invalidRawCookie);
            assertThat(issuer.safeAuditComment(session, boundedMutation, bounded, maximumKey, "Reviewed rationale")).isFalse();
        }
        bounded.removeHeader("Cookie");
        var maximumCookies = new Cookie[6000];
        java.util.Arrays.fill(maximumCookies, new Cookie("other", "unrelated"));
        maximumCookies[5999] = new Cookie(GovernanceReviewerCredentials.COOKIE, session.token());
        bounded.setCookies(maximumCookies); bounded.removeHeader("Cookie");
        assertThat(issuer.safeAuditComment(session, boundedMutation, bounded, maximumKey, "Reviewed rationale")).isTrue();
        var oversizedCookies = java.util.Arrays.copyOf(maximumCookies, 6001);
        oversizedCookies[6000] = new Cookie("other", "unrelated");
        bounded.setCookies(oversizedCookies); bounded.removeHeader("Cookie");
        assertThat(issuer.safeAuditComment(session, boundedMutation, bounded, maximumKey, "Reviewed rationale")).isFalse();
        bounded.setCookies(new Cookie("other", "unrelated")); bounded.removeHeader("Cookie");
        assertThat(issuer.safeAuditComment(session, boundedMutation, bounded, maximumKey, "Reviewed rationale")).isFalse();

        var request = auditCommentRequest(session, "audit-comment-key");
        var mutation = issuer.mutationContext(session, request);
        request.removeHeader("Cookie");
        request.addHeader("Cookie", GovernanceReviewerCredentials.COOKIE + "=" + session.token());
        assertThat(issuer.safeAuditComment(session, mutation, request, "audit-comment-key", "Reviewed rationale")).isTrue();
        request.addHeader("Cookie", "extra=value");
        assertThat(issuer.safeAuditComment(session, mutation, request, "audit-comment-key", "Reviewed rationale")).isFalse();
        request.removeHeader("Cookie"); request.addHeader("Cookie", "x".repeat(6001));
        assertThat(issuer.safeAuditComment(session, mutation, request, "audit-comment-key", "Reviewed rationale")).isFalse();
        request.removeHeader("Cookie");
        request.addHeader("Authorization", "synthetic-comment-owned-auth-reference-at-least-32");
        assertThat(issuer.safeAuditComment(session, mutation, request, "audit-comment-key", "Reviewed rationale")).isFalse();
        request.removeHeader("Authorization"); request.addHeader("X-CSRF-Token", session.csrfToken());
        assertThat(issuer.safeAuditComment(session, mutation, request, "audit-comment-key", "Reviewed rationale")).isFalse();
        request.removeHeader("X-CSRF-Token"); request.addHeader("X-CSRF-Token", session.csrfToken());
        request.setCookies(new Cookie(GovernanceReviewerCredentials.COOKIE, "different-cookie"));
        assertThat(issuer.safeAuditComment(session, mutation, request, "audit-comment-key", "Reviewed rationale")).isFalse();
        request.setCookies(new Cookie(GovernanceReviewerCredentials.COOKIE, session.token()),
                new Cookie(GovernanceReviewerCredentials.COOKIE, session.token()));
        assertThat(issuer.safeAuditComment(session, mutation, request, "audit-comment-key", "Reviewed rationale")).isFalse();
        request.setCookies(new Cookie(GovernanceReviewerCredentials.COOKIE, session.token()),
                new Cookie(GovernanceReviewerCredentials.COOKIE, "different-cookie"));
        assertThat(issuer.safeAuditComment(session, mutation, request, "audit-comment-key", "Reviewed rationale")).isFalse();
        request.setCookies(new Cookie(GovernanceReviewerCredentials.COOKIE, session.token()));
        request.addHeader("Idempotency-Key", "duplicate-key");
        assertThat(issuer.safeAuditComment(session, mutation, request, "audit-comment-key", "Reviewed rationale")).isFalse();
    }

    private MockHttpServletRequest auditCommentRequest(GovernanceReviewerCredentials.Session session, String key) {
        var request = cookie(session.token());
        request.addHeader("X-CSRF-Token", session.csrfToken()); request.addHeader("Idempotency-Key", key);
        return request;
    }

    private GovernanceReviewerCredentials issuer(String bootstrap, String signing, String actor, String workspace, String cKey) {
        return new GovernanceReviewerCredentials(bootstrap, signing, actor, workspace, cKey, clock);
    }
    private void assertDeniedConfiguration(String bootstrap, String signing, String actor, String workspace, String cKey) {
        var invalid = issuer(bootstrap, signing, actor, workspace, cKey);
        assertThat(invalid.exchange(exchange(bootstrap))).isNull();
        assertThat(invalid.session(cookie(issue().token()))).isNull();
    }
    private GovernanceReviewerCredentials.Session issue() {
        var session = issuer.exchange(exchange(BOOTSTRAP)); assertThat(session).isNotNull(); return session;
    }
    private MockHttpServletRequest exchange(String key) {
        var request = new MockHttpServletRequest("GET", GovernanceReviewerCredentials.SESSION_PATH);
        request.addHeader("Authorization", "GovernanceBootstrap " + key); return request;
    }
    private MockHttpServletRequest cookie(String token) {
        var request = new MockHttpServletRequest(); request.setCookies(new Cookie(GovernanceReviewerCredentials.COOKIE, token)); return request;
    }
    private MockHttpServletRequest csrfRequest(String csrf) {
        var request = new MockHttpServletRequest(); request.addHeader("X-CSRF-Token", csrf); return request;
    }
    private ObjectNode payload(GovernanceReviewerCredentials.Session session) {
        return (ObjectNode) json.readTree(Base64.getUrlDecoder().decode(session.token().split("\\.")[0]));
    }
    private void assertRejected(ObjectNode payload) throws Exception {
        assertThat(issuer.session(cookie(sign(json.writeValueAsString(payload))))).isNull();
    }
    private String sign(String raw) throws Exception { return sign(raw, SIGNING); }
    private String sign(String raw, String key) throws Exception {
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
        return signPayload(payload, key);
    }
    private String signPayload(String payload, String key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return payload + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(
                mac.doFinal((GovernanceReviewerCredentials.PURPOSE + ":" + payload).getBytes(StandardCharsets.UTF_8)));
    }
    private int concurrentExchanges(GovernanceReviewerCredentials credentials, int count) throws Exception {
        try (var workers = Executors.newFixedThreadPool(16)) {
            var jobs = new ArrayList<Callable<Boolean>>();
            for (int n = 0; n < count; n++) jobs.add(() -> credentials.exchange(exchange(BOOTSTRAP)) != null);
            int successes = 0;
            for (var result : workers.invokeAll(jobs, 10, TimeUnit.SECONDS)) if (result.get(2, TimeUnit.SECONDS)) successes++;
            return successes;
        }
    }
    private int windowSize(GovernanceReviewerCredentials credentials, String field) throws Exception {
        var window = GovernanceReviewerCredentials.class.getDeclaredField(field); window.setAccessible(true);
        return ((Deque<?>) window.get(credentials)).size();
    }
    private String originalRaw(GovernanceReviewerCredentials.Session session) {
        return new String(Base64.getUrlDecoder().decode(session.token().split("\\.")[0]), StandardCharsets.UTF_8);
    }

    private String actualCompleteTokenTimeKey(GovernanceReviewerCredentials.Session control) {
        ObjectNode body = payload(control);
        String span = "\"issuedAt\":" + body.path("issuedAt").longValue()
                + ",\"expiresAt\":" + body.path("expiresAt").longValue();
        String raw = originalRaw(control);
        int charOffset = raw.indexOf(span);
        assertThat(charOffset).isGreaterThanOrEqualTo(0);
        assertThat(raw.lastIndexOf(span)).isEqualTo(charOffset);
        byte[] bytes = raw.getBytes(StandardCharsets.UTF_8);
        int byteOffset = raw.substring(0, charOffset).getBytes(StandardCharsets.UTF_8).length;
        int spanEnd = byteOffset + span.getBytes(StandardCharsets.UTF_8).length;
        int start = (byteOffset + 2) / 3 * 3;
        int end = spanEnd / 3 * 3;
        assertThat(end).isGreaterThan(start);
        String key = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(java.util.Arrays.copyOfRange(bytes, start, end));
        assertThat(key.getBytes(StandardCharsets.UTF_8).length).isGreaterThanOrEqualTo(32);
        assertThat(control.token().split("\\.")[0]).contains(key);
        return key;
    }

    private String actualViewTimeKey(long expires) {
        return "\"expiresAt\":" + expires + ",\"actorId\":\"" + ACTOR + "\"";
    }

    private String projectedActualView(ObjectNode claims) {
        return json.writeValueAsString(json.createObjectNode().put("csrfToken", claims.path("csrf").stringValue())
                .put("expiresAt", claims.path("expiresAt").longValue()).put("actorId", claims.path("actor").stringValue())
                .put("workspaceId", claims.path("workspace").stringValue()).put("role", claims.path("role").stringValue())
                .put("sessionId", claims.path("sessionId").stringValue()).put("demoMode", claims.path("demoMode").booleanValue()));
    }

    private ObjectNode claimsForConfiguredKeys(ObjectNode source, String bootstrap, String signing) throws Exception {
        String encodedBootstrap = Base64.getUrlEncoder().withoutPadding().encodeToString(bootstrap.getBytes(StandardCharsets.UTF_8));
        String encodedActor = Base64.getUrlEncoder().withoutPadding().encodeToString(ACTOR.getBytes(StandardCharsets.UTF_8));
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(signing.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        String generation = Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(
                ("FINSEC_GOVERNANCE_AUTHORITY_V1:" + encodedBootstrap + ":" + encodedActor + ":" + WORKSPACE)
                        .getBytes(StandardCharsets.UTF_8)));
        return source.deepCopy().put("generation", generation);
    }

    private static final class MutableClock extends Clock {
        private Instant now = Instant.parse("2026-10-02T18:00:00Z");
        void advance(long seconds) { now = now.plusSeconds(seconds); }
        void set(Instant value) { now = value; }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
