package com.finsecseal.platform.governance;

import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.Collections;
import java.util.Deque;
import java.util.Set;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/** Separate governance issuer; bootstrap credentials never sign sessions. */
@Component
public final class GovernanceReviewerCredentials {
    public static final String COOKIE = "__Host-FINSEC_GOVERNANCE";
    public static final String SESSION_PATH = "/api/v1/governance-reviewer-session";
    static final String PURPOSE = "FINSEC_GOVERNANCE_SESSION_V1";
    private static final String BOOTSTRAP_SCHEME = "GovernanceBootstrap ";
    private static final long LIFETIME_SECONDS = 1800;
    private static final int MAX_OUTPUT_UTF8_BYTES = 6000;
    private static final Set<String> FIELDS = Set.of("purpose", "sessionId", "csrf", "issuedAt",
            "expiresAt", "actor", "workspace", "role", "demoMode", "generation");
    private static final ObjectMapper JSON = JsonMapper.builder(JsonFactory.builder()
                    .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(2)
                            .maxStringLength(256).maxNameLength(32).maxNumberLength(19)
                            .maxTokenCount(128).build())
                    .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                    .disable(StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION).build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY)
            .enable(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS).build();

    private final String bootstrapKey;
    private final String signingKey;
    private final String actor;
    private final UUID workspace;
    private final Clock clock;
    private final boolean configured;
    // Sensitive derived privacy capability; neither raw C credentials nor C authentication authority.
    private final int contractReferenceByteLength;
    private final byte[] contractReferenceFingerprint;
    // One node's bounded sliding windows. Rejected requests do not grow either deque.
    private final Deque<Instant> attempts = new ArrayDeque<>();
    private final Deque<Instant> issuances = new ArrayDeque<>();

    @Autowired
    public GovernanceReviewerCredentials(
            @Value("${finsec.governance-access.bootstrap-key:}") String bootstrapKey,
            @Value("${finsec.governance-access.signing-key:}") String signingKey,
            @Value("${finsec.governance-access.actor:}") String actor,
            @Value("${finsec.governance-access.workspace:}") String workspace,
            @Value("${finsec.contract-access.key:}") String contractKey) {
        this(bootstrapKey, signingKey, actor, workspace, contractKey, Clock.systemUTC());
    }

    GovernanceReviewerCredentials(String bootstrapKey, String signingKey, String actor,
            String workspace, String contractKey, Clock clock) {
        this.bootstrapKey = bootstrapKey;
        this.signingKey = signingKey;
        this.actor = actor;
        this.workspace = canonicalUuid(workspace);
        this.clock = java.util.Objects.requireNonNull(clock);
        if (unsafeSuppliedCredential(bootstrapKey, actor, workspace, this.workspace)
                || unsafeSuppliedCredential(signingKey, actor, workspace, this.workspace)
                || credentialInPublicMetadata(contractKey, actor, workspace, this.workspace)
                || credentialInOwnedFailureOutput(contractKey)
                || credentialInOwnedCookieOutput(contractKey)
                || contractCredentialCouldBeUuidTraceSubstring(contractKey)) {
            throw new IllegalArgumentException("Unsafe governance config");
        }
        // Match the existing C signer UTF8 replacement representation, without retaining raw C.
        // A UTF16 length above the frame byte bound cannot fit any bounded UTF8 output frame.
        byte[] contractReference = contractKey == null || contractKey.length() > MAX_OUTPUT_UTF8_BYTES
                ? new byte[0] : contractKey.getBytes(StandardCharsets.UTF_8);
        try {
            this.contractReferenceByteLength = contractReference.length >= 32
                    && contractReference.length <= MAX_OUTPUT_UTF8_BYTES ? contractReference.length : 0;
            this.contractReferenceFingerprint = contractReferenceByteLength == 0
                    ? null : outputPrivacyDigest().digest(contractReference);
        } finally { java.util.Arrays.fill(contractReference, (byte) 0); }
        this.configured = validKey(bootstrapKey) && validKey(signingKey)
                && !equal(bootstrapKey, signingKey)
                && !equal(bootstrapKey, contractKey) && !equal(signingKey, contractKey)
                && this.workspace != null && actor != null && !actor.isBlank()
                && actor.length() <= 120 && actor.equals(actor.strip())
                && actor.codePoints().noneMatch(Character::isISOControl);
    }

    /** Only the exact GET can consume a bootstrap attempt and issue a session. */
    synchronized Session exchange(HttpServletRequest request) {
        if (!"GET".equals(request.getMethod()) || !SESSION_PATH.equals(request.getRequestURI())
                || request.getQueryString() != null) return null;
        Instant eventTime = clock.instant();
        long now = eventTime.getEpochSecond();
        trim(attempts, eventTime.minusSeconds(60));
        trim(issuances, eventTime.minusSeconds(LIFETIME_SECONDS));
        if (attempts.size() >= 60) return null;
        attempts.addLast(eventTime);
        String authorization = singleHeader(request, "Authorization");
        if (!configured || authorization == null || !authorization.startsWith(BOOTSTRAP_SCHEME)
                || authorization.length() > 4096) return null;
        String supplied = authorization.substring(BOOTSTRAP_SCHEME.length());
        if (supplied.isEmpty() || supplied.codePoints().anyMatch(c ->
                Character.isWhitespace(c) || Character.isISOControl(c))
                || !equal(bootstrapKey, supplied) || issuances.size() >= 32) return null;
        UUID sessionId = UUID.randomUUID();
        String csrf = UUID.randomUUID() + ":" + UUID.randomUUID();
        long expires = now + LIFETIME_SECONDS;
        String generation = currentGeneration();
        var body = JSON.createObjectNode().put("purpose", PURPOSE).put("sessionId", sessionId.toString())
                .put("csrf", csrf).put("issuedAt", now).put("expiresAt", expires).put("actor", actor)
                .put("workspace", workspace.toString()).put("role", GovernanceReviewerContext.ROLE)
                .put("demoMode", true).put("generation", generation);
        byte[] raw = JSON.writeValueAsBytes(body);
        String payload = encode(raw);
        String token = payload + "." + signature(payload);
        // Render once: Expires depends on the renderer clock. Emit this exact checked header.
        String issuanceCookieHeader = ResponseCookie.from(COOKIE, token).httpOnly(true).secure(true)
                .sameSite("Lax").path("/").maxAge(LIFETIME_SECONDS).build().toString();
        if (!safeActualOutput(raw, token, csrf, sessionId, expires, issuanceCookieHeader)) return null;
        Session session = new Session(this, token, csrf,
                context(sessionId, now, expires, generation, false), issuanceCookieHeader);
        issuances.addLast(eventTime);
        return session;
    }

    /** Key safety only: secrets and recognizable CSRF shapes must never enter admission storage. */
    boolean safeIdempotencyKey(Session session, String key) {
        if (!configured || session == null || session.issuer != this || key == null || key.length() > 128) return false;
        if (key.contains(bootstrapKey) || key.contains(signingKey)
                || key.contains(session.csrf) || key.contains(session.token)) return false;
        for (int start = 0; start + 73 <= key.length(); start++) {
            if (validCsrf(key.substring(start, start + 73))) return false;
        }
        // Same private C privacy capability; the early filter rejects before reservation or replay.
        return safeContractOutputFrame(key);
    }

    /** A cookie read never issues or renews a session. Durable revocation is checked by access. */
    Session session(HttpServletRequest request) {
        if (!configured || request.getCookies() == null) return null;
        String token = null;
        for (var cookie : request.getCookies()) {
            if (COOKIE.equals(cookie.getName())) {
                if (token != null) return null;
                token = cookie.getValue();
            }
        }
        if (token == null || token.length() > 2048) return null;
        try {
            String[] parts = token.split("\\.", -1);
            if (parts.length != 2 || !parts[0].matches("[A-Za-z0-9_-]+")
                    || !parts[1].matches("[A-Za-z0-9_-]{43}")
                    || !equal(signature(parts[0]), parts[1])) return null;
            byte[] decoded = Base64.getUrlDecoder().decode(parts[0]);
            if (!encode(decoded).equals(parts[0])) return null;
            JsonNode body = JSON.readTree(decoded);
            if (body == null || !body.isObject() || body.size() != FIELDS.size()
                    || body.properties().stream().anyMatch(e -> !FIELDS.contains(e.getKey()))) return null;
            for (String field : Set.of("purpose", "sessionId", "csrf", "actor", "workspace", "role", "generation")) {
                if (!body.path(field).isTextual()) return null;
            }
            if (!PURPOSE.equals(body.path("purpose").stringValue())
                    || !actor.equals(body.path("actor").stringValue())
                    || !workspace.toString().equals(body.path("workspace").stringValue())
                    || !GovernanceReviewerContext.ROLE.equals(body.path("role").stringValue())
                    || !body.path("demoMode").isBoolean() || !body.path("demoMode").booleanValue()
                    || !equal(currentGeneration(), body.path("generation").stringValue())) return null;
            UUID sessionId = canonicalUuid(body.path("sessionId").stringValue());
            String csrf = body.path("csrf").stringValue();
            if (sessionId == null || !validCsrf(csrf)
                    || !nonnegativeLong(body.path("issuedAt")) || !nonnegativeLong(body.path("expiresAt"))) return null;
            long issuedAt = body.path("issuedAt").longValue();
            long expires = body.path("expiresAt").longValue();
            if (!validTime(issuedAt, expires)
                    || !safeActualOutput(decoded, token, csrf, sessionId, expires, null)) return null;
            return new Session(this, token, csrf,
                    context(sessionId, issuedAt, expires, currentGeneration(), false), null);
        } catch (RuntimeException invalid) {
            // Parser details may include attacker-controlled secrets: never echo or log them.
            return null;
        }
    }

    GovernanceReviewerContext mutationContext(Session session, HttpServletRequest request) {
        if (session == null || session.issuer != this || !current(session.context, false)
                || !equal(session.csrf, singleHeader(request, "X-CSRF-Token"))) return null;
        var identity = session.context;
        return context(identity.sessionId(), identity.issuedAt(), identity.expiresAt(), identity.generation(), true);
    }

    boolean current(GovernanceReviewerContext context, boolean mutationRequired) {
        return configured && context != null && context.belongsTo(this)
                && actor.equals(context.actorId()) && workspace.equals(context.workspaceId())
                && equal(currentGeneration(), context.generation())
                && validTime(context.issuedAt(), context.expiresAt())
                && (!mutationRequired || context.csrfVerified());
    }

    private GovernanceReviewerContext context(UUID sessionId, long issuedAt, long expires,
            String generation, boolean mutation) {
        Proof proof = new Proof(this, workspace, actor, sessionId, issuedAt, expires, generation, mutation);
        return GovernanceReviewerContext.issued(proof, workspace, actor, sessionId,
                issuedAt, expires, generation, mutation);
    }

    private boolean validTime(long issuedAt, long expires) {
        long now = clock.instant().getEpochSecond();
        return issuedAt >= 0 && issuedAt <= now && expires > now && expires > issuedAt
                && expires - issuedAt <= LIFETIME_SECONDS;
    }

    private String currentGeneration() {
        return mac("FINSEC_GOVERNANCE_AUTHORITY_V1:" + encode(bootstrapKey.getBytes(StandardCharsets.UTF_8))
                + ":" + encode(actor.getBytes(StandardCharsets.UTF_8)) + ":" + workspace);
    }

    private String signature(String payload) { return mac(PURPOSE + ":" + payload); }

    private String mac(String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(signingKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return encode(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.GeneralSecurityException failure) {
            throw new IllegalStateException("Governance signature unavailable");
        }
    }

    static String singleHeader(HttpServletRequest request, String name) {
        var headers = request.getHeaders(name);
        if (headers == null) return null;
        var values = Collections.list(headers);
        return values.size() == 1 ? values.getFirst() : null;
    }

    static UUID canonicalUuid(String text) {
        try {
            UUID id = UUID.fromString(text);
            return id.toString().equals(text) ? id : null;
        } catch (RuntimeException invalid) { return null; }
    }

    private static boolean validCsrf(String csrf) {
        if (csrf == null || csrf.length() != 73 || csrf.charAt(36) != ':') return false;
        return canonicalUuid(csrf.substring(0, 36)) != null && canonicalUuid(csrf.substring(37)) != null;
    }

    private static boolean nonnegativeLong(JsonNode value) {
        return value.isIntegralNumber() && value.bigIntegerValue().signum() >= 0
                && value.bigIntegerValue().bitLength() <= 63;
    }

    private static boolean credentialInPublicMetadata(String key, String actor,
            String rawWorkspace, UUID canonicalWorkspace) {
        // Preserve empty/short blank defaults, but a >=32-byte C reference may be configured
        // even if it is whitespace. No supplied reference is normalized or retained here.
        if (key == null || (key.isBlank() && key.getBytes(StandardCharsets.UTF_8).length < 32)) return false;
        return (actor != null && actor.contains(key))
                || (rawWorkspace != null && rawWorkspace.contains(key))
                || (canonicalWorkspace != null && canonicalWorkspace.toString().contains(key))
                || credentialInSerializedMetadata(key, actor, canonicalWorkspace);
    }

    private static boolean credentialInSerializedMetadata(String key, String actor, UUID workspace) {
        // These spans end at a real property opening, never at an invented dynamic value.
        String purposePrefix = "{" + serializedFields(JSON.createObjectNode().put("purpose", PURPOSE))
                + "," + fieldOpening("sessionId");
        String issuerRole = "," + serializedFields(JSON.createObjectNode()
                .put("role", GovernanceReviewerContext.ROLE).put("demoMode", true))
                + "," + fieldOpening("generation");
        String viewRole = "," + serializedFields(JSON.createObjectNode()
                .put("role", GovernanceReviewerContext.ROLE)) + "," + fieldOpening("sessionId");
        if (publicSpanContains(key, purposePrefix, true)
                || publicSpanContains(key, issuerRole, false)
                || viewRole.contains(key)) return true;
        if (actor == null || workspace == null) return false;
        String claims = "," + serializedFields(JSON.createObjectNode().put("actor", actor)
                .put("workspace", workspace.toString()).put("role", GovernanceReviewerContext.ROLE)
                .put("demoMode", true)) + "," + fieldOpening("generation");
        String view = "," + serializedFields(JSON.createObjectNode().put("actorId", actor)
                .put("workspaceId", workspace.toString()).put("role", GovernanceReviewerContext.ROLE))
                + "," + fieldOpening("sessionId");
        return publicSpanContains(key, claims, false) || view.contains(key);
    }

    private static String serializedFields(JsonNode fields) {
        String object = new String(JSON.writeValueAsBytes(fields), StandardCharsets.UTF_8);
        return object.substring(1, object.length() - 1);
    }

    private static String fieldOpening(String name) { return JSON.writeValueAsString(name) + ":\""; }

    private static boolean publicSpanContains(String key, String span, boolean actualPrefix) {
        if (span.contains(key)) return true;
        byte[] bytes = span.getBytes(StandardCharsets.UTF_8);
        // Only complete, entirely known three-byte groups occur in the actual payload encoding.
        for (int start = 0; start < (actualPrefix ? 1 : 3); start++) {
            int end = start + (bytes.length - start) / 3 * 3;
            if (end > start && encode(java.util.Arrays.copyOfRange(bytes, start, end)).contains(key)) return true;
        }
        return false;
    }

    private boolean safeActualOutput(byte[] originalRaw, String token, String csrf, UUID sessionId,
            long expires, String issuanceCookieHeader) {
        if (originalRaw.length > MAX_OUTPUT_UTF8_BYTES) return false;
        String raw = new String(originalRaw, StandardCharsets.UTF_8);
        // Same seven fields and order as the actual controller SessionView; no context is minted here.
        String view = new String(JSON.writeValueAsBytes(JSON.createObjectNode().put("csrfToken", csrf)
                .put("expiresAt", expires).put("actorId", actor).put("workspaceId", workspace.toString())
                .put("role", GovernanceReviewerContext.ROLE).put("sessionId", sessionId.toString())
                .put("demoMode", true)), StandardCharsets.UTF_8);
        for (String key : new String[]{bootstrapKey, signingKey}) {
            if (raw.contains(key) || token.contains(key) || view.contains(key)
                    || (issuanceCookieHeader != null && issuanceCookieHeader.contains(key))) return false;
        }
        return safeContractOutputFrame(originalRaw) && safeContractOutputFrame(token)
                && safeContractOutputFrame(view)
                && (issuanceCookieHeader == null || safeContractOutputFrame(issuanceCookieHeader));
    }

    /** A-package response transport guard; no public credential/reference comparison API. */
    boolean safeActualResponseFrame(byte[] exactUtf8Frame) {
        if (exactUtf8Frame == null || exactUtf8Frame.length > MAX_OUTPUT_UTF8_BYTES) return false;
        for (String key : new String[]{bootstrapKey, signingKey}) {
            // Keep blank/short disabled defaults; inspect whole supplied references at the UTF8 privacy floor.
            if (key == null || key.length() > MAX_OUTPUT_UTF8_BYTES) continue;
            byte[] reference = key.getBytes(StandardCharsets.UTF_8);
            try {
                if (reference.length >= 32 && containsExactBytes(exactUtf8Frame, reference)) return false;
            } finally { java.util.Arrays.fill(reference, (byte) 0); }
        }
        return safeContractOutputFrame(exactUtf8Frame);
    }

    private static boolean containsExactBytes(byte[] frame, byte[] reference) {
        if (reference.length == 0 || reference.length > frame.length) return false;
        for (int start = 0; start <= frame.length - reference.length; start++) {
            int offset = 0;
            while (offset < reference.length && frame[start + offset] == reference[offset]) offset++;
            if (offset == reference.length) return true;
        }
        return false;
    }

    private boolean safeContractOutputFrame(String frame) {
        // Bound allocation first; UTF8 output takes at least one byte per UTF16 unit.
        if (frame == null || frame.length() > MAX_OUTPUT_UTF8_BYTES) return false;
        return safeContractOutputFrame(frame.getBytes(StandardCharsets.UTF_8));
    }

    private boolean safeContractOutputFrame(byte[] frame) {
        if (frame == null || frame.length > MAX_OUTPUT_UTF8_BYTES) return false;
        if (contractReferenceFingerprint == null || frame.length < contractReferenceByteLength) return true;
        MessageDigest digest = outputPrivacyDigest();
        for (int start = 0; start <= frame.length - contractReferenceByteLength; start++) {
            digest.update(frame, start, contractReferenceByteLength);
            byte[] candidateFingerprint = digest.digest(); // digest resets for the next exact-byte window.
            boolean match;
            try { match = MessageDigest.isEqual(contractReferenceFingerprint, candidateFingerprint); }
            finally { java.util.Arrays.fill(candidateFingerprint, (byte) 0); }
            if (match) return false;
        }
        return true;
    }

    private static MessageDigest outputPrivacyDigest() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (java.security.NoSuchAlgorithmException unavailable) {
            // Provider details and credential-derived bytes must not become an exception cause/message.
            throw new IllegalStateException("Privacy check unavailable");
        }
    }

    private static boolean unsafeSuppliedCredential(String key, String actor,
            String rawWorkspace, UUID canonicalWorkspace) {
        return credentialInPublicMetadata(key, actor, rawWorkspace, canonicalWorkspace)
                || couldBeUuidTraceSubstring(key) || credentialInOwnedFailureOutput(key)
                || credentialInOwnedCookieOutput(key);
    }

    private static boolean credentialInOwnedCookieOutput(String key) {
        // Match supplied A/C references against actual known output, even if C is disabled/partial.
        // Raw C is not retained; private C comparisons cover dynamic output and idempotency frames.
        if (key == null || key.getBytes(StandardCharsets.UTF_8).length < 32) return false;
        String claimsPrefix = "{" + serializedFields(JSON.createObjectNode().put("purpose", PURPOSE))
                + "," + fieldOpening("sessionId");
        byte[] bytes = claimsPrefix.getBytes(StandardCharsets.UTF_8);
        // Every complete six-bit group is fixed by the known prefix, including a partial-byte group.
        // Present prefix: 55 bytes -> 73 known characters. The next character depends on unknown bits.
        int knownBase64Characters = bytes.length * 8 / 6;
        String cookiePrefix = COOKIE + "=" + encode(bytes).substring(0, knownBase64Characters);
        // Expires is dynamic and lies before this actual contiguous trailing attribute span.
        // Same exact builder as the existing Filter logout clear-cookie (Max-Age=0, epoch Expires).
        String clearCookie = ResponseCookie.from(COOKIE, "").httpOnly(true).secure(true)
                .sameSite("Lax").path("/").maxAge(0).build().toString();
        return cookiePrefix.contains(key) || "; Secure; HttpOnly; SameSite=Lax".contains(key)
                || clearCookie.contains(key);
    }

    private static boolean credentialInOwnedFailureOutput(String key) {
        // Fixed-output references use the UTF8 floor, not A's nonblank issuance condition.
        // Existing C configured() may accept whitespace. Short/empty defaults are preserved.
        if (key == null || key.getBytes(StandardCharsets.UTF_8).length < 32) return false;
        for (String span : new String[]{
                "Use the exact canonical governance API path and method",
                "Current governance session authority required",
                "A single safe Idempotency-Key is required",
                "Governance authority storage unavailable",
                "GOVERNANCE_AUTHORITY_STORAGE_UNAVAILABLE category=AUTHORITY_STORAGE classification=DATA_ACCESS_EXCEPTION trace=UNAVAILABLE",
                "com.finsecseal.platform.governance.GovernanceAccessFilter",
                "Current admitted governance mutation authority required",
                "Current governance reviewer authority required",
                "Governance signature unavailable",
                "GovernanceReviewerContext[redacted]",
                "GovernanceMutationContext[redacted]",
                "GovernanceIssuerProof[redacted]",
                "GovernanceFilterFacts[redacted]",
                "GovernanceSession[redacted]",
                "Unsafe governance config",
                ownedProblemPrefix(400, "Bad Request", "VALIDATION_ERROR",
                        "Use the exact canonical governance API path and method"),
                ownedProblemPrefix(400, "Bad Request", "VALIDATION_ERROR",
                        "A single safe Idempotency-Key is required"),
                ownedProblemPrefix(403, "Forbidden", "OPERATOR_AUTH_REQUIRED",
                        "Current governance session authority required"),
                ownedProblemPrefix(500, "Internal Server Error", "INTERNAL_ERROR",
                        "Governance authority storage unavailable")}) {
            if (span.contains(key)) return true;
        }
        return false;
    }

    private static String ownedProblemPrefix(int status, String title, String code, String detail) {
        // Same actual ordered node as the A filter. Stop at trace VALUE, never invent dynamic data.
        return "{" + serializedFields(JSON.createObjectNode().put("status", status).put("title", title)
                .put("code", code).put("detail", detail)) + "," + fieldOpening("traceId");
    }

    private static boolean contractCredentialCouldBeUuidTraceSubstring(String key) {
        // C privacy floor applies even when actor/workspace/C authority is disabled or partial.
        // Short/default references remain unchanged; >36 units cannot fit the existing UUID trace shape.
        if (key == null || key.isBlank() || key.length() > 36) return false;
        byte[] reference = key.getBytes(StandardCharsets.UTF_8);
        try { return reference.length >= 32 && couldBeUuidTraceSubstring(key); }
        finally { java.util.Arrays.fill(reference, (byte) 0); }
    }

    private static boolean couldBeUuidTraceSubstring(String key) {
        if (key == null || key.isBlank() || key.length() > 36) return false;
        int hyphens = 0;
        for (int index = 0; index < key.length(); index++) {
            if (key.charAt(index) == '-' && ++hyphens > 4) return false;
        }
        for (int firstGroup = 0; firstGroup <= 4 - hyphens; firstGroup++) {
            String beforeGroups = "0-".repeat(firstGroup);
            String afterGroups = "-0".repeat(4 - hyphens - firstGroup);
            for (int beforeEdge = 0; beforeEdge < 2; beforeEdge++) {
                for (int afterEdge = 0; afterEdge < 2; afterEdge++) {
                    String candidate = beforeGroups + (beforeEdge == 0 ? "" : "0")
                            + key + (afterEdge == 0 ? "" : "0") + afterGroups;
                    if (candidate.length() > 36) continue;
                    try {
                        UUID.fromString(candidate);
                        return true;
                    } catch (IllegalArgumentException ignored) {
                        // Parser messages can contain the key: never inspect, chain or log them.
                    }
                }
            }
        }
        return false;
    }

    private static boolean validKey(String key) {
        return key != null && !key.isBlank() && key.getBytes(StandardCharsets.UTF_8).length >= 32;
    }

    private static String encode(byte[] value) { return Base64.getUrlEncoder().withoutPadding().encodeToString(value); }
    private static boolean equal(String expected, String supplied) {
        return expected != null && supplied != null && MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8), supplied.getBytes(StandardCharsets.UTF_8));
    }
    private static void trim(Deque<Instant> values, Instant oldest) {
        while (!values.isEmpty() && !values.getFirst().isAfter(oldest)) values.removeFirst();
    }

    /** Only this enclosing issuer can mint a proof; Context exposes no proof accessor. */
    static final class Proof {
        private final GovernanceReviewerCredentials issuer;
        private final UUID workspace;
        private final String actor;
        private final UUID session;
        private final long issued;
        private final long expires;
        private final String generation;
        private final boolean mutation;
        private Proof(GovernanceReviewerCredentials issuer, UUID workspace, String actor, UUID session,
                long issued, long expires, String generation, boolean mutation) {
            this.issuer = issuer; this.workspace = workspace; this.actor = actor; this.session = session;
            this.issued = issued; this.expires = expires; this.generation = generation; this.mutation = mutation;
        }
        boolean matches(GovernanceReviewerCredentials expectedIssuer, UUID expectedWorkspace,
                String expectedActor, UUID expectedSession, long expectedIssued, long expectedExpires,
                String expectedGeneration, boolean expectedMutation) {
            return issuer == expectedIssuer && workspace.equals(expectedWorkspace) && actor.equals(expectedActor)
                    && session.equals(expectedSession) && issued == expectedIssued && expires == expectedExpires
                    && generation.equals(expectedGeneration) && mutation == expectedMutation;
        }
        @Override public String toString() { return "GovernanceIssuerProof[redacted]"; }
    }

    static final class Session {
        private final GovernanceReviewerCredentials issuer;
        private final String token;
        private final String csrf;
        private final GovernanceReviewerContext context;
        private final String issuanceCookieHeader;
        private Session(GovernanceReviewerCredentials issuer, String token, String csrf,
                GovernanceReviewerContext context, String issuanceCookieHeader) {
            this.issuer = issuer; this.token = token; this.csrf = csrf; this.context = context;
            this.issuanceCookieHeader = issuanceCookieHeader;
        }
        String token() { return token; }
        String csrfToken() { return csrf; }
        String issuanceCookieHeader() { return issuanceCookieHeader; }
        boolean safeActualResponseFrame(byte[] exactUtf8Frame) {
            return issuer.safeActualResponseFrame(exactUtf8Frame);
        }
        GovernanceReviewerContext identity() { return context; }
        @Override public String toString() { return "GovernanceSession[redacted]"; }
    }
}
