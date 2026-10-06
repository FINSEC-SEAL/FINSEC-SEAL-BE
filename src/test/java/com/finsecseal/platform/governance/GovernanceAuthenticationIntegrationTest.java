package com.finsecseal.platform.governance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.FinsecSealApplication;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.IdempotencyFilter;
import com.finsecseal.common.api.IdempotencyInstanceLease;
import com.finsecseal.common.api.TraceIdFilter;
import com.finsecseal.release.DigestService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.Connection;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.MethodOrderer;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.server.servlet.context.ServletWebServerApplicationContext;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.ConnectionHolder;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/** Actual issuer/filter/common admission/JPA/PostgreSQL; continuation probes never make D decisions. */
@Testcontainers
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Import(GovernanceAuthenticationIntegrationTest.ProbeConfiguration.class)
@SpringBootTest(classes = FinsecSealApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "finsec.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "finsec.cors.allowed-origins=http://localhost:5173",
        "finsec.scheduling.enabled=false", "finsec.generation.worker-enabled=false",
        "spring.datasource.hikari.maximum-pool-size=8",
        "finsec.governance-access.bootstrap-key=synthetic-governance-http-bootstrap-at-least-32-bytes",
        "finsec.governance-access.signing-key=synthetic-governance-http-signing-at-least-32-bytes",
        "finsec.governance-access.actor=governance-http-reviewer",
        "finsec.governance-access.workspace=0198f1e2-0000-7000-8000-000000000001",
        "finsec.contract-access.key=separate-contract-http-key-at-least-32-bytes"
})
class GovernanceAuthenticationIntegrationTest {
    private static final String BOOTSTRAP = "synthetic-governance-http-bootstrap-at-least-32-bytes";
    private static final String SIGNING = "synthetic-governance-http-signing-at-least-32-bytes";
    private static final String ACTOR = "governance-http-reviewer";
    private static final String CONTRACT_KEY = "separate-contract-http-key-at-least-32-bytes";
    private static final UUID WORKSPACE = UUID.fromString("0198f1e2-0000-7000-8000-000000000001");
    private static final String SESSION = GovernanceReviewerCredentials.SESSION_PATH;
    private static final String KNOWN_COOKIE_TRANSPORT_98 = "__Host-FINSEC_GOVERNANCE=eyJwdXJwb3NlIjoiRklOU0VDX0dPVkVSTkFOQ0VfU0VTU0lPTl9WMSIsInNlc3Npb25JZCI6I";
    private static final List<String> GOVERNED = List.of("findings", "agent_releases", "agents",
            "test_runs", "test_case_runs", "oracle_results", "audit_records");

    @Container @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");
    @LocalServerPort int port;
    @Autowired ServletWebServerApplicationContext webServerContext;
    @Autowired JdbcTemplate db;
    @Autowired ObjectMapper json;
    @Autowired DigestService digest;
    @Autowired GovernanceReviewerCredentials issuer;
    @Autowired GovernanceReviewerSessionRevocations revocations;
    @Autowired GovernanceAccess access;
    @Autowired GovernanceAccessFilter filter;
    @Autowired GovernanceReviewerSessionController controller;
    @Autowired IdempotencyFilter common;
    @Autowired IdempotencyInstanceLease instance;
    @Autowired TraceIdFilter trace;
    @Autowired PlatformTransactionManager transactions;
    @Autowired ContinuationProbe probe;
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    @Test void exchangeAndCookieOnlyCurrentExposeSevenFieldsWithoutRenewalOrSecrets() throws Exception {
        var before = snapshot(GOVERNED);
        var exchange = http("GET", SESSION, null, List.of("Authorization", "GovernanceBootstrap " + BOOTSTRAP,
                "Origin", "http://localhost:5173"));
        assertThat(exchange.statusCode()).withFailMessage(exchange.body()).isEqualTo(200);
        assertThat(exchange.headers().allValues("Access-Control-Allow-Origin")).containsExactly("http://localhost:5173");
        assertThat(exchange.headers().firstValue("Access-Control-Allow-Credentials")).contains("true");
        assertNoStore(exchange);
        String setCookie = exchange.headers().firstValue("Set-Cookie").orElseThrow();
        assertThat(setCookie).contains(GovernanceReviewerCredentials.COOKIE + "=", "Path=/", "Max-Age=1800",
                "Secure", "HttpOnly", "SameSite=Lax").doesNotContain("Domain=");
        JsonNode view = json.readTree(exchange.body()).path("data");
        assertThat(view.properties().stream().map(Map.Entry::getKey).toList()).containsExactlyInAnyOrder(
                "csrfToken", "expiresAt", "actorId", "workspaceId", "role", "sessionId", "demoMode");
        assertThat(view.path("expiresAt").isIntegralNumber()).isTrue();
        assertThat(view.path("expiresAt").longValue()).isBetween(Instant.now().getEpochSecond() + 1700,
                Instant.now().getEpochSecond() + 1800);
        assertThat(view.path("actorId").asString()).isEqualTo(ACTOR);
        assertThat(view.path("workspaceId").asString()).isEqualTo(WORKSPACE.toString());
        assertThat(view.path("role").asString()).isEqualTo("AI_GOVERNANCE_REVIEWER");
        assertThat(view.path("demoMode").booleanValue()).isTrue();
        String cookie = setCookie.split(";", 2)[0];
        var current = http("GET", SESSION, null, List.of("Cookie", cookie, "Origin", "http://localhost:5173"));
        assertThat(current.statusCode()).isEqualTo(200);
        assertThat(json.readTree(current.body()).path("data")).isEqualTo(view);
        assertThat(current.headers().allValues("Set-Cookie")).isEmpty();
        assertNoStore(current);
        assertThat(exchange.body() + current.body()).doesNotContain(BOOTSTRAP, SIGNING, cookie.split("=", 2)[1],
                "signature", "generation", "cookieToken");
        assertThat(snapshot(GOVERNED)).isEqualTo(before);
    }

    @Test @ExtendWith(OutputCaptureExtension.class)
    void unsafeSuppliedConfigurationRefusesRealSpringStartupBeforeReady(CapturedOutput output) {
        var before = snapshot(withAdmission());
        String uuidKey = "abcdefab-1234-5678-9abc-def012345678";
        List<String[]> unsafe = new ArrayList<>(List.of(
                new String[]{BOOTSTRAP, SIGNING, SIGNING, WORKSPACE.toString(), CONTRACT_KEY},
                new String[]{uuidKey, "", "", "", CONTRACT_KEY},
                new String[]{BOOTSTRAP, SIGNING, "wrapped-" + CONTRACT_KEY, WORKSPACE.toString(), CONTRACT_KEY},
                new String[]{"", "", "", "malformed-" + CONTRACT_KEY, CONTRACT_KEY}));
        String boundaryActor = "02123456-1234-5678-9abc-def012345678";
        String escapedActor = "reviewer-\"quote\\slash-suffix";
        String escapedScalar = json.writeValueAsString(escapedActor);
        String escapedValue = escapedScalar.substring(1, escapedScalar.length() - 1);
        String roleKey = "\"role\":\"AI_GOVERNANCE_REVIEWER\",\"demoMode\":true";
        String purposeKey = "\"purpose\":\"FINSEC_GOVERNANCE_SESSION_V1\"";
        List<String> serializedCanaries = new ArrayList<>();
        for (String actor : List.of(boundaryActor, escapedActor)) {
            String value = actor.equals(escapedActor) ? escapedValue : actor;
            for (String field : List.of("workspace", "workspaceId")) {
                String key = value + "\",\"" + field + "\":\"" + WORKSPACE;
                serializedCanaries.add(key);
                unsafe.add(new String[]{key, SIGNING, actor, WORKSPACE.toString(), CONTRACT_KEY});
                unsafe.add(new String[]{BOOTSTRAP, key, actor, WORKSPACE.toString(), CONTRACT_KEY});
                unsafe.add(new String[]{BOOTSTRAP, SIGNING, actor, WORKSPACE.toString(), key});
            }
        }
        String actualPurposePrefix = "{\"purpose\":\"FINSEC_GOVERNANCE_SESSION_V1\",\"sessionId\":\"";
        String actualRoleOpening = ",\"role\":\"AI_GOVERNANCE_REVIEWER\",\"demoMode\":true,\"generation\":\"";
        String actualViewOpening = ",\"role\":\"AI_GOVERNANCE_REVIEWER\",\"sessionId\":\"";
        List<String> fixedCanaries = new ArrayList<>(List.of(roleKey, purposeKey,
                actualPurposePrefix, actualPurposePrefix.substring(0, 41),
                actualPurposePrefix.substring(1), actualRoleOpening, actualViewOpening));
        for (String span : List.of(actualPurposePrefix, actualRoleOpening)) {
            byte[] bytes = span.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            for (int start = 0; start < (span == actualPurposePrefix ? 1 : 3); start++) {
                int end = start + (bytes.length - start) / 3 * 3;
                fixedCanaries.add(java.util.Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(java.util.Arrays.copyOfRange(bytes, start, end)));
            }
        }
        for (String key : fixedCanaries) {
            serializedCanaries.add(key);
            unsafe.add(new String[]{key, SIGNING, ACTOR, WORKSPACE.toString(), CONTRACT_KEY});
            unsafe.add(new String[]{BOOTSTRAP, key, ACTOR, WORKSPACE.toString(), CONTRACT_KEY});
            unsafe.add(new String[]{BOOTSTRAP, SIGNING, ACTOR, WORKSPACE.toString(), key});
        }
        for (String key : ownedFixedFailureCanaries()) {
            serializedCanaries.add(key);
            unsafe.add(new String[]{key, SIGNING, ACTOR, WORKSPACE.toString(), CONTRACT_KEY});
            unsafe.add(new String[]{BOOTSTRAP, key, ACTOR, WORKSPACE.toString(), CONTRACT_KEY});
            unsafe.add(new String[]{BOOTSTRAP, SIGNING, ACTOR, WORKSPACE.toString(), key});
        }
        String clearCookie = org.springframework.http.ResponseCookie.from(GovernanceReviewerCredentials.COOKIE, "")
                .httpOnly(true).secure(true).sameSite("Lax").path("/").maxAge(0).build().toString();
        assertThat(KNOWN_COOKIE_TRANSPORT_98.getBytes(java.nio.charset.StandardCharsets.UTF_8)).hasSize(98);
        for (String key : List.of(GovernanceReviewerCredentials.COOKIE + "=eyJwdXJwb3NlIjoi",
                "; Secure; HttpOnly; SameSite=Lax", GovernanceReviewerCredentials.COOKIE + "=; Path=/; Max-Age=0", clearCookie,
                KNOWN_COOKIE_TRANSPORT_98)) {
            assertThat(key.getBytes(java.nio.charset.StandardCharsets.UTF_8).length).isGreaterThanOrEqualTo(32);
            serializedCanaries.add(key);
            unsafe.add(new String[]{key, SIGNING, ACTOR, WORKSPACE.toString(), CONTRACT_KEY});
            unsafe.add(new String[]{BOOTSTRAP, key, ACTOR, WORKSPACE.toString(), CONTRACT_KEY});
            unsafe.add(new String[]{BOOTSTRAP, SIGNING, ACTOR, WORKSPACE.toString(), key});
        }
        // Complete known cookie prefix must fail before missing settings disable issuance.
        unsafe.add(new String[]{KNOWN_COOKIE_TRANSPORT_98, "", "", "", CONTRACT_KEY});
        unsafe.add(new String[]{"", KNOWN_COOKIE_TRANSPORT_98, "", "", CONTRACT_KEY});
        unsafe.add(new String[]{"", "", "", "", KNOWN_COOKIE_TRANSPORT_98});
        for (String key : List.of("abcdefab-1234-5678-9abc-def012345678", "00000000-0000-0000-0000-00000000")) {
            assertThat(key.getBytes(java.nio.charset.StandardCharsets.UTF_8).length).isGreaterThanOrEqualTo(32);
            serializedCanaries.add(key);
            unsafe.add(new String[]{key, SIGNING, ACTOR, WORKSPACE.toString(), CONTRACT_KEY});
            unsafe.add(new String[]{BOOTSTRAP, key, ACTOR, WORKSPACE.toString(), CONTRACT_KEY});
            unsafe.add(new String[]{BOOTSTRAP, SIGNING, ACTOR, WORKSPACE.toString(), key});
            unsafe.add(new String[]{key, "", "", "", CONTRACT_KEY});
            unsafe.add(new String[]{"", key, "", "", CONTRACT_KEY});
            unsafe.add(new String[]{"", "", "", "", key});
        }
        String whitespaceC = " ".repeat(32);
        unsafe.add(new String[]{BOOTSTRAP, SIGNING, "governance-" + whitespaceC + "reviewer", WORKSPACE.toString(), whitespaceC});
        unsafe.add(new String[]{"", "", "", "invalid-" + whitespaceC + "-workspace", whitespaceC});
        for (String[] cfg : unsafe) {
            AtomicInteger ready = new AtomicInteger();
            assertThatThrownBy(() -> {
                try (var unexpected = startRealContext(cfg[0], cfg[1], cfg[2], cfg[3], cfg[4], ready)) {
                    throw new AssertionError("Unsafe configuration returned a running context");
                }
            }).satisfies(failure -> {
                Throwable root = failure;
                while (root.getCause() != null) root = root.getCause();
                assertThat(root).isInstanceOf(IllegalArgumentException.class)
                        .hasMessage("Unsafe governance config").hasNoCause();
            });
            assertThat(ready.get()).isZero();
            assertThat(snapshot(withAdmission())).isEqualTo(before);
        }
        assertThat(output.toString()).doesNotContain(BOOTSTRAP, SIGNING, CONTRACT_KEY, uuidKey);
        for (String canary : serializedCanaries) assertThat(output.toString()).doesNotContain(canary);
        assertThat(snapshot(withAdmission())).isEqualTo(before);
    }

    @Test void blankStartupAndSafeHttpTracesKeepCredentialMetadataOutOfResponsesAndStorage() throws Exception {
        var before = snapshot(withAdmission());
        AtomicInteger ready = new AtomicInteger();
        try (var disabled = startRealContext("", "", "", "", "", ready)) {
            assertThat(ready.get()).isEqualTo(1);
            int disabledPort = disabled.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
            var denied = httpAt(disabledPort, "GET", SESSION, null,
                    List.of("Authorization", "GovernanceBootstrap " + BOOTSTRAP));
            assertThat(denied.statusCode()).isEqualTo(403);
            assertThat(denied.headers().allValues("Set-Cookie")).isEmpty();
            assertCredentialFreeResponse(denied);
        }
        assertThat(snapshot(withAdmission())).isEqualTo(before);
        for (String traceCanary : List.of(BOOTSTRAP, SIGNING)) {
            var exchange = http("GET", SESSION, null, List.of("Authorization", "GovernanceBootstrap " + BOOTSTRAP,
                    "X-Trace-Id", traceCanary, "Origin", "http://localhost:5173"));
            assertThat(exchange.statusCode()).isEqualTo(200);
            assertCredentialFreeResponse(exchange);
            assertActualStablePublicFragments(exchange, BOOTSTRAP, SIGNING, CONTRACT_KEY);
            assertResponseUsesSafeMdcTrace(exchange);
            assertThat(exchange.headers().firstValue("Access-Control-Allow-Origin")).contains("http://localhost:5173");
            var view = json.readTree(exchange.body()).path("data");
            Session session = new Session(exchange.headers().firstValue("Set-Cookie").orElseThrow().split(";", 2)[0],
                    view.path("csrfToken").asString(), UUID.fromString(view.path("sessionId").asString()));
            var current = http("GET", SESSION, null, List.of("Cookie", session.cookie, "X-Trace-Id", traceCanary));
            assertThat(current.statusCode()).isEqualTo(200);
            assertThat(current.headers().allValues("Set-Cookie")).isEmpty();
            assertThat(json.readTree(current.body()).path("data")).isEqualTo(view);
            assertCredentialFreeResponse(current); assertResponseUsesSafeMdcTrace(current);
            var denied = http("GET", SESSION, null, List.of("X-Trace-Id", traceCanary));
            assertThat(denied.statusCode()).isEqualTo(403);
            assertCredentialFreeResponse(denied); assertResponseUsesSafeMdcTrace(denied);
            var corsDenied = http("GET", SESSION, null, List.of("Authorization", "GovernanceBootstrap " + BOOTSTRAP,
                    "Origin", "https://not-allowed.invalid", "X-Trace-Id", traceCanary));
            assertThat(corsDenied.statusCode()).isEqualTo(403); assertCredentialFreeResponse(corsDenied);
            for (String origin : List.of("http://localhost:5173", "https://not-allowed.invalid")) {
                var preflight = http("OPTIONS", SESSION, null, List.of("Origin", origin,
                        "Access-Control-Request-Method", "GET", "X-Trace-Id", traceCanary));
                assertThat(preflight.statusCode()).isEqualTo(origin.startsWith("http://localhost") ? 200 : 403);
                assertCredentialFreeResponse(preflight);
                assertThat(preflight.headers().allValues("Set-Cookie")).isEmpty();
            }
            String safeTrace = UUID.randomUUID().toString();
            var safe = http("GET", SESSION, null, List.of("Cookie", session.cookie, "X-Trace-Id", safeTrace));
            assertThat(safe.statusCode()).isEqualTo(200);
            assertThat(safe.headers().firstValue("X-Trace-Id")).contains(safeTrace);
            assertResponseUsesSafeMdcTrace(safe);
            String logoutKey = key(), path = SESSION + "/" + session.id;
            var headers = mutationHeaders(session, logoutKey); headers.addAll(List.of("X-Trace-Id", traceCanary));
            var logout = http("DELETE", path, null, headers);
            assertThat(logout.statusCode()).isEqualTo(204); assertCleared(logout); assertNoStore(logout);
            assertCredentialFreeResponse(logout);
            assertIdempotencySecretsAbsent(session, "DELETE", path, logoutKey, "COMPLETED", false);
            assertThat(independentDb().queryForObject("select count(*) from reviewer_session_revocations where session_digest=?",
                    Integer.class, sessionDigest(session))).isEqualTo(1);
            var replay = http("DELETE", path, null, headers);
            assertThat(replay.statusCode()).isEqualTo(204); assertCleared(replay); assertNoStore(replay);
            assertThat(replay.headers().firstValue("Idempotent-Replayed")).contains("true");
            assertThat(replay.headers().firstValue("X-Trace-Id")).isEqualTo(logout.headers().firstValue("X-Trace-Id"));
            assertCredentialFreeResponse(replay);
            assertIdempotencySecretsAbsent(session, "DELETE", path, logoutKey, "COMPLETED", false);
            assertThat(snapshot(GOVERNED)).isEqualTo(beforeSnapshotGoverned(before));
            var directRequest = new MockHttpServletRequest("GET", SESSION); directRequest.setServletPath(SESSION);
            directRequest.addHeader("Authorization", "GovernanceBootstrap " + BOOTSTRAP);
            directRequest.addHeader("X-Trace-Id", traceCanary);
            AtomicReference<String> observed = new AtomicReference<>();
            direct(filter, directRequest, (request, response) -> {
                access.currentSession((HttpServletRequest) request);
                observed.set(TraceIdFilter.currentTraceId());
            });
            assertThat(observed.get()).doesNotContain(BOOTSTRAP, SIGNING, CONTRACT_KEY);
            assertThat(UUID.fromString(observed.get())).isNotNull();
            assertThat(TraceIdFilter.currentTraceId()).isNull();
        }
    }

    @Test void safeDistinctUtf8KeysPreserveActualEscapedClaimsAndSessionViewBoundaries() throws Exception {
        var before = snapshot(withAdmission());
        String bootstrap = "k".repeat(32), signing = "é".repeat(16);
        String actor = "reviewer-\"quote\\slash-suffix";
        AtomicInteger ready = new AtomicInteger();
        try (var safe = startRealContext(bootstrap, signing, actor, WORKSPACE.toString(), CONTRACT_KEY, ready)) {
            assertThat(ready.get()).isEqualTo(1);
            int port = safe.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
            var exchange = httpAt(port, "GET", SESSION, null,
                    List.of("Authorization", "GovernanceBootstrap " + bootstrap, "Origin", "http://localhost:5173"));
            assertThat(exchange.statusCode()).withFailMessage(exchange.body()).isEqualTo(200);
            assertNoStore(exchange);
            assertThat(json.readTree(exchange.body()).path("data").path("actorId").asString()).isEqualTo(actor);
            assertActualStablePublicFragments(exchange, bootstrap, signing, CONTRACT_KEY);
            String cookie = exchange.headers().firstValue("Set-Cookie").orElseThrow().split(";", 2)[0];
            var current = httpAt(port, "GET", SESSION, null, List.of("Cookie", cookie));
            assertThat(current.statusCode()).isEqualTo(200);
            assertNoStore(current);
            assertThat(current.headers().allValues("Set-Cookie")).isEmpty();
            assertThat(json.readTree(current.body()).path("data")).isEqualTo(json.readTree(exchange.body()).path("data"));
            assertThat(current.headers().map().toString() + current.body()).doesNotContain(bootstrap, signing, CONTRACT_KEY);
        }
        assertThat(snapshot(withAdmission())).isEqualTo(before);
    }

    @Test void encodedJsonOnlyViewKeyKeepsRealSpringHttpExchangeAndCookieCurrentValid() throws Exception {
        String key = "LCJyb2xlIjoiQUlfR09WRVJOQU5DRV9SRVZJRVdFUiIsInNlc3Npb25JZCI6";
        assertThat(key.getBytes(java.nio.charset.StandardCharsets.UTF_8)).hasSize(60);
        var before = snapshot(withAdmission());
        for (int position = 0; position < 3; position++) {
            String bootstrap = position == 0 ? key : BOOTSTRAP;
            String signing = position == 1 ? key : SIGNING;
            String cKey = position == 2 ? key : CONTRACT_KEY;
            AtomicInteger ready = new AtomicInteger();
            try (var safe = startRealContext(bootstrap, signing, ACTOR, WORKSPACE.toString(), cKey, ready)) {
                assertThat(ready.get()).isEqualTo(1);
                int port = safe.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
                var exchange = httpAt(port, "GET", SESSION, null,
                        List.of("Authorization", "GovernanceBootstrap " + bootstrap,
                                "Origin", "http://localhost:5173"));
                assertThat(exchange.statusCode()).withFailMessage(exchange.body()).isEqualTo(200);
                assertNoStore(exchange);
                assertActualStablePublicFragments(exchange, bootstrap, signing, cKey);
                String cookie = exchange.headers().firstValue("Set-Cookie").orElseThrow().split(";", 2)[0];
                var current = httpAt(port, "GET", SESSION, null, List.of("Cookie", cookie));
                assertThat(current.statusCode()).withFailMessage(current.body()).isEqualTo(200);
                assertNoStore(current);
                assertThat(current.headers().allValues("Set-Cookie")).isEmpty();
                assertThat(json.readTree(current.body()).path("data"))
                        .isEqualTo(json.readTree(exchange.body()).path("data"));
                assertThat(current.headers().map().toString() + current.body()).doesNotContain(bootstrap, signing, cKey);
                assertThat(snapshot(withAdmission())).isEqualTo(before);
            }
            assertThat(snapshot(withAdmission())).isEqualTo(before);
        }
    }

    private void assertActualStablePublicFragments(HttpResponse<String> exchange,
            String bootstrap, String signing, String cKey) {
        JsonNode view = json.readTree(exchange.body()).path("data");
        String actor = view.path("actorId").asString(), workspace = view.path("workspaceId").asString();
        String claims = json.writeValueAsString(json.createObjectNode().put("actor", actor).put("workspace", workspace)
                .put("role", "AI_GOVERNANCE_REVIEWER").put("demoMode", true));
        String publicView = json.writeValueAsString(json.createObjectNode().put("actorId", actor)
                .put("workspaceId", workspace).put("role", "AI_GOVERNANCE_REVIEWER"));
        String token = exchange.headers().firstValue("Set-Cookie").orElseThrow().split(";", 2)[0].split("=", 2)[1];
        String decoded = new String(java.util.Base64.getUrlDecoder().decode(token.split("\\.", 2)[0]),
                java.nio.charset.StandardCharsets.UTF_8);
        assertThat(decoded).contains(claims.substring(1, claims.length() - 1));
        assertThat(exchange.body()).contains(publicView.substring(1, publicView.length() - 1));
        String exactView = json.writeValueAsString(json.createObjectNode()
                .put("csrfToken", view.path("csrfToken").asString()).put("expiresAt", view.path("expiresAt").longValue())
                .put("actorId", actor).put("workspaceId", workspace).put("role", view.path("role").asString())
                .put("sessionId", view.path("sessionId").asString()).put("demoMode", view.path("demoMode").booleanValue()));
        assertThat(exchange.body()).contains(exactView);
        assertThat(token).doesNotContain(bootstrap, signing, cKey);
        assertThat(decoded).startsWith("{\"purpose\":\"FINSEC_GOVERNANCE_SESSION_V1\",\"sessionId\":\"");
        assertThat(decoded).contains(",\"role\":\"AI_GOVERNANCE_REVIEWER\",\"demoMode\":true,\"generation\":\"");
        assertThat(exactView).contains(",\"role\":\"AI_GOVERNANCE_REVIEWER\",\"sessionId\":\"");
        assertThat(decoded).doesNotContain(bootstrap, signing, cKey);
        assertThat(exchange.headers().map().toString() + exchange.body()).doesNotContain(bootstrap, signing, cKey);
        // role/demoMode is contiguous only in issuer claims, not in the SessionView record.
        assertThat(decoded).contains("\"role\":\"AI_GOVERNANCE_REVIEWER\",\"demoMode\":true");
        assertThat(decoded).contains("\"purpose\":\"FINSEC_GOVERNANCE_SESSION_V1\"");
    }

    @Test void realHttpJPAAdmittedContinuationIsReadCommittedAndReplayDoesNotCallConsumer() throws Exception {
        Graph graph = graph(WORKSPACE);
        Session session = httpSession();
        var before = snapshot(GOVERNED);
        int calls = probe.callCount();
        String key = key();
        var first = risk(graph, session, key, List.of());
        assertThat(first.statusCode()).withFailMessage(first.body()).isEqualTo(200);
        assertThat(json.readTree(first.body()).path("holderSynchronized").booleanValue()).isFalse();
        assertThat(json.readTree(first.body()).path("isolation").asString()).isEqualTo("read committed");
        assertThat(json.readTree(first.body()).path("readOnly").asString()).isEqualTo("off");
        assertNoStore(first);
        assertIdempotencySecretsAbsent(session, "POST", riskPath(graph.finding), key, "COMPLETED", false);
        var replay = risk(graph, session, key, List.of());
        assertThat(replay.statusCode()).isEqualTo(200);
        assertThat(replay.body()).isEqualTo(first.body());
        assertThat(replay.headers().firstValue("Idempotent-Replayed")).contains("true");
        assertNoStore(replay);
        assertIdempotencySecretsAbsent(session, "POST", riskPath(graph.finding), key, "COMPLETED", false);
        assertThat(probe.callCount()).isEqualTo(calls + 1);
        assertThat(snapshot(GOVERNED)).isEqualTo(before);
        assertThat(db.queryForObject("select state from api_idempotency_records where idempotency_key=?",
                String.class, key)).isEqualTo("COMPLETED");
    }

    @Test void logoutCommitsDurablyAndAuthenticatedRevokedRepeatsClearBeforeReplay() throws Exception {
        Session session = httpSession();
        String path = SESSION + "/" + session.id;
        String key = key();
        var first = http("DELETE", path, null, mutationHeaders(session, key));
        assertThat(first.statusCode()).withFailMessage(first.body()).isEqualTo(204);
        assertCleared(first); assertNoStore(first);
        assertThat(independentDb().queryForObject("select count(*) from reviewer_session_revocations where session_digest=?",
                Integer.class, sessionDigest(session))).isEqualTo(1);
        assertIdempotencySecretsAbsent(session, "DELETE", path, key, "COMPLETED", false);
        var replay = http("DELETE", path, null, mutationHeaders(session, key));
        assertThat(replay.statusCode()).isEqualTo(204);
        assertThat(replay.headers().firstValue("Idempotent-Replayed")).contains("true");
        assertCleared(replay); assertNoStore(replay);
        assertIdempotencySecretsAbsent(session, "DELETE", path, key, "COMPLETED", false);
        String freshKey = key();
        var fresh = http("DELETE", path, null, mutationHeaders(session, freshKey));
        assertThat(fresh.statusCode()).isEqualTo(204); assertCleared(fresh);
        assertIdempotencySecretsAbsent(session, "DELETE", path, freshKey, "COMPLETED", false);
        var current = http("GET", SESSION, null, List.of("Cookie", session.cookie));
        assertThat(current.statusCode()).isEqualTo(403); assertNoStore(current);
        for (List<String> headers : List.of(List.of("Cookie", session.cookie, "Idempotency-Key", key),
                List.of("Cookie", session.cookie, "X-CSRF-Token", "invalid", "Idempotency-Key", key),
                List.of("Cookie", signedInvalidRepeatCookie(session, true), "X-CSRF-Token", session.csrf, "Idempotency-Key", key),
                List.of("Cookie", signedInvalidRepeatCookie(session, false), "X-CSRF-Token", session.csrf, "Idempotency-Key", key),
                List.of("Authorization", "GovernanceBootstrap " + BOOTSTRAP, "Idempotency-Key", key))) {
            var invalid = http("DELETE", path, null, headers);
            assertThat(invalid.statusCode()).isEqualTo(403);
            assertThat(invalid.headers().allValues("Set-Cookie")).isEmpty();
            assertThat(invalid.headers().allValues("Idempotent-Replayed")).isEmpty();
        }
        assertThat(independentDb().queryForObject("select count(*) from reviewer_session_revocations where session_digest=?",
                Integer.class, sessionDigest(session))).isEqualTo(1);
    }

    @Test void secretBearingKeysDenyAuthenticatedRiskAndOwnLogoutBeforeAdmission() throws Exception {
        Graph graph = graph(WORKSPACE);
        Session current = httpSession(), old = httpSession(), different = httpSession();
        String oldKey = key();
        var oldLogout = http("DELETE", SESSION + "/" + old.id, null, mutationHeaders(old, oldKey));
        assertThat(oldLogout.statusCode()).isEqualTo(204);
        assertIdempotencySecretsAbsent(old, "DELETE", SESSION + "/" + old.id, oldKey, "COMPLETED", false);
        var before = snapshot(withAdmission());
        int calls = probe.callCount();
        for (String secret : List.of(current.csrf, old.csrf, different.csrf, BOOTSTRAP, SIGNING)) {
            for (String forbiddenKey : List.of(secret, "pre-" + secret + "-post")) {
                for (boolean logout : List.of(false, true)) {
                    String method = logout ? "DELETE" : "POST";
                    String path = logout ? SESSION + "/" + current.id : riskPath(graph.finding);
                    var denied = http(method, path, logout ? null : "{}", mutationHeaders(current, forbiddenKey));
                    assertThat(denied.statusCode()).isEqualTo(400);
                    assertThat(json.readTree(denied.body()).path("code").stringValue()).isEqualTo("VALIDATION_ERROR");
                    assertNoStore(denied);
                    assertThat(denied.headers().allValues("Set-Cookie")).isEmpty();
                    assertThat(denied.headers().allValues("Idempotent-Replayed")).isEmpty();
                    assertThat(denied.body()).doesNotContain(current.csrf, old.csrf, different.csrf, BOOTSTRAP, SIGNING);
                    assertThat(probe.callCount()).isEqualTo(calls);
                    assertThat(independentDb().queryForObject("select count(*) from api_idempotency_records where idempotency_key=?",
                            Integer.class, forbiddenKey)).isZero();
                    assertThat(snapshot(withAdmission())).isEqualTo(before);
                }
            }
        }
        String safeRiskKey = key();
        assertThat(risk(graph, current, safeRiskKey, List.of()).statusCode()).isEqualTo(200);
        assertIdempotencySecretsAbsent(current, "POST", riskPath(graph.finding), safeRiskKey, "COMPLETED", false);
        var replay = risk(graph, current, safeRiskKey, List.of());
        assertThat(replay.statusCode()).isEqualTo(200);
        assertThat(replay.headers().firstValue("Idempotent-Replayed")).contains("true");
        assertIdempotencySecretsAbsent(current, "POST", riskPath(graph.finding), safeRiskKey, "COMPLETED", false);
        assertThat(probe.callCount()).isEqualTo(calls + 1);
        String safeLogoutKey = key();
        var logout = http("DELETE", SESSION + "/" + current.id, null, mutationHeaders(current, safeLogoutKey));
        assertThat(logout.statusCode()).isEqualTo(204); assertCleared(logout);
        assertIdempotencySecretsAbsent(current, "DELETE", SESSION + "/" + current.id, safeLogoutKey, "COMPLETED", false);
        assertThat(independentDb().queryForObject("select count(*) from reviewer_session_revocations where session_digest=?",
                Integer.class, sessionDigest(current))).isEqualTo(1);
    }

    @Test void logoutForeignSessionAndActorConflictCannotClearCookieOrReserve() throws Exception {
        Session session = httpSession();
        var before = snapshot(withAdmission());
        var foreign = http("DELETE", SESSION + "/" + UUID.randomUUID(), null, mutationHeaders(session, key()));
        assertThat(foreign.statusCode()).isEqualTo(403);
        var headers = mutationHeaders(session, key()); headers.addAll(List.of("X-Actor-Id", "foreign-actor"));
        var conflict = http("DELETE", SESSION + "/" + session.id, null, headers);
        assertThat(conflict.statusCode()).isEqualTo(403);
        assertThat(foreign.headers().allValues("Set-Cookie")).isEmpty();
        assertThat(conflict.headers().allValues("Set-Cookie")).isEmpty();
        assertThat(snapshot(withAdmission())).isEqualTo(before);
    }

    @Test void actualLogoutStorageFailureReturns5xxNot204AndRetainsRecoveryRecord() throws Exception {
        Session session = httpSession();
        String key = key();
        var before = snapshot(GOVERNED);
        db.execute("create function governance_test_revoke_failure() returns trigger language plpgsql as $$ begin raise exception 'synthetic-private-storage-canary'; end; $$");
        db.execute("create trigger governance_test_revoke_failure before insert on reviewer_session_revocations for each row execute function governance_test_revoke_failure()");
        try {
            var failure = http("DELETE", SESSION + "/" + session.id, null, mutationHeaders(session, key));
            assertThat(failure.statusCode()).isBetween(500, 599);
            assertThat(failure.body()).doesNotContain("synthetic-private-storage-canary", BOOTSTRAP, SIGNING, session.cookie);
            // Clearing the browser cookie is not durable revocation; that distinction is observable on5xx.
            assertThat(db.queryForObject("select count(*) from reviewer_session_revocations where session_digest=?",
                    Integer.class, sessionDigest(session))).isZero();
            assertThat(db.queryForObject("select state from api_idempotency_records where idempotency_key=?",
                    String.class, key)).isEqualTo("RECOVERY_REQUIRED");
            assertIdempotencySecretsAbsent(session, "DELETE", SESSION + "/" + session.id, key, "RECOVERY_REQUIRED", true);
            assertThat(snapshot(GOVERNED)).isEqualTo(before);
        } finally {
            db.execute("drop trigger governance_test_revoke_failure on reviewer_session_revocations");
            db.execute("drop function governance_test_revoke_failure()");
        }
    }

    @Test void preparedEarlyPostgresDiagnosticSuppressesOnlyTraceAndRestoresWithoutRenewal() throws Exception {
        // A UUID-shaped C reference is forbidden. This UUID is only caller trace/MDC input,
        // distinct from the safe configured C reference; no known-C trace output guarantee is claimed.
        String callerTraceCanary = "abcdefab-1234-5678-9abc-def012345678";
        Graph graph = graph(WORKSPACE);
        Session mainSession = httpSession();
        AtomicInteger ready = new AtomicInteger();
        try (var safe = startRealContext(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE.toString(), CONTRACT_KEY, ready)) {
            assertThat(ready.get()).isEqualTo(1);
            int safePort = safe.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
            var exchange = httpAt(safePort, "GET", SESSION, null,
                    List.of("Authorization", "GovernanceBootstrap " + BOOTSTRAP));
            assertThat(exchange.statusCode()).isEqualTo(200);
            String safeCookie = exchange.headers().firstValue("Set-Cookie").orElseThrow().split(";", 2)[0];
            var before = snapshot(withAdmission());
            int calls = probe.callCount();
            var logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(GovernanceAccessFilter.class);
            assertThat(logger.isWarnEnabled()).isTrue();
            var appender = new PreparedDiagnosticAppender();
            appender.setContext(logger.getLoggerContext()); appender.start(); logger.addAppender(appender);
            boolean renamed = false;
            try {
                db.execute("alter table reviewer_session_revocations rename to governance_lookup_unavailable_fixture");
                renamed = true;
                var riskHeaders = mutationHeaders(mainSession, key());
                riskHeaders.addAll(List.of("X-Trace-Id", callerTraceCanary));
                var failure = http("POST", riskPath(graph.finding), "{}", riskHeaders);
                assertEarlyStorageFailure(failure);
                assertThat(probe.callCount()).isEqualTo(calls);
                assertThat(appender.events).isEmpty(); // Selected owned storage diagnostic omission.
                var currentFailure = httpAt(safePort, "GET", SESSION, null,
                        List.of("Cookie", safeCookie, "X-Trace-Id", callerTraceCanary));
                assertEarlyStorageFailure(currentFailure);
                assertThat(appender.events).isEmpty();
                // Same-thread actual filter + physical SELECT: do not infer servlet-thread MDC from the caller thread.
                Map<String, String> previousMdc = MDC.getCopyOfContextMap();
                try {
                    for (String previousTrace : new String[]{null, callerTraceCanary}) {
                        if (previousTrace == null) MDC.remove(TraceIdFilter.TRACE_ID);
                        else MDC.put(TraceIdFilter.TRACE_ID, previousTrace);
                        MDC.put("governanceDiagnosticSentinel", "safe-sentinel");
                        var request = new MockHttpServletRequest("GET", SESSION); request.setServletPath(SESSION);
                        request.setCookies(new Cookie(GovernanceReviewerCredentials.COOKIE, mainSession.cookie.split("=", 2)[1]));
                        var response = new MockHttpServletResponse();
                        AtomicInteger continued = new AtomicInteger();
                        filter.doFilter(request, response, (req, res) -> continued.incrementAndGet());
                        assertThat(response.getStatus()).isEqualTo(500);
                        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
                        assertThat(response.getHeaders("Set-Cookie")).isEmpty();
                        assertThat(continued.get()).isZero();
                        assertThat(MDC.get(TraceIdFilter.TRACE_ID)).isEqualTo(previousTrace);
                        assertThat(MDC.get("governanceDiagnosticSentinel")).isEqualTo("safe-sentinel");
                        assertThat(appender.events).isEmpty();
                    }
                } finally {
                    if (previousMdc == null) MDC.clear(); else MDC.setContextMap(previousMdc);
                }
            } finally {
                try {
                    if (renamed) db.execute("alter table governance_lookup_unavailable_fixture rename to reviewer_session_revocations");
                } finally {
                    logger.detachAppender(appender); appender.stop();
                }
            }
            assertThat(snapshot(withAdmission())).isEqualTo(before);
            var recovery = httpAt(safePort, "GET", SESSION, null, List.of("Cookie", safeCookie));
            assertThat(recovery.statusCode()).isEqualTo(200); assertNoStore(recovery);
            assertThat(recovery.headers().allValues("Set-Cookie")).isEmpty();
            assertThat(json.readTree(recovery.body()).path("data")).isEqualTo(json.readTree(exchange.body()).path("data"));
            var mainRecovery = http("GET", SESSION, null, List.of("Cookie", mainSession.cookie));
            assertThat(mainRecovery.statusCode()).isEqualTo(200); assertNoStore(mainRecovery);
            assertThat(mainRecovery.headers().allValues("Set-Cookie")).isEmpty();
            assertThat(snapshot(withAdmission())).isEqualTo(before);
            assertThat(probe.callCount()).isEqualTo(calls);
        }
    }

    @Test @ExtendWith(OutputCaptureExtension.class)
    void renderedConsoleStorageFaultOmitsNative42SigningAndCSecretsWithSafeControls(CapturedOutput output) throws Exception {
        String native42 = ": GOVERNANCE_AUTHORITY_STORAGE_UNAVAILABLE";
        assertThat(native42.getBytes(java.nio.charset.StandardCharsets.UTF_8)).hasSize(42);
        String transportControlPrefix = "SAFE_GOVERNANCE_CONSOLE_TRANSPORT_CONTROL_";
        int transportControlOrdinal = 0;
        String callerTrace = "abcdefab-1234-5678-9abc-def012345678";
        for (String[] settings : List.of(
                new String[]{BOOTSTRAP, native42, CONTRACT_KEY},
                new String[]{BOOTSTRAP, SIGNING, native42},
                new String[]{"s".repeat(32), "é".repeat(16), CONTRACT_KEY})) {
            String bootstrap = settings[0], signing = settings[1], cKey = settings[2];
            String transportControl = transportControlPrefix + (++transportControlOrdinal);
            AtomicInteger ready = new AtomicInteger();
            var before = snapshot(withAdmission());
            try (var selected = startRealContext(bootstrap, signing, ACTOR, WORKSPACE.toString(), cKey, ready)) {
                assertThat(ready.get()).isEqualTo(1); // Otherwise-valid settings; no new configuration restriction.
                int selectedPort = selected.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
                var selectedIssuer = selected.getBean(GovernanceReviewerCredentials.class);
                var selectedFilter = selected.getBean(GovernanceAccessFilter.class);
                var exchange = httpAt(selectedPort, "GET", SESSION, null,
                        List.of("Authorization", "GovernanceBootstrap " + bootstrap));
                assertThat(exchange.statusCode()).isEqualTo(200); assertNoStore(exchange);
                var view = json.readTree(exchange.body()).path("data");
                String cookie = exchange.headers().firstValue("Set-Cookie").orElseThrow().split(";", 2)[0];
                assertThat(privateIssuerWindowSize(selectedIssuer, "issuances")).isEqualTo(1);
                assertThat(privateIssuerWindowSize(selectedIssuer, "attempts")).isEqualTo(1);
                // The actual application ConsoleAppender/encoder renders this through its configured transport.
                // OutputCaptureExtension captures those bytes; no invented PatternLayout or event-only comparison.
                org.slf4j.LoggerFactory.getLogger(GovernanceAuthenticationIntegrationTest.class).warn(transportControl);
                assertThat(output.getAll()).contains(": " + transportControl);
                var logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(GovernanceAccessFilter.class);
                assertThat(logger.isWarnEnabled()).isTrue();
                var appender = new PreparedDiagnosticAppender();
                appender.setContext(logger.getLoggerContext()); appender.start(); logger.addAppender(appender);
                boolean renamed = false;
                try {
                    db.execute("alter table reviewer_session_revocations rename to governance_lookup_unavailable_fixture");
                    renamed = true;
                    var failure = httpAt(selectedPort, "GET", SESSION, null,
                            List.of("Cookie", cookie, "X-Trace-Id", callerTrace));
                    assertEarlyStorageFailure(failure);
                    assertThat(appender.events).isEmpty();
                    assertThat(failure.headers().map().toString() + failure.body())
                            .doesNotContain(bootstrap, signing, cKey, cookie.split("=", 2)[1], view.path("csrfToken").asString());
                    Map<String, String> previousMdc = MDC.getCopyOfContextMap();
                    try {
                        for (String previousTrace : new String[]{null, callerTrace}) {
                            if (previousTrace == null) MDC.remove(TraceIdFilter.TRACE_ID);
                            else MDC.put(TraceIdFilter.TRACE_ID, previousTrace);
                            MDC.put("governanceDiagnosticSentinel", "safe-sentinel");
                            var request = new MockHttpServletRequest("GET", SESSION); request.setServletPath(SESSION);
                            request.setCookies(new Cookie(GovernanceReviewerCredentials.COOKIE, cookie.split("=", 2)[1]));
                            var response = new MockHttpServletResponse();
                            AtomicInteger continued = new AtomicInteger();
                            selectedFilter.doFilter(request, response, (req, res) -> continued.incrementAndGet());
                            assertThat(response.getStatus()).isEqualTo(500);
                            assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
                            assertThat(response.getHeaders("Set-Cookie")).isEmpty();
                            assertThat(response.getHeaders("Idempotent-Replayed")).isEmpty();
                            assertThat(json.readTree(response.getContentAsByteArray()).path("detail").asString())
                                    .isEqualTo("Governance authority storage unavailable");
                            assertThat(continued.get()).isZero();
                            assertThat(MDC.get(TraceIdFilter.TRACE_ID)).isEqualTo(previousTrace);
                            assertThat(MDC.get("governanceDiagnosticSentinel")).isEqualTo("safe-sentinel");
                            assertThat(appender.events).isEmpty();
                        }
                    } finally {
                        if (previousMdc == null) MDC.clear(); else MDC.setContextMap(previousMdc);
                    }
                    assertThat(output.getAll()).doesNotContain(native42, bootstrap, signing, cKey,
                            cookie.split("=", 2)[1], view.path("csrfToken").asString());
                } finally {
                    try {
                        if (renamed) db.execute("alter table governance_lookup_unavailable_fixture rename to reviewer_session_revocations");
                    } finally { logger.detachAppender(appender); appender.stop(); }
                }
                assertThat(snapshot(withAdmission())).isEqualTo(before);
                var recovery = httpAt(selectedPort, "GET", SESSION, null,
                        List.of("Cookie", cookie, "X-Trace-Id", callerTrace));
                assertThat(recovery.statusCode()).isEqualTo(200); assertNoStore(recovery);
                assertThat(recovery.headers().allValues("Set-Cookie")).isEmpty();
                assertThat(json.readTree(recovery.body()).path("data")).isEqualTo(view);
                assertThat(privateIssuerWindowSize(selectedIssuer, "issuances")).isEqualTo(1);
                assertThat(privateIssuerWindowSize(selectedIssuer, "attempts")).isEqualTo(1);
                assertThat(snapshot(withAdmission())).isEqualTo(before);
                assertThat(output.getAll()).doesNotContain(native42, bootstrap, signing, cKey,
                        cookie.split("=", 2)[1], view.path("csrfToken").asString());
            }
        }
    }

    @Test void ownedFixedFailureRepresentationsMatchSafeHttpAndPreparedStorageDiagnostic() throws Exception {
        String bootstrap = "s".repeat(32), signing = "é".repeat(16);
        AtomicInteger ready = new AtomicInteger();
        var before = snapshot(withAdmission());
        try (var safe = startRealContext(bootstrap, signing, ACTOR, WORKSPACE.toString(), CONTRACT_KEY, ready)) {
            assertThat(ready.get()).isEqualTo(1);
            int selectedPort = safe.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
            var denial = httpAt(selectedPort, "GET", SESSION, null, List.of());
            assertOwnedProblemRepresentation(denial, 403, "Forbidden", "OPERATOR_AUTH_REQUIRED",
                    "Current governance session authority required", bootstrap, signing);
            var malformed = httpAt(selectedPort, "GET", SESSION + "?owned=1", null, List.of());
            assertOwnedProblemRepresentation(malformed, 400, "Bad Request", "VALIDATION_ERROR",
                    "Use the exact canonical governance API path and method", bootstrap, signing);
            var exchange = httpAt(selectedPort, "GET", SESSION, null,
                    List.of("Authorization", "GovernanceBootstrap " + bootstrap));
            assertThat(exchange.statusCode()).isEqualTo(200);
            var view = json.readTree(exchange.body()).path("data");
            String cookie = exchange.headers().firstValue("Set-Cookie").orElseThrow().split(";", 2)[0];
            var invalidKey = httpAt(selectedPort, "DELETE", SESSION + "/" + view.path("sessionId").asString(), null,
                    List.of("Cookie", cookie, "X-CSRF-Token", view.path("csrfToken").asString(), "Idempotency-Key", "not valid"));
            assertOwnedProblemRepresentation(invalidKey, 400, "Bad Request", "VALIDATION_ERROR",
                    "A single safe Idempotency-Key is required", bootstrap, signing);
            var logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(GovernanceAccessFilter.class);
            var appender = new PreparedDiagnosticAppender();
            appender.setContext(logger.getLoggerContext()); appender.start(); logger.addAppender(appender);
            boolean renamed = false;
            try {
                db.execute("alter table reviewer_session_revocations rename to governance_lookup_unavailable_fixture");
                renamed = true;
                var unavailable = httpAt(selectedPort, "GET", SESSION, null, List.of("Cookie", cookie));
                assertOwnedProblemRepresentation(unavailable, 500, "Internal Server Error", "INTERNAL_ERROR",
                        "Governance authority storage unavailable", bootstrap, signing);
                assertThat(appender.events).isEmpty();
            } finally {
                try {
                    if (renamed) db.execute("alter table governance_lookup_unavailable_fixture rename to reviewer_session_revocations");
                } finally { logger.detachAppender(appender); appender.stop(); }
            }
            var current = httpAt(selectedPort, "GET", SESSION, null, List.of("Cookie", cookie));
            assertThat(current.statusCode()).isEqualTo(200); assertNoStore(current);
            assertThat(current.headers().allValues("Set-Cookie")).isEmpty();
            assertThat(json.readTree(current.body()).path("data")).isEqualTo(view);
            assertThat(current.headers().map().toString() + current.body()).doesNotContain(bootstrap, signing, CONTRACT_KEY,
                    cookie.split("=", 2)[1]);
            assertThat(snapshot(withAdmission())).isEqualTo(before);
        }
        assertThat(snapshot(withAdmission())).isEqualTo(before);
    }

    @Test void actualCookieTransportUsesStoredIssuanceHeaderAndSafeRawHttpBoundaries() throws Exception {
        var before = snapshot(withAdmission());
        for (String[] cfg : List.of(new String[]{"b".repeat(32), "s".repeat(32)},
                new String[]{"k".repeat(32), "é".repeat(16)})) {
            String bootstrap = cfg[0], signing = cfg[1];
            AtomicInteger ready = new AtomicInteger();
            try (var safe = startRealContext(bootstrap, signing, ACTOR, WORKSPACE.toString(), CONTRACT_KEY, ready)) {
                assertThat(ready.get()).isEqualTo(1);
                int selectedPort = safe.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
                var exchanged = httpAt(selectedPort, "GET", SESSION, null,
                        List.of("Authorization", "GovernanceBootstrap " + bootstrap, "Origin", "http://localhost:5173"));
                assertThat(exchanged.statusCode()).withFailMessage(exchanged.body()).isEqualTo(200);
                assertNoStore(exchanged);
                assertThat(exchanged.headers().allValues("Set-Cookie")).hasSize(1);
                String rawHeader = exchanged.headers().firstValue("Set-Cookie").orElseThrow();
                String nameValue = rawHeader.split(";", 2)[0];
                assertThat(rawHeader).startsWith(GovernanceReviewerCredentials.COOKIE + "=eyJwdXJwb3NlIjoi")
                        .startsWith(KNOWN_COOKIE_TRANSPORT_98).contains("; Path=/; Max-Age=1800; Expires=").endsWith("; Secure; HttpOnly; SameSite=Lax")
                        .doesNotContain("Domain=", bootstrap, signing, CONTRACT_KEY);
                assertActualStablePublicFragments(exchanged, bootstrap, signing, CONTRACT_KEY);
                var current = httpAt(selectedPort, "GET", SESSION, null, List.of("Cookie", nameValue));
                assertThat(current.statusCode()).isEqualTo(200); assertNoStore(current);
                assertThat(current.headers().allValues("Set-Cookie")).isEmpty();
                assertThat(json.readTree(current.body()).path("data")).isEqualTo(json.readTree(exchanged.body()).path("data"));
                assertThat(current.headers().map().toString() + current.body()).doesNotContain(bootstrap, signing, CONTRACT_KEY);
                assertThat(snapshot(withAdmission())).isEqualTo(before);
            }
        }
        // On the actual authenticated filter path the controller delivers the exact stored String;
        // it cannot rebuild a time-dependent Expires header after issuer safety validation.
        var request = new MockHttpServletRequest("GET", SESSION); request.setServletPath(SESSION);
        request.addHeader("Authorization", "GovernanceBootstrap " + BOOTSTRAP);
        AtomicInteger continuations = new AtomicInteger();
        var response = direct(filter, request, (authenticated, ignored) -> {
            var actualRequest = (HttpServletRequest) authenticated;
            var issued = access.currentSession(actualRequest);
            assertThat(access.issued(actualRequest)).isTrue();
            String stored = issued.issuanceCookieHeader();
            assertThat(stored).isNotNull();
            var delivered = controller.current(actualRequest);
            assertThat(delivered.getHeaders().getFirst("Set-Cookie")).isSameAs(stored);
            assertThat(stored).startsWith(GovernanceReviewerCredentials.COOKIE + "=" + issued.token() + "; Path=/; Max-Age=1800; Expires=")
                    .endsWith("; Secure; HttpOnly; SameSite=Lax").doesNotContain(BOOTSTRAP, SIGNING, CONTRACT_KEY);
            continuations.incrementAndGet();
        });
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(continuations.get()).isEqualTo(1);
        assertThat(snapshot(withAdmission())).isEqualTo(before);
        // Existing authenticated logout filter clearing/replay assertions remain unchanged.
    }

    @Test void safeAuthenticatedLogoutPreservesActualFixedClearCookieAndSecretFreeAdmission() throws Exception {
        var before = snapshot(GOVERNED);
        Session session = httpSession();
        String logoutKey = key(), path = SESSION + "/" + session.id;
        String expected = org.springframework.http.ResponseCookie.from(GovernanceReviewerCredentials.COOKIE, "")
                .httpOnly(true).secure(true).sameSite("Lax").path("/").maxAge(0).build().toString();
        var logout = http("DELETE", path, null, mutationHeaders(session, logoutKey));
        assertThat(logout.statusCode()).withFailMessage(logout.body()).isEqualTo(204); assertNoStore(logout);
        assertThat(logout.headers().allValues("Set-Cookie")).containsExactly(expected);
        assertThat(expected).startsWith(GovernanceReviewerCredentials.COOKIE + "=; Path=/; Max-Age=0; Expires=")
                .endsWith("; Secure; HttpOnly; SameSite=Lax");
        assertThat(logout.headers().map().toString() + logout.body()).doesNotContain(
                BOOTSTRAP, SIGNING, CONTRACT_KEY, session.cookie.split("=", 2)[1], session.csrf);
        assertIdempotencySecretsAbsent(session, "DELETE", path, logoutKey, "COMPLETED", false);
        assertThat(snapshot(GOVERNED)).isEqualTo(before);
        // Admission/revocation are legitimate logout writes, so do not claim all storage unchanged.
    }

    @Test void sameThreadMvcFixedUuidC99CookieRefusalPrecedesIssuanceAndPostgresAdmission() throws Exception {
        String c99 = KNOWN_COOKIE_TRANSPORT_98 + "j";
        assertThat(c99.getBytes(java.nio.charset.StandardCharsets.UTF_8)).hasSize(99);
        UUID fixed = UUID.fromString("00000000-0000-4000-8000-000000000001");
        var before = snapshot(withAdmission());
        // Mockito static scope is caller-thread only: this is actual synchronous Spring MVC,
        // not an assertion that the separate HttpClient servlet thread inherited the mock.
        for (String reference : List.of(CONTRACT_KEY, c99)) {
            AtomicInteger ready = new AtomicInteger();
            try (var selected = startRealContext(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE.toString(), reference, ready)) {
                assertThat(ready.get()).isEqualTo(1);
                var mvc = org.springframework.test.web.servlet.setup.MockMvcBuilders
                        .webAppContextSetup((org.springframework.web.context.WebApplicationContext) selected)
                        .addFilters(selected.getBean(TraceIdFilter.class), selected.getBean(GovernanceAccessFilter.class),
                                selected.getBean(IdempotencyFilter.class)).build();
                var selectedIssuer = selected.getBean(GovernanceReviewerCredentials.class);
                try (var uuids = org.mockito.Mockito.mockStatic(UUID.class, org.mockito.Mockito.CALLS_REAL_METHODS)) {
                    uuids.when(UUID::randomUUID).thenReturn(fixed);
                    var response = mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get(SESSION)
                            .header("Authorization", "GovernanceBootstrap " + BOOTSTRAP)).andReturn().getResponse();
                    assertThat(response.getHeader("Cache-Control")).contains("no-store");
                    if (reference.equals(c99)) {
                        assertThat(response.getStatus()).isEqualTo(403);
                        assertThat(response.getHeaders("Set-Cookie")).isEmpty();
                        assertThat(response.getContentAsString()).doesNotContain(c99, BOOTSTRAP, SIGNING);
                        assertThat(privateIssuerWindowSize(selectedIssuer, "issuances")).isZero();
                    } else {
                        assertThat(response.getStatus()).isEqualTo(200);
                        assertThat(response.getHeaders("Set-Cookie")).hasSize(1);
                        assertThat(response.getHeader("Set-Cookie")).startsWith(c99);
                        assertThat(privateIssuerWindowSize(selectedIssuer, "issuances")).isEqualTo(1);
                    }
                    assertThat(privateIssuerWindowSize(selectedIssuer, "attempts")).isEqualTo(1);
                }
                assertThat(snapshot(withAdmission())).isEqualTo(before);
            }
        }
        assertThat(snapshot(withAdmission())).isEqualTo(before);
    }

    @Test void actualHttpKnownCIdempotencySecretIsRejectedBeforeReservationWithSafeLogoutControl() throws Exception {
        String cKey = "private-c-admission-canary-32bytes";
        assertThat(cKey.getBytes(java.nio.charset.StandardCharsets.UTF_8).length).isGreaterThanOrEqualTo(32);
        AtomicInteger ready = new AtomicInteger();
        var governedBefore = snapshot(GOVERNED);
        try (var selected = startRealContext(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE.toString(), cKey, ready)) {
            assertThat(ready.get()).isEqualTo(1);
            int selectedPort = selected.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
            var exchange = httpAt(selectedPort, "GET", SESSION, null,
                    List.of("Authorization", "GovernanceBootstrap " + BOOTSTRAP));
            assertThat(exchange.statusCode()).isEqualTo(200);
            var view = json.readTree(exchange.body()).path("data");
            Session current = new Session(exchange.headers().firstValue("Set-Cookie").orElseThrow().split(";", 2)[0],
                    view.path("csrfToken").asString(), UUID.fromString(view.path("sessionId").asString()));
            String path = SESSION + "/" + current.id;
            var before = snapshot(withAdmission());
            for (String forbidden : List.of(cKey, "pre-" + cKey + "-post")) {
                assertThat(forbidden).matches("[A-Za-z0-9._:-]{1,128}");
                var denied = httpAt(selectedPort, "DELETE", path, null, mutationHeaders(current, forbidden));
                assertThat(denied.statusCode()).isEqualTo(400); assertNoStore(denied);
                assertThat(denied.headers().allValues("Set-Cookie")).isEmpty();
                assertThat(denied.headers().allValues("Idempotent-Replayed")).isEmpty();
                assertThat(denied.headers().map().toString() + denied.body()).doesNotContain(cKey, BOOTSTRAP, SIGNING,
                        current.csrf, current.cookie.split("=", 2)[1]);
                assertThat(independentDb().queryForObject("select count(*) from api_idempotency_records where workspace_id=? and actor_id=? and http_method='DELETE' and request_path=? and idempotency_key=?",
                        Integer.class, WORKSPACE, ACTOR, path, forbidden)).isZero();
                assertThat(snapshot(withAdmission())).isEqualTo(before);
            }
            String safeKey = key();
            var valid = httpAt(selectedPort, "DELETE", path, null, mutationHeaders(current, safeKey));
            assertThat(valid.statusCode()).isEqualTo(204); assertNoStore(valid); assertCleared(valid);
            assertThat(valid.headers().map().toString() + valid.body()).doesNotContain(cKey, BOOTSTRAP, SIGNING);
            assertIdempotencySecretsAbsent(current, "DELETE", path, safeKey, "COMPLETED", false);
            assertThat(independentDb().queryForObject("select count(*) from api_idempotency_records where workspace_id=? and actor_id=? and http_method='DELETE' and request_path=? and idempotency_key=? and state='COMPLETED'",
                    Integer.class, WORKSPACE, ACTOR, path, safeKey)).isEqualTo(1);
        }
        assertThat(snapshot(GOVERNED)).isEqualTo(governedBefore);
    }

    @Test void actualHttpNativeRequiredTraceBoundaryIsGuardedAcrossAllThreeSuppliedKeyPositions() throws Exception {
        String composite = "required\",\"traceId\":\"00000000-0000";
        String traceValue = "00000000-0000-4000-8000-000000000001";
        String nearMiss = "00000000-0001-4000-8000-000000000001";
        assertThat(composite.getBytes(java.nio.charset.StandardCharsets.UTF_8)).hasSize(34);
        assertThat(traceValue).doesNotContain(composite);
        var before = snapshot(withAdmission());
        for (String[] cfg : List.of(new String[]{BOOTSTRAP, SIGNING, CONTRACT_KEY},
                new String[]{composite, SIGNING, CONTRACT_KEY},
                new String[]{BOOTSTRAP, composite, CONTRACT_KEY},
                new String[]{BOOTSTRAP, SIGNING, composite})) {
            boolean safeControl = cfg[0].equals(BOOTSTRAP) && cfg[1].equals(SIGNING) && cfg[2].equals(CONTRACT_KEY);
            AtomicInteger ready = new AtomicInteger();
            try (var selected = startRealContext(cfg[0], cfg[1], ACTOR, WORKSPACE.toString(), cfg[2], ready)) {
                assertThat(ready.get()).isEqualTo(1);
                int selectedPort = selected.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
                var denied = httpAt(selectedPort, "GET", SESSION, null, List.of("X-Trace-Id", traceValue));
                assertThat(denied.statusCode()).isEqualTo(403); assertNoStore(denied);
                assertThat(denied.headers().firstValue("Content-Type").orElseThrow()).startsWith("application/problem+json");
                assertThat(denied.headers().firstValue("X-Trace-Id").orElseThrow()).isEqualTo(traceValue);
                assertThat(denied.headers().allValues("Set-Cookie")).isEmpty();
                assertThat(denied.headers().allValues("Idempotent-Replayed")).isEmpty();
                if (safeControl) {
                    // Observe the exact native counterexample carrier with no matching configured secret.
                    assertThat(denied.body()).contains(composite);
                    assertThat(json.readTree(denied.body()).path("detail").asString())
                            .isEqualTo("Current governance session authority required");
                    assertThat(json.readTree(denied.body()).path("traceId").asString()).isEqualTo(traceValue);
                    assertThat(denied.headers().map().toString() + denied.body()).doesNotContain(BOOTSTRAP, SIGNING, CONTRACT_KEY);
                } else {
                    assertThat(denied.body()).isEmpty();
                    assertThat(denied.headers().map().toString()).doesNotContain(composite);
                }
                var ordinary = httpAt(selectedPort, "GET", SESSION, null, List.of("X-Trace-Id", nearMiss));
                assertThat(ordinary.statusCode()).isEqualTo(403); assertNoStore(ordinary);
                assertThat(ordinary.body()).isNotEmpty().doesNotContain(composite);
                assertThat(json.readTree(ordinary.body()).path("traceId").asString()).isEqualTo(nearMiss);
                assertThat(ordinary.headers().allValues("Set-Cookie")).isEmpty();
                var selectedIssuer = selected.getBean(GovernanceReviewerCredentials.class);
                assertThat(privateIssuerWindowSize(selectedIssuer, "attempts")).isZero();
                assertThat(privateIssuerWindowSize(selectedIssuer, "issuances")).isZero();
                assertThat(snapshot(withAdmission())).isEqualTo(before);
            }
        }
        assertThat(snapshot(withAdmission())).isEqualTo(before);
    }

    @Test void actualHttpCompositeCTraceProblemIsEmptyWithoutConfigurationFailureOrAdmission() throws Exception {
        String composite = "\"traceId\":\"abcdefab-1234-5678-9abc";
        String traceValue = "abcdefab-1234-5678-9abc-def012345678";
        String nearMiss = "abcdefab-1234-5678-9abd-def012345678";
        assertThat(composite.getBytes(java.nio.charset.StandardCharsets.UTF_8)).hasSize(34);
        var before = snapshot(withAdmission());
        for (String reference : List.of(CONTRACT_KEY, composite)) {
            AtomicInteger ready = new AtomicInteger();
            try (var selected = startRealContext(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE.toString(), reference, ready)) {
                assertThat(ready.get()).isEqualTo(1);
                int selectedPort = selected.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
                var denied = httpAt(selectedPort, "GET", SESSION, null, List.of("X-Trace-Id", traceValue));
                assertThat(denied.statusCode()).isEqualTo(403); assertNoStore(denied);
                assertThat(denied.headers().firstValue("Content-Type").orElseThrow()).startsWith("application/problem+json");
                assertThat(denied.headers().firstValue("X-Trace-Id").orElseThrow()).isEqualTo(traceValue);
                assertThat(denied.headers().allValues("Set-Cookie")).isEmpty();
                assertThat(denied.headers().allValues("Idempotent-Replayed")).isEmpty();
                if (reference.equals(composite)) {
                    assertThat(denied.body()).isEmpty();
                    assertThat(denied.headers().map().toString()).doesNotContain(composite);
                } else {
                    // Synthetic carrier is not this safe context's configured C secret.
                    assertThat(denied.body()).contains(composite);
                    assertThat(json.readTree(denied.body()).path("traceId").asString()).isEqualTo(traceValue);
                    assertThat(denied.headers().map().toString() + denied.body()).doesNotContain(BOOTSTRAP, SIGNING, CONTRACT_KEY);
                }
                var ordinary = httpAt(selectedPort, "GET", SESSION, null, List.of("X-Trace-Id", nearMiss));
                assertThat(ordinary.statusCode()).isEqualTo(403); assertNoStore(ordinary);
                assertThat(json.readTree(ordinary.body()).path("traceId").asString()).isEqualTo(nearMiss);
                assertThat(ordinary.body()).doesNotContain(composite);
                var selectedIssuer = selected.getBean(GovernanceReviewerCredentials.class);
                assertThat(privateIssuerWindowSize(selectedIssuer, "attempts")).isZero();
                assertThat(privateIssuerWindowSize(selectedIssuer, "issuances")).isZero();
                assertThat(snapshot(withAdmission())).isEqualTo(before);
            }
        }
    }

    @Test void actualHttpCompositeCTraceSuccessEnvelopeWithholdsProofButDoesNotRefundIssuerQuota() throws Exception {
        String composite = "\"traceId\":\"abcdefab-1234-5678-9abc";
        String traceValue = "abcdefab-1234-5678-9abc-def012345678";
        String nearMiss = "abcdefab-1234-5678-9abd-def012345678";
        var before = snapshot(withAdmission());
        AtomicInteger controlReady = new AtomicInteger();
        try (var control = startRealContext(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE.toString(), CONTRACT_KEY, controlReady)) {
            assertThat(controlReady.get()).isEqualTo(1);
            int selectedPort = control.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
            var ordinary = httpAt(selectedPort, "GET", SESSION, null,
                    List.of("Authorization", "GovernanceBootstrap " + BOOTSTRAP, "X-Trace-Id", traceValue));
            assertThat(ordinary.statusCode()).isEqualTo(200); assertNoStore(ordinary);
            assertThat(ordinary.headers().allValues("Set-Cookie")).hasSize(1);
            assertThat(ordinary.body()).contains(composite).doesNotContain(BOOTSTRAP, SIGNING, CONTRACT_KEY);
            assertThat(json.readTree(ordinary.body()).path("traceId").asString()).isEqualTo(traceValue);
            assertThat(snapshot(withAdmission())).isEqualTo(before);
        }
        AtomicInteger ready = new AtomicInteger();
        try (var selected = startRealContext(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE.toString(), composite, ready)) {
            assertThat(ready.get()).isEqualTo(1);
            int selectedPort = selected.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
            var selectedIssuer = selected.getBean(GovernanceReviewerCredentials.class);
            var withheld = httpAt(selectedPort, "GET", SESSION, null,
                    List.of("Authorization", "GovernanceBootstrap " + BOOTSTRAP, "X-Trace-Id", traceValue));
            assertThat(withheld.statusCode()).isEqualTo(403); assertNoStore(withheld);
            assertThat(withheld.body()).isEmpty();
            assertThat(withheld.headers().allValues("Set-Cookie")).isEmpty();
            assertThat(withheld.headers().allValues("Idempotent-Replayed")).isEmpty();
            assertThat(withheld.headers().map().toString()).doesNotContain(composite, BOOTSTRAP, SIGNING);
            // Exchange completed internally before Controller's exact response-body gate.
            assertThat(privateIssuerWindowSize(selectedIssuer, "attempts")).isEqualTo(1);
            assertThat(privateIssuerWindowSize(selectedIssuer, "issuances")).isEqualTo(1);
            assertThat(snapshot(withAdmission())).isEqualTo(before);
            var exchanged = httpAt(selectedPort, "GET", SESSION, null,
                    List.of("Authorization", "GovernanceBootstrap " + BOOTSTRAP, "X-Trace-Id", nearMiss));
            assertThat(exchanged.statusCode()).isEqualTo(200); assertNoStore(exchanged);
            assertThat(exchanged.headers().allValues("Set-Cookie")).hasSize(1);
            assertThat(exchanged.headers().map().toString() + exchanged.body()).doesNotContain(composite, BOOTSTRAP, SIGNING);
            var view = json.readTree(exchanged.body()).path("data");
            Session current = new Session(exchanged.headers().firstValue("Set-Cookie").orElseThrow().split(";", 2)[0],
                    view.path("csrfToken").asString(), UUID.fromString(view.path("sessionId").asString()));
            var deniedRead = httpAt(selectedPort, "GET", SESSION, null,
                    List.of("Cookie", current.cookie, "X-Trace-Id", traceValue));
            assertThat(deniedRead.statusCode()).isEqualTo(403); assertNoStore(deniedRead);
            assertThat(deniedRead.body()).isEmpty(); assertThat(deniedRead.headers().allValues("Set-Cookie")).isEmpty();
            var safeRead = httpAt(selectedPort, "GET", SESSION, null,
                    List.of("Cookie", current.cookie, "X-Trace-Id", nearMiss));
            assertThat(safeRead.statusCode()).isEqualTo(200); assertNoStore(safeRead);
            assertThat(safeRead.headers().allValues("Set-Cookie")).isEmpty();
            assertThat(json.readTree(safeRead.body()).path("data")).isEqualTo(view);
            assertThat(safeRead.headers().map().toString() + safeRead.body()).doesNotContain(composite, BOOTSTRAP, SIGNING);
            assertThat(privateIssuerWindowSize(selectedIssuer, "attempts")).isEqualTo(2);
            assertThat(privateIssuerWindowSize(selectedIssuer, "issuances")).isEqualTo(2);
            assertThat(snapshot(withAdmission())).isEqualTo(before);
            String logoutKey = key(), path = SESSION + "/" + current.id;
            var headers = new ArrayList<String>(mutationHeaders(current, logoutKey));
            headers.add("X-Trace-Id"); headers.add(nearMiss);
            var logout = httpAt(selectedPort, "DELETE", path, null, headers);
            assertThat(logout.statusCode()).isEqualTo(204); assertNoStore(logout); assertCleared(logout);
            String expected = org.springframework.http.ResponseCookie.from(GovernanceReviewerCredentials.COOKIE, "")
                    .httpOnly(true).secure(true).sameSite("Lax").path("/").maxAge(0).build().toString();
            assertThat(logout.headers().allValues("Set-Cookie")).containsExactly(expected);
            assertThat(logout.headers().map().toString() + logout.body()).doesNotContain(composite, BOOTSTRAP, SIGNING,
                    current.csrf, current.cookie.split("=", 2)[1]);
            assertIdempotencySecretsAbsent(current, "DELETE", path, logoutKey, "COMPLETED", false);
            // Additionally bind this context's C34 rather than assuming the baseline CONTRACT_KEY.
            independentDb().query("select t.* from api_idempotency_records t where workspace_id=? and actor_id=? and http_method='DELETE' and request_path=? and idempotency_key=?", result -> {
                assertThat(result.next()).isTrue();
                var columns = result.getMetaData();
                for (int index = 1; index <= columns.getColumnCount(); index++) {
                    if ("response_body".equals(columns.getColumnName(index))) continue;
                    String value = result.getString(index); if (value != null) assertThat(value).doesNotContain(composite);
                }
                byte[] body = result.getBytes("response_body"); assertThat(body).isNotNull();
                assertThat(new String(body, java.nio.charset.StandardCharsets.UTF_8)).doesNotContain(composite);
                assertThat(result.next()).isFalse(); return null;
            }, WORKSPACE, ACTOR, path, logoutKey);
            assertThat(snapshot(GOVERNED)).isEqualTo(beforeSnapshotGoverned(before));
        }
    }

    @Test void composedRealTcpResponseMapperFaultsOverflowAndExactBytesPreservePrivacyQuotaAndPostgres() throws Exception {
        AtomicInteger ready = new AtomicInteger();
        var before = snapshot(withAdmission());
        try (var selected = startResponseSerializerFixtureContext(ready)) {
            assertThat(ready.get()).isEqualTo(1);
            int selectedPort = selected.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
            var fixture = selected.getBean(ResponseSerializerFixture.class);
            assertThat(org.mockito.Mockito.mockingDetails(selected.getBean(ObjectMapper.class)).isSpy()).isTrue();
            assertThat(fixture.mapper.get()).isSameAs(selected.getBean(ObjectMapper.class));
            var selectedIssuer = selected.getBean(GovernanceReviewerCredentials.class);
            String traceValue = "abcdefab-1234-5678-9abc-def012345678";
            var authHeaders = List.of("Authorization", "GovernanceBootstrap " + BOOTSTRAP, "X-Trace-Id", traceValue);
            fixture.select(ResponseSerializerMode.NORMAL);
            var ordinary = responseFixtureHttpBytes(selectedPort, SESSION, authHeaders);
            assertThat(ordinary.statusCode()).isEqualTo(200); assertNoStore(ordinary);
            assertThat(ordinary.headers().firstValue("Content-Type").orElseThrow()).startsWith("application/json");
            assertThat(ordinary.body()).containsExactly(fixture.exactFrame.get());
            assertThat(fixture.calls.get()).isEqualTo(1); assertThat(fixture.faults.get()).isZero();
            assertThat(fixture.lastKind.get()).isEqualTo("SESSION");
            var originalView = json.readTree(ordinary.body()).path("data");
            assertThat(originalView.properties().stream().map(Map.Entry::getKey).toList()).containsExactlyInAnyOrder(
                    "csrfToken", "expiresAt", "actorId", "workspaceId", "role", "sessionId", "demoMode");
            String cookie = ordinary.headers().firstValue("Set-Cookie").orElseThrow().split(";", 2)[0];
            assertThat(ordinary.headers().allValues("Set-Cookie")).hasSize(1);
            fixture.select(ResponseSerializerMode.NORMAL);
            var normalProblem = responseFixtureHttpBytes(selectedPort, SESSION, List.of("X-Trace-Id", traceValue));
            assertThat(normalProblem.statusCode()).isEqualTo(403); assertNoStore(normalProblem);
            assertThat(normalProblem.body()).containsExactly(fixture.exactFrame.get());
            assertThat(fixture.calls.get()).isEqualTo(1); assertThat(fixture.lastKind.get()).isEqualTo("PROBLEM:OPERATOR_AUTH_REQUIRED");
            assertThat(normalProblem.headers().firstValue("Content-Type").orElseThrow()).startsWith("application/problem+json");
            assertThat(snapshot(withAdmission())).isEqualTo(before);
            var logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
            var appender = new PreparedDiagnosticAppender();
            appender.setContext(logger.getLoggerContext()); appender.start(); logger.addAppender(appender);
            int issued = 1;
            try {
                for (ResponseSerializerMode mode : List.of(ResponseSerializerMode.THROW, ResponseSerializerMode.OVERSIZE)) {
                    fixture.select(mode);
                    var withheld = responseFixtureHttpBytes(selectedPort, SESSION, authHeaders);
                    assertResponseFixtureRefusal(withheld, 403, "application/json", fixture, mode, "SESSION");
                    issued++;
                    assertThat(privateIssuerWindowSize(selectedIssuer, "attempts")).isEqualTo(issued);
                    assertThat(privateIssuerWindowSize(selectedIssuer, "issuances")).isEqualTo(issued);
                    fixture.select(mode);
                    var denied = responseFixtureHttpBytes(selectedPort, SESSION, List.of("X-Trace-Id", traceValue));
                    assertResponseFixtureRefusal(denied, 403, "application/problem+json", fixture, mode, "PROBLEM:OPERATOR_AUTH_REQUIRED");
                    fixture.select(mode);
                    var invalid = responseFixtureHttpBytes(selectedPort, SESSION + "?invalid=1", authHeaders);
                    assertResponseFixtureRefusal(invalid, 400, "application/problem+json", fixture, mode, "PROBLEM:VALIDATION_ERROR");
                    boolean renamed = false;
                    try {
                        db.execute("alter table reviewer_session_revocations rename to governance_response_mapper_lookup_fixture");
                        renamed = true;
                        fixture.select(mode);
                        var unavailable = responseFixtureHttpBytes(selectedPort, SESSION,
                                List.of("Cookie", cookie, "X-Trace-Id", traceValue));
                        assertResponseFixtureRefusal(unavailable, 500, "application/problem+json", fixture, mode, "PROBLEM:INTERNAL_ERROR");
                    } finally {
                        if (renamed) db.execute("alter table governance_response_mapper_lookup_fixture rename to reviewer_session_revocations");
                        fixture.select(ResponseSerializerMode.NORMAL);
                    }
                    assertThat(privateIssuerWindowSize(selectedIssuer, "attempts")).isEqualTo(issued);
                    assertThat(privateIssuerWindowSize(selectedIssuer, "issuances")).isEqualTo(issued);
                    assertThat(snapshot(withAdmission())).isEqualTo(before);
                    var restored = responseFixtureHttpBytes(selectedPort, SESSION,
                            List.of("Cookie", cookie, "X-Trace-Id", traceValue));
                    assertThat(restored.statusCode()).isEqualTo(200); assertNoStore(restored);
                    assertThat(restored.body()).containsExactly(fixture.exactFrame.get());
                    assertThat(fixture.calls.get()).isEqualTo(1); assertThat(fixture.faults.get()).isZero();
                    assertThat(restored.headers().allValues("Set-Cookie")).isEmpty();
                    assertThat(json.readTree(restored.body()).path("data")).isEqualTo(originalView);
                    assertThat(privateIssuerWindowSize(selectedIssuer, "issuances")).isEqualTo(issued);
                }
                assertThat(appender.events).noneMatch(event ->
                        event.getLoggerName().equals(GovernanceAccessFilter.class.getName())); // Owned storage log is omitted.
                for (var event : appender.events) {
                    assertThat(event.getFormattedMessage()).doesNotContain(BOOTSTRAP, SIGNING, CONTRACT_KEY, ResponseSerializerFixture.FAULT_MARKER);
                    assertThat(event.getMDCPropertyMap().toString()).doesNotContain(BOOTSTRAP, SIGNING, CONTRACT_KEY, ResponseSerializerFixture.FAULT_MARKER);
                    if (event.getThrowableProxy() != null)
                        assertThat(ch.qos.logback.classic.spi.ThrowableProxyUtil.asString(event.getThrowableProxy()))
                                .doesNotContain(BOOTSTRAP, SIGNING, CONTRACT_KEY, ResponseSerializerFixture.FAULT_MARKER);
                }
                assertThat(snapshot(withAdmission())).isEqualTo(before);
            } finally {
                fixture.select(ResponseSerializerMode.NORMAL);
                logger.detachAppender(appender); appender.stop();
            }
        }
        assertThat(snapshot(withAdmission())).isEqualTo(before);
    }

    private void assertResponseFixtureRefusal(HttpResponse<byte[]> response, int status, String mediaType,
            ResponseSerializerFixture fixture, ResponseSerializerMode mode, String kind) {
        assertThat(response.statusCode()).isEqualTo(status); assertNoStore(response);
        assertThat(response.headers().firstValue("Content-Type").orElseThrow()).startsWith(mediaType);
        assertThat(response.body()).isEmpty();
        assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
        assertThat(response.headers().allValues("Idempotent-Replayed")).isEmpty();
        assertThat(response.headers().map().toString()).doesNotContain(BOOTSTRAP, SIGNING, CONTRACT_KEY, ResponseSerializerFixture.FAULT_MARKER);
        assertThat(fixture.calls.get()).isEqualTo(1); assertThat(fixture.faults.get()).isEqualTo(1);
        assertThat(fixture.lastKind.get()).isEqualTo(kind);
        if (mode == ResponseSerializerMode.THROW) assertThat(fixture.exactFrame.get()).isNull();
        else {
            assertThat(fixture.exactFrame.get().length).isGreaterThan(6000);
            assertThat(new String(fixture.exactFrame.get(), java.nio.charset.StandardCharsets.UTF_8))
                    .contains(BOOTSTRAP, SIGNING, CONTRACT_KEY, ResponseSerializerFixture.FAULT_MARKER);
        }
    }

    private HttpResponse<byte[]> responseFixtureHttpBytes(int selectedPort, String path, List<String> headers) throws Exception {
        var builder = HttpRequest.newBuilder(URI.create("http://localhost:" + selectedPort + path)).timeout(Duration.ofSeconds(15));
        for (int i = 0; i < headers.size(); i += 2) builder.header(headers.get(i), headers.get(i + 1));
        return client.send(builder.GET().build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    private ConfigurableApplicationContext startResponseSerializerFixtureContext(AtomicInteger ready) {
        // Explicit source only: old startup contexts and the main test context never import this fixture.
        return new SpringApplicationBuilder(FinsecSealApplication.class, ResponseSerializerFixtureConfiguration.class)
                .listeners((ApplicationListener<ApplicationReadyEvent>) event -> ready.incrementAndGet())
                .run("--server.port=0", "--spring.main.banner-mode=off", "--spring.main.lazy-initialization=false",
                        "--spring.datasource.url=" + POSTGRES.getJdbcUrl(), "--spring.datasource.username=" + POSTGRES.getUsername(),
                        "--spring.datasource.password=" + POSTGRES.getPassword(),
                        "--finsec.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        "--finsec.cors.allowed-origins=http://localhost:5173", "--finsec.scheduling.enabled=false",
                        "--finsec.generation.worker-enabled=false", "--spring.datasource.hikari.maximum-pool-size=2",
                        "--finsec.governance-access.bootstrap-key=" + BOOTSTRAP,
                        "--finsec.governance-access.signing-key=" + SIGNING,
                        "--finsec.governance-access.actor=" + ACTOR, "--finsec.governance-access.workspace=" + WORKSPACE,
                        "--finsec.contract-access.key=" + CONTRACT_KEY);
    }

    enum ResponseSerializerMode { NORMAL, THROW, OVERSIZE }

    static final class ResponseSerializerFixture {
        static final String FAULT_MARKER = "synthetic-private-mapper-fault-canary-32bytes";
        final AtomicReference<ResponseSerializerMode> mode = new AtomicReference<>(ResponseSerializerMode.NORMAL);
        final AtomicReference<ObjectMapper> mapper = new AtomicReference<>();
        final AtomicReference<byte[]> exactFrame = new AtomicReference<>();
        final AtomicReference<String> lastKind = new AtomicReference<>();
        final AtomicInteger calls = new AtomicInteger(), faults = new AtomicInteger();
        void select(ResponseSerializerMode selected) {
            calls.set(0); faults.set(0); exactFrame.set(null); lastKind.set(null); mode.set(selected);
        }
        ObjectMapper observeActualApplicationMapper(ObjectMapper actual) {
            ObjectMapper observed = org.mockito.Mockito.spy(actual);
            org.mockito.Mockito.doAnswer(invocation -> {
                Object value = invocation.getArgument(0);
                String kind = null;
                if (value instanceof com.finsecseal.common.api.ApiResponse<?> response
                        && response.data() instanceof GovernanceReviewerSessionController.SessionView) kind = "SESSION";
                else if (value instanceof tools.jackson.databind.node.ObjectNode problem) {
                    String detail = problem.path("detail").asString();
                    if (List.of("Current governance session authority required",
                            "Use the exact canonical governance API path and method",
                            "Governance authority storage unavailable").contains(detail))
                        kind = "PROBLEM:" + problem.path("code").asString();
                }
                if (kind == null) return invocation.callRealMethod(); // No read/parser or other-role response mocking.
                calls.incrementAndGet(); lastKind.set(kind);
                ResponseSerializerMode selected = mode.get();
                if (selected == ResponseSerializerMode.THROW) {
                    faults.incrementAndGet();
                    throw new IllegalStateException(FAULT_MARKER + " " + BOOTSTRAP + " " + SIGNING + " " + CONTRACT_KEY);
                }
                byte[] frame;
                if (selected == ResponseSerializerMode.OVERSIZE) {
                    faults.incrementAndGet();
                    // Actual registered Tools serializer, actual response object, test-only extra padding property.
                    tools.jackson.databind.node.ObjectNode decorated = actual.valueToTree(value);
                    decorated.put("governanceResponseFixturePadding", "x".repeat(6001) + FAULT_MARKER + BOOTSTRAP + SIGNING + CONTRACT_KEY);
                    frame = actual.writeValueAsBytes(decorated);
                } else frame = (byte[]) invocation.callRealMethod();
                exactFrame.set(frame.clone()); return frame;
            }).when(observed).writeValueAsBytes(org.mockito.Mockito.any());
            mapper.set(observed); return observed;
        }
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class ResponseSerializerFixtureConfiguration {
        @Bean static ResponseSerializerFixture governanceResponseSerializerFixture() { return new ResponseSerializerFixture(); }
        @Bean static org.springframework.beans.factory.config.BeanPostProcessor governanceResponseMapperObserver(ResponseSerializerFixture fixture) {
            return new org.springframework.beans.factory.config.BeanPostProcessor() {
                @Override public Object postProcessAfterInitialization(Object bean, String name) {
                    return bean instanceof ObjectMapper actual ? fixture.observeActualApplicationMapper(actual) : bean;
                }
            };
        }
    }

    private int privateIssuerWindowSize(GovernanceReviewerCredentials selected, String name) throws Exception {
        synchronized (selected) {
            var field = GovernanceReviewerCredentials.class.getDeclaredField(name); field.setAccessible(true);
            return ((java.util.Deque<?>) field.get(selected)).size();
        }
    }

    private void assertFreshActualQuotaContext() throws Exception {
        assertThat(webServerContext.isActive()).as("quota application context is active").isTrue();
        assertThat(webServerContext.getWebServer()).as("quota actual web server exists").isNotNull();
        assertThat(webServerContext.getWebServer().getPort()).as("quota actual server port matches injected port")
                .isEqualTo(port);
        assertThat(webServerContext.getBean(GovernanceReviewerCredentials.class) == issuer)
                .as("quota issuer is the current application context bean").isTrue();
        assertThat(privateIssuerWindowSize(issuer, "attempts")).as("fresh quota issuer attempts").isZero();
        assertThat(privateIssuerWindowSize(issuer, "issuances")).as("fresh quota issuer issuances").isZero();
    }

    private void assertOwnedProblemRepresentation(HttpResponse<String> response, int status, String title,
            String code, String detail, String... canaries) {
        String fixed = json.writeValueAsString(json.createObjectNode().put("status", status).put("title", title)
                .put("code", code).put("detail", detail));
        String prefix = fixed.substring(0, fixed.length() - 1) + ",\"traceId\":\"";
        assertThat(response.statusCode()).isEqualTo(status); assertNoStore(response);
        assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
        assertThat(response.headers().allValues("Idempotent-Replayed")).isEmpty();
        assertThat(response.body()).startsWith(prefix);
        assertResponseUsesSafeMdcTrace(response);
        assertThat(response.headers().map().toString() + response.body()).doesNotContain(canaries);
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

    private void assertEarlyStorageFailure(HttpResponse<String> response) {
        assertThat(response.statusCode()).isEqualTo(500); assertNoStore(response);
        assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
        assertThat(response.headers().allValues("Idempotent-Replayed")).isEmpty();
        assertThat(json.readTree(response.body()).path("detail").asString())
                .isEqualTo("Governance authority storage unavailable");
        assertThat(response.body()).doesNotContain(BOOTSTRAP, SIGNING, "select exists", "session_digest",
                "reviewer_session_revocations", "governance_lookup_unavailable_fixture", "PSQLException");
        // Existing caller XTrace/problem trace transport is deliberately unchanged; diagnostic-only guarantee.
    }

    private static final class PreparedDiagnosticAppender extends ch.qos.logback.core.AppenderBase<ch.qos.logback.classic.spi.ILoggingEvent> {
        final List<ch.qos.logback.classic.spi.ILoggingEvent> events = new java.util.concurrent.CopyOnWriteArrayList<>();
        @Override protected void append(ch.qos.logback.classic.spi.ILoggingEvent event) {
            // Capture actual emission-time fields; absence of the owned event is checked separately.
            event.prepareForDeferredProcessing();
            events.add(event);
        }
    }

    @Test void directTransactionalLogoutRollbackAndCommitAreVisibleToIndependentReader() throws Exception {
        assertThat(transactions).isInstanceOf(JpaTransactionManager.class);
        var session = issue(issuer);
        var identity = issuer.mutationContext(session, csrf(session.csrfToken()));
        String digest = this.digest.sha256("FINSEC_GOVERNANCE_SESSION_ID_V1:" + WORKSPACE + ":" + identity.sessionId());
        for (boolean rollback : List.of(true, false)) {
            MockHttpServletRequest request = mutation("DELETE", SESSION + "/" + identity.sessionId(), session);
            direct(filter, request, (req, res) -> new TransactionTemplate(transactions).executeWithoutResult(status -> {
                assertNormalJPAHolder();
                controller.revoke(identity.sessionId(), (HttpServletRequest) req);
                assertThat(db.queryForObject("select count(*) from reviewer_session_revocations where session_digest=?",
                        Integer.class, digest)).isEqualTo(1);
                assertThat(independentDb().queryForObject("select count(*) from reviewer_session_revocations where session_digest=?",
                        Integer.class, digest)).isZero();
                if (rollback) status.setRollbackOnly();
            }));
            assertThat(independentDb().queryForObject("select count(*) from reviewer_session_revocations where session_digest=?",
                    Integer.class, digest)).isEqualTo(rollback ? 0 : 1);
        }
    }

    @Test void deniedOriginsAndPreflightsDoNotIssueOrReserveAndAllowedOriginUsesNativeContract() throws Exception {
        var before = snapshot(withAdmission());
        var denied = http("GET", SESSION, null, List.of("Origin", "https://not-allowed.invalid",
                "Authorization", "GovernanceBootstrap " + BOOTSTRAP));
        assertThat(denied.statusCode()).isEqualTo(403);
        assertThat(denied.headers().allValues("Set-Cookie")).isEmpty();
        var allowed = http("OPTIONS", SESSION, null, List.of("Origin", "http://localhost:5173",
                "Access-Control-Request-Method", "GET", "Access-Control-Request-Headers", "Authorization"));
        assertThat(allowed.statusCode()).isEqualTo(200);
        assertThat(allowed.headers().firstValue("Access-Control-Allow-Origin")).contains("http://localhost:5173");
        assertThat(allowed.headers().firstValue("Access-Control-Allow-Credentials")).contains("true");
        var rejected = http("OPTIONS", SESSION, null, List.of("Origin", "https://not-allowed.invalid",
                "Access-Control-Request-Method", "GET"));
        assertThat(rejected.statusCode()).isEqualTo(403);
        assertThat(allowed.headers().allValues("Set-Cookie")).isEmpty();
        assertThat(snapshot(withAdmission())).isEqualTo(before);
    }

    @Test void csrfCookieHeaderCardinalityActorAndBootstrapOnlyRiskFailuresPrecedeReservation() throws Exception {
        Graph graph = graph(WORKSPACE);
        Session session = httpSession();
        var before = snapshot(withAdmission());
        List<List<String>> rejected = List.of(
                List.of("Authorization", "GovernanceBootstrap " + BOOTSTRAP, "Idempotency-Key", key()),
                List.of("Cookie", session.cookie, "Idempotency-Key", key()),
                List.of("Cookie", session.cookie, "X-CSRF-Token", "wrong", "Idempotency-Key", key()),
                List.of("Cookie", session.cookie + "; " + session.cookie, "X-CSRF-Token", session.csrf, "Idempotency-Key", key()),
                List.of("Cookie", session.cookie, "X-CSRF-Token", session.csrf, "X-CSRF-Token", session.csrf, "Idempotency-Key", key()),
                List.of("Cookie", session.cookie, "X-CSRF-Token", session.csrf, "X-Actor-Id", "wrong", "Idempotency-Key", key()),
                List.of("Cookie", session.cookie, "X-CSRF-Token", session.csrf, "Idempotency-Key", key(), "Idempotency-Key", key()));
        for (List<String> headers : rejected) {
            var denied = http("POST", riskPath(graph.finding), "{}", headers);
            assertThat(denied.statusCode()).withFailMessage(denied.body()).isBetween(400, 403);
            assertThat(denied.headers().allValues("Idempotent-Replayed")).isEmpty();
            assertNoStore(denied);
        }
        assertThat(snapshot(withAdmission())).isEqualTo(before);
    }

    @Test void foreignAndMissingFindingWorkspaceFKDenyBeforeCompletedCacheReplay() throws Exception {
        UUID foreignWorkspace = UUID.randomUUID();
        db.update("insert into workspaces(id,name,mode) values(?, 'foreign governance fixture','DEMO')", foreignWorkspace);
        Graph foreign = graph(foreignWorkspace);
        Session session = httpSession();
        String cachedKey = key();
        var cached = new MockHttpServletRequest("POST", riskPath(foreign.finding));
        cached.setContentType("application/json"); cached.setContent("{}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        cached.addHeader("Idempotency-Key", cachedKey); cached.addHeader("X-Actor-Id", ACTOR);
        cached.setAttribute(IdempotencyFilter.WORKSPACE, WORKSPACE);
        var cachedResponse = new MockHttpServletResponse();
        trace.doFilter(cached, cachedResponse, (r, s) -> common.doFilter(r, s,
                (untrusted, result) -> ((HttpServletResponse) result).getWriter().write("synthetic-cache-canary")));
        assertThat(db.queryForObject("select state from api_idempotency_records where idempotency_key=?",
                String.class, cachedKey)).isEqualTo("COMPLETED");
        var before = snapshot(withAdmission());
        for (UUID finding : List.of(foreign.finding, UUID.randomUUID())) {
            var denied = http("POST", riskPath(finding), "{}", mutationHeaders(session, cachedKey));
            assertThat(denied.statusCode()).isEqualTo(403);
            assertThat(denied.headers().allValues("Idempotent-Replayed")).isEmpty();
            assertThat(denied.body()).doesNotContain("synthetic-cache-canary");
        }
        assertThat(snapshot(withAdmission())).isEqualTo(before);
    }

    @Test void exactCompletedRiskResponseCannotReplayWithoutCurrentCookieCsrfAuthority() throws Exception {
        Graph graph = graph(WORKSPACE);
        Session session = httpSession();
        String key = key();
        var primed = risk(graph, session, key, List.of());
        assertThat(primed.statusCode()).withFailMessage(primed.body()).isEqualTo(200);
        assertThat(db.queryForObject("select state from api_idempotency_records where idempotency_key=?",
                String.class, key)).isEqualTo("COMPLETED");
        assertIdempotencySecretsAbsent(session, "POST", riskPath(graph.finding), key, "COMPLETED", false);
        int calls = probe.callCount();
        List<List<String>> invalidAuthorities = List.of(
                List.of("X-CSRF-Token", session.csrf, "Idempotency-Key", key),
                List.of("Cookie", GovernanceReviewerCredentials.COOKIE + "=invalid", "X-CSRF-Token", session.csrf, "Idempotency-Key", key),
                List.of("Cookie", session.cookie, "Idempotency-Key", key),
                List.of("Cookie", session.cookie, "X-CSRF-Token", "wrong", "Idempotency-Key", key),
                List.of("Cookie", signedInvalidRepeatCookie(session, true), "X-CSRF-Token", session.csrf, "Idempotency-Key", key),
                List.of("Cookie", signedInvalidRepeatCookie(session, false), "X-CSRF-Token", session.csrf, "Idempotency-Key", key));
        for (List<String> headers : invalidAuthorities) {
            var before = snapshot(withAdmission());
            // Same route, key, body and content type as the actual completed valid response.
            var denied = http("POST", riskPath(graph.finding), "{}", headers);
            assertThat(denied.statusCode()).isEqualTo(403);
            assertNoStore(denied);
            assertThat(denied.headers().allValues("Idempotent-Replayed")).isEmpty();
            assertThat(denied.body()).isNotEqualTo(primed.body()).doesNotContain("holderSynchronized", "read committed");
            assertThat(probe.callCount()).isEqualTo(calls);
            assertThat(snapshot(withAdmission())).isEqualTo(before);
        }
        var cookieRequest = new MockHttpServletRequest();
        cookieRequest.setCookies(new Cookie(GovernanceReviewerCredentials.COOKIE, session.cookie.split("=", 2)[1]));
        var held = issuer.session(cookieRequest);
        assertThat(held).isNotNull();
        var independent = new GovernanceReviewerSessionRevocations(independentDb(), digest, issuer);
        independent.revoke(issuer.mutationContext(held, csrf(session.csrf)));
        assertThat(independent.isRevoked(held.identity())).isTrue();
        var revokedBefore = snapshot(withAdmission());
        var revoked = risk(graph, session, key, List.of());
        assertThat(revoked.statusCode()).isEqualTo(403);
        assertNoStore(revoked);
        assertThat(revoked.headers().allValues("Idempotent-Replayed")).isEmpty();
        assertThat(revoked.body()).isNotEqualTo(primed.body()).doesNotContain("holderSynchronized", "read committed");
        assertThat(probe.callCount()).isEqualTo(calls);
        assertThat(snapshot(withAdmission())).isEqualTo(revokedBefore);
    }

    @Test void directRealFilterHeadQueryAndUnsupportedMethodsDenyOtherwiseValidInputs() throws Exception {
        Graph graph = graph(WORKSPACE);
        var session = issue(issuer);
        var before = snapshot(withAdmission());
        int calls = probe.callCount();
        List<MockHttpServletRequest> requests = new ArrayList<>();
        requests.add(mutation("HEAD", SESSION, session));
        requests.add(mutation("HEAD", riskPath(graph.finding), session));
        requests.add(mutation("PATCH", riskPath(graph.finding), session));
        requests.add(mutation("PUT", riskPath(graph.finding), session));
        var queriedRisk = mutation("POST", riskPath(graph.finding), session);
        queriedRisk.setQueryString("source=canary"); requests.add(queriedRisk);
        var queriedCurrent = mutation("GET", SESSION, session);
        queriedCurrent.setQueryString("source=canary"); requests.add(queriedCurrent);
        for (var request : requests) {
            AtomicInteger downstream = new AtomicInteger();
            var denied = direct(filter, request, (r, s) -> downstream.incrementAndGet());
            assertThat(denied.getStatus()).isEqualTo(400);
            assertThat(denied.getHeader("Cache-Control")).isEqualTo("no-store");
            assertThat(denied.getHeaders("Idempotent-Replayed")).isEmpty();
            assertThat(denied.getHeaders("Set-Cookie")).isEmpty();
            assertThat(downstream.get()).isZero();
            assertThat(probe.callCount()).isEqualTo(calls);
            assertThat(snapshot(withAdmission())).isEqualTo(before);
        }
    }

    @Test void directRealFilterRejectsProtectedVariantsWithoutDownstreamOrDatabaseEffects() throws Exception {
        String id = UUID.randomUUID().toString();
        var before = snapshot(withAdmission());
        for (String raw : List.of(SESSION + ";matrix", SESSION + "%ZZ", SESSION + "%2525252541",
                "/api/v1/findings;matrix/" + id + ":accept-risk",
                "/api/v1/findings/" + id + ":accept%2525252drisk",
                "/api/v1/findings/%ZZ", "/%2525252561pi/v1/findings/" + id + ":accept-risk")) {
            var req = new MockHttpServletRequest("POST", raw);
            req.setServletPath(raw);
            req.addHeader("Authorization", "GovernanceBootstrap " + BOOTSTRAP);
            AtomicInteger downstream = new AtomicInteger();
            var response = direct(filter, req, (r, s) -> downstream.incrementAndGet());
            assertThat(response.getStatus()).isEqualTo(400);
            assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
            assertThat(downstream.get()).isZero();
            assertThat(response.getHeaders("Set-Cookie")).isEmpty();
            assertThat(response.getHeaders("Idempotent-Replayed")).isEmpty();
        }
        assertThat(snapshot(withAdmission())).isEqualTo(before);
    }

    @Test void mappedProtectedDotAndEncodedSlashAliasesUseOriginalUriRejection() throws Exception {
        String id = UUID.randomUUID().toString();
        var before = snapshot(withAdmission());
        for (String raw : List.of("/api/v1/agents/../findings/" + id + ":accept-risk",
                "/api/v1/agents/%2e%2e%2ffindings/" + id + ":accept-risk")) {
            var req = new MockHttpServletRequest("POST", raw);
            req.setServletPath("/api/v1/findings/" + id + ":accept-risk");
            AtomicInteger downstream = new AtomicInteger();
            assertThat(direct(filter, req, (r, s) -> downstream.incrementAndGet()).getStatus()).isEqualTo(400);
            assertThat(downstream.get()).isZero();
        }
        assertThat(snapshot(withAdmission())).isEqualTo(before);
    }

    @Test void clearlyUnrelatedMalformedNestedAndCanonicalTriageResolveKeepPriorSkip() throws Exception {
        String id = UUID.randomUUID().toString();
        for (String raw : List.of("/api/v1/agents/%ZZ", "/api/v1/agents/%2525252541",
                "/actuator/health/%ZZ", "/api/v2/agents/%ZZ", "/other/%2525252541",
                "/api/v1/findings/" + id + ":triage", "/api/v1/findings/" + id + ":resolve")) {
            var req = new MockHttpServletRequest("GET", raw); req.setServletPath(raw);
            AtomicInteger downstream = new AtomicInteger();
            var response = new MockHttpServletResponse();
            filter.doFilter(req, response, (r, s) -> downstream.incrementAndGet());
            assertThat(downstream.get()).isEqualTo(1);
            assertThat(response.getHeader("Cache-Control")).isNull();
        }
    }

    @Test void actualContainerCanonicalHeadQueryMatrixAndNestedPathsDenyWithoutEffects() throws Exception {
        var before = snapshot(withAdmission());
        for (String path : List.of(SESSION, SESSION + "?secret=canary", SESSION + ";matrix",
                SESSION + "%2525252541", "/api/v1/agents/../findings/" + UUID.randomUUID() + ":accept-risk")) {
            var response = http(path.equals(SESSION) ? "HEAD" : "GET", path, null,
                    List.of("Authorization", "GovernanceBootstrap " + BOOTSTRAP));
            assertThat(response.statusCode()).isBetween(400, 499);
            assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
        }
        assertThat(snapshot(withAdmission())).isEqualTo(before);
    }

    @Test void admittedAuditCommentBindsSameSealedFactsAcrossCachedRequestAndRejectsMutatedInputs() throws Exception {
        Graph graph = graph(WORKSPACE);
        var before = snapshot(GOVERNED);
        class CountingClock extends Clock {
            private final Clock delegate;
            private final AtomicInteger calls;
            CountingClock(Clock delegate, AtomicInteger calls) { this.delegate = delegate; this.calls = calls; }
            @Override public ZoneId getZone() { return delegate.getZone(); }
            @Override public Clock withZone(ZoneId zone) { return new CountingClock(delegate.withZone(zone), calls); }
            @Override public Instant instant() { calls.incrementAndGet(); return delegate.instant(); }
        }
        var clockCalls = new AtomicInteger();
        var local = localIssuer(new CountingClock(Clock.systemUTC(), clockCalls));
        // Real spies preserve actual PG execution; no authority/SQL return value is stubbed.
        var observedDb = org.mockito.Mockito.spy(db);
        var localRevocations = org.mockito.Mockito.spy(new GovernanceReviewerSessionRevocations(observedDb, digest, local));
        var localAccess = new GovernanceAccess(observedDb, local, localRevocations, instance);
        var localFilter = new GovernanceAccessFilter(local, localRevocations, localAccess, json);
        var session = issue(local);
        AtomicInteger completedChecks = new AtomicInteger();
        var response = direct(localFilter, mutation("POST", riskPath(graph.finding), session), (req, res) -> {
            var request = (HttpServletRequest) req;
            org.mockito.Mockito.clearInvocations(observedDb, localRevocations);
            var context = localAccess.requireMutationContext(request);
            assertThat(org.mockito.Mockito.mockingDetails(observedDb).getInvocations())
                    .as("real mutation-context admission uses JdbcTemplate").isNotEmpty();
            org.mockito.Mockito.verify(localRevocations, org.mockito.Mockito.atLeastOnce())
                    .isRevoked(org.mockito.Mockito.any(GovernanceReviewerContext.class));
            assertThat(request.getClass().getSimpleName()).isEqualTo("CachedBodyRequest");
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            var currentIdentity = local.mutationContext(session, request);
            org.mockito.Mockito.clearInvocations(observedDb, localRevocations);
            clockCalls.set(0);
            localAccess.requireSafeAuditComment(context, request, "Reviewed rationale");
            localAccess.requireSafeAuditComment(context, new jakarta.servlet.http.HttpServletRequestWrapper(request), "Reviewed rationale");
            org.mockito.Mockito.verifyNoInteractions(observedDb, localRevocations);
            assertThat(clockCalls.get()).as("public comment guard clock calls").isZero();
            assertThat(local.current(currentIdentity, true)).isTrue();
            assertThat(clockCalls.get()).as("current authority positive clock control").isPositive();
            assertCommentDenied(() -> localAccess.requireSafeAuditComment(null, request, "Reviewed rationale"));
            assertCommentDenied(() -> localAccess.requireSafeAuditComment(context, null, "Reviewed rationale"));
            assertCommentDenied(() -> new GovernanceAccess(observedDb, local, localRevocations, instance)
                    .requireSafeAuditComment(context, request, "Reviewed rationale"));
            var copied = mutation("POST", riskPath(graph.finding), session);
            copied.removeHeader("Idempotency-Key"); copied.addHeader("Idempotency-Key", context.idempotencyKey());
            assertCommentDenied(() -> localAccess.requireSafeAuditComment(context, copied, "Reviewed rationale"));
            localAccess.establish(copied, session, local.mutationContext(session, copied), graph.finding,
                    context.idempotencyKey(), false, false);
            assertCommentDenied(() -> localAccess.requireSafeAuditComment(context, copied, "Reviewed rationale"));
            for (HttpServletRequest changed : List.of(
                    new jakarta.servlet.http.HttpServletRequestWrapper(request) { @Override public String getMethod() { return "PUT"; } },
                    new jakarta.servlet.http.HttpServletRequestWrapper(request) { @Override public String getRequestURI() { return riskPath(UUID.randomUUID()); } },
                    new jakarta.servlet.http.HttpServletRequestWrapper(request) { @Override public String getQueryString() { return "changed=true"; } },
                    alteredAuditHeader(request, "Idempotency-Key", "different-key"),
                    alteredAuditHeader(request, "X-CSRF-Token", "different-csrf"),
                    alteredAuditHeader(request, "Authorization", "synthetic-comment-owned-auth-reference-at-least-32"),
                    new jakarta.servlet.http.HttpServletRequestWrapper(request) {
                        @Override public Cookie[] getCookies() { return new Cookie[]{new Cookie(GovernanceReviewerCredentials.COOKIE, "different-token")}; }
                    })) assertCommentDenied(() -> localAccess.requireSafeAuditComment(context, changed, "Reviewed rationale"));
            String originalTrace = TraceIdFilter.currentTraceId();
            MDC.put(TraceIdFilter.TRACE_ID, UUID.randomUUID().toString());
            try { assertCommentDenied(() -> localAccess.requireSafeAuditComment(context, request, "Reviewed rationale")); }
            finally { MDC.put(TraceIdFilter.TRACE_ID, originalTrace); }
            localAccess.requireSafeAuditComment(context, request, "Reviewed rationale");
            org.mockito.Mockito.verifyNoInteractions(observedDb, localRevocations);
            // Mark completion only after every positive, purity and mutated-input assertion returned.
            completedChecks.incrementAndGet();
        });
        assertThat(response.getStatus()).as("sealed-request direct callback response").isEqualTo(200);
        assertThat(completedChecks.get()).as("all sealed-request callback assertions completed").isEqualTo(1);
        assertThat(snapshot(GOVERNED)).isEqualTo(before);
    }

    @Test @ExtendWith(OutputCaptureExtension.class)
    void actualTcpAuditCommentDeniesLiteralReferencesBeforeContinuationWithoutDomainWrites(CapturedOutput output) throws Exception {
        Graph graph = graph(WORKSPACE);
        var before = snapshot(GOVERNED);
        try (var selected = startCommentProbeContext()) {
            int selectedPort = ((ServletWebServerApplicationContext) selected).getWebServer().getPort();
            var selectedProbe = selected.getBean(ContinuationProbe.class);
            var exchange = httpAt(selectedPort, "GET", SESSION, null, List.of("Authorization", "GovernanceBootstrap " + BOOTSTRAP));
            assertThat(exchange.statusCode()).isEqualTo(200);
            var view = json.readTree(exchange.body()).path("data");
            var session = new Session(exchange.headers().firstValue("Set-Cookie").orElseThrow().split(";", 2)[0],
                    view.path("csrfToken").asString(), UUID.fromString(view.path("sessionId").asString()));
            int start = selectedProbe.callCount();
            String safeKey = key();
            var safe = httpAt(selectedPort, "POST", riskPath(graph.finding),
                    json.writeValueAsString(Map.of("comment", "Reviewed rationale")), mutationHeaders(session, safeKey));
            assertThat(safe.statusCode()).isEqualTo(200);
            assertThat(selectedProbe.callCount()).isEqualTo(start + 1);
            for (String reference : List.of(BOOTSTRAP, SIGNING, CONTRACT_KEY, session.cookie.split("=", 2)[1], session.csrf)) {
                String selectedKey = key();
                var denied = httpAt(selectedPort, "POST", riskPath(graph.finding),
                        json.writeValueAsString(Map.of("comment", "Reviewed " + reference)), mutationHeaders(session, selectedKey));
                assertThat(denied.statusCode()).isEqualTo(403);
                assertNoStore(denied);
                assertThat(denied.headers().allValues("Set-Cookie")).isEmpty();
                assertThat(denied.body()).doesNotContain(reference);
                assertThat(selectedProbe.callCount()).isEqualTo(start + 1);
                assertIdempotencySecretsAbsent(session, "POST", riskPath(graph.finding), selectedKey, "COMPLETED", false);
            }
            assertThat(snapshot(GOVERNED)).isEqualTo(before);
            String captureControl = "AUDIT_COMMENT_CAPTURE_OK";
            assertThat(captureControl.getBytes(java.nio.charset.StandardCharsets.UTF_8).length).isLessThan(32);
            org.slf4j.LoggerFactory.getLogger(GovernanceAuthenticationIntegrationTest.class).warn(captureControl);
            assertThat(output.getAll()).as("same actual captured log transport positive control").contains(captureControl);
            assertThat(output.getAll()).doesNotContain(BOOTSTRAP, SIGNING, CONTRACT_KEY, session.cookie.split("=", 2)[1], session.csrf);
        }
    }

    @Test void pureAuditCommentSuccessStillRequiresFinalExpiryAndCommittedRevocationCheckAfterAllLocks() throws Exception {
        for (boolean revoke : List.of(false, true)) {
            Graph graph = graph(WORKSPACE);
            var before = snapshot(GOVERNED);
            var clock = new MutableClock();
            var local = localIssuer(clock);
            var localRevocations = new GovernanceReviewerSessionRevocations(db, digest, local);
            var localAccess = new GovernanceAccess(db, local, localRevocations, instance);
            var localFilter = new GovernanceAccessFilter(local, localRevocations, localAccess, json);
            var session = issue(local);
            AtomicInteger continuations = new AtomicInteger();
            AtomicInteger completedChecks = new AtomicInteger();
            var response = direct(localFilter, mutation("POST", riskPath(graph.finding), session), (req, res) -> {
                var request = (HttpServletRequest) req;
                var context = localAccess.requireMutationContext(request);
                new TransactionTemplate(transactions).executeWithoutResult(status -> {
                    lockAll(db, graph);
                    String preparedComment = "Reviewed rationale";
                    localAccess.requireSafeAuditComment(context, request, preparedComment);
                    if (revoke) {
                        var identity = local.mutationContext(session, request);
                        var independentWriter = new GovernanceReviewerSessionRevocations(independentDb(), digest, local);
                        independentWriter.revoke(identity);
                        assertThat(independentWriter.isRevoked(session.identity())).isTrue();
                    } else clock.now = Instant.ofEpochSecond(session.identity().expiresAt());
                    assertDenied(() -> {
                        localAccess.verifyMutation(context, WORKSPACE, graph.finding);
                        continuations.incrementAndGet();
                    });
                    status.setRollbackOnly();
                });
                // Each expiry/committed-revocation branch proves completion after transaction processing.
                completedChecks.incrementAndGet();
            });
            assertThat(response.getStatus()).as("%s branch direct callback response",
                    revoke ? "committed-revocation" : "expiry").isEqualTo(200);
            assertThat(completedChecks.get()).as("%s branch final-authority assertions completed",
                    revoke ? "committed-revocation" : "expiry").isEqualTo(1);
            assertThat(continuations.get()).isZero();
            assertThat(snapshot(GOVERNED)).isEqualTo(before);
        }
    }

    private HttpServletRequest alteredAuditHeader(HttpServletRequest request, String name, String value) {
        return new jakarta.servlet.http.HttpServletRequestWrapper(request) {
            @Override public String getHeader(String selected) { return name.equalsIgnoreCase(selected) ? value : super.getHeader(selected); }
            @Override public java.util.Enumeration<String> getHeaders(String selected) {
                return name.equalsIgnoreCase(selected) ? java.util.Collections.enumeration(List.of(value)) : super.getHeaders(selected);
            }
        };
    }

    private ConfigurableApplicationContext startCommentProbeContext() {
        return new SpringApplicationBuilder(FinsecSealApplication.class, ProbeConfiguration.class)
                .run("--server.port=0", "--spring.main.banner-mode=off", "--spring.main.lazy-initialization=false",
                        "--spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                        "--spring.datasource.username=" + POSTGRES.getUsername(),
                        "--spring.datasource.password=" + POSTGRES.getPassword(),
                        "--finsec.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        "--finsec.scheduling.enabled=false", "--finsec.generation.worker-enabled=false",
                        "--spring.datasource.hikari.maximum-pool-size=2",
                        "--finsec.governance-access.bootstrap-key=" + BOOTSTRAP,
                        "--finsec.governance-access.signing-key=" + SIGNING,
                        "--finsec.governance-access.actor=" + ACTOR,
                        "--finsec.governance-access.workspace=" + WORKSPACE,
                        "--finsec.contract-access.key=" + CONTRACT_KEY);
    }

    @Test void actualJPAHolderFalseBeforeAfterJdbcAndAccessPositiveWithoutForcedFlags() throws Exception {
        Graph graph = graph(WORKSPACE);
        assertThat(transactions).isInstanceOf(JpaTransactionManager.class);
        var before = snapshot(GOVERNED);
        direct(filter, mutation("POST", riskPath(graph.finding), issue(issuer)), (req, res) -> {
            var context = access.requireMutationContext((HttpServletRequest) req);
            new TransactionTemplate(transactions).executeWithoutResult(status -> {
                assertNormalJPAHolder();
                lockAll(db, graph);
                access.verifyMutation(context, WORKSPACE, graph.finding);
            });
        });
        assertThat(snapshot(GOVERNED)).isEqualTo(before);
    }

    @Test void otherwiseValidAdmittedAuthorityDeniesMissingReadOnlyWrongSourceAndNonRCTx() throws Exception {
        Graph graph = graph(WORKSPACE);
        var before = snapshot(GOVERNED);
        var session = issue(issuer);
        direct(filter, mutation("POST", riskPath(graph.finding), session), (req, res) -> {
            var context = access.requireMutationContext((HttpServletRequest) req);
            assertDenied(() -> access.verifyMutation(context, WORKSPACE, graph.finding));
            for (int isolation : List.of(TransactionDefinition.ISOLATION_READ_COMMITTED,
                    TransactionDefinition.ISOLATION_REPEATABLE_READ, TransactionDefinition.ISOLATION_SERIALIZABLE)) {
                TransactionTemplate outer = new TransactionTemplate(transactions);
                outer.setIsolationLevel(isolation);
                if (isolation == TransactionDefinition.ISOLATION_READ_COMMITTED) outer.setReadOnly(true);
                outer.executeWithoutResult(status -> {
                    new TransactionTemplate(transactions).executeWithoutResult(joined ->
                            assertDenied(() -> access.verifyMutation(context, WORKSPACE, graph.finding)));
                    status.setRollbackOnly();
                });
            }
            new TransactionTemplate(transactions).executeWithoutResult(status -> {
                DataSource source = db.getDataSource();
                Object holder = TransactionSynchronizationManager.unbindResource(source);
                try { assertDenied(() -> access.verifyMutation(context, WORKSPACE, graph.finding)); }
                finally { TransactionSynchronizationManager.bindResource(source, holder); }
                status.setRollbackOnly();
            });
            GovernanceAccess wrongSource = new GovernanceAccess(independentDb(), issuer, revocations, instance);
            wrongSource.establish((HttpServletRequest) req, session,
                    issuer.mutationContext(session, csrf(session.csrfToken())), graph.finding,
                    ((HttpServletRequest) req).getHeader("Idempotency-Key"), false, false);
            var otherwiseValid = wrongSource.requireMutationContext((HttpServletRequest) req);
            new TransactionTemplate(transactions).executeWithoutResult(status -> {
                assertThat(TransactionSynchronizationManager.getResource(db.getDataSource())).isNotNull();
                assertDenied(() -> wrongSource.verifyMutation(otherwiseValid, WORKSPACE, graph.finding));
            });
        });
        assertThat(snapshot(GOVERNED)).isEqualTo(before);
    }

    @Test void physicalPostgresReadOnlyDespiteWritableSpringDeniesValidAuthorityAndAdmission() throws Exception {
        Graph graph = graph(WORKSPACE);
        var before = snapshot(GOVERNED);
        direct(filter, mutation("POST", riskPath(graph.finding), issue(issuer)), (req, res) -> {
            var context = access.requireMutationContext((HttpServletRequest) req);
            new TransactionTemplate(transactions).executeWithoutResult(status -> {
                assertThat(TransactionSynchronizationManager.isCurrentTransactionReadOnly()).isFalse();
                db.execute("set transaction read only");
                assertThat(db.queryForObject("show transaction_read_only", String.class)).isEqualTo("on");
                assertDenied(() -> access.verifyMutation(context, WORKSPACE, graph.finding));
                status.setRollbackOnly();
            });
        });
        assertThat(snapshot(GOVERNED)).isEqualTo(before);
    }

    @Test void publicAdmissionCannotMintContextAndIssuerTraceKeyResourceRemainBound() throws Exception {
        Graph graph = graph(WORKSPACE);
        var request = new MockHttpServletRequest("POST", riskPath(graph.finding));
        request.setAttribute(IdempotencyFilter.ADMISSION, new IdempotencyFilter.Admission(UUID.randomUUID(), "raw"));
        assertDenied(() -> access.requireMutationContext(request));
        assertThat(GovernanceAccess.MutationContext.class.getConstructors()).isEmpty();
        var before = snapshot(GOVERNED);
        var original = mutation("POST", riskPath(graph.finding), issue(issuer));
        direct(filter, original, (req, res) -> {
            var context = access.requireMutationContext((HttpServletRequest) req);
            new TransactionTemplate(transactions).executeWithoutResult(status -> {
                assertDenied(() -> access.verifyMutation(context, UUID.randomUUID(), graph.finding));
                assertDenied(() -> access.verifyMutation(context, WORKSPACE, UUID.randomUUID()));
                String oldTrace = TraceIdFilter.currentTraceId();
                MDC.put(TraceIdFilter.TRACE_ID, UUID.randomUUID().toString());
                try { assertDenied(() -> access.verifyMutation(context, WORKSPACE, graph.finding)); }
                finally { MDC.put(TraceIdFilter.TRACE_ID, oldTrace); }
                GovernanceAccess foreignAccess = new GovernanceAccess(db, issuer, revocations, instance);
                assertDenied(() -> foreignAccess.verifyMutation(context, WORKSPACE, graph.finding));
                original.removeHeader("Idempotency-Key"); original.addHeader("Idempotency-Key", "different-key");
                assertDenied(() -> access.requireMutationContext((HttpServletRequest) req));
            });
        });
        assertThat(snapshot(GOVERNED)).isEqualTo(before);
    }

    @Test void expiryAfterEveryBlockingConsumerLockIncludingOriginalSourceRunDeniesContinuation() throws Exception {
        for (String table : List.of("findings", "agent_releases", "agents", "test_runs"))
            lockWaitThenDeny(table, false);
    }

    @Test void independentCommittedRevocationAfterEveryLockIncludingOriginalSourceRunDeniesContinuation() throws Exception {
        for (String table : List.of("findings", "agent_releases", "agents", "test_runs"))
            lockWaitThenDeny(table, true);
    }

    @Test void separateNodeLocalIssuerQuotaDirectRealFilterBoundsAttemptsAndIssuances() throws Exception {
        // Isolated test issuer with validated Clock constructor; actual HTTP bean remains systemClock.
        var clock = new MutableClock();
        var local = localIssuer(clock);
        var localRevocations = new GovernanceReviewerSessionRevocations(db, digest, local);
        var localAccess = new GovernanceAccess(db, local, localRevocations, instance);
        var localFilter = new GovernanceAccessFilter(local, localRevocations, localAccess, json);
        AtomicInteger issued = new AtomicInteger();
        for (int index = 0; index < 33; index++) {
            var req = new MockHttpServletRequest("GET", SESSION); req.setServletPath(SESSION);
            req.addHeader("Authorization", "GovernanceBootstrap " + BOOTSTRAP);
            var response = direct(localFilter, req, (r, s) -> { localAccess.currentSession((HttpServletRequest) r); issued.incrementAndGet(); });
            assertThat(response.getStatus()).isEqualTo(index < 32 ? 200 : 403);
        }
        assertThat(issued.get()).isEqualTo(32);
        clock.now = clock.now.plusSeconds(1800);
        assertThat(issue(local)).isNotNull();
        var attempts = localIssuer(new MutableClock());
        for (int index = 0; index < 60; index++) {
            var req = new MockHttpServletRequest("GET", SESSION);
            req.addHeader("Authorization", "GovernanceBootstrap invalid");
            assertThat(attempts.exchange(req)).isNull();
        }
        var valid = new MockHttpServletRequest("GET", SESSION);
        valid.addHeader("Authorization", "GovernanceBootstrap " + BOOTSTRAP);
        assertThat(attempts.exchange(valid)).isNull();
    }

    @Test @Order(Integer.MAX_VALUE) @DirtiesContext(methodMode = DirtiesContext.MethodMode.BEFORE_METHOD)
    void actualHttpSystemClockIssuerEnforcesNodeLocalIssuanceQuota() throws Exception {
        assertFreshActualQuotaContext();
        var before = snapshot(withAdmission());
        Instant start = Instant.now();
        for (int index = 0; index < 33; index++) {
            var response = http("GET", SESSION, null, List.of("Authorization", "GovernanceBootstrap " + BOOTSTRAP));
            assertThat(Duration.between(start, Instant.now())).as("quota observation within 55 seconds index=%d", index)
                    .isLessThan(Duration.ofSeconds(55));
            int attempts = privateIssuerWindowSize(issuer, "attempts");
            int issuances = privateIssuerWindowSize(issuer, "issuances");
            // Numeric state and URI path/port only; never print credentials, headers, or response bodies.
            assertThat(response.statusCode()).withFailMessage(
                    "quota HTTP index=%d requestPort=%d responsePort=%d responsePath=%s status=%d attempts=%d issuances=%d",
                    index, port, response.uri().getPort(), response.uri().getPath(), response.statusCode(), attempts, issuances)
                    .isEqualTo(index < 32 ? 200 : 403);
            assertThat(attempts).as("quota attempts after exchange index=%d", index).isEqualTo(index + 1);
            assertThat(issuances).as("quota issuances after exchange index=%d", index).isEqualTo(Math.min(index + 1, 32));
            if (index == 32) assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
        }
        assertThat(snapshot(withAdmission())).isEqualTo(before);
    }

    @Test @Order(Integer.MAX_VALUE - 1) @DirtiesContext(methodMode = DirtiesContext.MethodMode.BEFORE_METHOD)
    void actualHttpAttemptQuotaDeniesValidExchangeBelowIssuanceLimit() throws Exception {
        assertFreshActualQuotaContext();
        var before = snapshot(withAdmission());
        Instant start = Instant.now();
        // One actual successful exchange proves configuration; 59 failures exhaust attempts, not32 issuances.
        var configuredSession = httpSession();
        int successfulIssuances = 1;
        for (int index = 0; index < 59; index++) {
            var response = http("GET", SESSION, null, List.of("Authorization", "GovernanceBootstrap invalid-attempt-" + index));
            assertThat(response.statusCode()).isEqualTo(403);
            assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
            assertNoStore(response);
        }
        assertThat(Duration.between(start, Instant.now())).isLessThan(Duration.ofSeconds(55));
        assertThat(successfulIssuances).isLessThan(32);
        var denied = http("GET", SESSION, null, List.of("Authorization", "GovernanceBootstrap " + BOOTSTRAP));
        assertThat(denied.statusCode()).isEqualTo(403);
        assertThat(denied.headers().allValues("Set-Cookie")).isEmpty();
        assertNoStore(denied);
        var current = http("GET", SESSION, null, List.of("Cookie", configuredSession.cookie));
        assertThat(current.statusCode()).isEqualTo(200);
        assertThat(current.headers().allValues("Set-Cookie")).isEmpty();
        assertThat(snapshot(withAdmission())).isEqualTo(before);
    }

    private void lockWaitThenDeny(String blockedTable, boolean revoke) throws Exception {
        Graph graph = graph(WORKSPACE);
        var before = snapshot(GOVERNED);
        MutableClock clock = new MutableClock();
        var local = localIssuer(clock);
        var localRevocations = new GovernanceReviewerSessionRevocations(db, digest, local);
        var localAccess = new GovernanceAccess(db, local, localRevocations, instance);
        var localFilter = new GovernanceAccessFilter(local, localRevocations, localAccess, json);
        var session = issue(local);
        var mutationIdentity = local.mutationContext(session, csrf(session.csrfToken()));
        AtomicInteger continuations = new AtomicInteger();
        AtomicInteger completedChecks = new AtomicInteger();
        AtomicInteger waitingPid = new AtomicInteger();
        CountDownLatch enteringLocks = new CountDownLatch(1);
        UUID blockedId = switch (blockedTable) {
            case "findings" -> graph.finding; case "agent_releases" -> graph.release;
            case "agents" -> graph.agent; default -> graph.sourceRun;
        };
        try (var pool = Executors.newSingleThreadExecutor(); Connection holder = independentDb().getDataSource().getConnection()) {
            holder.setAutoCommit(false);
            try (var statement = holder.prepareStatement("select id from " + blockedTable + " where id=? for update")) {
                statement.setObject(1, blockedId); try (var result = statement.executeQuery()) { assertThat(result.next()).isTrue(); }
            }
            var future = pool.submit(() -> {
                var response = direct(localFilter, mutation("POST", riskPath(graph.finding), session), (req, res) -> {
                    var context = localAccess.requireMutationContext((HttpServletRequest) req);
                    new TransactionTemplate(transactions).executeWithoutResult(status -> {
                        waitingPid.set(db.queryForObject("select pg_backend_pid()", Integer.class));
                        enteringLocks.countDown();
                        lockAll(db, graph);
                        localAccess.requireSafeAuditComment(context, (HttpServletRequest) req, "Reviewed rationale");
                        assertDenied(() -> localAccess.verifyMutation(context, WORKSPACE, graph.finding));
                        // A D-shaped continuation would only be reached after successful verification.
                        if (local.current(mutationIdentity, true) && !localRevocations.isRevoked(mutationIdentity))
                            continuations.incrementAndGet();
                        status.setRollbackOnly();
                    });
                    // A swallowed guard denial cannot count as completed final-verification/rollback evidence.
                    completedChecks.incrementAndGet();
                });
                return response;
            });
            assertThat(enteringLocks.await(10, TimeUnit.SECONDS)).isTrue();
            awaitPostgresLock(waitingPid.get());
            if (revoke) {
                var writer = new GovernanceReviewerSessionRevocations(independentDb(), digest, local);
                writer.revoke(mutationIdentity);
                assertThat(writer.isRevoked(session.identity())).isTrue();
            } else clock.now = Instant.ofEpochSecond(session.identity().expiresAt());
            holder.commit();
            var response = future.get(15, TimeUnit.SECONDS);
            assertThat(response.getStatus()).as("lock-wait table=%s branch=%s direct callback response",
                    blockedTable, revoke ? "committed-revocation" : "expiry").isEqualTo(200);
        }
        assertThat(completedChecks.get()).as("lock-wait table=%s branch=%s final-authority assertions completed",
                blockedTable, revoke ? "committed-revocation" : "expiry").isEqualTo(1);
        assertThat(continuations.get()).isZero();
        assertThat(snapshot(GOVERNED)).isEqualTo(before);
    }

    private void awaitPostgresLock(int pid) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (System.nanoTime() < deadline) {
            if (Boolean.TRUE.equals(independentDb().queryForObject(
                    "select exists(select 1 from pg_stat_activity where pid=? and wait_event_type='Lock')", Boolean.class, pid))) return;
            Thread.sleep(20);
        }
        throw new AssertionError("Actual PostgreSQL lock wait was not observed");
    }

    private void assertNormalJPAHolder() {
        assertThat(transactions).isInstanceOf(JpaTransactionManager.class);
        var holder = (ConnectionHolder) TransactionSynchronizationManager.getResource(db.getDataSource());
        assertThat(holder).isNotNull(); assertThat(holder.isSynchronizedWithTransaction()).isFalse();
        assertThat(db.queryForObject("select 1", Integer.class)).isEqualTo(1);
        assertThat(holder.isSynchronizedWithTransaction()).isFalse();
        assertThat(db.queryForObject("show transaction_isolation", String.class)).isEqualTo("read committed");
        assertThat(db.queryForObject("show transaction_read_only", String.class)).isEqualTo("off");
    }

    private static void lockAll(JdbcTemplate db, Graph graph) {
        db.queryForObject("select id from findings where id=? for update", UUID.class, graph.finding);
        db.queryForObject("select id from agent_releases where id=? for update", UUID.class, graph.release);
        db.queryForObject("select id from agents where id=? for update", UUID.class, graph.agent);
        // Original source oracle -> case run -> TestRun, never latest_seen_run_id.
        assertThat(db.queryForObject("""
                select tr.id from findings f join oracle_results o on o.id=f.source_oracle_result_id
                    join test_case_runs c on c.id=o.test_case_run_id join test_runs tr on tr.id=c.test_run_id
                    where f.id=? for update of tr
                """, UUID.class, graph.finding)).isEqualTo(graph.sourceRun);
    }

    private MockHttpServletResponse direct(GovernanceAccessFilter selected, MockHttpServletRequest request,
            FilterChain continuation) throws Exception {
        var response = new MockHttpServletResponse();
        trace.doFilter(request, response, (r, s) -> selected.doFilter(r, s,
                (authenticated, result) -> common.doFilter(authenticated, result, continuation)));
        return response;
    }

    private MockHttpServletRequest mutation(String method, String path, GovernanceReviewerCredentials.Session session) {
        var request = new MockHttpServletRequest(method, path); request.setServletPath(path);
        request.setCookies(new Cookie(GovernanceReviewerCredentials.COOKIE, session.token()));
        request.addHeader("X-CSRF-Token", session.csrfToken()); request.addHeader("Idempotency-Key", key());
        return request;
    }

    private GovernanceReviewerCredentials.Session issue(GovernanceReviewerCredentials credentials) {
        var request = new MockHttpServletRequest("GET", SESSION);
        request.addHeader("Authorization", "GovernanceBootstrap " + BOOTSTRAP);
        var session = credentials.exchange(request); assertThat(session).isNotNull(); return session;
    }

    private MockHttpServletRequest csrf(String value) {
        var request = new MockHttpServletRequest(); request.addHeader("X-CSRF-Token", value); return request;
    }

    private GovernanceReviewerCredentials localIssuer(Clock clock) {
        return new GovernanceReviewerCredentials(BOOTSTRAP, SIGNING, ACTOR, WORKSPACE.toString(), "", clock);
    }

    private Session httpSession() throws Exception {
        var response = http("GET", SESSION, null, List.of("Authorization", "GovernanceBootstrap " + BOOTSTRAP));
        assertThat(response.statusCode()).withFailMessage(response.body()).isEqualTo(200);
        var view = json.readTree(response.body()).path("data");
        return new Session(response.headers().firstValue("Set-Cookie").orElseThrow().split(";", 2)[0],
                view.path("csrfToken").asString(), UUID.fromString(view.path("sessionId").asString()));
    }

    private HttpResponse<String> risk(Graph graph, Session session, String key, List<String> extras) throws Exception {
        var headers = mutationHeaders(session, key); headers.addAll(extras);
        return http("POST", riskPath(graph.finding), "{}", headers);
    }

    private ArrayList<String> mutationHeaders(Session session, String key) {
        return new ArrayList<>(List.of("Cookie", session.cookie, "X-CSRF-Token", session.csrf, "Idempotency-Key", key));
    }

    private HttpResponse<String> http(String method, String path, String body, List<String> headers) throws Exception {
        return httpAt(port, method, path, body, headers);
    }

    private HttpResponse<String> httpAt(int selectedPort, String method, String path, String body,
            List<String> headers) throws Exception {
        var builder = HttpRequest.newBuilder(URI.create("http://localhost:" + selectedPort + path)).timeout(Duration.ofSeconds(15));
        for (int i = 0; i < headers.size(); i += 2) builder.header(headers.get(i), headers.get(i + 1));
        if (body != null) builder.header("Content-Type", "application/json");
        builder.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private ConfigurableApplicationContext startRealContext(String bootstrap, String signing, String actor,
            String workspace, String cKey, AtomicInteger ready) {
        return new SpringApplicationBuilder(FinsecSealApplication.class)
                .listeners((ApplicationListener<ApplicationReadyEvent>) event -> ready.incrementAndGet())
                .run("--server.port=0", "--spring.main.banner-mode=off", "--spring.main.lazy-initialization=false",
                        "--spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                        "--spring.datasource.username=" + POSTGRES.getUsername(),
                        "--spring.datasource.password=" + POSTGRES.getPassword(),
                        "--finsec.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        "--finsec.cors.allowed-origins=http://localhost:5173", "--finsec.scheduling.enabled=false",
                        "--finsec.generation.worker-enabled=false", "--spring.datasource.hikari.maximum-pool-size=2",
                        "--finsec.governance-access.bootstrap-key=" + bootstrap,
                        "--finsec.governance-access.signing-key=" + signing,
                        "--finsec.governance-access.actor=" + actor, "--finsec.governance-access.workspace=" + workspace,
                        "--finsec.contract-access.key=" + cKey);
    }

    private void assertCredentialFreeResponse(HttpResponse<String> response) {
        assertThat(response.headers().map().toString() + response.body()).doesNotContain(BOOTSTRAP, SIGNING, CONTRACT_KEY);
        String trace = response.headers().firstValue("X-Trace-Id").orElseThrow();
        assertThat(UUID.fromString(trace)).isNotNull();
    }

    private void assertResponseUsesSafeMdcTrace(HttpResponse<String> response) {
        assertThat(json.readTree(response.body()).path("traceId").asString())
                .isEqualTo(response.headers().firstValue("X-Trace-Id").orElseThrow());
    }

    private Map<String, String> beforeSnapshotGoverned(Map<String, String> source) {
        var governed = new LinkedHashMap<String, String>();
        for (String table : GOVERNED) governed.put(table, source.get(table));
        return governed;
    }

    private String sessionDigest(Session session) {
        return digest.sha256("FINSEC_GOVERNANCE_SESSION_ID_V1:" + WORKSPACE + ":" + session.id);
    }

    private String signedInvalidRepeatCookie(Session session, boolean expired) throws Exception {
        String token = session.cookie.split("=", 2)[1];
        var body = (tools.jackson.databind.node.ObjectNode) json.readTree(
                java.util.Base64.getUrlDecoder().decode(token.split("\\.", 2)[0]));
        if (expired) {
            long now = Instant.now().getEpochSecond(); body.put("issuedAt", now - 1801); body.put("expiresAt", now - 1);
        } else body.put("generation", "synthetic-rotated-authority-generation");
        String payload = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(json.writeValueAsBytes(body));
        var mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(SIGNING.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256"));
        String signature = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(
                (GovernanceReviewerCredentials.PURPOSE + ":" + payload).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        return GovernanceReviewerCredentials.COOKIE + "=" + payload + "." + signature;
    }

    private void assertNoStore(HttpResponse<?> response) { assertThat(response.headers().firstValue("Cache-Control")).contains("no-store"); }
    private void assertCleared(HttpResponse<?> response) {
        assertThat(response.headers().firstValue("Set-Cookie").orElseThrow())
                .contains(GovernanceReviewerCredentials.COOKIE + "=", "Max-Age=0", "Secure", "HttpOnly", "SameSite=Lax");
    }
    private static void assertDenied(Runnable call) { assertThatThrownBy(call::run).isInstanceOf(BusinessException.class); }
    private static void assertCommentDenied(Runnable call) {
        assertThatThrownBy(call::run).isInstanceOfSatisfying(BusinessException.class, failure -> {
            assertThat(failure.errorCode()).isEqualTo(com.finsecseal.common.api.ErrorCode.OPERATOR_AUTH_REQUIRED);
            assertThat(failure.getMessage()).isEqualTo("Current admitted governance mutation authority required");
        });
    }
    private String key() { return "gov-" + UUID.randomUUID(); }
    private static String riskPath(UUID finding) { return "/api/v1/findings/" + finding + ":accept-risk"; }
    private static List<String> withAdmission() {
        var tables = new ArrayList<>(GOVERNED); tables.add("api_idempotency_records"); tables.add("reviewer_session_revocations"); return tables;
    }
    private void assertIdempotencySecretsAbsent(Session session, String method, String path, String key,
            String expectedState, boolean recoveryBodyIsNull) {
        String[] canaries = {session.cookie.split("=", 2)[1], session.csrf, BOOTSTRAP, SIGNING, CONTRACT_KEY};
        independentDb().query("""
                select t.* from api_idempotency_records t
                 where workspace_id=? and actor_id=? and http_method=? and request_path=? and idempotency_key=?
                """, result -> {
            assertThat(result.next()).isTrue();
            assertThat(result.getString("state")).isEqualTo(expectedState);
            var columns = result.getMetaData();
            for (int index = 1; index <= columns.getColumnCount(); index++) {
                if ("response_body".equals(columns.getColumnName(index))) continue;
                String value = result.getString(index);
                if (value != null) assertThat(value).doesNotContain(canaries);
            }
            byte[] body = result.getBytes("response_body");
            if (recoveryBodyIsNull) assertThat(body).isNull();
            else {
                assertThat(body).isNotNull();
                assertThat(new String(body, java.nio.charset.StandardCharsets.UTF_8)).doesNotContain(canaries);
            }
            assertThat(result.next()).isFalse();
            return null;
        }, WORKSPACE, ACTOR, method, path, key);
    }

    private Map<String, String> snapshot(List<String> tables) {
        var result = new LinkedHashMap<String, String>();
        for (String table : tables) result.put(table, db.queryForObject(
                "select coalesce(jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text),'[]'::jsonb)::text from " + table + " t", String.class));
        return result;
    }
    private JdbcTemplate independentDb() {
        return new JdbcTemplate(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()));
    }

    private Graph graph(UUID workspace) {
        UUID agent = UUID.randomUUID(), release = UUID.randomUUID(), suite = UUID.randomUUID(), testCase = UUID.randomUUID();
        UUID run = UUID.randomUUID(), caseRun = UUID.randomUUID(), oracle = UUID.randomUUID(), finding = UUID.randomUUID();
        String hash = "sha256:" + "a".repeat(64);
        db.update("insert into agents(id,workspace_id,agent_key,name,purpose_summary,status) values(?,?,?,'Governance fixture','test','ACTIVE')",
                agent, workspace, "gov-" + agent);
        db.update("""
                insert into agent_releases(id,agent_id,version,business_purpose,manifest_schema_version,manifest_json,
                    agent_artifact_fingerprint,release_fingerprint,lifecycle_state,effective_status)
                values(?,?,'1.0.0','LOAN_DOCUMENT_COMPLETENESS_REVIEW','1.0','{}',?,?,'DRAFT','DRAFT')
                """, release, agent, hash, hash);
        db.update("""
                insert into test_suites(id,workspace_id,suite_key,version,fixture_version,generation_config_json,suite_hash,status)
                values(?,?,?,'1.0','fixture-v1','{}',?,'DRAFT')
                """, suite, workspace, "gov-" + suite, hash);
        db.update("""
                insert into test_cases(id,suite_id,case_key,case_type,partition_name,category,severity,delivery_channel,
                    target_tool,attack_goal,payload_hash,preconditions_json,expected_invariant,oracle_type,generation_source,
                    hidden_from_patch_generator,expected_result_json,trial_policy_json)
                values(?,?,'FA-02','ATTACK','SEED','FA-02','CRITICAL','DOCUMENT','CUSTOMER_DATA_READ','cross customer read',
                    ?,'{}','INV-01','CROSS_CUSTOMER','GOLDEN',false,'{}','{}')
                """, testCase, suite, hash);
        db.update("update test_suites set status='READY' where id=?", suite);
        db.update("""
                insert into test_runs(id,release_id,suite_id,mode,status,agent_artifact_fingerprint,release_fingerprint,
                    config_json,fixture_version,fixture_digest,model_config_hash,total_cases)
                values(?,?,?,'BASELINE','RUNNING',?,?,'{}','fixture-v1',?,?,1)
                """, run, release, suite, hash, hash, hash, hash);
        db.update("""
                insert into test_case_runs(id,test_run_id,test_case_id,trial_index,status,security_outcome,variant_hash,
                    started_at,completed_at,result_json) values(?,?,?,0,'FAILED_SECURITY','ATTACK_SUCCESS',?,now(),now(),'{}')
                """, caseRun, run, testCase, hash);
        db.update("""
                insert into oracle_results(id,test_case_run_id,oracle_type,oracle_version,outcome,reason_code,invariant_id,
                    evidence_json,evidence_digest,evaluated_at)
                values(?,?,'CROSS_CUSTOMER','1.0','ATTACK_SUCCESS','UNAUTHORIZED_RECORD_RETURNED','INV-01','{}',?,now())
                """, oracle, caseRun, hash);
        db.update("""
                insert into findings(id,release_id,source_oracle_result_id,category,severity,title,status,violated_invariant,
                    root_cause_json,first_seen_run_id,latest_seen_run_id)
                values(?,?,?,'FA-02','CRITICAL','Governance fixture','OPEN','INV-01','{}',?,?)
                """, finding, release, oracle, run, run);
        return new Graph(agent, release, run, finding);
    }

    private record Session(String cookie, String csrf, UUID id) {}
    private record Graph(UUID agent, UUID release, UUID sourceRun, UUID finding) {}
    private static final class MutableClock extends Clock {
        private volatile Instant now = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class ProbeConfiguration {
        @Bean ContinuationProbe governanceContinuationProbe(GovernanceAccess access, JdbcTemplate db) {
            return new ContinuationProbe(access, db);
        }
    }

    /** Test-only D-shaped consumer: no Finding/Release/domain or audit writes. */
    @TestComponent @RestController
    public static class ContinuationProbe {
        private final GovernanceAccess access;
        private final JdbcTemplate db;
        final AtomicInteger calls = new AtomicInteger();
        ContinuationProbe(GovernanceAccess access, JdbcTemplate db) { this.access = access; this.db = db; }

        public int callCount() { return calls.get(); }

        @Transactional
        @PostMapping("/api/v1/findings/{findingId}:accept-risk")
        public Map<String, Object> verify(@PathVariable UUID findingId, HttpServletRequest request,
                @org.springframework.web.bind.annotation.RequestBody(required = false) Map<String, String> body) {
            var context = access.requireMutationContext(request);
            var holder = (ConnectionHolder) TransactionSynchronizationManager.getResource(db.getDataSource());
            assertThat(holder.isSynchronizedWithTransaction()).isFalse();
            var row = db.queryForMap("""
                    select a.id as agent, r.id as release, tr.id as source_run, a.workspace_id as workspace
                    from findings f join agent_releases r on r.id=f.release_id join agents a on a.id=r.agent_id
                    join oracle_results o on o.id=f.source_oracle_result_id
                    join test_case_runs c on c.id=o.test_case_run_id join test_runs tr on tr.id=c.test_run_id
                    where f.id=? for update of f,r,a,tr
                    """, findingId);
            assertThat(holder.isSynchronizedWithTransaction()).isFalse();
            String preparedComment = body == null ? "Governance continuation probe"
                    : body.getOrDefault("comment", "Governance continuation probe");
            access.requireSafeAuditComment(context, request, preparedComment);
            access.verifyMutation(context, (UUID) row.get("workspace"), findingId);
            calls.incrementAndGet();
            return Map.of("holderSynchronized", holder.isSynchronizedWithTransaction(),
                    "isolation", db.queryForObject("show transaction_isolation", String.class),
                    "readOnly", db.queryForObject("show transaction_read_only", String.class));
        }
    }
}
