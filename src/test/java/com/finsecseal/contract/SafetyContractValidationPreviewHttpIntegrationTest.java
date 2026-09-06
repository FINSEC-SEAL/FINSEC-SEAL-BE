package com.finsecseal.contract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.contract.SafetyContractSemanticValidator.Issue;
import com.finsecseal.contract.SafetyContractSemanticValidator.IssueSeverity;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationResult;
import com.finsecseal.release.ReleaseDto;
import com.finsecseal.release.ReleaseService;
import com.finsecseal.runtime.AgentRuntimeService;
import com.finsecseal.sandbox.tool.ToolDispatcher;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/** Actual HTTP, shared idempotency middleware, PostgreSQL and A catalog read with C validation. */
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT, properties = {
        "finsec.contract-preview.enabled=true",
        "server.address=127.0.0.1",
        "server.forward-headers-strategy=none",
        "finsec.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "finsec.scheduling.enabled=false"
})
class SafetyContractValidationPreviewHttpIntegrationTest {

    private static final String PREFIX = "/api/v1/contract-validation-previews/";
    private static final String ACTOR = "role-c-preview-test";
    private static final String SENTINEL = "PRIVATE_PROCESSING_DETAIL_DO_NOT_RETURN";
    private static final List<String> DOMAIN_TABLES = List.of(
            "agents", "agent_releases", "release_artifacts", "release_tools",
            "safety_contracts", "safety_contract_versions", "patch_proposals", "patch_approvals",
            "test_runs", "test_case_runs", "execution_events", "oracle_results", "findings",
            "replay_links", "sandbox_namespaces", "sandbox_review_notes",
            "sandbox_loan_decisions", "sandbox_exfil_events", "sandbox_tool_idempotency_records"
    );

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @LocalServerPort int port;
    @Autowired AgentService agents;
    @Autowired ReleaseService releases;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate jdbc;
    @Autowired ConfigurableEnvironment environment;
    @Autowired SafetyContractValidationPreviewService previews;
    @Autowired ReleaseToolCatalogContractAdapter catalogs;
    @MockitoSpyBean SafetyContractCanonicalizer canonicalizer;
    @MockitoSpyBean ToolDispatcher dispatcher;
    @MockitoSpyBean AgentRuntimeService runtime;

    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5)).build();

    @AfterEach
    void previewNeverInvokesToolDispatchOrAgentRuntime() {
        verifyNoInteractions(dispatcher, runtime);
    }

    @Test
    void validPreviewBindsExactVerifiedSourceAndHashWithoutChangingDomainState() throws Exception {
        var release = release("valid-release-manifest-v1.1.json");
        var source = releases.toolCatalog(release.id(), ACTOR);
        ObjectNode contract = contract();
        String expectedHash = canonicalizer.canonicalizeAndHash(contract).policyHash();
        Map<String, String> before = domainSnapshot();
        int audits = count("audit_records");
        int reservations = count("api_idempotency_records");

        var response = post(release.id(), contract, key());

        JsonNode data = data(response, "VALID");
        assertThat(data.path("previewOnly").asBoolean()).isTrue();
        assertThat(data.path("issues").isEmpty()).isTrue();
        assertThat(data.path("policyHash").asString()).isEqualTo(expectedHash);
        assertThat(data.at("/source/releaseId").asString()).isEqualTo(release.id().toString());
        assertThat(data.at("/source/manifestSchemaVersion").asString()).isEqualTo("1.1");
        assertThat(data.at("/source/agentArtifactFingerprint").asString())
                .isEqualTo(source.agentArtifactFingerprint());
        assertThat(data.at("/source/releaseFingerprint").asString()).isEqualTo(source.releaseFingerprint());
        assertThat(data.at("/source/serverToolCatalogHash").asString()).isEqualTo(source.serverToolCatalogHash());
        assertThat(response.body()).doesNotContain("systemPrompt", "Review only document completeness", "APPROVED");
        assertThat(domainSnapshot()).isEqualTo(before);
        assertThat(count("audit_records")).isEqualTo(audits + 1);
        assertThat(count("api_idempotency_records")).isEqualTo(reservations + 1);
        assertThat(jdbc.queryForObject("select count(*) from audit_records where resource_id = ? and actor_id = ?",
                Integer.class, release.id(), ACTOR)).isGreaterThanOrEqualTo(2);
        verifyNoInteractions(dispatcher, runtime);
    }

    @Test
    void equivalentSetAndPropertyOrderHasTheSamePolicyHashAndCallerInputIsUnchanged() throws Exception {
        var release = release("valid-release-manifest-v1.1.json");
        ObjectNode original = contract();
        ObjectNode saved = original.deepCopy();
        JsonNode direct = mapper.valueToTree(previews.preview(release.id(), original, ACTOR));
        assertThat(original).isEqualTo(saved);
        ObjectNode reordered = mapper.createObjectNode();
        List<Map.Entry<String, JsonNode>> entries = new ArrayList<>(original.properties());
        Collections.reverse(entries);
        entries.forEach(entry -> reordered.set(entry.getKey(), entry.getValue().deepCopy()));
        reverse((ArrayNode) reordered.path("allowedTools"));
        reverse((ArrayNode) reordered.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed"));
        reverse((ArrayNode) reordered.at("/outputPolicy/reviewStatusAllowed"));
        JsonNode http = data(post(release.id(), reordered, key()), "VALID");
        assertThat(http.path("policyHash")).isEqualTo(direct.path("policyHash"));
        assertThat(original).isEqualTo(saved);
    }

    @Test
    void tcCon001AllToolsDeniedReportsEveryRequiredToolWithoutHash() throws Exception {
        var release = release("valid-release-manifest-v1.1.json");
        ObjectNode candidate = contract();
        ((ArrayNode) candidate.path("allowedTools")).removeAll();
        JsonNode data = data(post(release.id(), candidate, key()), "INVALID");
        List<String> missing = new ArrayList<>();
        data.path("issues").forEach(issue -> {
            if (issue.path("code").asString().equals("REQUIRED_TOOL_MISSING")) {
                missing.add(issue.path("message").asString());
                assertThat(issue.path("jsonPointer").asString()).startsWith("/allowedTools");
                assertThat(issue.path("severity").asString()).isEqualTo("ERROR");
            }
        });
        assertThat(missing).containsExactlyInAnyOrder(
                "Required loan-review Tool is missing: CASE_CONTEXT_READ",
                "Required loan-review Tool is missing: CUSTOMER_DATA_READ",
                "Required loan-review Tool is missing: DOCUMENT_READER",
                "Required loan-review Tool is missing: LOAN_POLICY_SEARCH",
                "Required loan-review Tool is missing: REVIEW_NOTE_WRITE");
        assertNoHash(data);
    }

    @Test
    void tcCon002AgentCannotAllowAHumanOnlyTool() throws Exception {
        var release = release("valid-release-manifest-v1.1.json");
        ObjectNode candidate = contract();
        ((ArrayNode) candidate.path("allowedTools")).add("LOAN_DECISION_UPDATE");
        assertIssue(post(release.id(), candidate, key()), "HUMAN_ONLY_TOOL_ALLOWED");
    }

    @Test
    void tcCon003AbsentFieldAndSchemaPresentAccountNumberHaveDifferentIssues() throws Exception {
        var release = release("valid-release-manifest-v1.1.json");
        ObjectNode absent = contract();
        ((ArrayNode) absent.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed")).add("notInOutput");
        assertIssue(post(release.id(), absent, key()), "FIELD_NOT_IN_TOOL_OUTPUT");
        ObjectNode account = contract();
        ((ArrayNode) account.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed")).add("accountNumber");
        JsonNode data = assertIssue(post(release.id(), account, key()), "FIELD_EXCEEDS_TEMPLATE");
        assertThat(issueCodes(data)).doesNotContain("FIELD_NOT_IN_TOOL_OUTPUT");
    }

    @Test
    void closedSchemaDuplicateSetAndWrongTypeAreInvalidCandidates() throws Exception {
        var release = release("valid-release-manifest-v1.1.json");
        ObjectNode unknown = contract();
        unknown.put("approveNow", true);
        assertIssue(post(release.id(), unknown, key()), "UNKNOWN_FIELD");
        ObjectNode duplicate = contract();
        ((ArrayNode) duplicate.path("allowedTools")).add("CASE_CONTEXT_READ");
        assertIssue(post(release.id(), duplicate, key()), "DUPLICATE_VALUE");
        ObjectNode wrongType = contract();
        wrongType.put("version", "1");
        assertIssue(post(release.id(), wrongType, key()), "TYPE");
        assertIssue(postRaw(PREFIX + release.id(), "[]", key(), ACTOR, "application/json", Map.of()), "TYPE");
    }

    @Test
    void warningResultOmitsHashWithoutInventingAProductionWarningRule() throws Exception {
        var release = release("valid-release-manifest-v1.1.json");
        var warningValidator = mock(SafetyContractSemanticValidator.class);
        var unusedCanonicalizer = mock(SafetyContractCanonicalizer.class);
        when(warningValidator.validate(any(), any())).thenReturn(ValidationResult.fromIssues(List.of(
                new Issue("/metadata", "TEST_WARNING", IssueSeverity.WARNING, "Isolated warning result"))));
        var service = new SafetyContractValidationPreviewService(catalogs, warningValidator, unusedCanonicalizer);
        JsonNode result = mapper.valueToTree(service.preview(release.id(), contract(), ACTOR));
        assertThat(result.path("status").asString()).isEqualTo("WARN");
        assertNoHash(result);
        verifyNoInteractions(unusedCanonicalizer);
    }

    @Test
    void successfulSnapshotReplayDoesNotRepeatSourceAuditOrDomainWrites() throws Exception {
        var release = release("valid-release-manifest-v1.1.json");
        ObjectNode body = contract();
        String key = key();
        var first = post(release.id(), body, key);
        data(first, "VALID");
        var domain = domainSnapshot();
        var middleware = middlewareSnapshot();
        var replay = post(release.id(), body, key);
        assertThat(replay.statusCode()).isEqualTo(200);
        assertThat(replay.body()).isEqualTo(first.body());
        assertThat(replay.headers().firstValue("Idempotent-Replayed")).contains("true");
        assertThat(replay.headers().firstValue("X-Trace-Id"))
                .isEqualTo(first.headers().firstValue("X-Trace-Id"));
        assertThat(domainSnapshot()).isEqualTo(domain);
        assertThat(middlewareSnapshot()).isEqualTo(middleware);
        ObjectNode different = body.deepCopy();
        different.put("version", 2);
        assertProblem(post(release.id(), different, key), 409, "IDEMPOTENCY_CONFLICT");
    }

    @Test
    void forwardedHeadersCannotReplayAnAlreadySuccessfulLocalPreview() throws Exception {
        var release = release("valid-release-manifest-v1.1.json");
        String body = mapper.writeValueAsString(contract());
        String key = key();
        var first = postRaw(PREFIX + release.id(), body, key, ACTOR, "application/json", Map.of());
        data(first, "VALID");
        Map<String, String> before = middlewareSnapshot();
        for (String header : List.of("Forwarded", "X-Forwarded-For", "X-Forwarded-Host",
                "X-Forwarded-Proto", "X-Forwarded-Unrecognized")) {
            var denied = postRaw(PREFIX + release.id(), body, key, ACTOR, "application/json",
                    Map.of(header, "for=203.0.113.10"));
            assertGuardProblem(denied, 403, "CONTRACT_PREVIEW_ACCESS_DENIED");
            assertThat(middlewareSnapshot()).isEqualTo(before);
        }
    }

    @Test
    void disablingFeatureOrRemovingLocalProfileBlocksCachedPreviewBeforeSharedMiddleware() throws Exception {
        var release = release("valid-release-manifest-v1.1.json");
        String body = mapper.writeValueAsString(contract());
        String key = key();
        data(postRaw(PREFIX + release.id(), body, key, ACTOR, "application/json", Map.of()), "VALID");
        Map<String, String> before = middlewareSnapshot();
        String propertyName = "preview-test-disabled-" + UUID.randomUUID();
        String[] active = environment.getActiveProfiles();
        try {
            environment.getPropertySources().addFirst(new MapPropertySource(propertyName,
                    Map.of("finsec.contract-preview.enabled", "false")));
            assertGuardProblem(postRaw(PREFIX + release.id(), body, key, ACTOR, "application/json", Map.of()),
                    404, "CONTRACT_PREVIEW_DISABLED");
            assertThat(middlewareSnapshot()).isEqualTo(before);
            environment.getPropertySources().remove(propertyName);
            environment.setActiveProfiles("test");
            assertGuardProblem(postRaw(PREFIX + release.id(), body, key, ACTOR, "application/json", Map.of()),
                    404, "CONTRACT_PREVIEW_DISABLED");
            assertThat(middlewareSnapshot()).isEqualTo(before);
        } finally {
            environment.getPropertySources().remove(propertyName);
            environment.setActiveProfiles(active);
        }
        assertThat(postRaw(PREFIX + release.id(), body, key, ACTOR, "application/json", Map.of())
                .headers().firstValue("Idempotent-Replayed")).contains("true");
    }

    @Test
    void missingOrBlankActorCannotReplayAStoredDemoUserResponse() throws Exception {
        var release = release("valid-release-manifest-v1.1.json");
        String body = mapper.writeValueAsString(contract());
        String key = key();
        data(postRaw(PREFIX + release.id(), body, key, "demo-user", "application/json", Map.of()), "VALID");
        Map<String, String> before = middlewareSnapshot();
        for (String actor : new String[] {null, "", "   ", "a".repeat(121)}) {
            assertGuardProblem(postRaw(PREFIX + release.id(), body, key, actor, "application/json", Map.of()),
                    400, "VALIDATION_ERROR");
            assertThat(middlewareSnapshot()).isEqualTo(before);
        }
    }

    @Test
    void encodedAndMatrixAliasesCannotBypassIdempotencyOrBodyBounds() throws Exception {
        var release = release("valid-release-manifest-v1.1.json");
        String body = mapper.writeValueAsString(contract());
        Map<String, String> before = middlewareSnapshot();
        for (String path : List.of(
                "/%61pi/v1/contract-validation-previews/" + release.id(),
                "/api/v1/contract-validation-%70reviews/" + release.id(),
                "/api;alias=x/v1/contract-validation-previews/" + release.id(),
                "/api/v1/contract-validation-previews;alias=x/" + release.id())) {
            assertGuardProblem(postRaw(path, body, null, ACTOR, "application/json", Map.of()),
                    400, "VALIDATION_ERROR");
            assertThat(middlewareSnapshot()).isEqualTo(before);
        }
        String propertyName = "preview-alias-disabled-" + UUID.randomUUID();
        try {
            environment.getPropertySources().addFirst(new MapPropertySource(propertyName,
                    Map.of("finsec.contract-preview.enabled", "false")));
            assertGuardProblem(postRaw("/%61pi/v1/contract-validation-previews/" + release.id(),
                    body, null, ACTOR, "application/json", Map.of()), 404, "CONTRACT_PREVIEW_DISABLED");
            assertThat(middlewareSnapshot()).isEqualTo(before);
        } finally {
            environment.getPropertySources().remove(propertyName);
        }
    }

    @Test
    void freshKeysReevaluateTamperedCatalogWhileAllowedSameKeyRetainsItsExplicitSnapshot() throws Exception {
        var release = release("valid-release-manifest-v1.1.json");
        ObjectNode body = contract();
        String originalKey = key();
        var original = post(release.id(), body, originalKey);
        data(original, "VALID");
        jdbc.update("update release_artifacts set content_json = '{\"forged\":true}'::jsonb "
                + "where release_id = ? and name = 'server-tool-catalog'", release.id());
        var replay = post(release.id(), body, originalKey);
        assertThat(replay.body()).isEqualTo(original.body());
        assertThat(replay.headers().firstValue("Idempotent-Replayed")).contains("true");
        String freshKey = key();
        assertSourceFailure(post(release.id(), body, freshKey));
        assertThat(jdbc.queryForObject("select state from api_idempotency_records where idempotency_key = ?",
                String.class, freshKey)).isEqualTo("RECOVERY_REQUIRED");
        assertProblem(post(release.id(), body, freshKey), 409, "IDEMPOTENCY_IN_PROGRESS");
    }

    @Test
    void missingLegacyAndTamperedFingerprintAreSourceFailuresRatherThanInvalidCandidates() throws Exception {
        assertSourceFailure(post(UUID.randomUUID(), contract(), key()));
        var legacy = release("valid-release-manifest.json");
        assertSourceFailure(post(legacy.id(), contract(), key()));
        var tampered = release("valid-release-manifest-v1.1.json");
        jdbc.update("update agent_releases set release_fingerprint = ? where id = ?",
                "sha256:" + "f".repeat(64), tampered.id());
        assertSourceFailure(post(tampered.id(), contract(), key()));
    }

    @Test
    void malformedUuidJsonEmptyBodyAndDepthFailSafelyWhileWrongMediaTypeIs415() throws Exception {
        var release = release("valid-release-manifest-v1.1.json");
        assertProblem(postRaw(PREFIX + "not-a-uuid", "{}", key(), ACTOR, "application/json", Map.of()),
                400, "VALIDATION_ERROR");
        for (String body : List.of("", "{", "[".repeat(1100) + "0" + "]".repeat(1100))) {
            var response = postRaw(PREFIX + release.id(), body, key(), ACTOR, "application/json", Map.of());
            assertProblem(response, 400, "VALIDATION_ERROR");
            assertThat(response.body()).doesNotContain("StreamConstraintsException", "JsonParseException", "stackTrace");
        }
        assertProblem(postRaw(PREFIX + release.id(), "{}", key(), ACTOR, "text/plain", Map.of()),
                415, "UNSUPPORTED_MEDIA_TYPE");
    }

    @Test
    void sharedMiddlewareRequiresKeyAndEnforcesTwoMegabyteLimitBeforeSourceAccess() throws Exception {
        var release = release("valid-release-manifest-v1.1.json");
        Map<String, String> before = middlewareSnapshot();
        assertProblem(postRaw(PREFIX + release.id(), "{}", null, ACTOR, "application/json", Map.of()),
                400, "VALIDATION_ERROR");
        assertProblem(postRaw(PREFIX + release.id(), " ".repeat(2 * 1024 * 1024 + 1), key(), ACTOR,
                "application/json", Map.of()), 422, "MANIFEST_INVALID");
        assertThat(middlewareSnapshot()).isEqualTo(before);
    }

    @Test
    void unexpectedCanonicalizationFailureIsCauseFree500AndRequiresExplicitRecovery() throws Exception {
        var release = release("valid-release-manifest-v1.1.json");
        ObjectNode body = contract();
        String key = key();
        doThrow(new IllegalStateException(SENTINEL)).when(canonicalizer).canonicalizeAndHash(any());
        var response = post(release.id(), body, key);
        assertProblem(response, 500, "CONTRACT_PREVIEW_PROCESSING_FAILED");
        assertThat(response.body()).doesNotContain(SENTINEL, "IllegalStateException", "policyHash", "VALID");
        assertThat(mapper.readTree(response.body()).path("retryable").asBoolean()).isFalse();
        assertProblem(post(release.id(), body, key), 409, "IDEMPOTENCY_IN_PROGRESS");
        verifyNoInteractions(dispatcher, runtime);
    }

    @Test
    void unrelatedApiNamespaceRetainsExistingSharedMiddlewareBehavior() throws Exception {
        String actorKey = "preview-unrelated-" + UUID.randomUUID();
        String body = mapper.writeValueAsString(Map.of("agentKey", actorKey, "name", "Unrelated", "purposeSummary", "test"));
        var response = postRaw("/api/v1/agents", body, key(), ACTOR, "application/json",
                Map.of("Forwarded", "for=203.0.113.10"));
        assertThat(response.statusCode()).isEqualTo(201);
        assertThat(mapper.readTree(response.body()).at("/data/agentKey").asString()).isEqualTo(actorKey);
    }

    @Test
    void allowedCorsPreflightNeedsNoActorOrKeyAndReturnsOnlySharedCorsHeaders() throws Exception {
        var release = release("valid-release-manifest-v1.1.json");
        data(post(release.id(), contract(), key()), "VALID");

        var response = preflight(PREFIX + release.id(), allowedOrigin(), Map.of());

        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        assertThat(response.headers().firstValue("Access-Control-Allow-Origin")).contains(allowedOrigin());
        assertThat(response.headers().firstValue("Access-Control-Allow-Credentials")).contains("true");
        assertThat(response.headers().firstValue("Access-Control-Allow-Methods").orElseThrow()).contains("POST");
        assertThat(response.headers().firstValue("Access-Control-Allow-Headers").orElseThrow()
                .toLowerCase(java.util.Locale.ROOT)).contains("content-type", "idempotency-key", "x-actor-id");
        assertThat(response.body()).isEmpty();
        assertThat(response.headers().firstValue("Idempotent-Replayed")).isEmpty();
    }

    @Test
    void corsPreflightRetainsOriginActivationForwardingAndCanonicalPathGuards() throws Exception {
        var release = release("valid-release-manifest-v1.1.json");
        data(post(release.id(), contract(), key()), "VALID");
        String path = PREFIX + release.id();

        var invalidOrigin = preflight(path, "https://untrusted.invalid", Map.of());
        assertThat(invalidOrigin.statusCode()).isEqualTo(403);
        assertThat(invalidOrigin.headers().firstValue("Access-Control-Allow-Origin")).isEmpty();
        assertThat(invalidOrigin.headers().firstValue("Idempotent-Replayed")).isEmpty();
        assertThat(invalidOrigin.body()).doesNotContain("previewOnly", "policyHash", "serverToolCatalogHash");
        for (String header : List.of("Forwarded", "X-Forwarded-For")) {
            assertGuardProblem(preflight(path, allowedOrigin(), Map.of(header, "for=203.0.113.10")),
                    403, "CONTRACT_PREVIEW_ACCESS_DENIED");
        }
        for (String alias : List.of("/%61pi/v1/contract-validation-previews/" + release.id(),
                "/api/v1/contract-validation-previews;alias=x/" + release.id())) {
            assertGuardProblem(preflight(alias, allowedOrigin(), Map.of()), 400, "VALIDATION_ERROR");
        }

        String propertyName = "preview-cors-disabled-" + UUID.randomUUID();
        String[] active = environment.getActiveProfiles();
        try {
            environment.getPropertySources().addFirst(new MapPropertySource(propertyName,
                    Map.of("finsec.contract-preview.enabled", "false")));
            assertGuardProblem(preflight(path, allowedOrigin(), Map.of()), 404, "CONTRACT_PREVIEW_DISABLED");
            environment.getPropertySources().remove(propertyName);
            environment.setActiveProfiles("test");
            assertGuardProblem(preflight(path, allowedOrigin(), Map.of()), 404, "CONTRACT_PREVIEW_DISABLED");
        } finally {
            environment.getPropertySources().remove(propertyName);
            environment.setActiveProfiles(active);
        }
    }

    @Test
    void ordinaryOptionsAndPostWithPreflightLikeHeadersStillRequireActor() throws Exception {
        var release = release("valid-release-manifest-v1.1.json");
        String path = PREFIX + release.id();
        assertGuardProblem(options(path, Map.of("Origin", allowedOrigin())), 400, "VALIDATION_ERROR");
        Map<String, String> domain = domainSnapshot();
        Map<String, String> middleware = middlewareSnapshot();
        assertGuardProblem(postRaw(path, mapper.writeValueAsString(contract()), key(), null,
                "application/json", Map.of("Origin", allowedOrigin(),
                        "Access-Control-Request-Method", "POST",
                        "Access-Control-Request-Headers", "x-actor-id,idempotency-key")),
                400, "VALIDATION_ERROR");
        assertThat(domainSnapshot()).isEqualTo(domain);
        assertThat(middlewareSnapshot()).isEqualTo(middleware);
    }

    @Test
    void freshOriginPostHasCorsHeadersWhileExistingSharedReplayOmitsThem() throws Exception {
        var release = release("valid-release-manifest-v1.1.json");
        String path = PREFIX + release.id();
        String body = mapper.writeValueAsString(contract());
        String key = key();
        Map<String, String> domain = domainSnapshot();
        var fresh = postRaw(path, body, key, ACTOR, "application/json", Map.of("Origin", allowedOrigin()));
        data(fresh, "VALID");
        assertThat(fresh.headers().firstValue("Access-Control-Allow-Origin")).contains(allowedOrigin());
        assertThat(domainSnapshot()).isEqualTo(domain);
        Map<String, String> middleware = middlewareSnapshot();

        var replay = postRaw(path, body, key, ACTOR, "application/json", Map.of("Origin", allowedOrigin()));

        assertThat(replay.statusCode()).isEqualTo(200);
        assertThat(replay.body()).isEqualTo(fresh.body());
        assertThat(replay.headers().firstValue("Idempotent-Replayed")).contains("true");
        // A's existing filter replays before MVC CORS handling; this is an owner integration limitation.
        assertThat(replay.headers().firstValue("Access-Control-Allow-Origin")).isEmpty();
        assertThat(domainSnapshot()).isEqualTo(domain);
        assertThat(middlewareSnapshot()).isEqualTo(middleware);
    }

    @Test
    void localOptInActivationMatrixKeepsGuardRegisteredWhenControllerIsAbsent() {
        for (String profile : List.of("local", "test")) {
            for (String enabled : List.of("true", "false", "missing")) {
                MockEnvironment env = safeEnvironment();
                env.setActiveProfiles(profile);
                if (!enabled.equals("missing")) env.setProperty("finsec.contract-preview.enabled", enabled);
                try (var context = new AnnotationConfigApplicationContext()) {
                    context.setEnvironment(env);
                    context.registerBean(ObjectMapper.class, () -> mapper);
                    context.registerBean(SafetyContractValidationPreviewService.class,
                            () -> mock(SafetyContractValidationPreviewService.class));
                    context.register(SafetyContractValidationPreviewController.class,
                            SafetyContractValidationPreviewAccessFilter.class);
                    context.refresh();
                    assertThat(context.getBeansOfType(SafetyContractValidationPreviewAccessFilter.class)).hasSize(1);
                    assertThat(context.getBeansOfType(SafetyContractValidationPreviewController.class))
                            .hasSize(profile.equals("local") && enabled.equals("true") ? 1 : 0);
                }
            }
        }
    }

    @Test
    void nonLoopbackPeerIsDeniedAndUnsafeStartupFailsClosedEvenAfterLaterEnabling() throws Exception {
        MockEnvironment safe = safeEnvironment().withProperty("finsec.contract-preview.enabled", "true");
        safe.setActiveProfiles("local");
        var filter = new SafetyContractValidationPreviewAccessFilter(safe, mapper);
        MockHttpServletRequest request = mockRequest("203.0.113.10");
        var response = new MockHttpServletResponse();
        AtomicBoolean called = new AtomicBoolean();
        filter.doFilter(request, response, (req, res) -> called.set(true));
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(called).isFalse();

        for (Map<String, String> unsafe : List.of(Map.of("server.address", "0.0.0.0"),
                Map.of("server.address", "localhost"), Map.of("server.forward-headers-strategy", "framework"))) {
            MockEnvironment env = safeEnvironment().withProperty("finsec.contract-preview.enabled", "true");
            env.setActiveProfiles("local");
            unsafe.forEach(env::setProperty);
            assertThatThrownBy(() -> new SafetyContractValidationPreviewAccessFilter(env, mapper))
                    .isInstanceOf(IllegalStateException.class);
        }

        MockEnvironment delayed = safeEnvironment().withProperty("server.address", "0.0.0.0")
                .withProperty("finsec.contract-preview.enabled", "false");
        delayed.setActiveProfiles("local");
        var delayedFilter = new SafetyContractValidationPreviewAccessFilter(delayed, mapper);
        delayed.setProperty("finsec.contract-preview.enabled", "true");
        delayed.setProperty("server.address", "127.0.0.1");
        var delayedResponse = new MockHttpServletResponse();
        delayedFilter.doFilter(mockRequest("127.0.0.1"), delayedResponse, (req, res) -> called.set(true));
        assertThat(delayedResponse.getStatus()).isEqualTo(403);
        assertThat(called).isFalse();
    }

    private MockEnvironment safeEnvironment() {
        return new MockEnvironment().withProperty("server.address", "127.0.0.1")
                .withProperty("server.forward-headers-strategy", "none");
    }

    private MockHttpServletRequest mockRequest(String peer) {
        var request = new MockHttpServletRequest("POST", PREFIX + UUID.randomUUID());
        request.setRemoteAddr(peer);
        request.addHeader("X-Actor-Id", ACTOR);
        return request;
    }

    private ReleaseDto.Response release(String fixtureName) throws Exception {
        String agentKey = "preview-" + UUID.randomUUID();
        var agent = agents.create(new AgentDto.CreateRequest(agentKey, "C Preview", "Contract validation"));
        ObjectNode manifest = fixture(fixtureName);
        ((ObjectNode) manifest.path("agent")).put("id", agentKey);
        return releases.create(agent.id(), manifest, ACTOR);
    }

    private ObjectNode contract() throws Exception {
        return fixture("loan-review-safety-contract.json");
    }

    private ObjectNode fixture(String name) throws Exception {
        try (InputStream input = getClass().getResourceAsStream("/fixtures/" + name)) {
            assertThat(input).isNotNull();
            return (ObjectNode) mapper.readTree(input);
        }
    }

    private HttpResponse<String> post(UUID releaseId, JsonNode contract, String key) throws Exception {
        Map<String, String> before = domainSnapshot();
        HttpResponse<String> response = postRaw(PREFIX + releaseId, mapper.writeValueAsString(contract), key,
                ACTOR, "application/json", Map.of());
        assertThat(domainSnapshot()).isEqualTo(before);
        return response;
    }

    private HttpResponse<String> postRaw(String path, String body, String key, String actor,
            String contentType, Map<String, String> headers) throws Exception {
        var builder = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .timeout(Duration.ofSeconds(20)).header("Content-Type", contentType)
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (key != null) builder.header("Idempotency-Key", key);
        if (actor != null) builder.header("X-Actor-Id", actor);
        headers.forEach(builder::header);
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private String allowedOrigin() {
        return environment.getRequiredProperty("finsec.cors.allowed-origins").split(",")[0].trim();
    }

    private HttpResponse<String> preflight(String path, String origin, Map<String, String> extraHeaders)
            throws Exception {
        Map<String, String> headers = new LinkedHashMap<>(extraHeaders);
        headers.put("Origin", origin);
        headers.put("Access-Control-Request-Method", "POST");
        headers.put("Access-Control-Request-Headers", "content-type,idempotency-key,x-actor-id");
        return options(path, headers);
    }

    private HttpResponse<String> options(String path, Map<String, String> headers) throws Exception {
        Map<String, String> domain = domainSnapshot();
        Map<String, String> middleware = middlewareSnapshot();
        var builder = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .timeout(Duration.ofSeconds(20)).method("OPTIONS", HttpRequest.BodyPublishers.noBody());
        headers.forEach(builder::header);
        HttpResponse<String> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        assertThat(domainSnapshot()).isEqualTo(domain);
        assertThat(middlewareSnapshot()).isEqualTo(middleware);
        return response;
    }

    private JsonNode data(HttpResponse<String> response, String status) throws Exception {
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        JsonNode body = mapper.readTree(response.body());
        assertThat(body.path("traceId").asString()).isNotBlank();
        JsonNode data = body.path("data");
        assertThat(data.path("status").asString()).isEqualTo(status);
        assertThat(data.path("previewOnly").asBoolean()).isTrue();
        return data;
    }

    private JsonNode assertIssue(HttpResponse<String> response, String code) throws Exception {
        JsonNode data = data(response, "INVALID");
        assertThat(issueCodes(data)).contains(code);
        assertNoHash(data);
        return data;
    }

    private List<String> issueCodes(JsonNode data) {
        List<String> codes = new ArrayList<>();
        data.path("issues").forEach(issue -> codes.add(issue.path("code").asString()));
        return codes;
    }

    private void assertNoHash(JsonNode data) {
        assertThat(data.path("policyHash").isNull() || data.path("policyHash").isMissingNode()).isTrue();
    }

    private void assertProblem(HttpResponse<String> response, int status, String code) throws Exception {
        assertThat(response.statusCode()).as(response.body()).isEqualTo(status);
        JsonNode body = mapper.readTree(response.body());
        assertThat(body.path("code").asString()).isEqualTo(code);
        assertThat(body.path("data").isMissingNode()).isTrue();
    }

    private void assertGuardProblem(HttpResponse<String> response, int status, String code) throws Exception {
        assertProblem(response, status, code);
        assertThat(response.headers().firstValue("Idempotent-Replayed")).isEmpty();
        assertThat(response.body()).doesNotContain("previewOnly", "policyHash", "serverToolCatalogHash");
    }

    private void assertSourceFailure(HttpResponse<String> response) throws Exception {
        assertProblem(response, 503, "CONTRACT_PREVIEW_SOURCE_UNAVAILABLE");
        JsonNode problem = mapper.readTree(response.body());
        assertThat(problem.path("errors").isEmpty()).isFalse();
        assertThat(problem.path("retryable").asBoolean()).isFalse();
        assertThat(response.body()).doesNotContain("policyHash", "systemPrompt", "forged", "BusinessException");
    }

    private int count(String table) {
        return jdbc.queryForObject("select count(*) from " + table, Integer.class);
    }

    private Map<String, String> domainSnapshot() {
        return snapshot(DOMAIN_TABLES);
    }

    private Map<String, String> middlewareSnapshot() {
        return snapshot(List.of("audit_records", "api_idempotency_records"));
    }

    private Map<String, String> snapshot(List<String> tables) {
        Map<String, String> result = new LinkedHashMap<>();
        for (String table : tables) {
            result.put(table, jdbc.queryForObject("select coalesce(jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text),"
                    + " '[]'::jsonb)::text from " + table + " t", String.class));
        }
        return result;
    }

    private void reverse(ArrayNode values) {
        List<JsonNode> entries = new ArrayList<>();
        values.forEach(value -> entries.add(value.deepCopy()));
        Collections.reverse(entries);
        values.removeAll();
        entries.forEach(values::add);
    }

    private String key() {
        return "c-preview-" + UUID.randomUUID();
    }
}
