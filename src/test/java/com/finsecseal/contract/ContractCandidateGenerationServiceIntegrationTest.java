package com.finsecseal.contract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ReleaseLifecycleState;
import com.finsecseal.contract.ContractCandidateGenerationService.CandidateGenerationException;
import com.finsecseal.contract.ContractCandidateGenerationService.FailureCode;
import com.finsecseal.contract.SafetyContractCandidateResponseProcessor.CandidateResponseException;
import com.finsecseal.contract.SafetyContractGenerationSourceService.GenerationSourceException;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionIdentity;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationStatus;
import com.finsecseal.evidence.RedactionService;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.ReleaseDto;
import com.finsecseal.release.ReleaseService;
import com.finsecseal.runtime.ai.ContractCandidateAiClient;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * Real Spring source proxy, PostgreSQL and B HTTP client with local model responses.
 * The enabled application context proves bean activation and route removal; generation calls use
 * an explicitly keyless loopback client. No external model, Operation or candidate persistence is exercised.
 */
@Testcontainers
@SpringBootTest(properties = {
        "finsec.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "finsec.scheduling.enabled=false", "finsec.ai.enabled=true"
})
@ExtendWith(OutputCaptureExtension.class)
class ContractCandidateGenerationServiceIntegrationTest {
    private static final String ACTOR = "c-initial-generation-integration";
    private static final String SYSTEM_PROMPT = "INITIAL-GENERATION-PRIVATE-SYSTEM-PROMPT-CANARY";
    private static final String SECRET = "INITIAL-GENERATION-SYNTHETIC-SECRET-CANARY";
    private static final String RAW_RESPONSE = "INITIAL-GENERATION-RAW-PROVIDER-CANARY";
    private static final List<String> DOMAIN_TABLES = List.of(
            "agents", "agent_releases", "release_artifacts", "safety_contracts", "safety_contract_versions",
            "contract_version_evidence", "api_idempotency_records", "patch_proposals", "patch_approvals",
            "test_suites", "test_cases", "test_runs", "test_case_runs", "run_event_counters", "execution_events",
            "findings", "oracle_results", "replay_links", "release_decisions", "evidence_references");

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired ContractCandidateGenerationService enabledWorker;
    @MockitoSpyBean SafetyContractGenerationSourceService sources;
    @Autowired SafetyContractCandidatePromptBuilder prompts;
    @Autowired SafetyContractCandidateResponseProcessor processor;
    @Autowired LoanReviewFinancialTemplate template;
    @Autowired RedactionService redaction;
    @Autowired AgentService agents;
    @Autowired ReleaseService releases;
    @Autowired ObjectMapper mapper;
    @Autowired DigestService digests;
    @Autowired JdbcTemplate jdbc;
    @Autowired DataSource dataSource;
    @Autowired PlatformTransactionManager transactions;
    @Autowired @Qualifier("requestMappingHandlerMapping") RequestMappingHandlerMapping handlerMappings;

    private HttpServer server;
    private ContractCandidateAiClient client;
    private final AtomicInteger httpCalls = new AtomicInteger();
    private final AtomicReference<JsonNode> outbound = new AtomicReference<>();
    private final AtomicReference<Throwable> handlerFailure = new AtomicReference<>();
    private final AtomicReference<ModelEntry> modelEntry = new AtomicReference<>();

    @AfterEach
    void stopLocalServer() {
        if (server != null) server.stop(0);
    }

    @Test
    void aiEnabledContextActivatesWorkerWithoutTheLegacySynchronousGenerationRoute() {
        assertThat(enabledWorker).isNotNull();
        assertThat(handlerMappings.getHandlerMethods()).isNotEmpty();
        assertThat(handlerMappings.getHandlerMethods().keySet().stream()
                .flatMap(mapping -> mapping.getPatternValues().stream()))
                .anyMatch(pattern -> pattern.equals("/api/v1/releases/{id}/contracts:generate"));
        assertThat(handlerMappings.getHandlerMethods().values())
                .noneMatch(handler -> handler.getBeanType().getSimpleName()
                        .equals("ContractCandidateGenerationController"));
    }

    @Test
    void validCandidateUsesCommittedSourceAndReleasedLockBeforeActualHttp(CapturedOutput output) throws Exception {
        ReleaseDto.Response release = release(true, null);
        VersionIdentity identity = identity(release.id());
        Baseline before = baseline(release.id());
        AtomicBoolean lockAcquired = new AtomicBoolean();
        AtomicBoolean committedAuditVisible = new AtomicBoolean();
        var service = service(exchange -> {
            // This HTTP thread gets a separate physical connection to observe the source commit.
            TransactionTemplate independent = new TransactionTemplate(transactions);
            independent.setTimeout(5);
            independent.executeWithoutResult(status -> {
                UUID locked = jdbc.queryForObject("select id from agent_releases where id=? for update nowait",
                        UUID.class, release.id());
                lockAcquired.set(release.id().equals(locked));
                committedAuditVisible.set(accessAuditCount(release.id()) == before.accessAudits() + 1);
            });
            respond(exchange, 200, modelEnvelope(policy(identity).toString()));
        });
        assertThat(AopUtils.isAopProxy(sources)).isTrue();
        clearInvocations(sources);
        long callerThread = Thread.currentThread().threadId();

        var result = service.generate(identity, LoanReviewFinancialTemplate.KEY, ACTOR);

        verify(sources).prepare(release.id(), LoanReviewFinancialTemplate.KEY, ACTOR);
        assertHttpCall(callerThread);
        assertThat(lockAcquired).isTrue();
        assertThat(committedAuditVisible).isTrue();
        assertThat(result.identity()).isEqualTo(identity);
        assertThat(result.catalogBinding().releaseId()).isEqualTo(release.id());
        assertThat(result.catalogBinding().agentArtifactFingerprint()).isEqualTo(release.agentArtifactFingerprint());
        assertThat(result.catalogBinding().releaseFingerprint()).isEqualTo(release.releaseFingerprint());
        assertThat(result.analyzedAt()).isEqualTo(release.analyzedAt());
        assertThat(result.lifecycleState()).isEqualTo(ReleaseLifecycleState.ANALYZED);
        assertThat(result.templateKey()).isEqualTo(LoanReviewFinancialTemplate.KEY);
        assertThat(result.validation().status()).isEqualTo(ValidationStatus.VALID);
        assertThat(result.validation().issues()).isEmpty();
        assertThat(result.policy().toString()).isEqualTo(policy(identity).toString());
        assertThat(result.canonicalPolicy()).isPresent();
        assertThat(result.canonicalPolicy().orElseThrow().policyHash()).matches("sha256:[0-9a-f]{64}");
        assertThat(result.provider()).isEqualTo("loopback-provider");
        assertThat(result.model()).isEqualTo("initial-response-fixture");
        assertThat(result.latencyMs()).isEqualTo(7);
        JsonNode request = outbound.get();
        assertThat(request.size()).isEqualTo(3);
        assertThat(request.path("promptVersion").stringValue()).isEqualTo(result.promptVersion());
        JsonNode input = mapper.readTree(request.path("inputJson").stringValue());
        assertThat(input.at("/identity/versionId").stringValue()).isEqualTo(identity.versionId().toString());
        assertThat(input.at("/identity/workspaceId").stringValue()).isEqualTo(identity.workspaceId().toString());
        assertThat(input.at("/identity/releaseId").stringValue()).isEqualTo(identity.releaseId().toString());
        assertThat(input.at("/identity/contractKey").stringValue()).isEqualTo(identity.contractKey());
        assertThat(input.at("/identity/version").intValue()).isEqualTo(identity.version());
        assertThat(input.at("/financialTemplate")).isEqualTo(policy(identity));
        assertThat(input.at("/source/releaseFingerprint").stringValue()).isEqualTo(release.releaseFingerprint());
        assertThat(result.promptDigest()).isEqualTo(digests.sha256(mapper.writeValueAsBytes(mapper.createArrayNode()
                .add(result.promptVersion()).add(request.path("instructions").stringValue())
                .add(request.path("inputJson").stringValue()))));
        assertThat(request.toString()).doesNotContain(SYSTEM_PROMPT, SECRET, RAW_RESPONSE, "systemPrompt");
        assertThat(result.toString()).doesNotContain(SYSTEM_PROMPT, SECRET, RAW_RESPONSE);
        assertThat(result.policy().toString()).doesNotContain(SYSTEM_PROMPT, SECRET, RAW_RESPONSE);
        assertThat(output.getAll()).doesNotContain(SYSTEM_PROMPT, SECRET, RAW_RESPONSE);
        assertUnchanged(before, release.id(), 1);
    }

    @Test
    void missingRequiredNormalFieldReturnsInvalidWithoutCanonicalPolicyOrPersistence(CapturedOutput output)
            throws Exception {
        ReleaseDto.Response release = release(true, null);
        VersionIdentity identity = identity(release.id());
        ObjectNode invalid = policy(identity);
        ((ArrayNode) invalid.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed")).remove(0);
        var service = service(exchange -> respond(exchange, 200, modelEnvelope(invalid.toString())));
        Baseline before = baseline(release.id());

        var result = service.generate(identity, LoanReviewFinancialTemplate.KEY, ACTOR);

        assertThat(result.identity()).isEqualTo(identity);
        assertThat(result.validation().status()).isEqualTo(ValidationStatus.INVALID);
        assertThat(result.validation().issues()).anyMatch(issue -> issue.code().equals("REQUIRED_FIELD_MISSING"));
        assertThat(result.policy().toString()).isEqualTo(invalid.toString());
        assertThat(result.canonicalPolicy()).isEmpty();
        assertHttpCall(Thread.currentThread().threadId());
        assertThat(output.getAll()).doesNotContain(SYSTEM_PROMPT, SECRET, RAW_RESPONSE);
        assertUnchanged(before, release.id(), 1);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("outerTransactions")
    void ambientTransactionsOrSynchronizationFailBeforeSourceAndModel(String description, boolean readOnly,
            int propagation, boolean actual) throws Exception {
        ReleaseDto.Response release = release(true, null);
        VersionIdentity identity = identity(release.id());
        var service = service(exchange -> respond(exchange, 400, "Unexpected request"));
        Baseline before = baseline(release.id());
        clearInvocations(sources);
        TransactionTemplate outer = new TransactionTemplate(transactions);
        outer.setReadOnly(readOnly);
        outer.setPropagationBehavior(propagation);

        assertThatThrownBy(() -> outer.executeWithoutResult(status -> {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isEqualTo(actual);
            assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isTrue();
            service.generate(identity, LoanReviewFinancialTemplate.KEY, ACTOR);
        })).isInstanceOfSatisfying(CandidateGenerationException.class, failure -> {
            assertThat(failure.code()).isEqualTo(FailureCode.UNSAFE_TRANSACTION);
            assertSafeFailure(failure);
        });

        verify(sources, never()).prepare(any(), any(), any());
        assertNoHttp();
        assertUnchanged(before, release.id(), 0);
    }

    @Test
    void providerHttpFailureKeepsSourceAuditWithoutRawBodyExposureOrCandidateWrites(CapturedOutput output)
            throws Exception {
        ReleaseDto.Response release = release(true, null);
        var service = service(exchange -> respond(exchange, 400, RAW_RESPONSE));
        Baseline before = baseline(release.id());

        assertThatThrownBy(() -> service.generate(identity(release.id()), LoanReviewFinancialTemplate.KEY, ACTOR))
                .isInstanceOfSatisfying(CandidateGenerationException.class, failure -> {
                    assertThat(failure.code()).isEqualTo(FailureCode.MODEL_CALL_FAILURE);
                    assertSafeFailure(failure);
                });

        assertHttpCall(Thread.currentThread().threadId());
        assertThat(output.getAll()).doesNotContain(SYSTEM_PROMPT, SECRET, RAW_RESPONSE);
        assertUnchanged(before, release.id(), 1);
    }

    @Test
    void malformedContentPreservesStrictResponseFailureWithoutRawRendering(CapturedOutput output) throws Exception {
        ReleaseDto.Response release = release(true, null);
        var service = service(exchange -> respond(exchange, 200, modelEnvelope("{" + RAW_RESPONSE)));
        Baseline before = baseline(release.id());

        assertThatThrownBy(() -> service.generate(identity(release.id()), LoanReviewFinancialTemplate.KEY, ACTOR))
                .isInstanceOfSatisfying(CandidateResponseException.class, failure -> {
                    assertThat(failure.code())
                            .isEqualTo(SafetyContractCandidateResponseProcessor.FailureCode.MALFORMED_RESPONSE);
                    assertSafeFailure(failure);
                });

        assertHttpCall(Thread.currentThread().threadId());
        assertThat(output.getAll()).doesNotContain(SYSTEM_PROMPT, SECRET, RAW_RESPONSE);
        assertUnchanged(before, release.id(), 1);
    }

    @Test
    void draftSourceRejectionNeverCallsModelOrChangesDomainState(CapturedOutput output) throws Exception {
        ReleaseDto.Response release = release(false, null);
        var service = service(exchange -> respond(exchange, 400, "Unexpected request"));
        Baseline before = baseline(release.id());
        clearInvocations(sources);

        assertThatThrownBy(() -> service.generate(identity(release.id()), LoanReviewFinancialTemplate.KEY, ACTOR))
                .isInstanceOfSatisfying(GenerationSourceException.class, failure -> {
                    assertThat(failure.code())
                            .isEqualTo(SafetyContractGenerationSourceService.FailureCode.RELEASE_NOT_ANALYZED);
                    assertSafeFailure(failure);
                });

        verify(sources).prepare(release.id(), LoanReviewFinancialTemplate.KEY, ACTOR);
        assertNoHttp();
        assertThat(domainSnapshot()).isEqualTo(before.domain());
        assertThat(otherAuditSnapshot(release.id())).isEqualTo(before.otherAudits());
        // Source access audit behavior on source failure remains A's existing contract.
        assertThat(accessAuditCount(release.id())).isGreaterThanOrEqualTo(before.accessAudits());
        assertNoToolRequest();
        assertThat(output.getAll()).doesNotContain(SYSTEM_PROMPT, SECRET, RAW_RESPONSE);
    }

    @Test
    void secretManifestTextStopsBeforeHttpAfterCommittedSourceRead(CapturedOutput output) throws Exception {
        ReleaseDto.Response release = release(true, "Bearer " + SECRET);
        var service = service(exchange -> respond(exchange, 400, "Unexpected request"));
        Baseline before = baseline(release.id());

        assertThatThrownBy(() -> service.generate(identity(release.id()), LoanReviewFinancialTemplate.KEY, ACTOR))
                .isInstanceOfSatisfying(BusinessException.class, failure -> {
                    assertThat(failure.errorCode()).isEqualTo(ErrorCode.SECRET_DETECTED);
                    assertSafeFailure(failure);
                });

        assertNoHttp();
        assertThat(output.getAll()).doesNotContain(SYSTEM_PROMPT, SECRET, RAW_RESPONSE);
        assertUnchanged(before, release.id(), 1);
    }

    private ContractCandidateGenerationService service(HttpHandler response) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/agent/contract-candidates", exchange -> {
            try {
                httpCalls.incrementAndGet();
                assertThat(exchange.getRequestMethod()).isEqualTo("POST");
                assertThat(exchange.getRequestHeaders().getFirst("Authorization")).isNull();
                outbound.set(mapper.readTree(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
                response.handle(exchange);
            } catch (Throwable failure) {
                handlerFailure.set(failure);
                try { respond(exchange, 500, "Local test handler failed"); }
                catch (IOException ignored) { exchange.close(); }
            }
        });
        server.start();
        client = spy(new ContractCandidateAiClient(HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2)).version(HttpClient.Version.HTTP_1_1).build(), mapper,
                URI.create("http://127.0.0.1:" + server.getAddress().getPort()), Duration.ofSeconds(10), null));
        doAnswer(invocation -> {
            // Check on the caller thread immediately before entering the actual B HTTP client.
            ModelEntry entry = new ModelEntry(Thread.currentThread().threadId(),
                    TransactionSynchronizationManager.isActualTransactionActive(),
                    TransactionSynchronizationManager.isSynchronizationActive(),
                    TransactionSynchronizationManager.hasResource(dataSource));
            modelEntry.set(entry);
            assertThat(entry).isEqualTo(new ModelEntry(Thread.currentThread().threadId(), false, false, false));
            return invocation.callRealMethod();
        }).when(client).generate(any(), any(), any());
        return new ContractCandidateGenerationService(sources, prompts, processor, client, mapper, redaction);
    }

    private void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private String modelEnvelope(String content) {
        return mapper.createObjectNode().put("provider", "loopback-provider").put("model", "initial-response-fixture")
                .put("content", content).put("latencyMs", 7).toString();
    }

    private ObjectNode policy(VersionIdentity identity) {
        return ((ObjectNode) template.policyRules()).put("contractId", identity.contractKey()).put("version", identity.version());
    }

    private VersionIdentity identity(UUID releaseId) {
        return new VersionIdentity(UUID.randomUUID(), AgentService.DEMO_WORKSPACE_ID, releaseId,
                "initial-integration-" + UUID.randomUUID(), 7);
    }

    private ReleaseDto.Response release(boolean analyze, String description) throws Exception {
        String key = "initial-generation-" + UUID.randomUUID().toString().replace("-", "");
        var agent = agents.create(new AgentDto.CreateRequest(key, "Initial generation test", "Document review"));
        ObjectNode manifest;
        try (var input = getClass().getResourceAsStream("/fixtures/valid-release-manifest-v1.1.json")) {
            manifest = (ObjectNode) mapper.readTree(input);
        }
        ((ObjectNode) manifest.path("agent")).put("id", key);
        ((ObjectNode) manifest.path("systemPrompt")).put("text", SYSTEM_PROMPT);
        if (description != null) ((ObjectNode) manifest.path("businessPurpose")).put("description", description);
        var result = releases.create(agent.id(), manifest, ACTOR);
        if (analyze) {
            releases.analyze(result.id(), ACTOR);
            return releases.find(result.id());
        }
        return result;
    }

    private void assertHttpCall(long callerThread) {
        verify(client, times(1)).generate(any(), any(), any());
        assertThat(httpCalls.get()).isEqualTo(1);
        assertThat(handlerFailure.get()).isNull();
        assertThat(modelEntry.get()).isEqualTo(new ModelEntry(callerThread, false, false, false));
    }

    private void assertNoHttp() {
        verify(client, never()).generate(any(), any(), any());
        assertThat(httpCalls.get()).isZero();
        assertThat(outbound.get()).isNull();
        assertThat(modelEntry.get()).isNull();
        assertThat(handlerFailure.get()).isNull();
    }

    private Baseline baseline(UUID releaseId) {
        return new Baseline(domainSnapshot(), otherAuditSnapshot(releaseId), accessAuditCount(releaseId));
    }

    private void assertUnchanged(Baseline before, UUID releaseId, int accessDelta) {
        assertThat(domainSnapshot()).isEqualTo(before.domain());
        assertThat(otherAuditSnapshot(releaseId)).isEqualTo(before.otherAudits());
        assertThat(accessAuditCount(releaseId)).isEqualTo(before.accessAudits() + accessDelta);
        assertNoToolRequest();
        if (accessDelta > 0) {
            JsonNode metadata = jdbc.queryForObject("select metadata_json::text from audit_records where actor_id=? "
                            + "and resource_id=? and action='SYSTEM_PROMPT_DECRYPTED_INTERNAL' order by occurred_at desc limit 1",
                    (row, index) -> mapper.readTree(row.getString(1)), ACTOR, releaseId);
            assertThat(metadata.path("purpose").stringValue()).isEqualTo("TOOL_CATALOG_INTEGRITY_CHECK");
            assertThat(metadata.path("plaintextReturned").booleanValue()).isFalse();
            assertThat(metadata.toString()).doesNotContain(SYSTEM_PROMPT, SECRET, RAW_RESPONSE);
        }
    }

    private void assertNoToolRequest() {
        assertThat(jdbc.queryForObject("select count(*) from execution_events where event_type='TOOL_REQUEST'",
                Integer.class)).isZero();
    }

    private Map<String, String> domainSnapshot() {
        Map<String, String> result = new LinkedHashMap<>();
        for (String table : DOMAIN_TABLES) {
            String key = table.equals("contract_version_evidence") ? "version_id"
                    : table.equals("run_event_counters") ? "run_id" : "id";
            result.put(table, jdbc.queryForObject("select coalesce(jsonb_agg(to_jsonb(t) order by " + key
                    + ")::text, '[]') from " + table + " t", String.class));
        }
        return result;
    }

    private String otherAuditSnapshot(UUID releaseId) {
        return jdbc.queryForObject("select coalesce(jsonb_agg(to_jsonb(t) order by id)::text, '[]') from audit_records t "
                + "where (actor_id=? and resource_id=? and action='SYSTEM_PROMPT_DECRYPTED_INTERNAL') is not true",
                String.class, ACTOR, releaseId);
    }

    private int accessAuditCount(UUID releaseId) {
        return jdbc.queryForObject("select count(*) from audit_records where actor_id=? and resource_id=? "
                + "and action='SYSTEM_PROMPT_DECRYPTED_INTERNAL'", Integer.class, ACTOR, releaseId);
    }

    private void assertSafeFailure(RuntimeException failure) {
        assertThat(failure.getCause()).isNull();
        assertThat(failure.getSuppressed()).isEmpty();
        StringWriter rendered = new StringWriter();
        failure.printStackTrace(new PrintWriter(rendered));
        assertThat(rendered.toString()).doesNotContain(SYSTEM_PROMPT, SECRET, RAW_RESPONSE);
    }

    private static Stream<Arguments> outerTransactions() {
        return Stream.of(
                Arguments.of("writable transaction", false, TransactionDefinition.PROPAGATION_REQUIRED, true),
                Arguments.of("read-only transaction", true, TransactionDefinition.PROPAGATION_REQUIRED, true),
                Arguments.of("synchronization-only SUPPORTS", false, TransactionDefinition.PROPAGATION_SUPPORTS, false));
    }

    @FunctionalInterface
    private interface HttpHandler { void handle(HttpExchange exchange) throws Exception; }
    private record Baseline(Map<String, String> domain, String otherAudits, int accessAudits) {}
    private record ModelEntry(long threadId, boolean active, boolean synchronization, boolean dataSourceBound) {}
}
