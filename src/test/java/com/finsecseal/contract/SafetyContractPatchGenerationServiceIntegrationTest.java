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
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionState;
import com.finsecseal.contract.SafetyContractPatchGenerationService.FailureCode;
import com.finsecseal.contract.SafetyContractPatchGenerationService.PatchGenerationException;
import com.finsecseal.contract.SafetyContractPatchGenerationService.PatchGenerationResult;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.Status;
import com.finsecseal.contract.SafetyContractPatchResponseProcessor.PatchResponseException;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.platform.contract.ContractPersistenceService;
import com.finsecseal.platform.contract.ContractPersistenceService.Version;
import com.finsecseal.platform.contract.PatchSourceService;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.ReleaseDto;
import com.finsecseal.release.ReleaseService;
import com.finsecseal.runtime.ai.ContractCandidateAiClient;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
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
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
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
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * Actual Spring source proxy/PostgreSQL/B HTTP composition with a local response stub.
 * The generator is constructed directly; this does not claim production activation or a live model call.
 * B/D provenance is a seeded fixture, not an executed attack. No provider key is read by this test.
 */
@Testcontainers
@SpringBootTest(properties = {
        "finsec.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "finsec.scheduling.enabled=false", "finsec.ai.enabled=false"
})
@ExtendWith(OutputCaptureExtension.class)
class SafetyContractPatchGenerationServiceIntegrationTest {
    private static final String ACTOR = "c-patch-generation-integration";
    private static final String SESSION = "PATCH-GENERATION-PRIVATE-SESSION";
    private static final String SYSTEM_PROMPT = "PATCH-GENERATION-PRIVATE-SYSTEM-PROMPT";
    private static final String FORBIDDEN = "PATCH-GENERATION-HELD-OUT-CANARY";
    private static final String SECRET = "PATCH-GENERATION-SYNTHETIC-SECRET-CANARY";
    private static final String RAW_RESPONSE = "PATCH-GENERATION-RAW-PROVIDER-CANARY";
    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final ReviewerContext REVIEWER = new ReviewerContext(
            AgentService.DEMO_WORKSPACE_ID, ACTOR, "AI_SECURITY_REVIEWER", SESSION, true, true, false);
    private static final List<String> DOMAIN_TABLES = List.of(
            "agents", "agent_releases", "release_artifacts", "safety_contracts", "safety_contract_versions",
            "contract_version_evidence", "api_idempotency_records", "patch_proposals", "patch_approvals",
            "test_suites", "test_cases", "test_runs", "test_case_runs", "run_event_counters", "execution_events",
            "findings", "oracle_results", "replay_links", "release_decisions", "evidence_references");

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired SafetyContractPatchGenerationSourceService sources;
    @Autowired SafetyContractPatchPromptBuilder prompts;
    @Autowired SafetyContractPatchResponseProcessor processor;
    @MockitoSpyBean PatchSourceService patchSources;
    @MockitoSpyBean ContractPersistenceService contracts;
    @MockitoSpyBean SafetyContractGenerationSourceService generationSources;
    @Autowired AgentService agents;
    @Autowired ReleaseService releases;
    @Autowired ExecutionEventService events;
    @Autowired ObjectMapper mapper;
    @Autowired CanonicalJsonService canonical;
    @Autowired DigestService digests;
    @Autowired JdbcTemplate jdbc;
    @Autowired DataSource dataSource;
    @Autowired PlatformTransactionManager transactions;

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
    void proposedResponseUsesCommittedSourceAndReleasedLockBeforeActualHttp(CapturedOutput output) throws Exception {
        ObjectNode evidence = mapper.createObjectNode();
        evidence.putObject("observation").put("email", "synthetic@example.invalid")
                .put("accountNumber", "SYNTHETIC-ACCOUNT-314159").put("customerId", "CUST-SYNTHETIC-42");
        Seed seed = seed("SEED", false, false, false, evidence);
        ObjectNode broad = policy(1);
        ((ArrayNode) broad.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed")).add("accountNumber");
        Version base = contracts.create(seed.releaseId(), broad, REVIEWER);
        Baseline before = baseline(seed);
        AtomicReference<PhysicalTransaction> preparation = new AtomicReference<>();
        doAnswer(invocation -> {
            preparation.set(physicalTransaction());
            return invocation.callRealMethod();
        }).when(patchSources).find(seed.findingId(), REVIEWER);
        AtomicBoolean lockAcquired = new AtomicBoolean();
        AtomicBoolean committedAuditVisible = new AtomicBoolean();
        ObjectNode body = patchResponse(policy(2), true);
        SafetyContractPatchGenerationService service = service(exchange -> {
            // A different thread and physical connection can observe commit and take the former lock.
            TransactionTemplate independent = new TransactionTemplate(transactions);
            independent.setTimeout(5);
            independent.executeWithoutResult(status -> {
                UUID locked = jdbc.queryForObject("select id from agent_releases where id=? for update nowait",
                        UUID.class, seed.releaseId());
                lockAcquired.set(seed.releaseId().equals(locked));
                committedAuditVisible.set(accessAuditCount(seed.releaseId()) == before.accessAudits() + 1);
            });
            respond(exchange, 200, modelEnvelope(body.toString()));
        });
        long callerThread = Thread.currentThread().threadId();
        clearOwnerInvocations();

        PatchGenerationResult result = service.generate(seed.findingId(), base.id(), REVIEWER);

        assertThat(preparation.get()).isEqualTo(new PhysicalTransaction("repeatable read", "off", true, true,
                TransactionDefinition.ISOLATION_REPEATABLE_READ));
        assertThat(modelEntry.get()).isEqualTo(new ModelEntry(callerThread, false, false, false));
        assertThat(handlerFailure.get()).isNull();
        assertThat(lockAcquired).isTrue();
        assertThat(committedAuditVisible).isTrue();
        assertThat(httpCalls.get()).isEqualTo(1);
        verify(client, times(1)).generate(any(), any(), any());
        assertThat(result.assessment().decision().status()).isEqualTo(Status.PROPOSED);
        assertThat(result.assessment().candidate().resultPolicy().toString()).isEqualTo(policy(2).toString());
        assertThat(result.finding().findingId()).isEqualTo(seed.findingId());
        assertThat(result.sourceRunId()).isEqualTo(seed.runId());
        assertThat(result.sourceCaseId()).isEqualTo(seed.caseId());
        assertThat(result.oracleResultId()).isEqualTo(seed.oracleId());
        assertThat(result.baseIdentity().versionId()).isEqualTo(base.id());
        assertThat(result.baseIdentity().contractKey()).isEqualTo(base.contractKey());
        assertThat(result.baseState()).isEqualTo(VersionState.CANDIDATE);
        assertThat(result.basePolicyHash()).isEqualTo(base.policyHash());
        assertThat(result.baseResourceHash()).isEqualTo(base.resourceHash());
        assertThat(result.catalogBinding().releaseId()).isEqualTo(seed.releaseId());
        assertThat(result.analyzedAt()).isNotNull();
        assertThat(result.templateKey()).isEqualTo(LoanReviewFinancialTemplate.KEY);
        assertThat(result.provider()).isEqualTo("loopback-provider");
        assertThat(result.model()).isEqualTo("patch-response-fixture");
        assertThat(result.latencyMs()).isEqualTo(7);
        JsonNode request = outbound.get();
        assertThat(request.size()).isEqualTo(3);
        assertThat(request.path("promptVersion").stringValue()).isEqualTo(result.promptVersion());
        JsonNode input = mapper.readTree(request.path("inputJson").stringValue());
        assertThat(input.at("/source/findingId").stringValue()).isEqualTo(seed.findingId().toString());
        assertThat(input.at("/base/identity/versionId").stringValue()).isEqualTo(base.id().toString());
        assertThat(input.at("/base/resourceHash").stringValue()).isEqualTo(base.resourceHash());
        assertThat(input.at("/evidence/redacted/observation/email").stringValue()).isEqualTo("[REDACTED:SENSITIVE_PII]");
        assertThat(input.at("/evidence/redacted/observation/accountNumber").stringValue()).isEqualTo("[REDACTED:FINANCIAL]");
        assertThat(input.at("/evidence/redacted/observation/customerId").stringValue()).startsWith("[SYNTH_ID:");
        assertThat(result.sourceEvidenceDigest()).isEqualTo(seed.evidenceDigest());
        assertThat(result.redactedEvidenceDigest()).isEqualTo(digests.sha256(mapper.writeValueAsBytes(input.at("/evidence/redacted"))));
        assertThat(input.at("/evidence/redactedDigest").stringValue()).isEqualTo(result.redactedEvidenceDigest());
        assertThat(result.promptDigest()).isEqualTo(digests.sha256(mapper.writeValueAsBytes(mapper.createArrayNode()
                .add(result.promptVersion()).add(request.path("instructions").stringValue())
                .add(request.path("inputJson").stringValue()))));
        assertThat(request.toString()).doesNotContain(SESSION, SYSTEM_PROMPT, "synthetic@example.invalid",
                "SYNTHETIC-ACCOUNT-314159", "CUST-SYNTHETIC-42");
        assertThat(result.toString()).doesNotContain(SESSION, SYSTEM_PROMPT, body.toString(), request.toString());
        ((ObjectNode) result.assessment().candidate().resultPolicy()).put("purpose", "LOCAL-MUTATION");
        assertThat(result.assessment().candidate().resultPolicy().path("purpose").stringValue())
                .isEqualTo(LoanReviewFinancialTemplate.PURPOSE);
        assertThat(output.getAll()).doesNotContain(SESSION, SYSTEM_PROMPT, "synthetic@example.invalid", "SYNTHETIC-ACCOUNT-314159");
        assertUnchanged(before, seed, 1);
    }

    @ParameterizedTest
    @EnumSource(value = Status.class, names = {"NO_CHANGE_NEEDED", "INVALID"})
    void nonProposedAssessmentsReturnWithoutAnyLifecycleWrite(Status expected, CapturedOutput output) throws Exception {
        Seed seed = seed("SEED", false, false, false, mapper.createObjectNode());
        Version base = contracts.create(seed.releaseId(), policy(1), REVIEWER);
        ObjectNode body = patchResponse(policy(expected == Status.NO_CHANGE_NEEDED ? 1 : 2), expected == Status.INVALID);
        if (expected == Status.INVALID) {
            // Declared set expansion is rejected through the actual parser and narrowing/semantic engines.
            ((ArrayNode) body.at("/resultPolicy/fieldPolicy/CUSTOMER_DATA_READ/allowed")).add("accountNumber");
            ((ArrayNode) body.at("/operations/0/retainedValues")).add("accountNumber");
        }
        var service = service(exchange -> respond(exchange, 200, modelEnvelope(body.toString())));
        Baseline before = baseline(seed);
        clearOwnerInvocations();

        var result = service.generate(seed.findingId(), base.id(), REVIEWER);

        assertThat(result.assessment().decision().status()).isEqualTo(expected);
        if (expected == Status.NO_CHANGE_NEEDED) {
            assertThat(result.assessment().candidate().operations()).isEmpty();
            assertThat(result.assessment().decision().acceptedProposal().orElseThrow().resultPolicy().policyHash())
                    .isEqualTo(base.policyHash());
        } else assertThat(result.assessment().decision().acceptedProposal()).isEmpty();
        assertThat(httpCalls.get()).isEqualTo(1);
        assertThat(handlerFailure.get()).isNull();
        assertThat(modelEntry.get()).isEqualTo(new ModelEntry(Thread.currentThread().threadId(), false, false, false));
        assertThat(output.getAll()).doesNotContain(SESSION, SYSTEM_PROMPT);
        assertUnchanged(before, seed, 1);
    }

    @ParameterizedTest
    @ValueSource(strings = {"HELD_OUT", "hidden", "ancestor", "foreign", "digest"})
    void forbiddenOwnerSourcesNeverReachHttpLogsResultsOrEvents(String reason, CapturedOutput output) throws Exception {
        ObjectNode evidence = mapper.createObjectNode().put("observation", FORBIDDEN);
        Seed seed = seed(reason.equals("HELD_OUT") ? "HELD_OUT" : reason.equals("ancestor") ? "MUTATION" : "SEED",
                reason.equals("hidden"), reason.equals("ancestor"), reason.equals("digest"), evidence);
        Version base = contracts.create(seed.releaseId(), policy(1), REVIEWER);
        ReviewerContext reviewer = reason.equals("foreign")
                ? new ReviewerContext(UUID.randomUUID(), ACTOR, REVIEWER.role(), SESSION, true, true, false) : REVIEWER;
        var service = service(exchange -> respond(exchange, 400, "unexpected request"));
        Baseline before = baseline(seed);
        AtomicReference<PatchGenerationResult> returned = new AtomicReference<>();
        clearOwnerInvocations();

        assertThatThrownBy(() -> returned.set(service.generate(seed.findingId(), base.id(), reviewer)))
                .isInstanceOfSatisfying(BusinessException.class, failure -> {
                    assertThat(failure.errorCode()).isEqualTo(reason.equals("digest")
                            ? ErrorCode.EVIDENCE_INCOMPLETE : ErrorCode.RESOURCE_NOT_FOUND);
                    assertThat(failure.getMessage()).doesNotContain(FORBIDDEN, seed.evidenceDigest());
                });

        assertThat(returned.get()).isNull();
        verify(patchSources).find(seed.findingId(), reviewer);
        verify(contracts, never()).find(any(), any());
        verify(generationSources, never()).prepare(any(), any(), any());
        assertNoHttp();
        assertThat(output.getAll()).doesNotContain(FORBIDDEN, seed.evidenceDigest(), SESSION, SYSTEM_PROMPT);
        assertThat(domainSnapshot().get("execution_events")).doesNotContain(FORBIDDEN, seed.evidenceDigest());
        assertUnchanged(before, seed, 0);
    }

    @Test
    void actualBaseIntegrityFailureStopsGenerationWithoutModelOrWrites(CapturedOutput output) throws Exception {
        Seed seed = seed("SEED", false, false, false, mapper.createObjectNode());
        Version base = contracts.create(seed.releaseId(), policy(1), REVIEWER);
        assertThat(jdbc.update("update contract_version_evidence set resource_hash=? where version_id=?",
                "sha256:" + "f".repeat(64), base.id())).isEqualTo(1);
        var service = service(exchange -> respond(exchange, 400, "unexpected request"));
        Baseline before = baseline(seed);
        clearOwnerInvocations();

        assertThatThrownBy(() -> service.generate(seed.findingId(), base.id(), REVIEWER))
                .isInstanceOfSatisfying(BusinessException.class,
                        failure -> assertThat(failure.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE));

        verify(patchSources).find(seed.findingId(), REVIEWER);
        verify(contracts).find(base.id(), REVIEWER);
        verify(generationSources, never()).prepare(any(), any(), any());
        assertNoHttp();
        assertThat(output.getAll()).doesNotContain(SESSION, SYSTEM_PROMPT);
        assertUnchanged(before, seed, 0);
    }

    @Test
    void secretEvidenceIsRejectedAfterSourceCommitBeforeAnyHttp(CapturedOutput output) throws Exception {
        Seed seed = seed("SEED", false, false, false, mapper.createObjectNode().put("authorization", SECRET));
        Version base = contracts.create(seed.releaseId(), policy(1), REVIEWER);
        var service = service(exchange -> respond(exchange, 400, "unexpected request"));
        Baseline before = baseline(seed);
        clearOwnerInvocations();

        assertThatThrownBy(() -> service.generate(seed.findingId(), base.id(), REVIEWER))
                .isInstanceOfSatisfying(BusinessException.class, failure -> {
                    assertThat(failure.errorCode()).isEqualTo(ErrorCode.SECRET_DETECTED);
                    assertThat(failure.getMessage()).doesNotContain(SECRET, seed.evidenceDigest());
                });

        assertNoHttp();
        assertThat(output.getAll()).doesNotContain(SECRET, seed.evidenceDigest(), SESSION, SYSTEM_PROMPT);
        assertThat(domainSnapshot().get("execution_events")).doesNotContain(SECRET, seed.evidenceDigest());
        assertUnchanged(before, seed, 1);
    }

    @Test
    void secretManifestDescriptionIsRejectedWithOrdinaryEvidenceBeforeAnyHttp(CapturedOutput output) throws Exception {
        String token = "PATCH-MANIFEST-SYNTHETIC-SECRET-42";
        String description = "Bearer " + token;
        Seed seed = seed("SEED", false, false, false, mapper.createObjectNode(), description);
        assertThat(releases.getRequired(seed.releaseId()).getManifestJson()
                .at("/businessPurpose/description").stringValue()).isEqualTo(description);
        Version base = contracts.create(seed.releaseId(), policy(1), REVIEWER);
        var service = service(exchange -> respond(exchange, 400, "unexpected request"));
        Baseline before = baseline(seed);
        AtomicReference<PatchGenerationResult> returned = new AtomicReference<>();
        clearOwnerInvocations();

        assertThatThrownBy(() -> returned.set(service.generate(seed.findingId(), base.id(), REVIEWER)))
                .isInstanceOfSatisfying(BusinessException.class, failure -> {
                    assertThat(failure.errorCode()).isEqualTo(ErrorCode.SECRET_DETECTED);
                    assertThat(failure.getCause()).isNull();
                    assertThat(failure.getSuppressed()).isEmpty();
                    assertThat(failure.getMessage()).doesNotContain(description, token);
                });

        assertThat(returned.get()).isNull();
        assertNoHttp();
        assertThat(output.getAll()).doesNotContain(description, token, SESSION, SYSTEM_PROMPT);
        // The ordinary empty evidence digest can legitimately appear in safe existing events.
        assertThat(domainSnapshot().get("execution_events")).doesNotContain(description, token);
        assertUnchanged(before, seed, 1);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("outerTransactions")
    void outerActualTransactionsAndSynchronizationStopBeforeEveryOwnerRead(
            String description, int isolation, boolean readOnly, int propagation, boolean actual) throws Exception {
        Seed seed = seed("SEED", false, false, false, mapper.createObjectNode());
        Version base = contracts.create(seed.releaseId(), policy(1), REVIEWER);
        var service = service(exchange -> respond(exchange, 400, "unexpected request"));
        TransactionTemplate outer = new TransactionTemplate(transactions);
        outer.setIsolationLevel(isolation);
        outer.setReadOnly(readOnly);
        outer.setPropagationBehavior(propagation);
        Baseline before = baseline(seed);
        clearOwnerInvocations();

        assertThatThrownBy(() -> outer.executeWithoutResult(status -> {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isEqualTo(actual);
            assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isTrue();
            service.generate(seed.findingId(), base.id(), REVIEWER);
        })).isInstanceOfSatisfying(PatchGenerationException.class,
                failure -> assertSafeFailure(failure, FailureCode.UNSAFE_TRANSACTION));

        verify(patchSources, never()).find(any(), any());
        verify(contracts, never()).find(any(), any());
        verify(generationSources, never()).prepare(any(), any(), any());
        assertNoHttp();
        assertUnchanged(before, seed, 0);
    }

    @Test
    void providerHttpFailureDoesNotExposeBodyOrWriteAfterSourceCommit(CapturedOutput output) throws Exception {
        Seed seed = seed("SEED", false, false, false, mapper.createObjectNode());
        Version base = contracts.create(seed.releaseId(), policy(1), REVIEWER);
        var service = service(exchange -> respond(exchange, 400, RAW_RESPONSE));
        Baseline before = baseline(seed);
        clearOwnerInvocations();

        assertThatThrownBy(() -> service.generate(seed.findingId(), base.id(), REVIEWER))
                .isInstanceOfSatisfying(PatchGenerationException.class,
                        failure -> assertSafeFailure(failure, FailureCode.MODEL_CALL_FAILURE));

        verify(client, times(1)).generate(any(), any(), any());
        assertThat(httpCalls.get()).isEqualTo(1);
        assertThat(handlerFailure.get()).isNull();
        assertThat(output.getAll()).doesNotContain(RAW_RESPONSE, SESSION, SYSTEM_PROMPT);
        assertUnchanged(before, seed, 1);
    }

    @Test
    void malformedModelContentRemainsStrictFailureWithoutRawResponseExposure(CapturedOutput output) throws Exception {
        Seed seed = seed("SEED", false, false, false, mapper.createObjectNode());
        Version base = contracts.create(seed.releaseId(), policy(1), REVIEWER);
        var service = service(exchange -> respond(exchange, 200, modelEnvelope("{" + RAW_RESPONSE)));
        Baseline before = baseline(seed);
        clearOwnerInvocations();

        assertThatThrownBy(() -> service.generate(seed.findingId(), base.id(), REVIEWER))
                .isInstanceOfSatisfying(PatchResponseException.class, failure -> {
                    assertThat(failure.code()).isEqualTo(SafetyContractPatchResponseProcessor.FailureCode.MALFORMED_RESPONSE);
                    assertThat(failure.getCause()).isNull();
                    assertThat(failure.getSuppressed()).isEmpty();
                    assertThat(failure.getMessage()).doesNotContain(RAW_RESPONSE);
                });

        verify(client, times(1)).generate(any(), any(), any());
        assertThat(httpCalls.get()).isEqualTo(1);
        assertThat(handlerFailure.get()).isNull();
        assertThat(output.getAll()).doesNotContain(RAW_RESPONSE, SESSION, SYSTEM_PROMPT);
        assertUnchanged(before, seed, 1);
    }

    private SafetyContractPatchGenerationService service(HttpHandler response) throws IOException {
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
            modelEntry.set(new ModelEntry(Thread.currentThread().threadId(),
                    TransactionSynchronizationManager.isActualTransactionActive(),
                    TransactionSynchronizationManager.isSynchronizationActive(),
                    TransactionSynchronizationManager.hasResource(dataSource)));
            return invocation.callRealMethod();
        }).when(client).generate(any(), any(), any());
        return new SafetyContractPatchGenerationService(sources, prompts, client, processor);
    }

    private void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private String modelEnvelope(String content) {
        return mapper.createObjectNode().put("provider", "loopback-provider").put("model", "patch-response-fixture")
                .put("content", content).put("latencyMs", 7).toString();
    }

    private ObjectNode patchResponse(ObjectNode result, boolean narrowing) {
        ObjectNode response = mapper.createObjectNode();
        response.set("resultPolicy", result);
        var operations = response.putArray("operations");
        if (narrowing) operations.addObject().put("type", "NARROW_SET").put("setKind", "ALLOWED_FIELDS")
                .put("toolName", "CUSTOMER_DATA_READ").putArray("retainedValues").add("incomeBand").add("employmentStatus");
        return response.put("rootCause", "Unexpected field availability observed")
                .put("normalWorkflowImpact", "Keep both required review fields")
                .put("rollback", "Create a separately reviewed replacement version");
    }

    private void assertNoHttp() {
        verify(client, never()).generate(any(), any(), any());
        assertThat(httpCalls.get()).isZero();
        assertThat(outbound.get()).isNull();
        assertThat(modelEntry.get()).isNull();
        assertThat(handlerFailure.get()).isNull();
    }

    private PhysicalTransaction physicalTransaction() {
        return new PhysicalTransaction(jdbc.queryForObject("select current_setting('transaction_isolation')", String.class),
                jdbc.queryForObject("select current_setting('transaction_read_only')", String.class),
                TransactionSynchronizationManager.isActualTransactionActive(),
                TransactionSynchronizationManager.isSynchronizationActive(),
                TransactionSynchronizationManager.getCurrentTransactionIsolationLevel());
    }

    private void clearOwnerInvocations() { clearInvocations(patchSources, contracts, generationSources); }

    private Baseline baseline(Seed seed) {
        return new Baseline(domainSnapshot(), otherAuditSnapshot(), accessAuditCount(seed.releaseId()));
    }

    private void assertUnchanged(Baseline before, Seed seed, int accessDelta) {
        verify(contracts, never()).create(any(), any(), any());
        verify(contracts, never()).storePatch(any(), any(), any(), any());
        verify(contracts, never()).validate(any(), any(), any());
        verify(contracts, never()).approve(any(), any(), any(), any());
        verify(contracts, never()).approve(any(), any(), any(), any(), any());
        verify(contracts, never()).reject(any(), any(), any(), any());
        verify(contracts, never()).approved(any(), any(), any());
        assertThat(domainSnapshot()).isEqualTo(before.domain());
        assertThat(otherAuditSnapshot()).isEqualTo(before.otherAudits());
        assertThat(accessAuditCount(seed.releaseId())).isEqualTo(before.accessAudits() + accessDelta);
        assertThat(jdbc.queryForObject("select count(*) from execution_events where event_type='TOOL_REQUEST'", Integer.class)).isZero();
        if (accessDelta > 0) {
            JsonNode metadata = jdbc.queryForObject("select metadata_json::text from audit_records where actor_id=? "
                            + "and resource_id=? and action='SYSTEM_PROMPT_DECRYPTED_INTERNAL' order by occurred_at desc limit 1",
                    (row, index) -> mapper.readTree(row.getString(1)), ACTOR, seed.releaseId());
            assertThat(metadata.path("purpose").stringValue()).isEqualTo("TOOL_CATALOG_INTEGRITY_CHECK");
            assertThat(metadata.path("plaintextReturned").booleanValue()).isFalse();
            assertThat(metadata.toString()).doesNotContain(SESSION, SYSTEM_PROMPT, SECRET, FORBIDDEN, RAW_RESPONSE);
        }
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

    private String otherAuditSnapshot() {
        return jdbc.queryForObject("select coalesce(jsonb_agg(to_jsonb(t) order by id)::text, '[]') from audit_records t "
                + "where not (actor_id=? and action='SYSTEM_PROMPT_DECRYPTED_INTERNAL')", String.class, ACTOR);
    }

    private int accessAuditCount(UUID releaseId) {
        return jdbc.queryForObject("select count(*) from audit_records where actor_id=? and resource_id=? "
                + "and action='SYSTEM_PROMPT_DECRYPTED_INTERNAL'", Integer.class, ACTOR, releaseId);
    }

    private void assertSafeFailure(PatchGenerationException failure, FailureCode code) {
        assertThat(failure.code()).isEqualTo(code);
        assertThat(failure.getCause()).isNull();
        assertThat(failure.getSuppressed()).isEmpty();
        assertThat(failure.getMessage()).doesNotContain(SESSION, SYSTEM_PROMPT, RAW_RESPONSE, SECRET, FORBIDDEN);
    }

    private static Stream<Arguments> outerTransactions() {
        return Stream.of(
                Arguments.of("default writable", TransactionDefinition.ISOLATION_DEFAULT, false, TransactionDefinition.PROPAGATION_REQUIRED, true),
                Arguments.of("read-only RR", TransactionDefinition.ISOLATION_REPEATABLE_READ, true, TransactionDefinition.PROPAGATION_REQUIRED, true),
                Arguments.of("writable RR", TransactionDefinition.ISOLATION_REPEATABLE_READ, false, TransactionDefinition.PROPAGATION_REQUIRED, true),
                Arguments.of("synchronization only", TransactionDefinition.ISOLATION_DEFAULT, false, TransactionDefinition.PROPAGATION_SUPPORTS, false));
    }

    private ObjectNode policy(int version) throws Exception {
        try (var stream = getClass().getResourceAsStream("/fixtures/loan-review-safety-contract.json")) {
            return ((ObjectNode) mapper.readTree(stream)).put("contractId", "patch-generation-policy").put("version", version);
        }
    }

    private ReleaseDto.Response release(String description) throws Exception {
        String key = "c-patch-generation-" + UUID.randomUUID();
        var agent = agents.create(new AgentDto.CreateRequest(key, "Patch generation fixture", "Document review"));
        ObjectNode manifest;
        try (var stream = getClass().getResourceAsStream("/fixtures/valid-release-manifest-v1.1.json")) {
            manifest = (ObjectNode) mapper.readTree(stream);
        }
        ((ObjectNode) manifest.path("agent")).put("id", key);
        ((ObjectNode) manifest.path("systemPrompt")).put("text", SYSTEM_PROMPT);
        if (description != null) ((ObjectNode) manifest.path("businessPurpose")).put("description", description);
        UUID releaseId = releases.create(agent.id(), manifest, ACTOR).id();
        releases.analyze(releaseId, ACTOR);
        return releases.find(releaseId);
    }

    private Seed seed(String partition, boolean hidden, boolean hiddenParent, boolean invalidDigest, JsonNode evidence) throws Exception {
        return seed(partition, hidden, hiddenParent, invalidDigest, evidence, null);
    }

    private Seed seed(String partition, boolean hidden, boolean hiddenParent, boolean invalidDigest,
            JsonNode evidence, String description) throws Exception {
        var release = release(description);
        String suffix = UUID.randomUUID().toString();
        UUID suite = UUID.randomUUID();
        UUID testCase = UUID.randomUUID();
        UUID run = UUID.randomUUID();
        UUID caseRun = UUID.randomUUID();
        UUID oracle = UUID.randomUUID();
        UUID finding = UUID.randomUUID();
        String evidenceDigest = digests.sha256(canonical.canonicalize(evidence));
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        Timestamp time = Timestamp.from(now);
        Timestamp started = Timestamp.from(now.minusSeconds(1));
        // Existing source integration fixture sequence, with every DB guard enabled.
        jdbc.update("""
                insert into test_suites(id,workspace_id,suite_key,version,fixture_version,generation_config_json,
                    suite_hash,status,created_at,updated_at)
                values(?,?,?,'1.0.0','fixture-v1','{}'::jsonb,?,'DRAFT',?,?)
                """, suite, REVIEWER.workspaceId(), "patch-generation-" + suffix, HASH, time, time);
        jdbc.update("""
                insert into test_cases(id,suite_id,case_key,case_type,partition_name,category,severity,
                    delivery_channel,target_tool,attack_goal,payload_hash,preconditions_json,expected_invariant,
                    oracle_type,generation_source,hidden_from_patch_generator,expected_result_json,trial_policy_json,
                    created_at,updated_at)
                values(?,?,?,'ATTACK',?,'FA-02','CRITICAL','DOCUMENT','CUSTOMER_DATA_READ','cross customer read',?,
                    '{}'::jsonb,'INV-01','CROSS_CUSTOMER','GOLDEN',?,'{}'::jsonb,'{}'::jsonb,?,?)
                """, testCase, suite, "case-" + suffix, partition, HASH, hidden, time, time);
        if (hiddenParent) {
            UUID parent = UUID.randomUUID();
            jdbc.update("""
                    insert into test_cases(id,suite_id,case_key,case_type,partition_name,category,severity,
                        delivery_channel,payload_hash,preconditions_json,expected_invariant,oracle_type,
                        generation_source,hidden_from_patch_generator,expected_result_json,trial_policy_json)
                    values(?,?,'hidden-parent','ATTACK','HELD_OUT','FA-02','HIGH','DOCUMENT',?,'{}','INV-01',
                        'CROSS_CUSTOMER','GOLDEN',true,'{}','{}')
                    """, parent, suite, HASH);
            jdbc.update("update test_cases set parent_seed_id=? where id=?", parent, testCase);
        }
        jdbc.update("update test_suites set status='READY',updated_at=? where id=?", time, suite);
        jdbc.update("""
                insert into test_runs(id,release_id,suite_id,mode,status,agent_artifact_fingerprint,release_fingerprint,
                    config_json,fixture_version,fixture_digest,model_config_hash,total_cases,completed_cases,
                    operational_error_count,started_at,completed_at,summary_json,created_at,updated_at)
                values(?,?,?,'BASELINE','QUEUED',?,?,'{}'::jsonb,'fixture-v1',?,?,1,0,0,null,null,'{}'::jsonb,?,?)
                """, run, release.id(), suite, release.agentArtifactFingerprint(), release.releaseFingerprint(), HASH, HASH, time, time);
        jdbc.update("""
                insert into test_case_runs(id,test_run_id,test_case_id,trial_index,status,security_outcome,
                    variant_hash,started_at,completed_at,result_json,created_at,updated_at)
                values(?,?,?,0,'PENDING',null,?,null,null,'{}'::jsonb,?,?)
                """, caseRun, run, testCase, HASH, time, time);
        jdbc.update("update test_case_runs set status='FAILED_SECURITY',security_outcome='ATTACK_SUCCESS', "
                + "started_at=?,completed_at=?,updated_at=? where id=?", started, time, time, caseRun);
        // Oracle evidence is immutable after completion: canaries and bad digests enter only at fixture INSERT.
        jdbc.update("""
                insert into oracle_results(id,test_case_run_id,oracle_type,oracle_version,outcome,reason_code,
                    invariant_id,evidence_json,evidence_digest,evaluated_at,created_at,updated_at)
                values(?,?,'CROSS_CUSTOMER','1.0','ATTACK_SUCCESS','UNAUTHORIZED_RECORD_RETURNED','INV-01',
                    cast(? as jsonb),?,?,?,?)
                """, oracle, caseRun, evidence.toString(), invalidDigest ? HASH : evidenceDigest, time, time, time);
        jdbc.update("""
                insert into findings(id,release_id,source_oracle_result_id,category,severity,title,status,
                    violated_invariant,root_cause_json,first_seen_run_id,latest_seen_run_id,created_at,updated_at)
                values(?,?,?,'FA-02','CRITICAL','Synthetic unauthorized record fixture','OPEN','INV-01','{}'::jsonb,?,?,?,?)
                """, finding, release.id(), oracle, run, run, time, time);
        jdbc.update("update test_runs set status='PREPARING',updated_at=? where id=?", Timestamp.from(now.minusSeconds(2)), run);
        jdbc.update("update test_runs set status='RUNNING',started_at=?,updated_at=? where id=?", started, started, run);
        jdbc.update("insert into run_event_counters(run_id,last_sequence) values(?,0)", run);
        UUID trace = UUID.randomUUID();
        // Safe event payloads deliberately exclude the Oracle-only canary and its digest.
        events.append(run, new ExecutionEventDto.AppendRequest(null, trace, ExecutionEventType.RUN_STARTED,
                null, null, null, null, "RUN_STARTED", mapper.createObjectNode()), ACTOR);
        events.append(run, new ExecutionEventDto.AppendRequest(null, trace, ExecutionEventType.RUN_COMPLETED,
                null, null, null, null, "RUN_COMPLETED", mapper.createObjectNode()), ACTOR);
        jdbc.update("update test_runs set status='COMPLETED',completed_cases=1,started_at=?,completed_at=?,updated_at=? "
                + "where id=?", started, time, time, run);
        jdbc.update("update agent_releases set lifecycle_state='TESTING',effective_status='TESTING' where id=?", release.id());
        return new Seed(release.id(), finding, oracle, run, testCase, evidenceDigest);
    }

    @FunctionalInterface
    private interface HttpHandler { void handle(HttpExchange exchange) throws Exception; }
    private record Seed(UUID releaseId, UUID findingId, UUID oracleId, UUID runId, UUID caseId, String evidenceDigest) {}
    private record Baseline(Map<String, String> domain, String otherAudits, int accessAudits) {}
    private record PhysicalTransaction(String isolation, String readOnly, boolean active, boolean synchronization, Integer metadataIsolation) {}
    private record ModelEntry(long threadId, boolean active, boolean synchronization, boolean dataSourceBound) {}
}
