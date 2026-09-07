package com.finsecseal.contract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.platform.contract.ContractPersistenceService;
import com.finsecseal.platform.contract.ContractPersistenceService.Version;
import com.finsecseal.release.ReleaseService;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.CannotCreateTransactionException;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/** Actual HTTP, A access/idempotency filters, transactional service proxies and PostgreSQL. */
@Testcontainers
@ExtendWith(OutputCaptureExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "finsec.scheduling.enabled=false",
        "finsec.contract-access.key=c-review-http-key-at-least-32-bytes-long-test-only",
        "finsec.contract-access.actor=c-stored-review-http",
        "finsec.contract-access.workspace=0198f1e2-0000-7000-8000-000000000001"
})
class StoredSafetyContractReviewControllerIntegrationTest {
    private static final String PREFIX = "/api/v1/platform/contracts";
    private static final String KEY = "c-review-http-key-at-least-32-bytes-long-test-only";
    private static final String ACTOR = "c-stored-review-http";
    private static final String COMMENT = "현재 신청자의 서류 검토 범위와 정상업무 영향을 확인했습니다.";
    private static final String SESSION = "HTTP-REVIEW-PRIVATE-FIXTURE-SESSION";
    private static final String SQL_CANARY = "HTTP-REVIEW-PRIVATE-SQL-FAILURE";
    private static final String TRANSACTION_CANARY = "HTTP-REVIEW-PRIVATE-TRANSACTION-FAILURE";
    private static final String FOREIGN_CANARY = "FOREIGN-CONTRACT-NOT-FOR-DISCLOSURE";
    private static final ReviewerContext REVIEWER = reviewer(AgentService.DEMO_WORKSPACE_ID);
    private static final List<String> SNAPSHOT_TABLES = List.of(
            "agent_releases", "release_artifacts", "safety_contracts", "safety_contract_versions",
            "contract_version_evidence", "audit_records", "api_idempotency_records",
            "patch_proposals", "patch_approvals", "test_runs", "test_case_runs", "execution_events",
            "findings", "oracle_results", "replay_links", "release_decisions", "evidence_references");

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @LocalServerPort int port;
    @Autowired AgentService agents;
    @Autowired ReleaseService releases;
    @MockitoSpyBean ContractPersistenceService contracts;
    @MockitoSpyBean StoredSafetyContractReviewService reviews;
    @Autowired SafetyContractCanonicalizer canonicalizer;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate jdbc;
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    @Test
    void repeatedAuthenticatedGetsExposeNullableJsonTextAndResourceHashWithoutWrites() throws Exception {
        Version candidate = contracts.create(release(), policy(1), REVIEWER);
        Map<String, String> before = databaseSnapshot();
        clearInvocations(contracts, reviews);

        HttpResponse<String> first = get(candidate.id());
        JsonNode data = success(first, candidate);
        assertThat(fields(data)).containsExactlyInAnyOrder("identity", "state", "policyHash", "resourceHash",
                "storedPolicyJson", "canonicalPolicyJson", "baseline", "validation", "review", "changes");
        assertIdentity(data.path("identity"), candidate);
        assertThat(data.path("state").asString()).isEqualTo("CANDIDATE");
        assertThat(data.path("baseline").isNull()).isTrue();
        assertThat(data.path("validation").isNull()).isTrue();
        assertThat(data.path("review").isNull()).isTrue();
        assertThat(data.path("changes").size()).isEqualTo(1);
        JsonNode addition = data.path("changes").get(0);
        assertThat(fields(addition)).containsExactlyInAnyOrder("pointer", "kind", "beforeJson", "afterJson");
        assertThat(addition.path("pointer").asString()).isEmpty();
        assertThat(addition.path("kind").asString()).isEqualTo("ADDED");
        assertThat(addition.path("beforeJson").isNull()).isTrue();
        assertThat(addition.path("afterJson").isString()).isTrue();
        assertThat(mapper.readTree(addition.path("afterJson").asString())).isEqualTo(candidate.policy());
        assertThat(first.body()).doesNotContain(SESSION, KEY, "credential-request:");

        HttpResponse<String> repeated = get(path(candidate.id()), Map.of(
                "X-Contract-Reviewer-Key", KEY, "X-Actor-Id", ACTOR));
        assertThat(success(repeated, candidate)).isEqualTo(data);
        // The mutation concurrency token is not advertised as a validator for this GET representation.
        String mutationToken = '"' + data.path("resourceHash").asString() + '"';
        HttpResponse<String> conditional = get(path(candidate.id()), Map.of(
                "X-Contract-Reviewer-Key", KEY, "If-None-Match", mutationToken));
        assertThat(success(conditional, candidate)).isEqualTo(data);
        ((ObjectNode) mapper.readTree(data.path("storedPolicyJson").asString())).put("purpose", "LOCAL-ONLY");
        assertThat(success(get(candidate.id()), candidate)).isEqualTo(data);
        verify(contracts, never()).list(any(), any());
        verifyNoAuthorityCalls();
        assertThat(databaseSnapshot()).isEqualTo(before);
    }

    @Test
    void approvedHistoricalReviewProjectsOnlyPublicReviewAndValidationFields() throws Exception {
        UUID releaseId = release();
        Version first = approve(releaseId, policy(1));
        Version second = approve(releaseId, policy(2));
        assertThat(releases.find(releaseId).safetyContractHash()).isEqualTo(second.policyHash());
        Map<String, String> before = databaseSnapshot();
        clearInvocations(contracts, reviews);

        JsonNode data = success(get(second.id()), second);

        assertThat(data.path("state").asString()).isEqualTo("APPROVED");
        assertThat(fields(data.path("baseline"))).containsExactlyInAnyOrder("identity", "policyHash");
        assertIdentity(data.at("/baseline/identity"), first);
        assertThat(data.at("/baseline/policyHash").asString()).isEqualTo(first.policyHash());
        assertThat(fields(data.path("validation"))).containsExactlyInAnyOrder("status", "issues");
        assertThat(data.at("/validation/status").asString()).isEqualTo("VALID");
        assertThat(data.at("/validation/issues").isArray()).isTrue();
        assertThat(fields(data.path("review"))).containsExactlyInAnyOrder("actorId", "role", "comment", "decision");
        assertThat(data.at("/review/actorId").asString()).isEqualTo(ACTOR);
        assertThat(data.at("/review/role").asString()).isEqualTo(REVIEWER.role());
        assertThat(data.at("/review/comment").asString()).isEqualTo(COMMENT);
        assertThat(data.at("/review/decision").asString()).isEqualTo("APPROVED");
        assertThat(data.toString()).doesNotContain(SESSION, "sessionId", "validationHash", "sourceBinding");
        assertThat(change(data, "/version").path("beforeJson").asString()).isEqualTo("1");
        assertThat(change(data, "/version").path("afterJson").asString()).isEqualTo("2");
        verifyNoAuthorityCalls();
        assertThat(databaseSnapshot()).isEqualTo(before);
    }

    @Test
    void storedUnicodeAndLargeIntegersRemainExactJsonTextInSnapshotsAndDiff() throws Exception {
        UUID releaseId = release();
        Version baseline = approve(releaseId, policy(1));
        ObjectNode submitted = policy(2);
        submitted.put("purpose", "대출 검토 \"서류\" · café\n추가 확인");
        BigInteger large = new BigInteger("9007199254740994");
        ((ObjectNode) submitted.at("/cardinality/CUSTOMER_DATA_READ")).put("maxRequestedRecords", large);
        Version candidate = contracts.create(releaseId, submitted, REVIEWER);
        Version stored = contracts.find(candidate.id(), REVIEWER);
        // A already canonicalizes provider input. Only its reloaded stored tree is the review source.
        assertThat(stored.policy().at("/cardinality/CUSTOMER_DATA_READ/maxRequestedRecords").bigIntegerValue())
                .isEqualTo(large);
        Map<String, String> before = databaseSnapshot();
        clearInvocations(contracts, reviews);

        JsonNode data = success(get(candidate.id()), stored);

        assertIdentity(data.at("/baseline/identity"), baseline);
        assertThat(data.path("storedPolicyJson").asString()).contains(large.toString(), "대출 검토", "café");
        assertThat(data.path("canonicalPolicyJson").asString()).contains(large.toString());
        JsonNode numberChange = change(data, "/cardinality/CUSTOMER_DATA_READ/maxRequestedRecords");
        assertThat(numberChange.path("beforeJson").isString()).isTrue();
        assertThat(numberChange.path("beforeJson").asString()).isEqualTo("1");
        assertThat(numberChange.path("afterJson").isString()).isTrue();
        assertThat(numberChange.path("afterJson").asString()).isEqualTo(large.toString());
        JsonNode purposeChange = change(data, "/purpose");
        assertThat(purposeChange.path("afterJson").isString()).isTrue();
        assertThat(purposeChange.path("afterJson").asString())
                .isEqualTo(mapper.writeValueAsString(stored.policy().path("purpose")));
        assertThat(mapper.readTree(purposeChange.path("afterJson").asString()))
                .isEqualTo(stored.policy().path("purpose"));
        assertThat(data.path("validation").isNull()).isTrue();
        verifyNoAuthorityCalls();
        assertThat(databaseSnapshot()).isEqualTo(before);
    }

    @Test
    void invalidCandidateReturnsActualIssuesWithoutAnApprovalProjection() throws Exception {
        ObjectNode policy = policy(1);
        ((ArrayNode) policy.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed")).add("accountNumber");
        Version candidate = contracts.create(release(), policy, REVIEWER);
        Version invalid = contracts.validate(candidate.id(), etag(candidate), REVIEWER);
        Map<String, String> before = databaseSnapshot();
        clearInvocations(contracts, reviews);

        JsonNode data = success(get(invalid.id()), invalid);

        assertThat(data.path("state").asString()).isEqualTo("CANDIDATE");
        assertThat(data.at("/validation/status").asString()).isEqualTo("INVALID");
        assertThat(data.at("/validation/issues").isArray()).isTrue();
        assertThat(data.at("/validation/issues").isEmpty()).isFalse();
        for (JsonNode issue : data.at("/validation/issues")) {
            assertThat(fields(issue)).containsExactlyInAnyOrder("jsonPointer", "code", "severity", "message");
        }
        assertThat(data.path("review").isNull()).isTrue();
        verifyNoAuthorityCalls();
        assertThat(databaseSnapshot()).isEqualTo(before);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("deniedCredentials")
    void accessFilterRejectsCredentialsBeforeAnyServiceRead(
            String description, Map<String, String> headers, CapturedOutput output
    ) throws Exception {
        Version candidate = contracts.create(release(), policy(1), REVIEWER);
        Map<String, String> before = databaseSnapshot();
        clearInvocations(contracts, reviews);

        for (boolean conditional : List.of(false, true)) {
            Map<String, String> requestHeaders = new LinkedHashMap<>(headers);
            if (conditional) requestHeaders.put("If-None-Match", '"' + candidate.resourceHash() + '"');
            HttpResponse<String> response = get(path(candidate.id()), requestHeaders);

            JsonNode problem = mapper.readTree(response.body());
            assertThat(response.statusCode()).isEqualTo(403);
            assertThat(problem.path("code").asString()).isEqualTo("CONTRACT_AUTH_REQUIRED");
            assertThat(response.headers().firstValue("Content-Type")).hasValueSatisfying(
                    type -> assertThat(type).startsWith("application/problem+json"));
            assertThat(response.headers().firstValue("ETag")).isEmpty();
            assertThat(problem.path("traceId").asString()).isEqualTo(response.headers().firstValue("X-Trace-Id").orElseThrow());
            assertThat(response.body()).doesNotContain(candidate.policyHash(), candidate.contractKey(), KEY);
        }
        assertThat(output.getAll()).doesNotContain(KEY, "HTTP-WRONG-KEY-CANARY", "HTTP-COOKIE-CANARY", "HTTP-FORGED-ACTOR-CANARY");
        verify(reviews, never()).review(any(), any());
        verify(contracts, never()).find(any(), any());
        verify(contracts, never()).list(any(), any());
        assertThat(databaseSnapshot()).isEqualTo(before);
    }

    @Test
    void authenticatedForeignWorkspaceRequestIsDeniedWithoutPolicyDisclosure(CapturedOutput output) throws Exception {
        UUID workspace = UUID.randomUUID();
        UUID agent = UUID.randomUUID();
        String agentKey = "foreign-review-" + UUID.randomUUID();
        // A's demo AgentService cannot select another workspace; seed only this foreign tenant/Agent fixture.
        jdbc.update("insert into workspaces(id,name,mode) values(?,'Foreign review fixture','DEMO')", workspace);
        jdbc.update("insert into agents(id,workspace_id,agent_key,name,purpose_summary,status) "
                + "values(?,?,?,'Foreign review fixture','Document review','ACTIVE')", agent, workspace, agentKey);
        UUID releaseId = release(agent, agentKey);
        ObjectNode foreignPolicy = policy(1).put("contractId", FOREIGN_CANARY);
        Version foreign = contracts.create(releaseId, foreignPolicy, reviewer(workspace));
        Map<String, String> before = databaseSnapshot();
        clearInvocations(contracts, reviews);

        HttpResponse<String> response = get(foreign.id());

        problem(response, 403, "OPERATOR_AUTH_REQUIRED");
        assertThat(response.body()).doesNotContain(FOREIGN_CANARY, foreign.policyHash(), SESSION, KEY);
        assertThat(output.getAll()).doesNotContain(FOREIGN_CANARY, foreign.policyHash(), SESSION, KEY);
        verify(contracts).find(eq(foreign.id()), any(ReviewerContext.class));
        verify(contracts, never()).list(any(), any());
        assertThat(databaseSnapshot()).isEqualTo(before);
    }

    @Test
    void unknownIdPreservesANotFoundStatusAndSafeProblemShape() throws Exception {
        Map<String, String> before = databaseSnapshot();

        problem(get(UUID.randomUUID()), 404, "RESOURCE_NOT_FOUND");

        assertThat(databaseSnapshot()).isEqualTo(before);
    }

    @Test
    void malformedUuidIs400BeforeServiceInvocationAndNeverEchoesInput(CapturedOutput output) throws Exception {
        String malformed = "HTTP-PRIVATE-BAD-UUID-CANARY";
        Map<String, String> before = databaseSnapshot();
        clearInvocations(contracts, reviews);

        HttpResponse<String> response = get(PREFIX + "/" + malformed + "/review", credentials());

        problem(response, 400, "CONTRACT_REVIEW_INVALID_REQUEST");
        assertThat(response.body()).doesNotContain(malformed, KEY, SESSION);
        assertThat(output.getAll()).doesNotContain(malformed, KEY, SESSION);
        verify(reviews, never()).review(any(), any());
        verify(contracts, never()).find(any(), any());
        assertThat(databaseSnapshot()).isEqualTo(before);
    }

    @Test
    void syntheticInconsistentSnapshotAfterRealAReadReturnsSafe409WithoutWrites(CapturedOutput output) throws Exception {
        Version candidate = contracts.create(release(), policy(1), REVIEWER);
        Map<String, String> before = databaseSnapshot();
        clearInvocations(contracts, reviews);
        doAnswer(invocation -> {
            Version actual = (Version) invocation.callRealMethod();
            // Synthetic returned-snapshot fault only, after actual authorized A persistence reads.
            // Jackson rejects this integer through A.create; no overflowing version is persisted here.
            ObjectNode inconsistentPolicy = (ObjectNode) actual.policy().deepCopy();
            inconsistentPolicy.put("version", new BigInteger("4294967297"));
            return new Version(actual.id(), actual.workspaceId(), actual.releaseId(), actual.contractKey(),
                    actual.version(), actual.state(), inconsistentPolicy, actual.policyHash(), actual.resourceHash(),
                    actual.basePolicyHash(), actual.validation().deepCopy(), actual.review().deepCopy());
        }).when(contracts).find(eq(candidate.id()), any(ReviewerContext.class));

        HttpResponse<String> response = get(candidate.id());

        problem(response, 409, "CONTRACT_REVIEW_STORED_VERSION_INVALID");
        assertThat(response.body()).doesNotContain("4294967297", candidate.policyHash());
        assertThat(output.getAll()).doesNotContain(KEY, SESSION);
        verify(contracts).find(eq(candidate.id()), any(ReviewerContext.class));
        verify(contracts, never()).list(any(), any());
        assertThat(databaseSnapshot()).isEqualTo(before);
    }

    @Test
    void actualAIntegrityFailurePreservesCodeWithSafeDetailsAndNoWrites() throws Exception {
        Version candidate = contracts.create(release(), policy(1), REVIEWER);
        assertThat(jdbc.update("update safety_contract_versions set policy_hash=? where id=?",
                "sha256:" + "f".repeat(64), candidate.id())).isEqualTo(1);
        Map<String, String> before = databaseSnapshot();

        HttpResponse<String> response = get(candidate.id());

        JsonNode error = problem(response, 409, "EVIDENCE_INCOMPLETE");
        assertThat(error.path("detail").asString()).doesNotContain("Contract persistence integrity check failed");
        assertThat(response.body()).doesNotContain(candidate.policyHash(), KEY, SESSION);
        assertThat(databaseSnapshot()).isEqualTo(before);
    }

    @Test
    void actualTransactionalSqlFailureReturnsSafe503WithoutLeakingItsCause(CapturedOutput output) throws Exception {
        Version candidate = contracts.create(release(), policy(1), REVIEWER);
        Map<String, String> before = databaseSnapshot();
        doAnswer(invocation -> {
            invocation.callRealMethod();
            // The live C/A transaction is aborted by PostgreSQL, not by a mocked processing exception.
            return jdbc.queryForObject("select cast(? as integer)", Integer.class, SQL_CANARY);
        }).when(contracts).find(eq(candidate.id()), any(ReviewerContext.class));

        HttpResponse<String> response = get(candidate.id());

        problem(response, 503, "CONTRACT_REVIEW_UNAVAILABLE");
        assertThat(response.body()).doesNotContain(SQL_CANARY, "PSQLException", "BadSqlGrammar", KEY, SESSION);
        assertThat(output.getAll()).doesNotContain(SQL_CANARY, "PSQLException", KEY, SESSION);
        assertThat(databaseSnapshot()).isEqualTo(before);
    }

    @Test
    void genericTransactionBoundaryFailureAlsoReturnsSafe503(CapturedOutput output) throws Exception {
        Version candidate = contracts.create(release(), policy(1), REVIEWER);
        Map<String, String> before = databaseSnapshot();
        // Explicit boundary injection for infrastructure failures outside the service's own catch block.
        // The separate SQL test proves actual PostgreSQL/proxy failure behavior.
        doThrow(new CannotCreateTransactionException(TRANSACTION_CANARY,
                new IllegalStateException(TRANSACTION_CANARY)))
                .when(reviews).review(eq(candidate.id()), any(ReviewerContext.class));

        HttpResponse<String> response = get(candidate.id());

        problem(response, 503, "CONTRACT_REVIEW_UNAVAILABLE");
        assertThat(response.body()).doesNotContain(TRANSACTION_CANARY, "CannotCreateTransactionException", KEY, SESSION);
        assertThat(output.getAll()).doesNotContain(TRANSACTION_CANARY, "CannotCreateTransactionException", KEY, SESSION);
        assertThat(databaseSnapshot()).isEqualTo(before);
    }

    @Test
    void staleGetResourceHashCannotApproveAfterValidationAndOnlyPostIdempotencyEvidenceIsAdded() throws Exception {
        UUID releaseId = release();
        suppliedRemediation(releaseId);
        Version candidate = contracts.create(releaseId, policy(1), REVIEWER);
        HttpResponse<String> initial = get(candidate.id());
        JsonNode initialData = success(initial, candidate);
        String oldTag = '"' + initialData.path("resourceHash").asString() + '"';
        Version validated = contracts.validate(candidate.id(), oldTag, REVIEWER);
        assertThat(validated.state()).isEqualTo("VALIDATED");
        assertThat(etag(validated)).isNotEqualTo(oldTag);
        success(get(candidate.id()), validated);
        Map<String, String> before = databaseSnapshot();
        int reservations = count("api_idempotency_records");
        String idempotencyKey = UUID.randomUUID().toString();

        HttpResponse<String> response = post(PREFIX + "/" + candidate.id() + ":approve",
                mapper.createObjectNode().put("comment", COMMENT).toString(), oldTag, idempotencyKey);

        assertThat(response.statusCode()).isEqualTo(409);
        assertThat(mapper.readTree(response.body()).path("code").asString()).isEqualTo("RESOURCE_CONFLICT");
        Map<String, String> after = databaseSnapshot();
        before.remove("api_idempotency_records");
        after.remove("api_idempotency_records");
        assertThat(after).isEqualTo(before);
        assertThat(count("api_idempotency_records")).isEqualTo(reservations + 1);
        assertThat(jdbc.queryForObject("select state from api_idempotency_records where idempotency_key=?",
                String.class, idempotencyKey)).isEqualTo("COMPLETED");
        assertThat(jdbc.queryForObject("select response_status from api_idempotency_records where idempotency_key=?",
                Integer.class, idempotencyKey)).isEqualTo(409);
        assertThat(jdbc.queryForObject("select actor_id from api_idempotency_records where idempotency_key=?",
                String.class, idempotencyKey)).isEqualTo(ACTOR);
        assertThat(contracts.find(candidate.id(), REVIEWER)).isEqualTo(validated);
        assertThat(releases.find(releaseId).safetyContractHash()).isNull();
    }

    private HttpResponse<String> get(UUID versionId) throws Exception {
        return get(path(versionId), credentials());
    }

    private HttpResponse<String> get(String path, Map<String, String> headers) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri(path)).timeout(Duration.ofSeconds(10)).GET();
        headers.forEach(request::header);
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> post(String path, String body, String match, String idempotency) throws Exception {
        return client.send(HttpRequest.newBuilder(uri(path)).timeout(Duration.ofSeconds(10))
                .header("X-Contract-Reviewer-Key", KEY).header("Content-Type", "application/json")
                .header("If-Match", match).header("Idempotency-Key", idempotency)
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private URI uri(String path) { return URI.create("http://localhost:" + port + path); }
    private String path(UUID id) { return PREFIX + "/" + id + "/review"; }
    private Map<String, String> credentials() { return Map.of("X-Contract-Reviewer-Key", KEY); }
    private String etag(Version version) { return '"' + version.resourceHash() + '"'; }

    private JsonNode success(HttpResponse<String> response, Version expected) {
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("Cache-Control")).contains("no-store");
        assertThat(response.headers().firstValue("ETag")).isEmpty();
        assertThat(response.headers().firstValue("Content-Type")).hasValueSatisfying(
                type -> assertThat(type).startsWith("application/json"));
        JsonNode envelope = mapper.readTree(response.body());
        assertThat(envelope.path("traceId").asString())
                .isEqualTo(response.headers().firstValue("X-Trace-Id").orElseThrow());
        assertThat(envelope.path("timestamp").isString()).isTrue();
        JsonNode data = envelope.path("data");
        assertThat(data.path("policyHash").asString()).isEqualTo(expected.policyHash());
        assertThat(data.path("resourceHash").asString()).isEqualTo(expected.resourceHash());
        assertThat(data.path("storedPolicyJson").isString()).isTrue();
        assertThat(data.path("storedPolicyJson").asString()).isEqualTo(storedPolicyText(expected.id()));
        assertThat(data.path("canonicalPolicyJson").isString()).isTrue();
        assertThat(data.path("canonicalPolicyJson").asString())
                .isEqualTo(canonicalizer.canonicalizeAndHash(expected.policy()).canonicalJson());
        return data;
    }

    private JsonNode problem(HttpResponse<String> response, int status, String code) {
        assertThat(response.statusCode()).isEqualTo(status);
        assertThat(response.headers().firstValue("Cache-Control")).contains("no-store");
        assertThat(response.headers().firstValue("ETag")).isEmpty();
        assertThat(response.headers().firstValue("Content-Type")).hasValueSatisfying(
                type -> assertThat(type).startsWith("application/problem+json"));
        JsonNode error = mapper.readTree(response.body());
        assertThat(error.path("status").asInt()).isEqualTo(status);
        assertThat(error.path("code").asString()).isEqualTo(code);
        assertThat(error.path("instance").asString()).isEqualTo(PREFIX);
        assertThat(error.path("traceId").asString())
                .isEqualTo(response.headers().firstValue("X-Trace-Id").orElseThrow());
        assertThat(error.has("data")).isFalse();
        return error;
    }

    private void assertIdentity(JsonNode identity, Version version) {
        assertThat(fields(identity)).containsExactlyInAnyOrder("versionId", "workspaceId", "releaseId", "contractKey", "version");
        assertThat(identity.path("versionId").asString()).isEqualTo(version.id().toString());
        assertThat(identity.path("workspaceId").asString()).isEqualTo(version.workspaceId().toString());
        assertThat(identity.path("releaseId").asString()).isEqualTo(version.releaseId().toString());
        assertThat(identity.path("contractKey").asString()).isEqualTo(version.contractKey());
        assertThat(identity.path("version").isIntegralNumber()).isTrue();
        assertThat(identity.path("version").asInt()).isEqualTo(version.version());
    }

    private Set<String> fields(JsonNode node) {
        return node.properties().stream().map(Map.Entry::getKey).collect(Collectors.toSet());
    }

    private JsonNode change(JsonNode data, String pointer) {
        for (JsonNode change : data.path("changes")) {
            if (pointer.equals(change.path("pointer").asString())) return change;
        }
        throw new AssertionError("Expected review change at " + pointer);
    }

    private UUID release() throws Exception {
        String key = "review-http-" + UUID.randomUUID();
        var agent = agents.create(new AgentDto.CreateRequest(key, "Review HTTP test", "Document review"));
        return release(agent.id(), key);
    }

    private UUID release(UUID agentId, String agentKey) throws Exception {
        ObjectNode manifest = (ObjectNode) fixture("valid-release-manifest-v1.1.json");
        ((ObjectNode) manifest.get("agent")).put("id", agentKey);
        UUID releaseId = releases.create(agentId, manifest, ACTOR).id();
        releases.analyze(releaseId, ACTOR);
        return releaseId;
    }

    private Version approve(UUID releaseId, ObjectNode policy) {
        suppliedRemediation(releaseId);
        Version candidate = contracts.create(releaseId, policy, REVIEWER);
        Version validated = contracts.validate(candidate.id(), etag(candidate), REVIEWER);
        return contracts.approve(candidate.id(), etag(validated), COMMENT, REVIEWER);
    }

    private void suppliedRemediation(UUID releaseId) {
        // Supplied lifecycle fixture only; this does not represent completed B attacks or a D decision.
        assertThat(jdbc.update("update agent_releases set lifecycle_state='REMEDIATION', "
                + "effective_status='REMEDIATION' where id=?", releaseId)).isEqualTo(1);
    }

    private ObjectNode policy(int version) throws Exception {
        return ((ObjectNode) fixture("loan-review-safety-contract.json")).put("version", version);
    }

    private JsonNode fixture(String name) throws Exception {
        try (var input = getClass().getResourceAsStream("/fixtures/" + name)) { return mapper.readTree(input); }
    }

    private static ReviewerContext reviewer(UUID workspace) {
        return new ReviewerContext(workspace, ACTOR, "AI_SECURITY_REVIEWER", SESSION, true, true, false);
    }

    private String storedPolicyText(UUID versionId) {
        return jdbc.queryForObject("select policy_json::text from safety_contract_versions where id=?",
                (row, index) -> mapper.writeValueAsString(mapper.readTree(row.getString(1))), versionId);
    }

    private Map<String, String> databaseSnapshot() {
        Map<String, String> result = new LinkedHashMap<>();
        for (String table : SNAPSHOT_TABLES) {
            result.put(table, jdbc.queryForObject("select coalesce(jsonb_agg(to_jsonb(t) "
                    + "order by to_jsonb(t)::text)::text, '[]') from " + table + " t", String.class));
        }
        return result;
    }

    private int count(String table) {
        // Call sites supply fixed test table names.
        return jdbc.queryForObject("select count(*) from " + table, Integer.class);
    }

    private void verifyNoAuthorityCalls() {
        verify(contracts, never()).create(any(), any(), any());
        verify(contracts, never()).validate(any(), any(), any());
        verify(contracts, never()).approve(any(), any(), any(), any());
        verify(contracts, never()).reject(any(), any(), any(), any());
        verify(contracts, never()).approved(any(), any(), any());
    }

    private static Stream<Arguments> deniedCredentials() {
        return Stream.of(
                Arguments.of("missing key", Map.of()),
                Arguments.of("wrong key", Map.of("X-Contract-Reviewer-Key", "HTTP-WRONG-KEY-CANARY")),
                Arguments.of("cookie with valid key", Map.of("X-Contract-Reviewer-Key", KEY, "Cookie", "session=HTTP-COOKIE-CANARY")),
                Arguments.of("forged actor with valid key", Map.of("X-Contract-Reviewer-Key", KEY, "X-Actor-Id", "HTTP-FORGED-ACTOR-CANARY")));
    }
}
