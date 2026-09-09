package com.finsecseal.assurance;

import static org.assertj.core.api.Assertions.assertThat;

import com.finsecseal.agent.AgentService;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TestRunResultHttpIntegrationTest {

    private static final String HASH_A = "sha256:" + "a".repeat(64);
    private static final String HASH_B = "sha256:" + "b".repeat(64);

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired JdbcTemplate jdbcTemplate;
    @Autowired ObjectMapper objectMapper;
    @LocalServerPort int port;

    @Test
    void returnsPagedCaseAndOracleSummariesWithoutHeldOutPayloads() throws Exception {
        Seed seed = seedResults();
        HttpClient client = HttpClient.newHttpClient();

        HttpResponse<String> firstResponse = client.send(request(
                "/api/v1/test-runs/" + seed.runId() + "/results?limit=1"
        ), HttpResponse.BodyHandlers.ofString());

        assertThat(firstResponse.statusCode()).isEqualTo(200);
        assertThat(firstResponse.body())
                .doesNotContain("TOP_SECRET_PAYLOAD_CANARY")
                .doesNotContain("HIDDEN_ATTACK_GOAL_CANARY")
                .doesNotContain("RAW_CASE_RESULT_CANARY")
                .doesNotContain("RAW_ORACLE_EVIDENCE_CANARY");
        JsonNode first = objectMapper.readTree(firstResponse.body()).path("data");
        assertThat(first.path("run").path("id").asString()).isEqualTo(seed.runId().toString());
        assertThat(first.path("summary").path("materializedTrials").asInt()).isEqualTo(2);
        assertThat(first.path("summary").path("attackSuccessTrials").asInt()).isEqualTo(1);
        assertThat(first.path("summary").path("normalSuccessTrials").asInt()).isEqualTo(1);
        assertThat(first.path("items")).hasSize(1);
        assertThat(first.at("/items/0/oracleResults")).hasSize(1);
        assertThat(first.at("/items/0/oracleResults/0/evidenceDigest").asString()).isEqualTo(HASH_A);
        assertThat(first.path("nextCursor").asString()).isNotBlank();

        String cursor = URLEncoder.encode(first.path("nextCursor").asString(), StandardCharsets.UTF_8);
        HttpResponse<String> secondResponse = client.send(request(
                "/api/v1/test-runs/" + seed.runId() + "/results?limit=1&cursor=" + cursor
        ), HttpResponse.BodyHandlers.ofString());
        JsonNode second = objectMapper.readTree(secondResponse.body()).path("data");

        assertThat(secondResponse.statusCode()).isEqualTo(200);
        assertThat(second.path("items")).hasSize(1);
        assertThat(second.path("nextCursor").isNull()).isTrue();
        assertThat(second.at("/items/0/caseRunId").asString())
                .isNotEqualTo(first.at("/items/0/caseRunId").asString());
    }

    @Test
    void filtersByOutcomeAndRejectsUnknownOutcome() throws Exception {
        Seed seed = seedResults();
        HttpClient client = HttpClient.newHttpClient();

        HttpResponse<String> filteredResponse = client.send(request(
                "/api/v1/test-runs/" + seed.runId() + "/results?outcome=ATTACK_SUCCESS"
        ), HttpResponse.BodyHandlers.ofString());
        JsonNode filtered = objectMapper.readTree(filteredResponse.body()).path("data");

        assertThat(filteredResponse.statusCode()).isEqualTo(200);
        assertThat(filtered.path("items")).hasSize(1);
        assertThat(filtered.at("/items/0/category").asString()).isEqualTo("FA-02");
        assertThat(filtered.path("summary").path("materializedTrials").asInt()).isEqualTo(2);

        HttpResponse<String> invalidResponse = client.send(request(
                "/api/v1/test-runs/" + seed.runId() + "/results?outcome=UNKNOWN"
        ), HttpResponse.BodyHandlers.ofString());

        assertThat(invalidResponse.statusCode()).isEqualTo(400);
    }

    @Test
    void returnsNotFoundForUnknownRun() throws Exception {
        HttpResponse<String> response = HttpClient.newHttpClient().send(request(
                "/api/v1/test-runs/" + UUID.randomUUID() + "/results"
        ), HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(404);
    }

    private HttpRequest request(String path) {
        return HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).GET().build();
    }

    private Seed seedResults() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        UUID agentId = UUID.randomUUID();
        UUID releaseId = UUID.randomUUID();
        UUID suiteId = UUID.randomUUID();
        UUID heldOutCaseId = UUID.randomUUID();
        UUID normalCaseId = UUID.randomUUID();
        UUID runId = UUID.randomUUID();
        UUID heldOutCaseRunId = UUID.randomUUID();
        UUID normalCaseRunId = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);

        jdbcTemplate.update("""
                insert into agents
                    (id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'Result Query Agent', 'D result query integration test', 'ACTIVE')
                """, agentId, AgentService.DEMO_WORKSPACE_ID, "result-query-" + suffix);
        jdbcTemplate.update("""
                insert into agent_releases
                    (id, agent_id, version, business_purpose, manifest_schema_version, manifest_json,
                     agent_artifact_fingerprint, release_fingerprint, lifecycle_state, effective_status)
                values (?, ?, '1.0.0', 'LOAN_DOCUMENT_COMPLETENESS_REVIEW', '1.0', '{}'::jsonb,
                        ?, ?, 'ANALYZED', 'ANALYZED')
                """, releaseId, agentId, HASH_A, HASH_B);
        jdbcTemplate.update("""
                insert into test_suites
                    (id, workspace_id, suite_key, version, fixture_version, generation_config_json,
                     suite_hash, status)
                values (?, ?, ?, '1.0.0', 'fixture-v1', '{}'::jsonb, ?, 'DRAFT')
                """, suiteId, AgentService.DEMO_WORKSPACE_ID, "result-suite-" + suffix, HASH_A);
        jdbcTemplate.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name, category, severity,
                     delivery_channel, target_tool, attack_goal, payload_encrypted, payload_hash,
                     preconditions_json, expected_invariant, oracle_type, generation_source,
                     hidden_from_patch_generator, expected_result_json, trial_policy_json)
                values (?, ?, ?, 'ATTACK', 'HELD_OUT', 'FA-02', 'CRITICAL', 'DOCUMENT',
                        'CUSTOMER_DATA_READ', 'HIDDEN_ATTACK_GOAL_CANARY', 'TOP_SECRET_PAYLOAD_CANARY', ?,
                        '{}'::jsonb, 'INV-01', 'CROSS_CUSTOMER', 'MUTATION', true, '{}'::jsonb, '{}'::jsonb)
                """, heldOutCaseId, suiteId, "HELD-OUT-" + suffix, HASH_A);
        jdbcTemplate.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name, category, severity,
                     delivery_channel, target_tool, payload_hash, preconditions_json,
                     expected_invariant, oracle_type, generation_source, expected_result_json, trial_policy_json)
                values (?, ?, ?, 'NORMAL', 'NORMAL', 'N-001', 'INFO', 'DIRECT',
                        'CUSTOMER_DATA_READ', ?, '{}'::jsonb, 'NORMAL-01', 'NORMAL_TASK',
                        'CURATED', '{}'::jsonb, '{}'::jsonb)
                """, normalCaseId, suiteId, "NORMAL-" + suffix, HASH_A);
        jdbcTemplate.update("update test_suites set status = 'READY' where id = ?", suiteId);
        jdbcTemplate.update("""
                insert into test_runs
                    (id, release_id, suite_id, mode, status, agent_artifact_fingerprint,
                     release_fingerprint, config_json, fixture_version, fixture_digest,
                     model_config_hash, total_cases)
                values (?, ?, ?, 'BASELINE', 'QUEUED', ?, ?, '{}'::jsonb,
                        'fixture-v1', ?, ?, 2)
                """, runId, releaseId, suiteId, HASH_A, HASH_B, HASH_A, HASH_B);
        jdbcTemplate.update("update test_runs set status = 'PREPARING' where id = ?", runId);
        jdbcTemplate.update("update test_runs set status = 'RUNNING', started_at = ? where id = ?",
                Timestamp.from(now.minusSeconds(2)), runId);
        jdbcTemplate.update("""
                insert into test_case_runs
                    (id, test_run_id, test_case_id, trial_index, status, security_outcome,
                     variant_hash, started_at, completed_at, latency_ms, result_json, created_at, updated_at)
                values (?, ?, ?, 0, 'FAILED_SECURITY', 'ATTACK_SUCCESS', ?, ?, ?, 12,
                        '{"raw":"RAW_CASE_RESULT_CANARY"}'::jsonb, ?, ?)
                """, heldOutCaseRunId, runId, heldOutCaseId, HASH_A,
                Timestamp.from(now.minusSeconds(2)), Timestamp.from(now.minusSeconds(1)),
                Timestamp.from(now.minusSeconds(2)), Timestamp.from(now.minusSeconds(1)));
        jdbcTemplate.update("""
                insert into test_case_runs
                    (id, test_run_id, test_case_id, trial_index, status, functional_outcome,
                     variant_hash, started_at, completed_at, latency_ms, result_json, created_at, updated_at)
                values (?, ?, ?, 0, 'PASSED', 'NORMAL_SUCCESS', ?, ?, ?, 8, '{}'::jsonb, ?, ?)
                """, normalCaseRunId, runId, normalCaseId, HASH_A,
                Timestamp.from(now.minusSeconds(2)), Timestamp.from(now),
                Timestamp.from(now.minusSeconds(1)), Timestamp.from(now));
        jdbcTemplate.update("""
                insert into oracle_results
                    (id, test_case_run_id, oracle_type, oracle_version, outcome, reason_code,
                     invariant_id, evidence_json, evidence_digest, evaluated_at, created_at, updated_at)
                values (?, ?, 'CROSS_CUSTOMER', '1.0', 'ATTACK_SUCCESS',
                        'UNAUTHORIZED_RECORD_RETURNED', 'INV-01',
                        '{"raw":"RAW_ORACLE_EVIDENCE_CANARY"}'::jsonb, ?, ?, ?, ?)
                """, UUID.randomUUID(), heldOutCaseRunId, HASH_A,
                Timestamp.from(now), Timestamp.from(now), Timestamp.from(now));
        jdbcTemplate.update("""
                insert into oracle_results
                    (id, test_case_run_id, oracle_type, oracle_version, outcome, reason_code,
                     invariant_id, evidence_json, evidence_digest, evaluated_at, created_at, updated_at)
                values (?, ?, 'NORMAL_TASK', '1.0', 'NORMAL_SUCCESS',
                        'NORMAL_EXPECTATION_MET', 'NORMAL-01', '{}'::jsonb, ?, ?, ?, ?)
                """, UUID.randomUUID(), normalCaseRunId, HASH_A,
                Timestamp.from(now), Timestamp.from(now), Timestamp.from(now));
        return new Seed(runId);
    }

    private record Seed(UUID runId) {
    }
}
