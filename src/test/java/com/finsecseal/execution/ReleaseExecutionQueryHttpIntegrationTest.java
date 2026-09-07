package com.finsecseal.execution;

import static org.assertj.core.api.Assertions.assertThat;

import com.finsecseal.agent.AgentService;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
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
class ReleaseExecutionQueryHttpIntegrationTest {

    private static final String HASH_A = "sha256:" + "a".repeat(64);
    private static final String HASH_B = "sha256:" + "b".repeat(64);
    private static final String HASH_C = "sha256:" + "c".repeat(64);

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired
    JdbcTemplate jdbcTemplate;

    @Autowired
    ObjectMapper objectMapper;

    @LocalServerPort
    int port;

    @Test
    void listsReadySuitesRunsAndReplayComparisonsForARelease() throws Exception {
        Seed seed = seedExecutionEvidence();
        HttpClient client = HttpClient.newHttpClient();

        HttpResponse<String> suites = client.send(request(
                "/api/v1/releases/" + seed.releaseId() + "/test-suites?status=READY&limit=10"
        ), HttpResponse.BodyHandlers.ofString());
        assertThat(suites.statusCode()).isEqualTo(200);
        JsonNode suitesJson = objectMapper.readTree(suites.body());
        assertThat(suitesJson.path("data").path("items")).hasSize(1);
        assertThat(suitesJson.at("/data/items/0/id").asString()).isEqualTo(seed.suiteId().toString());
        assertThat(suitesJson.at("/data/items/0/status").asString()).isEqualTo("READY");
        assertThat(suitesJson.at("/data/items/0/caseCount").asInt()).isEqualTo(1);

        HttpResponse<String> runs = client.send(request(
                "/api/v1/releases/" + seed.releaseId() + "/test-runs?mode=BASELINE&status=QUEUED&limit=10"
        ), HttpResponse.BodyHandlers.ofString());
        assertThat(runs.statusCode()).isEqualTo(200);
        JsonNode runsJson = objectMapper.readTree(runs.body());
        assertThat(runsJson.path("data").path("items")).hasSize(1);
        assertThat(runsJson.at("/data/items/0/id").asString()).isEqualTo(seed.runId().toString());
        assertThat(runsJson.at("/data/items/0/mode").asString()).isEqualTo("BASELINE");
        assertThat(runsJson.at("/data/items/0/status").asString()).isEqualTo("QUEUED");
        assertThat(runsJson.at("/data/items/0/latestSequence").asInt()).isEqualTo(0);

        HttpResponse<String> replayComparisons = client.send(request(
                "/api/v1/releases/" + seed.releaseId() + "/replay-comparisons?limit=10"
        ), HttpResponse.BodyHandlers.ofString());
        assertThat(replayComparisons.statusCode()).isEqualTo(200);
        JsonNode replayJson = objectMapper.readTree(replayComparisons.body());
        assertThat(replayJson.path("data").path("items")).isEmpty();
    }

    private HttpRequest request(String path) {
        return HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .header("X-Actor-Id", "role-b-console")
                .GET()
                .build();
    }

    private Seed seedExecutionEvidence() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        UUID agentId = UUID.randomUUID();
        UUID releaseId = UUID.randomUUID();
        jdbcTemplate.update("""
                insert into agents
                    (id, workspace_id, agent_key, name, purpose_summary, status)
                values (?, ?, ?, 'Execution Query Agent', 'Role B query integration test', 'ACTIVE')
                """, agentId, AgentService.DEMO_WORKSPACE_ID, "execution-query-" + suffix);
        jdbcTemplate.update("""
                insert into agent_releases
                    (id, agent_id, version, business_purpose, manifest_schema_version, manifest_json,
                     agent_artifact_fingerprint, release_fingerprint, lifecycle_state, effective_status,
                     revalidation_reason_json, created_at, updated_at)
                values (?, ?, '1.0.0', 'LOAN_DOCUMENT_COMPLETENESS_REVIEW', '1.0', '{}'::jsonb,
                        ?, ?, 'ANALYZED', 'ANALYZED', '{}'::jsonb, ?, ?)
                """, releaseId, agentId, HASH_A, HASH_B,
                Timestamp.from(Instant.now().minusSeconds(5)), Timestamp.from(Instant.now().minusSeconds(5)));

        UUID suiteId = UUID.randomUUID();
        UUID caseId = UUID.randomUUID();
        UUID runId = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);

        jdbcTemplate.update("""
                insert into test_suites
                    (id, workspace_id, suite_key, version, fixture_version, generation_config_json,
                     suite_hash, status, created_at, updated_at)
                                values (?, ?, ?, '1.0.0', 'fixture-v1', '{}'::jsonb, ?, 'BUILDING', ?, ?)
                """, suiteId, AgentService.DEMO_WORKSPACE_ID, "execution-suite-" + suffix,
                HASH_A, Timestamp.from(now.minusSeconds(3)), Timestamp.from(now.minusSeconds(3)));
        jdbcTemplate.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name, category, severity,
                     delivery_channel, target_tool, attack_goal, payload_hash, preconditions_json,
                     expected_invariant, oracle_type, generation_source, expected_result_json,
                     trial_policy_json, created_at, updated_at)
                values (?, ?, ?, 'ATTACK', 'SEED', 'FA-03', 'HIGH', 'DIRECT', 'CUSTOMER_DATA_READ',
                        'sensitive field lookup', ?, '{}'::jsonb, 'INV-03', 'SENSITIVE_FIELD',
                        'CURATED', '{}'::jsonb, '{}'::jsonb, ?, ?)
                """, caseId, suiteId, "FA-03-" + suffix, HASH_A,
                Timestamp.from(now.minusSeconds(3)), Timestamp.from(now.minusSeconds(3)));
        jdbcTemplate.update("update test_suites set status = 'READY', updated_at = ? where id = ?",
                Timestamp.from(now.minusSeconds(2)), suiteId);

        jdbcTemplate.update("""
                insert into test_runs
                    (id, release_id, suite_id, mode, status, baseline_pair_group_id,
                     agent_artifact_fingerprint, release_fingerprint, config_json, fixture_version,
                     fixture_digest, model_config_hash, random_seed, total_cases, completed_cases,
                     operational_error_count, started_at, completed_at, summary_json, created_at, updated_at)
                                values (?, ?, ?, 'BASELINE', 'QUEUED', ?, ?, ?, '{}'::jsonb, 'fixture-v1', ?, ?, ?, 1, 0, 0, null, null, '{}'::jsonb, ?, ?)
                """, runId, releaseId, suiteId, UUID.randomUUID(), HASH_A,
                HASH_B, HASH_A, HASH_B, 42L, Timestamp.from(now.minusSeconds(1)), Timestamp.from(now.minusSeconds(1)));

        return new Seed(releaseId, suiteId, runId);
    }

    private record Seed(UUID releaseId, UUID suiteId, UUID runId) {
    }
}