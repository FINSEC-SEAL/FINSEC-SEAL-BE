package com.finsecseal.contract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;

import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.common.domain.ReleaseLifecycleState;
import com.finsecseal.contract.SafetyContractGenerationSourceService.FailureCode;
import com.finsecseal.contract.SafetyContractGenerationSourceService.GenerationSourceException;
import com.finsecseal.contract.SafetyContractGenerationSourceService.PreparedGenerationSource;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationStatus;
import com.finsecseal.release.ReleaseDto;
import com.finsecseal.release.ReleaseIntegrityVerifier;
import com.finsecseal.release.ReleaseService;
import java.sql.Connection;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

@Testcontainers
@SpringBootTest
@ExtendWith(OutputCaptureExtension.class)
class SafetyContractGenerationSourceServiceIntegrationTest {
    private static final String ACTOR = "c-generation-source-integration";
    private static final String SECRET = "GENERATION-PROMPT-SECRET-CANARY";
    private static final List<String> DOMAIN_TABLES = List.of(
            "agent_releases", "release_artifacts", "safety_contracts", "safety_contract_versions",
            "patch_proposals", "patch_approvals", "test_runs", "test_case_runs", "execution_events",
            "findings", "oracle_results", "replay_links", "release_decisions", "evidence_references");

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired SafetyContractGenerationSourceService sources;
    @Autowired SafetyContractSemanticValidator validator;
    @Autowired SafetyContractCanonicalizer canonicalizer;
    @Autowired AgentService agents;
    @MockitoSpyBean ReleaseService releases;
    @MockitoSpyBean ReleaseIntegrityVerifier integrity;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate jdbc;
    @Autowired DataSource dataSource;

    // Deliberately no test-managed transaction: the actual C service must retain A's lock itself.
    @Test
    void actualAnalyzedSourcePreservesAllPolicyInputsWithoutLifecycleOrSecretLeak(CapturedOutput output)
            throws Exception {
        var release = release("valid-release-manifest-v1.1.json", true);
        JsonNode stored = jdbc.queryForObject("select manifest_json::text from agent_releases where id = ?",
                (row, index) -> mapper.readTree(row.getString(1)), release.id());
        Map<String, String> before = domainSnapshot();
        int auditBefore = auditCount(release.id());

        PreparedGenerationSource prepared = prepare(release.id());

        assertThat(prepared.catalog().releaseId()).isEqualTo(release.id());
        assertThat(prepared.catalog().agentArtifactFingerprint()).isEqualTo(release.agentArtifactFingerprint());
        assertThat(prepared.catalog().releaseFingerprint()).isEqualTo(release.releaseFingerprint());
        assertThat(prepared.lifecycleState()).isEqualTo(ReleaseLifecycleState.ANALYZED);
        assertThat(prepared.analyzedAt()).isEqualTo(release.analyzedAt());
        for (String field : List.of("businessPurpose", "businessWorkflow", "humanApprovalBoundaries",
                "runtimeContextRequirements", "networkRequirements", "tools", "serverToolCatalog")) {
            assertThat(prepared.manifestContext().path(field)).isEqualTo(stored.path(field));
        }
        assertThat(prepared.manifestContext().at("/businessPurpose/description").asString())
                .contains("현재 Case");
        assertThat(prepared.manifestContext().path("tools").size()).isEqualTo(5);
        assertThat(prepared.manifestContext().at("/serverToolCatalog/tools/0/inputSchema").isObject()).isTrue();
        assertThat(prepared.manifestContext().toString()).doesNotContain("systemPrompt", SECRET, "[ENCRYPTED]");
        assertThat(prepared.toString()).doesNotContain(SECRET);
        assertThat(output.getAll()).doesNotContain(SECRET);

        ObjectNode candidate = (ObjectNode) prepared.templateRules();
        candidate.put("contractId", "integration-test-only").put("version", 1);
        assertThat(validator.validate(candidate, prepared.catalog().semanticCatalog()).status())
                .isEqualTo(ValidationStatus.VALID);
        assertThat(canonicalizer.canonicalizeAndHash(candidate).policyHash()).matches("sha256:[0-9a-f]{64}");
        assertThat(prepared.templateRules().has("contractId")).isFalse();
        assertThat(domainSnapshot()).isEqualTo(before);
        assertAudit(release.id(), auditBefore + 1);
    }

    @Test
    void returnedContainersCannotChangePreparedInputsOrPersistedData() throws Exception {
        var release = release("valid-release-manifest-v1.1.json", true);
        var prepared = prepare(release.id());
        JsonNode expected = prepared.manifestContext();
        Map<String, String> before = domainSnapshot();
        ((ArrayNode) prepared.manifestContext().path("tools")).removeAll();
        ((ObjectNode) prepared.manifestContext().path("businessPurpose")).put("code", "FORGED");
        ((ObjectNode) prepared.templateRules().path("externalEgress")).put("allowed", true);

        assertThat(prepared.manifestContext()).isEqualTo(expected);
        assertThat(prepared.templateRules().at("/externalEgress/allowed").asBoolean()).isFalse();
        assertThat(domainSnapshot()).isEqualTo(before);
        assertThat(prepare(release.id()).manifestContext()).isEqualTo(expected);
    }

    @Test
    void draftRejectionRollsBackDomainWorkAndPreservesTheRealAccessAudit(CapturedOutput output)
            throws Exception {
        var release = release("valid-release-manifest-v1.1.json", false);
        Map<String, String> before = domainSnapshot();
        int audits = auditCount(release.id());

        expectFailure(release.id(), FailureCode.RELEASE_NOT_ANALYZED);

        assertThat(domainSnapshot()).isEqualTo(before);
        assertAudit(release.id(), audits + 1);
        assertThat(output.getAll()).doesNotContain(SECRET);
    }

    @Test
    void legacyCatalogFailsBeforeAnyGenerationSnapshotIsReturned() throws Exception {
        var release = release("valid-release-manifest.json", true);
        Map<String, String> before = domainSnapshot();
        int audits = auditCount(release.id());

        expectFailure(release.id(), FailureCode.SOURCE_UNAVAILABLE);

        assertThat(domainSnapshot()).isEqualTo(before);
        // A rejects unsupported Manifest version before decrypting or auditing a catalog read.
        assertThat(auditCount(release.id())).isEqualTo(audits);
    }

    @ParameterizedTest
    @ValueSource(strings = {"business-purpose", "business-workflow", "human-boundaries",
            "runtime-context", "server-tool-catalog", "CUSTOMER_DATA_READ", "release-fingerprint"})
    void corruptedAnalyzedLookingFixtureReachesTheActualVerifierAndFailsClosed(String corrupted,
            CapturedOutput output) throws Exception {
        var release = release("valid-release-manifest-v1.1.json", false);
        // Prepare an adversarial stored snapshot while DRAFT permits test fixture mutation.
        // Production guards stay enabled. The analysis-looking state makes this an integrity test,
        // rather than an early RELEASE_NOT_ANALYZED rejection or a failed UPDATE assertion.
        if (corrupted.equals("release-fingerprint")) {
            assertThat(jdbc.update("update agent_releases set release_fingerprint = ? where id = ?",
                    "sha256:" + "f".repeat(64), release.id())).isEqualTo(1);
        } else {
            assertThat(jdbc.update("update release_artifacts set sha256 = ? where release_id = ? and name = ?",
                    "sha256:" + "f".repeat(64), release.id(), corrupted)).isGreaterThan(0);
        }
        assertThat(jdbc.update("update agent_releases set lifecycle_state = 'ANALYZED', "
                + "effective_status = 'ANALYZED', analyzed_at = now() where id = ?", release.id())).isEqualTo(1);
        assertThat(releases.find(release.id()).analyzedAt()).isNotNull();
        clearInvocations(integrity);
        int audits = auditCount(release.id());
        Map<String, String> before = domainSnapshot();

        expectFailure(release.id(), FailureCode.SOURCE_UNAVAILABLE);

        verify(integrity).verify(any(UUID.class), eq(release.id()), any(JsonNode.class));
        assertThat(domainSnapshot()).isEqualTo(before);
        assertAudit(release.id(), audits + 1);
        assertThat(output.getAll()).doesNotContain(SECRET);
    }

    @Test
    void verifiedReaderRetainsReleaseLockUntilItsProjectionIsComplete() throws Exception {
        var release = release("valid-release-manifest-v1.1.json", true);
        CountDownLatch afterVerification = new CountDownLatch(1);
        CountDownLatch finishProjection = new CountDownLatch(1);
        doAnswer(invocation -> {
            afterVerification.countDown();
            if (!finishProjection.await(8, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Test synchronization timed out");
            }
            return invocation.callRealMethod();
        }).when(releases).getRequired(release.id());

        try (var executor = Executors.newFixedThreadPool(2)) {
            var reader = executor.submit(() -> prepare(release.id()));
            try {
                assertThat(afterVerification.await(8, TimeUnit.SECONDS)).isTrue();
                var writer = executor.submit(() -> jdbc.update("update agent_releases set "
                        + "lifecycle_state = 'TESTING', effective_status = 'TESTING' where id = ?", release.id()));
                await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(jdbc.queryForObject(
                        "select count(*) from pg_stat_activity where wait_event_type = 'Lock' "
                                + "and query like 'update agent_releases set %'", Integer.class)).isGreaterThan(0));
                assertThat(writer.isDone()).isFalse();
                finishProjection.countDown();

                PreparedGenerationSource result = reader.get(8, TimeUnit.SECONDS);
                assertThat(writer.get(8, TimeUnit.SECONDS)).isEqualTo(1);
                assertThat(result.lifecycleState()).isEqualTo(ReleaseLifecycleState.ANALYZED);
                assertThat(result.catalog().releaseFingerprint()).isEqualTo(release.releaseFingerprint());
                assertThat(jdbc.queryForObject("select lifecycle_state from agent_releases where id = ?",
                        String.class, release.id())).isEqualTo("TESTING");
            } finally {
                finishProjection.countDown();
            }
        }
    }

    @Test
    void writerCommittedBeforeVerificationIsObservedAsOneCompleteSnapshot() throws Exception {
        var release = release("valid-release-manifest-v1.1.json", true);
        // Resource close order releases the writer before waiting for the reader on any failure.
        try (var executor = Executors.newSingleThreadExecutor(); Connection writer = dataSource.getConnection()) {
            writer.setAutoCommit(false);
            int writerPid;
            try (var query = writer.createStatement(); var row = query.executeQuery("select pg_backend_pid()")) {
                assertThat(row.next()).isTrue();
                writerPid = row.getInt(1);
            }
            try (var update = writer.prepareStatement("update agent_releases set lifecycle_state = 'TESTING', "
                    + "effective_status = 'TESTING' where id = ?")) {
                update.setObject(1, release.id());
                assertThat(update.executeUpdate()).isEqualTo(1);
            }
            var reader = executor.submit(() -> prepare(release.id()));
            await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(jdbc.queryForObject(
                    "select count(*) from pg_stat_activity where ? = any(pg_blocking_pids(pid))",
                    Integer.class, writerPid)).isGreaterThan(0));
            assertThat(reader.isDone()).isFalse();
            writer.commit();

            PreparedGenerationSource result = reader.get(8, TimeUnit.SECONDS);
            assertThat(result.lifecycleState()).isEqualTo(ReleaseLifecycleState.TESTING);
            assertThat(result.analyzedAt()).isEqualTo(release.analyzedAt());
            assertThat(result.catalog().releaseFingerprint()).isEqualTo(release.releaseFingerprint());
            // A subsequent actual call proves the first call released its lock.
            assertThat(prepare(release.id()).manifestContext()).isEqualTo(result.manifestContext());
        }
    }

    private PreparedGenerationSource prepare(UUID id) {
        return sources.prepare(id, LoanReviewFinancialTemplate.KEY, ACTOR);
    }

    private void expectFailure(UUID id, FailureCode code) {
        assertThatThrownBy(() -> prepare(id)).isInstanceOfSatisfying(GenerationSourceException.class, error -> {
            assertThat(error.code()).isEqualTo(code);
            assertThat(error.getCause()).isNull();
            assertThat(error.getSuppressed()).isEmpty();
            assertThat(error.getMessage()).doesNotContain(SECRET, "systemPrompt");
        });
    }

    private ReleaseDto.Response release(String fixture, boolean analyze) throws Exception {
        String key = "generation-" + UUID.randomUUID().toString().replace("-", "");
        var agent = agents.create(new AgentDto.CreateRequest(key, "Generation source test", "Document review"));
        ObjectNode manifest;
        try (var input = getClass().getResourceAsStream("/fixtures/" + fixture)) {
            manifest = (ObjectNode) mapper.readTree(input);
        }
        ((ObjectNode) manifest.path("agent")).put("id", key);
        ((ObjectNode) manifest.path("systemPrompt")).put("text", SECRET);
        var result = releases.create(agent.id(), manifest, ACTOR);
        if (analyze) {
            releases.analyze(result.id(), ACTOR);
            // Compare the stored timestamp, whose precision is defined by PostgreSQL.
            return releases.find(result.id());
        }
        return result;
    }

    private Map<String, String> domainSnapshot() {
        Map<String, String> snapshot = new LinkedHashMap<>();
        for (String table : DOMAIN_TABLES) {
            snapshot.put(table, jdbc.queryForObject("select coalesce(jsonb_agg(to_jsonb(t) order by id)::text, '[]') "
                    + "from " + table + " t", String.class));
        }
        return snapshot;
    }

    private int auditCount(UUID id) {
        return jdbc.queryForObject("select count(*) from audit_records where resource_id = ? "
                + "and actor_id = ? and action = 'SYSTEM_PROMPT_DECRYPTED_INTERNAL'", Integer.class, id, ACTOR);
    }

    private void assertAudit(UUID id, int expected) {
        assertThat(auditCount(id)).isEqualTo(expected);
        JsonNode metadata = jdbc.queryForObject("select metadata_json::text from audit_records where resource_id = ? "
                + "and actor_id = ? and action = 'SYSTEM_PROMPT_DECRYPTED_INTERNAL' order by occurred_at desc limit 1",
                (row, index) -> mapper.readTree(row.getString(1)), id, ACTOR);
        assertThat(metadata.path("purpose").asString()).isEqualTo("TOOL_CATALOG_INTEGRITY_CHECK");
        assertThat(metadata.path("plaintextReturned").asBoolean()).isFalse();
        assertThat(metadata.toString()).doesNotContain(SECRET);
    }
}
