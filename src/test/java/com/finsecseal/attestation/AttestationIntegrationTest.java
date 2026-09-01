package com.finsecseal.attestation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.ReleaseDto;
import com.finsecseal.release.ReleaseService;
import java.io.IOException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

@Testcontainers
@SpringBootTest
class AttestationIntegrationTest {

    private static final String HASH_A = "sha256:" + "a".repeat(64);
    private static final String HASH_B = "sha256:" + "b".repeat(64);

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired
    AgentService agentService;

    @Autowired
    ReleaseService releaseService;

    @Autowired
    AttestationService attestationService;

    @Autowired
    JdbcTemplate jdbcTemplate;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    CanonicalJsonService canonicalJsonService;

    @Autowired
    DigestService digestService;

    @Test
    void createsOneDeterministicAttestationPreservesItAndMarksItStale() throws Exception {
        Seed seed = seedDecision("deterministic", false);
        assertSqlState("23514", () -> jdbcTemplate.update("""
                insert into release_attestations
                    (id, release_decision_id, format_version, document_json, document_hash,
                     html_content, generated_at, disclaimer_version)
                values (?, ?, '1.0', '{}'::jsonb, ?, 'not a valid report', ?, 'finsec-internal/v1')
                """, UUID.randomUUID(), seed.decisionId(), HASH_A,
                Timestamp.from(seed.confirmedAt())));

        AttestationDto.View first = attestationService.findOrCreate(seed.releaseId(), "governance-reviewer");
        AttestationDto.View second = attestationService.findOrCreate(seed.releaseId(), "governance-reviewer");

        assertThat(second.id()).isEqualTo(first.id());
        assertThat(second.documentHash()).isEqualTo(first.documentHash());
        assertThat(first.documentHash())
                .isEqualTo(digestService.sha256(canonicalJsonService.canonicalize(first.document())));
        assertThat(first.document().at("/decision/value").asString()).isEqualTo("BLOCKED");
        assertThat(first.document().at("/disclaimer/ko").asString())
                .isEqualTo(AttestationService.DISCLAIMER_KO);
        assertThat(first.document().at("/disclaimer/en").asString())
                .isEqualTo(AttestationService.DISCLAIMER_EN);
        assertThat(first.stale()).isFalse();
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from release_attestations where release_decision_id = ?",
                Integer.class,
                seed.decisionId()
        )).isEqualTo(1);
        assertThat(jdbcTemplate.queryForObject("""
                select count(*) from audit_records
                 where resource_type = 'RELEASE_ATTESTATION' and resource_id = ?
                """, Integer.class, first.id())).isEqualTo(1);

        AttestationDto.Export json = attestationService.export(seed.releaseId(), "json", "report-viewer");
        AttestationDto.Export html = attestationService.export(seed.releaseId(), "html", "report-viewer");
        assertThat(json.content()).isEqualTo(canonicalJsonService.canonicalize(first.document()));
        assertThat(new String(html.content(), java.nio.charset.StandardCharsets.UTF_8))
                .contains(AttestationService.DISCLAIMER_KO)
                .contains(AttestationService.DISCLAIMER_EN);

        assertSqlState("55000", () -> jdbcTemplate.update(
                "update release_attestations set document_hash = ? where id = ?",
                HASH_A,
                first.id()
        ));
        jdbcTemplate.update("""
                insert into decision_invalidations
                    (id, release_decision_id, reasons_json, invalidated_by, invalidated_at, created_at)
                values (?, ?, '{"reason":"MODEL_CHANGE"}'::jsonb, 'reviewer', now(), now())
                """, UUID.randomUUID(), seed.decisionId());

        AttestationDto.View stale = attestationService.findOrCreate(seed.releaseId(), "report-viewer");
        AttestationDto.Export staleHtml = attestationService.export(seed.releaseId(), "html", "report-viewer");
        assertThat(stale.stale()).isTrue();
        assertThat(stale.documentHash()).isEqualTo(first.documentHash());
        assertThat(stale.invalidation().path("reasons").path("reason").asString()).isEqualTo("MODEL_CHANGE");
        assertThat(new String(staleHtml.content(), java.nio.charset.StandardCharsets.UTF_8))
                .contains("STALE / NEEDS_REVALIDATION")
                .contains(AttestationService.DISCLAIMER_KO);
    }

    @Test
    void rejectsDecisionSnapshotWhoseDigestDoesNotMatch() throws Exception {
        Seed seed = seedDecision("bad-digest", true);

        assertThatThrownBy(() -> attestationService.findOrCreate(seed.releaseId(), "governance-reviewer"))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE));
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from release_attestations where release_decision_id = ?",
                Integer.class,
                seed.decisionId()
        )).isZero();
    }

    @Test
    void createsHistoricalAttestationAfterDecisionWasInvalidatedAndReleaseChanged() throws Exception {
        Seed seed = seedDecision("historical", false);
        String decisionFingerprint = jdbcTemplate.queryForObject(
                "select release_fingerprint from agent_releases where id = ?",
                String.class,
                seed.releaseId()
        );
        invalidateAndChangeContract(seed);

        AttestationDto.View attestation = attestationService.findOrCreate(
                seed.releaseId(),
                "governance-reviewer"
        );

        assertThat(attestation.stale()).isTrue();
        assertThat(attestation.document().at("/release/fingerprint").asString())
                .isEqualTo(decisionFingerprint)
                .isNotEqualTo(HASH_B);
        assertThat(jdbcTemplate.queryForObject(
                "select release_fingerprint from agent_releases where id = ?",
                String.class,
                seed.releaseId()
        )).isEqualTo(HASH_B);
    }

    private Seed seedDecision(String suffix, boolean badDigest) throws IOException {
        String agentKey = "attestation-" + suffix + "-" + UUID.randomUUID().toString().substring(0, 8);
        AgentDto.Response agent = agentService.create(new AgentDto.CreateRequest(
                agentKey,
                "Attestation Agent",
                "Internal attestation projection test"
        ));
        ObjectNode manifest = (ObjectNode) objectMapper.readTree(
                getClass().getResourceAsStream("/fixtures/valid-release-manifest.json")
        );
        ((ObjectNode) manifest.path("agent")).put("id", agentKey);
        ReleaseDto.Response release = releaseService.create(agent.id(), manifest, "attestation-test");
        releaseService.analyze(release.id(), "attestation-test");
        ReleaseDto.FingerprintResponse fingerprints = releaseService.fingerprint(
                release.id(),
                "attestation-test"
        );
        jdbcTemplate.update("""
                update agent_releases
                   set lifecycle_state = 'BLOCKED', effective_status = 'BLOCKED'
                 where id = ?
                """, release.id());

        UUID decisionId = UUID.randomUUID();
        Instant confirmedAt = Instant.now().truncatedTo(ChronoUnit.MICROS);
        ObjectNode snapshot = decisionSnapshot(agent, release, manifest, fingerprints, confirmedAt);
        String inputDigest = badDigest
                ? HASH_A
                : digestService.sha256(canonicalJsonService.canonicalize(snapshot));
        jdbcTemplate.update("""
                insert into release_decisions
                    (id, release_id, decision, gate_policy_version, input_snapshot_json, input_digest,
                     proposed_at, confirmed_by, confirmed_at)
                values (?, ?, 'BLOCKED', 'mvp-gate/1', ?::jsonb, ?, ?, 'governance-reviewer', ?)
                """,
                decisionId,
                release.id(),
                json(snapshot),
                inputDigest,
                Timestamp.from(confirmedAt.minusSeconds(1)),
                Timestamp.from(confirmedAt)
        );
        return new Seed(release.id(), decisionId, confirmedAt);
    }

    private ObjectNode decisionSnapshot(
            AgentDto.Response agent,
            ReleaseDto.Response release,
            JsonNode manifest,
            ReleaseDto.FingerprintResponse fingerprints,
            Instant testedAt
    ) {
        ObjectNode snapshot = objectMapper.createObjectNode();
        snapshot.put("schemaVersion", "1.0");
        snapshot.set("agent", objectMapper.createObjectNode()
                .put("id", agent.id().toString())
                .put("name", agent.name()));
        snapshot.set("release", objectMapper.createObjectNode()
                .put("id", release.id().toString())
                .put("version", release.version())
                .put("fingerprint", release.releaseFingerprint())
                .put("agentArtifactFingerprint", release.agentArtifactFingerprint()));
        snapshot.set("model", objectMapper.createObjectNode()
                .put("provider", manifest.at("/model/provider").asString())
                .put("name", manifest.at("/model/name").asString())
                .put("resolvedName", manifest.at("/model/name").asString())
                .put("parametersHash", fingerprints.components().get("modelHash")));
        snapshot.put("systemPromptFingerprint", fingerprints.components().get("systemPromptHash"));
        snapshot.put("toolSetFingerprint", fingerprints.components().get("toolSetHash"));
        ArrayNode toolSchemas = snapshot.putArray("toolSchemaFingerprints");
        jdbcTemplate.query("""
                select definition.tool_key, definition.schema_hash, definition.description_hash
                  from release_tools link
                  join tool_definitions definition on definition.id = link.tool_definition_id
                 where link.release_id = ? order by link.ordinal
                """, resultSet -> {
                    while (resultSet.next()) {
                        toolSchemas.add(objectMapper.createObjectNode()
                                .put("toolName", resultSet.getString("tool_key"))
                                .put("schemaHash", resultSet.getString("schema_hash"))
                                .put("descriptionHash", resultSet.getString("description_hash")));
                    }
                    return null;
                }, release.id());
        snapshot.put("ragConfigurationFingerprint", fingerprints.components().get("ragConfigHash"));
        snapshot.set("safetyContract", objectMapper.createObjectNode()
                .put("status", "N_A")
                .putNull("versionId")
                .putNull("version")
                .putNull("hash"));
        snapshot.set("testSuite", objectMapper.createObjectNode()
                .put("id", UUID.randomUUID().toString())
                .put("version", "1.0.0")
                .put("hash", HASH_A));
        snapshot.set("sandbox", objectMapper.createObjectNode()
                .put("fixtureVersion", "fixture-v1")
                .put("fixtureDigest", HASH_A));
        ObjectNode results = snapshot.putObject("results");
        for (String field : new String[]{"baseline", "sealReplay", "heldOut", "normalRegression"}) {
            ObjectNode result = objectMapper.createObjectNode()
                    .put("status", "N_A")
                    .put("reason", "No conclusive trials");
            result.putArray("sourceRunIds");
            results.set(field, result);
        }
        snapshot.putArray("metrics");
        snapshot.putArray("remainingFindings");
        snapshot.putNull("approvedPatch");
        ObjectNode decision = objectMapper.createObjectNode()
                .put("value", "BLOCKED")
                .put("gatePolicyVersion", "mvp-gate/1");
        decision.putArray("ruleTrace")
                .add(objectMapper.createObjectNode().put("ruleId", "INTEGRITY_BLOCK"));
        snapshot.set("decision", decision);
        snapshot.put("testedAt", testedAt.toString());
        return snapshot;
    }

    private void invalidateAndChangeContract(Seed seed) {
        jdbcTemplate.update("""
                insert into decision_invalidations
                    (id, release_decision_id, reasons_json, invalidated_by, invalidated_at, created_at)
                values (?, ?, '{"reason":"SAFETY_CONTRACT_CHANGE"}'::jsonb, 'reviewer', now(), now())
                """, UUID.randomUUID(), seed.decisionId());
        UUID contractId = UUID.randomUUID();
        jdbcTemplate.update("""
                insert into safety_contracts
                    (id, workspace_id, release_id, contract_key, status, created_at, updated_at)
                select ?, agent.workspace_id, release.id, 'historical-policy', 'APPROVED', now(), now()
                  from agent_releases release join agents agent on agent.id = release.agent_id
                 where release.id = ?
                """, contractId, seed.releaseId());
        jdbcTemplate.update("""
                insert into safety_contract_versions
                    (id, contract_id, version, state, policy_json, policy_hash, validation_json,
                     created_by, approved_by, approved_at, created_at, updated_at)
                values (?, ?, 1, 'APPROVED', '{}'::jsonb, ?, '{}'::jsonb,
                        'reviewer', 'reviewer', now(), now(), now())
                """, UUID.randomUUID(), contractId, HASH_B);
        jdbcTemplate.update("""
                update agent_releases
                   set lifecycle_state = 'NEEDS_REVALIDATION',
                       effective_status = 'NEEDS_REVALIDATION',
                       safety_contract_hash = ?,
                       release_fingerprint = ?
                 where id = ?
                """, HASH_B, HASH_B, seed.releaseId());
    }

    private String json(JsonNode value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception exception) {
            throw new IllegalArgumentException(exception);
        }
    }

    private void assertSqlState(String expected, Runnable operation) {
        assertThatThrownBy(operation::run)
                .rootCause()
                .isInstanceOfSatisfying(java.sql.SQLException.class, exception ->
                        assertThat(exception.getSQLState()).isEqualTo(expected));
    }

    private record Seed(UUID releaseId, UUID decisionId, Instant confirmedAt) {
    }
}
