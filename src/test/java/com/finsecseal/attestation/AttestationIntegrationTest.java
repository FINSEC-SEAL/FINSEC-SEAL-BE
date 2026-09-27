package com.finsecseal.attestation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.oracle.domain.EvidenceDigest;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.ReleaseDto;
import com.finsecseal.release.ReleaseService;
import java.io.IOException;
import java.sql.Connection;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.AopTestUtils;
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

    @Autowired
    ExecutionEventService eventService;

    @Autowired
    DataSource dataSource;

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
        ObjectNode forged = projectionDocument(seed, true);
        String forgedHash = digestService.sha256(canonicalJsonService.canonicalize(forged));
        String forgedHtml = "%s %s %s %s %s".formatted(
                AttestationService.DISCLAIMER_KO,
                AttestationService.DISCLAIMER_EN,
                seed.releaseId(),
                "BLOCKED",
                forgedHash
        );
        assertSqlState("23514", () -> jdbcTemplate.update("""
                insert into release_attestations
                    (id, release_decision_id, format_version, document_json, document_hash,
                     html_content, generated_at, disclaimer_version)
                values (?, ?, '1.0', ?::jsonb, ?, ?, ?, 'finsec-internal/v1')
                """, UUID.randomUUID(), seed.decisionId(), json(forged), forgedHash, forgedHtml,
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
    void rejectsStoredProjectionWithValidDocumentButForgedHtml() throws Exception {
        Seed seed = seedDecision("forged-html", false);
        ObjectNode exactDocument = projectionDocument(seed, false);
        String exactHash = digestService.sha256(canonicalJsonService.canonicalize(exactDocument));
        String forgedHtml = "%s %s %s %s %s forged-template".formatted(
                AttestationService.DISCLAIMER_KO,
                AttestationService.DISCLAIMER_EN,
                seed.releaseId(),
                "BLOCKED",
                exactHash
        );
        assertThat(jdbcTemplate.update("""
                insert into release_attestations
                    (id, release_decision_id, format_version, document_json, document_hash,
                     html_content, generated_at, disclaimer_version)
                values (?, ?, '1.0', ?::jsonb, ?, ?, ?, 'finsec-internal/v1')
                """, UUID.randomUUID(), seed.decisionId(), json(exactDocument), exactHash, forgedHtml,
                Timestamp.from(seed.confirmedAt()))).isEqualTo(1);

        assertThatThrownBy(() -> attestationService.findOrCreate(seed.releaseId(), "governance-reviewer"))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.RELEASE_CHANGED));
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
    void rejectsDecisionSnapshotWhoseTestSuiteDoesNotCloseToStoredEvidence() throws Exception {
        Seed seed = seedDecision(
                "bad-suite-closure",
                false,
                snapshot -> ((ObjectNode) snapshot.path("testSuite")).put("hash", HASH_B)
        );

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
    void attestsObservedEffectCountsFromFailedAttackRunWithoutChangingLegacyShape() throws Exception {
        Seed seed = effectDecision("observed-effects", counts -> { });
        ObjectNode forged = projectionDocument(seed, false);
        ((ObjectNode) forged.path("observedEffectCounts").get(0)).put("value", 99);
        String forgedHash = digestService.sha256(canonicalJsonService.canonicalize(forged));
        String forgedHtml = "%s %s %s %s %s".formatted(
                AttestationService.DISCLAIMER_KO, AttestationService.DISCLAIMER_EN,
                seed.releaseId(), "BLOCKED", forgedHash);
        assertSqlState("23514", () -> jdbcTemplate.update("""
                insert into release_attestations
                    (id, release_decision_id, format_version, document_json, document_hash,
                     html_content, generated_at, disclaimer_version)
                values (?, ?, '1.0', ?::jsonb, ?, ?, ?, 'finsec-internal/v1')
                """, UUID.randomUUID(), seed.decisionId(), json(forged), forgedHash, forgedHtml,
                Timestamp.from(seed.confirmedAt())));

        AttestationDto.View attestation = attestationService.findOrCreate(seed.releaseId(), "governance-reviewer");
        assertThat(canonicalJsonService.canonicalize(attestation.document().path("observedEffectCounts")))
                .isEqualTo(canonicalJsonService.canonicalize(seed.snapshot().path("observedEffectCounts")));
        assertThat(attestationService.findOrCreate(seed.releaseId(), "governance-reviewer").id())
                .isEqualTo(attestation.id());
        assertThat(attestation.document().at("/observedEffectCounts/0/value").longValue()).isEqualTo(2);
        assertThat(attestation.document().at("/observedEffectCounts/1/value").longValue()).isZero();
        assertThat(attestation.documentHash())
                .isEqualTo(digestService.sha256(canonicalJsonService.canonicalize(attestation.document())));
        assertThat(new String(attestationService.export(seed.releaseId(), "html", "report-viewer").content(),
                java.nio.charset.StandardCharsets.UTF_8)).contains("observedEffectCounts");

        Seed legacy = seedDecision("legacy-no-effect-counts", false);
        assertThat(attestationService.findOrCreate(legacy.releaseId(), "governance-reviewer")
                .document().path("observedEffectCounts").isMissingNode()).isTrue();
    }

    @Test
    void projectsStoredDShapedGcReportAndCoverageIntoCanonicalJsonHtmlAndHash() throws Exception {
        Seed seed = seedDecision("gc-projection", false, snapshot -> {
            GcSource source = protectedGcSource(snapshot);
            snapshot.set("criticalInvariantAnySuccess", gcReport(source));
            snapshot.set("criticalTrialCoverage", gcCoverage(snapshot, 1));
        });
        ObjectNode omitted = projectionDocument(seed, false);
        omitted.remove("criticalInvariantAnySuccess");
        assertDirectAttestationRejected(seed, omitted);
        ObjectNode changed = projectionDocument(seed, false);
        ((ObjectNode) changed.path("criticalTrialCoverage")).put("complete", true);
        assertDirectAttestationRejected(seed, changed);

        AttestationDto.View first = attestationService.findOrCreate(seed.releaseId(), "governance-reviewer");
        AttestationDto.View second = attestationService.findOrCreate(seed.releaseId(), "governance-reviewer");
        assertThat(second.id()).isEqualTo(first.id());
        assertThat(second.documentHash()).isEqualTo(first.documentHash());
        assertThat(canonicalJsonService.canonicalString(first.document().path("criticalInvariantAnySuccess")))
                .isEqualTo(canonicalJsonService.canonicalString(
                        seed.snapshot().path("criticalInvariantAnySuccess")));
        assertThat(canonicalJsonService.canonicalString(first.document().path("criticalTrialCoverage")))
                .isEqualTo(canonicalJsonService.canonicalString(seed.snapshot().path("criticalTrialCoverage")));
        assertThat(first.document().at("/criticalInvariantAnySuccess/invariants/0/anySuccess")
                .asBoolean()).isTrue();
        assertThat(first.document().at("/criticalInvariantAnySuccess/invariants/1/anySuccess")
                .isNull()).isTrue();
        assertThat(first.documentHash())
                .isEqualTo(digestService.sha256(canonicalJsonService.canonicalize(first.document())));
        assertThat(attestationService.export(seed.releaseId(), "json", "report-viewer").content())
                .isEqualTo(canonicalJsonService.canonicalize(first.document()));
        assertThat(new String(attestationService.export(seed.releaseId(), "html", "report-viewer").content(),
                java.nio.charset.StandardCharsets.UTF_8))
                .contains("criticalInvariantAnySuccess", "criticalTrialCoverage");
        assertThat(attestationAuditCount(first.id())).isEqualTo(1);
    }

    @Test
    void refusesMalformedForeignOrFalseGcReportsWithoutAttestationOrAudit() throws Exception {
        Seed wrongOrder = gcDecision("gc-wrong-order", (snapshot, report) ->
                ((ObjectNode) report.path("invariants").get(0)).put("gcId", "GC-02"));
        assertIncompleteAttestation(wrongOrder);

        Seed missingCoverage = gcDecision("gc-no-coverage", (snapshot, report) ->
                snapshot.remove("criticalTrialCoverage"));
        assertIncompleteAttestation(missingCoverage);

        Seed literalFalse = gcDecision("gc-literal-false", (snapshot, report) -> {
            ObjectNode first = (ObjectNode) report.path("invariants").get(0);
            first.put("status", "AVAILABLE").put("anySuccess", false).putNull("reason");
        });
        assertIncompleteAttestation(literalFalse);
        assertDirectAttestationRejected(literalFalse, projectionDocument(literalFalse, false));

        Seed foreign = seedDecision("gc-foreign-source", false);
        UUID foreignRun = protectedGcSource(foreign.snapshot()).runId();
        Seed mismatched = seedDecision("gc-mismatched-source", false, snapshot -> {
            GcSource source = protectedGcSource(snapshot);
            ObjectNode report = gcReport(source);
            ((ArrayNode) report.at("/invariants/0/sourceRunIds")).removeAll().add(foreignRun.toString());
            snapshot.set("criticalInvariantAnySuccess", report);
            snapshot.set("criticalTrialCoverage", gcCoverage(snapshot, 1));
        });
        assertIncompleteAttestation(mismatched);
    }

    @Test
    void readsExistingLegacyPassWithoutChangingJsonHtmlHashOrAuditButRejectsNewPass() throws Exception {
        Seed historical = seedDecision("legacy-pass-existing", false, "PASS", snapshot ->
                conclusiveLegacyPassEvidence(snapshot));
        String persistedSnapshotJson = jdbcTemplate.queryForObject(
                "select input_snapshot_json::text from release_decisions where id = ?",
                String.class, historical.decisionId());
        Seed persistedHistorical = new Seed(historical.releaseId(), historical.decisionId(),
                historical.confirmedAt(), historical.inputDigest(),
                (ObjectNode) objectMapper.readTree(persistedSnapshotJson));
        ObjectNode historicalDocument = projectionDocument(persistedHistorical, false);
        String historicalHash = digestService.sha256(canonicalJsonService.canonicalize(historicalDocument));
        String historicalHtml = legacyHtml(historicalDocument, historicalHash);
        UUID historicalAttestationId = insertHistoricalPassAttestation(
                persistedHistorical, historicalDocument, historicalHash, historicalHtml);
        int auditBefore = attestationAuditCount(historicalAttestationId);

        AttestationDto.View first = attestationService.findOrCreate(historical.releaseId(), "report-viewer");
        AttestationDto.View second = attestationService.findOrCreate(historical.releaseId(), "report-viewer");
        assertThat(first.id()).isEqualTo(historicalAttestationId);
        assertThat(second.id()).isEqualTo(historicalAttestationId);
        assertThat(first.document()).isEqualTo(historicalDocument);
        assertThat(first.documentHash()).isEqualTo(historicalHash);
        assertThat(attestationService.export(historical.releaseId(), "json", "report-viewer").content())
                .isEqualTo(canonicalJsonService.canonicalize(historicalDocument));
        assertThat(new String(attestationService.export(historical.releaseId(), "html", "report-viewer").content(),
                java.nio.charset.StandardCharsets.UTF_8)).isEqualTo(historicalHtml);
        assertThat(attestationAuditCount(historicalAttestationId)).isEqualTo(auditBefore);

        Seed newPass = seedDecision("legacy-pass-new", false, "PASS", snapshot ->
                conclusiveLegacyPassEvidence(snapshot));
        assertIncompleteAttestation(newPass);
        assertDirectAttestationRejected(newPass, projectionDocument(newPass, false));

        Seed modernPass = seedDecision("modern-pass-new", false, "PASS", snapshot -> {
            conclusiveLegacyPassEvidence(snapshot);
            snapshot.set("criticalInvariantAnySuccess", gcReport(null));
            snapshot.set("criticalTrialCoverage", gcCoverage(snapshot, 0));
        });
        assertIncompleteAttestation(modernPass);
        assertDirectAttestationRejected(modernPass, projectionDocument(modernPass, false));
    }

    @Test
    void attestsScheduledOperationalErrorRateFromQueuedFailedAndCancelledParents() throws Exception {
        Seed seed = seedDecision("scheduled-oer-selected", false, "REVIEW", snapshot -> {
            UUID completed = effectSourceRun(snapshot, "COMPLETED");
            UUID failed = effectSourceRun(snapshot, "FAILED");
            UUID cancelled = scheduledBaselineRun(snapshot, "CANCELLED", 1);
            UUID queued = scheduledBaselineRun(snapshot, "QUEUED", 1);
            snapshot.withArray("metrics").add(scheduledOerMetric(
                    List.of(completed, failed, cancelled, queued), 1L, 4L));
        });

        AttestationDto.View first = attestationService.findOrCreate(seed.releaseId(), "governance-reviewer");
        AttestationDto.View second = attestationService.findOrCreate(seed.releaseId(), "report-viewer");
        assertThat(first.id()).isEqualTo(second.id());
        assertThat(first.documentHash()).isEqualTo(second.documentHash());
        assertThat(canonicalJsonService.canonicalString(first.document().path("metrics")))
                .isEqualTo(canonicalJsonService.canonicalString(seed.snapshot().path("metrics")));
        assertThat(first.documentHash())
                .isEqualTo(digestService.sha256(canonicalJsonService.canonicalize(first.document())));
        assertThat(attestationService.export(seed.releaseId(), "json", "report-viewer").content())
                .isEqualTo(canonicalJsonService.canonicalize(first.document()));
        String html = new String(attestationService.export(seed.releaseId(), "html", "report-viewer").content(),
                java.nio.charset.StandardCharsets.UTF_8);
        assertThat(html).contains("OperationalErrorRate", "REVIEW");
        assertThat(attestationAuditCount(first.id())).isEqualTo(1);
    }

    @Test
    void attestsActiveScheduledParentsAndExplicitZeroSlotNa() throws Exception {
        for (String status : List.of("PREPARING", "RUNNING", "CANCELLING")) {
            Seed seed = seedDecision("scheduled-oer-" + status.toLowerCase(java.util.Locale.ROOT),
                    false, "REVIEW", snapshot -> {
                        UUID source = scheduledBaselineRun(snapshot, status, 1);
                        snapshot.withArray("metrics").add(scheduledOerMetric(List.of(source), 0L, 1L));
                    });
            AttestationDto.View view = attestationService.findOrCreate(seed.releaseId(), "governance-reviewer");
            assertThat(canonicalJsonService.canonicalString(view.document().path("metrics")))
                    .isEqualTo(canonicalJsonService.canonicalString(seed.snapshot().path("metrics")));
            assertThat(attestationAuditCount(view.id())).isEqualTo(1);
        }

        Seed zeroSlots = seedDecision("scheduled-oer-zero-slots", false, "REVIEW", snapshot -> {
            UUID source = scheduledBaselineRun(snapshot, "QUEUED", 0);
            snapshot.withArray("metrics").add(scheduledOerMetric(List.of(source), null, null));
        });
        AttestationDto.View unavailable = attestationService.findOrCreate(
                zeroSlots.releaseId(), "governance-reviewer");
        JsonNode metric = unavailable.document().path("metrics").get(4);
        assertThat(metric.path("status").asString()).isEqualTo("N_A");
        assertThat(metric.path("reason").asString()).isEqualTo("NO_SCHEDULED_TRIALS");
        assertThat(metric.path("sourceTestRunIds").size()).isEqualTo(1);
        assertThat(metric.path("numerator").isNull()).isTrue();
        assertThat(metric.path("denominator").isNull()).isTrue();
    }

    @Test
    void scheduledOerRejectsForeignCohortsWhileOtherMetricsAndResultsStayConclusive() throws Exception {
        Seed foreign = seedDecision("oer-foreign-release", false, "REVIEW", snapshot -> {
        });
        UUID foreignRun = scheduledBaselineRun(foreign.snapshot(), "QUEUED", 1);
        Seed foreignRelease = seedDecision("oer-target-release", false, "REVIEW", snapshot ->
                snapshot.withArray("metrics").add(scheduledOerMetric(List.of(foreignRun), 0L, 1L)));
        assertIncompleteAttestation(foreignRelease);

        Seed otherSuite = seedDecision("oer-other-suite", false, "REVIEW", snapshot -> {
        });
        UUID foreignSuiteId = UUID.fromString(otherSuite.snapshot().at("/testSuite/id").asString());
        Seed wrongSuite = seedDecision("oer-target-suite", false, "REVIEW", snapshot -> {
            UUID source = scheduledBaselineRun(snapshot, "QUEUED", 1, foreignSuiteId,
                    snapshot.at("/sandbox/fixtureVersion").asString(),
                    snapshot.at("/sandbox/fixtureDigest").asString());
            snapshot.withArray("metrics").add(scheduledOerMetric(List.of(source), 0L, 1L));
        });
        assertIncompleteAttestation(wrongSuite);

        Seed wrongFixture = seedDecision("oer-target-fixture", false, "REVIEW", snapshot -> {
            UUID source = scheduledBaselineRun(snapshot, "QUEUED", 1,
                    UUID.fromString(snapshot.at("/testSuite/id").asString()), "other-fixture", HASH_B);
            snapshot.withArray("metrics").add(scheduledOerMetric(List.of(source), 0L, 1L));
        });
        assertIncompleteAttestation(wrongFixture);

        Seed wrongAgentFingerprint = seedDecision("oer-target-agent-fingerprint", false, "REVIEW", snapshot -> {
            UUID source = scheduledBaselineRun(snapshot, "QUEUED", 1);
            assertThat(snapshot.at("/release/agentArtifactFingerprint").asString()).isNotEqualTo(HASH_B);
            corruptQueuedRunFingerprint(source, true);
            snapshot.withArray("metrics").add(scheduledOerMetric(List.of(source), 0L, 1L));
        });
        assertIncompleteAttestation(wrongAgentFingerprint);

        Seed wrongReleaseFingerprint = seedDecision("oer-target-release-fingerprint", false, "REVIEW", snapshot -> {
            UUID source = scheduledBaselineRun(snapshot, "QUEUED", 1);
            assertThat(snapshot.at("/release/fingerprint").asString()).isNotEqualTo(HASH_B);
            corruptQueuedRunFingerprint(source, false);
            snapshot.withArray("metrics").add(scheduledOerMetric(List.of(source), 0L, 1L));
        });
        assertIncompleteAttestation(wrongReleaseFingerprint);

        Seed duplicateSource = seedDecision("oer-duplicate-source", false, "REVIEW", snapshot -> {
            UUID source = scheduledBaselineRun(snapshot, "QUEUED", 1);
            snapshot.withArray("metrics").add(scheduledOerMetric(List.of(source, source), 0L, 1L));
        });
        assertIncompleteAttestation(duplicateSource);

        Seed malformedSource = seedDecision("oer-malformed-source", false, "REVIEW", snapshot -> {
            ObjectNode metric = scheduledOerMetric(List.of(), 0L, 1L);
            metric.withArray("sourceTestRunIds").add("not-a-uuid");
            snapshot.withArray("metrics").add(metric);
        });
        assertIncompleteAttestation(malformedSource);

        Seed otherMetric = seedDecision("oer-other-metric-strict", false, "REVIEW", snapshot -> {
            UUID queued = scheduledBaselineRun(snapshot, "QUEUED", 1);
            ObjectNode baseline = (ObjectNode) snapshot.path("metrics").get(0);
            baseline.remove("reason");
            baseline.put("status", "AVAILABLE").put("numerator", 0).put("denominator", 1)
                    .put("evidenceDigest", HASH_A);
            baseline.putArray("sourceTestRunIds").add(queued.toString());
            snapshot.withArray("metrics").add(scheduledOerMetric(List.of(queued), 0L, 1L));
        });
        assertIncompleteAttestation(otherMetric);

        Seed result = seedDecision("oer-result-strict", false, "REVIEW", snapshot -> {
            UUID queued = scheduledBaselineRun(snapshot, "QUEUED", 1);
            ObjectNode baseline = (ObjectNode) snapshot.path("results").path("baseline");
            baseline.remove("reason");
            baseline.put("status", "AVAILABLE").put("numerator", 0).put("denominator", 1)
                    .put("evidenceDigest", HASH_A);
            baseline.putArray("sourceRunIds").add(queued.toString());
            snapshot.withArray("metrics").add(scheduledOerMetric(List.of(queued), 0L, 1L));
        });
        assertIncompleteAttestation(result);
    }

    @Test
    void rejectsMalformedCountEvidenceEvenWhenDecisionDigestIsRecomputed() throws Exception {
        Seed stringValue = effectDecision("string-effect-count", counts -> {
            ObjectNode first = (ObjectNode) counts.get(0);
            first.put("value", "2");
            refreshCountDigest(first);
        });
        assertIncompleteAttestation(stringValue);

        Seed staleInnerDigest = effectDecision("stale-inner-effect-digest", counts ->
                ((ObjectNode) counts.get(0)).put("value", 3));
        assertIncompleteAttestation(staleInnerDigest);

        Seed malformedNa = effectDecision("malformed-na-effect-count", counts ->
                ((ObjectNode) counts.get(1)).put("status", "N_A").put("reason", "EVIDENCE_INCOMPLETE"));
        assertIncompleteAttestation(malformedNa);

        Seed duplicateSource = effectDecision("duplicate-effect-source", counts -> {
            ObjectNode first = (ObjectNode) counts.get(0);
            ((ArrayNode) first.path("sourceTestRunIds")).add(first.at("/sourceTestRunIds/0").asString());
            refreshCountDigest(first);
        });
        assertIncompleteAttestation(duplicateSource);

        Seed runningSource = seedDecision("running-effect-source", false, snapshot -> {
            UUID run = effectSourceRun(snapshot, "RUNNING");
            availableEffects(snapshot, run);
        });
        assertIncompleteAttestation(runningSource);
    }

    @Test
    void rejectsForeignEffectSourceWithBothInnerAndOuterDigestsValid() throws Exception {
        Seed foreign = seedDecision("foreign-effect-source-owner", false, snapshot ->
                effectSourceRun(snapshot, "FAILED"));
        UUID foreignRun = jdbcTemplate.queryForObject("select id from test_runs where release_id = ?",
                UUID.class, foreign.releaseId());
        Seed target = seedDecision("foreign-effect-source-target", false, snapshot ->
                availableEffects(snapshot, foreignRun));
        assertIncompleteAttestation(target);
    }

    @Test
    void preservesExplicitNaEffectCountWithoutInventingZero() throws Exception {
        Seed seed = effectDecision("na-effect-count", counts -> {
            ObjectNode second = (ObjectNode) counts.get(1);
            second.remove("value");
            second.remove("evidenceDigest");
            second.put("status", "N_A").put("reason", "EFFECT_EVIDENCE_INCOMPLETE_OR_NO_CONCLUSIVE_TRIALS");
            second.putArray("sourceTestRunIds");
        });
        var document = attestationService.findOrCreate(seed.releaseId(), "governance-reviewer").document();
        assertThat(document.at("/observedEffectCounts/1/status").asString()).isEqualTo("N_A");
        assertThat(document.at("/observedEffectCounts/1/value").isMissingNode()).isTrue();
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
        jdbcTemplate.update("""
                update agent_releases
                   set lifecycle_state = 'VERIFYING', effective_status = 'VERIFYING'
                 where id = ?
                """, seed.releaseId());

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

    @Test
    void serializesConcurrentCreationToOneImmutableAttestation() throws Exception {
        Seed seed = seedDecision("concurrent-create", false);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(() -> attestationService.findOrCreate(seed.releaseId(), "reviewer-one"));
            var second = executor.submit(() -> attestationService.findOrCreate(seed.releaseId(), "reviewer-two"));

            AttestationDto.View firstView = first.get(5, TimeUnit.SECONDS);
            AttestationDto.View secondView = second.get(5, TimeUnit.SECONDS);
            assertThat(secondView.id()).isEqualTo(firstView.id());
            assertThat(secondView.documentHash()).isEqualTo(firstView.documentHash());
        }
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from release_attestations where release_decision_id = ?",
                Integer.class,
                seed.decisionId()
        )).isEqualTo(1);
    }

    @Test
    void waitsForConcurrentLatestDecisionAndBuildsTheNewDecision() throws Exception {
        Seed seed = seedDecision("latest-race", false);
        UUID latestDecisionId = UUID.randomUUID();
        Instant latestConfirmedAt = seed.confirmedAt().plusSeconds(2);
        ObjectNode latestSnapshot = seed.snapshot().deepCopy();
        latestSnapshot.put("testedAt", latestConfirmedAt.toString());
        String latestDigest = digestService.sha256(canonicalJsonService.canonicalize(latestSnapshot));

        try (Connection first = dataSource.getConnection(); var executor = Executors.newSingleThreadExecutor()) {
            first.setAutoCommit(false);
            lockRelease(first, seed.releaseId());
            var attestation = executor.submit(() ->
                    attestationService.findOrCreate(seed.releaseId(), "latest-race-reviewer")
            );
            assertThatThrownBy(() -> attestation.get(200, TimeUnit.MILLISECONDS))
                    .isInstanceOf(java.util.concurrent.TimeoutException.class);
            try (var insert = first.prepareStatement("""
                    insert into release_decisions
                        (id, release_id, decision, gate_policy_version, input_snapshot_json, input_digest,
                         proposed_at, confirmed_by, confirmed_at)
                    values (?, ?, 'BLOCKED', 'mvp-gate/1', ?::jsonb, ?, ?, 'governance-reviewer', ?)
                    """)) {
                insert.setObject(1, latestDecisionId);
                insert.setObject(2, seed.releaseId());
                insert.setString(3, json(latestSnapshot));
                insert.setString(4, latestDigest);
                insert.setTimestamp(5, Timestamp.from(latestConfirmedAt.minusSeconds(1)));
                insert.setTimestamp(6, Timestamp.from(latestConfirmedAt));
                assertThat(insert.executeUpdate()).isEqualTo(1);
            }
            first.commit();
            assertThat(attestation.get(5, TimeUnit.SECONDS).releaseDecisionId())
                    .isEqualTo(latestDecisionId);
        }
    }

    @Test
    void waitsForConcurrentInvalidationAndReturnsHistoricalAttestationAsStale() throws Exception {
        Seed seed = seedDecision("invalidation-race", false);
        try (Connection first = dataSource.getConnection(); var executor = Executors.newSingleThreadExecutor()) {
            first.setAutoCommit(false);
            lockRelease(first, seed.releaseId());
            var attestation = executor.submit(() ->
                    attestationService.findOrCreate(seed.releaseId(), "invalidation-race-reviewer")
            );
            assertThatThrownBy(() -> attestation.get(200, TimeUnit.MILLISECONDS))
                    .isInstanceOf(java.util.concurrent.TimeoutException.class);
            try (var invalidation = first.prepareStatement("""
                    insert into decision_invalidations
                        (id, release_decision_id, reasons_json, invalidated_by, invalidated_at, created_at)
                    values (?, ?, '{"reason":"MODEL_CHANGE"}'::jsonb, 'reviewer', now(), now())
                    """)) {
                invalidation.setObject(1, UUID.randomUUID());
                invalidation.setObject(2, seed.decisionId());
                assertThat(invalidation.executeUpdate()).isEqualTo(1);
            }
            try (var transition = first.prepareStatement("""
                    update agent_releases
                       set lifecycle_state = 'VERIFYING', effective_status = 'VERIFYING'
                     where id = ?
                    """)) {
                transition.setObject(1, seed.releaseId());
                assertThat(transition.executeUpdate()).isEqualTo(1);
            }
            first.commit();
            assertThat(attestation.get(5, TimeUnit.SECONDS).stale()).isTrue();
        }
    }

    @Test
    void directInvalidationInsertSerializesOnTheReleaseParentLock() throws Exception {
        Seed seed = seedDecision("direct-invalidation-lock", false);
        try (Connection first = dataSource.getConnection(); var executor = Executors.newSingleThreadExecutor()) {
            first.setAutoCommit(false);
            lockRelease(first, seed.releaseId());
            var invalidation = executor.submit(() -> jdbcTemplate.update("""
                    insert into decision_invalidations
                        (id, release_decision_id, reasons_json, invalidated_by, invalidated_at, created_at)
                    values (?, ?, '{"reason":"MODEL_CHANGE"}'::jsonb, 'reviewer', now(), now())
                    """, UUID.randomUUID(), seed.decisionId()));

            assertThatThrownBy(() -> invalidation.get(200, TimeUnit.MILLISECONDS))
                    .isInstanceOf(java.util.concurrent.TimeoutException.class);
            first.rollback();
            assertThat(invalidation.get(5, TimeUnit.SECONDS)).isEqualTo(1);
        }

        assertThat(attestationService.findOrCreate(seed.releaseId(), "governance-reviewer").stale())
                .isTrue();
    }

    private Seed seedDecision(String suffix, boolean badDigest) throws IOException {
        return seedDecision(suffix, badDigest, snapshot -> { });
    }

    private Seed seedDecision(
            String suffix,
            boolean badDigest,
            Consumer<ObjectNode> snapshotMutator
    ) throws IOException {
        return seedDecision(suffix, badDigest, "BLOCKED", snapshotMutator);
    }

    private Seed seedDecision(
            String suffix,
            boolean badDigest,
            String decisionValue,
            Consumer<ObjectNode> snapshotMutator
    ) throws IOException {
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
                   set lifecycle_state = ?, effective_status = ?
                 where id = ?
                """, decisionValue, decisionValue, release.id());

        UUID decisionId = UUID.randomUUID();
        Instant confirmedAt = Instant.now().truncatedTo(ChronoUnit.MICROS);
        ObjectNode snapshot = decisionSnapshot(agent, release, manifest, fingerprints, confirmedAt, decisionValue);
        snapshotMutator.accept(snapshot);
        String inputDigest = badDigest
                ? HASH_A
                : digestService.sha256(canonicalJsonService.canonicalize(snapshot));
        jdbcTemplate.update("""
                insert into release_decisions
                    (id, release_id, decision, gate_policy_version, input_snapshot_json, input_digest,
                     proposed_at, confirmed_by, confirmed_at)
                values (?, ?, ?, 'mvp-gate/1', ?::jsonb, ?, ?, 'governance-reviewer', ?)
                """,
                decisionId,
                release.id(),
                decisionValue,
                json(snapshot),
                inputDigest,
                Timestamp.from(confirmedAt.minusSeconds(1)),
                Timestamp.from(confirmedAt)
        );
        return new Seed(release.id(), decisionId, confirmedAt, inputDigest, snapshot.deepCopy());
    }

    private ObjectNode decisionSnapshot(
            AgentDto.Response agent,
            ReleaseDto.Response release,
            JsonNode manifest,
            ReleaseDto.FingerprintResponse fingerprints,
            Instant testedAt,
            String decisionValue
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
        UUID suiteId = UUID.randomUUID();
        jdbcTemplate.update("""
                insert into test_suites
                    (id, workspace_id, suite_key, version, fixture_version,
                     generation_config_json, suite_hash, status, created_at, updated_at)
                values (?, ?, ?, '1.0.0', 'fixture-v1', '{}'::jsonb, ?, 'BUILDING', now(), now())
                """,
                suiteId,
                AgentService.DEMO_WORKSPACE_ID,
                "attestation-suite-" + suiteId.toString().substring(0, 8),
                HASH_A
        );
        jdbcTemplate.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name, category, severity,
                     delivery_channel, target_tool, payload_hash, preconditions_json, expected_invariant,
                     oracle_type, generation_source, expected_result_json, trial_policy_json)
                values (?, ?, 'ATTESTATION-ATTACK-1', 'ATTACK', 'SEED', 'FA-01', 'HIGH',
                        'DIRECT', 'CUSTOMER_DATA_READ', ?, '{}'::jsonb, 'NO_UNAUTHORIZED_EXPOSURE',
                        'CROSS_CUSTOMER', 'CURATED', '{}'::jsonb, '{}'::jsonb)
                """, UUID.randomUUID(), suiteId, HASH_A);
        jdbcTemplate.update("update test_suites set status = 'READY' where id = ?", suiteId);
        snapshot.set("testSuite", objectMapper.createObjectNode()
                .put("id", suiteId.toString())
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
        ArrayNode metrics = snapshot.putArray("metrics");
        for (String metricName : new String[]{
                "BaselineASR", "SealReplayASR", "HeldOutASR", "NormalRegression"
        }) {
            ObjectNode metric = objectMapper.createObjectNode()
                    .put("metric", metricName)
                    .put("status", "N_A")
                    .put("reason", "No conclusive trials")
                    .put("calculatorVersion", "1.0");
            metric.putArray("sourceTestRunIds");
            metrics.add(metric);
        }
        snapshot.putArray("remainingFindings");
        snapshot.putNull("approvedPatch");
        ObjectNode decision = objectMapper.createObjectNode()
                .put("value", decisionValue)
                .put("gatePolicyVersion", "mvp-gate/1");
        decision.putArray("ruleTrace")
                .add(objectMapper.createObjectNode().put("ruleId", "INTEGRITY_BLOCK"));
        snapshot.set("decision", decision);
        snapshot.put("testedAt", testedAt.toString());
        return snapshot;
    }

    private UUID effectSourceRun(ObjectNode snapshot, String terminalStatus) {
        UUID releaseId = UUID.fromString(snapshot.at("/release/id").asString());
        UUID suiteId = UUID.fromString(snapshot.at("/testSuite/id").asString());
        UUID caseId = jdbcTemplate.queryForObject(
                "select id from test_cases where suite_id = ? and case_key = 'ATTESTATION-ATTACK-1'",
                UUID.class, suiteId);
        UUID runId = UUID.randomUUID();
        jdbcTemplate.update("""
                insert into test_runs
                    (id, release_id, suite_id, mode, status, agent_artifact_fingerprint,
                     release_fingerprint, config_json, fixture_version, fixture_digest,
                     model_config_hash, total_cases)
                values (?, ?, ?, 'BASELINE', 'QUEUED', ?, ?, '{}'::jsonb, ?, ?, ?, 1)
                """, runId, releaseId, suiteId, snapshot.at("/release/agentArtifactFingerprint").asString(),
                snapshot.at("/release/fingerprint").asString(), snapshot.at("/sandbox/fixtureVersion").asString(),
                snapshot.at("/sandbox/fixtureDigest").asString(), HASH_A);
        jdbcTemplate.update("insert into run_event_counters (run_id, last_sequence) values (?, 0)", runId);
        UUID traceId = UUID.randomUUID();
        eventService.append(runId, new ExecutionEventDto.AppendRequest(null, traceId,
                ExecutionEventType.RUN_STARTED, null, null, null, null, "RUN_STARTED",
                objectMapper.createObjectNode()), "attestation-test");
        jdbcTemplate.update("update test_runs set status = 'PREPARING' where id = ?", runId);
        jdbcTemplate.update("update test_runs set status = 'RUNNING', started_at = now() where id = ?", runId);
        UUID caseRunId = UUID.randomUUID();
        jdbcTemplate.update("""
                insert into test_case_runs (id, test_run_id, test_case_id, trial_index, status, variant_hash)
                values (?, ?, ?, 0, 'EXECUTING', ?)
                """, caseRunId, runId, caseId, HASH_A);
        if ("FAILED".equals(terminalStatus)) {
            jdbcTemplate.update("""
                    update test_case_runs set status = 'ERROR', error_code = 'PROVIDER_TIMEOUT', completed_at = now()
                     where id = ?
                    """, caseRunId);
            eventService.append(runId, new ExecutionEventDto.AppendRequest(caseRunId, traceId,
                    ExecutionEventType.RUN_FAILED, null, null, null, null, "PROVIDER_TIMEOUT",
                    objectMapper.createObjectNode()), "attestation-test");
            jdbcTemplate.update("""
                    update test_runs set status = 'FAILED', completed_cases = 1,
                                         operational_error_count = 1, completed_at = now()
                     where id = ?
                    """, runId);
        } else if ("COMPLETED".equals(terminalStatus)) {
            jdbcTemplate.update("update test_case_runs set status = 'PASSED', completed_at = now() where id = ?",
                    caseRunId);
            eventService.append(runId, new ExecutionEventDto.AppendRequest(null, traceId,
                    ExecutionEventType.RUN_COMPLETED, null, null, null, null, "RUN_COMPLETED",
                    objectMapper.createObjectNode()), "attestation-test");
            jdbcTemplate.update("""
                    update test_runs set status = 'COMPLETED', completed_cases = 1, completed_at = now()
                     where id = ?
                    """, runId);
        }
        return runId;
    }

    private Seed gcDecision(String suffix, BiConsumer<ObjectNode, ObjectNode> mutation) throws IOException {
        return seedDecision(suffix, false, snapshot -> {
            ObjectNode report = gcReport(null);
            snapshot.set("criticalInvariantAnySuccess", report);
            snapshot.set("criticalTrialCoverage", gcCoverage(snapshot, 0));
            mutation.accept(snapshot, report);
        });
    }

    private ObjectNode gcReport(GcSource positive) {
        ObjectNode report = objectMapper.createObjectNode();
        ArrayNode invariants = report.putArray("invariants");
        String[] gcIds = {"GC-01", "GC-02", "GC-03", "GC-04"};
        String[] invariantIds = {"INV-01", "INV-02", "INV-04", "INV-05"};
        for (int index = 0; index < gcIds.length; index++) {
            boolean observed = index == 0 && positive != null;
            ObjectNode item = objectMapper.createObjectNode()
                    .put("gcId", gcIds[index])
                    .put("invariantId", invariantIds[index])
                    .put("status", observed ? "AVAILABLE" : "N_A");
            if (observed) {
                item.putNull("reason").put("anySuccess", true);
            } else {
                item.put("reason", "NEGATIVE_PROOF_UNAVAILABLE").putNull("anySuccess");
            }
            ArrayNode runIds = item.putArray("sourceRunIds");
            ArrayNode caseRunIds = item.putArray("sourceCaseRunIds");
            ArrayNode oracleIds = item.putArray("sourceOracleResultIds");
            ArrayNode eventIds = item.putArray("sourceEventIds");
            if (observed) {
                runIds.add(positive.runId().toString());
                caseRunIds.add(positive.caseRunId().toString());
                oracleIds.add(positive.oracleResultId().toString());
                eventIds.add(positive.sourceEventId().toString());
            }
            invariants.add(item);
        }
        return report;
    }

    private ObjectNode gcCoverage(ObjectNode snapshot, long conclusiveTrials) {
        UUID suiteId = UUID.fromString(snapshot.at("/testSuite/id").asString());
        UUID caseId = jdbcTemplate.queryForObject(
                "select id from test_cases where suite_id = ? and case_key = 'ATTESTATION-ATTACK-1'",
                UUID.class, suiteId);
        ObjectNode coverage = objectMapper.createObjectNode()
                .put("complete", false).put("requiredCategoriesPresent", false);
        coverage.putArray("cases").add(objectMapper.createObjectNode()
                .put("testCaseId", caseId.toString()).put("category", "FA-01")
                .put("partition", "SEED").put("mode", "SEAL_REPLAY")
                .put("requiredTrials", 3).put("conclusiveTrials", conclusiveTrials)
                .put("complete", false).put("reason", "INSUFFICIENT_DISTINCT_TRIALS"));
        return coverage;
    }

    private GcSource protectedGcSource(ObjectNode snapshot) {
        UUID releaseId = UUID.fromString(snapshot.at("/release/id").asString());
        UUID suiteId = UUID.fromString(snapshot.at("/testSuite/id").asString());
        UUID caseId = jdbcTemplate.queryForObject(
                "select id from test_cases where suite_id = ? and case_key = 'ATTESTATION-ATTACK-1'",
                UUID.class, suiteId);
        UUID runId = UUID.randomUUID();
        UUID caseRunId = UUID.randomUUID();
        UUID traceId = UUID.randomUUID();
        UUID oracleId = UUID.randomUUID();
        UUID contractId = UUID.randomUUID();
        UUID contractVersionId = UUID.randomUUID();
        jdbcTemplate.update("""
                insert into safety_contracts (id, workspace_id, release_id, contract_key, status)
                values (?, ?, ?, 'attestation-gc-source', 'APPROVED')
                """, contractId, AgentService.DEMO_WORKSPACE_ID, releaseId);
        jdbcTemplate.update("""
                insert into safety_contract_versions
                    (id, contract_id, version, state, policy_json, policy_hash, validation_json,
                     created_by, approved_by, approved_at)
                values (?, ?, 1, 'APPROVED', '{}'::jsonb, ?, '{}'::jsonb, 'test', 'test', now())
                """, contractVersionId, contractId, HASH_A);
        jdbcTemplate.update("""
                insert into test_runs
                    (id, release_id, suite_id, contract_version_id, mode, status, agent_artifact_fingerprint,
                     release_fingerprint, config_json, fixture_version, fixture_digest,
                     model_config_hash, total_cases)
                values (?, ?, ?, ?, 'SEAL_REPLAY', 'QUEUED', ?, ?, '{}'::jsonb, ?, ?, ?, 1)
                """, runId, releaseId, suiteId, contractVersionId,
                snapshot.at("/release/agentArtifactFingerprint").asString(),
                snapshot.at("/release/fingerprint").asString(), snapshot.at("/sandbox/fixtureVersion").asString(),
                snapshot.at("/sandbox/fixtureDigest").asString(), HASH_A);
        jdbcTemplate.update("insert into run_event_counters (run_id, last_sequence) values (?, 0)", runId);
        eventService.append(runId, new ExecutionEventDto.AppendRequest(null, traceId,
                ExecutionEventType.RUN_STARTED, null, null, null, null, "RUN_STARTED",
                objectMapper.createObjectNode()), "attestation-test");
        jdbcTemplate.update("update test_runs set status = 'PREPARING' where id = ?", runId);
        jdbcTemplate.update("update test_runs set status = 'RUNNING', started_at = now() where id = ?", runId);
        jdbcTemplate.update("""
                insert into test_case_runs (id, test_run_id, test_case_id, trial_index, status, variant_hash)
                values (?, ?, ?, 0, 'EXECUTING', ?)
                """, caseRunId, runId, caseId, HASH_A);
        ExecutionEventDto.Event source = eventService.append(runId, new ExecutionEventDto.AppendRequest(
                caseRunId, traceId, ExecutionEventType.TOOL_RESPONSE, "CUSTOMER_DATA_READ", null,
                objectMapper.createObjectNode().put("customerRecordReturned", true), null,
                "TOOL_EXECUTED", objectMapper.createObjectNode()), "attestation-test");
        Map<String, Object> evidence = Map.of(
                "apiEventSequence", source.sequence(),
                "observedUnauthorizedCustomerIdHashes", List.of(HASH_A),
                "unauthorizedRecordCount", 1);
        jdbcTemplate.update("""
                insert into oracle_results
                    (id, test_case_run_id, source_event_id, oracle_type, oracle_version, outcome,
                     reason_code, invariant_id, evidence_json, evidence_digest,
                     evaluated_at, created_at, updated_at)
                values (?, ?, ?, 'CROSS_CUSTOMER', '1.0', 'ATTACK_SUCCESS',
                        'UNAUTHORIZED_RECORD_RETURNED', 'INV-01', ?::jsonb, ?, now(), now(), now())
                """, oracleId, caseRunId, source.eventId(), json(objectMapper.valueToTree(evidence)),
                EvidenceDigest.sha256(evidence));
        jdbcTemplate.update("""
                update test_case_runs
                   set status = 'FAILED_SECURITY', security_outcome = 'ATTACK_SUCCESS',
                       completed_at = now() where id = ?
                """, caseRunId);
        eventService.append(runId, new ExecutionEventDto.AppendRequest(null, traceId,
                ExecutionEventType.RUN_COMPLETED, null, null, null, null, "RUN_COMPLETED",
                objectMapper.createObjectNode()), "attestation-test");
        jdbcTemplate.update("""
                update test_runs set status = 'COMPLETED', completed_cases = 1, completed_at = now()
                 where id = ?
                """, runId);
        return new GcSource(runId, caseRunId, oracleId, source.eventId());
    }

    private void conclusiveLegacyPassEvidence(ObjectNode snapshot) {
        UUID sourceRunId = effectSourceRun(snapshot, "COMPLETED");
        for (String name : List.of("baseline", "sealReplay", "heldOut", "normalRegression")) {
            ObjectNode result = (ObjectNode) snapshot.path("results").path(name);
            result.remove("reason");
            result.put("status", "AVAILABLE").put("numerator", 0).put("denominator", 1)
                    .put("evidenceDigest", HASH_A);
            result.putArray("sourceRunIds").add(sourceRunId.toString());
        }
        for (JsonNode entry : snapshot.path("metrics")) {
            ObjectNode metric = (ObjectNode) entry;
            metric.remove("reason");
            metric.put("status", "AVAILABLE").put("numerator", 0).put("denominator", 1)
                    .put("evidenceDigest", HASH_A);
            metric.putArray("sourceTestRunIds").add(sourceRunId.toString());
        }
        ((ObjectNode) snapshot.path("decision")).putArray("ruleTrace")
                .add(objectMapper.createObjectNode().put("ruleId", "LEGACY_PASS"));
    }

    private ObjectNode scheduledOerMetric(List<UUID> runIds, Long numerator, Long denominator) {
        ObjectNode metric = objectMapper.createObjectNode();
        if (denominator == null) {
            metric.put("status", "N_A").put("reason", "NO_SCHEDULED_TRIALS");
        } else {
            metric.put("status", "AVAILABLE").put("numerator", numerator).put("denominator", denominator);
        }
        ArrayNode sources = metric.putArray("sourceTestRunIds");
        runIds.stream().sorted().forEach(runId -> sources.add(runId.toString()));
        if (denominator == null) {
            metric.putNull("numerator").putNull("denominator").putNull("value");
        }
        metric.put("metric", "OperationalErrorRate").put("calculatorVersion", "mvp-metrics/1");
        if (denominator != null) {
            metric.put("evidenceDigest", digestService.sha256(canonicalJsonService.canonicalize(metric)));
        }
        return metric;
    }

    private UUID scheduledBaselineRun(ObjectNode snapshot, String status, int totalCases) {
        return scheduledBaselineRun(snapshot, status, totalCases,
                UUID.fromString(snapshot.at("/testSuite/id").asString()),
                snapshot.at("/sandbox/fixtureVersion").asString(),
                snapshot.at("/sandbox/fixtureDigest").asString());
    }

    private UUID scheduledBaselineRun(ObjectNode snapshot, String status, int totalCases,
                                      UUID suiteId, String fixtureVersion, String fixtureDigest) {
        UUID runId = UUID.randomUUID();
        jdbcTemplate.update("""
                insert into test_runs
                    (id, release_id, suite_id, mode, status, agent_artifact_fingerprint,
                     release_fingerprint, config_json, fixture_version, fixture_digest,
                     model_config_hash, total_cases)
                values (?, ?, ?, 'BASELINE', 'QUEUED', ?, ?, '{}'::jsonb, ?, ?, ?, ?)
                """, runId, UUID.fromString(snapshot.at("/release/id").asString()), suiteId,
                snapshot.at("/release/agentArtifactFingerprint").asString(),
                snapshot.at("/release/fingerprint").asString(), fixtureVersion, fixtureDigest,
                HASH_A, totalCases);
        if ("QUEUED".equals(status)) {
            return runId;
        }
        UUID traceId = UUID.randomUUID();
        jdbcTemplate.update("insert into run_event_counters (run_id, last_sequence) values (?, 0)", runId);
        eventService.append(runId, new ExecutionEventDto.AppendRequest(null, traceId,
                ExecutionEventType.RUN_STARTED, null, null, null, null, "RUN_STARTED",
                objectMapper.createObjectNode()), "attestation-test");
        if ("PREPARING".equals(status) || "RUNNING".equals(status) || "CANCELLING".equals(status)) {
            jdbcTemplate.update("update test_runs set status = 'PREPARING' where id = ?", runId);
        }
        if ("RUNNING".equals(status)) {
            jdbcTemplate.update("update test_runs set status = 'RUNNING', started_at = now() where id = ?", runId);
        } else if ("CANCELLING".equals(status)) {
            eventService.append(runId, new ExecutionEventDto.AppendRequest(null, traceId,
                    ExecutionEventType.RUN_CANCEL_REQUESTED, null, null, null, null, "RUN_CANCEL_REQUESTED",
                    objectMapper.createObjectNode()), "attestation-test");
            jdbcTemplate.update("update test_runs set status = 'CANCELLING', cancel_requested_at = now() where id = ?",
                    runId);
        } else if ("FAILED".equals(status)) {
            eventService.append(runId, new ExecutionEventDto.AppendRequest(null, traceId,
                    ExecutionEventType.RUN_FAILED, null, null, null, null, "RUN_FAILED",
                    objectMapper.createObjectNode()), "attestation-test");
            jdbcTemplate.update("update test_runs set status = 'FAILED', completed_at = now() where id = ?", runId);
        } else if ("CANCELLED".equals(status)) {
            eventService.append(runId, new ExecutionEventDto.AppendRequest(null, traceId,
                    ExecutionEventType.RUN_CANCEL_REQUESTED, null, null, null, null, "RUN_CANCEL_REQUESTED",
                    objectMapper.createObjectNode()), "attestation-test");
            jdbcTemplate.update("""
                    update test_runs set status = 'CANCELLED', cancel_requested_at = now(), completed_at = now()
                     where id = ?
                    """, runId);
        } else if (!"PREPARING".equals(status) && !"RUNNING".equals(status)) {
            throw new IllegalArgumentException("Unsupported scheduled test Run status " + status);
        }
        return runId;
    }

    private void corruptQueuedRunFingerprint(UUID runId, boolean agentArtifact) {
        String column = agentArtifact ? "agent_artifact_fingerprint" : "release_fingerprint";
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try (var statement = connection.createStatement()) {
                // V4 correctly prevents application writes from changing a Run snapshot.
                // This transaction creates an adversarial stored row solely to verify
                // the independent Attestation source-closure predicate.
                statement.execute("alter table test_runs disable trigger test_run_identity_guard");
                try (var update = connection.prepareStatement(
                        "update test_runs set " + column + " = ? where id = ?")) {
                    update.setString(1, HASH_B);
                    update.setObject(2, runId);
                    assertThat(update.executeUpdate()).isEqualTo(1);
                }
                statement.execute("alter table test_runs enable trigger test_run_identity_guard");
                connection.commit();
            } catch (Exception exception) {
                connection.rollback();
                throw exception;
            }
        } catch (Exception exception) {
            throw new IllegalStateException("Failed to create mismatched queued Run fixture", exception);
        }
    }

    private UUID insertHistoricalPassAttestation(
            Seed seed, ObjectNode document, String documentHash, String html
    ) throws Exception {
        UUID id = UUID.randomUUID();
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try (var statement = connection.createStatement()) {
                statement.execute("alter table release_attestations disable trigger release_attestation_zz_gc_coverage_guard");
                try (var insert = connection.prepareStatement("""
                        insert into release_attestations
                            (id, release_decision_id, format_version, document_json, document_hash,
                             html_content, generated_at, disclaimer_version)
                        values (?, ?, '1.0', ?::jsonb, ?, ?, ?, 'finsec-internal/v1')
                        """)) {
                    insert.setObject(1, id);
                    insert.setObject(2, seed.decisionId());
                    insert.setString(3, json(document));
                    insert.setString(4, documentHash);
                    insert.setString(5, html);
                    insert.setTimestamp(6, Timestamp.from(seed.confirmedAt()));
                    assertThat(insert.executeUpdate()).isEqualTo(1);
                }
                statement.execute("alter table release_attestations enable trigger release_attestation_zz_gc_coverage_guard");
                connection.commit();
            } catch (Exception exception) {
                connection.rollback();
                throw exception;
            }
        }
        return id;
    }

    private String legacyHtml(ObjectNode document, String documentHash) throws Exception {
        var render = AttestationService.class.getDeclaredMethod("renderHtml", JsonNode.class, String.class);
        render.setAccessible(true);
        return (String) render.invoke(AopTestUtils.getTargetObject(attestationService), document, documentHash);
    }

    private void assertDirectAttestationRejected(Seed seed, ObjectNode document) {
        String documentHash = digestService.sha256(canonicalJsonService.canonicalize(document));
        String html = "%s %s %s %s %s".formatted(
                AttestationService.DISCLAIMER_KO, AttestationService.DISCLAIMER_EN,
                seed.releaseId(), seed.snapshot().at("/decision/value").asString(), documentHash);
        assertSqlState("23514", () -> jdbcTemplate.update("""
                insert into release_attestations
                    (id, release_decision_id, format_version, document_json, document_hash,
                     html_content, generated_at, disclaimer_version)
                values (?, ?, '1.0', ?::jsonb, ?, ?, ?, 'finsec-internal/v1')
                """, UUID.randomUUID(), seed.decisionId(), json(document), documentHash, html,
                Timestamp.from(seed.confirmedAt())));
    }

    private int attestationAuditCount(UUID attestationId) {
        Integer count = jdbcTemplate.queryForObject("""
                select count(*) from audit_records
                 where resource_type = 'RELEASE_ATTESTATION' and resource_id = ?
                """, Integer.class, attestationId);
        return count == null ? 0 : count;
    }

    private ObjectNode effectCount(String metric, long value, UUID sourceRunId) {
        ObjectNode count = objectMapper.createObjectNode()
                .put("metric", metric).put("calculatorVersion", "mvp-metrics/1")
                .put("status", "AVAILABLE").put("value", value);
        count.putArray("sourceTestRunIds").add(sourceRunId.toString());
        count.put("evidenceDigest", digestService.sha256(canonicalJsonService.canonicalize(count)));
        return count;
    }

    private ArrayNode availableEffects(ObjectNode snapshot, UUID sourceRunId) {
        ArrayNode counts = snapshot.putArray("observedEffectCounts");
        counts.add(effectCount("UnauthorizedRecordExposureCount", 2, sourceRunId));
        counts.add(effectCount("ExfiltrationSuccessCount", 0, sourceRunId));
        return counts;
    }

    private Seed effectDecision(String suffix, Consumer<ArrayNode> mutation) throws IOException {
        return seedDecision(suffix, false, snapshot -> {
            UUID sourceRunId = effectSourceRun(snapshot, "FAILED");
            mutation.accept(availableEffects(snapshot, sourceRunId));
        });
    }

    private void refreshCountDigest(ObjectNode count) {
        count.remove("evidenceDigest");
        count.put("evidenceDigest", digestService.sha256(canonicalJsonService.canonicalize(count)));
    }

    private void assertIncompleteAttestation(Seed seed) {
        assertThatThrownBy(() -> attestationService.findOrCreate(seed.releaseId(), "governance-reviewer"))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE));
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from release_attestations where release_decision_id = ?",
                Integer.class, seed.decisionId())).isZero();
        assertThat(jdbcTemplate.queryForObject("""
                select count(*) from audit_records
                 where resource_type = 'RELEASE_ATTESTATION'
                   and (resource_id in (select id from release_attestations where release_decision_id = ?)
                        or metadata_json->>'releaseDecisionId' = ?)
                """, Integer.class, seed.decisionId(), seed.decisionId().toString())).isZero();
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

    private ObjectNode projectionDocument(Seed seed, boolean forgeMetric) {
        ObjectNode snapshot = seed.snapshot();
        ObjectNode document = objectMapper.createObjectNode();
        document.put("schemaVersion", "1.0");
        document.put("attestationType", "FINSEC_SEAL_INTERNAL_RELEASE_ATTESTATION");
        document.put("canonicalizationVersion", CanonicalJsonService.VERSION);
        for (String field : new String[]{
                "agent", "release", "model", "systemPromptFingerprint", "toolSetFingerprint",
                "toolSchemaFingerprints", "ragConfigurationFingerprint", "safetyContract",
                "testSuite", "sandbox", "results", "metrics", "remainingFindings", "approvedPatch"
        }) {
            document.set(field, snapshot.path(field).deepCopy());
        }
        if (snapshot.has("observedEffectCounts")) {
            document.set("observedEffectCounts", snapshot.path("observedEffectCounts").deepCopy());
        }
        if (snapshot.has("criticalInvariantAnySuccess")) {
            document.set("criticalInvariantAnySuccess", snapshot.path("criticalInvariantAnySuccess").deepCopy());
            document.set("criticalTrialCoverage", snapshot.path("criticalTrialCoverage").deepCopy());
        }
        if (forgeMetric) {
            ((ObjectNode) document.path("metrics").get(0)).put("reason", "forged metric evidence");
        }
        ObjectNode decision = objectMapper.createObjectNode()
                .put("id", seed.decisionId().toString())
                .put("value", snapshot.at("/decision/value").asString())
                .put("gatePolicyVersion", "mvp-gate/1");
        decision.set("ruleTrace", snapshot.at("/decision/ruleTrace").deepCopy());
        decision.put("inputDigest", seed.inputDigest());
        decision.put("proposedAt", seed.confirmedAt().minusSeconds(1).toString());
        decision.put("confirmedAt", seed.confirmedAt().toString());
        document.set("decision", decision);
        document.set("reviewer", objectMapper.createObjectNode()
                .put("actorId", "governance-reviewer")
                .put("role", "AI_GOVERNANCE_REVIEWER")
                .put("demoMode", true));
        document.set("testedAt", snapshot.path("testedAt").deepCopy());
        document.putArray("revalidationTriggers")
                .add("MODEL_CHANGE")
                .add("SYSTEM_PROMPT_CHANGE")
                .add("TOOL_SET_OR_SCHEMA_OR_DESCRIPTION_CHANGE")
                .add("RAG_CHANGE")
                .add("SAFETY_CONTRACT_CHANGE")
                .add("BUSINESS_PURPOSE_OR_CONTEXT_CHANGE");
        document.set("disclaimer", objectMapper.createObjectNode()
                .put("version", AttestationService.DISCLAIMER_VERSION)
                .put("ko", AttestationService.DISCLAIMER_KO)
                .put("en", AttestationService.DISCLAIMER_EN));
        document.put("generatedAt", seed.confirmedAt().toString());
        return document;
    }

    private String json(JsonNode value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception exception) {
            throw new IllegalArgumentException(exception);
        }
    }

    private void lockRelease(Connection connection, UUID releaseId) throws Exception {
        try (var lock = connection.prepareStatement(
                "select id from agent_releases where id = ? for update"
        )) {
            lock.setObject(1, releaseId);
            lock.executeQuery().close();
        }
    }

    private void assertSqlState(String expected, Runnable operation) {
        assertThatThrownBy(operation::run)
                .rootCause()
                .isInstanceOfSatisfying(java.sql.SQLException.class, exception ->
                        assertThat(exception.getSQLState()).isEqualTo(expected));
    }

    private record Seed(
            UUID releaseId,
            UUID decisionId,
            Instant confirmedAt,
            String inputDigest,
            ObjectNode snapshot
    ) {
    }

    private record GcSource(UUID runId, UUID caseRunId, UUID oracleResultId, UUID sourceEventId) {
    }
}
