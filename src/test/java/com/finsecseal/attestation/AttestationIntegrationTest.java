package com.finsecseal.attestation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.assurance.AttackRateBreakdownCalculator;
import com.finsecseal.assurance.CompletionRateCalculator;
import com.finsecseal.assurance.PolicyLatencyCalculator;
import com.finsecseal.assurance.TrialEvaluation;
import com.finsecseal.assurance.TrialSuccessDistributionCalculator;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.oracle.domain.EvidenceDigest;
import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.ReleaseDto;
import com.finsecseal.release.ReleaseService;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.AopTestUtils;
import org.springframework.web.util.HtmlUtils;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.cfg.JsonNodeFeature;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AttestationIntegrationTest {

    private static final String HASH_A = "sha256:" + "a".repeat(64);
    private static final String HASH_B = "sha256:" + "b".repeat(64);

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @LocalServerPort
    int port;

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

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
    void projectsFrozenMetricReportsIntoCanonicalJsonHtmlAndHash() throws Exception {
        Seed seed = seedDecision("four-reports", false, this::availableMetricReports);
        AttestationDto.View first = attestationService.findOrCreate(seed.releaseId(), "governance-reviewer");
        for (String field : AttestationDecisionMetricValidator.FIELDS) {
            assertThat(canonicalJsonService.canonicalString(first.document().path(field)))
                    .isEqualTo(canonicalJsonService.canonicalString(seed.snapshot().path(field)));
        }
        assertThat(first.document().at("/policyLatency/averageMs").decimalValue())
                .isEqualByComparingTo("12.34567890123456");
        assertThat(first.document().at("/trialSuccessDistribution/categories/0/successBits").toString())
                .isEqualTo("[1,0,null]");
        assertThat(first.document().at("/attackRateBreakdown/groups/1/numerator").longValue()).isZero();
        assertThat(first.document().at("/attackRateBreakdown/groups/1/anySuccess").asBoolean()).isFalse();
        assertThat(first.document().at("/attackRateBreakdown/groups/2/anySuccess").isNull()).isTrue();
        assertThat(first.documentHash()).isEqualTo(digestService.sha256(canonicalJsonService.canonicalize(first.document())));
        AttestationDto.Export jsonExport = attestationService.export(seed.releaseId(), "json", "governance-reviewer");
        String html = new String(attestationService.export(seed.releaseId(), "html", "governance-reviewer").content(), StandardCharsets.UTF_8);
        String domText = HtmlUtils.htmlUnescape(html.substring(html.indexOf("<pre>") + 5, html.indexOf("</pre>")));
        assertThat(canonicalJsonService.canonicalString(objectMapper.readTree(domText)))
                .isEqualTo(canonicalJsonService.canonicalString(first.document()));
        assertThat(canonicalJsonService.canonicalString(objectMapper.readTree(jsonExport.content())))
                .isEqualTo(canonicalJsonService.canonicalString(first.document()));
        assertThat(html).contains(AttestationService.DISCLAIMER_KO, AttestationService.DISCLAIMER_EN);
        assertThat(attestationService.export(seed.releaseId(), "json", "governance-reviewer").content()).isEqualTo(jsonExport.content());
        assertThat(attestationService.findOrCreate(seed.releaseId(), "governance-reviewer").id()).isEqualTo(first.id());
        assertThat(attestationAuditCount(first.id())).isEqualTo(1);
    }

    @Test
    void preservesActualDDecimalInStorageApiAndHtmlWhileRecordingCanonicalRepresentation() throws Exception {
        Seed seed = seedDecision("decimal-pipeline", false, snapshot -> availableMetricReports(snapshot,
                List.of(new BigDecimal("8"), new BigDecimal("8.000000000000002"))));
        ObjectMapper precise = objectMapper.rebuild().enable(JsonNodeFeature.USE_BIG_DECIMAL_FOR_FLOATS).build();
        String decisionJson = jdbcTemplate.queryForObject("select input_snapshot_json::text from release_decisions where id = ?", String.class, seed.decisionId());
        assertThat(precise.readTree(decisionJson).at("/policyLatency/averageMs").decimalValue())
                .isEqualByComparingTo("8.000000000000001");
        AttestationController controller = new AttestationController(attestationService);
        AttestationDto.View first = attestationService.findOrCreate(seed.releaseId(), "governance-reviewer");
        assertThat(first.document().at("/policyLatency/averageMs").decimalValue()).isEqualByComparingTo("8.000000000000001");
        String storedJson = jdbcTemplate.queryForObject("select document_json::text from release_attestations where id = ?", String.class, first.id());
        assertThat(precise.readTree(storedJson).at("/policyLatency/averageMs").decimalValue()).isEqualByComparingTo("8.000000000000001");
        byte[] apiJson = objectMapper.writeValueAsBytes(controller.find(seed.releaseId(), "governance-reviewer"));
        assertThat(precise.readTree(apiJson).at("/data/document/policyLatency/averageMs").decimalValue()).isEqualByComparingTo("8.000000000000001");
        byte[] htmlBytes = controller.export(seed.releaseId(), "html", "governance-reviewer").getBody();
        String html = new String(htmlBytes, StandardCharsets.UTF_8);
        String domText = HtmlUtils.htmlUnescape(html.substring(html.indexOf("<pre>") + 5, html.indexOf("</pre>")));
        assertThat(precise.readTree(domText).at("/policyLatency/averageMs").decimalValue()).isEqualByComparingTo("8.000000000000001");
        var canonicalResponse = controller.export(seed.releaseId(), "json", "governance-reviewer");
        byte[] canonicalBytes = canonicalResponse.getBody();
        // The owner-approved additional precise representation retains this existing canonical output.
        assertThat(precise.readTree(canonicalBytes).at("/policyLatency/averageMs").decimalValue()).isEqualByComparingTo("8.000000000000002");
        assertThat(canonicalResponse.getHeaders().getFirst("X-Attestation-Hash")).isEqualTo(first.documentHash());
        assertThat(first.documentHash()).isEqualTo(digestService.sha256(canonicalBytes));
        assertThat(first.documentHash()).isEqualTo(digestService.sha256(canonicalJsonService.canonicalize(first.document())));
        assertThat(controller.export(seed.releaseId(), "json", "governance-reviewer").getBody()).isEqualTo(canonicalBytes);
        assertThat(attestationService.findOrCreate(seed.releaseId(), "governance-reviewer").document()).isEqualTo(first.document());
        assertThat(attestationAuditCount(first.id())).isEqualTo(1);
        ObjectNode altered = (ObjectNode) first.document().deepCopy();
        ((ObjectNode) altered.path("policyLatency")).put("averageMs", new BigDecimal("8.000000000000002"));
        assertThat(canonicalJsonService.canonicalize(altered)).isEqualTo(canonicalBytes);
        String alteredHtml = legacyHtml(altered, first.documentHash());
        assertSqlState("23514", () -> insertAttestation(jdbcTemplate, seed, altered, first.documentHash(), alteredHtml));
        Path evidence = Path.of("build", "test-evidence", "attestation-decimal");
        Files.createDirectories(evidence);
        Files.writeString(evidence.resolve("decision.json"), decisionJson);
        Files.writeString(evidence.resolve("attestation.json"), storedJson);
        Files.write(evidence.resolve("api-response.json"), apiJson);
        Files.write(evidence.resolve("report.html"), htmlBytes);
        Files.write(evidence.resolve("canonical-download.json"), canonicalBytes);
        Files.write(evidence.resolve("precise-document-candidate.json"), objectMapper.writeValueAsBytes(first.document()));
        Files.writeString(evidence.resolve("document-hash.txt"), first.documentHash());
    }

    @Test
    void downloadsPreciseReportOverHttpWithoutChangingCanonicalHtmlOrStoredEvidence() throws Exception {
        Seed seed = seedDecision("precise-http", false, snapshot -> availableMetricReports(snapshot,
                List.of(new BigDecimal("8"), new BigDecimal("8.000000000000002"))));
        ObjectMapper precise = objectMapper.rebuild().enable(JsonNodeFeature.USE_BIG_DECIMAL_FOR_FLOATS).build();
        AttestationDto.View view = attestationService.findOrCreate(seed.releaseId(), "governance-reviewer");
        Map<String, Object> decisionBefore = jdbcTemplate.queryForMap("select input_snapshot_json::text as snapshot, input_digest, confirmed_at from release_decisions where id = ?", seed.decisionId());
        Map<String, Object> storedBefore = jdbcTemplate.queryForMap("select document_json::text as document, document_hash, html_content, generated_at, format_version, disclaimer_version from release_attestations where id = ?", view.id());
        HttpResponse<byte[]> canonical = exportHttp(seed.releaseId(), "json");
        HttpResponse<byte[]> defaultJson = exportHttp(seed.releaseId(), null);
        HttpResponse<byte[]> html = exportHttp(seed.releaseId(), "html");
        HttpResponse<byte[]> exact = exportHttp(seed.releaseId(), "json-precise");
        assertThat(canonical.statusCode()).isEqualTo(200);
        assertThat(defaultJson.statusCode()).isEqualTo(200);
        assertThat(html.statusCode()).isEqualTo(200);
        assertThat(exact.statusCode()).isEqualTo(200);
        assertThat(exact.headers().firstValue("Content-Type").orElseThrow())
                .contains("application/json", "profile=\"urn:finsec-seal:attestation:json-precise:v1\"");
        assertThat(exact.headers().firstValue("Content-Disposition").orElseThrow())
                .isEqualTo("attachment; filename=\"finsec-attestation-" + seed.releaseId().toString().substring(0, 8) + "-precise.json\"");
        assertThat(exact.headers().firstValue("Cache-Control")).contains("no-store");
        assertThat(exact.headers().firstValue("X-Attestation-Hash")).contains(view.documentHash());
        assertThat(exact.headers().firstValue("X-Attestation-Stale")).contains("false");
        JsonNode source = precise.readTree((String) decisionBefore.get("snapshot"));
        JsonNode document = precise.readTree(exact.body());
        for (String field : AttestationDecisionMetricValidator.FIELDS) {
            assertThat(document.path(field)).isEqualTo(source.path(field));
        }
        assertThat(document.at("/policyLatency/averageMs").decimalValue()).isEqualByComparingTo("8.000000000000001");
        assertThat(precise.readTree(canonical.body()).at("/policyLatency/averageMs").decimalValue()).isEqualByComparingTo("8.000000000000002");
        assertThat(document.at("/trialSuccessDistribution/categories/0/successBits").toString()).isEqualTo("[1,0,null]");
        assertThat(document.at("/attackRateBreakdown/groups/1/value").decimalValue()).isEqualByComparingTo("0");
        assertThat(document.at("/attackRateBreakdown/groups/2/status").asString()).isEqualTo("N_A");
        assertThat(document.at("/attackRateBreakdown/groups/2/anySuccess").isNull()).isTrue();
        assertThat(new String(exact.body(), StandardCharsets.UTF_8)).contains(AttestationService.DISCLAIMER_KO, AttestationService.DISCLAIMER_EN);
        assertThat(defaultJson.body()).isEqualTo(canonical.body());
        assertThat(canonical.body()).isEqualTo(canonicalJsonService.canonicalize(view.document()));
        assertThat(digestService.sha256(canonical.body())).isEqualTo(view.documentHash());
        assertThat(digestService.sha256(canonicalJsonService.canonicalize(document))).isEqualTo(view.documentHash());
        assertThat(digestService.sha256(exact.body())).isNotEqualTo(view.documentHash());
        assertThat(exportHttp(seed.releaseId(), "JSON-PRECISE").body()).isEqualTo(exact.body());
        assertThat(exportHttp(seed.releaseId(), "json-precise").body()).isEqualTo(exact.body());
        assertThat(exportHttp(seed.releaseId(), null).body()).isEqualTo(defaultJson.body());
        assertThat(exportHttp(seed.releaseId(), "json").body()).isEqualTo(canonical.body());
        assertThat(exportHttp(seed.releaseId(), "html").body()).isEqualTo(html.body());
        HttpResponse<byte[]> unknown = exportHttp(seed.releaseId(), "not-a-format");
        assertThat(unknown.statusCode()).isEqualTo(400);
        assertThat(precise.readTree(unknown.body()).path("code").asString()).isEqualTo("VALIDATION_ERROR");
        assertThat(jdbcTemplate.queryForMap("select input_snapshot_json::text as snapshot, input_digest, confirmed_at from release_decisions where id = ?", seed.decisionId())).isEqualTo(decisionBefore);
        assertThat(jdbcTemplate.queryForMap("select document_json::text as document, document_hash, html_content, generated_at, format_version, disclaimer_version from release_attestations where id = ?", view.id())).isEqualTo(storedBefore);
        assertThat(attestationAuditCount(view.id())).isEqualTo(1);
        Path evidence = Path.of("build", "test-evidence", "attestation-precise-http");
        Files.createDirectories(evidence);
        Files.writeString(evidence.resolve("decision.json"), (String) decisionBefore.get("snapshot"));
        Files.writeString(evidence.resolve("attestation.json"), (String) storedBefore.get("document"));
        Files.write(evidence.resolve("precise-download.json"), exact.body());
        Files.write(evidence.resolve("canonical-download.json"), canonical.body());
        Files.write(evidence.resolve("default-download.json"), defaultJson.body());
        Files.write(evidence.resolve("report.html"), html.body());
        Files.writeString(evidence.resolve("precise-headers.json"), objectMapper.writeValueAsString(exact.headers().map()));
        Files.writeString(evidence.resolve("canonical-headers.json"), objectMapper.writeValueAsString(canonical.headers().map()));
        Files.writeString(evidence.resolve("document-hash.txt"), view.documentHash());
    }

    @Test
    void preservesUnavailableNullsEscapesReportTextAndRejectsClassifiedAndSecretCanaries() throws Exception {
        String canary = "RAW_CREDIT_REPORT_CANARY";
        Seed seed = seedDecision("report-null", false, snapshot -> {
            unavailableMetricReports(snapshot);
            ((ObjectNode) snapshot.path("policyLatency")).put("reason", "<script>alert('test')</script> 원본 Café e\u0301")
                    .put("creditReport", "[REDACTED:CREDIT]");
        });
        AttestationDto.View view = attestationService.findOrCreate(seed.releaseId(), "governance-reviewer");
        assertThat(view.document().at("/completionRate/value").isNull()).isTrue();
        String html = new String(attestationService.export(seed.releaseId(), "html", "governance-reviewer").content(), StandardCharsets.UTF_8);
        String dom = HtmlUtils.htmlUnescape(html.substring(html.indexOf("<pre>") + 5, html.indexOf("</pre>")));
        assertThat(html).contains("&lt;script&gt;").doesNotContain("<script>", canary);
        assertThat(dom).doesNotContain(canary, "sk-01234567890123456789");
        assertThat(new String(attestationService.export(seed.releaseId(), "json", "governance-reviewer").content(), StandardCharsets.UTF_8))
                .doesNotContain(canary, "sk-01234567890123456789");
        HttpResponse<byte[]> preciseResponse = exportHttp(seed.releaseId(), "json-precise");
        assertThat(preciseResponse.statusCode()).isEqualTo(200);
        ObjectMapper precise = objectMapper.rebuild().enable(JsonNodeFeature.USE_BIG_DECIMAL_FOR_FLOATS).build();
        JsonNode preciseDocument = precise.readTree(preciseResponse.body());
        assertThat(preciseDocument.at("/policyLatency/reason").asString()).isEqualTo("<script>alert('test')</script> 원본 Café e\u0301");
        assertThat(preciseDocument.at("/completionRate/value").isNull()).isTrue();
        assertThat(new String(preciseResponse.body(), StandardCharsets.UTF_8)).doesNotContain(canary, "sk-01234567890123456789");
        Seed classified = seedDecision("report-classified", false, snapshot -> {
            unavailableMetricReports(snapshot);
            ((ObjectNode) snapshot.path("policyLatency")).put("creditReport", canary);
        });
        assertIncompleteAttestation(classified);
        assertThat(exportHttp(classified.releaseId(), "json-precise").statusCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE.status().value());
        Seed secret = seedDecision("report-secret", false, snapshot -> {
            unavailableMetricReports(snapshot);
            ((ObjectNode) snapshot.path("policyLatency")).put("reason", "sk-01234567890123456789");
        });
        assertThatThrownBy(() -> attestationService.findOrCreate(secret.releaseId(), "governance-reviewer"))
                .isInstanceOfSatisfying(BusinessException.class, error -> assertThat(error.errorCode()).isEqualTo(ErrorCode.SECRET_DETECTED));
        assertThat(jdbcTemplate.queryForObject("select count(*) from release_attestations where release_decision_id = ?", Integer.class, secret.decisionId())).isZero();
        HttpResponse<byte[]> secretResponse = exportHttp(secret.releaseId(), "json-precise");
        assertThat(secretResponse.statusCode()).isEqualTo(ErrorCode.SECRET_DETECTED.status().value());
        assertThat(new String(secretResponse.body(), StandardCharsets.UTF_8)).doesNotContain("sk-01234567890123456789");
    }

    @Test
    void rejectsValidlyHashedMalformedMetricShapesAndContradictoryFrozenGroups() throws Exception {
        List<Consumer<ObjectNode>> mutations = List.of(
                snapshot -> snapshot.putNull("policyLatency"),
                snapshot -> snapshot.put("completionRate", "unavailable"),
                snapshot -> ((ObjectNode) snapshot.path("policyLatency")).put("status", "N_A"),
                snapshot -> ((ObjectNode) snapshot.path("completionRate")).put("value", 0.99),
                snapshot -> ((ObjectNode) snapshot.path("completionRate")).put("denominator", 0),
                snapshot -> ((ObjectNode) snapshot.path("policyLatency")).put("invalidEventCount", 2),
                snapshot -> ((ObjectNode) snapshot.at("/trialSuccessDistribution/cases/0/orderedTrials/0")).put("trialIndex", -1),
                snapshot -> ((ObjectNode) snapshot.at("/attackRateBreakdown/groups/0")).put("numerator", 0).put("value", 0).put("anySuccess", false),
                snapshot -> ((ObjectNode) snapshot.at("/attackRateBreakdown/groups/0")).put("denominator", 2).put("value", 0.5),
                snapshot -> ((ObjectNode) snapshot.at("/attackRateBreakdown/groups/0")).put("excludedTrials", 1),
                snapshot -> ((ObjectNode) snapshot.at("/attackRateBreakdown/groups/2")).put("status", "AVAILABLE").putNull("reason")
                        .put("numerator", 0).put("denominator", 1).put("value", 0).put("anySuccess", false),
                snapshot -> replaceFirstSuccessBit(snapshot, new BigInteger("18446744073709551617")),
                snapshot -> replaceFirstSuccessBit(snapshot, new BigInteger("-18446744073709551615")),
                snapshot -> replaceFirstSuccessBit(snapshot, BigInteger.TWO),
                snapshot -> ((ArrayNode) snapshot.at("/policyLatency/sourceRunIds")).add("not-a-uuid"),
                snapshot -> ((ArrayNode) snapshot.at("/policyLatency/sourceEventIds")).add(snapshot.at("/policyLatency/sourceEventIds/0").deepCopy())
        );
        for (Consumer<ObjectNode> mutation : mutations) {
            Seed seed = seedDecision("malformed-report", false, snapshot -> {
                availableMetricReports(snapshot);
                mutation.accept(snapshot);
            });
            String before = jdbcTemplate.queryForObject("select input_snapshot_json::text from release_decisions where id = ?", String.class, seed.decisionId());
            assertIncompleteAttestation(seed);
            assertThat(jdbcTemplate.queryForObject("select input_snapshot_json::text from release_decisions where id = ?", String.class, seed.decisionId())).isEqualTo(before);
        }
    }

    @Test
    void preservesActualDInconclusiveSuccessAndNullExclusionControls() throws Exception {
        List<FrozenTrialFixture> fixtures = List.of(
                new FrozenTrialFixture("ATTACK", OracleOutcome.ATTACK_BLOCKED, false, false, 0, null),
                new FrozenTrialFixture("ATTACK", OracleOutcome.ATTACK_SUCCESS, false, false, 1, null),
                new FrozenTrialFixture("ATTACK", OracleOutcome.ATTACK_SUCCESS, true, false, 1, null),
                new FrozenTrialFixture("ATTACK", OracleOutcome.ATTACK_BLOCKED, true, false, null, "INCONCLUSIVE_ORACLE"),
                new FrozenTrialFixture("NORMAL", OracleOutcome.NORMAL_FAILURE, false, false, 0, null),
                new FrozenTrialFixture("NORMAL", OracleOutcome.NORMAL_SUCCESS, false, false, 1, null),
                new FrozenTrialFixture("NORMAL", OracleOutcome.NORMAL_FAILURE, true, false, null, "INCONCLUSIVE_ORACLE"),
                new FrozenTrialFixture("NORMAL", OracleOutcome.NORMAL_SUCCESS, true, false, null, "INCONCLUSIVE_ORACLE"),
                new FrozenTrialFixture("ATTACK", OracleOutcome.ATTACK_SUCCESS, true, true, null, "OPERATIONAL_ERROR"),
                new FrozenTrialFixture("NORMAL", OracleOutcome.NORMAL_SUCCESS, true, true, null, "OPERATIONAL_ERROR"));
        ArrayNode evidence = objectMapper.createArrayNode();
        for (FrozenTrialFixture fixture : fixtures) {
            Seed seed = seedDecision("d-inconclusive-control", false,
                    snapshot -> actualDTrialMetricReports(snapshot, fixture));
            evidence.add(assertFrozenTrialControl(seed, fixture));
        }
        Path directory = Path.of("build", "test-evidence", "attestation-inconclusive-bits");
        Files.createDirectories(directory);
        Files.writeString(directory.resolve("accepted-controls.json"), objectMapper.writeValueAsString(evidence));
    }

    @Test
    void rejectsMatchingInconclusiveFailureBitsWithoutChangingDecisionOrWritingAttestation() throws Exception {
        List<FrozenTrialFixture> fixtures = List.of(
                new FrozenTrialFixture("ATTACK", OracleOutcome.ATTACK_BLOCKED, false, false, 0, null),
                new FrozenTrialFixture("NORMAL", OracleOutcome.NORMAL_FAILURE, false, false, 0, null),
                new FrozenTrialFixture("NORMAL", OracleOutcome.NORMAL_SUCCESS, false, false, 1, null));
        ArrayNode accepted = objectMapper.createArrayNode();
        ArrayNode rejected = objectMapper.createArrayNode();
        for (FrozenTrialFixture fixture : fixtures) {
            // First prove that the same actual-D fixture and source structure can be stored/read.
            Seed control = seedDecision("d-inconclusive-negative-control", false,
                    snapshot -> actualDTrialMetricReports(snapshot, fixture));
            accepted.add(assertFrozenTrialControl(control, fixture));
            Seed malformed = seedDecision("d-inconclusive-negative", false, snapshot -> {
                actualDTrialMetricReports(snapshot, fixture);
                ((ObjectNode) snapshot.at("/trialSuccessDistribution/cases/0/orderedTrials/0"))
                        .put("secondaryInconclusive", true);
                ((ObjectNode) snapshot.at("/trialSuccessDistribution/categories/0/orderedTrials/0"))
                        .put("secondaryInconclusive", true);
            });
            JsonNode snapshot = malformed.snapshot();
            assertThat(snapshot.at("/trialSuccessDistribution/cases/0/orderedTrials/0"))
                    .isEqualTo(snapshot.at("/trialSuccessDistribution/categories/0/orderedTrials/0"));
            assertThat(malformed.inputDigest()).isEqualTo(digestService.sha256(canonicalJsonService.canonicalize(snapshot)));
            String before = frozenDecisionRow(malformed);
            assertIncompleteAttestation(malformed);
            String after = frozenDecisionRow(malformed);
            assertThat(after).isEqualTo(before);
            ObjectNode row = objectMapper.createObjectNode().put("caseType", fixture.caseType())
                    .put("successBit", fixture.bit()).put("secondaryInconclusive", true)
                    .put("attestations", 0).put("generationAudits", 0);
            row.set("decisionBefore", objectMapper.readTree(before));
            row.set("decisionAfter", objectMapper.readTree(after));
            rejected.add(row);
        }
        Path directory = Path.of("build", "test-evidence", "attestation-inconclusive-bits");
        Files.createDirectories(directory);
        Files.writeString(directory.resolve("negative-accepted-controls.json"), objectMapper.writeValueAsString(accepted));
        Files.writeString(directory.resolve("rejected-matching-copies.json"), objectMapper.writeValueAsString(rejected));
    }

    @Test
    void rejectsPreciselyWrongCompletionAndAttackFractionsWithoutWrites() throws Exception {
        ObjectMapper precise = objectMapper.rebuild().enable(JsonNodeFeature.USE_BIG_DECIMAL_FOR_FLOATS).build();
        for (String field : List.of("completionRate", "attackRateBreakdown")) {
            for (String invalid : List.of("1.00000000000000001", "0.99999999999999999", "1E-400")) {
                boolean expectedZero = "1E-400".equals(invalid);
                Seed seed = seedDecision("precise-fraction-invalid", false, snapshot -> {
                    availableMetricReports(snapshot);
                    if ("completionRate".equals(field)) {
                        UUID run = UUID.fromString(snapshot.at("/completionRate/sourceRunIds/0").asString());
                        snapshot.set(field, objectMapper.valueToTree(new CompletionRateCalculator().calculate(List.of(
                                new CompletionRateCalculator.RunCounts(run, 1, 1, expectedZero ? 0 : 1, 0)))));
                    }
                    ObjectNode target = "completionRate".equals(field) ? (ObjectNode) snapshot.path(field)
                            : (ObjectNode) snapshot.at("/attackRateBreakdown/groups/" + (expectedZero ? 1 : 0));
                    target.put("value", new BigDecimal(invalid));
                });
                String before = jdbcTemplate.queryForObject("select input_snapshot_json::text from release_decisions where id = ?", String.class, seed.decisionId());
                String valuePath = "completionRate".equals(field) ? "/completionRate/value"
                        : "/attackRateBreakdown/groups/" + (expectedZero ? 1 : 0) + "/value";
                assertThat(precise.readTree(before).at(valuePath).decimalValue()).isEqualByComparingTo(invalid);
                assertThat(new BigDecimal(invalid).doubleValue()).isEqualTo(expectedZero ? 0.0 : 1.0);
                assertIncompleteAttestation(seed);
                assertThat(jdbcTemplate.queryForObject("select input_snapshot_json::text from release_decisions where id = ?", String.class, seed.decisionId())).isEqualTo(before);
            }
        }
        for (String counter : List.of("numerator", "denominator")) {
            Seed seed = seedDecision("precise-counter-invalid", false, snapshot -> {
                availableMetricReports(snapshot);
                ((ObjectNode) snapshot.path("completionRate")).put(counter, new BigInteger("18446744073709551617"));
            });
            assertIncompleteAttestation(seed);
        }
    }

    @Test
    void acceptsGenuineDCompletionFractionsAndScaleEquivalentLongBoundaries() throws Exception {
        List<long[]> counts = List.of(new long[]{3, 3, 1}, new long[]{1, 1, 0}, new long[]{1, 1, 1},
                new long[]{Long.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE},
                new long[]{Long.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE - 1});
        for (long[] count : counts) {
            for (boolean scaled : List.of(false, true)) {
                List<CompletionRateCalculator.CompletionRate> produced = new ArrayList<>();
                Seed seed = seedDecision("genuine-fraction", false, snapshot -> {
                    availableMetricReports(snapshot);
                    UUID run = UUID.fromString(snapshot.at("/completionRate/sourceRunIds/0").asString());
                    // Synthetic D input proves its numeric contract, not current/live trial counts.
                    var report = new CompletionRateCalculator().calculate(List.of(
                            new CompletionRateCalculator.RunCounts(run, count[0], count[1], count[2], 0)));
                    produced.add(report);
                    ObjectNode frozen = (ObjectNode) objectMapper.valueToTree(report);
                    if (scaled) frozen.put("value", BigDecimal.valueOf(report.value()).setScale(20));
                    snapshot.set("completionRate", frozen);
                });
                AttestationDto.View view = attestationService.findOrCreate(seed.releaseId(), "governance-reviewer");
                assertThat(view.document().at("/completionRate/value").decimalValue())
                        .isEqualByComparingTo(BigDecimal.valueOf(produced.getFirst().value()));
                assertThat(view.document().at("/completionRate/numerator").longValue()).isEqualTo(count[2]);
                assertThat(view.document().at("/completionRate/denominator").longValue()).isEqualTo(count[0]);
                assertThat(attestationAuditCount(view.id())).isEqualTo(1);
            }
        }
    }

    @Test
    void acceptsGenuineDAttackThirdZeroOneAndScaleEquivalentFrozenTrials() throws Exception {
        for (boolean third : List.of(false, true)) {
            for (boolean scaled : List.of(false, true)) {
                Seed seed = seedDecision("genuine-attack-fraction", false, snapshot -> {
                    availableMetricReports(snapshot);
                    if (third) addTwoFrozenFailedAttackTrials(snapshot);
                    var distribution = objectMapper.treeToValue(snapshot.path("trialSuccessDistribution"),
                            TrialSuccessDistributionCalculator.Report.class);
                    ObjectNode report = (ObjectNode) objectMapper.valueToTree(new AttackRateBreakdownCalculator().calculate(distribution));
                    if (scaled) for (JsonNode group : report.path("groups")) {
                        if ("AVAILABLE".equals(group.path("status").asString())) {
                            ((ObjectNode) group).put("value", group.path("value").decimalValue().setScale(20));
                        }
                    }
                    snapshot.set("attackRateBreakdown", report);
                });
                AttestationDto.View view = attestationService.findOrCreate(seed.releaseId(), "governance-reviewer");
                for (JsonNode group : view.document().at("/attackRateBreakdown/groups")) {
                    if ("SEED".equals(group.path("partition").asString())) {
                        assertThat(group.path("value").decimalValue()).isEqualByComparingTo(third ? "0.3333333333333333" : "1");
                        assertThat(group.path("denominator").longValue()).isEqualTo(third ? 3 : 1);
                    } else if ("MUTATION".equals(group.path("partition").asString())) {
                        assertThat(group.path("value").decimalValue()).isEqualByComparingTo("0");
                    } else {
                        assertThat(group.path("value").isNull()).isTrue();
                    }
                }
                assertThat(attestationAuditCount(view.id())).isEqualTo(1);
            }
        }
    }

    @Test
    void rejectsDirectAlteredPreciseFractionsEvenWhenCanonicalHashesMatch() throws Exception {
        Seed seed = seedDecision("fraction-sql", false, this::availableMetricReports);
        AttestationDto.View view = attestationService.findOrCreate(seed.releaseId(), "governance-reviewer");
        String before = jdbcTemplate.queryForObject("select document_json::text from release_attestations where id = ?", String.class, view.id());
        for (String path : List.of("/completionRate", "/attackRateBreakdown/groups/0")) {
            ObjectNode altered = (ObjectNode) view.document().deepCopy();
            ((ObjectNode) altered.at(path)).put("value", new BigDecimal("1.00000000000000001"));
            assertThat(canonicalJsonService.canonicalize(altered)).isEqualTo(canonicalJsonService.canonicalize(view.document()));
            String alteredHtml = legacyHtml(altered, view.documentHash());
            assertSqlState("23514", () -> insertAttestation(jdbcTemplate, seed, altered, view.documentHash(), alteredHtml));
        }
        assertThat(jdbcTemplate.queryForObject("select document_json::text from release_attestations where id = ?", String.class, view.id())).isEqualTo(before);
        assertThat(attestationAuditCount(view.id())).isEqualTo(1);
    }

    @Test
    void rejectsForeignReportSourcesAndWrongEventOrTrialIdentities() throws Exception {
        Seed foreign = seedDecision("foreign-report", false, this::availableMetricReports);
        for (String field : AttestationDecisionMetricValidator.FIELDS) {
            Seed seed = seedDecision("foreign-metric-source", false, snapshot -> {
                availableMetricReports(snapshot);
                snapshot.set(field, foreign.snapshot().path(field).deepCopy());
            });
            assertIncompleteAttestation(seed);
        }
        Seed event = seedDecision("wrong-event", false, snapshot -> {
            availableMetricReports(snapshot);
            UUID runId = UUID.fromString(snapshot.at("/policyLatency/sourceRunIds/0").asString());
            UUID started = jdbcTemplate.queryForObject("select id from execution_events where run_id = ? and event_type = 'RUN_STARTED'", UUID.class, runId);
            ((ObjectNode) snapshot.path("policyLatency")).putArray("sourceEventIds").add(started.toString());
        });
        assertIncompleteAttestation(event);
        Seed trial = seedDecision("wrong-trial", false, snapshot -> {
            availableMetricReports(snapshot);
            String foreignCaseRun = foreign.snapshot().at("/trialSuccessDistribution/cases/0/orderedTrials/0/caseRunId").asString();
            ((ObjectNode) snapshot.at("/trialSuccessDistribution/cases/0/orderedTrials/0")).put("caseRunId", foreignCaseRun);
            ((ObjectNode) snapshot.at("/trialSuccessDistribution/categories/0/orderedTrials/0")).put("caseRunId", foreignCaseRun);
        });
        assertIncompleteAttestation(trial);
        for (String mismatch : List.of("suite", "fixtureVersion", "fixtureDigest", "agentFingerprint", "releaseFingerprint")) {
            Seed seed = seedDecision("report-cohort-source", false, snapshot -> {
                unavailableMetricReports(snapshot);
                UUID runId = scheduledBaselineRun(snapshot, "QUEUED", 1,
                        "suite".equals(mismatch) ? UUID.fromString(foreign.snapshot().at("/testSuite/id").asString()) : UUID.fromString(snapshot.at("/testSuite/id").asString()),
                        "fixtureVersion".equals(mismatch) ? "foreign-fixture" : snapshot.at("/sandbox/fixtureVersion").asString(),
                        "fixtureDigest".equals(mismatch) ? HASH_B : snapshot.at("/sandbox/fixtureDigest").asString());
                if (mismatch.endsWith("Fingerprint")) corruptQueuedRunFingerprint(runId, "agentFingerprint".equals(mismatch));
                ((ObjectNode) snapshot.path("completionRate")).putArray("sourceRunIds").add(runId.toString());
            });
            assertIncompleteAttestation(seed);
        }
    }

    @Test
    void preservesFrozenZeroCompletionAfterScheduledSourceMaterializesAndCompletes() throws Exception {
        UUID[] source = new UUID[1];
        Seed seed = seedDecision("frozen-completion", false, snapshot -> {
            unavailableMetricReports(snapshot);
            source[0] = scheduledBaselineRun(snapshot, "RUNNING", 1);
            ObjectNode rate = report(true, null).put("numerator", 0).put("denominator", 1).put("value", 0)
                    .put("cancelledTrials", 0).put("unmaterializedTrials", 1);
            ids(rate, "sourceRunIds", List.of(source[0]));
            snapshot.set("completionRate", rate);
        });
        AttestationDto.View before = attestationService.findOrCreate(seed.releaseId(), "governance-reviewer");
        UUID caseId = jdbcTemplate.queryForObject("select id from test_cases where suite_id = ? and case_key = 'ATTESTATION-ATTACK-1'", UUID.class, UUID.fromString(seed.snapshot().at("/testSuite/id").asString()));
        UUID caseRun = UUID.randomUUID();
        jdbcTemplate.update("insert into test_case_runs (id, test_run_id, test_case_id, trial_index, status, variant_hash) values (?, ?, ?, 0, 'EXECUTING', ?)", caseRun, source[0], caseId, HASH_A);
        jdbcTemplate.update("update test_case_runs set status = 'PASSED', completed_at = now() where id = ?", caseRun);
        eventService.append(source[0], new ExecutionEventDto.AppendRequest(null, UUID.randomUUID(), ExecutionEventType.RUN_COMPLETED, null, null, null, null, "RUN_COMPLETED", objectMapper.createObjectNode()), "attestation-test");
        jdbcTemplate.update("update test_runs set status = 'COMPLETED', completed_cases = 1, completed_at = now() where id = ?", source[0]);
        AttestationDto.View after = attestationService.findOrCreate(seed.releaseId(), "governance-reviewer");
        assertThat(after.document()).isEqualTo(before.document());
        assertThat(after.documentHash()).isEqualTo(before.documentHash());
        assertThat(after.document().at("/completionRate/numerator").longValue()).isZero();
        assertThat(attestationAuditCount(after.id())).isEqualTo(1);
    }

    @Test
    void validatesFiniteDecimalLatencyWithoutBinaryDoubleNarrowing() throws Exception {
        Seed seed = seedDecision("decimal-contract", false, this::availableMetricReports);
        ObjectNode snapshot = seed.snapshot().deepCopy();
        BigDecimal huge = new BigDecimal("1E+400");
        for (String field : List.of("averageMs", "p50Ms", "p95Ms", "p99Ms")) ((ObjectNode) snapshot.path("policyLatency")).put(field, huge);
        // This tests D's decimal boundary directly; RFC8785's existing number range is separate.
        new AttestationDecisionMetricValidator(jdbcTemplate).validate(seed.releaseId(), snapshot);
        assertThat(snapshot.at("/policyLatency/averageMs").decimalValue()).isEqualByComparingTo(huge);
        for (String field : List.of("averageMs", "p50Ms", "p95Ms", "p99Ms")) ((ObjectNode) snapshot.path("policyLatency")).put(field, BigDecimal.ZERO);
        new AttestationDecisionMetricValidator(jdbcTemplate).validate(seed.releaseId(), snapshot);
    }

    @Test
    void directInsertsRequireExactMetricPresenceValuesAndArrayOrder() throws Exception {
        Seed seed = seedDecision("metric-sql", false, this::availableMetricReports);
        ObjectNode expected = projectionDocument(persistedSeed(seed), false);
        for (String field : AttestationDecisionMetricValidator.FIELDS) {
            ObjectNode omitted = expected.deepCopy(); omitted.remove(field); assertDirectAttestationRejected(seed, omitted);
            ObjectNode nulled = expected.deepCopy(); nulled.putNull(field); assertDirectAttestationRejected(seed, nulled);
            ObjectNode altered = expected.deepCopy(); ((ObjectNode) altered.path(field)).put("invented", "value"); assertDirectAttestationRejected(seed, altered);
        }
        ObjectNode reordered = expected.deepCopy();
        ArrayNode bits = (ArrayNode) reordered.at("/trialSuccessDistribution/categories/0/successBits");
        bits.removeAll(); bits.addNull().add(0).add(1);
        assertDirectAttestationRejected(seed, reordered);
        Seed absent = seedDecision("metric-absent", false);
        ObjectNode invented = projectionDocument(absent, false); invented.putNull("policyLatency"); assertDirectAttestationRejected(absent, invented);
        Seed nullSource = seedDecision("metric-null-source", false, snapshot -> snapshot.putNull("policyLatency"));
        ObjectNode absentFromNull = projectionDocument(nullSource, false); absentFromNull.remove("policyLatency"); assertDirectAttestationRejected(nullSource, absentFromNull);
        // Exact modern projection is accepted and subsequently verified by the application.
        String hash = digestService.sha256(canonicalJsonService.canonicalize(expected));
        UUID id = insertAttestation(jdbcTemplate, seed, expected, hash, legacyHtml(expected, hash));
        assertThat(attestationService.findOrCreate(seed.releaseId(), "governance-reviewer").id()).isEqualTo(id);
    }

    @Test
    void readsOnlyExactStoredLegacyMetricOmissionsAndRejectsPartialStoredProjection() throws Exception {
        Seed seed = seedDecision("metric-legacy", false, this::availableMetricReports);
        ObjectNode document = projectionDocument(persistedSeed(seed), false);
        AttestationDecisionMetricValidator.FIELDS.forEach(document::remove);
        String hash = digestService.sha256(canonicalJsonService.canonicalize(document));
        String html = legacyHtml(document, hash);
        UUID id = insertHistoricalPassAttestation(seed, document, hash, html);
        String bytes = jdbcTemplate.queryForObject("select document_json::text from release_attestations where id = ?", String.class, id);
        AttestationDto.View view = attestationService.findOrCreate(seed.releaseId(), "governance-reviewer");
        assertThat(view.id()).isEqualTo(id); assertThat(view.documentHash()).isEqualTo(hash);
        HttpResponse<byte[]> oldCanonical = exportHttp(seed.releaseId(), "json");
        HttpResponse<byte[]> oldHtml = exportHttp(seed.releaseId(), "html");
        HttpResponse<byte[]> legacyPrecise = exportHttp(seed.releaseId(), "json-precise");
        assertThat(legacyPrecise.statusCode()).isEqualTo(200);
        JsonNode legacyDocument = objectMapper.readTree(legacyPrecise.body());
        for (String field : AttestationDecisionMetricValidator.FIELDS) assertThat(legacyDocument.has(field)).isFalse();
        assertThat(legacyPrecise.headers().firstValue("X-Attestation-Hash")).contains(hash);
        assertThat(digestService.sha256(canonicalJsonService.canonicalize(legacyDocument))).isEqualTo(hash);
        assertThat(exportHttp(seed.releaseId(), null).body()).isEqualTo(oldCanonical.body());
        assertThat(exportHttp(seed.releaseId(), "json").body()).isEqualTo(oldCanonical.body());
        assertThat(exportHttp(seed.releaseId(), "html").body()).isEqualTo(oldHtml.body());
        assertThat(exportHttp(seed.releaseId(), "json-precise").body()).isEqualTo(legacyPrecise.body());
        assertThat(new String(attestationService.export(seed.releaseId(), "html", "governance-reviewer").content(), StandardCharsets.UTF_8)).isEqualTo(html);
        assertThat(jdbcTemplate.queryForObject("select document_json::text from release_attestations where id = ?", String.class, id)).isEqualTo(bytes);
        assertThat(attestationAuditCount(id)).isZero();
        Seed partial = seedDecision("metric-partial-legacy", false, this::availableMetricReports);
        ObjectNode partialDocument = projectionDocument(persistedSeed(partial), false); partialDocument.remove("policyLatency");
        String partialHash = digestService.sha256(canonicalJsonService.canonicalize(partialDocument));
        UUID partialId = insertHistoricalPassAttestation(partial, partialDocument, partialHash, legacyHtml(partialDocument, partialHash));
        assertThatThrownBy(() -> attestationService.findOrCreate(partial.releaseId(), "governance-reviewer"))
                .isInstanceOfSatisfying(BusinessException.class, error -> assertThat(error.errorCode()).isEqualTo(ErrorCode.RELEASE_CHANGED));
        HttpResponse<byte[]> partialResponse = exportHttp(partial.releaseId(), "json-precise");
        assertThat(partialResponse.statusCode()).isEqualTo(ErrorCode.RELEASE_CHANGED.status().value());
        assertThat(objectMapper.readTree(partialResponse.body()).path("code").asString()).isEqualTo("RELEASE_CHANGED");
        assertThat(attestationAuditCount(partialId)).isZero();
    }

    @Test
    void upgradingV19PreservesRichDecisionAndOriginalOmissionReportWithoutBackfill() throws Exception {
        Seed legacy = persistedSeed(seedDecision("upgrade-rich-metrics", false, this::unavailableMetricReports));
        ObjectNode document = projectionDocument(legacy, false);
        AttestationDecisionMetricValidator.FIELDS.forEach(document::remove);
        String hash = digestService.sha256(canonicalJsonService.canonicalize(document));
        String html = legacyHtml(document, hash);
        String database = "attestation_upgrade_" + UUID.randomUUID().toString().replace("-", "");
        jdbcTemplate.execute("create database " + database);
        String url = "jdbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getMappedPort(5432) + "/" + database;
        try {
            Flyway v19 = Flyway.configure().dataSource(url, POSTGRES.getUsername(), POSTGRES.getPassword())
                    .target(MigrationVersion.fromVersion("19")).load();
            v19.migrate();
            try (Connection target = DriverManager.getConnection(url, POSTGRES.getUsername(), POSTGRES.getPassword())) {
                copyUpgradeSeed(legacy, target);
                JdbcTemplate jdbc = new JdbcTemplate(new org.springframework.jdbc.datasource.SingleConnectionDataSource(target, true));
                UUID id = insertAttestation(jdbc, legacy, document, hash, html);
                Map<String, Object> before = jdbc.queryForMap("select document_json::text, document_hash, html_content, generated_at from release_attestations where id = ?", id);
                String decisionBefore = jdbc.queryForObject("select input_snapshot_json::text from release_decisions where id = ?", String.class, legacy.decisionId());
                List<Map<String, Object>> checksums = jdbc.queryForList("select installed_rank, version, script, checksum from flyway_schema_history order by installed_rank");
                Flyway current = Flyway.configure().dataSource(url, POSTGRES.getUsername(), POSTGRES.getPassword()).load();
                assertThat(current.migrate().migrationsExecuted).isEqualTo(1);
                assertThat(current.info().current().getVersion()).isEqualTo(MigrationVersion.fromVersion("20"));
                assertThat(current.validateWithResult().validationSuccessful).isTrue();
                assertThat(jdbc.queryForList("select installed_rank, version, script, checksum from flyway_schema_history where version is distinct from '20' order by installed_rank")).isEqualTo(checksums);
                assertThat(jdbc.queryForMap("select document_json::text, document_hash, html_content, generated_at from release_attestations where id = ?", id)).isEqualTo(before);
                assertThat(jdbc.queryForObject("select input_snapshot_json::text from release_decisions where id = ?", String.class, legacy.decisionId())).isEqualTo(decisionBefore);
                assertThat(jdbc.queryForObject("select count(*) from audit_records where resource_type = 'RELEASE_ATTESTATION' and resource_id = ?", Integer.class, id)).isZero();
                assertThat(jdbc.queryForObject("select tgenabled::text from pg_trigger where tgrelid = 'release_attestations'::regclass and tgname = 'release_attestation_decision_metrics_guard'", String.class)).isEqualTo("O");
                assertThat(jdbc.queryForObject("select jsonb_exists(document_json, 'policyLatency') from release_attestations where id = ?", Boolean.class, id)).isFalse();
                // The old omission may survive, but the same omission cannot be newly inserted.
                assertSqlState("23514", () -> insertAttestation(jdbc, legacy, document, hash, html));
                Seed fresh = persistedSeed(seedDecision("upgrade-new-metrics", false, this::unavailableMetricReports));
                copyUpgradeSeed(fresh, target);
                ObjectNode exact = projectionDocument(fresh, false);
                String exactHash = digestService.sha256(canonicalJsonService.canonicalize(exact));
                ObjectNode omitted = exact.deepCopy(); omitted.remove("completionRate");
                String omittedHash = digestService.sha256(canonicalJsonService.canonicalize(omitted));
                String omittedHtml = legacyHtml(omitted, omittedHash);
                assertSqlState("23514", () -> insertAttestation(jdbc, fresh, omitted, omittedHash, omittedHtml));
                UUID exactId = insertAttestation(jdbc, fresh, exact, exactHash, legacyHtml(exact, exactHash));
                assertThat(jdbc.queryForObject("select document_json->'completionRate' = (select input_snapshot_json->'completionRate' from release_decisions where id = ?) from release_attestations where id = ?", Boolean.class, fresh.decisionId(), exactId)).isTrue();
            }
        } finally {
            // This isolated database belongs only to this container test; shared test order is unchanged.
            jdbcTemplate.execute("drop database " + database);
        }
    }

    private void copyUpgradeSeed(Seed seed, Connection target) throws Exception {
        UUID agent = UUID.fromString(seed.snapshot().at("/agent/id").asString());
        UUID suite = UUID.fromString(seed.snapshot().at("/testSuite/id").asString());
        copyUpgradeRow("agents", agent, target);
        copyUpgradeRow("agent_releases", seed.releaseId(), target);
        copyUpgradeRow("test_suites", suite, target);
        copyUpgradeRow("release_decisions", seed.decisionId(), target);
    }

    private void copyUpgradeRow(String table, UUID id, Connection target) throws Exception {
        // All callers use the four fixed A fixture tables above, never user-provided identifiers.
        try (Connection source = dataSource.getConnection();
             var query = source.prepareStatement("select * from " + table + " where id = ?")) {
            query.setObject(1, id);
            try (var row = query.executeQuery()) {
                assertThat(row.next()).isTrue();
                var metadata = row.getMetaData();
                List<String> columns = new ArrayList<>();
                List<String> placeholders = new ArrayList<>();
                for (int index = 1; index <= metadata.getColumnCount(); index++) {
                    columns.add(metadata.getColumnName(index)); placeholders.add("?");
                }
                try (var insert = target.prepareStatement("insert into " + table + " (" + String.join(",", columns)
                        + ") values (" + String.join(",", placeholders) + ")")) {
                    for (int index = 1; index <= columns.size(); index++) insert.setObject(index, row.getObject(index));
                    assertThat(insert.executeUpdate()).isEqualTo(1);
                }
            }
        }
    }

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
        HttpResponse<byte[]> stalePrecise = exportHttp(seed.releaseId(), "json-precise");
        assertThat(stalePrecise.statusCode()).isEqualTo(200);
        assertThat(stalePrecise.headers().firstValue("X-Attestation-Stale")).contains("true");
        assertThat(stalePrecise.headers().firstValue("X-Attestation-Hash")).contains(first.documentHash());
        assertThat(canonicalJsonService.canonicalize(objectMapper.readTree(stalePrecise.body()))).isEqualTo(json.content());
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
        HttpResponse<byte[]> forgedResponse = exportHttp(seed.releaseId(), "json-precise");
        assertThat(forgedResponse.statusCode()).isEqualTo(ErrorCode.RELEASE_CHANGED.status().value());
        assertThat(objectMapper.readTree(forgedResponse.body()).path("code").asString()).isEqualTo("RELEASE_CHANGED");
        assertThat(new String(forgedResponse.body(), StandardCharsets.UTF_8)).doesNotContain("forged-template");
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
        return effectSourceRun(snapshot, terminalStatus, "ATTESTATION-ATTACK-1", (run, trial) -> { });
    }

    private UUID effectSourceRun(ObjectNode snapshot, String terminalStatus, String caseKey,
                                 BiConsumer<UUID, UUID> beforeTerminal) {
        UUID releaseId = UUID.fromString(snapshot.at("/release/id").asString());
        UUID suiteId = UUID.fromString(snapshot.at("/testSuite/id").asString());
        UUID caseId = jdbcTemplate.queryForObject(
                "select id from test_cases where suite_id = ? and case_key = ?",
                UUID.class, suiteId, caseKey);
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
        beforeTerminal.accept(runId, caseRunId);
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
        } else if ("COMPLETED".equals(terminalStatus) || "ATTACK_SUCCESS".equals(terminalStatus)) {
            jdbcTemplate.update("update test_case_runs set status = ?, security_outcome = ?, completed_at = now() where id = ?",
                    "ATTACK_SUCCESS".equals(terminalStatus) ? "FAILED_SECURITY" : "PASSED",
                    "ATTACK_SUCCESS".equals(terminalStatus) ? "ATTACK_SUCCESS" : null, caseRunId);
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

    private ObjectNode report(boolean available, String reason) {
        ObjectNode report = objectMapper.createObjectNode().put("status", available ? "AVAILABLE" : "N_A");
        if (available) report.putNull("reason"); else report.put("reason", reason);
        return report;
    }

    private void ids(ObjectNode report, String field, List<UUID> ids) {
        ArrayNode values = report.putArray(field);
        ids.stream().sorted().forEach(id -> values.add(id.toString()));
    }

    private void unavailableMetricReports(ObjectNode snapshot) {
        ObjectNode latency = report(false, "NO_POLICY_EVALUATIONS").put("observedEventCount", 0).put("invalidEventCount", 0);
        for (String field : List.of("averageMs", "p50Ms", "p95Ms", "p99Ms")) latency.putNull(field);
        latency.putArray("sourceEventIds"); latency.putArray("sourceRunIds"); snapshot.set("policyLatency", latency);
        ObjectNode completion = report(false, "NO_SCHEDULED_TRIALS");
        for (String field : List.of("numerator", "denominator", "value", "cancelledTrials", "unmaterializedTrials")) completion.putNull(field);
        completion.putArray("sourceRunIds"); snapshot.set("completionRate", completion);
        ObjectNode distribution = report(false, "NO_OBSERVED_TRIALS");
        distribution.putArray("cases"); distribution.putArray("categories"); distribution.putArray("sourceRunIds"); snapshot.set("trialSuccessDistribution", distribution);
        ObjectNode breakdown = report(false, "NO_OBSERVED_ATTACK_TRIALS");
        breakdown.putArray("groups"); breakdown.putArray("sourceRunIds"); snapshot.set("attackRateBreakdown", breakdown);
    }

    private void availableMetricReports(ObjectNode snapshot) {
        availableMetricReports(snapshot, List.of(new BigDecimal("12.34567890123456")));
    }

    private void availableMetricReports(ObjectNode snapshot, List<BigDecimal> durations) {
        unavailableMetricReports(snapshot);
        UUID originalSuite = UUID.fromString(snapshot.at("/testSuite/id").asString());
        UUID suite = UUID.randomUUID();
        jdbcTemplate.update("""
                insert into test_suites (id, workspace_id, suite_key, version, fixture_version, generation_config_json, suite_hash, status)
                values (?, ?, ?, '1.0.0', 'fixture-v1', '{}'::jsonb, ?, 'BUILDING')
                """, suite, AgentService.DEMO_WORKSPACE_ID, "metric-suite-" + suite, HASH_A);
        String[] partitions = {"SEED", "MUTATION", "HELD_OUT"};
        for (int index = 0; index < partitions.length; index++) {
            jdbcTemplate.update("""
                    insert into test_cases (id, suite_id, case_key, case_type, partition_name, category, severity,
                       delivery_channel, target_tool, payload_hash, preconditions_json, expected_invariant,
                       oracle_type, generation_source, expected_result_json, trial_policy_json)
                    select ?, ?, ?, case_type, ?, category, severity, delivery_channel, target_tool, payload_hash,
                           preconditions_json, expected_invariant, oracle_type, generation_source,
                           expected_result_json, trial_policy_json
                      from test_cases where suite_id = ? and case_key = 'ATTESTATION-ATTACK-1'
                    """, UUID.randomUUID(), suite, "METRIC-" + index, partitions[index], originalSuite);
        }
        jdbcTemplate.update("update test_suites set status = 'READY' where id = ?", suite);
        ((ObjectNode) snapshot.path("testSuite")).put("id", suite.toString());
        List<PolicyLatencyCalculator.EventSample> samples = new ArrayList<>();
        List<UUID> runIds = new ArrayList<>();
        runIds.add(effectSourceRun(snapshot, "ATTACK_SUCCESS", "METRIC-0", (run, trial) -> {
            for (BigDecimal duration : durations) {
              var event = eventService.append(run, new ExecutionEventDto.AppendRequest(trial, UUID.randomUUID(),
                    ExecutionEventType.POLICY_EVALUATED, null, null, null,
                    objectMapper.createObjectNode().put("durationMs", duration),
                    "POLICY_EVALUATED", objectMapper.createObjectNode()), "attestation-test");
              String persisted = jdbcTemplate.queryForObject("select policy_decision_json::text from execution_events where id = ?", String.class, event.eventId());
              samples.add(new PolicyLatencyCalculator.EventSample(event.eventId(), run, objectMapper.readTree(persisted)));
            }
        }));
        runIds.add(effectSourceRun(snapshot, "COMPLETED", "METRIC-1", (run, trial) -> { }));
        runIds.add(effectSourceRun(snapshot, "FAILED", "METRIC-2", (run, trial) -> { }));
        // Consume the actual D-produced report; production A never invokes the calculator.
        snapshot.set("policyLatency", objectMapper.valueToTree(new PolicyLatencyCalculator().calculate(samples)));
        ObjectNode completion = report(true, null).put("numerator", 3).put("denominator", 3).put("value", 1)
                .put("cancelledTrials", 0).put("unmaterializedTrials", 0);
        ids(completion, "sourceRunIds", runIds); snapshot.set("completionRate", completion);
        ObjectNode distribution = report(true, null);
        ArrayNode cases = distribution.putArray("cases");
        ArrayNode ordered = objectMapper.createArrayNode();
        ArrayNode bits = objectMapper.createArrayNode();
        ObjectNode breakdown = report(true, null);
        ArrayNode groups = breakdown.putArray("groups");
        for (int index = 0; index < runIds.size(); index++) {
            UUID run = runIds.get(index);
            UUID caseRun = jdbcTemplate.queryForObject("select id from test_case_runs where test_run_id = ?", UUID.class, run);
            UUID testCase = jdbcTemplate.queryForObject("select test_case_id from test_case_runs where id = ?", UUID.class, caseRun);
            ObjectNode trial = objectMapper.createObjectNode().put("runId", run.toString()).put("testCaseId", testCase.toString())
                    .put("caseRunId", caseRun.toString()).put("trialIndex", 0).put("secondaryInconclusive", index == 0);
            if (index == 2) trial.putNull("successBit").put("exclusionReason", "OPERATIONAL_ERROR");
            else trial.put("successBit", index == 0 ? 1 : 0).putNull("exclusionReason");
            ObjectNode item = report(index != 2, "NO_CONCLUSIVE_TRIALS").put("runId", run.toString())
                    .put("mode", "BASELINE").put("testCaseId", testCase.toString()).put("caseKey", "METRIC-" + index)
                    .put("caseType", "ATTACK").put("category", "FA-01").put("partition", partitions[index])
                    .put("excludedTrials", index == 2 ? 1 : 0);
            item.putArray("successBits").add(trial.path("successBit").deepCopy());
            item.putArray("orderedTrials").add(trial.deepCopy());
            if (index == 2) item.putNull("successCount").putNull("trials");
            else item.put("successCount", index == 0 ? 1 : 0).put("trials", 1);
            cases.add(item); ordered.add(trial.deepCopy()); bits.add(trial.path("successBit").deepCopy());
            ObjectNode group = report(index != 2, "NO_CONCLUSIVE_ATTACK_TRIALS").put("mode", "BASELINE")
                    .put("category", "FA-01").put("partition", partitions[index]).put("excludedTrials", index == 2 ? 1 : 0);
            if (index == 2) {
                group.putNull("numerator").putNull("denominator").putNull("value").putNull("anySuccess");
                ids(group, "sourceRunIds", List.of());
            } else {
                group.put("numerator", index == 0 ? 1 : 0).put("denominator", 1).put("value", index == 0 ? 1 : 0).put("anySuccess", index == 0);
                ids(group, "sourceRunIds", List.of(run));
            }
            groups.add(group);
        }
        ObjectNode category = report(true, null).put("mode", "BASELINE").put("caseType", "ATTACK")
                .put("category", "FA-01").put("successCount", 1).put("trials", 2).put("excludedTrials", 1);
        category.set("successBits", bits); category.set("orderedTrials", ordered); ids(category, "sourceRunIds", runIds);
        distribution.putArray("categories").add(category); ids(distribution, "sourceRunIds", runIds);
        snapshot.set("trialSuccessDistribution", distribution);
        ids(breakdown, "sourceRunIds", runIds); snapshot.set("attackRateBreakdown", breakdown);
    }

    private HttpResponse<byte[]> exportHttp(UUID releaseId, String format) throws Exception {
        String path = "/api/v1/releases/" + releaseId + "/evidence-export"
                + (format == null ? "" : "?format=" + format);
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .timeout(Duration.ofSeconds(10)).header("X-Actor-Id", "governance-reviewer").GET().build();
        return http.send(request, HttpResponse.BodyHandlers.ofByteArray());
    }

    private void addTwoFrozenFailedAttackTrials(ObjectNode snapshot) {
        ObjectNode distribution = (ObjectNode) snapshot.path("trialSuccessDistribution");
        ArrayNode cases = (ArrayNode) distribution.path("cases");
        ObjectNode category = (ObjectNode) distribution.at("/categories/0");
        ObjectNode template = (ObjectNode) cases.get(0);
        List<UUID> runs = new ArrayList<>();
        for (JsonNode id : distribution.path("sourceRunIds")) runs.add(UUID.fromString(id.asString()));
        for (int index = 0; index < 2; index++) {
            UUID run = effectSourceRun(snapshot, "COMPLETED", "METRIC-0", (source, trial) -> { });
            UUID caseRun = jdbcTemplate.queryForObject("select id from test_case_runs where test_run_id = ?", UUID.class, run);
            ObjectNode trial = ((ObjectNode) template.at("/orderedTrials/0")).deepCopy()
                    .put("runId", run.toString()).put("caseRunId", caseRun.toString()).put("successBit", 0)
                    .put("secondaryInconclusive", false);
            ObjectNode item = template.deepCopy().put("runId", run.toString()).put("successCount", 0);
            item.putArray("successBits").add(0); item.putArray("orderedTrials").add(trial);
            cases.add(item);
            ((ArrayNode) category.path("successBits")).add(0);
            ((ArrayNode) category.path("orderedTrials")).add(trial.deepCopy());
            runs.add(run);
        }
        category.put("trials", 4);
        ids(category, "sourceRunIds", runs); ids(distribution, "sourceRunIds", runs);
        snapshot.set("completionRate", objectMapper.valueToTree(new CompletionRateCalculator().calculate(runs.stream()
                .map(run -> new CompletionRateCalculator.RunCounts(run, 1, 1, 1, 0)).toList())));
    }

    private void actualDTrialMetricReports(ObjectNode snapshot, FrozenTrialFixture fixture) {
        unavailableMetricReports(snapshot);
        UUID originalSuite = UUID.fromString(snapshot.at("/testSuite/id").asString());
        UUID suite = UUID.randomUUID();
        UUID testCase = UUID.randomUUID();
        String caseKey = "FROZEN-" + fixture.caseType();
        String partition = "NORMAL".equals(fixture.caseType()) ? "NORMAL" : "SEED";
        String category = "NORMAL".equals(fixture.caseType()) ? "NORMAL_REGRESSION" : "FA-01";
        jdbcTemplate.update("""
                insert into test_suites (id, workspace_id, suite_key, version, fixture_version,
                   generation_config_json, suite_hash, status)
                values (?, ?, ?, '1.0.0', 'fixture-v1', '{}'::jsonb, ?, 'BUILDING')
                """, suite, AgentService.DEMO_WORKSPACE_ID, "frozen-trial-" + suite, HASH_A);
        jdbcTemplate.update("""
                insert into test_cases (id, suite_id, case_key, case_type, partition_name, category, severity,
                   delivery_channel, target_tool, payload_hash, preconditions_json, expected_invariant,
                   oracle_type, generation_source, expected_result_json, trial_policy_json)
                select ?, ?, ?, ?, ?, ?, severity, delivery_channel, target_tool, payload_hash,
                       preconditions_json, expected_invariant, ?, generation_source, expected_result_json,
                       trial_policy_json from test_cases where suite_id = ? and case_key = 'ATTESTATION-ATTACK-1'
                """, testCase, suite, caseKey, fixture.caseType(), partition, category,
                "NORMAL".equals(fixture.caseType()) ? "NORMAL_TASK" : "CROSS_CUSTOMER", originalSuite);
        jdbcTemplate.update("update test_suites set status = 'READY' where id = ?", suite);
        ((ObjectNode) snapshot.path("testSuite")).put("id", suite.toString());
        UUID run = effectSourceRun(snapshot, fixture.operationalError() ? "FAILED" : "COMPLETED", caseKey,
                (source, trial) -> { });
        UUID caseRun = jdbcTemplate.queryForObject("select id from test_case_runs where test_run_id = ?", UUID.class, run);
        Set<OracleOutcome> outcomes = fixture.inconclusive()
                ? Set.of(fixture.outcome(), OracleOutcome.INCONCLUSIVE) : Set.of(fixture.outcome());
        // Synthetic producer inputs exercise D's frozen numeric contract, not a B/Oracle runtime execution.
        TrialEvaluation evaluation = new TrialEvaluation(run, caseRun, "BASELINE", fixture.caseType(), category,
                "HIGH", fixture.operationalError() ? "ERROR" : "PASSED", outcomes, Set.of(),
                false, false, fixture.operationalError());
        var distribution = new TrialSuccessDistributionCalculator().calculate(List.of(
                new TrialSuccessDistributionCalculator.TrialSample(evaluation, testCase, caseKey, partition, 0)), Set.of());
        snapshot.set("trialSuccessDistribution", objectMapper.valueToTree(distribution));
        snapshot.set("attackRateBreakdown", objectMapper.valueToTree(new AttackRateBreakdownCalculator().calculate(distribution)));
        snapshot.set("completionRate", objectMapper.valueToTree(new CompletionRateCalculator().calculate(List.of(
                new CompletionRateCalculator.RunCounts(run, 1, 1, 1, 0)))));
    }

    private ObjectNode assertFrozenTrialControl(Seed seed, FrozenTrialFixture fixture) throws IOException {
        String before = frozenDecisionRow(seed);
        AttestationDto.View view = attestationService.findOrCreate(seed.releaseId(), "governance-reviewer");
        ObjectMapper precise = objectMapper.rebuild().enable(JsonNodeFeature.USE_BIG_DECIMAL_FOR_FLOATS).build();
        JsonNode source = precise.readTree(objectMapper.readTree(before).path("snapshot").asString());
        JsonNode projected = precise.readTree(objectMapper.writeValueAsBytes(view.document()));
        for (String field : AttestationDecisionMetricValidator.FIELDS) {
            assertThat(projected.path(field)).isEqualTo(source.path(field));
        }
        JsonNode bit = projected.at("/trialSuccessDistribution/cases/0/orderedTrials/0/successBit");
        if (fixture.bit() == null) {
            assertThat(bit.isNull()).isTrue();
            assertThat(projected.at("/trialSuccessDistribution/cases/0/status").asString()).isEqualTo("N_A");
            assertThat(projected.at("/trialSuccessDistribution/cases/0/excludedTrials").longValue()).isEqualTo(1);
            assertThat(projected.at("/trialSuccessDistribution/cases/0/orderedTrials/0/exclusionReason").asString())
                    .isEqualTo(fixture.reason());
        } else {
            assertThat(bit.longValue()).isEqualTo(fixture.bit().longValue());
            assertThat(projected.at("/trialSuccessDistribution/cases/0/status").asString()).isEqualTo("AVAILABLE");
        }
        assertThat(projected.at("/trialSuccessDistribution/cases/0/orderedTrials/0/secondaryInconclusive").asBoolean())
                .isEqualTo(fixture.inconclusive());
        assertThat(attestationService.findOrCreate(seed.releaseId(), "governance-reviewer").id()).isEqualTo(view.id());
        assertThat(attestationAuditCount(view.id())).isEqualTo(1);
        String after = frozenDecisionRow(seed);
        assertThat(after).isEqualTo(before);
        ObjectNode row = objectMapper.createObjectNode().put("caseType", fixture.caseType())
                .put("outcome", fixture.outcome().name()).put("secondaryInconclusive", fixture.inconclusive())
                .put("operationalError", fixture.operationalError()).put("generationAudits", 1);
        if (fixture.bit() == null) row.putNull("successBit"); else row.put("successBit", fixture.bit());
        row.set("decisionBefore", objectMapper.readTree(before));
        row.set("decisionAfter", objectMapper.readTree(after));
        row.set("projectedDistribution", projected.path("trialSuccessDistribution"));
        return row;
    }

    private String frozenDecisionRow(Seed seed) {
        return jdbcTemplate.queryForObject("""
                select jsonb_build_object('id', id, 'decision', decision, 'input_digest', input_digest,
                    'snapshot', input_snapshot_json::text, 'confirmed_at', confirmed_at)::text
                  from release_decisions where id = ?
                """, String.class, seed.decisionId());
    }

    private record FrozenTrialFixture(String caseType, OracleOutcome outcome, boolean inconclusive,
                                      boolean operationalError, Integer bit, String reason) { }

    private void replaceFirstSuccessBit(ObjectNode snapshot, BigInteger bit) {
        ((ObjectNode) snapshot.at("/trialSuccessDistribution/cases/0/orderedTrials/0")).put("successBit", bit);
        ((ObjectNode) snapshot.at("/trialSuccessDistribution/categories/0/orderedTrials/0")).put("successBit", bit);
        ((ArrayNode) snapshot.at("/trialSuccessDistribution/cases/0/successBits")).set(0, objectMapper.getNodeFactory().numberNode(bit));
        ((ArrayNode) snapshot.at("/trialSuccessDistribution/categories/0/successBits")).set(0, objectMapper.getNodeFactory().numberNode(bit));
    }

    private UUID insertAttestation(JdbcTemplate jdbc, Seed seed, ObjectNode document, String hash, String html) {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                insert into release_attestations (id, release_decision_id, format_version, document_json,
                  document_hash, html_content, generated_at, disclaimer_version)
                values (?, ?, '1.0', ?::jsonb, ?, ?, ?, 'finsec-internal/v1')
                """, id, seed.decisionId(), json(document), hash, html, Timestamp.from(seed.confirmedAt()));
        return id;
    }

    private Seed persistedSeed(Seed seed) throws IOException {
        String stored = jdbcTemplate.queryForObject("select input_snapshot_json::text from release_decisions where id = ?", String.class, seed.decisionId());
        return new Seed(seed.releaseId(), seed.decisionId(), seed.confirmedAt(), seed.inputDigest(),
                (ObjectNode) objectMapper.readTree(stored));
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
                statement.execute("alter table release_attestations disable trigger release_attestation_decision_metrics_guard");
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
                statement.execute("alter table release_attestations enable trigger release_attestation_decision_metrics_guard");
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
                "testSuite", "sandbox", "results", "metrics"
        }) {
            document.set(field, snapshot.path(field).deepCopy());
        }
        for (String field : AttestationDecisionMetricValidator.FIELDS) {
            if (snapshot.has(field)) document.set(field, snapshot.path(field).deepCopy());
        }
        if (snapshot.has("observedEffectCounts")) {
            document.set("observedEffectCounts", snapshot.path("observedEffectCounts").deepCopy());
        }
        if (snapshot.has("criticalInvariantAnySuccess")) {
            document.set("criticalInvariantAnySuccess", snapshot.path("criticalInvariantAnySuccess").deepCopy());
            document.set("criticalTrialCoverage", snapshot.path("criticalTrialCoverage").deepCopy());
        }
        document.set("remainingFindings", snapshot.path("remainingFindings").deepCopy());
        document.set("approvedPatch", snapshot.path("approvedPatch").deepCopy());
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

    @Test
    void preservesActualDNullReasonsAndSealedErrorCancelledReplayControls() throws Exception {
        List<SourceTrialFixture> fixtures = new ArrayList<>();
        for (String type : List.of("ATTACK", "NORMAL")) {
            fixtures.add(sourceTrial(type, "BASELINE", "PASSED", Set.of()));
            fixtures.add(sourceTrial(type, "BASELINE", "PASSED", Set.of(OracleOutcome.INCONCLUSIVE)));
            fixtures.add(sourceTrial(type, "SEAL_REPLAY", "PASSED", Set.of()));
            for (String status : List.of("ERROR", "CANCELLED")) {
                fixtures.add(sourceTrial(type, "BASELINE", status, Set.of()));
                fixtures.add(sourceTrial(type, "BASELINE", status, Set.of(OracleOutcome.INCONCLUSIVE)));
            }
        }
        ArrayNode accepted = objectMapper.createArrayNode();
        for (SourceTrialFixture fixture : fixtures) {
            Seed seed = seedDecision("source-null-control", false,
                    snapshot -> actualSourceMetricReports(snapshot, List.of(fixture), "FULL"));
            JsonNode trial = seed.snapshot().at("/trialSuccessDistribution/cases/0/orderedTrials/0");
            assertThat(trial.path("successBit").isNull()).isTrue();
            String reason = "CANCELLED".equals(fixture.status()) ? "CANCELLED"
                    : "ERROR".equals(fixture.status()) ? "OPERATIONAL_ERROR"
                    : "SEAL_REPLAY".equals(fixture.mode()) ? "REPLAY_NOT_COMPARABLE"
                    : fixture.outcomes().isEmpty() ? "MISSING_REQUIRED_ORACLE" : "INCONCLUSIVE_ORACLE";
            assertThat(trial.path("exclusionReason").asString()).isEqualTo(reason);
            assertThat(trial.path("secondaryInconclusive").asBoolean())
                    .isEqualTo(fixture.outcomes().contains(OracleOutcome.INCONCLUSIVE));
            accepted.add(assertSourceControl(seed, fixture.toString()));
        }
        saveSourceMatrix("null-priority-controls.json", accepted);
    }

    @Test
    void rejectsMatchingKnownNullFlagModeAndSealedPriorityContradictions() throws Exception {
        List<SourceMutation> mutations = new ArrayList<>();
        for (String type : List.of("ATTACK", "NORMAL")) {
            mutations.add(new SourceMutation("INC-false-" + type,
                    sourceTrial(type, "BASELINE", "PASSED", Set.of(OracleOutcome.INCONCLUSIVE)),
                    snapshot -> matchingSourceTrialField(snapshot, "secondaryInconclusive", false)));
            mutations.add(new SourceMutation("MISSING-true-" + type,
                    sourceTrial(type, "BASELINE", "PASSED", Set.of()),
                    snapshot -> matchingSourceTrialField(snapshot, "secondaryInconclusive", true)));
            mutations.add(new SourceMutation("BASELINE-replay-reason-" + type,
                    sourceTrial(type, "BASELINE", "PASSED", Set.of()),
                    snapshot -> matchingSourceTrialField(snapshot, "exclusionReason", "REPLAY_NOT_COMPARABLE")));
        }
        for (String status : List.of("ERROR", "CANCELLED")) {
            for (boolean secondary : List.of(false, true)) {
                SourceTrialFixture fixture = sourceTrial("ATTACK", "BASELINE", status,
                        secondary ? Set.of(OracleOutcome.INCONCLUSIVE) : Set.of());
                mutations.add(new SourceMutation(status + "-wrong-reason-" + secondary, fixture,
                        snapshot -> matchingSourceTrialField(snapshot, "exclusionReason",
                                secondary ? "INCONCLUSIVE_ORACLE" : "MISSING_REQUIRED_ORACLE")));
                mutations.add(new SourceMutation(status + "-nonnull-" + secondary, fixture,
                        snapshot -> coherentFirstSourceBit(snapshot, secondary ? 1 : 0)));
            }
        }
        for (String reason : List.of("CANCELLED", "NON_TERMINAL_CASE")) {
            mutations.add(new SourceMutation("PASSED-" + reason,
                    sourceTrial("ATTACK", "BASELINE", "PASSED", Set.of()),
                    snapshot -> matchingSourceTrialField(snapshot, "exclusionReason", reason)));
        }
        ArrayNode accepted = objectMapper.createArrayNode();
        ArrayNode rejected = objectMapper.createArrayNode();
        for (SourceMutation mutation : mutations) {
            Seed control = seedDecision("source-priority-negative-control", false,
                    snapshot -> actualSourceMetricReports(snapshot, List.of(mutation.fixture()), "FULL"));
            accepted.add(assertSourceControl(control, mutation.label()));
            Seed malformed = seedDecision("source-priority-negative", false, snapshot -> {
                actualSourceMetricReports(snapshot, List.of(mutation.fixture()), "FULL");
                mutation.mutation().accept(snapshot);
            });
            rejected.add(assertSourceRejection(malformed, mutation.label()));
        }
        saveSourceMatrix("null-priority-negative-controls.json", accepted);
        saveSourceMatrix("null-priority-rejections.json", rejected);
    }

    @Test
    void preservesStandaloneDObservedExcludedMixedAndEmptyDiagnosticSources() throws Exception {
        SourceTrialFixture zero = sourceTrial("ATTACK", "BASELINE", "PASSED", Set.of(OracleOutcome.ATTACK_BLOCKED));
        SourceTrialFixture one = sourceTrial("ATTACK", "BASELINE", "PASSED", Set.of(OracleOutcome.ATTACK_SUCCESS));
        SourceTrialFixture missing = sourceTrial("ATTACK", "BASELINE", "PASSED", Set.of());
        SourceTrialFixture replay = sourceTrial("ATTACK", "SEAL_REPLAY", "PASSED", Set.of());
        SourceTrialFixture normal = sourceTrial("NORMAL", "BASELINE", "PASSED", Set.of(OracleOutcome.NORMAL_SUCCESS));
        List<List<SourceTrialFixture>> fixtures = List.of(List.of(zero), List.of(one), List.of(missing),
                List.of(zero, missing), List.of(zero, replay), List.of(zero, one), List.of(normal));
        ArrayNode accepted = objectMapper.createArrayNode();
        for (List<SourceTrialFixture> fixture : fixtures) {
            Seed seed = seedDecision("standalone-source-control", false,
                    snapshot -> actualSourceMetricReports(snapshot, fixture, "STANDALONE"));
            JsonNode report = seed.snapshot().path("attackRateBreakdown");
            if (fixture.equals(List.of(missing))) {
                assertThat(report.at("/groups/0/sourceRunIds").isEmpty()).isTrue();
                assertThat(report.path("sourceRunIds").size()).isEqualTo(1);
                assertThat(report.at("/groups/0/numerator").isNull()).isTrue();
            }
            if (fixture.equals(List.of(zero, missing))) {
                assertThat(report.at("/groups/0/sourceRunIds").size()).isEqualTo(1);
                assertThat(report.path("sourceRunIds").size()).isEqualTo(2);
                assertThat(report.at("/groups/0/excludedTrials").longValue()).isEqualTo(1);
            }
            if (fixture.equals(List.of(zero, replay))) assertThat(report.path("groups").size()).isEqualTo(2);
            accepted.add(assertSourceControl(seed, fixture.toString()));
        }
        for (String diagnostic : List.of("INVALID_TRIAL_METADATA", "INVALID_TRIAL_DISTRIBUTION")) {
            Seed seed = seedDecision("standalone-diagnostic-control", false,
                    snapshot -> actualSourceMetricReports(snapshot, List.of(zero), diagnostic));
            assertThat(seed.snapshot().at("/attackRateBreakdown/reason").asString()).isEqualTo(diagnostic);
            assertThat(seed.snapshot().at("/attackRateBreakdown/groups").isEmpty()).isTrue();
            accepted.add(assertSourceControl(seed, diagnostic));
        }
        saveSourceMatrix("standalone-controls.json", accepted);
    }

    @Test
    void rejectsStandaloneDimensionNormalOriginsAndEveryConclusiveGroupSource() throws Exception {
        SourceTrialFixture zero = sourceTrial("ATTACK", "BASELINE", "PASSED", Set.of(OracleOutcome.ATTACK_BLOCKED));
        SourceTrialFixture missing = sourceTrial("ATTACK", "BASELINE", "PASSED", Set.of());
        SourceTrialFixture normal = sourceTrial("NORMAL", "BASELINE", "PASSED", Set.of(OracleOutcome.NORMAL_FAILURE));
        SourceTrialFixture heldOut = new SourceTrialFixture("ATTACK", "BASELINE", "PASSED",
                Set.of(OracleOutcome.ATTACK_BLOCKED), "HELD_OUT");
        ArrayNode accepted = objectMapper.createArrayNode();
        ArrayNode rejected = objectMapper.createArrayNode();
        for (SourceTrialFixture fixture : List.of(zero, missing)) {
            for (String field : List.of("mode", "category", "partition")) {
                String wrong = "mode".equals(field) ? "SEAL_REPLAY" : "category".equals(field) ? "FA-02" : "HELD_OUT";
                String label = fixture.outcomes().isEmpty() ? "N_A-" + field : "AVAILABLE-" + field;
                Seed control = seedDecision("dimension-negative-control", false,
                        snapshot -> actualSourceMetricReports(snapshot, List.of(fixture), "STANDALONE"));
                accepted.add(assertSourceControl(control, label));
                Seed malformed = seedDecision("dimension-negative", false, snapshot -> {
                    actualSourceMetricReports(snapshot, List.of(fixture), "STANDALONE");
                    ((ObjectNode) snapshot.at("/attackRateBreakdown/groups/0")).put(field, wrong);
                });
                rejected.add(assertSourceRejection(malformed, label));
            }
        }
        for (boolean normalOnly : List.of(false, true)) {
            List<SourceTrialFixture> fixtures = List.of(zero, normal);
            Seed control = seedDecision("normal-origin-negative-control", false,
                    snapshot -> actualSourceMetricReports(snapshot, fixtures, "STANDALONE"));
            accepted.add(assertSourceControl(control, "NORMAL-origin-" + normalOnly));
            Seed malformed = seedDecision("normal-origin-negative", false, snapshot -> {
                actualSourceMetricReports(snapshot, fixtures, "STANDALONE");
                UUID normalRun = jdbcTemplate.queryForObject("""
                        select run.id from test_runs run join test_case_runs trial on trial.test_run_id=run.id
                        join test_cases test_case on test_case.id=trial.test_case_id
                        where run.release_id=? and test_case.case_type='NORMAL'
                        """, UUID.class, UUID.fromString(snapshot.at("/release/id").asString()));
                ObjectNode report = (ObjectNode) snapshot.path("attackRateBreakdown");
                if (normalOnly) {
                    ids(report, "sourceRunIds", List.of(normalRun));
                    ObjectNode group = (ObjectNode) report.path("groups").get(0);
                    group.put("category", "NORMAL_REGRESSION").put("partition", "NORMAL");
                    ids(group, "sourceRunIds", List.of(normalRun));
                } else ((ArrayNode) report.path("sourceRunIds")).add(normalRun.toString());
            });
            rejected.add(assertSourceRejection(malformed, "NORMAL-origin-" + normalOnly));
        }
        List<SourceTrialFixture> multiple = List.of(zero, zero, heldOut);
        Seed control = seedDecision("multiple-source-negative-control", false,
                snapshot -> actualSourceMetricReports(snapshot, multiple, "STANDALONE"));
        accepted.add(assertSourceControl(control, "second-source-wrong-partition"));
        Seed malformed = seedDecision("multiple-source-negative", false, snapshot -> {
            actualSourceMetricReports(snapshot, multiple, "STANDALONE");
            ObjectNode report = (ObjectNode) snapshot.path("attackRateBreakdown");
            ObjectNode seedGroup = null;
            String heldOutRun = null;
            for (JsonNode group : report.path("groups")) {
                if ("SEED".equals(group.path("partition").asString())) seedGroup = (ObjectNode) group;
                else heldOutRun = group.at("/sourceRunIds/0").asString();
            }
            assertThat(seedGroup).isNotNull();
            assertThat(seedGroup.path("sourceRunIds").size()).isEqualTo(2);
            ((ArrayNode) seedGroup.path("sourceRunIds")).set(1, objectMapper.getNodeFactory().stringNode(heldOutRun));
        });
        rejected.add(assertSourceRejection(malformed, "second-source-wrong-partition"));
        saveSourceMatrix("standalone-negative-controls.json", accepted);
        saveSourceMatrix("standalone-rejections.json", rejected);
    }

    private SourceTrialFixture sourceTrial(String type, String mode, String status, Set<OracleOutcome> outcomes) {
        return new SourceTrialFixture(type, mode, status, outcomes, "NORMAL".equals(type) ? "NORMAL" : "SEED");
    }

    private void actualSourceMetricReports(ObjectNode snapshot, List<SourceTrialFixture> fixtures, String shape) {
        unavailableMetricReports(snapshot);
        UUID originalSuite = UUID.fromString(snapshot.at("/testSuite/id").asString());
        UUID suite = UUID.randomUUID();
        jdbcTemplate.update("""
                insert into test_suites (id, workspace_id, suite_key, version, fixture_version,
                    generation_config_json, suite_hash, status)
                values (?, ?, ?, '1.0.0', 'fixture-v1', '{}'::jsonb, ?, 'BUILDING')
                """, suite, AgentService.DEMO_WORKSPACE_ID, "source-contract-" + suite, HASH_A);
        List<UUID> testCases = new ArrayList<>();
        for (int index = 0; index < fixtures.size(); index++) {
            SourceTrialFixture fixture = fixtures.get(index);
            UUID testCase = UUID.randomUUID();
            testCases.add(testCase);
            jdbcTemplate.update("""
                    insert into test_cases (id, suite_id, case_key, case_type, partition_name, category, severity,
                        delivery_channel, target_tool, payload_hash, preconditions_json, expected_invariant,
                        oracle_type, generation_source, expected_result_json, trial_policy_json)
                    select ?, ?, ?, ?, ?, ?, severity, delivery_channel, target_tool, payload_hash,
                        preconditions_json, expected_invariant, ?, generation_source, expected_result_json,
                        trial_policy_json from test_cases where suite_id=? and case_key='ATTESTATION-ATTACK-1'
                    """, testCase, suite, "SOURCE-" + index, fixture.caseType(), fixture.partition(),
                    "NORMAL".equals(fixture.caseType()) ? "NORMAL_REGRESSION" : "FA-01",
                    "NORMAL".equals(fixture.caseType()) ? "NORMAL_TASK" : "CROSS_CUSTOMER", originalSuite);
        }
        jdbcTemplate.update("update test_suites set status='READY' where id=?", suite);
        ((ObjectNode) snapshot.path("testSuite")).put("id", suite.toString());
        List<TrialSuccessDistributionCalculator.TrialSample> samples = new ArrayList<>();
        List<CompletionRateCalculator.RunCounts> counts = new ArrayList<>();
        for (int index = 0; index < fixtures.size(); index++) {
            SourceTrialFixture fixture = fixtures.get(index);
            UUID testCase = testCases.get(index);
            SourceRun source = sealedSourceRun(snapshot, testCase, fixture.mode(), fixture.status());
            TrialEvaluation evaluation = new TrialEvaluation(source.runId(), source.caseRunId(), fixture.mode(),
                    fixture.caseType(), "NORMAL".equals(fixture.caseType()) ? "NORMAL_REGRESSION" : "FA-01",
                    "HIGH", fixture.status(), fixture.outcomes(), Set.of(), false, false,
                    Set.of("ERROR", "CANCELLED").contains(fixture.status()));
            samples.add(new TrialSuccessDistributionCalculator.TrialSample(evaluation, testCase,
                    "SOURCE-" + index, fixture.partition(), 0));
            boolean cancelled = "CANCELLED".equals(fixture.status());
            counts.add(new CompletionRateCalculator.RunCounts(source.runId(), 1, 1, cancelled ? 0 : 1, cancelled ? 1 : 0));
        }
        // These are unchanged D calculators with synthetic producer inputs and immutable DB source identity.
        var distribution = new TrialSuccessDistributionCalculator().calculate(samples, Set.of());
        var breakdownInput = distribution;
        if ("INVALID_TRIAL_METADATA".equals(shape)) {
            distribution = new TrialSuccessDistributionCalculator().calculate(List.of(samples.get(0), samples.get(0)), Set.of());
            breakdownInput = distribution;
        } else if ("INVALID_TRIAL_DISTRIBUTION".equals(shape)) {
            breakdownInput = new TrialSuccessDistributionCalculator.Report(distribution.status(), distribution.reason(),
                    List.of(distribution.cases().getFirst(), distribution.cases().getFirst()),
                    distribution.categories(), distribution.sourceRunIds());
        }
        snapshot.set("trialSuccessDistribution", objectMapper.valueToTree(distribution));
        snapshot.set("attackRateBreakdown", objectMapper.valueToTree(new AttackRateBreakdownCalculator().calculate(breakdownInput)));
        snapshot.set("completionRate", objectMapper.valueToTree(new CompletionRateCalculator().calculate(counts)));
        if (!"FULL".equals(shape)) snapshot.remove("trialSuccessDistribution");
    }

    private SourceRun sealedSourceRun(ObjectNode snapshot, UUID testCase, String mode, String childStatus) {
        UUID release = UUID.fromString(snapshot.at("/release/id").asString());
        UUID contractVersion = null;
        if ("SEAL_REPLAY".equals(mode)) {
            UUID contract = UUID.randomUUID();
            contractVersion = UUID.randomUUID();
            jdbcTemplate.update("""
                    insert into safety_contracts (id,workspace_id,release_id,contract_key,status)
                    values (?,?,?,?,'APPROVED')
                    """, contract, AgentService.DEMO_WORKSPACE_ID, release, "source-contract-" + contract);
            jdbcTemplate.update("""
                    insert into safety_contract_versions (id,contract_id,version,state,policy_json,policy_hash,
                        validation_json,created_by,approved_by,approved_at)
                    values (?,?,1,'APPROVED','{}'::jsonb,?,'{}'::jsonb,'test','test',now())
                    """, contractVersion, contract, HASH_A);
        }
        UUID run = UUID.randomUUID();
        UUID trial = UUID.randomUUID();
        UUID trace = UUID.randomUUID();
        jdbcTemplate.update("""
                insert into test_runs (id,release_id,suite_id,contract_version_id,mode,status,
                    agent_artifact_fingerprint,release_fingerprint,config_json,fixture_version,fixture_digest,
                    model_config_hash,total_cases)
                values (?,?,?,?,?,'QUEUED',?,?,'{}'::jsonb,?,?,?,1)
                """, run, release, UUID.fromString(snapshot.at("/testSuite/id").asString()), contractVersion, mode,
                snapshot.at("/release/agentArtifactFingerprint").asString(), snapshot.at("/release/fingerprint").asString(),
                snapshot.at("/sandbox/fixtureVersion").asString(), snapshot.at("/sandbox/fixtureDigest").asString(), HASH_A);
        jdbcTemplate.update("insert into run_event_counters (run_id,last_sequence) values (?,0)", run);
        eventService.append(run, new ExecutionEventDto.AppendRequest(null, trace, ExecutionEventType.RUN_STARTED,
                null, null, null, null, "RUN_STARTED", objectMapper.createObjectNode()), "attestation-test");
        jdbcTemplate.update("update test_runs set status='PREPARING' where id=?", run);
        jdbcTemplate.update("update test_runs set status='RUNNING',started_at=now() where id=?", run);
        jdbcTemplate.update("""
                insert into test_case_runs (id,test_run_id,test_case_id,trial_index,status,variant_hash)
                values (?,?,?,0,'EXECUTING',?)
                """, trial, run, testCase, HASH_A);
        jdbcTemplate.update("update test_case_runs set status=?,completed_at=now() where id=?", childStatus, trial);
        boolean failed = Set.of("ERROR", "CANCELLED").contains(childStatus);
        eventService.append(run, new ExecutionEventDto.AppendRequest(null, trace,
                failed ? ExecutionEventType.RUN_FAILED : ExecutionEventType.RUN_COMPLETED,
                null, null, null, null, failed ? "RUN_FAILED" : "RUN_COMPLETED", objectMapper.createObjectNode()), "attestation-test");
        jdbcTemplate.update("""
                update test_runs set status=?,completed_cases=1,operational_error_count=?,completed_at=now() where id=?
                """, failed ? "FAILED" : "COMPLETED", "ERROR".equals(childStatus) ? 1 : 0, run);
        return new SourceRun(run, trial);
    }

    private void matchingSourceTrialField(ObjectNode snapshot, String field, Object value) {
        for (String collection : List.of("cases", "categories")) {
            ObjectNode trial = (ObjectNode) snapshot.at("/trialSuccessDistribution/" + collection + "/0/orderedTrials/0");
            if (value instanceof Boolean flag) trial.put(field, flag);
            else trial.put(field, (String) value);
        }
    }

    private void coherentFirstSourceBit(ObjectNode snapshot, int bit) {
        for (String collection : List.of("cases", "categories")) {
            ObjectNode item = (ObjectNode) snapshot.at("/trialSuccessDistribution/" + collection + "/0");
            ObjectNode trial = (ObjectNode) item.at("/orderedTrials/0");
            trial.put("successBit", bit).putNull("exclusionReason");
            item.putArray("successBits").add(bit);
            item.put("status", "AVAILABLE").putNull("reason").put("successCount", bit).put("trials", 1).put("excludedTrials", 0);
        }
        ((ObjectNode) snapshot.path("trialSuccessDistribution")).put("status", "AVAILABLE").putNull("reason");
        ObjectNode breakdown = (ObjectNode) snapshot.path("attackRateBreakdown");
        ObjectNode group = (ObjectNode) breakdown.path("groups").get(0);
        breakdown.put("status", "AVAILABLE").putNull("reason");
        group.put("status", "AVAILABLE").putNull("reason").put("numerator", bit).put("denominator", 1)
                .put("value", bit).put("anySuccess", bit == 1).put("excludedTrials", 0);
        group.set("sourceRunIds", breakdown.path("sourceRunIds").deepCopy());
    }

    private ObjectNode assertSourceControl(Seed seed, String label) throws IOException {
        String before = frozenDecisionRow(seed);
        AttestationDto.View view = attestationService.findOrCreate(seed.releaseId(), "governance-reviewer");
        ObjectMapper precise = objectMapper.rebuild().enable(JsonNodeFeature.USE_BIG_DECIMAL_FOR_FLOATS).build();
        JsonNode source = precise.readTree(objectMapper.readTree(before).path("snapshot").asString());
        JsonNode projected = precise.readTree(objectMapper.writeValueAsBytes(view.document()));
        for (String field : AttestationDecisionMetricValidator.FIELDS) {
            assertThat(projected.path(field)).isEqualTo(source.path(field));
        }
        assertThat(attestationService.findOrCreate(seed.releaseId(), "governance-reviewer").id()).isEqualTo(view.id());
        assertThat(attestationAuditCount(view.id())).isEqualTo(1);
        assertThat(frozenDecisionRow(seed)).isEqualTo(before);
        ObjectNode row = objectMapper.createObjectNode().put("label", label).put("attestations", 1).put("generationAudits", 1);
        row.set("decisionBefore", objectMapper.readTree(before));
        row.set("decisionAfter", objectMapper.readTree(frozenDecisionRow(seed)));
        row.set("projectedReports", projected);
        row.set("immutableSources", sourceIdentityRows(seed));
        return row;
    }

    private ObjectNode assertSourceRejection(Seed seed, String label) throws IOException {
        JsonNode snapshot = seed.snapshot();
        assertThat(seed.inputDigest()).isEqualTo(digestService.sha256(canonicalJsonService.canonicalize(snapshot)));
        if (snapshot.has("trialSuccessDistribution")) {
            JsonNode item = snapshot.at("/trialSuccessDistribution/cases/0");
            JsonNode category = snapshot.at("/trialSuccessDistribution/categories/0");
            assertThat(item.path("orderedTrials")).isEqualTo(category.path("orderedTrials"));
            assertThat(item.path("successBits")).isEqualTo(category.path("successBits"));
            for (String field : List.of("status", "reason", "successCount", "trials", "excludedTrials")) {
                assertThat(item.path(field)).isEqualTo(category.path(field));
            }
        }
        for (String field : AttestationDecisionMetricValidator.FIELDS) {
            if (!snapshot.has(field)) continue;
            for (JsonNode id : snapshot.path(field).path("sourceRunIds")) {
                assertThat(jdbcTemplate.queryForObject("""
                        select count(*) from test_runs where id=? and release_id=? and suite_id=?
                          and mode in ('BASELINE','SEAL_REPLAY') and status in ('COMPLETED','FAILED')
                          and fixture_version=? and fixture_digest=? and agent_artifact_fingerprint=? and release_fingerprint=?
                        """, Integer.class, UUID.fromString(id.asString()), seed.releaseId(),
                        UUID.fromString(snapshot.at("/testSuite/id").asString()),
                        snapshot.at("/sandbox/fixtureVersion").asString(), snapshot.at("/sandbox/fixtureDigest").asString(),
                        snapshot.at("/release/agentArtifactFingerprint").asString(), snapshot.at("/release/fingerprint").asString()))
                        .isEqualTo(1);
            }
        }
        String before = frozenDecisionRow(seed);
        assertIncompleteAttestation(seed);
        assertThat(frozenDecisionRow(seed)).isEqualTo(before);
        ObjectNode row = objectMapper.createObjectNode().put("label", label).put("attestations", 0).put("generationAudits", 0);
        row.set("decisionBefore", objectMapper.readTree(before));
        row.set("decisionAfter", objectMapper.readTree(frozenDecisionRow(seed)));
        row.set("immutableSources", sourceIdentityRows(seed));
        return row;
    }

    private JsonNode sourceIdentityRows(Seed seed) throws IOException {
        String rows = jdbcTemplate.queryForObject("""
                select coalesce(jsonb_agg(jsonb_build_object('runId',run.id,'mode',run.mode,'runStatus',run.status,
                    'caseRunId',trial.id,'caseStatus',trial.status,'testCaseId',test_case.id,'caseType',test_case.case_type,
                    'category',test_case.category,'partition',test_case.partition_name,'suiteId',run.suite_id)), '[]'::jsonb)::text
                from test_runs run join test_case_runs trial on trial.test_run_id=run.id
                join test_cases test_case on test_case.id=trial.test_case_id where run.release_id=?
                """, String.class, seed.releaseId());
        return objectMapper.readTree(rows);
    }

    private void saveSourceMatrix(String filename, JsonNode rows) throws IOException {
        Path directory = Path.of("build", "test-evidence", "attestation-source-contract");
        Files.createDirectories(directory);
        Files.writeString(directory.resolve(filename), objectMapper.writeValueAsString(rows));
    }

    private record SourceTrialFixture(String caseType, String mode, String status, Set<OracleOutcome> outcomes,
                                      String partition) { }
    private record SourceMutation(String label, SourceTrialFixture fixture, Consumer<ObjectNode> mutation) { }
    private record SourceRun(UUID runId, UUID caseRunId) { }

    // BEGIN additive standalone conclusive-witness unit; earlier test/helper bytes stay unchanged.
    @Test
    void preservesStandaloneConclusiveEligibleStatusesMixedChildrenAndDistinctRunCardinality() throws Exception {
        ArrayNode accepted = objectMapper.createArrayNode();
        for (WitnessScenario scenario : witnessScenarios()) {
            if (scenario.forgedDenominator() != 0) continue;
            Seed seed = seedDecision("conclusive-witness-control", false,
                    snapshot -> actualWitnessMetricReports(snapshot, scenario.runs()));
            assertWitnessNormalReport(seed, scenario);
            JsonNode graph = assertWitnessGraph(seed, scenario);
            ObjectNode row = assertSourceControl(seed, scenario.label());
            row.set("fixtureGraph", graph);
            accepted.add(row);
        }
        saveWitnessControls(accepted);
    }

    @Test
    void rejectsStandaloneConclusiveExcludedOnlyWrongChildAndEveryDeclaredSource() throws Exception {
        ArrayNode accepted = objectMapper.createArrayNode();
        ArrayNode rejected = objectMapper.createArrayNode();
        for (WitnessScenario scenario : witnessScenarios()) {
            if (scenario.forgedDenominator() == 0) continue;
            Seed control = seedDecision("conclusive-witness-negative-control", false,
                    snapshot -> actualWitnessMetricReports(snapshot, scenario.runs()));
            assertWitnessNormalReport(control, scenario);
            JsonNode controlGraph = assertWitnessGraph(control, scenario);
            ObjectNode normal = assertSourceControl(control, scenario.label() + "-control");
            normal.set("fixtureGraph", controlGraph);
            accepted.add(normal);
            Seed malformed = seedDecision("conclusive-witness-negative", false, snapshot -> {
                List<UUID> declaredRuns = actualWitnessMetricReports(snapshot, scenario.runs());
                ObjectNode report = (ObjectNode) snapshot.path("attackRateBreakdown");
                ObjectNode group = witnessTargetGroup(snapshot);
                report.put("status", "AVAILABLE").putNull("reason");
                group.put("status", "AVAILABLE").putNull("reason").put("numerator", 0)
                        .put("denominator", scenario.forgedDenominator()).put("value", 0)
                        .put("anySuccess", false).put("excludedTrials", scenario.forgedExcluded());
                // Fixture order deliberately declares E before the ineligible second source in W10/W11.
                ArrayNode declaredSources = group.putArray("sourceRunIds");
                for (UUID run : declaredRuns) declaredSources.add(run.toString());
            });
            JsonNode graph = assertWitnessGraph(malformed, scenario);
            if (scenario.label().startsWith("W10") || scenario.label().startsWith("W11")) {
                JsonNode group = witnessTargetGroup(malformed.snapshot());
                assertThat(group.path("sourceRunIds")).isEqualTo(objectMapper.createArrayNode()
                        .add(graph.at("/0/id").asString()).add(graph.at("/1/id").asString()));
                assertThat(graph.at("/0/mode").asString()).isEqualTo(group.path("mode").asString());
                assertThat(graph.at("/1/mode").asString()).isEqualTo(group.path("mode").asString());
                assertThat(graph.at("/0/children").size()).isEqualTo(1);
                assertThat(graph.at("/1/children").size()).isEqualTo(1);
                JsonNode first = graph.at("/0/children/0");
                JsonNode last = graph.at("/1/children/0");
                for (JsonNode child : List.of(first, last)) {
                    assertThat(child.path("case_type").asString()).isEqualTo("ATTACK");
                    assertThat(child.path("category").asString()).isEqualTo(group.path("category").asString());
                    assertThat(child.path("partition_name").asString()).isEqualTo(group.path("partition").asString());
                }
                assertThat(first.path("status").asString()).isEqualTo("PASSED");
                assertThat(last.path("status").asString())
                        .isEqualTo(scenario.label().startsWith("W10") ? "ERROR" : "CANCELLED");
            }
            ObjectNode row = assertSourceRejection(malformed, scenario.label());
            row.set("fixtureGraph", graph);
            row.set("declaredBreakdown", malformed.snapshot().path("attackRateBreakdown").deepCopy());
            row.put("normalCounterpartLabel", scenario.label() + "-control");
            rejected.add(row);
        }
        saveWitnessControls(accepted);
        saveSourceMatrix("standalone-conclusive-witness-rejections.json", rejected);
    }

    private List<WitnessScenario> witnessScenarios() {
        WitnessCaseFixture passed = witnessAttack("PASSED", OracleOutcome.ATTACK_BLOCKED);
        WitnessCaseFixture security = witnessAttack("FAILED_SECURITY", OracleOutcome.ATTACK_SUCCESS);
        WitnessCaseFixture functional = witnessAttack("FAILED_FUNCTIONAL", OracleOutcome.ATTACK_BLOCKED);
        WitnessCaseFixture error = witnessAttack("ERROR", null);
        WitnessCaseFixture cancelled = witnessAttack("CANCELLED", null);
        WitnessCaseFixture heldOut = new WitnessCaseFixture("ATTACK", "FA-01", "HELD_OUT", "PASSED",
                Set.of(OracleOutcome.ATTACK_BLOCKED));
        WitnessCaseFixture otherCategory = new WitnessCaseFixture("ATTACK", "FA-02", "SEED", "PASSED",
                Set.of(OracleOutcome.ATTACK_BLOCKED));
        WitnessCaseFixture normal = new WitnessCaseFixture("NORMAL", "NORMAL_REGRESSION", "NORMAL", "PASSED",
                Set.of(OracleOutcome.NORMAL_SUCCESS));
        return List.of(
                new WitnessScenario("W01-PASSED", List.of(witnessRun(passed)), 0, 1, 0, 0, 0),
                new WitnessScenario("W02-FAILED_SECURITY", List.of(witnessRun(security)), 1, 1, 0, 0, 0),
                new WitnessScenario("W03-FAILED_FUNCTIONAL", List.of(witnessRun(functional)), 0, 1, 0, 0, 0),
                new WitnessScenario("W04-ERROR-only", List.of(witnessRun(error, error)), 0, 0, 2, 1, 1),
                new WitnessScenario("W05-CANCELLED-only", List.of(witnessRun(cancelled, cancelled)), 0, 0, 2, 1, 1),
                new WitnessScenario("W06-PASSED-ERROR-mixed", List.of(witnessRun(passed, error)), 0, 1, 1, 0, 0),
                new WitnessScenario("W07-SECURITY-CANCELLED-mixed", List.of(witnessRun(security, cancelled)), 1, 1, 1, 0, 0),
                new WitnessScenario("W08-eligible-other-partition", List.of(witnessRun(error, heldOut)), 0, 0, 1, 1, 0),
                new WitnessScenario("W09-eligible-other-category", List.of(witnessRun(error, otherCategory)), 0, 0, 1, 1, 0),
                new WitnessScenario("W10-second-source-ERROR", List.of(witnessRun(passed), witnessRun(error)), 0, 1, 1, 2, 0),
                new WitnessScenario("W11-second-source-CANCELLED", List.of(witnessRun(passed), witnessRun(cancelled)), 0, 1, 1, 2, 0),
                new WitnessScenario("W12-eligible-NORMAL-only", List.of(witnessRun(error, normal)), 0, 0, 1, 1, 0),
                new WitnessScenario("W13-two-eligible-one-Run", List.of(witnessRun(passed, passed)), 0, 2, 0, 0, 0));
    }

    private WitnessCaseFixture witnessAttack(String status, OracleOutcome outcome) {
        return new WitnessCaseFixture("ATTACK", "FA-01", "SEED", status,
                outcome == null ? Set.of() : Set.of(outcome));
    }

    private WitnessRunFixture witnessRun(WitnessCaseFixture... children) {
        return new WitnessRunFixture(List.of(children));
    }

    private List<UUID> actualWitnessMetricReports(ObjectNode snapshot, List<WitnessRunFixture> fixtures) {
        unavailableMetricReports(snapshot);
        UUID originalSuite = UUID.fromString(snapshot.at("/testSuite/id").asString());
        UUID suite = UUID.randomUUID();
        jdbcTemplate.update("""
                insert into test_suites (id,workspace_id,suite_key,version,fixture_version,
                    generation_config_json,suite_hash,status)
                values (?,?,?,'1.0.0','fixture-v1','{}'::jsonb,?,'BUILDING')
                """, suite, AgentService.DEMO_WORKSPACE_ID, "conclusive-witness-" + suite, HASH_A);
        List<List<UUID>> cases = new ArrayList<>();
        for (int runIndex = 0; runIndex < fixtures.size(); runIndex++) {
            List<UUID> children = new ArrayList<>();
            List<WitnessCaseFixture> childFixtures = fixtures.get(runIndex).children();
            for (int childIndex = 0; childIndex < childFixtures.size(); childIndex++) {
                WitnessCaseFixture fixture = childFixtures.get(childIndex);
                UUID testCase = UUID.randomUUID();
                children.add(testCase);
                jdbcTemplate.update("""
                        insert into test_cases (id,suite_id,case_key,case_type,partition_name,category,severity,
                            delivery_channel,target_tool,payload_hash,preconditions_json,expected_invariant,
                            oracle_type,generation_source,expected_result_json,trial_policy_json)
                        select ?,?,?,?,?,?,severity,delivery_channel,target_tool,payload_hash,preconditions_json,
                            expected_invariant,?,generation_source,expected_result_json,trial_policy_json
                        from test_cases where suite_id=? and case_key='ATTESTATION-ATTACK-1'
                        """, testCase, suite, "WITNESS-" + runIndex + "-" + childIndex,
                        fixture.caseType(), fixture.partition(), fixture.category(),
                        "NORMAL".equals(fixture.caseType()) ? "NORMAL_TASK" : "CROSS_CUSTOMER", originalSuite);
            }
            cases.add(children);
        }
        jdbcTemplate.update("update test_suites set status='READY' where id=?", suite);
        ((ObjectNode) snapshot.path("testSuite")).put("id", suite.toString());
        List<UUID> runIds = new ArrayList<>();
        List<TrialSuccessDistributionCalculator.TrialSample> samples = new ArrayList<>();
        List<CompletionRateCalculator.RunCounts> counts = new ArrayList<>();
        for (int runIndex = 0; runIndex < fixtures.size(); runIndex++) {
            List<WitnessCaseFixture> children = fixtures.get(runIndex).children();
            WitnessRunSource source = sealedWitnessRun(snapshot, cases.get(runIndex), children);
            runIds.add(source.runId());
            for (int childIndex = 0; childIndex < children.size(); childIndex++) {
                WitnessCaseFixture fixture = children.get(childIndex);
                TrialEvaluation evaluation = new TrialEvaluation(source.runId(), source.caseRunIds().get(childIndex),
                        "BASELINE", fixture.caseType(), fixture.category(), "HIGH", fixture.status(), fixture.outcomes(),
                        Set.of(), false, false, Set.of("ERROR", "CANCELLED").contains(fixture.status()));
                samples.add(new TrialSuccessDistributionCalculator.TrialSample(evaluation, cases.get(runIndex).get(childIndex),
                        "WITNESS-" + runIndex + "-" + childIndex, fixture.partition(), 0));
            }
            long cancelled = children.stream().filter(child -> "CANCELLED".equals(child.status())).count();
            counts.add(new CompletionRateCalculator.RunCounts(source.runId(), children.size(), children.size(),
                    children.size() - cancelled, cancelled));
        }
        var distribution = new TrialSuccessDistributionCalculator().calculate(samples, Set.of());
        snapshot.set("attackRateBreakdown", objectMapper.valueToTree(new AttackRateBreakdownCalculator().calculate(distribution)));
        snapshot.set("completionRate", objectMapper.valueToTree(new CompletionRateCalculator().calculate(counts)));
        // SQL DB-trigger fixture seam: this does not prove public runnable Release/B execution admission.
        snapshot.remove("trialSuccessDistribution");
        return runIds;
    }

    private WitnessRunSource sealedWitnessRun(ObjectNode snapshot, List<UUID> testCases,
                                              List<WitnessCaseFixture> children) {
        UUID run = UUID.randomUUID();
        UUID trace = UUID.randomUUID();
        jdbcTemplate.update("""
                insert into test_runs (id,release_id,suite_id,contract_version_id,mode,status,
                    agent_artifact_fingerprint,release_fingerprint,config_json,fixture_version,fixture_digest,
                    model_config_hash,total_cases)
                values (?,?,?,null,'BASELINE','QUEUED',?,?,'{}'::jsonb,?,?,?,?)
                """, run, UUID.fromString(snapshot.at("/release/id").asString()),
                UUID.fromString(snapshot.at("/testSuite/id").asString()),
                snapshot.at("/release/agentArtifactFingerprint").asString(), snapshot.at("/release/fingerprint").asString(),
                snapshot.at("/sandbox/fixtureVersion").asString(), snapshot.at("/sandbox/fixtureDigest").asString(),
                HASH_A, children.size());
        jdbcTemplate.update("insert into run_event_counters (run_id,last_sequence) values (?,0)", run);
        eventService.append(run, new ExecutionEventDto.AppendRequest(null, trace, ExecutionEventType.RUN_STARTED,
                null, null, null, null, "RUN_STARTED", objectMapper.createObjectNode()), "attestation-test");
        jdbcTemplate.update("update test_runs set status='PREPARING' where id=?", run);
        jdbcTemplate.update("update test_runs set status='RUNNING',started_at=now() where id=?", run);
        List<UUID> trials = new ArrayList<>();
        for (UUID testCase : testCases) {
            UUID trial = UUID.randomUUID();
            trials.add(trial);
            jdbcTemplate.update("""
                    insert into test_case_runs (id,test_run_id,test_case_id,trial_index,status,variant_hash)
                    values (?,?,?,0,'EXECUTING',?)
                    """, trial, run, testCase, HASH_A);
        }
        for (int index = 0; index < children.size(); index++) {
            jdbcTemplate.update("update test_case_runs set status=?,completed_at=now() where id=?",
                    children.get(index).status(), trials.get(index));
        }
        boolean failed = children.stream().anyMatch(child -> Set.of("ERROR", "CANCELLED").contains(child.status()));
        long errors = children.stream().filter(child -> "ERROR".equals(child.status())).count();
        eventService.append(run, new ExecutionEventDto.AppendRequest(null, trace,
                failed ? ExecutionEventType.RUN_FAILED : ExecutionEventType.RUN_COMPLETED,
                null, null, null, null, failed ? "RUN_FAILED" : "RUN_COMPLETED", objectMapper.createObjectNode()), "attestation-test");
        jdbcTemplate.update("""
                update test_runs set status=?,completed_cases=?,operational_error_count=?,completed_at=now() where id=?
                """, failed ? "FAILED" : "COMPLETED", children.size(), errors, run);
        return new WitnessRunSource(run, trials);
    }

    private ObjectNode witnessTargetGroup(JsonNode snapshot) {
        for (JsonNode group : snapshot.at("/attackRateBreakdown/groups")) {
            if ("BASELINE".equals(group.path("mode").asString()) && "FA-01".equals(group.path("category").asString())
                    && "SEED".equals(group.path("partition").asString())) return (ObjectNode) group;
        }
        throw new AssertionError("Actual D target ATTACK dimension is missing");
    }

    private void assertWitnessNormalReport(Seed seed, WitnessScenario scenario) {
        assertThat(seed.snapshot().has("trialSuccessDistribution")).isFalse();
        JsonNode report = seed.snapshot().path("attackRateBreakdown");
        JsonNode group = witnessTargetGroup(seed.snapshot());
        assertThat(report.path("sourceRunIds").size()).isEqualTo(scenario.runs().size());
        assertThat(report.path("groups").size()).isEqualTo(scenario.label().startsWith("W08") || scenario.label().startsWith("W09") ? 2 : 1);
        assertThat(group.path("excludedTrials").longValue()).isEqualTo(scenario.excluded());
        if (scenario.denominator() == 0) {
            assertThat(group.path("status").asString()).isEqualTo("N_A");
            assertThat(group.path("sourceRunIds").isEmpty()).isTrue();
            for (String field : List.of("numerator", "denominator", "value", "anySuccess")) assertThat(group.path(field).isNull()).isTrue();
        } else {
            assertThat(group.path("status").asString()).isEqualTo("AVAILABLE");
            assertThat(group.path("numerator").longValue()).isEqualTo(scenario.numerator());
            assertThat(group.path("denominator").longValue()).isEqualTo(scenario.denominator());
            assertThat(group.path("anySuccess").asBoolean()).isEqualTo(scenario.numerator() > 0);
            assertThat(group.path("sourceRunIds").size()).isEqualTo(1);
        }
    }

    private JsonNode assertWitnessGraph(Seed seed, WitnessScenario scenario) {
        ArrayNode graph = objectMapper.createArrayNode();
        List<UUID> runIds = new ArrayList<>();
        for (int runIndex = 0; runIndex < scenario.runs().size(); runIndex++) {
            List<WitnessCaseFixture> fixtures = scenario.runs().get(runIndex).children();
            UUID run = jdbcTemplate.queryForObject("""
                    select trial.test_run_id from test_case_runs trial join test_cases test_case on test_case.id=trial.test_case_id
                    where test_case.suite_id=? and test_case.case_key=?
                    """, UUID.class, UUID.fromString(seed.snapshot().at("/testSuite/id").asString()), "WITNESS-" + runIndex + "-0");
            runIds.add(run);
            java.util.Map<String,Object> parent = jdbcTemplate.queryForMap("""
                    select id,release_id,suite_id,mode,status,total_cases,completed_cases,operational_error_count
                    from test_runs where id=?
                    """, run);
            boolean failed = fixtures.stream().anyMatch(child -> Set.of("ERROR", "CANCELLED").contains(child.status()));
            assertThat(parent.get("release_id")).isEqualTo(seed.releaseId());
            assertThat(parent.get("suite_id")).isEqualTo(UUID.fromString(seed.snapshot().at("/testSuite/id").asString()));
            assertThat(parent.get("mode")).isEqualTo("BASELINE");
            assertThat(parent.get("status")).isEqualTo(failed ? "FAILED" : "COMPLETED");
            assertThat(((Number) parent.get("total_cases")).longValue()).isEqualTo(fixtures.size());
            assertThat(((Number) parent.get("completed_cases")).longValue()).isEqualTo(fixtures.size());
            assertThat(((Number) parent.get("operational_error_count")).longValue())
                    .isEqualTo(fixtures.stream().filter(child -> "ERROR".equals(child.status())).count());
            ArrayNode actualChildren = objectMapper.createArrayNode();
            List<UUID> childIds = new ArrayList<>();
            for (int childIndex = 0; childIndex < fixtures.size(); childIndex++) {
                WitnessCaseFixture fixture = fixtures.get(childIndex);
                java.util.Map<String,Object> child = jdbcTemplate.queryForMap("""
                        select trial.id,trial.test_run_id,trial.status,trial.trial_index,test_case.id as test_case_id,
                            test_case.case_type,test_case.category,test_case.partition_name
                        from test_case_runs trial join test_cases test_case on test_case.id=trial.test_case_id
                        where trial.test_run_id=? and test_case.case_key=?
                        """, run, "WITNESS-" + runIndex + "-" + childIndex);
                childIds.add((UUID) child.get("id"));
                assertThat(child.get("test_run_id")).isEqualTo(run);
                assertThat(child.get("status")).isEqualTo(fixture.status());
                assertThat(((Number) child.get("trial_index")).longValue()).isZero();
                assertThat(child.get("case_type")).isEqualTo(fixture.caseType());
                assertThat(child.get("category")).isEqualTo(fixture.category());
                assertThat(child.get("partition_name")).isEqualTo(fixture.partition());
                JsonNode actualChild = objectMapper.valueToTree(child);
                actualChildren.add(actualChild);
            }
            assertThat(Set.copyOf(childIds)).hasSize(fixtures.size());
            assertThat(jdbcTemplate.queryForObject("select count(*) from test_case_runs where test_run_id=?", Integer.class, run))
                    .isEqualTo(fixtures.size());
            ObjectNode row = objectMapper.valueToTree(parent);
            row.set("children", actualChildren);
            graph.add(row);
        }
        assertThat(Set.copyOf(runIds)).hasSize(scenario.runs().size());
        List<String> observedRuns = new ArrayList<>();
        for (JsonNode id : seed.snapshot().at("/attackRateBreakdown/sourceRunIds")) observedRuns.add(id.asString());
        assertThat(observedRuns)
                .containsExactlyInAnyOrderElementsOf(runIds.stream().map(UUID::toString).toList());
        return graph;
    }

    private static final List<JsonNode> CONCLUSIVE_WITNESS_CONTROLS = new ArrayList<>();

    private void saveWitnessControls(ArrayNode rows) throws IOException {
        synchronized (CONCLUSIVE_WITNESS_CONTROLS) {
            for (JsonNode row : rows) CONCLUSIVE_WITNESS_CONTROLS.add(row);
            ArrayNode combined = objectMapper.createArrayNode();
            CONCLUSIVE_WITNESS_CONTROLS.stream().sorted(java.util.Comparator.comparing(row -> row.path("label").asString()))
                    .forEach(combined::add);
            saveSourceMatrix("standalone-conclusive-witness-controls.json", combined);
        }
    }

    private record WitnessCaseFixture(String caseType, String category, String partition, String status,
                                      Set<OracleOutcome> outcomes) { }
    private record WitnessRunFixture(List<WitnessCaseFixture> children) { }
    private record WitnessRunSource(UUID runId, List<UUID> caseRunIds) { }
    private record WitnessScenario(String label, List<WitnessRunFixture> runs, long numerator, long denominator,
                                   long excluded, int forgedDenominator, int forgedExcluded) { }
    // END additive standalone conclusive-witness unit.

    private record GcSource(UUID runId, UUID caseRunId, UUID oracleResultId, UUID sourceEventId) {
    }
}
