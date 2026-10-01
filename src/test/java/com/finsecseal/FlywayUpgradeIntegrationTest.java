package com.finsecseal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.attestation.AttestationService;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import java.io.InputStream;
import java.security.MessageDigest;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Testcontainers
class FlywayUpgradeIntegrationTest {

    private static final String V9_SHA256 =
            "09e79ccfb30a6a68fdc44be96700c10692cb17e2cba3f27d1a7645f41e14fc05";

    @Container
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Test
    void upgradesAnAlreadyAppliedV9DatabaseWithoutChangingItsChecksum() throws Exception {
        assertThat(migrationSha256("db/migration/V9__idempotency_execution_lease.sql"))
                .isEqualTo(V9_SHA256);

        Flyway throughV9 = flyway(MigrationVersion.fromVersion("9"));
        assertThat(throughV9.migrate().migrationsExecuted).isEqualTo(9);
        assertThat(appliedVersionCount()).isEqualTo(9);
        UUID legacyNamespace = insertLegacyDocument();
        LegacyAttestation legacyPass = insertLegacyPassAttestation(legacyNamespace);

        Flyway current = flyway(null);
        assertThat(current.migrate().migrationsExecuted).isEqualTo(14);
        assertThat(appliedVersionCount()).isEqualTo(23);
        assertThat(current.validateWithResult().validationSuccessful).isTrue();
        assertThat(current.info().current().getVersion()).isEqualTo(MigrationVersion.fromVersion("20"));
        verifyDocumentSourceTimestamp(legacyNamespace);
        verifyReviewerSessionRevocationSchema();
        verifyRunReviewerGrantSchemaWithoutBackfill(legacyNamespace);
        verifyGcProjectionGuardAndLegacyPassWithoutBackfill(legacyPass);
        verifyUnverifiedSlotPlanSchemaWithoutBackfill(legacyNamespace);
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             var query = connection.createStatement();
             var guard = query.executeQuery("""
                     select tgenabled from pg_trigger
                      where tgrelid = 'release_attestations'::regclass
                        and tgname = 'release_attestation_decision_metrics_guard'
                     """)) {
            assertThat(guard.next()).isTrue();
            assertThat(guard.getString(1)).isEqualTo("O");
        }

        UUID leaseId = UUID.randomUUID();
        Instant now = Instant.now();
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             var insert = connection.prepareStatement("""
                     insert into application_instance_leases
                         (id, started_at, heartbeat_at, lease_expires_at, transition_secret_hash)
                     values (?, ?, ?, ?, digest('upgrade-owner-secret', 'sha256'))
                     """)) {
            insert.setObject(1, leaseId);
            insert.setTimestamp(2, java.sql.Timestamp.from(now));
            insert.setTimestamp(3, java.sql.Timestamp.from(now));
            insert.setTimestamp(4, java.sql.Timestamp.from(now.plusSeconds(30)));
            assertThat(insert.executeUpdate()).isEqualTo(1);
        }

        assertThatThrownBy(() -> updateLeaseWithoutOwnerProof(leaseId))
                .isInstanceOf(SQLException.class)
                .extracting(error -> ((SQLException) error).getSQLState())
                .isEqualTo("23514");
    }

    private UUID insertLegacyDocument() throws SQLException {
        UUID agent = UUID.randomUUID();
        UUID release = UUID.randomUUID();
        UUID run = UUID.randomUUID();
        String hash = "sha256:" + "a".repeat(64);
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())) {
            execute(connection, """
                    insert into agents (id, workspace_id, agent_key, name, purpose_summary, status)
                    values (?, '0198f1e2-0000-7000-8000-000000000001', ?, 'Upgrade', 'Synthetic fixture', 'ACTIVE')
                    """, agent, "document-upgrade-" + agent);
            execute(connection, """
                    insert into agent_releases (id, agent_id, version, business_purpose, manifest_schema_version,
                        manifest_json, agent_artifact_fingerprint, release_fingerprint, lifecycle_state, effective_status)
                    values (?, ?, '1.0.0', 'LOAN_DOCUMENT_COMPLETENESS_REVIEW', '1.0', '{}', ?, ?, 'ANALYZED', 'ANALYZED')
                    """, release, agent, hash, hash);
            execute(connection, """
                    insert into test_runs (id, release_id, mode, status, agent_artifact_fingerprint,
                        release_fingerprint, config_json, fixture_version, fixture_digest, model_config_hash)
                    values (?, ?, 'BASELINE', 'QUEUED', ?, ?, '{}', 'golden-v1', ?, ?)
                    """, run, release, hash, hash, hash, hash);
            execute(connection, """
                    insert into sandbox_namespaces (id, fixture_version, fixture_digest, state, expires_at)
                    values (?, 'golden-v1', ?, 'ACTIVE', now() + interval '7 days')
                    """, run, hash);
            execute(connection, """
                    insert into sandbox_customers (namespace_id, customer_key, display_name_token, profile_json, classification_json)
                    values (?, 'CUST-1001', 'SYNTHETIC', '{}', '{}')
                    """, run);
            execute(connection, """
                    insert into sandbox_loan_cases (namespace_id, case_key, applicant_customer_key, status,
                        allowed_document_ids_json, context_json)
                    values (?, 'CASE-1001', 'CUST-1001', 'IN_REVIEW', '["DOC-1001"]', '{}')
                    """, run);
            execute(connection, """
                    insert into sandbox_documents (namespace_id, document_key, case_key, owner_customer_key,
                        document_type, content_encrypted, content_digest, trust_level, classification_json)
                    values (?, 'DOC-1001', 'CASE-1001', 'CUST-1001', 'INCOME', 'legacy-encrypted-content', ?, 'UNTRUSTED', '{}')
                    """, run, hash);
        }
        return run;
    }

    private LegacyAttestation insertLegacyPassAttestation(UUID legacyRun) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        UUID decisionId = UUID.randomUUID();
        UUID attestationId = UUID.randomUUID();
        String hash = "sha256:" + "a".repeat(64);
        Instant confirmedAt = Instant.now().truncatedTo(ChronoUnit.MICROS);
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             var releaseQuery = connection.prepareStatement("select release_id from test_runs where id = ?")) {
            releaseQuery.setObject(1, legacyRun);
            UUID releaseId;
            try (var releases = releaseQuery.executeQuery()) {
                assertThat(releases.next()).isTrue();
                releaseId = releases.getObject(1, UUID.class);
            }

            ObjectNode snapshot = mapper.createObjectNode();
            snapshot.putObject("agent").put("id", UUID.randomUUID().toString());
            snapshot.putObject("release").put("id", releaseId.toString());
            snapshot.putObject("model").put("name", "historical-model");
            snapshot.put("systemPromptFingerprint", hash);
            snapshot.put("toolSetFingerprint", hash);
            snapshot.putArray("toolSchemaFingerprints");
            snapshot.put("ragConfigurationFingerprint", hash);
            snapshot.putObject("safetyContract").put("status", "N_A");
            snapshot.putObject("testSuite").put("status", "N_A");
            snapshot.putObject("sandbox").put("status", "N_A");
            snapshot.putObject("results").put("status", "N_A");
            snapshot.putArray("metrics");
            snapshot.putArray("remainingFindings");
            snapshot.putNull("approvedPatch");
            snapshot.putObject("decision").putArray("ruleTrace");
            snapshot.put("testedAt", confirmedAt.toString());
            String inputDigest = new DigestService().sha256(new CanonicalJsonService(mapper).canonicalize(snapshot));

            ObjectNode document = snapshot.deepCopy();
            document.put("schemaVersion", "1.0");
            document.put("attestationType", "FINSEC_SEAL_INTERNAL_RELEASE_ATTESTATION");
            document.put("canonicalizationVersion", CanonicalJsonService.VERSION);
            document.putObject("decision")
                    .put("id", decisionId.toString()).put("value", "PASS")
                    .put("gatePolicyVersion", "mvp-gate/1")
                    .put("inputDigest", inputDigest)
                    .put("proposedAt", confirmedAt.minusSeconds(1).toString())
                    .put("confirmedAt", confirmedAt.toString())
                    .putArray("ruleTrace");
            document.putObject("reviewer")
                    .put("actorId", "historical-reviewer")
                    .put("role", "AI_GOVERNANCE_REVIEWER")
                    .put("demoMode", true);
            document.putArray("revalidationTriggers")
                    .add("MODEL_CHANGE").add("SYSTEM_PROMPT_CHANGE")
                    .add("TOOL_SET_OR_SCHEMA_OR_DESCRIPTION_CHANGE").add("RAG_CHANGE")
                    .add("SAFETY_CONTRACT_CHANGE").add("BUSINESS_PURPOSE_OR_CONTEXT_CHANGE");
            document.putObject("disclaimer")
                    .put("version", AttestationService.DISCLAIMER_VERSION)
                    .put("ko", AttestationService.DISCLAIMER_KO)
                    .put("en", AttestationService.DISCLAIMER_EN);
            document.put("generatedAt", confirmedAt.toString());
            String documentHash = new DigestService().sha256(new CanonicalJsonService(mapper).canonicalize(document));
            String html = "<html><body>%s %s %s PASS %s</body></html>".formatted(
                    AttestationService.DISCLAIMER_KO, AttestationService.DISCLAIMER_EN,
                    releaseId, documentHash);

            execute(connection, """
                    insert into release_decisions
                        (id, release_id, decision, gate_policy_version, input_snapshot_json, input_digest,
                         proposed_at, confirmed_by, confirmed_at)
                    values (?, ?, 'PASS', 'mvp-gate/1', ?::jsonb, ?, ?, 'historical-reviewer', ?)
                    """, decisionId, releaseId, mapper.writeValueAsString(snapshot), inputDigest,
                    java.sql.Timestamp.from(confirmedAt.minusSeconds(1)), java.sql.Timestamp.from(confirmedAt));
            execute(connection, """
                    insert into release_attestations
                        (id, release_decision_id, format_version, document_json, document_hash,
                         html_content, generated_at, disclaimer_version)
                    values (?, ?, '1.0', ?::jsonb, ?, ?, ?, 'finsec-internal/v1')
                    """, attestationId, decisionId, mapper.writeValueAsString(document), documentHash, html,
                    java.sql.Timestamp.from(confirmedAt));
            return new LegacyAttestation(attestationId, decisionId, mapper.writeValueAsString(document),
                    documentHash, html);
        }
    }

    private void verifyGcProjectionGuardAndLegacyPassWithoutBackfill(LegacyAttestation legacy) throws Exception {
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             var guard = connection.prepareStatement("""
                     select tgenabled from pg_trigger
                      where tgrelid = 'release_attestations'::regclass
                        and tgname = 'release_attestation_zz_gc_coverage_guard'
                     """);
             var query = connection.prepareStatement("""
                     select document_json::text, document_hash, html_content
                       from release_attestations where id = ? and release_decision_id = ?
                     """)) {
            try (var triggers = guard.executeQuery()) {
                assertThat(triggers.next()).isTrue();
                assertThat(triggers.getString(1)).isEqualTo("O");
                assertThat(triggers.next()).isFalse();
            }
            query.setObject(1, legacy.id());
            query.setObject(2, legacy.decisionId());
            try (var attestations = query.executeQuery()) {
                assertThat(attestations.next()).isTrue();
                assertThat(new ObjectMapper().readTree(attestations.getString(1)))
                        .isEqualTo(new ObjectMapper().readTree(legacy.document()));
                assertThat(attestations.getString(2)).isEqualTo(legacy.hash());
                assertThat(attestations.getString(3)).isEqualTo(legacy.html());
                assertThat(attestations.next()).isFalse();
            }
            try (var audit = connection.prepareStatement("""
                    select count(*) from audit_records
                     where resource_type = 'RELEASE_ATTESTATION' and resource_id = ?
                    """)) {
                audit.setObject(1, legacy.id());
                try (var rows = audit.executeQuery()) {
                    assertThat(rows.next()).isTrue();
                    assertThat(rows.getInt(1)).isZero();
                }
            }
        }
    }

    private void verifyUnverifiedSlotPlanSchemaWithoutBackfill(UUID legacyRun) throws SQLException {
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             var plans = connection.prepareStatement("select count(*) from test_run_slot_plans");
             var slots = connection.prepareStatement("select count(*) from test_run_slot_entries");
             var legacy = connection.prepareStatement(
                     "select count(*) from test_run_slot_plans where run_id = ?");
             var invalidPolicy = connection.prepareStatement(
                     "select finsec_configured_trials_v1('{}'::jsonb)")) {
            try (var rows = plans.executeQuery()) {
                assertThat(rows.next()).isTrue();
                assertThat(rows.getInt(1)).isZero();
            }
            try (var rows = slots.executeQuery()) {
                assertThat(rows.next()).isTrue();
                assertThat(rows.getInt(1)).isZero();
            }
            legacy.setObject(1, legacyRun);
            try (var rows = legacy.executeQuery()) {
                assertThat(rows.next()).isTrue();
                assertThat(rows.getInt(1)).isZero();
            }
            try (var rows = invalidPolicy.executeQuery()) {
                assertThat(rows.next()).isTrue();
                assertThat(rows.getObject(1)).isNull();
            }
        }
    }

    private record LegacyAttestation(UUID id, UUID decisionId, String document, String hash, String html) {
    }

    private void verifyDocumentSourceTimestamp(UUID namespace) throws SQLException {
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             var statement = connection.createStatement()) {
            try (var columns = statement.executeQuery("""
                    select is_nullable, column_default from information_schema.columns
                     where table_schema = 'public' and table_name = 'sandbox_documents' and column_name = 'created_at'
                    """)) {
                assertThat(columns.next()).isTrue();
                assertThat(columns.getString("is_nullable")).isEqualTo("YES");
                assertThat(columns.getString("column_default")).isNull();
            }
            try (var legacy = statement.executeQuery("select created_at, content_encrypted from sandbox_documents")) {
                assertThat(legacy.next()).isTrue();
                assertThat(legacy.getTimestamp("created_at")).isNull();
                assertThat(legacy.getString("content_encrypted")).isEqualTo("legacy-encrypted-content");
                assertThat(legacy.next()).isFalse();
            }
            Instant sourceTime = Instant.parse("2026-09-01T00:00:00Z");
            execute(connection, """
                    insert into sandbox_documents (namespace_id, document_key, case_key, owner_customer_key,
                        document_type, content_encrypted, content_digest, trust_level, classification_json, created_at)
                    values (?, 'DOC-1002', 'CASE-1001', 'CUST-1001', 'INCOME', 'new-encrypted-content', ?, 'UNTRUSTED', '{}', ?)
                    """, namespace, "sha256:" + "b".repeat(64), java.sql.Timestamp.from(sourceTime));
            try (var created = statement.executeQuery("select created_at from sandbox_documents where document_key = 'DOC-1002'")) {
                assertThat(created.next()).isTrue();
                assertThat(created.getTimestamp("created_at").toInstant()).isEqualTo(sourceTime);
            }
        }
    }

    private void verifyReviewerSessionRevocationSchema() throws SQLException {
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             var statement = connection.createStatement();
             var columns = statement.executeQuery("""
                     select column_name from information_schema.columns
                      where table_schema = 'public' and table_name = 'reviewer_session_revocations'
                      order by ordinal_position
                     """)) {
            var names = new java.util.ArrayList<String>();
            while (columns.next()) names.add(columns.getString(1));
            assertThat(names).containsExactly("session_digest", "expires_at", "revoked_at");
        }
    }

    private void verifyRunReviewerGrantSchemaWithoutBackfill(UUID legacyRun) throws SQLException {
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             var statement = connection.createStatement();
             var columns = statement.executeQuery("""
                     select column_name from information_schema.columns
                      where table_schema = 'public' and table_name = 'test_run_reviewer_grants'
                      order by ordinal_position
                     """)) {
            var names = new java.util.ArrayList<String>();
            while (columns.next()) names.add(columns.getString(1));
            assertThat(names).containsExactly("run_id", "workspace_id", "actor_id", "reviewer_role",
                    "session_digest", "authority_stamp", "authority_expires_at", "created_at");
        }
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             var query = connection.prepareStatement("select count(*) from test_run_reviewer_grants where run_id = ?")) {
            query.setObject(1, legacyRun);
            try (var rows = query.executeQuery()) {
                assertThat(rows.next()).isTrue();
                assertThat(rows.getInt(1)).isZero();
            }
        }
    }

    private void execute(java.sql.Connection connection, String sql, Object... values) throws SQLException {
        try (var statement = connection.prepareStatement(sql)) {
            for (int index = 0; index < values.length; index++) statement.setObject(index + 1, values[index]);
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
    }

    private Flyway flyway(MigrationVersion target) {
        var configuration = Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        if (target != null) {
            configuration.target(target);
        }
        return configuration.load();
    }

    private int appliedVersionCount() throws SQLException {
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             var statement = connection.createStatement();
             var result = statement.executeQuery("select count(*) from flyway_schema_history where success")) {
            assertThat(result.next()).isTrue();
            return result.getInt(1);
        }
    }

    private void updateLeaseWithoutOwnerProof(UUID leaseId) throws SQLException {
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             var update = connection.prepareStatement("""
                     update application_instance_leases
                        set heartbeat_at = heartbeat_at + interval '1 second',
                            lease_expires_at = lease_expires_at + interval '1 second'
                      where id = ?
                     """)) {
            update.setObject(1, leaseId);
            update.executeUpdate();
        }
    }

    private String migrationSha256(String resource) throws Exception {
        try (InputStream input = getClass().getClassLoader().getResourceAsStream(resource)) {
            assertThat(input).isNotNull();
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(input.readAllBytes()));
        }
    }
}
