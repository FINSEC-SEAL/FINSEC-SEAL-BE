package com.finsecseal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.sql.SQLException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@SpringBootTest
class MigrationIntegrationTest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired
    JdbcTemplate jdbcTemplate;

    @Test
    void appliesAllMigrationsToRealPostgres() {
        Integer appliedMigrations = jdbcTemplate.queryForObject(
                "select count(*) from flyway_schema_history where success",
                Integer.class
        );
        Integer platformTables = jdbcTemplate.queryForObject(
                "select count(*) from information_schema.tables "
                        + "where table_schema = 'public' and table_name in "
                        + "('agents', 'agent_releases', 'execution_events', 'evidence_references', "
                        + "'release_attestations', 'sandbox_loan_cases')",
                Integer.class
        );
        String workspace = jdbcTemplate.queryForObject(
                "select name from workspaces where id = '0198f1e2-0000-7000-8000-000000000001'",
                String.class
        );

        assertThat(appliedMigrations).isEqualTo(4);
        assertThat(platformTables).isEqualTo(6);
        assertThat(workspace).isEqualTo("FINSEC SEAL Demo");
    }

    @Test
    void enforcesReleaseScopeDigestAndAppendOnlyInvariants() {
        String hashA = "sha256:" + "a".repeat(64);
        String hashB = "sha256:" + "b".repeat(64);
        seedIntegrityGraph(hashA, hashB);

        assertSqlState("55000", () -> jdbcTemplate.update("""
                insert into release_artifacts
                    (id, release_id, artifact_type, name, content_json, sha256,
                     canonicalization_version, sensitivity)
                values
                    ('0198f200-0000-7000-8000-000000000101',
                     '0198f200-0000-7000-8000-000000000011', 'MODEL_CONFIG', 'late', '{}'::jsonb,
                     ?, 'RFC8785+NFC/v1', 'NORMAL')
                """, hashA));
        assertSqlState("55000", () -> jdbcTemplate.update("""
                update agent_releases set manifest_json = '{"tampered":true}'::jsonb
                 where id = '0198f200-0000-7000-8000-000000000011'
                """));
        assertSqlState("55000", () -> jdbcTemplate.update("""
                update tool_definitions set description = 'tampered'
                 where id = '0198f200-0000-7000-8000-000000000031'
                """));
        assertSqlState("55000", () -> jdbcTemplate.update("""
                update rag_sources set config_json = '{"tampered":true}'::jsonb
                 where id = '0198f200-0000-7000-8000-000000000032'
                """));
        assertSqlState("23514", () -> jdbcTemplate.update("""
                insert into test_suites
                    (id, workspace_id, suite_key, version, fixture_version, generation_config_json,
                     suite_hash, status)
                values
                    ('0198f200-0000-7000-8000-000000000299',
                     '0198f1e2-0000-7000-8000-000000000001', 'bad-digest', '1.0.0', 'v1', '{}'::jsonb,
                     'not-a-sha256-digest', 'READY')
                """));
        assertSqlState("23514", () -> jdbcTemplate.update("""
                insert into execution_events
                    (id, workspace_id, run_id, test_case_run_id, trace_id, sequence, occurred_at,
                     event_type, payload_digest, metadata_json, event_hash)
                values
                    ('0198f200-0000-7000-8000-000000000081',
                     '0198f1e2-0000-7000-8000-000000000001',
                     '0198f200-0000-7000-8000-000000000051',
                     '0198f200-0000-7000-8000-000000000072',
                     '0198f200-0000-7000-8000-000000000091', 1, now(),
                     'RUN_STARTED', ?, '{}'::jsonb, ?)
                """, hashA, hashB));
        assertSqlState("23503", () -> jdbcTemplate.update("""
                insert into evidence_references
                    (id, workspace_id, owner_type, owner_id, evidence_type, digest, redacted_summary_json)
                values
                    ('0198f200-0000-7000-8000-000000000082',
                     '0198f1e2-0000-7000-8000-000000000001', 'EXECUTION_EVENT',
                     '0198f200-0000-7000-8000-000000009999', 'TRACE', ?, '{}'::jsonb)
                """, hashA));

        jdbcTemplate.update("""
                insert into execution_events
                    (id, workspace_id, run_id, test_case_run_id, trace_id, sequence, occurred_at,
                     event_type, payload_digest, metadata_json, event_hash)
                values
                    ('0198f200-0000-7000-8000-000000000083',
                     '0198f1e2-0000-7000-8000-000000000001',
                     '0198f200-0000-7000-8000-000000000051',
                     '0198f200-0000-7000-8000-000000000071',
                     '0198f200-0000-7000-8000-000000000091', 1, now(),
                     'RUN_STARTED', ?, '{}'::jsonb, ?)
                """, hashA, hashB);
        jdbcTemplate.update("""
                insert into evidence_references
                    (id, workspace_id, owner_type, owner_id, evidence_type, source_event_id,
                     digest, redacted_summary_json)
                values
                    ('0198f200-0000-7000-8000-000000000084',
                     '0198f1e2-0000-7000-8000-000000000001', 'EXECUTION_EVENT',
                     '0198f200-0000-7000-8000-000000000083', 'TRACE',
                     '0198f200-0000-7000-8000-000000000083', ?, '{}'::jsonb)
                """, hashA);
        jdbcTemplate.update("""
                insert into oracle_results
                    (id, test_case_run_id, source_event_id, oracle_type, oracle_version, outcome,
                     reason_code, invariant_id, evidence_json, evidence_digest, evaluated_at,
                     created_at, updated_at)
                values
                    ('0198f200-0000-7000-8000-000000000085',
                     '0198f200-0000-7000-8000-000000000071',
                     '0198f200-0000-7000-8000-000000000083', 'NORMAL_TASK', '1.0', 'NORMAL_SUCCESS',
                     'EXPECTED_RESULT', 'INV-1', '{}'::jsonb, ?, now(), now(), now())
                """, hashA);

        assertSqlState("55000", () -> jdbcTemplate.update("""
                update execution_events set reason_code = 'TAMPERED'
                 where id = '0198f200-0000-7000-8000-000000000083'
                """));
        assertSqlState("55000", () -> jdbcTemplate.update("""
                delete from execution_events where id = '0198f200-0000-7000-8000-000000000083'
                """));
        assertSqlState("55000", () -> jdbcTemplate.update("""
                update evidence_references set evidence_type = 'TAMPERED'
                 where id = '0198f200-0000-7000-8000-000000000084'
                """));
        assertSqlState("55000", () -> jdbcTemplate.update("""
                update oracle_results set reason_code = 'TAMPERED'
                 where id = '0198f200-0000-7000-8000-000000000085'
                """));
    }

    private void seedIntegrityGraph(String hashA, String hashB) {
        jdbcTemplate.update("""
                insert into workspaces (id, name, mode)
                values ('0198f200-0000-7000-8000-000000000002', 'Other workspace', 'DEMO')
                """);
        jdbcTemplate.update("""
                insert into agents
                    (id, workspace_id, agent_key, name, purpose_summary, status, created_at, updated_at)
                values
                    ('0198f200-0000-7000-8000-000000000003',
                     '0198f1e2-0000-7000-8000-000000000001', 'integrity-agent', 'Integrity Agent',
                     'test', 'ACTIVE', now(), now())
                """);
        jdbcTemplate.update("""
                insert into agent_releases
                    (id, agent_id, version, business_purpose, manifest_schema_version, manifest_json,
                     agent_artifact_fingerprint, release_fingerprint, lifecycle_state, effective_status,
                     created_at, updated_at)
                values
                    ('0198f200-0000-7000-8000-000000000011',
                     '0198f200-0000-7000-8000-000000000003', '1.0.0',
                     'LOAN_DOCUMENT_COMPLETENESS_REVIEW', '1.0', '{}'::jsonb, ?, ?,
                     'ANALYZED', 'ANALYZED', now(), now()),
                    ('0198f200-0000-7000-8000-000000000012',
                     '0198f200-0000-7000-8000-000000000003', '1.0.1',
                     'LOAN_DOCUMENT_COMPLETENESS_REVIEW', '1.0', '{}'::jsonb, ?, ?,
                     'DRAFT', 'DRAFT', now(), now())
                """, hashA, hashA, hashB, hashB);
        jdbcTemplate.update("""
                insert into tool_definitions
                    (id, tool_key, version, operation, input_schema_json, output_schema_json, description,
                     trust_level, risk_level, data_classifications_json, side_effect_type, adapter_key,
                     schema_hash, description_hash, created_at, updated_at)
                values
                    ('0198f200-0000-7000-8000-000000000031', 'TEST_TOOL', '1.0.0', 'READ', '{}'::jsonb,
                     '{}'::jsonb, 'test', 'TRUSTED_INTERNAL', 'LOW', '[]'::jsonb, 'NONE', 'test',
                     ?, ?, now(), now())
                """, hashA, hashB);
        jdbcTemplate.update("""
                insert into rag_sources
                    (id, workspace_id, source_key, version, trust_level, content_digest, config_json,
                     created_at, updated_at)
                values
                    ('0198f200-0000-7000-8000-000000000032',
                     '0198f1e2-0000-7000-8000-000000000001', 'test-rag', '1.0', 'TRUSTED_INTERNAL', ?,
                     '{}'::jsonb, now(), now())
                """, hashA);
        jdbcTemplate.update("""
                insert into release_tools (release_id, tool_definition_id, enabled, ordinal)
                values ('0198f200-0000-7000-8000-000000000012',
                        '0198f200-0000-7000-8000-000000000031', true, 0)
                """);
        jdbcTemplate.update("""
                insert into release_rag_sources (release_id, rag_source_id, retrieval_config_json, config_hash)
                values ('0198f200-0000-7000-8000-000000000012',
                        '0198f200-0000-7000-8000-000000000032', '{}'::jsonb, ?)
                """, hashA);
        jdbcTemplate.update("""
                update agent_releases set lifecycle_state = 'ANALYZED', effective_status = 'ANALYZED'
                 where id = '0198f200-0000-7000-8000-000000000012'
                """);
        jdbcTemplate.update("""
                insert into test_suites
                    (id, workspace_id, suite_key, version, fixture_version, generation_config_json,
                     suite_hash, status, created_at, updated_at)
                values
                    ('0198f200-0000-7000-8000-000000000041',
                     '0198f1e2-0000-7000-8000-000000000001', 'integrity-suite', '1.0.0', 'v1',
                     '{}'::jsonb, ?, 'READY', now(), now())
                """, hashA);
        jdbcTemplate.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name, category, severity, delivery_channel,
                     target_tool, payload_hash, preconditions_json, expected_invariant, oracle_type,
                     generation_source, expected_result_json, trial_policy_json, created_at, updated_at)
                values
                    ('0198f200-0000-7000-8000-000000000061',
                     '0198f200-0000-7000-8000-000000000041', 'case-1', 'NORMAL', 'NORMAL', 'NORMAL',
                     'LOW', 'DIRECT', 'TEST_TOOL', ?, '{}'::jsonb, 'INV-1', 'NORMAL_TASK', 'CURATED',
                     '{}'::jsonb, '{}'::jsonb, now(), now())
                """, hashA);
        jdbcTemplate.update("""
                insert into test_runs
                    (id, release_id, suite_id, mode, status, agent_artifact_fingerprint,
                     release_fingerprint, config_json, fixture_version, fixture_digest,
                     model_config_hash, total_cases, completed_cases, created_at, updated_at)
                values
                    ('0198f200-0000-7000-8000-000000000051',
                     '0198f200-0000-7000-8000-000000000011',
                     '0198f200-0000-7000-8000-000000000041', 'BASELINE', 'RUNNING', ?, ?, '{}'::jsonb,
                     'v1', ?, ?, 1, 0, now(), now()),
                    ('0198f200-0000-7000-8000-000000000052',
                     '0198f200-0000-7000-8000-000000000011',
                     '0198f200-0000-7000-8000-000000000041', 'BASELINE', 'COMPLETED', ?, ?, '{}'::jsonb,
                     'v1', ?, ?, 1, 1, now(), now())
                """, hashA, hashA, hashA, hashA, hashA, hashA, hashA, hashA);
        jdbcTemplate.update("""
                insert into test_case_runs
                    (id, test_run_id, test_case_id, trial_index, status, variant_hash,
                     created_at, updated_at)
                values
                    ('0198f200-0000-7000-8000-000000000071',
                     '0198f200-0000-7000-8000-000000000051',
                     '0198f200-0000-7000-8000-000000000061', 0, 'EXECUTING', ?, now(), now()),
                    ('0198f200-0000-7000-8000-000000000072',
                     '0198f200-0000-7000-8000-000000000052',
                     '0198f200-0000-7000-8000-000000000061', 0, 'PASSED', ?, now(), now())
                """, hashA, hashA);
    }

    private void assertSqlState(String expected, Runnable operation) {
        assertThatThrownBy(operation::run)
                .satisfies(exception -> assertThat(findSqlState(exception)).isEqualTo(expected));
    }

    private String findSqlState(Throwable exception) {
        Throwable current = exception;
        while (current != null) {
            if (current instanceof SQLException sqlException) {
                return sqlException.getSQLState();
            }
            current = current.getCause();
        }
        return null;
    }
}
