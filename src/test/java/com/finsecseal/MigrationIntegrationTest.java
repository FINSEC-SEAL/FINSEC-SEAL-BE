package com.finsecseal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
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

    @Autowired
    DataSource dataSource;

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
    void enforcesReleaseScopeDigestAndAppendOnlyInvariants() throws Exception {
        String hashA = "sha256:" + "a".repeat(64);
        String hashB = "sha256:" + "b".repeat(64);
        String hashC = "sha256:" + "c".repeat(64);
        String hashD = "sha256:" + "d".repeat(64);
        String hashE = "sha256:" + "e".repeat(64);
        seedIntegrityGraph(hashA, hashB, hashC, hashD, hashE);

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
                update agent_releases set release_fingerprint = ?
                 where id = '0198f200-0000-7000-8000-000000000011'
                """, hashC));
        assertSqlState("55000", () -> jdbcTemplate.update("""
                update agent_releases set safety_contract_hash = ?
                 where id = '0198f200-0000-7000-8000-000000000014'
                """, hashB));
        assertSqlState("55000", () -> jdbcTemplate.update("""
                update tool_definitions set description = 'tampered'
                 where id = '0198f200-0000-7000-8000-000000000031'
                """));
        assertSqlState("55000", () -> jdbcTemplate.update("""
                update rag_sources set config_json = '{"tampered":true}'::jsonb
                 where id = '0198f200-0000-7000-8000-000000000032'
                """));
        assertSqlState("23514", () -> jdbcTemplate.update("""
                insert into release_rag_sources (release_id, rag_source_id, retrieval_config_json, config_hash)
                values ('0198f200-0000-7000-8000-000000000013',
                        '0198f200-0000-7000-8000-000000000033', '{}'::jsonb, ?)
                """, hashA));
        assertSqlState("23514", () -> jdbcTemplate.update("""
                insert into test_case_runs
                    (id, test_run_id, test_case_id, trial_index, status, variant_hash,
                     created_at, updated_at)
                values
                    ('0198f200-0000-7000-8000-000000000074',
                     '0198f200-0000-7000-8000-000000000051',
                     '0198f200-0000-7000-8000-000000000062', 0, 'PENDING', ?, now(), now())
                """, hashA));
        assertSqlState("55000", () -> jdbcTemplate.update("""
                update test_runs set fixture_version = 'tampered'
                 where id = '0198f200-0000-7000-8000-000000000051'
                """));
        assertSqlState("55000", () -> jdbcTemplate.update("""
                update test_case_runs
                   set test_run_id = '0198f200-0000-7000-8000-000000000052'
                 where id = '0198f200-0000-7000-8000-000000000071'
                """));
        assertSqlState("55000", () -> jdbcTemplate.update("""
                update test_suites set status = 'TAMPERED'
                 where id = '0198f200-0000-7000-8000-000000000041'
                """));
        assertSqlState("55000", () -> jdbcTemplate.update("""
                update test_cases set expected_invariant = 'TAMPERED'
                 where id = '0198f200-0000-7000-8000-000000000061'
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
        assertSqlState("23514", () -> jdbcTemplate.update("""
                insert into execution_events
                    (id, workspace_id, run_id, test_case_run_id, trace_id, sequence, occurred_at,
                     event_type, payload_digest, metadata_json, prev_event_hash, event_hash)
                values
                    ('0198f200-0000-7000-8000-000000000088',
                     '0198f1e2-0000-7000-8000-000000000001',
                     '0198f200-0000-7000-8000-000000000051',
                     '0198f200-0000-7000-8000-000000000071',
                     '0198f200-0000-7000-8000-000000000091', 3, now(),
                     'MODEL_RESPONSE', ?, '{}'::jsonb, ?, ?)
                """, hashA, hashB, hashD));
        jdbcTemplate.update("""
                insert into execution_events
                    (id, workspace_id, run_id, test_case_run_id, trace_id, sequence, occurred_at,
                     event_type, payload_digest, metadata_json, event_hash)
                values
                    ('0198f200-0000-7000-8000-000000000086',
                     '0198f1e2-0000-7000-8000-000000000001',
                     '0198f200-0000-7000-8000-000000000052',
                     '0198f200-0000-7000-8000-000000000072',
                     '0198f200-0000-7000-8000-000000000092', 1, now(),
                     'RUN_STARTED', ?, '{}'::jsonb, ?)
                """, hashA, hashC);
        assertSqlState("23514", () -> jdbcTemplate.update("""
                insert into evidence_references
                    (id, workspace_id, owner_type, owner_id, evidence_type, source_event_id,
                     digest, redacted_summary_json)
                values
                    ('0198f200-0000-7000-8000-000000000087',
                     '0198f1e2-0000-7000-8000-000000000001', 'EXECUTION_EVENT',
                     '0198f200-0000-7000-8000-000000000083', 'TRACE',
                     '0198f200-0000-7000-8000-000000000086', ?, '{}'::jsonb)
                """, hashA));
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

        jdbcTemplate.update("""
                insert into findings
                    (id, release_id, source_oracle_result_id, category, severity, title, status,
                     violated_invariant, root_cause_json, first_seen_run_id, latest_seen_run_id,
                     created_at, updated_at)
                values
                    ('0198f200-0000-7000-8000-000000000090',
                     '0198f200-0000-7000-8000-000000000011',
                     '0198f200-0000-7000-8000-000000000085', 'SCOPE', 'HIGH', 'Synthetic finding',
                     'OPEN', 'INV-1', '{}'::jsonb,
                     '0198f200-0000-7000-8000-000000000051',
                     '0198f200-0000-7000-8000-000000000052', now(), now())
                """);
        assertSqlState("23514", () -> jdbcTemplate.update("""
                insert into replay_links
                    (id, finding_id, baseline_case_run_id, replay_case_run_id,
                     same_agent_artifact_fingerprint, same_fixture_digest, same_model_config,
                     same_variant_hash, expected_policy_difference, comparison_json)
                values
                    ('0198f200-0000-7000-8000-000000000094',
                     '0198f200-0000-7000-8000-000000000090',
                     '0198f200-0000-7000-8000-000000000071',
                     '0198f200-0000-7000-8000-000000000073',
                     true, true, true, true, true, '{}'::jsonb)
                """));
        assertSqlState("23514", () -> jdbcTemplate.update("""
                insert into replay_links
                    (id, finding_id, baseline_case_run_id, replay_case_run_id,
                     same_agent_artifact_fingerprint, same_fixture_digest, same_model_config,
                     same_variant_hash, expected_policy_difference, comparison_json)
                values
                    ('0198f200-0000-7000-8000-000000000093',
                     '0198f200-0000-7000-8000-000000000090',
                     '0198f200-0000-7000-8000-000000000071',
                     '0198f200-0000-7000-8000-000000000075',
                     true, true, false, true, true, '{}'::jsonb)
                """));
        jdbcTemplate.update("""
                insert into replay_links
                    (id, finding_id, baseline_case_run_id, replay_case_run_id,
                     same_agent_artifact_fingerprint, same_fixture_digest, same_model_config,
                     same_variant_hash, expected_policy_difference, comparison_json)
                values
                    ('0198f200-0000-7000-8000-000000000095',
                     '0198f200-0000-7000-8000-000000000090',
                     '0198f200-0000-7000-8000-000000000071',
                     '0198f200-0000-7000-8000-000000000075',
                     true, true, true, true, true, '{}'::jsonb)
                """);
        jdbcTemplate.update("""
                insert into patch_proposals
                    (id, finding_id, state, root_cause, recommended_rule_json, policy_diff_json,
                     normal_workflow_impact_json, rollback_json, generation_model_meta_json,
                     validation_json, created_at, updated_at)
                values
                    ('0198f200-0000-7000-8000-000000000096',
                     '0198f200-0000-7000-8000-000000000090', 'PROPOSED', 'test', '{}'::jsonb,
                     '{}'::jsonb, '{}'::jsonb, '{}'::jsonb, '{}'::jsonb, '{}'::jsonb, now(), now())
                """);
        jdbcTemplate.update("""
                insert into patch_approvals
                    (id, patch_proposal_id, decision, reviewer_actor_id, comment, base_hash,
                     decided_at, created_at)
                values
                    ('0198f200-0000-7000-8000-000000000097',
                     '0198f200-0000-7000-8000-000000000096', 'REJECTED', 'reviewer', 'test', ?,
                     now(), now())
                """, hashA);
        assertSqlState("55000", () -> jdbcTemplate.update("""
                update patch_proposals set policy_diff_json = '{"tampered":true}'::jsonb
                 where id = '0198f200-0000-7000-8000-000000000096'
                """));

        verifyLatestDecisionInvalidationAtCommit(hashA, hashB, hashD);

        assertConcurrentStaleHeadRejected(hashA, hashB, hashC);

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
        assertSqlState("55000", () -> jdbcTemplate.update("""
                update replay_links set same_variant_hash = false
                 where id = '0198f200-0000-7000-8000-000000000095'
                """));
        assertSqlState("55000", () -> jdbcTemplate.update("""
                update patch_approvals set comment = 'tampered'
                 where id = '0198f200-0000-7000-8000-000000000097'
                """));
    }

    private void seedIntegrityGraph(String hashA, String hashB, String hashC, String hashD, String hashE) {
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
                     'REMEDIATION', 'REMEDIATION', now(), now()),
                    ('0198f200-0000-7000-8000-000000000012',
                     '0198f200-0000-7000-8000-000000000003', '1.0.1',
                     'LOAN_DOCUMENT_COMPLETENESS_REVIEW', '1.0', '{}'::jsonb, ?, ?,
                     'DRAFT', 'DRAFT', now(), now()),
                    ('0198f200-0000-7000-8000-000000000013',
                     '0198f200-0000-7000-8000-000000000003', '1.0.2',
                     'LOAN_DOCUMENT_COMPLETENESS_REVIEW', '1.0', '{}'::jsonb, ?, ?,
                     'DRAFT', 'DRAFT', now(), now()),
                    ('0198f200-0000-7000-8000-000000000014',
                     '0198f200-0000-7000-8000-000000000003', '1.0.3',
                     'LOAN_DOCUMENT_COMPLETENESS_REVIEW', '1.0', '{}'::jsonb, ?, ?,
                     'PASS', 'PASS', now(), now())
                """, hashA, hashA, hashC, hashC, hashD, hashD, hashE, hashE);
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
                     '{}'::jsonb, now(), now()),
                    ('0198f200-0000-7000-8000-000000000033',
                     '0198f200-0000-7000-8000-000000000002', 'other-rag', '1.0', 'TRUSTED_INTERNAL', ?,
                     '{}'::jsonb, now(), now())
                """, hashA, hashA);
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
                     '{}'::jsonb, ?, 'READY', now(), now()),
                    ('0198f200-0000-7000-8000-000000000042',
                     '0198f1e2-0000-7000-8000-000000000001', 'other-suite', '1.0.0', 'v1',
                     '{}'::jsonb, ?, 'READY', now(), now())
                """, hashA, hashA);
        jdbcTemplate.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name, category, severity, delivery_channel,
                     target_tool, payload_hash, preconditions_json, expected_invariant, oracle_type,
                     generation_source, expected_result_json, trial_policy_json, created_at, updated_at)
                values
                    ('0198f200-0000-7000-8000-000000000061',
                     '0198f200-0000-7000-8000-000000000041', 'case-1', 'NORMAL', 'NORMAL', 'NORMAL',
                     'LOW', 'DIRECT', 'TEST_TOOL', ?, '{}'::jsonb, 'INV-1', 'NORMAL_TASK', 'CURATED',
                     '{}'::jsonb, '{}'::jsonb, now(), now()),
                    ('0198f200-0000-7000-8000-000000000062',
                     '0198f200-0000-7000-8000-000000000042', 'case-2', 'NORMAL', 'NORMAL', 'NORMAL',
                     'LOW', 'DIRECT', 'TEST_TOOL', ?, '{}'::jsonb, 'INV-2', 'NORMAL_TASK', 'CURATED',
                     '{}'::jsonb, '{}'::jsonb, now(), now())
                """, hashA, hashA);
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
                     'v1', ?, ?, 1, 1, now(), now()),
                    ('0198f200-0000-7000-8000-000000000053',
                     '0198f200-0000-7000-8000-000000000012',
                     '0198f200-0000-7000-8000-000000000041', 'BASELINE', 'COMPLETED', ?, ?, '{}'::jsonb,
                     'v1', ?, ?, 1, 1, now(), now())
                """, hashA, hashA, hashA, hashA, hashA, hashA, hashA, hashA,
                       hashC, hashC, hashA, hashA);
        jdbcTemplate.update("""
                insert into safety_contracts
                    (id, workspace_id, release_id, contract_key, status, created_at, updated_at)
                values
                    ('0198f200-0000-7000-8000-000000000034',
                     '0198f1e2-0000-7000-8000-000000000001',
                     '0198f200-0000-7000-8000-000000000011', 'seal-policy', 'APPROVED', now(), now())
                """);
        jdbcTemplate.update("""
                insert into safety_contract_versions
                    (id, contract_id, version, state, policy_json, policy_hash, validator_version,
                     validation_json, created_by, approved_by, approved_at, created_at, updated_at)
                values
                    ('0198f200-0000-7000-8000-000000000035',
                     '0198f200-0000-7000-8000-000000000034', 1, 'APPROVED', '{}'::jsonb, ?, '1.0',
                     '{}'::jsonb, 'reviewer', 'reviewer', now(), now(), now())
                """, hashC);
        jdbcTemplate.update("""
                update agent_releases
                   set lifecycle_state = 'VERIFYING', effective_status = 'VERIFYING',
                       safety_contract_hash = ?, release_fingerprint = ?
                 where id = '0198f200-0000-7000-8000-000000000011'
                """, hashC, hashB);
        jdbcTemplate.update("""
                insert into test_runs
                    (id, release_id, suite_id, contract_version_id, mode, status,
                     agent_artifact_fingerprint, release_fingerprint, config_json, fixture_version,
                     fixture_digest, model_config_hash, total_cases, completed_cases, created_at, updated_at)
                values
                    ('0198f200-0000-7000-8000-000000000054',
                     '0198f200-0000-7000-8000-000000000011',
                     '0198f200-0000-7000-8000-000000000041',
                     '0198f200-0000-7000-8000-000000000035', 'SEAL_REPLAY', 'COMPLETED',
                     ?, ?, '{}'::jsonb, 'v1', ?, ?, 1, 1, now(), now())
                """, hashA, hashB, hashA, hashA);
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
                     '0198f200-0000-7000-8000-000000000061', 0, 'PASSED', ?, now(), now()),
                    ('0198f200-0000-7000-8000-000000000073',
                     '0198f200-0000-7000-8000-000000000053',
                     '0198f200-0000-7000-8000-000000000061', 0, 'PASSED', ?, now(), now()),
                    ('0198f200-0000-7000-8000-000000000075',
                     '0198f200-0000-7000-8000-000000000054',
                     '0198f200-0000-7000-8000-000000000061', 0, 'PASSED', ?, now(), now())
                """, hashA, hashA, hashA, hashA);
    }

    private void verifyLatestDecisionInvalidationAtCommit(String hashA, String hashB, String policyHash) {
        jdbcTemplate.update("""
                insert into safety_contracts
                    (id, workspace_id, release_id, contract_key, status, created_at, updated_at)
                values
                    ('0198f200-0000-7000-8000-000000000036',
                     '0198f1e2-0000-7000-8000-000000000001',
                     '0198f200-0000-7000-8000-000000000014', 'terminal-policy', 'APPROVED', now(), now())
                """);
        jdbcTemplate.update("""
                insert into safety_contract_versions
                    (id, contract_id, version, state, policy_json, policy_hash, validation_json,
                     created_by, approved_by, approved_at, created_at, updated_at)
                values
                    ('0198f200-0000-7000-8000-000000000037',
                     '0198f200-0000-7000-8000-000000000036', 1, 'APPROVED', '{}'::jsonb, ?, '{}'::jsonb,
                     'reviewer', 'reviewer', now(), now(), now())
                """, policyHash);
        jdbcTemplate.update("""
                insert into release_decisions
                    (id, release_id, decision, gate_policy_version, input_snapshot_json, input_digest,
                     proposed_at, confirmed_by, confirmed_at, created_at)
                values
                    ('0198f200-0000-7000-8000-000000000106',
                     '0198f200-0000-7000-8000-000000000014', 'PASS', '1.0', '{}'::jsonb, ?,
                     now() - interval '2 hours', 'reviewer', now() - interval '1 hour', now() - interval '1 hour'),
                    ('0198f200-0000-7000-8000-000000000107',
                     '0198f200-0000-7000-8000-000000000014', 'PASS', '1.0', '{}'::jsonb, ?,
                     now() - interval '1 hour', 'reviewer', now(), now())
                """, hashA, hashB);
        jdbcTemplate.update("""
                insert into decision_invalidations
                    (id, release_decision_id, reasons_json, invalidated_by, invalidated_at, created_at)
                values
                    ('0198f200-0000-7000-8000-000000000108',
                     '0198f200-0000-7000-8000-000000000106', '{}'::jsonb, 'reviewer', now(), now())
                """);
        assertSqlState("23514", () -> jdbcTemplate.update("""
                update agent_releases
                   set lifecycle_state = 'NEEDS_REVALIDATION', effective_status = 'NEEDS_REVALIDATION',
                       safety_contract_hash = ?, release_fingerprint = ?
                 where id = '0198f200-0000-7000-8000-000000000014'
                """, policyHash, hashA));
        jdbcTemplate.update("""
                insert into decision_invalidations
                    (id, release_decision_id, reasons_json, invalidated_by, invalidated_at, created_at)
                values
                    ('0198f200-0000-7000-8000-000000000109',
                     '0198f200-0000-7000-8000-000000000107', '{}'::jsonb, 'reviewer', now(), now())
                """);
        assertSqlState("23505", () -> jdbcTemplate.update("""
                insert into decision_invalidations
                    (id, release_decision_id, reasons_json, invalidated_by, invalidated_at, created_at)
                values
                    ('0198f200-0000-7000-8000-000000000110',
                     '0198f200-0000-7000-8000-000000000107', '{}'::jsonb, 'reviewer', now(), now())
                """));
        assertSqlState("55000", () -> jdbcTemplate.update("""
                update agent_releases
                   set lifecycle_state = 'NEEDS_REVALIDATION', effective_status = 'PASS',
                       safety_contract_hash = ?, release_fingerprint = ?
                 where id = '0198f200-0000-7000-8000-000000000014'
                """, policyHash, hashA));
        assertThat(jdbcTemplate.update("""
                update agent_releases
                   set lifecycle_state = 'NEEDS_REVALIDATION', effective_status = 'NEEDS_REVALIDATION',
                       safety_contract_hash = ?, release_fingerprint = ?
                 where id = '0198f200-0000-7000-8000-000000000014'
                """, policyHash, hashA)).isEqualTo(1);
        assertThat(jdbcTemplate.queryForObject("""
                select effective_status from agent_releases
                 where id = '0198f200-0000-7000-8000-000000000014'
                """, String.class)).isEqualTo("NEEDS_REVALIDATION");
    }

    private void assertConcurrentStaleHeadRejected(String payloadHash, String currentHead, String nextHead)
            throws Exception {
        String staleAttemptHash = "sha256:" + "d".repeat(64);
        CountDownLatch secondConnectionStarted = new CountDownLatch(1);
        try (Connection first = dataSource.getConnection(); var executor = Executors.newSingleThreadExecutor()) {
            first.setAutoCommit(false);
            insertEvent(
                    first,
                    "0198f200-0000-7000-8000-000000000098",
                    2,
                    payloadHash,
                    currentHead,
                    nextHead
            );
            Future<String> staleInsert = executor.submit(() -> {
                secondConnectionStarted.countDown();
                try (Connection second = dataSource.getConnection()) {
                    insertEvent(
                            second,
                            "0198f200-0000-7000-8000-000000000099",
                            3,
                            payloadHash,
                            currentHead,
                            staleAttemptHash
                    );
                    return "accepted";
                } catch (SQLException exception) {
                    return exception.getSQLState();
                }
            });
            assertThat(secondConnectionStarted.await(2, TimeUnit.SECONDS)).isTrue();
            assertThatThrownBy(() -> staleInsert.get(200, TimeUnit.MILLISECONDS))
                    .isInstanceOf(java.util.concurrent.TimeoutException.class);

            first.commit();
            assertThat(staleInsert.get(5, TimeUnit.SECONDS)).isEqualTo("23514");
        }
    }

    private void insertEvent(
            Connection connection,
            String eventId,
            long sequence,
            String payloadDigest,
            String previousHash,
            String eventHash
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                insert into execution_events
                    (id, workspace_id, run_id, test_case_run_id, trace_id, sequence, occurred_at,
                     event_type, payload_digest, metadata_json, prev_event_hash, event_hash)
                values
                    (?::uuid, '0198f1e2-0000-7000-8000-000000000001',
                     '0198f200-0000-7000-8000-000000000051',
                     '0198f200-0000-7000-8000-000000000071',
                     '0198f200-0000-7000-8000-000000000091', ?, now(),
                     'MODEL_RESPONSE', ?, '{}'::jsonb, ?, ?)
                """)) {
            statement.setString(1, eventId);
            statement.setLong(2, sequence);
            statement.setString(3, payloadDigest);
            statement.setString(4, previousHash);
            statement.setString(5, eventHash);
            statement.executeUpdate();
        }
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
