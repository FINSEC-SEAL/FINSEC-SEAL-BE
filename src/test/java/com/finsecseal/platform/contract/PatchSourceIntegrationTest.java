package com.finsecseal.platform.contract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.attestation.AttestationService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.DecisionValue;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.release.ReleaseDto;
import com.finsecseal.release.ReleaseService;
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
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Testcontainers
@SpringBootTest(properties={"finsec.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","finsec.scheduling.enabled=false"})
class PatchSourceIntegrationTest {
    private static final String HASH_A="sha256:"+"a".repeat(64);
    @Container @ServiceConnection static final PostgreSQLContainer POSTGRES=new PostgreSQLContainer("postgres:17.11-alpine");
    @Autowired AgentService agentService;
    @Autowired ReleaseService releaseService;
    @Autowired JdbcTemplate jdbcTemplate;
    @Autowired ObjectMapper objectMapper;
    @Autowired ExecutionEventService eventService;
    @Autowired PatchSourceService service;
    @Autowired com.finsecseal.release.CanonicalJsonService canonical;
    @Autowired com.finsecseal.release.DigestService digest;
    private final com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext reviewer=
        new com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext(AgentService.DEMO_WORKSPACE_ID,"reviewer","AI_SECURITY_REVIEWER","s",true,true,false);

    @Test void returnsOnlyEligibleDigestBoundSources() throws Exception {
        Seed s=seed("SEED",false,false);
        var source=service.find(s.findingId(),reviewer);
        assertThat(source.facts().sourcePartition()).isEqualTo("SEED");
        assertThat(source.facts().findingId()).isEqualTo(s.findingId());
        assertThat(source.oracleResultId()).isEqualTo(s.oracleId());
        assertThat(source.evidence().isEmpty()).isTrue();
    }
    @Test void excludesHeldOutHiddenAndHiddenAncestry() throws Exception {
        for(Seed s:java.util.List.of(seed("HELD_OUT",false,false),seed("SEED",true,false),seed("MUTATION",false,true))) {
            assertThatThrownBy(()->service.find(s.findingId(),reviewer)).hasMessage("Eligible patch source not found");
        }
    }
    @Test void excludesForeignWorkspaceAndClosedFinding() throws Exception {
        Seed s=seed("SEED",false,false);
        var foreign=new com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext(UUID.randomUUID(),"reviewer","AI_SECURITY_REVIEWER","s",true,true,false);
        assertThatThrownBy(()->service.find(s.findingId(),foreign)).hasMessage("Eligible patch source not found");
        jdbcTemplate.update("update findings set status='RESOLVED' where id=?",s.findingId());
        assertThatThrownBy(()->service.find(s.findingId(),reviewer)).hasMessage("Eligible patch source not found");
    }
    @Autowired ContractPersistenceService contracts;
    @Autowired com.finsecseal.assurance.ReleaseAssuranceService assurance;
    @Autowired com.finsecseal.attestation.AttestationService attestations;
    @Test void approvedPolicyInvalidatesPriorDecisionWithoutDeletingEvidence() throws Exception {
        Seed s=seed("SEED",false,false);
        var proposal=assurance.evaluate(s.releaseId(),"reviewer");
        assurance.confirm(s.releaseId(),proposal.inputDigest(),new com.finsecseal.assurance.ReleaseAssuranceDto.ConfirmRequest(
            proposal.proposedDecision(),"Reviewed evidence"),"reviewer");
        var before=attestations.findOrCreate(s.releaseId(),"reviewer");
        var policy=objectMapper.readTree(getClass().getResourceAsStream("/fixtures/loan-review-safety-contract.json"));
        var c=contracts.create(s.releaseId(),policy,reviewer);
        var v=contracts.validate(c.id(),'"'+c.resourceHash()+'"',reviewer);
        contracts.approve(v.id(),'"'+v.resourceHash()+'"',"Review scope",reviewer);
        var after=attestations.findOrCreate(s.releaseId(),"reviewer");
        assertThat(after.documentHash()).isEqualTo(before.documentHash());
        assertThat(after.stale()).isTrue();
        assertThat(releaseService.find(s.releaseId()).effectiveStatus().name()).isEqualTo("NEEDS_REVALIDATION");
    }
    @Test void storesAndApprovesCValidatedPatchWithImmutableApprovalLink() throws Exception {
        Seed source=seed("SEED",false,false);
        jdbcTemplate.update("update agent_releases set lifecycle_state='REMEDIATION',effective_status='REMEDIATION' where id=?",source.releaseId());
        ObjectNode policy=(ObjectNode)objectMapper.readTree(getClass().getResourceAsStream("/fixtures/loan-review-safety-contract.json"));
        ObjectNode broad=policy.deepCopy();
        ((tools.jackson.databind.node.ArrayNode)broad.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed")).add("accountNumber");
        var base=contracts.create(source.releaseId(),broad,reviewer);
        var patch=new com.finsecseal.contract.SafetyContractPatchProposalFacts.ProposedPatch(policy.put("version",2),
            java.util.List.of(new com.finsecseal.contract.SafetyContractPatchOperation.NarrowSet(
                com.finsecseal.contract.SafetyContractPatchOperation.SetKind.ALLOWED_FIELDS,"CUSTOMER_DATA_READ",java.util.List.of("employmentStatus","incomeBand"))),
            "Excessive fields","Required workflow fields retained","Create a reviewed replacement");
        var stored=contracts.storePatch(source.findingId(),base.id(),patch,reviewer);
        var candidate=stored.candidate();
        var validated=contracts.validate(candidate.id(),'"'+candidate.resourceHash()+'"',reviewer);
        assertThatThrownBy(()->contracts.approve(validated.id(),'"'+validated.resourceHash()+'"',"review",reviewer)).hasMessageContaining("bound patchProposalId");
        assertThatThrownBy(()->contracts.approve(validated.id(),'"'+validated.resourceHash()+'"',"review",UUID.randomUUID(),reviewer)).hasMessageContaining("bound patchProposalId");
        String operations=jdbcTemplate.queryForObject("select policy_diff_json::text from patch_proposals where id=?",String.class,stored.patchProposalId());
        jdbcTemplate.update("update patch_proposals set policy_diff_json='[]' where id=?",stored.patchProposalId());
        assertThatThrownBy(()->contracts.approve(validated.id(),'"'+validated.resourceHash()+'"',"review",stored.patchProposalId(),reviewer)).hasMessageContaining("Patch approval evidence changed");
        assertThat(contracts.find(validated.id(),reviewer).state()).isEqualTo("VALIDATED");
        assertThat(jdbcTemplate.queryForObject("select count(*) from patch_approvals where patch_proposal_id=?",Integer.class,stored.patchProposalId())).isZero();
        jdbcTemplate.update("update patch_proposals set policy_diff_json=cast(? as jsonb) where id=?",operations,stored.patchProposalId());
        var approved=contracts.approve(validated.id(),'"'+validated.resourceHash()+'"',"Reviewed narrowing",stored.patchProposalId(),reviewer);
        assertThat(approved.state()).isEqualTo("APPROVED");
        assertThat(jdbcTemplate.queryForObject("select resulting_contract_version_id from patch_approvals where patch_proposal_id=?",UUID.class,stored.patchProposalId())).isEqualTo(approved.id());
        assertThatThrownBy(()->jdbcTemplate.update("update patch_proposals set root_cause='changed' where id=?",stored.patchProposalId())).hasMessageContaining("immutable");
    }
    private Seed seed(String partition, boolean hidden, boolean hiddenParent) throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        AgentDto.Response agent = agentService.create(new AgentDto.CreateRequest(
                "assurance-" + suffix, "Assurance Agent", "Release assurance integration test"
        ));
        ObjectNode manifest = (ObjectNode) objectMapper.readTree(
                getClass().getResourceAsStream("/fixtures/valid-release-manifest-v1.1.json")
        );
        ((ObjectNode) manifest.path("agent")).put("id", "assurance-" + suffix);
        ReleaseDto.Response release = releaseService.create(agent.id(), manifest, "test");
        releaseService.analyze(release.id(), "test");
        ReleaseDto.Response current = releaseService.find(release.id());

        UUID suiteId = UUID.randomUUID();
        UUID testCaseId = UUID.randomUUID();
        UUID runId = UUID.randomUUID();
        UUID caseRunId = UUID.randomUUID();
        UUID oracleId = UUID.randomUUID();
        UUID findingId = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);

        jdbcTemplate.update("""
                insert into test_suites
                    (id, workspace_id, suite_key, version, fixture_version, generation_config_json,
                     suite_hash, status, created_at, updated_at)
                values (?, ?, ?, '1.0.0', 'fixture-v1', '{}'::jsonb, ?, 'DRAFT', ?, ?)
                """, suiteId, AgentService.DEMO_WORKSPACE_ID, "assurance-suite-" + suffix,
                HASH_A, Timestamp.from(now), Timestamp.from(now));
        jdbcTemplate.update("""
                insert into test_cases
                    (id, suite_id, case_key, case_type, partition_name, category, severity,
                     delivery_channel, target_tool, attack_goal, payload_hash, preconditions_json,
                     expected_invariant, oracle_type, generation_source, hidden_from_patch_generator,
                     expected_result_json, trial_policy_json, created_at, updated_at)
                values (?, ?, ?, 'ATTACK', ?, 'FA-02', 'CRITICAL', 'DOCUMENT',
                        'CUSTOMER_DATA_READ', 'cross customer read', ?, '{}'::jsonb, 'INV-01',
                        'CROSS_CUSTOMER', 'GOLDEN', ?, '{}'::jsonb, '{}'::jsonb, ?, ?)
                """, testCaseId, suiteId, "FA-02-" + suffix, partition, HASH_A, hidden,
                Timestamp.from(now), Timestamp.from(now));
        if(hiddenParent) {
            UUID parent=UUID.randomUUID();
            jdbcTemplate.update("""
                insert into test_cases(id,suite_id,case_key,case_type,partition_name,category,severity,delivery_channel,
                payload_hash,preconditions_json,expected_invariant,oracle_type,generation_source,hidden_from_patch_generator,
                expected_result_json,trial_policy_json)
                values(?,?,'hidden-parent','ATTACK','HELD_OUT','FA-02','HIGH','DOCUMENT',?,'{}','INV-01','CROSS_CUSTOMER','GOLDEN',true,'{}','{}')
                """,parent,suiteId,HASH_A);
            jdbcTemplate.update("update test_cases set parent_seed_id=? where id=?",parent,testCaseId);
        }
        jdbcTemplate.update("update test_suites set status = 'READY', updated_at = ? where id = ?",
                Timestamp.from(now), suiteId);
        jdbcTemplate.update("""
                insert into test_runs
                    (id, release_id, suite_id, mode, status, agent_artifact_fingerprint,
                     release_fingerprint, config_json, fixture_version, fixture_digest,
                     model_config_hash, total_cases, completed_cases, operational_error_count,
                     started_at, completed_at, summary_json, created_at, updated_at)
                values (?, ?, ?, 'BASELINE', 'QUEUED', ?, ?, '{}'::jsonb, 'fixture-v1', ?, ?,
                        1, 0, 0, null, null, '{}'::jsonb, ?, ?)
                """, runId, release.id(), suiteId, current.agentArtifactFingerprint(),
                current.releaseFingerprint(), HASH_A, HASH_A, Timestamp.from(now), Timestamp.from(now));
        jdbcTemplate.update("""
                insert into test_case_runs
                    (id, test_run_id, test_case_id, trial_index, status, security_outcome,
                     variant_hash, started_at, completed_at, result_json, created_at, updated_at)
                values (?, ?, ?, 0, 'PENDING', null, ?, null, null, '{}'::jsonb, ?, ?)
                """, caseRunId, runId, testCaseId, HASH_A, Timestamp.from(now), Timestamp.from(now));
        jdbcTemplate.update("""
                update test_case_runs
                   set status = 'FAILED_SECURITY', security_outcome = 'ATTACK_SUCCESS',
                       started_at = ?, completed_at = ?, updated_at = ?
                 where id = ?
                """, Timestamp.from(now.minusSeconds(1)), Timestamp.from(now), Timestamp.from(now), caseRunId);
        jdbcTemplate.update("""
                insert into oracle_results
                    (id, test_case_run_id, oracle_type, oracle_version, outcome, reason_code,
                     invariant_id, evidence_json, evidence_digest, evaluated_at, created_at, updated_at)
                values (?, ?, 'CROSS_CUSTOMER', '1.0', 'ATTACK_SUCCESS',
                        'UNAUTHORIZED_RECORD_RETURNED', 'INV-01', '{}'::jsonb, ?, ?, ?, ?)
                """, oracleId, caseRunId, digest.sha256(canonical.canonicalize(objectMapper.createObjectNode())), Timestamp.from(now), Timestamp.from(now), Timestamp.from(now));
        jdbcTemplate.update("""
                insert into findings
                    (id, release_id, source_oracle_result_id, category, severity, title, status,
                     violated_invariant, root_cause_json, first_seen_run_id, latest_seen_run_id,
                     created_at, updated_at)
                values (?, ?, ?, 'FA-02', 'CRITICAL', 'Unauthorized customer record returned', 'OPEN',
                        'INV-01', '{}'::jsonb, ?, ?, ?, ?)
                """, findingId, release.id(), oracleId, runId, runId,
                Timestamp.from(now), Timestamp.from(now));
        jdbcTemplate.update("""
                update test_runs set status = 'PREPARING', updated_at = ? where id = ?
                """, Timestamp.from(now.minusSeconds(2)), runId);
        jdbcTemplate.update("""
                update test_runs set status = 'RUNNING', started_at = ?, updated_at = ? where id = ?
                """, Timestamp.from(now.minusSeconds(1)), Timestamp.from(now.minusSeconds(1)), runId);
        jdbcTemplate.update("insert into run_event_counters (run_id, last_sequence) values (?, 0)", runId);
        UUID traceId = UUID.randomUUID();
        eventService.append(runId, new ExecutionEventDto.AppendRequest(
                null, traceId, ExecutionEventType.RUN_STARTED,
                null, null, null, null, "RUN_STARTED", objectMapper.createObjectNode()
        ), "test");
        eventService.append(runId, new ExecutionEventDto.AppendRequest(
                null, traceId, ExecutionEventType.RUN_COMPLETED,
                null, null, null, null, "RUN_COMPLETED", objectMapper.createObjectNode()
        ), "test");
        jdbcTemplate.update("""
                update test_runs
                   set status = 'COMPLETED', completed_cases = 1, started_at = ?, completed_at = ?, updated_at = ?
                 where id = ?
                """, Timestamp.from(now.minusSeconds(1)), Timestamp.from(now), Timestamp.from(now), runId);
        jdbcTemplate.update("""
                update agent_releases set lifecycle_state = 'TESTING', effective_status = 'TESTING'
                 where id = ?
                """, release.id());
        return new Seed(release.id(),findingId,oracleId);
    }

    private record Seed(UUID releaseId,UUID findingId,UUID oracleId) {}
}
