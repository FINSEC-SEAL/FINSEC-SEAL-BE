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
    @Test void proposalDetailProjectsStoredPatchAndApprovedReviewWithoutPolicyBody() throws Exception {
        PatchFixture fixture=patchFixture();
        UUID proposalId=fixture.stored().patchProposalId();
        var pending=contracts.proposalDetail(proposalId,reviewer);
        assertThat(pending.path("id").stringValue()).isEqualTo(proposalId.toString());
        assertThat(pending.path("findingId").stringValue()).isEqualTo(fixture.source().findingId().toString());
        assertThat(pending.path("releaseId").stringValue()).isEqualTo(fixture.source().releaseId().toString());
        assertThat(pending.path("baseContractVersionId").stringValue()).isEqualTo(fixture.base().id().toString());
        assertThat(pending.path("candidateContractVersionId").stringValue()).isEqualTo(fixture.validated().id().toString());
        assertThat(pending.path("basePolicyHash").stringValue()).isEqualTo(fixture.base().policyHash());
        assertThat(pending.path("candidatePolicyHash").stringValue()).isEqualTo(fixture.validated().policyHash());
        assertThat(pending.path("state").stringValue()).isEqualTo("PROPOSED");
        assertThat(pending.path("rootCause").stringValue()).isEqualTo("Excessive fields");
        assertThat(pending.path("normalWorkflowImpact").stringValue()).isEqualTo("Required workflow fields retained");
        assertThat(pending.path("rollback").stringValue()).isEqualTo("Create a reviewed replacement");
        assertThat(pending.path("diff").size()).isEqualTo(1);
        assertThat(pending.at("/diff/0/type").stringValue()).isEqualTo("NARROW_SET");
        assertThat(pending.at("/diff/0/jsonPointer").stringValue()).isEqualTo("/fieldPolicy/CUSTOMER_DATA_READ/allowed");
        assertThat(pending.at("/diff/0/value/retainedValues").isArray()).isTrue();
        assertThat(pending.at("/validation/status").stringValue()).isEqualTo("PROPOSED");
        assertThat(pending.at("/validation/narrowingValid").booleanValue()).isTrue();
        assertThat(pending.path("source").path("evidenceDigest").stringValue()).startsWith("sha256:");
        assertThat(pending.path("catalogBinding").path("serverToolCatalogHash").stringValue()).startsWith("sha256:");
        assertThat(pending.path("generation").isNull()).isTrue();
        assertThat(pending.path("review").isNull()).isTrue();
        assertThat(pending.has("recommendedRule")).isFalse();
        assertThat(pending.path("validation").has("acceptedProposal")).isFalse();
        assertThat(pending.toString()).doesNotContain("accountNumber","canonicalJson","sourceOracleResultId","inputJson");

        contracts.approve(fixture.validated().id(),'"'+fixture.validated().resourceHash()+'"',
                "Reviewed narrowing",proposalId,reviewer);
        var approved=contracts.proposalDetail(proposalId,reviewer);
        assertThat(approved.path("state").stringValue()).isEqualTo("APPROVED");
        assertThat(approved.at("/review/decision").stringValue()).isEqualTo("APPROVED");
        assertThat(approved.at("/review/comment").stringValue()).isEqualTo("Reviewed narrowing");
        assertThat(approved.at("/review/decidedAt").isString()).isTrue();
        assertThat(approved.path("generation").isNull()).isTrue();
    }
    @Test void rejectedProposalDetailRemainsReadableAfterFindingCloses() throws Exception {
        PatchFixture fixture=patchFixture();
        UUID proposalId=fixture.stored().patchProposalId();
        contracts.rejectPatchProposal(proposalId,"Review rejected",reviewer);
        jdbcTemplate.update("update findings set status='RESOLVED' where id=?",fixture.source().findingId());
        assertThatThrownBy(()->service.find(fixture.source().findingId(),reviewer)).hasMessage("Eligible patch source not found");
        var detail=contracts.proposalDetail(proposalId,reviewer);
        assertThat(detail.path("state").stringValue()).isEqualTo("REJECTED");
        assertThat(detail.at("/review/decision").stringValue()).isEqualTo("REJECTED");
        assertThat(detail.at("/review/comment").stringValue()).isEqualTo("Review rejected");
        assertThat(detail.path("generation").isNull()).isTrue();
    }
    @Test void proposalDetailChecksReviewerBeforeNarrativeAndReturnsFixedIntegrityError() throws Exception {
        PatchFixture fixture=patchFixture();
        UUID proposalId=fixture.stored().patchProposalId();
        jdbcTemplate.update("update patch_proposals set root_cause='secret-narrative' where id=?",proposalId);
        var foreign=new com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext(
                UUID.randomUUID(),"reviewer","AI_SECURITY_REVIEWER","s",true,true,false);
        var invalid=new com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext(
                reviewer.workspaceId(),"reviewer","AI_SECURITY_REVIEWER","s",false,true,false);
        assertThatThrownBy(()->contracts.proposalDetail(proposalId,foreign))
                .isInstanceOf(BusinessException.class).hasMessage("Trusted workspace reviewer context is required")
                .satisfies(error->assertThat(((BusinessException)error).errorCode()).isEqualTo(ErrorCode.OPERATOR_AUTH_REQUIRED));
        assertThatThrownBy(()->contracts.proposalDetail(proposalId,invalid))
                .isInstanceOf(BusinessException.class).hasMessage("Trusted workspace reviewer context is required");
        assertProposalIntegrity(proposalId);
        assertThatThrownBy(()->contracts.proposalDetail(UUID.randomUUID(),reviewer))
                .isInstanceOf(BusinessException.class).hasMessage("Patch proposal not found")
                .satisfies(error->assertThat(((BusinessException)error).errorCode()).isEqualTo(ErrorCode.RESOURCE_NOT_FOUND));
    }
    @Test void proposalDetailRejectsForeignAndTamperedStoredBindings() throws Exception {
        PatchFixture fixture=patchFixture();
        PatchFixture other=patchFixture();
        UUID proposalId=fixture.stored().patchProposalId();
        String originalProof=jdbcTemplate.queryForObject("select validation_json::text from patch_proposals where id=?",String.class,proposalId);
        String originalDiff=jdbcTemplate.queryForObject("select policy_diff_json::text from patch_proposals where id=?",String.class,proposalId);
        jdbcTemplate.update("update patch_proposals set base_contract_version_id=null where id=?",proposalId);
        assertProposalIntegrity(proposalId);
        jdbcTemplate.update("update patch_proposals set base_contract_version_id=? where id=?",other.base().id(),proposalId);
        assertProposalIntegrity(proposalId);
        jdbcTemplate.update("update patch_proposals set base_contract_version_id=? where id=?",fixture.base().id(),proposalId);
        jdbcTemplate.update("update patch_proposals set validation_json='{}'::jsonb where id=?",proposalId);
        assertProposalIntegrity(proposalId);
        jdbcTemplate.update("update patch_proposals set validation_json=cast(? as jsonb) where id=?",originalProof,proposalId);
        jdbcTemplate.update("update patch_proposals set validation_json=jsonb_set(validation_json,'{candidateVersionId}',to_jsonb(cast(? as text))) where id=?",
                other.validated().id().toString(),proposalId);
        assertProposalIntegrity(proposalId);
        jdbcTemplate.update("update patch_proposals set validation_json=cast(? as jsonb) where id=?",originalProof,proposalId);
        jdbcTemplate.update("update patch_proposals set policy_diff_json='[{\"kind\":\"Unknown\",\"value\":{}}]'::jsonb where id=?",proposalId);
        assertProposalIntegrity(proposalId);
        jdbcTemplate.update("update patch_proposals set policy_diff_json=cast(? as jsonb) where id=?",originalDiff,proposalId);
        jdbcTemplate.update("update patch_proposals set state='APPROVED' where id=?",proposalId);
        assertProposalIntegrity(proposalId);
        jdbcTemplate.update("update patch_proposals set state='PROPOSED' where id=?",proposalId);
        jdbcTemplate.update("update patch_proposals set generation_model_meta_json='{\"generation\":{\"provider\":\"fake\"}}'::jsonb where id=?",proposalId);
        assertProposalIntegrity(proposalId);
        jdbcTemplate.update("update patch_proposals set generation_model_meta_json='{}'::jsonb where id=?",proposalId);
        jdbcTemplate.update("update safety_contract_versions set policy_hash=? where id=?",HASH_A,fixture.validated().id());
        assertProposalIntegrity(proposalId);
    }
    @Test void proposalDetailRejectsSecretInOtherwiseBoundedNarrative() throws Exception {
        PatchFixture fixture=patchFixture();
        UUID proposalId=fixture.stored().patchProposalId();
        String secret="sk-ABCDEFGHIJKLMNOPQRST";
        jdbcTemplate.update("""
            update patch_proposals set root_cause=?,
                validation_json=jsonb_set(validation_json,'{decision,acceptedProposal,rootCause}',to_jsonb(cast(? as text)))
            where id=?
            """,secret,secret,proposalId);
        assertProposalIntegrity(proposalId);
    }
    private void assertProposalIntegrity(UUID proposalId) {
        assertThatThrownBy(()->contracts.proposalDetail(proposalId,reviewer))
                .isInstanceOf(BusinessException.class).hasMessage("Patch proposal integrity check failed")
                .satisfies(error->assertThat(((BusinessException)error).errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE));
    }
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
    @Test void rejectsPatchProposalWithOneScopedReviewAndAuditWithoutChangingCandidateOrRelease() throws Exception {
        PatchFixture fixture=patchFixture();
        UUID proposalId=fixture.stored().patchProposalId();
        var beforeRelease=releaseService.find(fixture.source().releaseId());
        var beforeCandidate=contracts.find(fixture.validated().id(),reviewer);

        var rejected=contracts.rejectPatchProposal(proposalId,"Reviewed patch risk",reviewer);
        assertThat(rejected.id()).isEqualTo(proposalId);
        assertThat(rejected.findingId()).isEqualTo(fixture.source().findingId());
        assertThat(rejected.baseContractVersionId()).isEqualTo(fixture.base().id());
        assertThat(rejected.state()).isEqualTo("REJECTED");
        assertThat(rejected.decidedAt()).isNotNull();
        assertThat(proposalState(proposalId)).isEqualTo("REJECTED");
        var review=jdbcTemplate.queryForMap("select * from patch_approvals where patch_proposal_id=?",proposalId);
        assertThat(review.get("decision")).isEqualTo("REJECTED");
        assertThat(review.get("reviewer_actor_id")).isEqualTo(reviewer.actorId());
        assertThat(review.get("comment")).isEqualTo("Reviewed patch risk");
        assertThat(review.get("base_hash")).isEqualTo(fixture.base().policyHash());
        assertThat(review.get("resulting_contract_version_id")).isNull();
        assertThat(review.get("result_hash")).isNull();
        assertThat(jdbcTemplate.queryForObject("""
            select count(*) from audit_records where resource_type='PATCH_PROPOSAL' and resource_id=?
            and action='PATCH_PROPOSAL_REJECTED' and workspace_id=?
            """,Integer.class,proposalId,reviewer.workspaceId())).isEqualTo(1);
        String auditMetadata=jdbcTemplate.queryForObject("""
            select metadata_json::text from audit_records where resource_type='PATCH_PROPOSAL' and resource_id=?
            """,String.class,proposalId);
        assertThat(auditMetadata).contains(fixture.base().policyHash()).doesNotContain("Reviewed patch risk","recommendedRule");
        assertThat(contracts.find(beforeCandidate.id(),reviewer).state()).isEqualTo("VALIDATED");
        assertThat(contracts.find(beforeCandidate.id(),reviewer).resourceHash()).isEqualTo(beforeCandidate.resourceHash());
        var afterRelease=releaseService.find(fixture.source().releaseId());
        assertThat(afterRelease.releaseFingerprint()).isEqualTo(beforeRelease.releaseFingerprint());
        assertThat(afterRelease.safetyContractHash()).isEqualTo(beforeRelease.safetyContractHash());
        assertThatThrownBy(()->contracts.approve(beforeCandidate.id(),'"'+beforeCandidate.resourceHash()+'"',
                "review",proposalId,reviewer)).hasMessageContaining("pending");
        assertThatThrownBy(()->contracts.rejectPatchProposal(proposalId,"again",reviewer)).hasMessageContaining("pending");
        assertThat(jdbcTemplate.queryForObject("select count(*) from patch_approvals where patch_proposal_id=?",
                Integer.class,proposalId)).isEqualTo(1);

        // The V16 audit scope branch rejects both a mismatched workspace and an unknown proposal.
        assertThatThrownBy(()->insertProposalAudit(UUID.randomUUID(),proposalId))
                .hasMessageContaining("audit resource and workspace must match");
        assertThatThrownBy(()->insertProposalAudit(reviewer.workspaceId(),UUID.randomUUID()))
                .hasMessageContaining("audit resource does not exist");
        assertThat(jdbcTemplate.queryForObject("select count(*) from audit_records where resource_type='PATCH_PROPOSAL' and resource_id=?",
                Integer.class,proposalId)).isEqualTo(1);
    }
    @Test void rejectsOnlyAnAuthorizedPendingProposalWithAValidBaseAndComment() throws Exception {
        PatchFixture fixture=patchFixture();
        UUID proposalId=fixture.stored().patchProposalId();
        var foreign=new com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext(
                UUID.randomUUID(),"reviewer","AI_SECURITY_REVIEWER","s",true,true,false);
        var invalid=new com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext(
                reviewer.workspaceId(),"reviewer","AI_SECURITY_REVIEWER","s",false,true,false);
        assertThatThrownBy(()->contracts.rejectPatchProposal(proposalId,"review",foreign)).hasMessageContaining("Trusted workspace");
        assertThatThrownBy(()->contracts.rejectPatchProposal(proposalId,"review",invalid)).hasMessageContaining("Trusted workspace");
        assertThatThrownBy(()->contracts.rejectPatchProposal(UUID.randomUUID(),"review",reviewer)).hasMessageContaining("not found");
        assertThatThrownBy(()->contracts.rejectPatchProposal(proposalId,"   ",reviewer)).hasMessageContaining("comment");
        assertThatThrownBy(()->contracts.rejectPatchProposal(proposalId,"x".repeat(1001),reviewer)).hasMessageContaining("comment");
        assertThat(proposalState(proposalId)).isEqualTo("PROPOSED");
        assertThat(jdbcTemplate.queryForObject("select count(*) from patch_approvals where patch_proposal_id=?",
                Integer.class,proposalId)).isZero();
        assertThat(jdbcTemplate.queryForObject("select count(*) from audit_records where resource_type='PATCH_PROPOSAL' and resource_id=?",
                Integer.class,proposalId)).isZero();

        jdbcTemplate.update("update patch_proposals set base_contract_version_id=null where id=?",proposalId);
        assertThatThrownBy(()->contracts.rejectPatchProposal(proposalId,"review",reviewer)).hasMessageContaining("base Contract");
        PatchFixture other=patchFixture();
        jdbcTemplate.update("update patch_proposals set base_contract_version_id=? where id=?",other.base().id(),proposalId);
        assertThatThrownBy(()->contracts.rejectPatchProposal(proposalId,"review",reviewer)).hasMessageContaining("base Contract");
        jdbcTemplate.update("update patch_proposals set base_contract_version_id=? where id=?",fixture.base().id(),proposalId);
        jdbcTemplate.update("update safety_contract_versions set policy_hash=? where id=?",HASH_A,fixture.base().id());
        assertThatThrownBy(()->contracts.rejectPatchProposal(proposalId,"review",reviewer)).hasMessageContaining("integrity");
        assertThat(proposalState(proposalId)).isEqualTo("PROPOSED");
        assertThat(jdbcTemplate.queryForObject("select count(*) from patch_approvals where patch_proposal_id=?",
                Integer.class,proposalId)).isZero();
    }
    @Test void competingPatchRejectionsCommitOneTerminalDecision() throws Exception {
        PatchFixture fixture=patchFixture();
        UUID proposalId=fixture.stored().patchProposalId();
        var pool=java.util.concurrent.Executors.newFixedThreadPool(2);
        boolean completed=false;
        try {
            var gate=new java.util.concurrent.CountDownLatch(1);
            java.util.concurrent.Callable<Boolean> attempt=()->{
                gate.await();
                try { contracts.rejectPatchProposal(proposalId,"review",reviewer); return true; }
                catch(RuntimeException exception) { return false; }
            };
            var first=pool.submit(attempt);var second=pool.submit(attempt);gate.countDown();
            assertThat(java.util.List.of(first.get(30,java.util.concurrent.TimeUnit.SECONDS),
                    second.get(30,java.util.concurrent.TimeUnit.SECONDS))).containsExactlyInAnyOrder(true,false);
            completed=true;
        } finally {
            pool.shutdownNow();
            boolean terminated=pool.awaitTermination(5,java.util.concurrent.TimeUnit.SECONDS);
            if(completed) assertThat(terminated).isTrue();
        }
        assertThat(proposalState(proposalId)).isEqualTo("REJECTED");
        assertThat(jdbcTemplate.queryForObject("select count(*) from patch_approvals where patch_proposal_id=?",
                Integer.class,proposalId)).isEqualTo(1);
        assertThat(jdbcTemplate.queryForObject("select count(*) from audit_records where resource_type='PATCH_PROPOSAL' and resource_id=?",
                Integer.class,proposalId)).isEqualTo(1);
    }
    @Test void patchApprovalAndRejectionSerializeOnTheRelease() throws Exception {
        PatchFixture fixture=patchFixture();
        UUID proposalId=fixture.stored().patchProposalId();
        var before=releaseService.find(fixture.source().releaseId());
        var pool=java.util.concurrent.Executors.newFixedThreadPool(2);
        boolean completed=false;
        try {
            var gate=new java.util.concurrent.CountDownLatch(1);
            var reject=pool.submit(()->{gate.await();try {contracts.rejectPatchProposal(proposalId,"reject",reviewer);return true;}
                catch(RuntimeException exception){return false;}});
            var approve=pool.submit(()->{gate.await();try {contracts.approve(fixture.validated().id(),
                '"'+fixture.validated().resourceHash()+'"',"approve",proposalId,reviewer);return true;}
                catch(RuntimeException exception){return false;}});
            gate.countDown();
            assertThat(java.util.List.of(reject.get(30,java.util.concurrent.TimeUnit.SECONDS),
                    approve.get(30,java.util.concurrent.TimeUnit.SECONDS))).containsExactlyInAnyOrder(true,false);
            completed=true;
        } finally {
            pool.shutdownNow();
            boolean terminated=pool.awaitTermination(5,java.util.concurrent.TimeUnit.SECONDS);
            if(completed) assertThat(terminated).isTrue();
        }
        String decision=jdbcTemplate.queryForObject("select decision from patch_approvals where patch_proposal_id=?",String.class,proposalId);
        assertThat(jdbcTemplate.queryForObject("select count(*) from patch_approvals where patch_proposal_id=?",
                Integer.class,proposalId)).isEqualTo(1);
        assertThat(proposalState(proposalId)).isEqualTo(decision);
        if ("REJECTED".equals(decision)) {
            assertThat(contracts.find(fixture.validated().id(),reviewer).state()).isEqualTo("VALIDATED");
            assertThat(releaseService.find(fixture.source().releaseId()).releaseFingerprint()).isEqualTo(before.releaseFingerprint());
        } else {
            assertThat(decision).isEqualTo("APPROVED");
            assertThat(contracts.find(fixture.validated().id(),reviewer).state()).isEqualTo("APPROVED");
        }
    }
    @Test void reviewOrAuditInsertFailureRollsBackPatchRejection() throws Exception {
        PatchFixture reviewFailure=patchFixture();
        UUID reviewProposalId=reviewFailure.stored().patchProposalId();
        var oversizedActor=new com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext(
                reviewer.workspaceId(),"x".repeat(121),"AI_SECURITY_REVIEWER","s",true,true,false);
        assertThatThrownBy(()->contracts.rejectPatchProposal(reviewProposalId,"review",oversizedActor)).isInstanceOf(RuntimeException.class);
        assertThat(proposalState(reviewProposalId)).isEqualTo("PROPOSED");
        assertThat(jdbcTemplate.queryForObject("select count(*) from patch_approvals where patch_proposal_id=?",
                Integer.class,reviewProposalId)).isZero();

        PatchFixture auditFailure=patchFixture();
        UUID auditProposalId=auditFailure.stored().patchProposalId();
        String constraint="ck_patch_audit_test_"+auditProposalId.toString().replace("-","");
        jdbcTemplate.execute("alter table audit_records add constraint "+constraint+
                " check (resource_id <> '"+auditProposalId+"'::uuid or action <> 'PATCH_PROPOSAL_REJECTED')");
        try {
            assertThatThrownBy(()->contracts.rejectPatchProposal(auditProposalId,"review",reviewer))
                    .hasMessageContaining(constraint);
            assertThat(proposalState(auditProposalId)).isEqualTo("PROPOSED");
            assertThat(jdbcTemplate.queryForObject("select count(*) from patch_approvals where patch_proposal_id=?",
                    Integer.class,auditProposalId)).isZero();
            assertThat(jdbcTemplate.queryForObject("select count(*) from audit_records where resource_type='PATCH_PROPOSAL' and resource_id=?",
                    Integer.class,auditProposalId)).isZero();
        } finally {
            jdbcTemplate.execute("alter table audit_records drop constraint "+constraint);
        }
    }
    private String proposalState(UUID id) {
        return jdbcTemplate.queryForObject("select state from patch_proposals where id=?",String.class,id);
    }
    private void insertProposalAudit(UUID workspaceId,UUID proposalId) {
        jdbcTemplate.update("""
            insert into audit_records(id,workspace_id,actor_id,action,resource_type,resource_id,metadata_json,occurred_at)
            values(?,?,?,'PATCH_PROPOSAL_REJECTED','PATCH_PROPOSAL',?,'{}'::jsonb,now())
            """,UUID.randomUUID(),workspaceId,"reviewer",proposalId);
    }
    private PatchFixture patchFixture() throws Exception {
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
        return new PatchFixture(source,base,stored,validated);
    }
    private record PatchFixture(Seed source,ContractPersistenceService.Version base,
                                ContractPersistenceService.StoredPatch stored,ContractPersistenceService.Version validated) {}
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
