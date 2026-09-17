package com.finsecseal.platform.generation;

import com.finsecseal.audit.AuditService;
import com.finsecseal.common.api.*;
import com.finsecseal.common.persistence.UuidV7;
import com.finsecseal.contract.*;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.*;
import com.finsecseal.platform.contract.*;
import com.finsecseal.platform.generation.GenerationContract.*;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Service
public class GenerationOperationService {
    private final JdbcTemplate db;
    private final ObjectMapper json;
    private final ContractPersistenceService contracts;
    private final PatchSourceService patches;
    private final SafetyContractGenerationSourceService sources;
    private final SafetyContractSemanticValidator validator;
    private final ContractReviewerCredentials credentials;
    private final GenerationEngine engine;
    private final AuditService audit;
    private final CanonicalJsonService canonical;
    private final DigestService digests;
    private final long leaseSeconds;
    public GenerationOperationService(JdbcTemplate db,ObjectMapper json,ContractPersistenceService contracts,
            PatchSourceService patches,SafetyContractGenerationSourceService sources,SafetyContractSemanticValidator validator,
            ContractReviewerCredentials credentials,GenerationEngine engine,AuditService audit,CanonicalJsonService canonical,
            DigestService digests,@Value("${finsec.generation.lease-seconds:180}") long leaseSeconds) {
        if(leaseSeconds<30 || leaseSeconds>1800) throw new IllegalArgumentException("generation lease must be 30..1800 seconds");
        this.db=db;this.json=json;this.contracts=contracts;this.patches=patches;this.sources=sources;this.validator=validator;
        this.credentials=credentials;this.engine=engine;this.audit=audit;this.canonical=canonical;this.digests=digests;this.leaseSeconds=leaseSeconds;
    }

    @Transactional
    public Operation submit(Kind kind,UUID target,UUID baseVersionId,String template,ReviewerContext reviewer) {
        return submit(kind,target,baseVersionId,template,reviewer,null);
    }
    @Transactional
    public Operation submit(Kind kind,UUID target,UUID baseVersionId,String template,ReviewerContext reviewer,IdempotencyFilter.Admission admission) {
        String stamp=credentials.authorityStamp(reviewer);
        if(!engine.available(kind)) throw new GenerationUnavailableException();
        if(!LoanReviewFinancialTemplate.KEY.equals(template)) fail(ErrorCode.VALIDATION_ERROR,"Unsupported templateKey");
        // Serialize admission within one workspace and bound the persistent queue.
        db.queryForObject("select id from workspaces where id=? for no key update",UUID.class,reviewer.workspaceId());
        if(db.queryForObject("select count(*) from generation_operations where workspace_id=? and status in ('QUEUED','RUNNING')",Integer.class,reviewer.workspaceId())>=20)
            fail(ErrorCode.RESOURCE_CONFLICT,"Generation workspace queue is full");
        UUID release=target;
        if(kind==Kind.PATCH) {
            var base=contracts.find(baseVersionId,reviewer);
            release=base.releaseId();
        }
        Source source=loadSource(kind,release,kind==Kind.PATCH?target:null,baseVersionId,template,reviewer);
        if(db.queryForObject("select count(*) from generation_operations where release_id=? and status in ('QUEUED','RUNNING')",Integer.class,release)>0)
            fail(ErrorCode.RESOURCE_CONFLICT,"One active generation operation is allowed per Release");
        String key=kind==Kind.CONTRACT?"loan-review-default":contracts.find(baseVersionId,reviewer).contractKey();
        int latest=db.queryForObject("select coalesce(max(v.version),0) from safety_contract_versions v join safety_contracts c on c.id=v.contract_id where c.release_id=? and c.contract_key=?",Integer.class,release,key);
        if(latest==Integer.MAX_VALUE) fail(ErrorCode.RESOURCE_CONFLICT,"Contract version limit reached");
        int number=latest+1;
        if(kind==Kind.PATCH && contracts.find(baseVersionId,reviewer).version()!=latest)
            fail(ErrorCode.RESOURCE_CONFLICT,"Patch generation requires the latest contract version");
        UUID id=UuidV7.generate(), versionId=UuidV7.generate();
        db.update("""
            insert into generation_operations(id,admission_id,admission_digest,workspace_id,release_id,kind,status,version_id,contract_key,version,
                template_key,reviewer_json,authority_stamp,authority_expires_at,source_json)
            values(?,?,?,?,?,?,'QUEUED',?,?,?,?,cast(? as jsonb),?,now()+interval '30 minutes',cast(? as jsonb))
            """,id,admission==null?null:admission.recordId(),admission==null?null:admission.requestDigest(),reviewer.workspaceId(),release,kind.name(),versionId,key,number,template,json.writeValueAsString(reviewer),stamp,json.writeValueAsString(source));
        audit.append(reviewer.workspaceId(),reviewer.actorId(),"GENERATION_QUEUED","GENERATION_OPERATION",id,null,null,
                json.createObjectNode().put("kind",kind.name()).put("releaseId",release.toString()));
        return find(id,reviewer);
    }

    @Transactional(readOnly=true)
    public Operation find(UUID id,ReviewerContext reviewer) {
        credentials.authorityStamp(reviewer);
        var rows=db.query("select * from generation_operations where id=? and workspace_id=? and reviewer_json->>'actorId'=?",(rs,n)->
                new Operation(rs.getObject("id",UUID.class),Kind.valueOf(rs.getString("kind")),rs.getString("status"),"/api/v1/operations/"+id,
                    rs.getObject("release_id",UUID.class),rs.getString("outcome"),parseNullable(rs.getString("result_json")),rs.getString("error_code"),
                    rs.getString("error_stage"),false,rs.getTimestamp("created_at").toInstant(),instant(rs.getTimestamp("started_at")),instant(rs.getTimestamp("finished_at"))),
                id,reviewer.workspaceId(),reviewer.actorId());
        if(rows.isEmpty()) fail(ErrorCode.RESOURCE_NOT_FOUND,"Operation not found");
        return rows.getFirst();
    }

    @Transactional
    public Optional<Work> claim() {
        var rows=db.queryForList("select * from generation_operations where status='QUEUED' order by created_at,id for update skip locked limit 1");
        if(rows.isEmpty()) return Optional.empty();
        var row=rows.getFirst();UUID id=(UUID)row.get("id");
        ReviewerContext reviewer=json.readValue(row.get("reviewer_json").toString(),ReviewerContext.class);
        if(!authorized(row,reviewer)) {
            terminal(id,"FAILED",null,"AUTHORITY_EXPIRED","ADMISSION",null);
            audit.append((UUID)row.get("workspace_id"),reviewer.actorId(),"GENERATION_FAILED","GENERATION_OPERATION",id,null,null,
                    json.createObjectNode().put("code","AUTHORITY_EXPIRED"));
            return Optional.empty();
        }
        UUID token=UUID.randomUUID();
        db.update("update generation_operations set status='RUNNING',claim_token=?,started_at=now(),lease_expires_at=now()+(? * interval '1 second') where id=?",token,leaseSeconds,id);
        return Optional.of(new Work(id,token,Kind.valueOf(row.get("kind").toString()),
                new VersionIdentity((UUID)row.get("version_id"),(UUID)row.get("workspace_id"),(UUID)row.get("release_id"),row.get("contract_key").toString(),(Integer)row.get("version")),
                row.get("template_key").toString(),reviewer,json.readValue(row.get("source_json").toString(),Source.class)));
    }

    /** Short transaction ends before C or B is called. */
    @Transactional
    public void checkBeforeModel(Work work) {
        requireClaim(work);
        requireCurrentSource(work,work.expectedSource());
    }

    @Transactional
    public void complete(Work work,Generated generated) {
        requireClaim(work);
        if(generated==null || !work.expectedSource().equals(generated.observedSource())) fail(ErrorCode.RELEASE_CHANGED,"Generation source differs from reserved input");
        requireCurrentSource(work,generated.observedSource());
        validateMetadata(work,generated.metadata());
        UUID versionId=null,proposalId=null;
        var result=json.createObjectNode().put("assessment",generated.outcome());
        if(work.kind()==Kind.CONTRACT) {
            var catalog=sources.prepare(work.identity().releaseId(),work.templateKey(),work.reviewer().actorId()).catalog();
            var decision=validator.validate(generated.policy(),catalog.semanticCatalog());
            if(!decision.status().name().equals(generated.outcome())) fail(ErrorCode.EVIDENCE_INCOMPLETE,"Generation assessment changed");
            if(!Set.of("VALID","WARN","INVALID").contains(generated.outcome())) fail(ErrorCode.VALIDATION_ERROR,"Invalid initial assessment");
            if(!"INVALID".equals(generated.outcome())) {
                var v=contracts.createReserved(work.identity().releaseId(),generated.policy(),work.reviewer(),work.identity());
                versionId=v.id();result.put("contractVersionId",v.id().toString()).put("resourceHash",v.resourceHash()).put("policyHash",v.policyHash());
            }
        } else {
            var decision=contracts.assessPatch(work.expectedSource().findingId(),work.expectedSource().baseVersionId(),generated.patch(),work.reviewer());
            if(!decision.status().name().equals(generated.outcome())) fail(ErrorCode.EVIDENCE_INCOMPLETE,"Patch assessment changed");
            if("PROPOSED".equals(generated.outcome())) {
                var saved=contracts.storePatch(work.expectedSource().findingId(),work.expectedSource().baseVersionId(),generated.patch(),work.reviewer(),work.identity());
                versionId=saved.candidate().id();proposalId=saved.patchProposalId();
                result.put("contractVersionId",versionId.toString()).put("patchProposalId",proposalId.toString())
                        .put("resourceHash",saved.candidate().resourceHash()).put("policyHash",saved.candidate().policyHash());
            }
        }
        var issues=result.putArray("issues");
        if(generated.issues()!=null && generated.issues().isArray()) for(var issue:generated.issues()) {
            String code=issue.path("code").asString("VALIDATION_ISSUE");
            issues.addObject().put("code",code.matches("[A-Z0-9_]{1,100}")?code:"VALIDATION_ISSUE");
        }
        var metadata=json.createObjectNode();
        metadata.set("generation",json.valueToTree(generated.metadata()));metadata.set("source",json.valueToTree(generated.observedSource()));
        metadata.set("reservedIdentity",json.valueToTree(work.identity()));metadata.put("outcome",generated.outcome());
        String hash=digests.sha256(canonical.canonicalize(metadata));
        db.update("insert into contract_generation_records(operation_id,version_id,patch_proposal_id,metadata_json,metadata_hash) values(?,?,?,cast(? as jsonb),?)",work.operationId(),versionId,proposalId,metadata.toString(),hash);
        if(proposalId!=null) db.update("update patch_proposals set generation_model_meta_json=cast(? as jsonb) where id=?",metadata.toString(),proposalId);
        terminal(work.operationId(),"SUCCEEDED",generated.outcome(),null,null,result);
        audit.append(work.identity().workspaceId(),work.reviewer().actorId(),"GENERATION_SUCCEEDED","GENERATION_OPERATION",work.operationId(),null,hash,result);
    }

    @Transactional
    public void fail(Work work,String code,String stage) {
        var rows=db.queryForList("select id from generation_operations where id=? and status='RUNNING' and claim_token=? and lease_expires_at>now() for update",work.operationId(),work.claimToken());
        if(rows.isEmpty()) return;
        terminal(work.operationId(),"FAILED",null,code,stage,null);
        audit.append(work.identity().workspaceId(),work.reviewer().actorId(),"GENERATION_FAILED","GENERATION_OPERATION",work.operationId(),null,null,json.createObjectNode().put("code",code).put("stage",stage));
    }

    @Transactional
    public void expire() {
        // Never send a second provider call after a crash or uncertain timeout.
        var expired=db.queryForList("update generation_operations set status='RECOVERY_REQUIRED',error_code='EXECUTION_UNCERTAIN',error_stage='WORKER',finished_at=now() where status='RUNNING' and lease_expires_at<=now() returning id,workspace_id,reviewer_json");
        for(var row:expired) {
            var reviewer=json.readValue(row.get("reviewer_json").toString(),ReviewerContext.class);
            audit.append((UUID)row.get("workspace_id"),reviewer.actorId(),"GENERATION_RECOVERY_REQUIRED","GENERATION_OPERATION",(UUID)row.get("id"),null,null,
                    json.createObjectNode().put("code","EXECUTION_UNCERTAIN"));
        }
    }

    private Map<String,Object> requireClaim(Work work) {
        var rows=db.queryForList("select * from generation_operations where id=? and status='RUNNING' and claim_token=? and lease_expires_at>now() for update",work.operationId(),work.claimToken());
        if(rows.isEmpty()) fail(ErrorCode.RESOURCE_CONFLICT,"Generation claim expired or completed");
        var row=rows.getFirst();
        if(!authorized(row,work.reviewer()) || !row.get("version_id").equals(work.identity().versionId())
                || !row.get("release_id").equals(work.identity().releaseId()) || !row.get("workspace_id").equals(work.identity().workspaceId())
                || !row.get("contract_key").equals(work.identity().contractKey()) || !row.get("version").equals(work.identity().version())
                || !row.get("kind").equals(work.kind().name()) || !row.get("template_key").equals(work.templateKey())
                || !json.readValue(row.get("source_json").toString(),Source.class).equals(work.expectedSource()))
            fail(ErrorCode.OPERATOR_AUTH_REQUIRED,"Generation authority expired");
        return row;
    }
    private boolean authorized(Map<String,Object> row,ReviewerContext reviewer) {
        try {return ((Timestamp)row.get("authority_expires_at")).toInstant().isAfter(Instant.now())
                && credentials.authorityStamp(reviewer).equals(row.get("authority_stamp"));}
        catch(RuntimeException exception) {return false;}
    }
    private void requireCurrentSource(Work work,Source expected) {
        Source current=loadSource(work.kind(),work.identity().releaseId(),expected.findingId(),expected.baseVersionId(),work.templateKey(),work.reviewer());
        if(!expected.equals(current)) fail(ErrorCode.RELEASE_CHANGED,"Generation source changed; result was not saved");
    }
    private Source loadSource(Kind kind,UUID release,UUID finding,UUID base,String template,ReviewerContext reviewer) {
        var scopes=db.queryForList("select a.workspace_id from agent_releases r join agents a on a.id=r.agent_id where r.id=? for update of r",UUID.class,release);
        if(scopes.isEmpty() || !scopes.getFirst().equals(reviewer.workspaceId())) fail(ErrorCode.RESOURCE_NOT_FOUND,"Release not found");
        if(db.queryForObject("select count(*) from test_runs where release_id=? and status in ('QUEUED','PREPARING','RUNNING','CANCELLING')",Integer.class,release)>0)
            fail(ErrorCode.RESOURCE_CONFLICT,"Finish active runs before generation");
        var prepared=sources.prepare(release,template,reviewer.actorId());var catalog=prepared.catalog();
        var binding=new SourceBinding(catalog.releaseId(),catalog.manifestSchemaVersion(),catalog.agentArtifactFingerprint(),catalog.releaseFingerprint(),catalog.serverToolCatalogHash());
        if(kind==Kind.CONTRACT) return new Source(binding,prepared.analyzedAt(),null,null,null,null,null,null,null,null,null);
        if(db.queryForList("select id from findings where id=? and release_id=? for update",UUID.class,finding,release).isEmpty()) fail(ErrorCode.RESOURCE_NOT_FOUND,"Eligible patch source not found");
        var p=patches.find(finding,reviewer);var v=contracts.find(base,reviewer);
        if(!v.releaseId().equals(release)) fail(ErrorCode.RESOURCE_NOT_FOUND,"Patch base not found");
        return new Source(binding,prepared.analyzedAt(),finding,base,v.state(),v.policyHash(),v.resourceHash(),p.facts(),p.sourceRunId(),p.sourceCaseId(),p.oracleResultId());
    }
    private void validateMetadata(Work work,Metadata meta) {
        if(meta==null || !work.templateKey().equals(meta.templateKey()) || !text(meta.promptVersion(),200)
                || !digest(meta.promptDigest()) || !text(meta.provider(),80) || !text(meta.model(),120) || meta.latencyMs()<0)
            fail(ErrorCode.EVIDENCE_INCOMPLETE,"Invalid generation metadata");
        if(work.kind()==Kind.PATCH && (!work.expectedSource().finding().evidenceDigest().equals(meta.sourceEvidenceDigest()) || !digest(meta.redactedEvidenceDigest())))
            fail(ErrorCode.EVIDENCE_INCOMPLETE,"Patch evidence metadata mismatch");
    }
    private void terminal(UUID id,String status,String outcome,String code,String stage,JsonNode result) {
        db.update("update generation_operations set status=?,outcome=?,error_code=?,error_stage=?,result_json=cast(? as jsonb),finished_at=now() where id=?",status,outcome,code,stage,result==null?null:result.toString(),id);
    }
    private boolean text(String s,int max) {return s!=null && !s.isBlank() && s.codePointCount(0,s.length())<=max;}
    private boolean digest(String s) {return s!=null && s.matches("sha256:[0-9a-f]{64}");}
    private JsonNode parseNullable(String s) {return s==null?null:json.readTree(s);}
    private static Instant instant(Timestamp t) {return t==null?null:t.toInstant();}
    private static void fail(ErrorCode code,String message) {throw new BusinessException(code,message);}
    @org.springframework.web.bind.annotation.ResponseStatus(org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE)
    public static class GenerationUnavailableException extends RuntimeException {
        public GenerationUnavailableException() {super("Generation provider is disabled");}
    }
}
