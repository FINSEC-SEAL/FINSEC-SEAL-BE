package com.finsecseal.platform.contract;

import com.finsecseal.audit.AuditService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.persistence.UuidV7;
import com.finsecseal.contract.SafetyContractCanonicalizer;
import com.finsecseal.contract.SafetyContractPatchProposalPolicy;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.*;
import com.finsecseal.contract.SafetyContractPatchOperation;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter;
import com.finsecseal.contract.SafetyContractLifecyclePolicy;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.*;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.ReleaseService;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/** A owns persistence and source integrity; C owns every validation/approval decision. */
@Service
@Transactional(readOnly = true)
public class ContractPersistenceService {
    private final JdbcTemplate db;
    private final ObjectMapper json;
    private final SafetyContractCanonicalizer canonicalizer;
    private final SafetyContractLifecyclePolicy lifecycle;
    private final CanonicalJsonService canonical;
    private final DigestService digest;
    private final AuditService audit;
    private final ReleaseService releases;
    private final PatchSourceService patchSources;
    private final SafetyContractPatchProposalPolicy patchPolicy;
    private final ReleaseToolCatalogContractAdapter catalogs;
    public ContractPersistenceService(JdbcTemplate db, ObjectMapper json, SafetyContractCanonicalizer canonicalizer,
            SafetyContractLifecyclePolicy lifecycle, CanonicalJsonService canonical, DigestService digest,
            AuditService audit, ReleaseService releases, PatchSourceService patchSources,
            SafetyContractPatchProposalPolicy patchPolicy, ReleaseToolCatalogContractAdapter catalogs) {
        this.db=db;this.json=json;this.canonicalizer=canonicalizer;this.lifecycle=lifecycle;
        this.canonical=canonical;this.digest=digest;this.audit=audit;this.releases=releases;
        this.patchSources=patchSources;this.patchPolicy=patchPolicy;this.catalogs=catalogs;
    }
    public record Version(UUID id, UUID workspaceId, UUID releaseId, String contractKey, int version,
            String state, JsonNode policy, String policyHash, String resourceHash, String basePolicyHash,
            JsonNode validation, JsonNode review) {}
    public record ApprovedContract(Version version, String agentArtifactFingerprint, String releaseFingerprint) {}
    private record ReleaseState(UUID workspaceId, String policyHash, String artifact, String fingerprint, String state) {}

    public record History(List<JsonNode> items, String nextCursor) {}

    public JsonNode detail(Version version, ReviewerContext reviewer) {
        requireReviewer(reviewer, version.workspaceId());
        var node = (tools.jackson.databind.node.ObjectNode) json.valueToTree(version);
        UUID contractId = db.queryForObject("select contract_id from safety_contract_versions where id=?", UUID.class, version.id());
        node.put("contractId", contractId.toString());
        var diff = node.putArray("diff");
        var previous = db.queryForList("""
            select v.id from safety_contract_versions v join contract_version_evidence e on e.version_id=v.id
            where v.contract_id=? and v.version<? order by v.version desc limit 1
            """, UUID.class, contractId, version.version());
        JsonNode before = previous.isEmpty() ? json.createObjectNode() : find(previous.getFirst(), reviewer).policy();
        Set<String> fields = new TreeSet<>();
        before.properties().forEach(e -> fields.add(e.getKey()));
        version.policy().properties().forEach(e -> fields.add(e.getKey()));
        for (String field : fields) {
            if (!Objects.equals(before.get(field), version.policy().get(field))) {
                var change = diff.addObject().put("path", "/" + field.replace("~", "~0").replace("/", "~1"));
                change.set("before", before.get(field));
                change.set("after", version.policy().get(field));
            }
        }
        return node;
    }

    public JsonNode validationResult(Version version) {
        var result = (tools.jackson.databind.node.ObjectNode) version.validation().path("result").deepCopy();
        result.put("versionId", version.id().toString()).put("state", version.state())
                .put("resourceHash", version.resourceHash()).put("policyHash", version.policyHash());
        result.set("validationProof", version.validation());
        return result;
    }

    public History history(UUID contractId, int limit, String cursor, ReviewerContext reviewer) {
        if (limit < 1 || limit > 100) fail(ErrorCode.VALIDATION_ERROR, "limit must be between 1 and 100");
        var scopes = db.queryForList("select workspace_id from safety_contracts where id=?", UUID.class, contractId);
        if (scopes.isEmpty()) fail(ErrorCode.RESOURCE_NOT_FOUND, "Contract not found");
        requireReviewer(reviewer, scopes.getFirst());
        int after = 0;
        if (cursor != null) {
            try {
                String decoded = new String(Base64.getUrlDecoder().decode(cursor), java.nio.charset.StandardCharsets.UTF_8);
                String[] parts = decoded.split(":", -1);
                if (parts.length != 2 || !contractId.toString().equals(parts[0])) throw new IllegalArgumentException();
                after = Integer.parseInt(parts[1]);
                if (after < 1 || db.queryForObject("""
                    select count(*) from safety_contract_versions v join contract_version_evidence e on e.version_id=v.id
                    where v.contract_id=? and v.version=?
                    """, Integer.class, contractId, after) != 1) throw new IllegalArgumentException();
            } catch (RuntimeException exception) {
                fail(ErrorCode.VALIDATION_ERROR, "Invalid contract history cursor");
            }
        }
        var ids = db.queryForList("""
            select v.id from safety_contract_versions v join contract_version_evidence e on e.version_id=v.id
            where v.contract_id=? and v.version>? order by v.version limit ?
            """, UUID.class, contractId, after, limit + 1);
        var versions = ids.stream().limit(limit).map(id -> find(id, reviewer)).toList();
        String next = ids.size() > limit ? Base64.getUrlEncoder().withoutPadding().encodeToString(
                (contractId + ":" + versions.getLast().version()).getBytes(java.nio.charset.StandardCharsets.UTF_8)) : null;
        return new History(versions.stream().map(v -> detail(v, reviewer)).toList(), next);
    }

    @Transactional
    public Version create(UUID releaseId, JsonNode policy, ReviewerContext reviewer) {
        return createReserved(releaseId, policy, reviewer, null);
    }

    @Transactional
    public Version createReserved(UUID releaseId, JsonNode policy, ReviewerContext reviewer, VersionIdentity reservation) {
        ReleaseState release = lockRelease(releaseId, reviewer);
        if (reservation == null && db.queryForObject("select count(*) from generation_operations where release_id=? and status in ('QUEUED','RUNNING')",Integer.class,releaseId)>0)
            fail(ErrorCode.RESOURCE_CONFLICT,"A generation operation has reserved this Release");
        if (release.state().equals("DRAFT")) fail(ErrorCode.INVALID_STATE_TRANSITION,"Analyze the Release before creating a contract");
        var normalized = canonicalizer.canonicalizeAndHash(policy);
        JsonNode body = parse(normalized.canonicalJson());
        String key = body.path("contractId").stringValue();
        int number = body.path("version").intValue();
        if (key.length() > 100) fail(ErrorCode.VALIDATION_ERROR,"Contract key exceeds 100 characters");
        UUID contractId = UuidV7.generate();
        db.update("""
            insert into safety_contracts(id,workspace_id,release_id,contract_key,status) values(?,?,?,?,'ACTIVE')
            on conflict (release_id,contract_key) do nothing
            """,contractId,release.workspaceId(),releaseId,key);
        contractId=db.queryForObject("select id from safety_contracts where release_id=? and contract_key=?",UUID.class,releaseId,key);
        Integer latest=db.queryForObject("select coalesce(max(version),0) from safety_contract_versions where contract_id=?",Integer.class,contractId);
        if (number != latest+1) fail(ErrorCode.RESOURCE_CONFLICT,"Contract version must follow the latest stored version");
        UUID id=reservation==null?UuidV7.generate():reservation.versionId();
        if (reservation!=null && (!reservation.releaseId().equals(releaseId) || !reservation.workspaceId().equals(release.workspaceId())
                || !reservation.contractKey().equals(key) || reservation.version()!=number
                || db.queryForObject("select count(*) from generation_operations where version_id=? and release_id=? and contract_key=? and version=? and status='RUNNING' and lease_expires_at>now()",
                    Integer.class,id,releaseId,key,number)!=1)) fail(ErrorCode.RESOURCE_CONFLICT,"Generation reservation no longer owns this version");
        Version v=new Version(id,release.workspaceId(),releaseId,key,number,"CANDIDATE",body,normalized.policyHash(),
                "",release.policyHash(),json.createObjectNode(),json.createObjectNode());
        v=withHash(v);
        db.update("""
            insert into safety_contract_versions(id,contract_id,version,state,policy_json,policy_hash,created_by)
            values(?,?,?,'CANDIDATE',cast(? as jsonb),?,?)
            """,id,contractId,number,body.toString(),v.policyHash(),reviewer.actorId());
        db.update("insert into contract_version_evidence(version_id,base_policy_hash,resource_hash) values(?,?,?)",
                id,v.basePolicyHash(),v.resourceHash());
        record(v,reviewer,"CONTRACT_CANDIDATE_STORED",null);
        return v;
    }

    public Version find(UUID id, ReviewerContext reviewer) {
        Version v=load(id,reviewer);
        verify(v);
        return v;
    }
    public List<Version> list(UUID releaseId, ReviewerContext reviewer) {
        checkRelease(releaseId,reviewer,false);
        return db.queryForList("""
            select v.id from safety_contract_versions v join safety_contracts c on c.id=v.contract_id
            join contract_version_evidence e on e.version_id=v.id where c.release_id=? order by v.created_at,v.id
            """,UUID.class,releaseId).stream().map(id->find(id,reviewer)).toList();
    }
    @Transactional
    public Version validate(UUID id, String ifMatch, ReviewerContext reviewer) {
        Version old=locked(id,ifMatch,reviewer,true);
        var decision=lifecycle.validate(snapshot(old),reviewer.actorId());
        String next=decision.transitionCommand().isPresent()?"VALIDATED":"CANDIDATE";
        Version result=withHash(new Version(old.id(),old.workspaceId(),old.releaseId(),old.contractKey(),old.version(),next,
                old.policy(),old.policyHash(),"",old.basePolicyHash(),json.valueToTree(decision.validationProof()),old.review()));
        persist(old,result,null);
        record(result,reviewer,"CONTRACT_VALIDATED",old.resourceHash());
        return result;
    }
    @Transactional
    public Version approve(UUID id, String ifMatch, String comment, ReviewerContext reviewer) {
        return approve(id, ifMatch, comment, null, reviewer);
    }
    @Transactional
    public Version approve(UUID id, String ifMatch, String comment, UUID patchProposalId, ReviewerContext reviewer) {
        Version old=locked(id,ifMatch,reviewer,true);
        ReleaseState release=lockRelease(old.releaseId(),reviewer);
        if (!Set.of("REMEDIATION","PASS","REVIEW","BLOCKED").contains(release.state()))
            fail(ErrorCode.INVALID_STATE_TRANSITION,"Release must be in REMEDIATION or a terminal decision state before policy approval");
        var linked = db.queryForList("select id from patch_proposals where validation_json->>'candidateVersionId'=?", UUID.class, id.toString());
        if (!linked.isEmpty() && (linked.size() != 1 || !linked.getFirst().equals(patchProposalId)))
            fail(ErrorCode.RESOURCE_CONFLICT, "This candidate requires its bound patchProposalId");
        String patchBase = patchProposalId == null ? null : verifyPatch(patchProposalId, old, reviewer);
        var command=lifecycle.approve(snapshot(old),ifMatch,reviewer,comment);
        Version result=reviewed(old,command.targetState().name(),comment,reviewer,patchProposalId);
        persist(old,result,reviewer.actorId());
        releases.applySafetyContractHash(old.releaseId(),old.policyHash(),json.createObjectNode()
                .put("contractVersionId",id.toString()).put("reviewer",reviewer.actorId()));
        if (patchProposalId != null) {
            db.update("update patch_proposals set state='APPROVED',updated_at=now() where id=?", patchProposalId);
            db.update("""
                insert into patch_approvals(id,patch_proposal_id,resulting_contract_version_id,decision,
                    reviewer_actor_id,comment,base_hash,result_hash,decided_at)
                values(?,?,?,'APPROVED',?,?,?,?,now())
                """, UuidV7.generate(), patchProposalId, result.id(), reviewer.actorId(), comment, patchBase, result.policyHash());
        }
        record(result,reviewer,"CONTRACT_APPROVED",old.resourceHash());
        return result;
    }
    @Transactional
    public Version reject(UUID id, String ifMatch, String comment, ReviewerContext reviewer) {
        Version old=locked(id,ifMatch,reviewer,false);
        var command=lifecycle.reject(snapshot(old),ifMatch,reviewer,comment);
        Version result=reviewed(old,command.targetState().name(),comment,reviewer,null);
        persist(old,result,null);
        record(result,reviewer,"CONTRACT_REJECTED",old.resourceHash());
        return result;
    }
    /** Read under the same Release lock as approval. Old or legacy approvals never become current authority. */
    @Transactional
    public ApprovedContract approved(UUID releaseId, UUID versionId, ReviewerContext reviewer) {
        ReleaseState r=lockRelease(releaseId,reviewer);
        Version v=find(versionId,reviewer);
        if (!v.releaseId().equals(releaseId) || !v.state().equals("APPROVED")
                || !Objects.equals(v.policyHash(),r.policyHash()) || v.validation().isEmpty() || v.review().isEmpty())
            fail(ErrorCode.RELEASE_CHANGED,"Contract is not the current approved policy for this Release");
        releases.fingerprint(releaseId,reviewer.actorId());
        return new ApprovedContract(v,r.artifact(),r.fingerprint());
    }

    public record StoredPatch(UUID patchProposalId, Version candidate) {}

    /** C/B supply a candidate, never an accepted flag; the server reloads all source facts and reruns C. */
    @Transactional
    public StoredPatch storePatch(UUID findingId, UUID baseVersionId, ProposedPatch candidate, ReviewerContext reviewer) {
        return storePatch(findingId, baseVersionId, candidate, reviewer, null);
    }
    @Transactional
    public StoredPatch storePatch(UUID findingId, UUID baseVersionId, ProposedPatch candidate, ReviewerContext reviewer, VersionIdentity reservation) {
        Version base = find(baseVersionId, reviewer);
        lockRelease(base.releaseId(), reviewer);
        base = find(baseVersionId, reviewer);
        if (db.queryForList("select id from findings where id=? and release_id=? for update", UUID.class, findingId, base.releaseId()).isEmpty())
            fail(ErrorCode.RESOURCE_NOT_FOUND, "Eligible patch source not found");
        var decision = patchPolicy.evaluate(patchSources.find(findingId, reviewer).facts(), snapshot(base), candidate,
                catalogs.load(base.releaseId(), reviewer.actorId()));
        if (decision.status() != Status.PROPOSED) fail(ErrorCode.VALIDATION_ERROR, "C rejected the proposed policy change");
        var accepted = decision.acceptedProposal().orElseThrow();
        Version result = createReserved(base.releaseId(), parse(accepted.resultPolicy().canonicalJson()), reviewer, reservation);
        UUID id = UuidV7.generate();
        var operations = json.createArrayNode();
        for (var operation : accepted.operations()) {
            operations.addObject().put("kind", operation.getClass().getSimpleName()).set("value", json.valueToTree(operation));
        }
        var proof = json.createObjectNode().put("candidateVersionId", result.id().toString());
        proof.set("decision", json.valueToTree(decision));
        db.update("""
            insert into patch_proposals(id,finding_id,base_contract_version_id,state,root_cause,recommended_rule_json,
                policy_diff_json,normal_workflow_impact_json,rollback_json,generation_model_meta_json,validation_json)
            values(?,?,?,'PROPOSED',?,cast(? as jsonb),cast(? as jsonb),cast(? as jsonb),cast(? as jsonb),'{}',cast(? as jsonb))
            """, id, findingId, base.id(), accepted.rootCause(), result.policy().toString(), operations.toString(),
                json.valueToTree(accepted.normalWorkflowImpact()).toString(), json.valueToTree(accepted.rollback()).toString(), proof.toString());
        record(result, reviewer, "CONTRACT_PATCH_STORED", base.resourceHash());
        return new StoredPatch(id, result);
    }

    @Transactional
    public ProposalDecision assessPatch(UUID findingId,UUID baseId,ProposedPatch candidate,ReviewerContext reviewer) {
        Version base=find(baseId,reviewer);
        lockRelease(base.releaseId(),reviewer);
        base=find(baseId,reviewer);
        return patchPolicy.evaluate(patchSources.find(findingId,reviewer).facts(),snapshot(base),candidate,
                catalogs.load(base.releaseId(),reviewer.actorId()));
    }

    private String verifyPatch(UUID proposalId, Version candidate, ReviewerContext reviewer) {
        // Read and authorize provenance before loading proposal text or its evidence.
        var metadata = db.query("""
            select p.finding_id,p.base_contract_version_id,p.state,f.release_id
            from patch_proposals p join findings f on f.id=p.finding_id where p.id=? for update of p,f
            """, (rs,n) -> new Object[]{rs.getObject(1,UUID.class), rs.getObject(2,UUID.class), rs.getString(3), rs.getObject(4,UUID.class)}, proposalId);
        if (metadata.isEmpty()) fail(ErrorCode.RESOURCE_NOT_FOUND, "Patch proposal not found");
        var row = metadata.getFirst();
        if (!candidate.releaseId().equals(row[3]) || !"PROPOSED".equals(row[2]))
            fail(ErrorCode.RESOURCE_CONFLICT, "Patch proposal must be pending in the candidate Release");
        var source = patchSources.find((UUID) row[0], reviewer).facts();
        Version base = find((UUID) row[1], reviewer);
        var data = db.queryForMap("select * from patch_proposals where id=?", proposalId);
        JsonNode proof = parse(data.get("validation_json").toString());
        if (!candidate.id().toString().equals(proof.path("candidateVersionId").asString(null)))
            fail(ErrorCode.RESOURCE_CONFLICT, "Patch proposal is not bound to this candidate version");
        var operations = new ArrayList<SafetyContractPatchOperation>();
        try {
            for (var operation : parse(data.get("policy_diff_json").toString())) {
                Class<? extends SafetyContractPatchOperation> type = switch(operation.path("kind").stringValue()) {
                    case "AddConstraint" -> SafetyContractPatchOperation.AddConstraint.class;
                    case "NarrowSet" -> SafetyContractPatchOperation.NarrowSet.class;
                    case "LowerLimit" -> SafetyContractPatchOperation.LowerLimit.class;
                    case "DenyTool" -> SafetyContractPatchOperation.DenyTool.class;
                    case "SetHumanOnly" -> SafetyContractPatchOperation.SetHumanOnly.class;
                    default -> throw new IllegalArgumentException();
                };
                operations.add(json.treeToValue(operation.path("value"), type));
            }
        } catch (RuntimeException exception) { fail(ErrorCode.EVIDENCE_INCOMPLETE, "Invalid stored patch operations"); }
        var proposed = new ProposedPatch(parse(data.get("recommended_rule_json").toString()), operations,
                data.get("root_cause").toString(), parse(data.get("normal_workflow_impact_json").toString()).stringValue(),
                parse(data.get("rollback_json").toString()).stringValue());
        var decision = patchPolicy.evaluate(source, snapshot(base), proposed, catalogs.load(base.releaseId(), reviewer.actorId()));
        if (decision.status() != Status.PROPOSED || !json.valueToTree(decision).equals(proof.path("decision"))
                || !decision.acceptedProposal().orElseThrow().resultPolicy().policyHash().equals(candidate.policyHash()))
            fail(ErrorCode.EVIDENCE_INCOMPLETE, "Patch approval evidence changed or does not match candidate");
        return base.policyHash();
    }

    private Version reviewed(Version old,String state,String comment,ReviewerContext r,UUID patchProposalId) {
        JsonNode review=json.createObjectNode().put("actorId",r.actorId()).put("role",r.role())
                .put("sessionId",r.sessionId()).put("comment",comment).put("decision",state);
        if (patchProposalId != null) ((tools.jackson.databind.node.ObjectNode) review).put("patchProposalId", patchProposalId.toString());
        return withHash(new Version(old.id(),old.workspaceId(),old.releaseId(),old.contractKey(),old.version(),state,
                old.policy(),old.policyHash(),"",old.basePolicyHash(),old.validation(),review));
    }
    private Version locked(UUID id,String ifMatch,ReviewerContext reviewer,boolean currentBase) {
        Version initial=load(id,reviewer);
        ReleaseState release=lockRelease(initial.releaseId(),reviewer);
        Version v=find(id,reviewer);
        if (!Objects.equals(ifMatch,'"'+v.resourceHash()+'"')) fail(ErrorCode.RESOURCE_CONFLICT,"Stale or invalid strong If-Match");
        if (currentBase && !Objects.equals(v.basePolicyHash(),release.policyHash()))
            fail(ErrorCode.RELEASE_CHANGED,"The base policy changed; create and validate a new candidate");
        if (currentBase && db.queryForObject("select count(*) from test_runs where release_id=? and status in ('QUEUED','PREPARING','RUNNING','CANCELLING')",Integer.class,v.releaseId())>0)
            fail(ErrorCode.RESOURCE_CONFLICT,"Finish active runs before changing their policy configuration");
        return v;
    }
    private void persist(Version old,Version next,String approver) {
        int evidence=db.update("update contract_version_evidence set resource_hash=?,review_json=cast(? as jsonb) where version_id=? and resource_hash=?",
                next.resourceHash(),next.review().toString(),old.id(),old.resourceHash());
        int updated=db.update("""
            update safety_contract_versions set state=?,validation_json=cast(? as jsonb),validator_version=?,
            approved_by=?,approved_at=case when cast(? as text) is null then null else now() end,updated_at=now()
            where id=? and state=? and policy_hash=?
            """,next.state(),next.validation().toString(),next.validation().path("validatorVersion").asString(null),
                approver,approver,old.id(),old.state(),old.policyHash());
        if(evidence!=1||updated!=1) fail(ErrorCode.RESOURCE_CONFLICT,"Contract version changed concurrently");
    }
    private ContractVersionSnapshot snapshot(Version v) {
        Optional<ValidationProof> proof=v.validation().isEmpty()?Optional.empty():Optional.of(json.treeToValue(v.validation(),ValidationProof.class));
        return new ContractVersionSnapshot(new VersionIdentity(v.id(),v.workspaceId(),v.releaseId(),v.contractKey(),v.version()),
                VersionState.valueOf(v.state()),v.policy(),v.policyHash(),v.resourceHash(),Optional.ofNullable(v.basePolicyHash()),proof);
    }
    private Version load(UUID id, ReviewerContext reviewer) {
        List<UUID> scopes=db.queryForList("""
            select c.workspace_id from safety_contract_versions v
            join safety_contracts c on c.id=v.contract_id where v.id=?
            """,UUID.class,id);
        if(scopes.isEmpty()) fail(ErrorCode.RESOURCE_NOT_FOUND,"Server-owned contract version not found");
        requireReviewer(reviewer,scopes.getFirst());
        List<Version> rows=db.query("""
            select v.*,c.workspace_id,c.release_id,c.contract_key,e.base_policy_hash,e.resource_hash,e.review_json
            from safety_contract_versions v join safety_contracts c on c.id=v.contract_id
            join contract_version_evidence e on e.version_id=v.id where v.id=?
            """,(rs,n)->new Version(rs.getObject("id",UUID.class),rs.getObject("workspace_id",UUID.class),rs.getObject("release_id",UUID.class),
                rs.getString("contract_key"),rs.getInt("version"),rs.getString("state"),parse(rs.getString("policy_json")),rs.getString("policy_hash"),
                rs.getString("resource_hash"),rs.getString("base_policy_hash"),parse(rs.getString("validation_json")),parse(rs.getString("review_json"))),id);
        if(rows.isEmpty()) fail(ErrorCode.RESOURCE_NOT_FOUND,"Server-owned contract version not found");
        return rows.getFirst();
    }
    private ReleaseState lockRelease(UUID id,ReviewerContext r) { return checkRelease(id,r,true); }
    private ReleaseState checkRelease(UUID id,ReviewerContext reviewer,boolean lock) {
        var rows=db.query("""
            select a.workspace_id,r.safety_contract_hash,r.agent_artifact_fingerprint,r.release_fingerprint,r.lifecycle_state
            from agent_releases r join agents a on a.id=r.agent_id where r.id=?
            """+(lock?" for update of r":""),(rs,n)->new ReleaseState(rs.getObject(1,UUID.class),rs.getString(2),rs.getString(3),rs.getString(4),rs.getString(5)),id);
        if(rows.isEmpty()) fail(ErrorCode.RESOURCE_NOT_FOUND,"Release not found");
        requireReviewer(reviewer,rows.getFirst().workspaceId());
        return rows.getFirst();
    }
    static void requireReviewer(ReviewerContext r,UUID workspace) {
        if(r==null||workspace==null||!r.authenticated()||!r.csrfVerified()||!workspace.equals(r.workspaceId())
                ||!"AI_SECURITY_REVIEWER".equals(r.role())||r.actorId()==null||r.actorId().isBlank()||r.sessionId()==null||r.sessionId().isBlank())
            fail(ErrorCode.OPERATOR_AUTH_REQUIRED,"Trusted workspace reviewer context is required");
    }
    private void verify(Version v) {
        if(!canonicalizer.canonicalizeAndHash(v.policy()).policyHash().equals(v.policyHash()) || !hash(v).equals(v.resourceHash()))
            fail(ErrorCode.EVIDENCE_INCOMPLETE,"Contract persistence integrity check failed");
    }
    private String hash(Version v) {
        var node=json.valueToTree(v).deepCopy();
        ((tools.jackson.databind.node.ObjectNode)node).remove("resourceHash");
        return digest.sha256(canonical.canonicalize(node));
    }
    private Version withHash(Version v) {
        return new Version(v.id(),v.workspaceId(),v.releaseId(),v.contractKey(),v.version(),v.state(),v.policy(),v.policyHash(),hash(v),v.basePolicyHash(),v.validation(),v.review());
    }
    private JsonNode parse(String s) { return json.readTree(s); }
    private void record(Version v,ReviewerContext r,String action,String before) {
        audit.append(v.workspaceId(),r.actorId(),action,"CONTRACT_VERSION",v.id(),before,v.resourceHash(),
                json.createObjectNode().put("state",v.state()).put("policyHash",v.policyHash()));
    }
    private static void fail(ErrorCode code,String message) { throw new BusinessException(code,message); }
}
