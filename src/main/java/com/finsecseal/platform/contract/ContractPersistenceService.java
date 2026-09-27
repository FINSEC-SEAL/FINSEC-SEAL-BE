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
import com.finsecseal.evidence.RedactionService;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.ReleaseService;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

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
    private final RedactionService redaction;
    public ContractPersistenceService(JdbcTemplate db, ObjectMapper json, SafetyContractCanonicalizer canonicalizer,
            SafetyContractLifecyclePolicy lifecycle, CanonicalJsonService canonical, DigestService digest,
            AuditService audit, ReleaseService releases, PatchSourceService patchSources,
            SafetyContractPatchProposalPolicy patchPolicy, ReleaseToolCatalogContractAdapter catalogs,
            RedactionService redaction) {
        this.db=db;this.json=json;this.canonicalizer=canonicalizer;this.lifecycle=lifecycle;
        this.canonical=canonical;this.digest=digest;this.audit=audit;this.releases=releases;
        this.patchSources=patchSources;this.patchPolicy=patchPolicy;this.catalogs=catalogs;
        this.redaction=redaction;
    }
    public record Version(UUID id, UUID workspaceId, UUID releaseId, String contractKey, int version,
            String state, JsonNode policy, String policyHash, String resourceHash, String basePolicyHash,
            JsonNode validation, JsonNode review) {}
    public record ApprovedContract(Version version, String agentArtifactFingerprint, String releaseFingerprint) {}
    private record ReleaseState(UUID workspaceId, String policyHash, String artifact, String fingerprint, String state) {}
    private record PatchReview(UUID findingId, UUID baseVersionId, String state, UUID releaseId) {}
    private record ProposalScope(UUID findingId, UUID releaseId, UUID workspaceId) {}
    private record ProposalEvidence(UUID findingId, UUID releaseId, UUID baseVersionId, String state,
            String rootCause, String recommendedRule, String diff, String impact, String rollback,
            String generation, String validation, String sourceEvidenceDigest, String violatedInvariant,
            Instant createdAt, Instant updatedAt) {}
    private record ProposalReview(UUID candidateId, String decision, String actorId, String comment,
            String baseHash, String resultHash, Instant decidedAt) {}
    private record GenerationEvidence(UUID operationId, UUID versionId, String metadata, String metadataHash,
            UUID workspaceId, UUID releaseId, String kind, String status, String outcome, String source) {}

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
    public record RejectedPatch(UUID id, UUID findingId, UUID baseContractVersionId, String state, Instant decidedAt) {}

    /** Historical reviewer detail from one snapshot; current Finding eligibility is not re-evaluated. */
    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public JsonNode proposalDetail(UUID proposalId, ReviewerContext reviewer) {
        // The first read contains only ownership metadata, never narratives or model metadata.
        var scopes = db.query("""
            select p.finding_id,f.release_id,a.workspace_id
            from patch_proposals p join findings f on f.id=p.finding_id
            join agent_releases r on r.id=f.release_id join agents a on a.id=r.agent_id
            where p.id=?
            """, (rs,n) -> new ProposalScope(rs.getObject(1,UUID.class), rs.getObject(2,UUID.class),
                    rs.getObject(3,UUID.class)), proposalId);
        if (scopes.isEmpty()) fail(ErrorCode.RESOURCE_NOT_FOUND, "Patch proposal not found");
        ProposalScope scope = scopes.getFirst();
        requireReviewer(reviewer, scope.workspaceId());
        try {
            return readProposalDetail(proposalId, scope, reviewer);
        } catch (DataAccessException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw proposalIntegrity();
        }
    }

    private JsonNode readProposalDetail(UUID proposalId, ProposalScope scope, ReviewerContext reviewer) {
        var rows = db.query("""
            select p.finding_id,f.release_id,p.base_contract_version_id,p.state,p.root_cause,
                   p.recommended_rule_json::text,p.policy_diff_json::text,
                   p.normal_workflow_impact_json::text,p.rollback_json::text,
                   p.generation_model_meta_json::text,p.validation_json::text,
                   o.evidence_digest,f.violated_invariant,p.created_at,p.updated_at
            from patch_proposals p join findings f on f.id=p.finding_id
            join oracle_results o on o.id=f.source_oracle_result_id where p.id=?
            """, (rs,n) -> new ProposalEvidence(rs.getObject(1,UUID.class),rs.getObject(2,UUID.class),
                    rs.getObject(3,UUID.class),rs.getString(4),rs.getString(5),rs.getString(6),rs.getString(7),
                    rs.getString(8),rs.getString(9),rs.getString(10),rs.getString(11),rs.getString(12),
                    rs.getString(13),rs.getTimestamp(14).toInstant(),rs.getTimestamp(15).toInstant()), proposalId);
        if (rows.size()!=1) throw proposalIntegrity();
        ProposalEvidence row = rows.getFirst();
        if (!scope.findingId().equals(row.findingId()) || !scope.releaseId().equals(row.releaseId())
                || row.baseVersionId()==null || !Set.of("PROPOSED","APPROVED","REJECTED").contains(row.state()))
            throw proposalIntegrity();
        Version base = find(row.baseVersionId(), reviewer);
        JsonNode proof = parse(row.validation());
        UUID candidateId = proposalUuid(proof.path("candidateVersionId"));
        Version candidate = find(candidateId, reviewer);
        if (!scope.workspaceId().equals(base.workspaceId()) || !scope.workspaceId().equals(candidate.workspaceId())
                || !scope.releaseId().equals(base.releaseId()) || !scope.releaseId().equals(candidate.releaseId())
                || !base.contractKey().equals(candidate.contractKey()) || candidate.version()!=base.version()+1
                || !candidate.policyHash().equals(canonicalizer.canonicalizeAndHash(parse(row.recommendedRule())).policyHash()))
            throw proposalIntegrity();

        JsonNode decision = proof.path("decision");
        JsonNode accepted = decision.path("acceptedProposal");
        JsonNode source = accepted.path("source");
        JsonNode catalog = accepted.path("catalogBinding");
        JsonNode narrowing = decision.path("narrowing");
        JsonNode semantic = decision.path("semantic");
        if (!"PROPOSED".equals(proposalText(decision,"status")) || !decision.path("issues").isArray()
                || !decision.path("issues").isEmpty() || !accepted.isObject()
                || !scope.findingId().equals(proposalUuid(source.path("findingId")))
                || !scope.workspaceId().equals(proposalUuid(source.path("workspaceId")))
                || !scope.releaseId().equals(proposalUuid(source.path("releaseId")))
                || !Set.of("OPEN","TRIAGED").contains(proposalText(source,"findingStatus"))
                || !Set.of("SEED","MUTATION").contains(proposalText(source,"sourcePartition"))
                || !source.path("hiddenFromPatchGenerator").isBoolean()
                || source.path("hiddenFromPatchGenerator").booleanValue()
                || !proposalDigest(source,"evidenceDigest").equals(proposalDigest(row.sourceEvidenceDigest()))
                || !proposalText(source,"violatedInvariant").equals(row.violatedInvariant())
                || !base.id().equals(proposalUuid(accepted.path("baseIdentity").path("versionId")))
                || !base.workspaceId().equals(proposalUuid(accepted.path("baseIdentity").path("workspaceId")))
                || !base.releaseId().equals(proposalUuid(accepted.path("baseIdentity").path("releaseId")))
                || !base.contractKey().equals(proposalText(accepted.path("baseIdentity"),"contractKey"))
                || base.version()!=proposalInteger(accepted.path("baseIdentity"),"version")
                || !base.policyHash().equals(proposalDigest(accepted,"basePolicyHash"))
                || !candidate.policyHash().equals(proposalDigest(accepted.path("resultPolicy"),"policyHash"))
                || !canonicalizer.canonicalizeAndHash(parse(proposalText(accepted.path("resultPolicy"),"canonicalJson")))
                    .policyHash().equals(candidate.policyHash())
                || !scope.releaseId().equals(proposalUuid(catalog.path("releaseId")))
                || !narrowing.path("valid").isBoolean() || !narrowing.path("valid").booleanValue()
                || !narrowing.path("issues").isArray() || !narrowing.path("issues").isEmpty()
                || !Set.of("VALID","WARN").contains(proposalText(semantic,"status")))
            throw proposalIntegrity();
        proposalText(catalog,"manifestSchemaVersion");
        proposalDigest(catalog,"agentArtifactFingerprint");
        proposalDigest(catalog,"releaseFingerprint");
        proposalDigest(catalog,"serverToolCatalogHash");

        String impact = proposalString(parse(row.impact()));
        String rollback = proposalString(parse(row.rollback()));
        if (!proposalText(accepted,"rootCause").equals(row.rootCause())
                || !proposalText(accepted,"normalWorkflowImpact").equals(impact)
                || !proposalText(accepted,"rollback").equals(rollback)) throw proposalIntegrity();
        JsonNode storedDiff = parse(row.diff());
        if (!storedDiff.isArray() || storedDiff.isEmpty() || storedDiff.size()>100) throw proposalIntegrity();
        List<SafetyContractPatchOperation> operations = new ArrayList<>();
        ArrayNode diff = json.createArrayNode();
        for (JsonNode entry : storedDiff) {
            String kind = proposalText(entry,"kind");
            Class<? extends SafetyContractPatchOperation> type = switch (kind) {
                case "AddConstraint" -> SafetyContractPatchOperation.AddConstraint.class;
                case "NarrowSet" -> SafetyContractPatchOperation.NarrowSet.class;
                case "LowerLimit" -> SafetyContractPatchOperation.LowerLimit.class;
                case "DenyTool" -> SafetyContractPatchOperation.DenyTool.class;
                case "SetHumanOnly" -> SafetyContractPatchOperation.SetHumanOnly.class;
                default -> throw proposalIntegrity();
            };
            SafetyContractPatchOperation operation = json.treeToValue(entry.path("value"), type);
            operations.add(operation);
            diff.addObject().put("type", operation.type().name()).put("jsonPointer", operation.jsonPointer())
                    .set("value", json.valueToTree(operation));
        }
        if (!json.valueToTree(operations).equals(accepted.path("operations"))
                || !narrowing.path("validatedPatch").path("operations").equals(accepted.path("operations"))
                || !base.policyHash().equals(proposalDigest(narrowing.path("validatedPatch"),"basePolicyHash"))
                || !candidate.policyHash().equals(proposalDigest(narrowing.path("validatedPatch"),"resultPolicyHash")))
            throw proposalIntegrity();

        var reviews = db.query("""
            select resulting_contract_version_id,decision,reviewer_actor_id,comment,base_hash,result_hash,decided_at
            from patch_approvals where patch_proposal_id=?
            """, (rs,n) -> new ProposalReview(rs.getObject(1,UUID.class),rs.getString(2),rs.getString(3),
                    rs.getString(4),rs.getString(5),rs.getString(6),rs.getTimestamp(7).toInstant()), proposalId);
        if (reviews.size()>1 || ("PROPOSED".equals(row.state()) != reviews.isEmpty())) throw proposalIntegrity();
        ProposalReview review = reviews.isEmpty() ? null : reviews.getFirst();
        if (review!=null && (!row.state().equals(review.decision())
                || !base.policyHash().equals(proposalDigest(review.baseHash()))
                || ("APPROVED".equals(row.state())
                    ? !candidate.id().equals(review.candidateId()) || !candidate.policyHash().equals(proposalDigest(review.resultHash()))
                        || !"APPROVED".equals(candidate.state())
                        || !proposalId.equals(proposalUuid(candidate.review().path("patchProposalId")))
                    : review.candidateId()!=null || review.resultHash()!=null || "APPROVED".equals(candidate.state()))))
            throw proposalIntegrity();
        if (review==null && "APPROVED".equals(candidate.state())) throw proposalIntegrity();

        JsonNode generation = verifiedGeneration(proposalId, scope, row, base, candidate, source, catalog);
        ObjectNode detail = json.createObjectNode();
        detail.put("id",proposalId.toString()).put("findingId",scope.findingId().toString())
                .put("releaseId",scope.releaseId().toString()).put("baseContractVersionId",base.id().toString())
                .put("candidateContractVersionId",candidate.id().toString()).put("basePolicyHash",base.policyHash())
                .put("candidatePolicyHash",candidate.policyHash()).put("state",row.state())
                .put("rootCause",row.rootCause()).put("normalWorkflowImpact",impact).put("rollback",rollback)
                .put("createdAt",row.createdAt().toString()).put("updatedAt",row.updatedAt().toString());
        detail.set("diff",diff);
        ObjectNode validation = detail.putObject("validation");
        validation.put("status","PROPOSED").put("narrowingValid",true)
                .put("semanticStatus",proposalText(semantic,"status"));
        ArrayNode issues = validation.putArray("issues");
        JsonNode semanticIssues = semantic.path("issues");
        if (!semanticIssues.isArray() || semanticIssues.size()>100) throw proposalIntegrity();
        for (JsonNode issue : semanticIssues) {
            String code = proposalText(issue,"code");
            String pointer = proposalText(issue,"jsonPointer");
            if (!code.matches("[A-Z0-9_]{1,100}") || !pointer.startsWith("/") || pointer.length()>300
                    || !"WARNING".equals(proposalText(issue,"severity"))) throw proposalIntegrity();
            issues.addObject().put("code",code).put("jsonPointer",pointer).put("severity","WARNING");
        }
        if (("VALID".equals(proposalText(semantic,"status")) != issues.isEmpty())) throw proposalIntegrity();
        detail.putObject("source").put("partition",proposalText(source,"sourcePartition"))
                .put("evidenceDigest",proposalDigest(source,"evidenceDigest"))
                .put("violatedInvariant",row.violatedInvariant());
        detail.putObject("catalogBinding").put("manifestSchemaVersion",proposalText(catalog,"manifestSchemaVersion"))
                .put("agentArtifactFingerprint",proposalDigest(catalog,"agentArtifactFingerprint"))
                .put("releaseFingerprint",proposalDigest(catalog,"releaseFingerprint"))
                .put("serverToolCatalogHash",proposalDigest(catalog,"serverToolCatalogHash"));
        if (generation==null) detail.putNull("generation"); else detail.set("generation",generation);
        if (review==null) detail.putNull("review");
        else detail.putObject("review").put("decision",review.decision()).put("reviewerActorId",review.actorId())
                .put("comment",review.comment()).put("decidedAt",review.decidedAt().toString());
        return redaction.redact(detail).redacted();
    }

    private JsonNode verifiedGeneration(UUID proposalId, ProposalScope scope, ProposalEvidence row,
            Version base, Version candidate, JsonNode source, JsonNode catalog) {
        JsonNode metadata = parse(row.generation());
        var records = db.query("""
            select g.operation_id,g.version_id,g.metadata_json::text,g.metadata_hash,
                   o.workspace_id,o.release_id,o.kind,o.status,o.outcome,o.source_json::text
            from contract_generation_records g join generation_operations o on o.id=g.operation_id
            where g.patch_proposal_id=?
            """, (rs,n) -> new GenerationEvidence(rs.getObject(1,UUID.class),rs.getObject(2,UUID.class),
                    rs.getString(3),rs.getString(4),rs.getObject(5,UUID.class),rs.getObject(6,UUID.class),
                    rs.getString(7),rs.getString(8),rs.getString(9),rs.getString(10)), proposalId);
        if (records.isEmpty() && metadata.isObject() && metadata.isEmpty()) return null;
        if (records.size()!=1 || !metadata.isObject() || metadata.isEmpty()) throw proposalIntegrity();
        GenerationEvidence record = records.getFirst();
        JsonNode committed = parse(record.metadata());
        if (!metadata.equals(committed) || !digest.sha256(canonical.canonicalize(committed)).equals(proposalDigest(record.metadataHash()))
                || !candidate.id().equals(record.versionId()) || !scope.workspaceId().equals(record.workspaceId())
                || !scope.releaseId().equals(record.releaseId()) || !"PATCH".equals(record.kind())
                || !"SUCCEEDED".equals(record.status()) || !"PROPOSED".equals(record.outcome())
                || !parse(record.source()).equals(committed.path("source"))
                || !source.equals(committed.path("source").path("finding"))
                || !catalog.equals(committed.path("source").path("catalog"))
                || !scope.findingId().equals(proposalUuid(committed.path("source").path("findingId")))
                || !base.id().equals(proposalUuid(committed.path("source").path("baseVersionId")))
                || !base.policyHash().equals(proposalDigest(committed.path("source"),"basePolicyHash"))
                || !candidate.id().equals(proposalUuid(committed.path("reservedIdentity").path("versionId")))
                || !candidate.workspaceId().equals(proposalUuid(committed.path("reservedIdentity").path("workspaceId")))
                || !candidate.releaseId().equals(proposalUuid(committed.path("reservedIdentity").path("releaseId")))
                || !candidate.contractKey().equals(proposalText(committed.path("reservedIdentity"),"contractKey"))
                || candidate.version()!=proposalInteger(committed.path("reservedIdentity"),"version")
                || !"PROPOSED".equals(proposalText(committed,"outcome"))) throw proposalIntegrity();
        JsonNode model = committed.path("generation");
        if (!model.path("latencyMs").isIntegralNumber() || !model.path("latencyMs").canConvertToLong()
                || model.path("latencyMs").longValue()<0
                || !proposalDigest(model,"sourceEvidenceDigest").equals(proposalDigest(source,"evidenceDigest")))
            throw proposalIntegrity();
        ObjectNode result = json.createObjectNode();
        result.put("operationId",record.operationId().toString())
                .put("templateKey",proposalText(model,"templateKey"))
                .put("promptVersion",proposalText(model,"promptVersion"))
                .put("promptDigest",proposalDigest(model,"promptDigest"))
                .put("provider",proposalText(model,"provider"))
                .put("model",proposalText(model,"model"))
                .put("latencyMs",model.path("latencyMs").longValue())
                .put("sourceEvidenceDigest",proposalDigest(model,"sourceEvidenceDigest"))
                .put("redactedEvidenceDigest",proposalDigest(model,"redactedEvidenceDigest"))
                .put("metadataHash",proposalDigest(record.metadataHash()));
        return result;
    }

    private static String proposalText(JsonNode node, String field) { return proposalString(node.path(field)); }
    private static String proposalString(JsonNode node) {
        if (!node.isString() || node.stringValue().isBlank()) throw proposalIntegrity();
        return node.stringValue();
    }
    private static String proposalDigest(JsonNode node, String field) { return proposalDigest(proposalText(node,field)); }
    private static String proposalDigest(String value) {
        if (value==null || !value.matches("sha256:[0-9a-f]{64}")) throw proposalIntegrity();
        return value;
    }
    private static UUID proposalUuid(JsonNode node) {
        try { return UUID.fromString(proposalString(node)); }
        catch (IllegalArgumentException exception) { throw proposalIntegrity(); }
    }
    private static int proposalInteger(JsonNode node, String field) {
        JsonNode value = node.path(field);
        if (!value.isIntegralNumber() || !value.canConvertToInt()) throw proposalIntegrity();
        return value.intValue();
    }
    private static BusinessException proposalIntegrity() {
        return new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE,"Patch proposal integrity check failed");
    }

    /** Reject the proposal without changing its candidate Contract or the Release's effective policy. */
    @Transactional
    public RejectedPatch rejectPatchProposal(UUID proposalId, String comment, ReviewerContext reviewer) {
        // Resolve only the owning Release before checking reviewer authority or reading proposal content.
        var scopes = db.queryForList("""
            select f.release_id from patch_proposals p join findings f on f.id=p.finding_id where p.id=?
            """, UUID.class, proposalId);
        if (scopes.isEmpty()) fail(ErrorCode.RESOURCE_NOT_FOUND, "Patch proposal not found");
        UUID releaseId = scopes.getFirst();
        ReleaseState release = lockRelease(releaseId, reviewer);
        if (comment == null || comment.isBlank() || comment.length() > 1000)
            fail(ErrorCode.VALIDATION_ERROR, "Review comment is required and must not exceed 1000 characters");
        // Approval takes the same Release lock before it locks proposal and Finding rows.
        var reviews = db.query("""
            select p.finding_id,p.base_contract_version_id,p.state,f.release_id
            from patch_proposals p join findings f on f.id=p.finding_id where p.id=? for update of p,f
            """, (rs,n) -> new PatchReview(rs.getObject(1,UUID.class), rs.getObject(2,UUID.class),
                    rs.getString(3), rs.getObject(4,UUID.class)), proposalId);
        if (reviews.isEmpty()) fail(ErrorCode.RESOURCE_NOT_FOUND, "Patch proposal not found");
        PatchReview proposal = reviews.getFirst();
        if (!releaseId.equals(proposal.releaseId()) || !"PROPOSED".equals(proposal.state())
                || db.queryForObject("select count(*) from patch_approvals where patch_proposal_id=?",
                    Integer.class, proposalId) != 0)
            fail(ErrorCode.RESOURCE_CONFLICT, "Patch proposal is no longer pending review");
        if (proposal.baseVersionId() == null)
            fail(ErrorCode.EVIDENCE_INCOMPLETE, "Patch proposal base Contract is missing or foreign");
        var baseReleases = db.queryForList("""
            select c.release_id from safety_contract_versions v join safety_contracts c on c.id=v.contract_id
            where v.id=?
            """, UUID.class, proposal.baseVersionId());
        if (baseReleases.size() != 1 || !releaseId.equals(baseReleases.getFirst()))
            fail(ErrorCode.EVIDENCE_INCOMPLETE, "Patch proposal base Contract is missing or foreign");
        Version base = find(proposal.baseVersionId(), reviewer);
        int updated = db.update("update patch_proposals set state='REJECTED',updated_at=now() where id=? and state='PROPOSED'",
                proposalId);
        if (updated != 1) fail(ErrorCode.RESOURCE_CONFLICT, "Patch proposal is no longer pending review");
        Instant decidedAt = Instant.now();
        db.update("""
            insert into patch_approvals(id,patch_proposal_id,decision,reviewer_actor_id,comment,base_hash,decided_at)
            values(?,?,'REJECTED',?,?,?,?)
            """, UuidV7.generate(), proposalId, reviewer.actorId(), comment, base.policyHash(), Timestamp.from(decidedAt));
        audit.append(release.workspaceId(), reviewer.actorId(), "PATCH_PROPOSAL_REJECTED", "PATCH_PROPOSAL", proposalId,
                null, null, json.createObjectNode().put("findingId", proposal.findingId().toString())
                    .put("baseContractVersionId", base.id().toString()).put("state", "REJECTED")
                    .put("basePolicyHash", base.policyHash()));
        return new RejectedPatch(proposalId, proposal.findingId(), base.id(), "REJECTED", decidedAt);
    }

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
