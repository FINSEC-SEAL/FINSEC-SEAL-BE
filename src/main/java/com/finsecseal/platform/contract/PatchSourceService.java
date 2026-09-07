package com.finsecseal.platform.contract;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.FindingSourceFacts;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/** Dedicated generation read: never calls unrestricted Finding detail or related-Finding APIs. */
@Service
public class PatchSourceService {
    private final JdbcTemplate db;
    private final ObjectMapper json;
    private final CanonicalJsonService canonical;
    private final DigestService digest;
    public PatchSourceService(JdbcTemplate db,ObjectMapper json,CanonicalJsonService canonical,DigestService digest) {
        this.db=db;this.json=json;this.canonical=canonical;this.digest=digest;
    }
    public record PatchSource(FindingSourceFacts facts, UUID sourceRunId, UUID sourceCaseId,
            UUID oracleResultId, JsonNode evidence) {}
    private record Source(UUID releaseId, UUID workspace, String status, String partition, boolean hidden,
            UUID caseId, UUID runId, UUID oracleId, String evidenceDigest, String invariant) {}

    @Transactional(readOnly=true, isolation=org.springframework.transaction.annotation.Isolation.REPEATABLE_READ)
    public PatchSource find(UUID findingId, ReviewerContext reviewer) {
        if(reviewer==null) throw new BusinessException(ErrorCode.OPERATOR_AUTH_REQUIRED,"Trusted reviewer required");
        ContractPersistenceService.requireReviewer(reviewer,reviewer.workspaceId());
        // First fetch provenance only. No evidence/payload/root-cause field is selected here.
        List<Source> rows=db.query("""
            select f.release_id,a.workspace_id,f.status,c.partition_name,c.hidden_from_patch_generator,c.id,r.id,
                   o.id,o.evidence_digest,f.violated_invariant
            from findings f join oracle_results o on o.id=f.source_oracle_result_id
            join test_case_runs cr on cr.id=o.test_case_run_id
            join test_runs r on r.id=cr.test_run_id and r.release_id=f.release_id
            join test_cases c on c.id=cr.test_case_id and c.suite_id=r.suite_id
            join test_suites s on s.id=c.suite_id
            join agent_releases ar on ar.id=f.release_id join agents a on a.id=ar.agent_id
            where f.id=? and a.workspace_id=? and s.workspace_id=a.workspace_id
              and f.status in ('OPEN','TRIAGED') and o.outcome='ATTACK_SUCCESS'
              and r.mode in ('BASELINE','SEAL_REPLAY') and r.status='COMPLETED'
              and c.partition_name in ('SEED','MUTATION') and not c.hidden_from_patch_generator
            """,(rs,n)->new Source(rs.getObject(1,UUID.class),rs.getObject(2,UUID.class),rs.getString(3),rs.getString(4),rs.getBoolean(5),
                rs.getObject(6,UUID.class),rs.getObject(7,UUID.class),rs.getObject(8,UUID.class),rs.getString(9),rs.getString(10)),findingId,reviewer.workspaceId());
        if(rows.isEmpty()) return unavailable();
        Source s=rows.getFirst();
        // A mutation whose ancestor was held out is also ineligible; UNION terminates cycles,
        // then a leaf requirement below rejects cyclic or unresolved ancestry.
        Integer forbidden=db.queryForObject("""
            with recursive lineage as (
              select id,parent_seed_id,partition_name,hidden_from_patch_generator,suite_id from test_cases where id=?
              union
              select c.id,c.parent_seed_id,c.partition_name,c.hidden_from_patch_generator,c.suite_id
              from test_cases c join lineage l on c.id=l.parent_seed_id
            ) select case when not exists(select 1 from lineage where parent_seed_id is null)
               or exists(select 1 from lineage l join test_suites ts on ts.id=l.suite_id
                 where l.hidden_from_patch_generator or l.partition_name not in ('SEED','MUTATION') or ts.workspace_id<>?)
               then 1 else 0 end
            """,Integer.class,s.caseId(),reviewer.workspaceId());
        if(forbidden!=0) return unavailable();
        // Only now read D's digest-bound evidence. Related findings and encrypted attack
        // payloads are intentionally not part of the generator's input contract.
        JsonNode evidence=json.readTree(db.queryForObject("select evidence_json::text from oracle_results where id=?",String.class,s.oracleId()));
        if(!digest.sha256(canonical.canonicalize(evidence)).equals(s.evidenceDigest()))
            throw new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE,"Patch source evidence digest mismatch");
        return new PatchSource(new FindingSourceFacts(findingId,s.workspace(),s.releaseId(),s.status(),s.partition(),s.hidden(),
                s.evidenceDigest(),s.invariant()),s.runId(),s.caseId(),s.oracleId(),evidence);
    }
    private PatchSource unavailable() {throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND,"Eligible patch source not found");}
}
