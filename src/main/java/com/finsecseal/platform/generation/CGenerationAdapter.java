package com.finsecseal.platform.generation;

import com.finsecseal.contract.ContractCandidateGenerationService;
import com.finsecseal.contract.SafetyContractPatchGenerationService;
import com.finsecseal.platform.generation.GenerationContract.*;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/** Calls C without a transaction. B/C keep ownership of generation, validation and transport retries. */
@Component
public class CGenerationAdapter implements GenerationEngine {
    private final ObjectProvider<ContractCandidateGenerationService> initial;
    private final ObjectProvider<SafetyContractPatchGenerationService> patches;
    private final ObjectMapper json;
    public CGenerationAdapter(ObjectProvider<ContractCandidateGenerationService> initial,
            ObjectProvider<SafetyContractPatchGenerationService> patches, ObjectMapper json) {
        this.initial=initial; this.patches=patches; this.json=json;
    }
    public boolean available(Kind kind) {
        return kind==Kind.CONTRACT ? initial.getIfAvailable()!=null : patches.getIfAvailable()!=null;
    }
    public Generated generate(Work work) {
        if (work.kind()==Kind.CONTRACT) {
            var r=initial.getObject().generate(work.identity(),work.templateKey(),work.reviewer().actorId());
            if (!work.identity().equals(r.identity())) throw new IllegalStateException("Generation identity mismatch");
            return new Generated(r.validation().status().name(),r.policy(),null,
                    new Source(r.catalogBinding(),r.analyzedAt(),null,null,null,null,null,null,null,null,null),
                    new Metadata(r.templateKey(),r.promptVersion(),r.promptDigest(),r.provider(),r.model(),r.latencyMs(),null,null),
                    json.valueToTree(r.validation().issues()));
        }
        var r=patches.getObject().generate(work.expectedSource().findingId(),work.expectedSource().baseVersionId(),work.reviewer());
        return new Generated(r.assessment().decision().status().name(),null,r.assessment().candidate(),
                new Source(r.catalogBinding(),r.analyzedAt(),r.finding().findingId(),r.baseIdentity().versionId(),
                        r.baseState().name(),r.basePolicyHash(),r.baseResourceHash(),r.finding(),r.sourceRunId(),r.sourceCaseId(),r.oracleResultId()),
                new Metadata(r.templateKey(),r.promptVersion(),r.promptDigest(),r.provider(),r.model(),r.latencyMs(),r.sourceEvidenceDigest(),r.redactedEvidenceDigest()),
                json.valueToTree(r.assessment().decision().issues()));
    }
}
