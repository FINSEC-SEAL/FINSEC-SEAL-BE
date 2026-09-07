package com.finsecseal.contract;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.persistence.UuidV7;
import com.finsecseal.contract.SafetyContractCanonicalizer.CanonicalPolicy;
import com.finsecseal.contract.SafetyContractCandidatePromptBuilder.CandidatePrompt;
import com.finsecseal.contract.SafetyContractCandidateResponseProcessor.CandidateAssessment;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionIdentity;
import com.finsecseal.runtime.ai.ContractCandidateAiClient;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;

@Service
@ConditionalOnProperty(name = "finsec.ai.enabled", havingValue = "true")
public class ContractCandidateGenerationService {

    private final SafetyContractGenerationSourceService sourceService;
    private final SafetyContractCandidatePromptBuilder promptBuilder;
    private final SafetyContractCandidateResponseProcessor responseProcessor;
    private final ContractCandidateAiClient aiClient;
    private final JdbcTemplate jdbcTemplate;

    public ContractCandidateGenerationService(
            SafetyContractGenerationSourceService sourceService,
            SafetyContractCandidatePromptBuilder promptBuilder,
            SafetyContractCandidateResponseProcessor responseProcessor,
            ContractCandidateAiClient aiClient,
            JdbcTemplate jdbcTemplate
    ) {
        this.sourceService = Objects.requireNonNull(sourceService, "sourceService must not be null");
        this.promptBuilder = Objects.requireNonNull(promptBuilder, "promptBuilder must not be null");
        this.responseProcessor = Objects.requireNonNull(responseProcessor, "responseProcessor must not be null");
        this.aiClient = Objects.requireNonNull(aiClient, "aiClient must not be null");
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate must not be null");
    }

    @Transactional
    public CandidateGenerationResult generate(
            UUID releaseId,
            String templateKey,
            String contractKey,
            String actorId
    ) {
        if (releaseId == null
                || actorId == null
                || actorId.isBlank()
                || contractKey == null
                || contractKey.isBlank()
                || contractKey.length() > 100) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR, "releaseId, actorId, contractKey are required");
        }

        String normalizedTemplate = templateKey == null || templateKey.isBlank()
                ? LoanReviewFinancialTemplate.KEY
                : templateKey;

        SafetyContractGenerationSourceService.PreparedGenerationSource source =
                sourceService.prepare(releaseId, normalizedTemplate, actorId);
        UUID workspaceId = workspaceIdOf(releaseId);
        int nextVersion = nextVersionOf(releaseId, contractKey);
        VersionIdentity identity = new VersionIdentity(
                UuidV7.generate(),
                workspaceId,
                releaseId,
                contractKey,
                nextVersion
        );

        CandidatePrompt prompt = promptBuilder.build(source, identity);
        ContractCandidateAiClient.CandidateModelResponse modelResponse = aiClient.generate(
                prompt.promptVersion(),
                prompt.instructions(),
                prompt.inputJson()
        );

        CandidateAssessment assessment = responseProcessor.process(prompt, modelResponse.content());
        Optional<CanonicalPolicy> canonical = assessment.canonicalPolicy();

        return new CandidateGenerationResult(
                releaseId,
                workspaceId,
                contractKey,
                nextVersion,
                prompt.promptVersion(),
                prompt.promptDigest(),
                modelResponse.provider(),
                modelResponse.model(),
                modelResponse.latencyMs(),
                assessment.policy(),
                assessment.validation().status().name(),
                assessment.validation().issues(),
                canonical.map(CanonicalPolicy::policyHash).orElse(null),
                canonical.map(CanonicalPolicy::canonicalJson).orElse(null)
        );
    }

    private UUID workspaceIdOf(UUID releaseId) {
        UUID workspaceId = jdbcTemplate.queryForObject(
                """
                select a.workspace_id
                  from agent_releases r
                  join agents a on a.id = r.agent_id
                 where r.id = ?
                """,
                UUID.class,
                releaseId
        );
        if (workspaceId == null) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "Release not found");
        }
        return workspaceId;
    }

    private int nextVersionOf(UUID releaseId, String contractKey) {
        Integer latest = jdbcTemplate.queryForObject(
                """
                select coalesce(max(v.version), 0)
                  from safety_contracts c
                  join safety_contract_versions v on v.contract_id = c.id
                 where c.release_id = ?
                   and c.contract_key = ?
                """,
                Integer.class,
                releaseId,
                contractKey
        );
        return (latest == null ? 0 : latest) + 1;
    }

    public record CandidateGenerationResult(
            UUID releaseId,
            UUID workspaceId,
            String contractKey,
            int version,
            String promptVersion,
            String promptDigest,
            String provider,
            String model,
            long latencyMs,
            JsonNode policy,
            String validationStatus,
            List<SafetyContractSemanticValidator.Issue> issues,
            String canonicalPolicyHash,
            String canonicalPolicyJson
    ) {
    }
}
