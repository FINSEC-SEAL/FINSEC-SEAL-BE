package com.finsecseal.attack;

import com.finsecseal.attack.AttackMutationCandidateValidator.TrustedSeed;
import com.finsecseal.attack.AttackMutationCandidateValidator.ValidatedCandidate;
import com.finsecseal.runtime.ai.AttackMutationAiClient;
import com.finsecseal.runtime.ai.ModelTokenUsage;
import java.util.List;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;

@Service
public final class AttackMutationGenerationService {

    private final ObjectProvider<AttackMutationAiClient> clientProvider;
    private final AttackMutationCandidateValidator validator;

    public AttackMutationGenerationService(
            ObjectProvider<AttackMutationAiClient> clientProvider,
            AttackMutationCandidateValidator validator
    ) {
        this.clientProvider = clientProvider;
        this.validator = validator;
    }

    public GenerationResult generate(TrustedSeed seed, int count) {
        if (seed == null || count < 1 || count > AttackMutationCandidateValidator.MAX_BATCH_SIZE) {
            throw new IllegalArgumentException("Attack mutation count must be between 1 and 20");
        }
        AttackMutationAiClient client = clientProvider.getIfAvailable();
        if (client == null) {
            return GenerationResult.degraded(DegradationCode.AI_NOT_CONFIGURED);
        }
        try {
            AttackMutationAiClient.GenerationResponse response = client.generate(seed, count);
            if (response == null
                    || response.provider() == null || response.provider().isBlank()
                    || response.model() == null || response.model().isBlank()
                    || response.tokenUsage() == null) {
                return GenerationResult.degraded(DegradationCode.INVALID_PROVIDER_RESPONSE);
            }
            List<ValidatedCandidate> candidates = validator.validateBatch(seed, response.candidates());
            if (candidates.size() != count) {
                return GenerationResult.degraded(DegradationCode.INVALID_PROVIDER_RESPONSE);
            }
            return new GenerationResult(
                    candidates,
                    false,
                    response.provider(),
                    response.model(),
                    response.tokenUsage(),
                    null
            );
        } catch (RuntimeException exception) {
            return GenerationResult.degraded(DegradationCode.PROVIDER_OR_VALIDATION_FAILURE);
        }
    }

    public record GenerationResult(
            List<ValidatedCandidate> candidates,
            boolean generationDegraded,
            String provider,
            String model,
            ModelTokenUsage tokenUsage,
            DegradationCode degradationCode
    ) {
        public GenerationResult {
            candidates = List.copyOf(candidates);
        }

        private static GenerationResult degraded(DegradationCode code) {
            return new GenerationResult(List.of(), true, null, null, ModelTokenUsage.ZERO, code);
        }
    }

    public enum DegradationCode {
        AI_NOT_CONFIGURED,
        INVALID_PROVIDER_RESPONSE,
        PROVIDER_OR_VALIDATION_FAILURE
    }
}
