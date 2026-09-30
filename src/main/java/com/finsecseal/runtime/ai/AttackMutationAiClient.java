package com.finsecseal.runtime.ai;

import com.finsecseal.attack.AttackMutationCandidateValidator.TrustedSeed;
import java.util.List;

public interface AttackMutationAiClient {

    GenerationResponse generate(TrustedSeed seed, int count);

    record GenerationResponse(
            String provider,
            String model,
            List<byte[]> candidates,
            ModelTokenUsage tokenUsage
    ) {
        public GenerationResponse {
            candidates = candidates == null ? null : candidates.stream()
                    .map(candidate -> candidate == null ? null : candidate.clone())
                    .toList();
        }

        @Override
        public List<byte[]> candidates() {
            return candidates == null ? null : candidates.stream()
                    .map(candidate -> candidate == null ? null : candidate.clone())
                    .toList();
        }
    }
}
