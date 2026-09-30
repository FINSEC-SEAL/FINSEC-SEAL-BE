package com.finsecseal.attack;

import java.util.List;
import java.util.Objects;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/** Keeps curated variants separate from unrendered, unpersisted mutation candidates. */
@Component
public final class AttackGenerator {

    private final AttackVariantFactory variantFactory;
    private final AttackMutationCandidateValidator candidateValidator;
    private final AttackMutationGenerationService mutationGenerationService;

    @Autowired
    public AttackGenerator(AttackVariantFactory variantFactory,
            AttackMutationCandidateValidator candidateValidator,
            AttackMutationGenerationService mutationGenerationService) {
        this.variantFactory = Objects.requireNonNull(variantFactory);
        this.candidateValidator = Objects.requireNonNull(candidateValidator);
        this.mutationGenerationService = Objects.requireNonNull(mutationGenerationService);
    }

    /** Source-compatible constructor for focused validation tests. */
    public AttackGenerator(AttackVariantFactory variantFactory,
            AttackMutationCandidateValidator candidateValidator) {
        this.variantFactory = Objects.requireNonNull(variantFactory);
        this.candidateValidator = Objects.requireNonNull(candidateValidator);
        this.mutationGenerationService = null;
    }

    public List<AttackVariant> generateVariants(AttackSeed seed, int count) {
        if (seed == null || count != 1) {
            throw new IllegalArgumentException("Only one curated attack seed variant is supported");
        }
        return List.of(variantFactory.fromSeed(seed));
    }

    public List<AttackMutationCandidateValidator.ValidatedCandidate> validateCandidates(
            AttackMutationCandidateValidator.TrustedSeed seed, List<byte[]> rawCandidates) {
        return candidateValidator.validateBatch(seed, rawCandidates);
    }

    public AttackMutationGenerationService.GenerationResult generateMutationCandidates(
            AttackMutationCandidateValidator.TrustedSeed seed,
            int count
    ) {
        if (mutationGenerationService == null) {
            throw new IllegalStateException("Attack mutation generation service is not configured");
        }
        return mutationGenerationService.generate(seed, count);
    }
}
