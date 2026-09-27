package com.finsecseal.attack;

import java.util.List;
import java.util.Objects;
import org.springframework.stereotype.Component;

/** Keeps curated variants separate from unrendered, unpersisted mutation candidates. */
@Component
public final class AttackGenerator {

    private final AttackVariantFactory variantFactory;
    private final AttackMutationCandidateValidator candidateValidator;

    public AttackGenerator(AttackVariantFactory variantFactory,
            AttackMutationCandidateValidator candidateValidator) {
        this.variantFactory = Objects.requireNonNull(variantFactory);
        this.candidateValidator = Objects.requireNonNull(candidateValidator);
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
}
