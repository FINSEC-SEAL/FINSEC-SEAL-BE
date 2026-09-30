package com.finsecseal.attack;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.finsecseal.attack.AttackMutationCandidateValidator.TrustedSeed;
import com.finsecseal.release.DigestService;
import com.finsecseal.runtime.ai.AttackMutationAiClient;
import com.finsecseal.runtime.ai.ModelTokenUsage;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

class AttackMutationGenerationServiceTest {

    private static final UUID PARENT_ID =
            UUID.fromString("0198f200-0000-7000-8000-000000000701");
    private final AttackMutationCandidateValidator validator =
            new AttackMutationCandidateValidator(new DigestService());

    @Test
    void acceptsOnlyValidatedCandidatesAndPreservesProviderProvenance() {
        AttackMutationAiClient client = mock(AttackMutationAiClient.class);
        when(client.generate(seed(), 1)).thenReturn(new AttackMutationAiClient.GenerationResponse(
                "openai-compatible",
                "mutation-model-resolved",
                List.of(candidate("Synthetic wording variant", "FOOTNOTE")),
                new ModelTokenUsage(10, 4, 14)
        ));

        var result = service(client).generate(seed(), 1);

        assertThat(result.generationDegraded()).isFalse();
        assertThat(result.candidates()).hasSize(1);
        assertThat(result.provider()).isEqualTo("openai-compatible");
        assertThat(result.model()).isEqualTo("mutation-model-resolved");
        assertThat(result.tokenUsage().totalTokens()).isEqualTo(14);
    }

    @Test
    void providerFailureOrInvalidCandidateFallsBackWithoutPersistableCandidates() {
        AttackMutationAiClient failed = mock(AttackMutationAiClient.class);
        when(failed.generate(seed(), 1)).thenThrow(new IllegalStateException("provider secret"));
        var failedResult = service(failed).generate(seed(), 1);

        AttackMutationAiClient invalid = mock(AttackMutationAiClient.class);
        byte[] tampered = new String(
                candidate("Synthetic wording variant", "BODY"),
                StandardCharsets.UTF_8
        )
                .replace("FA-01", "FA-05")
                .getBytes(StandardCharsets.UTF_8);
        when(invalid.generate(seed(), 1)).thenReturn(new AttackMutationAiClient.GenerationResponse(
                "provider", "model", List.of(tampered), ModelTokenUsage.ZERO));
        var invalidResult = service(invalid).generate(seed(), 1);

        assertThat(failedResult.generationDegraded()).isTrue();
        assertThat(failedResult.candidates()).isEmpty();
        assertThat(invalidResult.generationDegraded()).isTrue();
        assertThat(invalidResult.candidates()).isEmpty();
    }

    @Test
    void missingClientFallsBackAndInvalidCountIsRejectedBeforeProviderUse() {
        @SuppressWarnings("unchecked")
        ObjectProvider<AttackMutationAiClient> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        AttackMutationGenerationService service =
                new AttackMutationGenerationService(provider, validator);

        assertThat(service.generate(seed(), 1).generationDegraded()).isTrue();
        assertThatThrownBy(() -> service.generate(seed(), 0))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private AttackMutationGenerationService service(AttackMutationAiClient client) {
        @SuppressWarnings("unchecked")
        ObjectProvider<AttackMutationAiClient> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(client);
        return new AttackMutationGenerationService(provider, validator);
    }

    private TrustedSeed seed() {
        return new TrustedSeed(
                PARENT_ID,
                "FA-01",
                "HIGH",
                "CUSTOMER_DATA_READ",
                "INV-CUSTOMER-BOUNDARY",
                "CROSS_CUSTOMER",
                "DOCUMENT_CONTENT",
                "Curated parent wording"
        );
    }

    private byte[] candidate(String payload, String location) {
        return ("""
                {"parentSeedId":"%s","category":"FA-01","severity":"HIGH",\
                "targetTool":"CUSTOMER_DATA_READ","expectedInvariant":"INV-CUSTOMER-BOUNDARY",\
                "oracleType":"CROSS_CUSTOMER","deliveryChannel":"DOCUMENT_CONTENT",\
                "payload":"%s","insertionLocation":"%s"}
                """).formatted(PARENT_ID, payload, location).getBytes(StandardCharsets.UTF_8);
    }
}
