package com.finsecseal.attack;

import com.finsecseal.attack.AttackMutationCandidateValidator.ValidatedCandidate;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

@Component
public class AttackVariantFactory {

    private final ObjectMapper objectMapper;
    private final CanonicalJsonService canonicalJsonService;
    private final DigestService digestService;

    public AttackVariantFactory(
            ObjectMapper objectMapper,
            CanonicalJsonService canonicalJsonService,
            DigestService digestService
    ) {
        this.objectMapper = objectMapper;
        this.canonicalJsonService = canonicalJsonService;
        this.digestService = digestService;
    }

    public AttackVariant fromSeed(AttackSeed seed) {
        return create(seed, seed.toolArguments());
    }

    public AttackVariant fromDocumentMutation(AttackSeed seed, ValidatedCandidate candidate) {
        if (seed == null || candidate == null || !"FA-01".equals(seed.category())) {
            throw new IllegalArgumentException("Document mutations require an FA-01 seed and validated candidate");
        }
        JsonNode copiedArguments = seed.toolArguments().deepCopy();
        if (!(copiedArguments instanceof ObjectNode arguments)
                || !(arguments.path("documents") instanceof ArrayNode documents)
                || documents.isEmpty()
                || !(documents.get(0) instanceof ObjectNode document)) {
            throw new IllegalArgumentException("FA-01 seed must contain a document delivery target");
        }
        document.put("content", candidate.payload());
        document.put("insertionLocation", candidate.insertionLocation());
        return create(seed, arguments);
    }

    private AttackVariant create(AttackSeed seed, JsonNode toolArguments) {
        if (seed == null || toolArguments == null) {
            throw new IllegalArgumentException("Attack seed and tool arguments are required");
        }
        ObjectNode canonical = objectMapper.createObjectNode();
        canonical.put("schemaVersion", "1.0");
        canonical.put("category", seed.category());
        canonical.put("severity", seed.severity());
        canonical.put("targetTool", seed.targetTool());
        canonical.put("invariantId", seed.invariantId());
        canonical.put("oracleType", seed.oracleType());
        canonical.set("toolArguments", toolArguments.deepCopy());

        String hash = digestService.sha256(canonicalJsonService.canonicalize(canonical));
        return new AttackVariant(
                seed.category(),
                seed.severity(),
                seed.targetTool(),
                seed.invariantId(),
                seed.oracleType(),
                toolArguments.deepCopy(),
                hash
        );
    }
}
