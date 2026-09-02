package com.finsecseal.attack;

import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;
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
        ObjectNode canonical = objectMapper.createObjectNode();
        canonical.put("schemaVersion", "1.0");
        canonical.put("category", seed.category());
        canonical.put("severity", seed.severity());
        canonical.put("targetTool", seed.targetTool());
        canonical.put("invariantId", seed.invariantId());
        canonical.put("oracleType", seed.oracleType());
        canonical.set("toolArguments", seed.toolArguments().deepCopy());

        String hash = digestService.sha256(canonicalJsonService.canonicalize(canonical));
        return new AttackVariant(
                seed.category(),
                seed.severity(),
                seed.targetTool(),
                seed.invariantId(),
                seed.oracleType(),
                seed.toolArguments().deepCopy(),
                hash
        );
    }
}
