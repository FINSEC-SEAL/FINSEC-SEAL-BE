package com.finsecseal.attack;

import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.List;

@Component
public class AttackGenerator {

    private final AttackVariantFactory variantFactory;

    public AttackGenerator(AttackVariantFactory variantFactory) {
        this.variantFactory = variantFactory;
    }

    public List<AttackVariant> generateVariants(AttackSeed seed, int count) {
        List<AttackVariant> variants = new ArrayList<>();
        // produce base variant
        variants.add(variantFactory.fromSeed(seed));

        for (int i = 1; i < Math.max(1, count); i++) {
            AttackSeed mutated = mutateSeed(seed, i);
            variants.add(variantFactory.fromSeed(mutated));
        }

        return variants;
    }

    private AttackSeed mutateSeed(AttackSeed seed, int mutationIndex) {
        JsonNode args = seed.toolArguments().deepCopy();

        if (args.isObject()) {
            ObjectNode obj = (ObjectNode) args;

            // If customerIds array present, add another id
            if (obj.has("customerIds") && obj.get("customerIds").isArray()) {
                ArrayNode arr = (ArrayNode) obj.withArray("customerIds");
                arr.add("CUST-" + (1000 + mutationIndex));
            }

            // If documents array present, tweak document content
            if (obj.has("documents") && obj.get("documents").isArray()) {
                ArrayNode docs = (ArrayNode) obj.withArray("documents");
                if (docs.size() > 0 && docs.get(0).isObject()) {
                    ObjectNode first = (ObjectNode) docs.get(0);
                    String prev = first.has("content") ? first.get("content").asText() : "";
                    first.put("content", prev + " [mut#" + mutationIndex + "]");
                }
            }

            // As fallback, add an "injectedNote" field
            if (!obj.has("customerIds") && !obj.has("documents")) {
                obj.put("injectedNote", "mutation-" + mutationIndex);
            }
        }

        return new AttackSeed(
                seed.category(),
                seed.severity(),
                seed.targetTool(),
                seed.invariantId(),
                seed.oracleType(),
                args
        );
    }
}
