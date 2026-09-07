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

        // Ensure uniqueness of variant hashes; attempt limit to avoid infinite loops
        java.util.Set<String> seen = new java.util.HashSet<>();
        seen.add(variants.get(0).variantHash());

        int attempts = 0;
        int mutationIndex = 1;
        int maxAttempts = Math.max(10, count * 10);

        while (variants.size() < Math.max(1, count) && attempts < maxAttempts) {
            AttackSeed mutated = mutateSeed(seed, mutationIndex);
            AttackVariant v = variantFactory.fromSeed(mutated);
            attempts++;
            mutationIndex++;
            if (seen.add(v.variantHash())) {
                variants.add(v);
            }
        }

        return variants;
    }

    private AttackSeed mutateSeed(AttackSeed seed, int mutationIndex) {
        JsonNode args = seed.toolArguments().deepCopy();

        if (args.isObject()) {
            ObjectNode obj = (ObjectNode) args;
            // Mutation strategy 1: customerIds arrays -> add or replace a customer id
            if (obj.has("customerIds") && obj.get("customerIds").isArray()) {
                ArrayNode arr = (ArrayNode) obj.withArray("customerIds");
                // Alternate between appending and rotating existing ids
                if (mutationIndex % 3 == 0 && arr.size() > 0) {
                    // rotate first element
                    arr.set(0, obj.textNode("CUST-" + (1000 + mutationIndex)));
                } else {
                    arr.add("CUST-" + (1000 + mutationIndex));
                }
            }

            // Mutation strategy 2: documents array -> append mutation marker or inject synthetic account
            if (obj.has("documents") && obj.get("documents").isArray()) {
                ArrayNode docs = (ArrayNode) obj.withArray("documents");
                if (docs.size() > 0 && docs.get(0).isObject()) {
                    ObjectNode first = (ObjectNode) docs.get(0);
                    String prev = first.has("content") ? first.get("content").asText() : "";
                    if (mutationIndex % 2 == 0) {
                        first.put("content", prev + " [mut#" + mutationIndex + "]");
                    } else {
                        // inject synthetic account patterns when plausible
                        first.put("content", prev + " SYNTH-ACCT-" + (1000 + mutationIndex));
                    }
                }
            }

            // Mutation strategy 3: replace or inject other notable fields
            if (!obj.has("customerIds") && !obj.has("documents")) {
                // toggle injectedNote vs mutatedFlag for variety
                if (mutationIndex % 2 == 0) {
                    obj.put("injectedNote", "mutation-" + mutationIndex);
                } else {
                    obj.put("mutatedFlag", "m" + mutationIndex);
                }
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
