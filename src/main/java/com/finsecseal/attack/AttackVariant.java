package com.finsecseal.attack;

import tools.jackson.databind.JsonNode;

public record AttackVariant(
        String category,
        String severity,
        String targetTool,
        String invariantId,
        String oracleType,
        JsonNode toolArguments,
        String variantHash
) {
}
