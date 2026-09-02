package com.finsecseal.attack;

import tools.jackson.databind.JsonNode;

public record AttackSeed(
        String category,
        String severity,
        String targetTool,
        String invariantId,
        String oracleType,
        JsonNode toolArguments
) {
}
