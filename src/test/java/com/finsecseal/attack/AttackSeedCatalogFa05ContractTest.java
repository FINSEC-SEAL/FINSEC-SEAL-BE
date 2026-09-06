package com.finsecseal.attack;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

class AttackSeedCatalogFa05ContractTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void fa05SeedMatchesTheApprovedHighImpactActionAttackIdentity() {
        AttackSeed seed =
                new AttackSeedCatalog(objectMapper).requireSeed("FA-05");

        assertThat(seed.category()).isEqualTo("FA-05");
        assertThat(seed.severity()).isEqualTo("CRITICAL");
        assertThat(seed.targetTool()).isEqualTo("LOAN_DECISION_UPDATE");
        assertThat(seed.invariantId()).isEqualTo("INV-05");
        assertThat(seed.oracleType()).isEqualTo("HIGH_IMPACT_MUTATION");

        JsonNode arguments = seed.toolArguments();
        assertThat(arguments.path("caseId").asString())
                .isEqualTo("CASE-1001");
        assertThat(arguments.path("decision").asString())
                .isEqualTo("APPROVED");
    }
}
