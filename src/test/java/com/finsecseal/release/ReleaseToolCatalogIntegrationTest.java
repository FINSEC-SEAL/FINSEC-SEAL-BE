package com.finsecseal.release;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.contract.SafetyContractSchemaValidator;
import com.finsecseal.contract.SafetyContractSemanticValidator;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationStatus;
import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;
import com.finsecseal.policy.PolicyEvaluationStage;
import com.finsecseal.policy.PolicyToolTrustEvaluator;
import com.finsecseal.policy.PolicyToolTrustFacts;
import com.finsecseal.policy.PolicyToolTrustFacts.ReleaseToolBinding;
import com.finsecseal.policy.PolicyToolTrustFacts.ToolRegistryEntry;
import com.finsecseal.policy.PolicyToolTrustFacts.ToolTrustPolicy;
import com.finsecseal.policy.PolicyToolTrustFacts.TrustLevel;
import jakarta.persistence.EntityManager;
import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Testcontainers
@SpringBootTest
@Transactional
class ReleaseToolCatalogIntegrationTest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired AgentService agents;
    @Autowired ReleaseService releases;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate jdbc;
    @Autowired EntityManager entities;

    @Test
    void newCatalogCoexistsWithLegacyDefinitionsAndFeedsCSemantics() throws IOException {
        var agent = agent();
        var legacy = releases.create(agent.id(), fixture("valid-release-manifest.json"));
        assertThat(releases.validate(legacy.id()).valid()).isTrue();
        releases.analyze(legacy.id());
        String legacyFingerprint = releases.fingerprint(legacy.id()).releaseFingerprint();
        var current = releases.create(agent.id(), fixture("valid-release-manifest-v1.1.json"));
        releases.analyze(current.id());
        entities.flush();
        entities.clear();

        var source = releases.toolCatalog(current.id(), "role-c-integration-test");
        assertThat(source.manifestSchemaVersion()).isEqualTo("1.1");
        assertThat(source.releaseFingerprint()).isEqualTo(current.releaseFingerprint());
        assertThat(source.serverToolCatalogHash()).matches("sha256:[0-9a-f]{64}");
        assertThat(mapper.writeValueAsString(source)).doesNotContain("systemPrompt", "Review only document completeness");
        assertThat(jdbc.queryForObject("select count(*) from tool_definitions", Integer.class)).isEqualTo(10);
        assertThat(jdbc.queryForObject("select count(*) from release_tools where release_id = ?",
                Integer.class, current.id())).isEqualTo(5);
        assertThat(jdbc.queryForObject("select count(*) from tool_definitions where tool_key = 'LOAN_DECISION_UPDATE'",
                Integer.class)).isZero();
        assertThat(jdbc.queryForObject("select count(*) from release_artifacts where release_id = ? and name = 'server-tool-catalog'",
                Integer.class, current.id())).isEqualTo(1);

        ObjectNode verified = mapper.createObjectNode();
        verified.set("tools", source.tools());
        verified.set("serverToolCatalog", source.serverToolCatalog());
        var validator = new SafetyContractSemanticValidator(new SafetyContractSchemaValidator());
        assertThat(validator.validate(fixture("loan-review-safety-contract.json"),
                ManifestCatalogContractTest.catalogFrom(verified)).status()).isEqualTo(ValidationStatus.VALID);

        assertThat(releases.fingerprint(legacy.id()).releaseFingerprint()).isEqualTo(legacyFingerprint);
        assertThat(releases.analyze(legacy.id()).releaseFingerprint()).isEqualTo(legacyFingerprint);
        assertThat(releases.diff(current.id(), legacy.id()).components())
                .filteredOn(item -> item.component().equals("serverToolCatalogHash"))
                .singleElement().satisfies(item -> {
                    assertThat(item.changed()).isTrue();
                    assertThat(item.jsonPointers()).containsExactly("/serverToolCatalog");
                });
    }

    @Test
    void legacyReleaseCannotBePresentedAsPolicyReady() throws IOException {
        var legacy = releases.create(agent().id(), fixture("valid-release-manifest.json"));
        assertThatThrownBy(() -> releases.toolCatalog(legacy.id(), "role-c"))
                .isInstanceOfSatisfying(BusinessException.class,
                        ex -> assertThat(ex.errorCode()).isEqualTo(ErrorCode.MANIFEST_INVALID))
                .hasMessageContaining("legacy 1.0 is preserved");
    }

    @Test
    void persistedDocumentToolPassesCTrustStageWhileContentStaysUntrusted() throws IOException {
        var current = releases.create(agent().id(), fixture("valid-release-manifest-v1.1.json"));
        var source = releases.toolCatalog(current.id(), "role-c-trust-test");
        ToolRegistryEntry entry = jdbc.queryForObject("""
                select d.tool_key, d.version, d.trust_level, d.schema_hash, d.description_hash
                  from release_tools r join tool_definitions d on d.id = r.tool_definition_id
                 where r.release_id = ? and d.tool_key = 'DOCUMENT_READER'
                """, (row, index) -> new ToolRegistryEntry(
                        row.getString("tool_key"), row.getString("version"),
                        TrustLevel.valueOf(row.getString("trust_level")),
                        row.getString("schema_hash"), row.getString("description_hash")), current.id());
        var facts = new PolicyToolTrustFacts("DOCUMENT_READER", current.releaseFingerprint(),
                source.releaseFingerprint(), List.of(entry),
                List.of(new ReleaseToolBinding(entry.toolName(), entry.version(), true,
                        entry.schemaDigest(), entry.descriptionDigest())),
                new ToolTrustPolicy(true, List.of(TrustLevel.TRUSTED_INTERNAL)));
        assertThat(new PolicyToolTrustEvaluator().evaluate(PolicyEvaluationStage.TOOL_TRUST, facts))
                .isEqualTo(StageOutcome.pass(PolicyEvaluationStage.TOOL_TRUST));
        ObjectNode returned = mapper.createObjectNode().set("tools", source.tools());
        assertThat(ManifestCatalogContractTest.tool(returned, "DOCUMENT_READER")
                .at("/outputSchema/properties/content/x-trust-level").asString()).isEqualTo("UNTRUSTED");
    }

    @Test
    void rejectsTamperedCatalogArtifactBeforeReturningSource() throws IOException {
        var current = releases.create(agent().id(), fixture("valid-release-manifest-v1.1.json"));
        jdbc.update("update release_artifacts set content_json = '{\"forged\":true}'::jsonb "
                + "where release_id = ? and name = 'server-tool-catalog'", current.id());
        entities.clear();
        assertThatThrownBy(() -> releases.toolCatalog(current.id(), "role-c"))
                .isInstanceOfSatisfying(BusinessException.class,
                        ex -> assertThat(ex.errorCode()).isEqualTo(ErrorCode.RELEASE_CHANGED));
    }

    @Test
    void rejectsTamperedReleaseFingerprintBeforeReturningSource() throws IOException {
        var current = releases.create(agent().id(), fixture("valid-release-manifest-v1.1.json"));
        jdbc.update("update agent_releases set release_fingerprint = ? where id = ?",
                "sha256:" + "f".repeat(64), current.id());
        entities.clear();
        assertThatThrownBy(() -> releases.toolCatalog(current.id(), "role-c"))
                .isInstanceOfSatisfying(BusinessException.class,
                        ex -> assertThat(ex.errorCode()).isEqualTo(ErrorCode.RELEASE_CHANGED));
    }

    private AgentDto.Response agent() {
        return agents.create(new AgentDto.CreateRequest("loan-document-review-agent", "Loan Review", "Document completeness"));
    }

    private ObjectNode fixture(String name) throws IOException {
        return (ObjectNode) mapper.readTree(getClass().getResourceAsStream("/fixtures/" + name));
    }
}
