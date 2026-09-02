package com.finsecseal.release;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.common.api.BusinessException;
import java.sql.Connection;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Testcontainers
@SpringBootTest
class DefinitionConcurrencyIntegrationTest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired
    AgentService agentService;

    @Autowired
    ReleaseService releaseService;

    @Autowired
    JdbcTemplate jdbcTemplate;

    @Autowired
    DataSource dataSource;

    @Autowired
    ObjectMapper objectMapper;

    @Test
    void serializesToolAndRagDefinitionMutationsInBothDirections() throws Exception {
        ReleaseDto.Response toolRelease = createRelease("tool", false);
        ReleaseDto.Response ragRelease = createRelease("rag", true);

        definitionFirstIsObserved(
                toolRelease.id(),
                """
                update tool_definitions definition set adapter_key = 'tampered-adapter'
                  from release_tools link
                 where link.tool_definition_id = definition.id and link.release_id = ?
                   and definition.tool_key = 'CASE_CONTEXT_READ'
                """
        );
        jdbcTemplate.update("""
                update tool_definitions definition set adapter_key = 'case_context_read'
                  from release_tools link
                 where link.tool_definition_id = definition.id and link.release_id = ?
                   and definition.tool_key = 'CASE_CONTEXT_READ'
                """, toolRelease.id());

        definitionFirstIsObserved(
                ragRelease.id(),
                """
                update rag_sources source set trust_level = 'UNTRUSTED'
                  from release_rag_sources link
                 where link.rag_source_id = source.id and link.release_id = ?
                """
        );
        jdbcTemplate.update("""
                update rag_sources source set trust_level = 'TRUSTED_INTERNAL'
                  from release_rag_sources link
                 where link.rag_source_id = source.id and link.release_id = ?
                """, ragRelease.id());

        analyzeFirstRejectsLateMutation(
                toolRelease.id(),
                """
                update tool_definitions definition set adapter_key = 'late-adapter'
                  from release_tools link
                 where link.tool_definition_id = definition.id and link.release_id = ?
                   and definition.tool_key = 'CASE_CONTEXT_READ'
                """
        );
        analyzeFirstRejectsLateMutation(
                ragRelease.id(),
                """
                update rag_sources source set trust_level = 'LATE_TRUST'
                  from release_rag_sources link
                 where link.rag_source_id = source.id and link.release_id = ?
                """
        );
    }

    private void definitionFirstIsObserved(UUID releaseId, String mutationSql) throws Exception {
        try (Connection first = dataSource.getConnection(); var executor = Executors.newSingleThreadExecutor()) {
            first.setAutoCommit(false);
            try (var mutation = first.prepareStatement(mutationSql)) {
                mutation.setObject(1, releaseId);
                assertThat(mutation.executeUpdate()).isEqualTo(1);
            }
            Future<Throwable> analyze = executor.submit(() -> {
                try {
                    releaseService.analyze(releaseId, "definition-first-review");
                    return null;
                } catch (Throwable throwable) {
                    return throwable;
                }
            });
            assertThatThrownBy(() -> analyze.get(200, TimeUnit.MILLISECONDS))
                    .isInstanceOf(java.util.concurrent.TimeoutException.class);
            first.commit();
            assertThat(analyze.get(5, TimeUnit.SECONDS)).isInstanceOf(BusinessException.class);
        }
        assertThat(jdbcTemplate.queryForObject(
                "select lifecycle_state from agent_releases where id = ?",
                String.class,
                releaseId
        )).isEqualTo("DRAFT");
    }

    private void analyzeFirstRejectsLateMutation(UUID releaseId, String mutationSql) throws Exception {
        try (Connection first = dataSource.getConnection(); var executor = Executors.newSingleThreadExecutor()) {
            first.setAutoCommit(false);
            try (var lock = first.prepareStatement(
                    "select lifecycle_state from agent_releases where id = ? for update"
            )) {
                lock.setObject(1, releaseId);
                lock.executeQuery().close();
            }
            Future<String> mutation = executor.submit(() -> {
                try (Connection second = dataSource.getConnection(); var statement = second.prepareStatement(mutationSql)) {
                    statement.setObject(1, releaseId);
                    statement.executeUpdate();
                    return "accepted";
                } catch (java.sql.SQLException exception) {
                    return exception.getSQLState();
                }
            });
            assertThatThrownBy(() -> mutation.get(200, TimeUnit.MILLISECONDS))
                    .isInstanceOf(java.util.concurrent.TimeoutException.class);
            try (var transition = first.prepareStatement("""
                    update agent_releases
                       set lifecycle_state = 'ANALYZED', effective_status = 'ANALYZED', analyzed_at = now()
                     where id = ?
                    """)) {
                transition.setObject(1, releaseId);
                assertThat(transition.executeUpdate()).isEqualTo(1);
            }
            first.commit();
            assertThat(mutation.get(5, TimeUnit.SECONDS)).isEqualTo("55000");
        }
    }

    private ReleaseDto.Response createRelease(String suffix, boolean uniqueRag) throws Exception {
        String unique = UUID.randomUUID().toString().substring(0, 8);
        String agentKey = "definition-" + suffix + "-" + unique;
        AgentDto.Response agent = agentService.create(new AgentDto.CreateRequest(
                agentKey,
                "Definition Concurrency Agent",
                "Definition serialization verification"
        ));
        JsonNode manifest = objectMapper.readTree(
                getClass().getResourceAsStream("/fixtures/valid-release-manifest.json")
        );
        ((ObjectNode) manifest.path("agent")).put("id", agentKey);
        if (uniqueRag) {
            ((ObjectNode) manifest.path("ragSources").get(0)).put("sourceId", "policy-" + unique);
        }
        return releaseService.create(agent.id(), manifest, "definition-concurrency-review");
    }
}
