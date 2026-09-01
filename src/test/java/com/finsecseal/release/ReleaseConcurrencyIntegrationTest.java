package com.finsecseal.release;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import java.io.IOException;
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
class ReleaseConcurrencyIntegrationTest {

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
    void committedDraftChildMutationIsObservedByWaitingAnalyze() throws Exception {
        ReleaseDto.Response release = createRelease("child-first");
        try (Connection first = dataSource.getConnection(); var executor = Executors.newSingleThreadExecutor()) {
            first.setAutoCommit(false);
            try (var statement = first.prepareStatement("""
                    update release_artifacts
                       set content_json = '{"tampered":true}'::jsonb
                     where release_id = ? and artifact_type = 'MODEL_CONFIG'
                    """)) {
                statement.setObject(1, release.id());
                assertThat(statement.executeUpdate()).isEqualTo(1);
            }

            Future<Throwable> analyze = executor.submit(() -> {
                try {
                    releaseService.analyze(release.id(), "concurrency-review");
                    return null;
                } catch (Throwable throwable) {
                    return throwable;
                }
            });
            assertThatThrownBy(() -> analyze.get(200, TimeUnit.MILLISECONDS))
                    .isInstanceOf(java.util.concurrent.TimeoutException.class);

            first.commit();
            Throwable failure = analyze.get(5, TimeUnit.SECONDS);
            assertThat(failure).isInstanceOfSatisfying(BusinessException.class, exception ->
                    assertThat(exception.errorCode()).isEqualTo(ErrorCode.RELEASE_CHANGED));
        }
        assertThat(jdbcTemplate.queryForObject(
                "select lifecycle_state from agent_releases where id = ?",
                String.class,
                release.id()
        )).isEqualTo("DRAFT");
    }

    @Test
    void committedAnalyzeMakesWaitingDraftChildMutationFail() throws Exception {
        ReleaseDto.Response release = createRelease("analyze-first");
        try (Connection first = dataSource.getConnection(); var executor = Executors.newSingleThreadExecutor()) {
            first.setAutoCommit(false);
            try (var lock = first.prepareStatement(
                    "select lifecycle_state from agent_releases where id = ? for update"
            )) {
                lock.setObject(1, release.id());
                lock.executeQuery().close();
            }

            Future<String> mutation = executor.submit(() -> {
                try (Connection second = dataSource.getConnection(); var statement = second.prepareStatement("""
                        update release_artifacts
                           set content_json = '{"late":true}'::jsonb
                         where release_id = ? and artifact_type = 'MODEL_CONFIG'
                        """)) {
                    statement.setObject(1, release.id());
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
                transition.setObject(1, release.id());
                assertThat(transition.executeUpdate()).isEqualTo(1);
            }
            first.commit();
            assertThat(mutation.get(5, TimeUnit.SECONDS)).isEqualTo("55000");
        }
        assertThat(jdbcTemplate.queryForObject("""
                select content_json::text from release_artifacts
                 where release_id = ? and artifact_type = 'MODEL_CONFIG'
                """, String.class, release.id())).doesNotContain("late");
    }

    @Test
    void archivedAgentCannotReceiveAWaitingRelease() throws Exception {
        String agentKey = "archive-race-" + UUID.randomUUID().toString().substring(0, 8);
        AgentDto.Response agent = agentService.create(new AgentDto.CreateRequest(
                agentKey,
                "Archive Race Agent",
                "Agent archive serialization verification"
        ));
        JsonNode manifest = objectMapper.readTree(
                getClass().getResourceAsStream("/fixtures/valid-release-manifest.json")
        );
        ((ObjectNode) manifest.path("agent")).put("id", agentKey);

        try (Connection first = dataSource.getConnection(); var executor = Executors.newSingleThreadExecutor()) {
            first.setAutoCommit(false);
            try (var archive = first.prepareStatement("update agents set status = 'ARCHIVED' where id = ?")) {
                archive.setObject(1, agent.id());
                assertThat(archive.executeUpdate()).isEqualTo(1);
            }

            Future<Throwable> creation = executor.submit(() -> {
                try {
                    releaseService.create(agent.id(), manifest, "archive-race-review");
                    return null;
                } catch (Throwable throwable) {
                    return throwable;
                }
            });
            assertThatThrownBy(() -> creation.get(200, TimeUnit.MILLISECONDS))
                    .isInstanceOf(java.util.concurrent.TimeoutException.class);

            first.commit();
            Throwable failure = creation.get(5, TimeUnit.SECONDS);
            assertThat(failure).isInstanceOfSatisfying(BusinessException.class, exception ->
                    assertThat(exception.errorCode()).isEqualTo(ErrorCode.INVALID_STATE_TRANSITION));
        }
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from agent_releases where agent_id = ?",
                Integer.class,
                agent.id()
        )).isZero();
    }

    private ReleaseDto.Response createRelease(String suffix) throws IOException {
        String agentKey = "loan-document-review-" + suffix + "-" + UUID.randomUUID().toString().substring(0, 8);
        AgentDto.Response agent = agentService.create(new AgentDto.CreateRequest(
                agentKey,
                "Concurrency Agent",
                "Release concurrency verification"
        ));
        JsonNode manifest = objectMapper.readTree(
                getClass().getResourceAsStream("/fixtures/valid-release-manifest.json")
        );
        ((ObjectNode) manifest.path("agent")).put("id", agentKey);
        return releaseService.create(agent.id(), manifest, "concurrency-review");
    }
}
