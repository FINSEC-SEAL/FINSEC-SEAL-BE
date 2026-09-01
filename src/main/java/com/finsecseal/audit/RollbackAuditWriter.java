package com.finsecseal.audit;

import com.finsecseal.common.persistence.UuidV7;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import jakarta.annotation.PreDestroy;
import java.sql.Timestamp;
import java.time.Instant;
import javax.sql.DataSource;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

@Component
public class RollbackAuditWriter {

    private final HikariDataSource dataSource;
    private final ObjectMapper objectMapper;

    public RollbackAuditWriter(DataSource primaryDataSource, ObjectMapper objectMapper) {
        HikariDataSource primary;
        try {
            primary = primaryDataSource.unwrap(HikariDataSource.class);
        } catch (Exception exception) {
            throw new IllegalStateException("Rollback audit requires a JDBC HikariDataSource", exception);
        }
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(primary.getJdbcUrl());
        config.setUsername(primary.getUsername());
        config.setPassword(primary.getPassword());
        config.setDriverClassName(primary.getDriverClassName());
        config.setMaximumPoolSize(2);
        config.setMinimumIdle(0);
        config.setConnectionTimeout(5_000);
        config.setPoolName("finsec-rollback-audit");
        this.dataSource = new HikariDataSource(config);
        this.objectMapper = objectMapper;
    }

    public void append(PromptAccessRolledBackEvent event) {
        try (var connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                boolean releaseExists;
                try (var exists = connection.prepareStatement(
                        "select exists(select 1 from agent_releases where id = ?)"
                )) {
                    exists.setObject(1, event.releaseId());
                    try (var result = exists.executeQuery()) {
                        result.next();
                        releaseExists = result.getBoolean(1);
                    }
                }
                if (!releaseExists) {
                    connection.rollback();
                    return;
                }
                try (var insert = connection.prepareStatement("""
                        insert into audit_records
                            (id, workspace_id, actor_id, action, resource_type, resource_id,
                             before_digest, after_digest, metadata_json, occurred_at)
                        values (?, ?, ?, 'SYSTEM_PROMPT_DECRYPTED_INTERNAL', 'AGENT_RELEASE', ?,
                                null, ?, ?::jsonb, ?)
                        """)) {
                    insert.setObject(1, UuidV7.generate());
                    insert.setObject(2, event.workspaceId());
                    insert.setString(3, event.actorId());
                    insert.setObject(4, event.releaseId());
                    insert.setString(5, event.artifactDigest());
                    insert.setString(6, objectMapper.writeValueAsString(event.metadata()));
                    insert.setTimestamp(7, Timestamp.from(Instant.now()));
                    if (insert.executeUpdate() != 1) {
                        throw new IllegalStateException("Rollback prompt audit was not inserted exactly once");
                    }
                }
                connection.commit();
            } catch (Exception exception) {
                connection.rollback();
                throw exception;
            }
        } catch (Exception exception) {
            throw new IllegalStateException("Rollback prompt audit could not be persisted", exception);
        }
    }

    @PreDestroy
    void close() {
        dataSource.close();
    }
}

