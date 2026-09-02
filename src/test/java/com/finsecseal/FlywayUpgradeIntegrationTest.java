package com.finsecseal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.InputStream;
import java.security.MessageDigest;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

@Testcontainers
class FlywayUpgradeIntegrationTest {

    private static final String V9_SHA256 =
            "09e79ccfb30a6a68fdc44be96700c10692cb17e2cba3f27d1a7645f41e14fc05";

    @Container
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Test
    void upgradesAnAlreadyAppliedV9DatabaseWithoutChangingItsChecksum() throws Exception {
        assertThat(migrationSha256("db/migration/V9__idempotency_execution_lease.sql"))
                .isEqualTo(V9_SHA256);

        Flyway throughV9 = flyway(MigrationVersion.fromVersion("9"));
        assertThat(throughV9.migrate().migrationsExecuted).isEqualTo(9);
        assertThat(appliedVersionCount()).isEqualTo(9);

        Flyway current = flyway(null);
        assertThat(current.migrate().migrationsExecuted).isEqualTo(2);
        assertThat(appliedVersionCount()).isEqualTo(11);
        assertThat(current.validateWithResult().validationSuccessful).isTrue();

        UUID leaseId = UUID.randomUUID();
        Instant now = Instant.now();
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             var insert = connection.prepareStatement("""
                     insert into application_instance_leases
                         (id, started_at, heartbeat_at, lease_expires_at, transition_secret_hash)
                     values (?, ?, ?, ?, digest('upgrade-owner-secret', 'sha256'))
                     """)) {
            insert.setObject(1, leaseId);
            insert.setTimestamp(2, java.sql.Timestamp.from(now));
            insert.setTimestamp(3, java.sql.Timestamp.from(now));
            insert.setTimestamp(4, java.sql.Timestamp.from(now.plusSeconds(30)));
            assertThat(insert.executeUpdate()).isEqualTo(1);
        }

        assertThatThrownBy(() -> updateLeaseWithoutOwnerProof(leaseId))
                .isInstanceOf(SQLException.class)
                .extracting(error -> ((SQLException) error).getSQLState())
                .isEqualTo("23514");
    }

    private Flyway flyway(MigrationVersion target) {
        var configuration = Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        if (target != null) {
            configuration.target(target);
        }
        return configuration.load();
    }

    private int appliedVersionCount() throws SQLException {
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             var statement = connection.createStatement();
             var result = statement.executeQuery("select count(*) from flyway_schema_history where success")) {
            assertThat(result.next()).isTrue();
            return result.getInt(1);
        }
    }

    private void updateLeaseWithoutOwnerProof(UUID leaseId) throws SQLException {
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             var update = connection.prepareStatement("""
                     update application_instance_leases
                        set heartbeat_at = heartbeat_at + interval '1 second',
                            lease_expires_at = lease_expires_at + interval '1 second'
                      where id = ?
                     """)) {
            update.setObject(1, leaseId);
            update.executeUpdate();
        }
    }

    private String migrationSha256(String resource) throws Exception {
        try (InputStream input = getClass().getClassLoader().getResourceAsStream(resource)) {
            assertThat(input).isNotNull();
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(input.readAllBytes()));
        }
    }
}
