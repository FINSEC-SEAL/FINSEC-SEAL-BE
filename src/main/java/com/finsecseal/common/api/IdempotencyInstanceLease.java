package com.finsecseal.common.api;

import com.finsecseal.common.persistence.UuidV7;
import jakarta.annotation.PostConstruct;
import java.sql.Timestamp;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class IdempotencyInstanceLease {

    private final JdbcTemplate jdbcTemplate;
    private final Duration staleAfter;
    private final UUID instanceId = UuidV7.generate();
    private final String transitionSecret;

    public IdempotencyInstanceLease(
            JdbcTemplate jdbcTemplate,
            @Value("${finsec.idempotency.instance-stale-after:30s}") Duration staleAfter
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.staleAfter = staleAfter;
        if (staleAfter.isNegative() || staleAfter.isZero()) {
            throw new IllegalStateException("Idempotency instance lease timeout must be positive");
        }
        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);
        this.transitionSecret = Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
    }

    @PostConstruct
    void register() {
        Instant now = Instant.now();
        jdbcTemplate.update("""
                insert into application_instance_leases
                    (id, started_at, heartbeat_at, lease_expires_at, transition_secret_hash)
                values (?, ?, ?, ?, digest(?::text, 'sha256'))
                """,
                instanceId,
                Timestamp.from(now),
                Timestamp.from(now),
                Timestamp.from(now.plus(staleAfter)),
                transitionSecret
        );
    }

    public UUID instanceId() {
        return instanceId;
    }

    String transitionSecret() {
        return transitionSecret;
    }

    @Scheduled(fixedDelayString = "${finsec.idempotency.instance-heartbeat-ms:5000}")
    @Transactional
    public void heartbeatAndReconcile() {
        Instant now = Instant.now();
        jdbcTemplate.update("""
                update application_instance_leases set heartbeat_at = ?, lease_expires_at = ?
                 where id = ? and stopped_at is null
                """, Timestamp.from(now), Timestamp.from(now.plus(staleAfter)), instanceId);
        jdbcTemplate.update("""
                update api_idempotency_records record
                   set state = 'RECOVERY_REQUIRED', execution_finished_at = ?,
                       recovery_reason = 'OWNER_LEASE_EXPIRED'
                 where record.state = 'PROCESSING' and record.expires_at <= ?
                   and exists (
                       select 1 from application_instance_leases lease
                        where lease.id = record.owner_instance_id
                          and (lease.stopped_at is not null or lease.lease_expires_at <= ?)
                   )
                """,
                Timestamp.from(now),
                Timestamp.from(now),
                Timestamp.from(now)
        );
    }

}
