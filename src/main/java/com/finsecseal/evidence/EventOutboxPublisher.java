package com.finsecseal.evidence;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class EventOutboxPublisher {

    private final JdbcTemplate jdbcTemplate;
    private final ExecutionEventService eventService;
    private final ExecutionEventStream eventStream;

    public EventOutboxPublisher(
            JdbcTemplate jdbcTemplate,
            ExecutionEventService eventService,
            ExecutionEventStream eventStream
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.eventService = eventService;
        this.eventStream = eventStream;
    }

    @Scheduled(fixedDelayString = "${finsec.sse.outbox-poll-ms:250}")
    @Transactional
    public void publishPending() {
        List<UUID> eventIds = jdbcTemplate.query("""
                select event_id
                  from event_outbox
                 where published_at is null
                 order by created_at, event_id
                 limit 100
                 for update skip locked
                """, (resultSet, rowNumber) -> resultSet.getObject("event_id", UUID.class));
        for (UUID eventId : eventIds) {
            eventStream.publish(eventService.findById(eventId));
            Instant publishedAt = Instant.now();
            jdbcTemplate.update("""
                    update event_outbox
                       set publish_attempts = publish_attempts + 1,
                           last_attempt_at = ?, published_at = ?
                     where event_id = ? and published_at is null
                    """, Timestamp.from(publishedAt), Timestamp.from(publishedAt), eventId);
        }
    }
}
