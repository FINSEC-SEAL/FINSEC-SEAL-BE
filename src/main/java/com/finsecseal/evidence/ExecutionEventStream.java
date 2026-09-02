package com.finsecseal.evidence;

import com.finsecseal.common.domain.ExecutionEventType;
import java.io.IOException;
import java.time.Duration;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@Component
public class ExecutionEventStream {

    private static final int LOCK_STRIPES = 256;

    private final ExecutionEventService eventService;
    private final long timeoutMillis;
    private final Object[] runLocks = new Object[LOCK_STRIPES];
    private final ConcurrentHashMap<UUID, Set<SseEmitter>> subscribers = new ConcurrentHashMap<>();

    public ExecutionEventStream(
            ExecutionEventService eventService,
            @Value("${finsec.sse.timeout:30m}") Duration timeout
    ) {
        this.eventService = eventService;
        this.timeoutMillis = timeout.toMillis();
        for (int index = 0; index < runLocks.length; index++) {
            runLocks[index] = new Object();
        }
    }

    public SseEmitter subscribe(UUID runId, long afterSequence) {
        SseEmitter emitter = new SseEmitter(timeoutMillis);
        Object lock = lockFor(runId);
        synchronized (lock) {
            Set<SseEmitter> runSubscribers = subscribers.computeIfAbsent(
                    runId,
                    ignored -> ConcurrentHashMap.newKeySet()
            );
            runSubscribers.add(emitter);
            emitter.onCompletion(() -> remove(runId, emitter));
            emitter.onTimeout(() -> {
                remove(runId, emitter);
                emitter.complete();
            });
            emitter.onError(ignored -> remove(runId, emitter));
            try {
                long cursor = afterSequence;
                while (true) {
                    ExecutionEventDto.History history = eventService.history(runId, cursor, 1000);
                    for (ExecutionEventDto.Event event : history.items()) {
                        send(emitter, event);
                        cursor = event.sequence();
                    }
                    if (history.nextCursor() == null) {
                        break;
                    }
                }
            } catch (RuntimeException | IOException exception) {
                remove(runId, emitter);
                emitter.completeWithError(exception);
                throw exception instanceof RuntimeException runtimeException
                        ? runtimeException
                        : new IllegalStateException("SSE replay failed", exception);
            }
        }
        return emitter;
    }

    public void publish(ExecutionEventDto.Event event) {
        Object lock = lockFor(event.runId());
        synchronized (lock) {
            Set<SseEmitter> runSubscribers = subscribers.get(event.runId());
            if (runSubscribers == null) {
                return;
            }
            for (SseEmitter emitter : Set.copyOf(runSubscribers)) {
                try {
                    send(emitter, event);
                } catch (IOException | IllegalStateException exception) {
                    remove(event.runId(), emitter);
                    emitter.completeWithError(exception);
                }
            }
        }
    }

    @Scheduled(fixedDelayString = "${finsec.sse.heartbeat-ms:15000}")
    void heartbeat() {
        subscribers.forEach((runId, runSubscribers) -> {
            Object lock = lockFor(runId);
            synchronized (lock) {
                for (SseEmitter emitter : Set.copyOf(runSubscribers)) {
                    try {
                        emitter.send(SseEmitter.event().name("heartbeat").comment("keep-alive"));
                    } catch (IOException | IllegalStateException exception) {
                        remove(runId, emitter);
                        emitter.completeWithError(exception);
                    }
                }
            }
        });
    }

    private void send(SseEmitter emitter, ExecutionEventDto.Event event) throws IOException {
        emitter.send(SseEmitter.event()
                .id(Long.toString(event.sequence()))
                .name(eventName(event.eventType()))
                .data(event));
    }

    private String eventName(ExecutionEventType type) {
        return switch (type) {
            case RUN_STARTED, RUN_CANCEL_REQUESTED, RUN_FAILED -> "run.status";
            case RUN_COMPLETED -> "run.completed";
            case FINDING_CREATED -> "finding.created";
            default -> "trace.event";
        };
    }

    private void remove(UUID runId, SseEmitter emitter) {
        Set<SseEmitter> runSubscribers = subscribers.get(runId);
        if (runSubscribers == null) {
            return;
        }
        runSubscribers.remove(emitter);
        if (runSubscribers.isEmpty()) {
            subscribers.remove(runId, runSubscribers);
        }
    }

    private Object lockFor(UUID runId) {
        return runLocks[Math.floorMod(runId.hashCode(), runLocks.length)];
    }
}
