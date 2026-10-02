package com.finsecseal.evidence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.finsecseal.common.domain.ExecutionEventType;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedConstruction;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyEmitter;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

// Test-owned emitter faults exercise Stream behavior; they do not prove HTTP or DB transactions.
class ExecutionEventStreamTest {

    private static final Duration TIMEOUT = Duration.ofMinutes(30);
    private final ExecutionEventService service = mock(ExecutionEventService.class);
    private final ExecutionEventStream stream = new ExecutionEventStream(service, TIMEOUT);
    private final UUID runId = UUID.randomUUID();

    @ParameterizedTest
    @EnumSource(Dispatch.class)
    void firstVisitedIoFaultIsRemovedWithoutCompletionAndHealthyDeliveryContinues(Dispatch dispatch)
            throws IOException {
        SseEmitter first = mock(SseEmitter.class);
        SseEmitter second = mock(SseEmitter.class);
        SseEmitter other = mock(SseEmitter.class);
        UUID otherRun = UUID.randomUUID();
        enroll(runId, first, second);
        enroll(otherRun, other);
        AtomicReference<SseEmitter> failed = new AtomicReference<>();
        IOException io = new IOException("test-owned disconnected emitter");
        for (SseEmitter emitter : List.of(first, second)) {
            doAnswer(invocation -> {
                if (failed.compareAndSet(null, (SseEmitter) invocation.getMock())) {
                    throw io;
                }
                return null;
            }).when(emitter).send(any(SseEmitter.SseEventBuilder.class));
            // The old app completion path would itself fail; the IO path must never call it.
            doThrow(new IllegalStateException("duplicate completion"))
                    .when(emitter).completeWithError(any());
        }

        ExecutionEventDto.Event event = event(runId, 1);
        dispatch.invoke(stream, event);
        SseEmitter fault = failed.get();
        assertThat(fault).isIn(first, second);
        SseEmitter healthy = fault == first ? second : first;
        assertThat(subscribers().get(runId)).containsExactly(healthy);
        assertThat(subscribers().get(otherRun)).containsExactly(other);
        verify(fault, times(1)).send(any(SseEmitter.SseEventBuilder.class));
        verify(healthy, times(1)).send(any(SseEmitter.SseEventBuilder.class));

        dispatch.invoke(stream, event);
        verify(fault, times(1)).send(any(SseEmitter.SseEventBuilder.class));
        verify(healthy, times(2)).send(any(SseEmitter.SseEventBuilder.class));
        verify(other, times(dispatch == Dispatch.HEARTBEAT ? 2 : 0))
                .send(any(SseEmitter.SseEventBuilder.class));
        for (SseEmitter emitter : List.of(first, second, other)) {
            verify(emitter, never()).completeWithError(any());
        }
        ArgumentCaptor<SseEmitter.SseEventBuilder> sent = builderCaptor();
        verify(healthy, times(2)).send(sent.capture());
        assertFrame(sent.getAllValues().getFirst(), dispatch, event);
    }

    @ParameterizedTest
    @EnumSource(Dispatch.class)
    void normalAndNoSubscriberDeliveryKeepTheExistingProjection(Dispatch dispatch) throws IOException {
        ExecutionEventDto.Event event = event(runId, 4);
        dispatch.invoke(stream, event);
        assertThat(subscribers()).isEmpty();
        SseEmitter emitter = mock(SseEmitter.class);
        enroll(runId, emitter);
        dispatch.invoke(stream, event);
        ArgumentCaptor<SseEmitter.SseEventBuilder> sent = builderCaptor();
        verify(emitter).send(sent.capture());
        assertFrame(sent.getValue(), dispatch, event);
        assertThat(subscribers().get(runId)).containsExactly(emitter);
        verify(emitter, never()).completeWithError(any());
    }

    @ParameterizedTest
    @EnumSource(Dispatch.class)
    void illegalStateStillRemovesAndCompletesWithTheOriginalFailure(Dispatch dispatch) throws IOException {
        SseEmitter emitter = mock(SseEmitter.class);
        enroll(runId, emitter);
        IllegalStateException failure = new IllegalStateException("existing non-IO policy");
        doThrow(failure).when(emitter).send(any(SseEmitter.SseEventBuilder.class));
        dispatch.invoke(stream, event(runId, 1));
        assertThat(subscribers()).doesNotContainKey(runId);
        verify(emitter).completeWithError(failure);
    }

    @ParameterizedTest(name = "{0}: cleanup {1}")
    @MethodSource("dispatchFailures")
    void nonIoCleanupFailureStillPropagatesItsOriginalIdentity(Dispatch dispatch, Throwable cleanup)
            throws IOException {
        SseEmitter emitter = mock(SseEmitter.class);
        enroll(runId, emitter);
        IllegalStateException sendFailure = new IllegalStateException("existing ISE cleanup");
        doThrow(sendFailure).when(emitter).send(any(SseEmitter.SseEventBuilder.class));
        doThrow(cleanup).when(emitter).completeWithError(sendFailure);
        assertSame(cleanup, assertThrows(Throwable.class, () -> dispatch.invoke(stream, event(runId, 1))));
        assertThat(subscribers()).doesNotContainKey(runId);
        verify(emitter).completeWithError(sendFailure);
    }

    @ParameterizedTest(name = "{0}: raw {1}")
    @MethodSource("dispatchFailures")
    void unexpectedNonIllegalStateSendFailureIsNotSwallowed(Dispatch dispatch, Throwable failure)
            throws IOException {
        SseEmitter emitter = mock(SseEmitter.class);
        enroll(runId, emitter);
        doThrow(failure).when(emitter).send(any(SseEmitter.SseEventBuilder.class));
        assertSame(failure, assertThrows(Throwable.class, () -> dispatch.invoke(stream, event(runId, 1))));
        assertThat(subscribers().get(runId)).containsExactly(emitter);
        verify(emitter, never()).completeWithError(any());
    }

    @Test
    void replayIoRetainsWrapperAndCauseWithoutAppCompletion() {
        IOException io = new IOException("replay IO");
        when(service.streamReplayHistory(runId, 2, 1000)).thenReturn(history(event(runId, 5), null));
        try (MockedConstruction<SseEmitter> construction = mockConstruction(SseEmitter.class,
                (emitter, context) -> {
                    doThrow(io).when(emitter).send(any(SseEmitter.SseEventBuilder.class));
                    doThrow(new IllegalStateException("duplicate completion"))
                            .when(emitter).completeWithError(any());
                })) {
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> stream.subscribe(runId, 2));
            assertThat(failure).hasMessage("SSE replay failed");
            assertSame(io, failure.getCause());
            assertThat(construction.constructed()).hasSize(1);
            SseEmitter emitter = construction.constructed().getFirst();
            verify(emitter, never()).completeWithError(any());
            assertThat(subscribers()).doesNotContainKey(runId);
        }
    }

    @Test
    void replayPageFailureStillCompletesAndRethrowsTheSameRuntime() {
        IllegalArgumentException failure = new IllegalArgumentException("second page failed");
        replayThenFail(failure);
        try (MockedConstruction<SseEmitter> construction = mockConstruction(SseEmitter.class)) {
            assertSame(failure, assertThrows(IllegalArgumentException.class, () -> stream.subscribe(runId, 2)));
            SseEmitter emitter = construction.constructed().getFirst();
            verify(emitter).completeWithError(failure);
            assertThat(subscribers()).doesNotContainKey(runId);
            verify(service).history(runId, 5, 1000);
        }
    }

    @ParameterizedTest
    @MethodSource("unexpectedFailures")
    void replayRuntimeCleanupRetainsItsUnexpectedFailurePolicy(Throwable cleanup) {
        IllegalArgumentException original = new IllegalArgumentException("second page failed");
        replayThenFail(original);
        try (MockedConstruction<SseEmitter> construction = mockConstruction(SseEmitter.class,
                (emitter, context) -> doThrow(cleanup).when(emitter).completeWithError(original))) {
            assertSame(cleanup, assertThrows(Throwable.class, () -> stream.subscribe(runId, 2)));
            assertThat(subscribers()).doesNotContainKey(runId);
            verify(construction.constructed().getFirst()).completeWithError(original);
        }
    }

    @ParameterizedTest
    @MethodSource("unexpectedFailures")
    void initialHistoryFailureOccursBeforeEmitterCreationOrRegistration(Throwable failure) {
        when(service.streamReplayHistory(runId, 2, 1000)).thenThrow(failure);
        try (MockedConstruction<SseEmitter> construction = mockConstruction(SseEmitter.class)) {
            assertSame(failure, assertThrows(Throwable.class, () -> stream.subscribe(runId, 2)));
            assertThat(construction.constructed()).isEmpty();
            assertThat(subscribers()).isEmpty();
            verify(service, never()).history(any(), org.mockito.ArgumentMatchers.anyLong(),
                    org.mockito.ArgumentMatchers.anyInt());
        }
    }

    @Test
    void replayRawErrorStillPropagatesWithoutIntroducingCleanup() {
        AssertionError failure = new AssertionError("raw replay error");
        replayThenFail(failure);
        try (MockedConstruction<SseEmitter> construction = mockConstruction(SseEmitter.class)) {
            assertSame(failure, assertThrows(AssertionError.class, () -> stream.subscribe(runId, 2)));
            SseEmitter emitter = construction.constructed().getFirst();
            assertThat(subscribers().get(runId)).containsExactly(emitter);
            verify(emitter, never()).completeWithError(any());
        }
    }

    @Test
    void normalPagedReplayRetainsCursorTimeoutAndSubsequentLiveDelivery() throws IOException {
        ExecutionEventDto.Event first = event(runId, 5);
        ExecutionEventDto.Event second = event(runId, 7);
        when(service.streamReplayHistory(runId, 2, 1000)).thenReturn(history(first, 5L));
        when(service.history(runId, 5, 1000)).thenReturn(history(second, null));
        AtomicReference<List<?>> arguments = new AtomicReference<>();
        try (MockedConstruction<SseEmitter> construction = mockConstruction(SseEmitter.class,
                (emitter, context) -> arguments.set(context.arguments()))) {
            SseEmitter emitter = stream.subscribe(runId, 2);
            assertSame(construction.constructed().getFirst(), emitter);
            assertThat(arguments.get()).isEqualTo(List.of(TIMEOUT.toMillis()));
            assertThat(subscribers().get(runId)).containsExactly(emitter);
            verify(service).streamReplayHistory(runId, 2, 1000);
            verify(service).history(runId, 5, 1000);
            ExecutionEventDto.Event live = event(runId, 8);
            stream.publish(live);
            ArgumentCaptor<SseEmitter.SseEventBuilder> sent = builderCaptor();
            verify(emitter, times(3)).send(sent.capture());
            assertFrame(sent.getAllValues().get(0), Dispatch.PUBLISH, first);
            assertFrame(sent.getAllValues().get(1), Dispatch.PUBLISH, second);
            assertFrame(sent.getAllValues().get(2), Dispatch.PUBLISH, live);
            verify(emitter).onCompletion(any());
            verify(emitter).onTimeout(any());
            verify(emitter).onError(any());
            verify(emitter, never()).completeWithError(any());
        }
    }

    @ParameterizedTest
    @EnumSource(Callback.class)
    void registeredCallbacksRetainTheirExistingRemovalAndTimeoutPolicy(Callback callback) {
        when(service.streamReplayHistory(runId, 0, 1000))
                .thenReturn(new ExecutionEventDto.History(List.of(), 0, null));
        AtomicReference<Runnable> completion = new AtomicReference<>();
        AtomicReference<Runnable> timeout = new AtomicReference<>();
        AtomicReference<Consumer<Throwable>> error = new AtomicReference<>();
        try (MockedConstruction<SseEmitter> construction = mockConstruction(SseEmitter.class,
                (emitter, context) -> {
                    doAnswer(invocation -> { completion.set(invocation.getArgument(0)); return null; })
                            .when(emitter).onCompletion(any());
                    doAnswer(invocation -> { timeout.set(invocation.getArgument(0)); return null; })
                            .when(emitter).onTimeout(any());
                    doAnswer(invocation -> { error.set(invocation.getArgument(0)); return null; })
                            .when(emitter).onError(any());
                })) {
            SseEmitter emitter = stream.subscribe(runId, 0);
            switch (callback) {
                case COMPLETION -> completion.get().run();
                case TIMEOUT -> timeout.get().run();
                case ERROR -> error.get().accept(new IOException("callback-owned IO"));
            }
            assertThat(subscribers()).doesNotContainKey(runId);
            verify(emitter, times(callback == Callback.TIMEOUT ? 1 : 0)).complete();
            verify(emitter, never()).completeWithError(any());
            assertThat(construction.constructed()).hasSize(1);
        }
    }

    private void replayThenFail(Throwable failure) {
        when(service.streamReplayHistory(runId, 2, 1000)).thenReturn(history(event(runId, 5), 5L));
        when(service.history(runId, 5, 1000)).thenThrow(failure);
    }

    private static Stream<Throwable> unexpectedFailures() {
        return Stream.of(new IllegalArgumentException("raw runtime"), new AssertionError("raw error"));
    }

    private static Stream<Arguments> dispatchFailures() {
        return Stream.of(Dispatch.values()).flatMap(dispatch -> unexpectedFailures()
                .map(failure -> Arguments.of(dispatch, failure)));
    }

    private void enroll(UUID run, SseEmitter... emitters) {
        Set<SseEmitter> owned = ConcurrentHashMap.newKeySet();
        owned.addAll(List.of(emitters));
        subscribers().put(run, owned);
    }

    @SuppressWarnings("unchecked")
    private ConcurrentHashMap<UUID, Set<SseEmitter>> subscribers() {
        return (ConcurrentHashMap<UUID, Set<SseEmitter>>) ReflectionTestUtils.getField(stream, "subscribers");
    }

    private static ExecutionEventDto.History history(ExecutionEventDto.Event event, Long next) {
        return new ExecutionEventDto.History(List.of(event), event.sequence(), next);
    }

    private static ExecutionEventDto.Event event(UUID run, long sequence) {
        return new ExecutionEventDto.Event("v1", UUID.randomUUID(), UUID.randomUUID(), run, null,
                sequence, Instant.parse("2026-10-01T00:00:00Z"), ExecutionEventType.RUN_STARTED,
                null, null, null, "unit-digest", null, null, null, "unit-prev", "unit-hash");
    }

    private static ArgumentCaptor<SseEmitter.SseEventBuilder> builderCaptor() {
        return ArgumentCaptor.forClass(SseEmitter.SseEventBuilder.class);
    }

    private static void assertFrame(SseEmitter.SseEventBuilder builder, Dispatch dispatch,
            ExecutionEventDto.Event event) {
        Set<ResponseBodyEmitter.DataWithMediaType> frame = builder.build();
        String text = frame.stream().map(ResponseBodyEmitter.DataWithMediaType::getData)
                .filter(String.class::isInstance).map(String.class::cast).collect(Collectors.joining());
        if (dispatch == Dispatch.HEARTBEAT) {
            assertThat(text).contains("event:heartbeat\n", ":keep-alive\n").doesNotContain("id:", "data:");
            assertThat(frame).allSatisfy(item -> assertThat(item.getData()).isInstanceOf(String.class));
        } else {
            assertThat(text).contains("id:" + event.sequence() + "\n", "event:run.status\n", "data:");
            assertThat(frame).extracting(ResponseBodyEmitter.DataWithMediaType::getData).contains(event);
        }
    }

    private enum Dispatch {
        PUBLISH, HEARTBEAT;

        void invoke(ExecutionEventStream stream, ExecutionEventDto.Event event) {
            if (this == PUBLISH) {
                stream.publish(event);
            } else {
                stream.heartbeat();
            }
        }
    }

    private enum Callback { COMPLETION, TIMEOUT, ERROR }
}
