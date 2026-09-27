package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.evidence.RedactionService;
import com.finsecseal.policy.GatewayRuntimeObservations.InvocationKey;
import com.finsecseal.policy.GatewayRuntimeObservations.StateCapture;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.runtime.ToolInvocation;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.sandbox.SandboxExecutionContext;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.DecimalNode;
import tools.jackson.databind.node.ObjectNode;

class ReadOnlyToolResultWitnessCaptureTest {

    private static final UUID RUN = UUID.fromString("00000000-0000-0000-0000-000000000101");
    private static final UUID CASE_RUN = UUID.fromString("00000000-0000-0000-0000-000000000102");
    private static final UUID TRACE = UUID.fromString("00000000-0000-0000-0000-000000000103");
    private static final String REQUEST_DIGEST = "sha256:" + "a".repeat(64);
    private static final String BEFORE_DIGEST = "sha256:" + "b".repeat(64);
    private static final String TOOL = "CUSTOMER_DATA_READ";

    private final ObjectMapper json = new ObjectMapper();
    private final RedactionService redaction = new RedactionService(json,
            new CanonicalJsonService(json), new DigestService(),
            Base64.getEncoder().encodeToString(new byte[32]));
    private final AtomicLong clock = new AtomicLong(100);
    private final ReadOnlyToolResultWitnessCapture witness =
            new ReadOnlyToolResultWitnessCapture(redaction, clock::get);

    @Test
    void capturesActualAdapterResultWithSameSnapshotDigestAndDefensiveBody() {
        InvocationKey key = key();
        UUID captureId = UUID.randomUUID();
        ObjectNode raw = json.createObjectNode().put("applicantId", "AP-123").put("amount", 20);
        AtomicInteger calls = new AtomicInteger();
        ToolAdapter adapter = adapter(calls, () -> result(raw));
        String expectedDigest = redaction.redact(raw.deepCopy()).originalDigest();

        var captured = witness.executeCaptured(key, before(key, captureId), context(), invocation(key), adapter);
        assertThat(calls).hasValue(1);
        assertThat(captured.captureId()).isEqualTo(captureId);
        assertThat(captured.result().output()).isEqualTo(raw);
        assertThat(captured.result().stateChanged()).isFalse();

        raw.put("amount", 999);
        ((ObjectNode) captured.result().output()).put("amount", 888);
        assertThat(captured.result().output().path("amount").asInt()).isEqualTo(20);
        var consumed = witness.consume(key, captureId);
        assertThat(consumed.rawOutputDigest()).isEqualTo(expectedDigest);
        assertThat(consumed.reportedStateChanged()).isFalse();
    }

    @Test
    void wrongCaptureAndSecondConsumptionFailAndSameKeyTombstoneBlocksNewAttempt() {
        InvocationKey key = key();
        UUID captureId = UUID.randomUUID();
        AtomicInteger calls = new AtomicInteger();
        ToolAdapter adapter = adapter(calls, () -> result(json.createObjectNode().put("ok", true)));
        witness.executeCaptured(key, before(key, captureId), context(), invocation(key), adapter);

        assertIncomplete(() -> witness.consume(key, UUID.randomUUID()));
        witness.consume(key, captureId);
        assertIncomplete(() -> witness.consume(key, captureId));
        assertIncomplete(() -> witness.executeCaptured(key, before(key, UUID.randomUUID()),
                context(), invocation(key), adapter));
        assertThat(calls).hasValue(1);
    }

    @Test
    void sameKeyConcurrentReservationNeverEntersSecondAdapter() throws Exception {
        InvocationKey key = key();
        UUID captureId = UUID.randomUUID();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger calls = new AtomicInteger();
        ToolAdapter adapter = adapter(calls, () -> {
            entered.countDown();
            await(release);
            return result(json.createObjectNode().put("ok", true));
        });
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<?> first = pool.submit(() -> witness.executeCaptured(
                    key, before(key, captureId), context(), invocation(key), adapter));
            assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
            assertIncomplete(() -> witness.executeCaptured(key, before(key, UUID.randomUUID()),
                    context(), invocation(key), adapter));
            release.countDown();
            first.get(5, TimeUnit.SECONDS);
            assertThat(calls).hasValue(1);
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    void failedAttemptKeepsTombstoneAndNeverExposesAdapterCause() {
        InvocationKey key = key();
        AtomicInteger calls = new AtomicInteger();
        ToolAdapter adapter = adapter(calls, () -> {
            throw new IllegalStateException("raw secret from adapter");
        });
        assertIncomplete(() -> witness.executeCaptured(key, before(key, UUID.randomUUID()),
                context(), invocation(key), adapter));
        assertIncomplete(() -> witness.executeCaptured(key, before(key, UUID.randomUUID()),
                context(), invocation(key), adapter));
        assertThat(calls).hasValue(1);
    }

    @Test
    void cancelledLateResultCannotPublishIntoReplacementSlot() throws Exception {
        InvocationKey key = key();
        UUID oldCapture = UUID.randomUUID();
        UUID newCapture = UUID.randomUUID();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ToolAdapter oldAdapter = adapter(new AtomicInteger(), () -> {
            entered.countDown();
            await(release);
            return result(json.createObjectNode().put("generation", "old"));
        });
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<?> oldAttempt = pool.submit(() -> witness.executeCaptured(
                    key, before(key, oldCapture), context(), invocation(key), oldAdapter));
            assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
            witness.cancel(key, oldCapture);
            assertIncomplete(() -> witness.consume(key, oldCapture));
            assertIncomplete(() -> witness.executeCaptured(key, before(key, newCapture),
                    context(), invocation(key), oldAdapter));

            clock.addAndGet(ReadOnlyToolResultWitnessCapture.TTL_NANOS + 1);
            var replacement = witness.executeCaptured(key, before(key, newCapture), context(),
                    invocation(key), adapter(new AtomicInteger(),
                            () -> result(json.createObjectNode().put("generation", "new"))));
            release.countDown();
            Throwable oldFailure = catchFutureFailure(oldAttempt);
            assertBusinessFailure(oldFailure);
            assertThat(witness.consume(key, replacement.captureId()).rawOutputDigest())
                    .isEqualTo(redaction.redact(replacement.result().output()).originalDigest());
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    void consumedTombstonesCountTowardGlobalCapacityAndExpireOnlyAtTtl() {
        AtomicInteger calls = new AtomicInteger();
        ToolAdapter adapter = adapter(calls, () -> result(json.createObjectNode().put("ok", true)));
        for (int i = 0; i < ReadOnlyToolResultWitnessCapture.MAX_ENTRIES; i++) {
            InvocationKey key = key();
            UUID captureId = UUID.randomUUID();
            witness.executeCaptured(key, before(key, captureId), context(), invocation(key), adapter);
            witness.consume(key, captureId);
        }
        InvocationKey extra = key();
        assertIncomplete(() -> witness.executeCaptured(extra, before(extra, UUID.randomUUID()),
                context(), invocation(extra), adapter));
        assertThat(calls).hasValue(ReadOnlyToolResultWitnessCapture.MAX_ENTRIES);

        clock.addAndGet(ReadOnlyToolResultWitnessCapture.TTL_NANOS);
        witness.executeCaptured(extra, before(extra, UUID.randomUUID()), context(), invocation(extra), adapter);
        assertThat(calls).hasValue(ReadOnlyToolResultWitnessCapture.MAX_ENTRIES + 1);
    }

    @Test
    void monotonicTtlWorksAcrossSignedLongOverflow() {
        clock.set(Long.MAX_VALUE - TimeUnit.SECONDS.toNanos(2));
        InvocationKey key = key();
        UUID captureId = UUID.randomUUID();
        ToolAdapter adapter = adapter(new AtomicInteger(),
                () -> result(json.createObjectNode().put("ok", true)));
        witness.executeCaptured(key, before(key, captureId), context(), invocation(key), adapter);
        clock.addAndGet(TimeUnit.SECONDS.toNanos(4));
        witness.consume(key, captureId);
        assertIncomplete(() -> witness.executeCaptured(key, before(key, UUID.randomUUID()),
                context(), invocation(key), adapter));
        clock.addAndGet(TimeUnit.SECONDS.toNanos(1));
        witness.executeCaptured(key, before(key, UUID.randomUUID()), context(), invocation(key), adapter);
    }

    @Test
    void rejectsHugeExponentAndAggregateNumericWorkBeforeRedaction() {
        RedactionService neverCalled = mock(RedactionService.class);
        ReadOnlyToolResultWitnessCapture capture =
                new ReadOnlyToolResultWitnessCapture(neverCalled, clock::get);
        InvocationKey hugeKey = key();
        JsonNode hugeExponent = DecimalNode.valueOf(new BigDecimal(BigInteger.ONE, -1_000_000));
        assertIncomplete(() -> capture.executeCaptured(hugeKey, before(hugeKey, UUID.randomUUID()),
                context(), invocation(hugeKey), adapter(new AtomicInteger(), () -> result(hugeExponent))));

        ArrayNode aggregate = json.createArrayNode();
        for (int i = 0; i < 36; i++) {
            aggregate.add(DecimalNode.valueOf(new BigDecimal(BigInteger.ONE, -30_000)));
        }
        InvocationKey aggregateKey = key();
        assertIncomplete(() -> capture.executeCaptured(aggregateKey,
                before(aggregateKey, UUID.randomUUID()), context(), invocation(aggregateKey),
                adapter(new AtomicInteger(), () -> result(aggregate))));
        verifyNoInteractions(neverCalled);
    }

    @Test
    void cyclicOversizeNullAndStateChangedResultsFailClosedBeforeRedaction() {
        RedactionService neverCalled = mock(RedactionService.class);
        ReadOnlyToolResultWitnessCapture capture =
                new ReadOnlyToolResultWitnessCapture(neverCalled, clock::get);
        ObjectNode cyclic = json.createObjectNode();
        cyclic.set("self", cyclic);
        assertRejectedOutput(capture, cyclic);
        assertRejectedOutput(capture, json.createObjectNode().put("large", "x".repeat(1024 * 1024)));
        assertRejectedOutput(capture, null);

        InvocationKey changedKey = key();
        assertIncomplete(() -> capture.executeCaptured(changedKey,
                before(changedKey, UUID.randomUUID()), context(), invocation(changedKey),
                adapter(new AtomicInteger(), () -> new ToolAdapter.ToolExecutionResult(
                        json.createObjectNode(), true))));
        verifyNoInteractions(neverCalled);
    }

    @Test
    void invalidContextStateChangingAdapterAndAmbientTransactionNeverEnterAdapter() {
        InvocationKey key = key();
        AtomicInteger calls = new AtomicInteger();
        ToolAdapter normal = adapter(calls, () -> result(json.createObjectNode()));
        SandboxExecutionContext invalid = new SandboxExecutionContext(RUN, CASE_RUN, TRACE,
                null, "CASE-1", "AP-1");
        assertIncomplete(() -> witness.executeCaptured(key, before(key, UUID.randomUUID()),
                invalid, invocation(key), normal));
        ToolAdapter stateChanging = new ToolAdapter() {
            @Override public String toolName() { return TOOL; }
            @Override public ToolEffect effect() { return ToolEffect.STATE_CHANGING; }
            @Override public ToolExecutionResult execute(SandboxExecutionContext ignored, JsonNode arguments) {
                calls.incrementAndGet();
                return result(json.createObjectNode());
            }
        };
        assertIncomplete(() -> witness.executeCaptured(key, before(key, UUID.randomUUID()),
                context(), invocation(key), stateChanging));

        boolean wasActive = TransactionSynchronizationManager.isActualTransactionActive();
        TransactionSynchronizationManager.setActualTransactionActive(true);
        try {
            assertIncomplete(() -> witness.executeCaptured(key, before(key, UUID.randomUUID()),
                    context(), invocation(key), normal));
        } finally {
            TransactionSynchronizationManager.setActualTransactionActive(wasActive);
        }
        assertThat(calls).hasValue(0);
    }

    private void assertRejectedOutput(ReadOnlyToolResultWitnessCapture capture, JsonNode output) {
        InvocationKey key = key();
        assertIncomplete(() -> capture.executeCaptured(key, before(key, UUID.randomUUID()),
                context(), invocation(key), adapter(new AtomicInteger(), () -> result(output))));
    }

    private static InvocationKey key() {
        return new InvocationKey(RUN, CASE_RUN, TRACE, UUID.randomUUID(), REQUEST_DIGEST);
    }

    private static StateCapture before(InvocationKey key, UUID captureId) {
        return new StateCapture(key, captureId, RUN, BEFORE_DIGEST, true);
    }

    private static SandboxExecutionContext context() {
        return new SandboxExecutionContext(RUN, CASE_RUN, TRACE, TestRunMode.BASELINE, "CASE-1", "AP-1");
    }

    private ToolInvocation invocation(InvocationKey key) {
        return new ToolInvocation(new ToolProposal(TOOL, json.createObjectNode()),
                key.toolCallId(), key.requestDigest());
    }

    private static ToolAdapter.ToolExecutionResult result(JsonNode output) {
        return new ToolAdapter.ToolExecutionResult(output, false);
    }

    private static ToolAdapter adapter(AtomicInteger calls,
            Supplier<ToolAdapter.ToolExecutionResult> response) {
        return new ToolAdapter() {
            @Override public String toolName() { return TOOL; }
            @Override public ToolExecutionResult execute(SandboxExecutionContext context, JsonNode arguments) {
                calls.incrementAndGet();
                return response.get();
            }
        };
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(5, TimeUnit.SECONDS)) throw new AssertionError("adapter release timed out");
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new AssertionError("adapter interrupted", exception);
        }
    }

    private static Throwable catchFutureFailure(Future<?> future) throws Exception {
        try {
            future.get(5, TimeUnit.SECONDS);
            throw new AssertionError("expected witness failure");
        } catch (ExecutionException exception) {
            return exception.getCause();
        }
    }

    private static void assertIncomplete(org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertBusinessFailure(catchThrowable(action));
    }

    private static void assertBusinessFailure(Throwable failure) {
        assertThat(failure).isInstanceOf(BusinessException.class)
                .hasMessage("Read-only Tool result witness is incomplete")
                .hasNoCause();
        assertThat(((BusinessException) failure).errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE);
    }
}
