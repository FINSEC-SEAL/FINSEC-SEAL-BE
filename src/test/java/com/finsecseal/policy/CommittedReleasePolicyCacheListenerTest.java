package com.finsecseal.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import com.finsecseal.audit.AuditDto;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@ExtendWith(OutputCaptureExtension.class)
class CommittedReleasePolicyCacheListenerTest {

    private static final UUID AUDIT = UUID.fromString("b8059709-e246-4933-a5b6-9f9d8521b6fa");
    private static final UUID WORKSPACE = UUID.fromString("c74148a3-57db-4e53-b871-b3c8adca4df5");
    private static final UUID RELEASE = UUID.fromString("3900c8b0-9855-4d76-b04c-6136b01051d9");
    private static final UUID OTHER_RELEASE = UUID.fromString("f8ac6186-1e79-4d9e-87b3-a2867c0cc9e5");
    private static final Instant OCCURRED = Instant.parse("2026-10-02T22:00:00Z");
    private static final String INVALIDATED = "AGENT_RELEASE_INVALIDATED";
    private static final String APPLIED = "RELEASE_CONTRACT_FINGERPRINT_APPLIED";
    private static final String CANARY = "PRIVATE-CACHE-SESSION-METADATA-CANARY";
    private final GatewayApprovedPolicySourceService cache = mock(GatewayApprovedPolicySourceService.class);
    private final CommittedReleasePolicyCacheListener listener = new CommittedReleasePolicyCacheListener(cache);

    @ParameterizedTest
    @ValueSource(strings = {INVALIDATED, APPLIED})
    void eachAllowedActionEvictsExactlyTheActualResource(String action) {
        listener.onCommittedReleaseAudit(record(action));

        verify(cache).invalidateRelease(RELEASE);
        verifyNoMoreInteractions(cache);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("missingRequiredFields")
    void missingRequiredScalarsAreIgnored(String field, AuditDto.Record record) {
        listener.onCommittedReleaseAudit(record);

        verifyNoInteractions(cache);
    }

    private static Stream<Arguments> missingRequiredFields() {
        return Stream.of(
                Arguments.of("null record", null),
                Arguments.of("id", new AuditDto.Record(null, WORKSPACE, null, INVALIDATED,
                        "AGENT_RELEASE", RELEASE, null, null, null, OCCURRED)),
                Arguments.of("workspaceId", new AuditDto.Record(AUDIT, null, null, INVALIDATED,
                        "AGENT_RELEASE", RELEASE, null, null, null, OCCURRED)),
                Arguments.of("resourceId", new AuditDto.Record(AUDIT, WORKSPACE, null, INVALIDATED,
                        "AGENT_RELEASE", null, null, null, null, OCCURRED)),
                Arguments.of("occurredAt", new AuditDto.Record(AUDIT, WORKSPACE, null, INVALIDATED,
                        "AGENT_RELEASE", RELEASE, null, null, null, null))
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("unrelatedRecords")
    void nonexactOrUnrelatedResourceAndActionAreIgnored(String description, AuditDto.Record record) {
        listener.onCommittedReleaseAudit(record);

        verifyNoInteractions(cache);
    }

    private static Stream<Arguments> unrelatedRecords() {
        Stream<Arguments> resourceTypes = Stream.of(null, "", "agent_release", "AGENT_RELEASE ",
                "CONTRACT_VERSION", "SYSTEM_PROMPT", "UNKNOWN_RESOURCE")
                .map(type -> Arguments.of("resource=" + type, new AuditDto.Record(AUDIT, WORKSPACE,
                        null, INVALIDATED, type, RELEASE, null, null, null, OCCURRED)));
        Stream<Arguments> actions = Stream.of(null, "", "agent_release_invalidated",
                "AGENT_RELEASE_INVALIDATED ", "RELEASE_CONTRACT_FINGERPRINT_APPLIED ",
                "CONTRACT_VERSION_APPROVED", "PROMPT_ACCESS", "AGENT_RELEASE_CREATED", "UNKNOWN_ACTION")
                .map(action -> Arguments.of("action=" + action, new AuditDto.Record(AUDIT, WORKSPACE,
                        null, action, "AGENT_RELEASE", RELEASE, null, null, null, OCCURRED)));
        return Stream.concat(resourceTypes, actions);
    }

    @ParameterizedTest(name = "{0}, {1}")
    @MethodSource("irrelevantFacts")
    void actorDigestsAndMetadataNeverSupplyAuthorityOrDiscloseContent(
            String action, String description, String actor, String before, String after, CapturedOutput output) {
        JsonNode metadata = spy(new ObjectMapper().createObjectNode()
                .put("token", CANARY).put("actorRole", "AI_GOVERNANCE_REVIEWER").put("approved", true));
        listener.onCommittedReleaseAudit(new AuditDto.Record(AUDIT, WORKSPACE, actor, action,
                "AGENT_RELEASE", RELEASE, before, after, metadata, OCCURRED));

        verify(cache).invalidateRelease(RELEASE);
        verifyNoMoreInteractions(cache);
        verifyNoInteractions(metadata);
        assertThat(output.getAll()).doesNotContain(CANARY);
    }

    private static Stream<Arguments> irrelevantFacts() {
        return List.of(INVALIDATED, APPLIED).stream().flatMap(action -> Stream.of(
                Arguments.of(action, "actor and digests absent", null, null, null),
                Arguments.of(action, "equal digests", "AI_GOVERNANCE_REVIEWER " + CANARY, CANARY, CANARY),
                Arguments.of(action, "different digests", CANARY, CANARY + "-before", CANARY + "-after"),
                Arguments.of(action, "malformed digest text", "untrusted-actor", "not-a-hash", "")
        ));
    }

    @ParameterizedTest
    @ValueSource(strings = {INVALIDATED, APPLIED})
    void duplicateSameReceiptAlwaysEvictsAgain(String action) {
        AuditDto.Record receipt = record(action);

        listener.onCommittedReleaseAudit(receipt);
        listener.onCommittedReleaseAudit(receipt);
        listener.onCommittedReleaseAudit(receipt);

        verify(cache, times(3)).invalidateRelease(RELEASE);
        verifyNoMoreInteractions(cache);
    }

    @Test
    void reversedReceiptOrderDelegatesEachResourceInDeliveryOrder() {
        AuditDto.Record earlier = record(INVALIDATED);
        AuditDto.Record later = new AuditDto.Record(UUID.randomUUID(), WORKSPACE, null, APPLIED,
                "AGENT_RELEASE", OTHER_RELEASE, null, null, null, OCCURRED.plusSeconds(1));

        listener.onCommittedReleaseAudit(later);
        listener.onCommittedReleaseAudit(earlier);
        listener.onCommittedReleaseAudit(later);

        var calls = inOrder(cache);
        calls.verify(cache).invalidateRelease(OTHER_RELEASE);
        calls.verify(cache).invalidateRelease(RELEASE);
        calls.verify(cache).invalidateRelease(OTHER_RELEASE);
        verifyNoMoreInteractions(cache);
    }

    @Test
    void differentReceiptsWithSameDigestStillEvictTheSameRelease() {
        for (String action : List.of(INVALIDATED, APPLIED)) {
            listener.onCommittedReleaseAudit(new AuditDto.Record(UUID.randomUUID(), WORKSPACE,
                    null, action, "AGENT_RELEASE", RELEASE, CANARY, CANARY, null, OCCURRED));
        }

        verify(cache, times(2)).invalidateRelease(RELEASE);
        verifyNoMoreInteractions(cache);
    }

    @ParameterizedTest
    @ValueSource(strings = {INVALIDATED, APPLIED})
    void springEventDeliveryCompletesOnThePublishingThread(String action) {
        AtomicReference<Thread> deliveryThread = new AtomicReference<>();
        doAnswer(invocation -> {
            deliveryThread.set(Thread.currentThread());
            return null;
        }).when(cache).invalidateRelease(RELEASE);
        try (var context = new AnnotationConfigApplicationContext()) {
            context.registerBean(GatewayApprovedPolicySourceService.class, () -> cache);
            context.register(CommittedReleasePolicyCacheListener.class);
            context.refresh();
            Thread publishingThread = Thread.currentThread();

            context.publishEvent(record(action));

            assertThat(deliveryThread.get()).isSameAs(publishingThread);
            verify(cache).invalidateRelease(RELEASE);
            verifyNoMoreInteractions(cache);
        }
    }

    private static AuditDto.Record record(String action) {
        return new AuditDto.Record(AUDIT, WORKSPACE, null, action, "AGENT_RELEASE",
                RELEASE, null, null, null, OCCURRED);
    }
}
