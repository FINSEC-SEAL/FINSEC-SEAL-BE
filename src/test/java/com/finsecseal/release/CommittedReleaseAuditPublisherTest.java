package com.finsecseal.release;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.finsecseal.audit.AuditDto;
import java.time.Instant;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

class CommittedReleaseAuditPublisherTest {

    private static final UUID AUDIT = UUID.fromString("0198f200-0000-7000-8000-000000001001");
    private static final UUID WORKSPACE = UUID.fromString("0198f200-0000-7000-8000-000000001002");
    private static final UUID RELEASE = UUID.fromString("0198f200-0000-7000-8000-000000001003");
    private static final Instant OCCURRED = Instant.parse("2026-10-03T01:02:03.123456789Z");
    private static final String INVALIDATED = "AGENT_RELEASE_INVALIDATED";
    private static final String APPLIED = "RELEASE_CONTRACT_FINGERPRINT_APPLIED";
    private static final String ACTOR = "actor-sensitive-canary";
    private static final String BEFORE = "before-digest-sensitive-canary";
    private static final String AFTER = "after-digest-sensitive-canary";
    private static final String METADATA = "metadata-policy-session-sensitive-canary";
    private static final String FAILURE_MESSAGE = "exception-message-stack-sensitive-canary";

    private final ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
    private final CommittedReleaseAuditPublisher helper = new CommittedReleaseAuditPublisher(publisher);
    private final ObjectMapper json = new ObjectMapper();
    private final Logger logger = (Logger) LoggerFactory.getLogger(CommittedReleaseAuditPublisher.class);
    private final ListAppender<ILoggingEvent> warnings = new ListAppender<>();

    @BeforeEach
    void captureWarnings() {
        TransactionSynchronizationManager.clear();
        warnings.start();
        logger.addAppender(warnings);
    }

    @AfterEach
    void cleanUp() {
        TransactionSynchronizationManager.clear();
        logger.detachAppender(warnings);
        warnings.stop();
    }

    @ParameterizedTest
    @MethodSource("invalidTransactions")
    void guardAndRegistrationRefuseInvalidTransactionStates(boolean actual, boolean synchronizedState, boolean readOnly) {
        transaction(actual, synchronizedState, readOnly);
        assertThatThrownBy(helper::requireWritableTransaction).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> register(receipt(INVALIDATED, BEFORE, AFTER))).isInstanceOf(IllegalStateException.class);
        assertNoRegistrationOrPublication();
    }

    static Stream<Arguments> invalidTransactions() {
        return Stream.of(
                Arguments.of(false, false, false), Arguments.of(false, true, false),
                Arguments.of(true, false, false), Arguments.of(true, true, true)
        );
    }

    @Test
    void writableActualSynchronizedTransactionPassesEntryGuardWithoutPublishing() {
        transaction(true, true, false);
        assertThatCode(helper::requireWritableTransaction).doesNotThrowAnyException();
        assertNoRegistrationOrPublication();
    }

    @ParameterizedTest
    @ValueSource(strings = {"actual", "synchronization", "readOnly"})
    void registrationRechecksStateAfterEntryGuard(String changedState) {
        transaction(true, true, false);
        helper.requireWritableTransaction();
        switch (changedState) {
            case "actual" -> TransactionSynchronizationManager.setActualTransactionActive(false);
            case "synchronization" -> TransactionSynchronizationManager.clearSynchronization();
            case "readOnly" -> TransactionSynchronizationManager.setCurrentTransactionReadOnly(true);
            default -> throw new AssertionError("Unknown test state");
        }
        assertThatThrownBy(() -> register(receipt(INVALIDATED, BEFORE, AFTER))).isInstanceOf(IllegalStateException.class);
        assertNoRegistrationOrPublication();
    }

    @Test
    void transactionIsRecheckedAfterSnapshotAndBeforeRegistration() {
        transaction(true, true, false);
        JsonNode changingMetadata = mock(JsonNode.class);
        doAnswer(invocation -> {
            TransactionSynchronizationManager.setCurrentTransactionReadOnly(true);
            return json.createObjectNode();
        }).when(changingMetadata).deepCopy();
        AuditDto.Record receipt = withMetadata(receipt(INVALIDATED, BEFORE, AFTER), changingMetadata);
        assertThatThrownBy(() -> register(receipt)).isInstanceOf(IllegalStateException.class);
        assertNoRegistrationOrPublication();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidReceipts")
    void invalidReceiptFactsFailBeforeRegistration(String label, AuditDto.Record receipt,
                                                  UUID workspace, UUID release, String action) {
        transaction(true, true, false);
        assertThatThrownBy(() -> helper.register(receipt, workspace, release, action))
                .isInstanceOf(IllegalArgumentException.class);
        assertNoRegistrationOrPublication();
    }

    static Stream<Arguments> invalidReceipts() {
        AuditDto.Record valid = facts(AUDIT, WORKSPACE, INVALIDATED, "AGENT_RELEASE", RELEASE, OCCURRED);
        return Stream.of(
                invalid("null receipt", null),
                invalid("missing audit", facts(null, WORKSPACE, INVALIDATED, "AGENT_RELEASE", RELEASE, OCCURRED)),
                invalid("missing workspace", facts(AUDIT, null, INVALIDATED, "AGENT_RELEASE", RELEASE, OCCURRED)),
                invalid("missing Release", facts(AUDIT, WORKSPACE, INVALIDATED, "AGENT_RELEASE", null, OCCURRED)),
                invalid("missing time", facts(AUDIT, WORKSPACE, INVALIDATED, "AGENT_RELEASE", RELEASE, null)),
                invalid("foreign workspace", facts(AUDIT, RELEASE, INVALIDATED, "AGENT_RELEASE", RELEASE, OCCURRED)),
                invalid("foreign Release", facts(AUDIT, WORKSPACE, INVALIDATED, "AGENT_RELEASE", WORKSPACE, OCCURRED)),
                invalid("missing resource type", facts(AUDIT, WORKSPACE, INVALIDATED, null, RELEASE, OCCURRED)),
                invalid("wrong resource type", facts(AUDIT, WORKSPACE, INVALIDATED, "CONTRACT_VERSION", RELEASE, OCCURRED)),
                invalid("missing action", facts(AUDIT, WORKSPACE, null, "AGENT_RELEASE", RELEASE, OCCURRED)),
                invalid("unrelated action", facts(AUDIT, WORKSPACE, "AGENT_RELEASE_CREATED", "AGENT_RELEASE", RELEASE, OCCURRED)),
                invalid("other allowed action", facts(AUDIT, WORKSPACE, APPLIED, "AGENT_RELEASE", RELEASE, OCCURRED)),
                invalid("noncanonical action", facts(AUDIT, WORKSPACE, "agent_release_invalidated", "AGENT_RELEASE", RELEASE, OCCURRED)),
                Arguments.of("missing expected workspace", valid, null, RELEASE, INVALIDATED),
                Arguments.of("missing expected Release", valid, WORKSPACE, null, INVALIDATED),
                Arguments.of("missing expected action", valid, WORKSPACE, RELEASE, null),
                Arguments.of("unrelated expected action", valid, WORKSPACE, RELEASE, "AGENT_RELEASE_CREATED")
        );
    }

    private static Arguments invalid(String label, AuditDto.Record receipt) {
        return Arguments.of(label, receipt, WORKSPACE, RELEASE, INVALIDATED);
    }

    @ParameterizedTest
    @MethodSource("allowedReceipts")
    void onlyAfterCommitPublishesDetachedReceiptWithUnchangedScalars(String action, boolean equalDigests) {
        transaction(true, true, false);
        AuditDto.Record receipt = receipt(action, BEFORE, equalDigests ? BEFORE : AFTER);
        helper.register(receipt, WORKSPACE, RELEASE, action);
        TransactionSynchronization synchronization = onlySynchronization();
        verifyNoInteractions(publisher);
        synchronization.beforeCommit(false);
        synchronization.beforeCompletion();
        verifyNoInteractions(publisher);
        synchronization.afterCommit();
        synchronization.afterCompletion(TransactionSynchronization.STATUS_COMMITTED);
        AuditDto.Record published = publishedReceipt();
        assertThat(published).isNotSameAs(receipt);
        assertThat(published.id()).isEqualTo(receipt.id());
        assertThat(published.workspaceId()).isEqualTo(receipt.workspaceId());
        assertThat(published.actorId()).isEqualTo(receipt.actorId());
        assertThat(published.action()).isEqualTo(receipt.action());
        assertThat(published.resourceType()).isEqualTo(receipt.resourceType());
        assertThat(published.resourceId()).isEqualTo(receipt.resourceId());
        assertThat(published.beforeDigest()).isEqualTo(receipt.beforeDigest());
        assertThat(published.afterDigest()).isEqualTo(receipt.afterDigest());
        assertThat(published.occurredAt()).isEqualTo(receipt.occurredAt());
        assertThat(published.metadata()).isEqualTo(receipt.metadata()).isNotSameAs(receipt.metadata());
        assertThat(warnings.list).isEmpty();
    }

    static Stream<Arguments> allowedReceipts() {
        return Stream.of(Arguments.of(INVALIDATED, false), Arguments.of(INVALIDATED, true),
                Arguments.of(APPLIED, false), Arguments.of(APPLIED, true));
    }

    @ParameterizedTest
    @ValueSource(ints = {TransactionSynchronization.STATUS_COMMITTED, TransactionSynchronization.STATUS_ROLLED_BACK,
            TransactionSynchronization.STATUS_UNKNOWN})
    void afterCompletionNeverPublishesWithoutAfterCommit(int status) {
        transaction(true, true, false);
        register(receipt(INVALIDATED, BEFORE, AFTER));
        onlySynchronization().afterCompletion(status);
        verifyNoInteractions(publisher);
        assertThat(warnings.list).isEmpty();
    }

    @Test
    void nestedMetadataIsDetachedFromOwnerAndListenerMutations() {
        transaction(true, true, false);
        AuditDto.Record original = receipt(INVALIDATED, BEFORE, AFTER);
        register(original);
        ((ObjectNode) original.metadata().path("nested")).put("value", "owner-changed");
        ((ObjectNode) original.metadata().path("nested")).putArray("labels").add("owner-array-changed");
        onlySynchronization().afterCommit();
        AuditDto.Record published = publishedReceipt();
        assertThat(published.metadata().at("/nested/value").asString()).isEqualTo(METADATA);
        assertThat(published.metadata().at("/nested/labels/0").asString()).isEqualTo("original-label");
        ((ObjectNode) published.metadata().path("nested")).put("value", "listener-changed");
        ((ObjectNode) published.metadata().path("nested")).putArray("labels").add("listener-array-changed");
        assertThat(original.metadata().at("/nested/value").asString()).isEqualTo("owner-changed");
        assertThat(original.metadata().at("/nested/labels/0").asString()).isEqualTo("owner-array-changed");
    }

    @Test
    void snapshotRuntimeExceptionPropagatesBeforeRegistration() {
        transaction(true, true, false);
        JsonNode failingMetadata = mock(JsonNode.class);
        RuntimeException failure = new IllegalStateException(FAILURE_MESSAGE);
        doThrow(failure).when(failingMetadata).deepCopy();
        AuditDto.Record receipt = withMetadata(receipt(INVALIDATED, BEFORE, AFTER), failingMetadata);
        assertThatThrownBy(() -> register(receipt)).isSameAs(failure);
        assertNoRegistrationOrPublication();
    }

    @Test
    void registrationRuntimeExceptionPropagatesWithoutPublishingOrWarning() {
        transaction(true, true, false);
        RuntimeException failure = new IllegalStateException(FAILURE_MESSAGE);
        try (var manager = mockStatic(TransactionSynchronizationManager.class, CALLS_REAL_METHODS)) {
            manager.when(() -> TransactionSynchronizationManager.registerSynchronization(any())).thenThrow(failure);
            assertThatThrownBy(() -> register(receipt(INVALIDATED, BEFORE, AFTER))).isSameAs(failure);
            assertNoRegistrationOrPublication();
        }
    }

    @Test
    void synchronousRuntimeFailureProducesSafeWarnAndDoesNotRetry() {
        transaction(true, true, false);
        RuntimeException failure = new IllegalStateException(FAILURE_MESSAGE);
        doThrow(failure).when(publisher).publishEvent(any(Object.class));
        register(receipt(INVALIDATED, BEFORE, AFTER));
        TransactionSynchronization synchronization = onlySynchronization();
        assertThatCode(synchronization::afterCommit).doesNotThrowAnyException();
        synchronization.afterCompletion(TransactionSynchronization.STATUS_COMMITTED);
        verify(publisher, times(1)).publishEvent(any(Object.class));
        ILoggingEvent warning = onlyWarning();
        assertThat(warning.getArgumentArray()).containsExactly(AUDIT, RELEASE, INVALIDATED, IllegalStateException.class.getName());
        assertThat(warning.getFormattedMessage()).doesNotContain(FAILURE_MESSAGE, ACTOR, METADATA, BEFORE, AFTER);
    }

    @Test
    void causeClassIsBoundedWithoutExceptionMessageOrStack() {
        transaction(true, true, false);
        RuntimeException failure = new ExceptionClassWithAnIntentionallyLongNameUsedToVerifyBoundedCauseClassLoggingWithoutPublishingAnyExceptionMessageOrStackTrace();
        assertThat(failure.getClass().getName().length()).isGreaterThan(128);
        doThrow(failure).when(publisher).publishEvent(any(Object.class));
        register(receipt(INVALIDATED, BEFORE, AFTER));
        onlySynchronization().afterCommit();
        ILoggingEvent warning = onlyWarning();
        assertThat(warning.getArgumentArray()).hasSize(4);
        assertThat((String) warning.getArgumentArray()[3]).hasSize(128).matches("[A-Za-z0-9_.$]{1,128}");
        assertThat(warning.getFormattedMessage()).doesNotContain(FAILURE_MESSAGE, ACTOR, METADATA, BEFORE, AFTER);
        verify(publisher, times(1)).publishEvent(any(Object.class));
    }

    @Test
    void publisherErrorPropagatesWithoutWarningOrRetry() {
        transaction(true, true, false);
        AssertionError failure = new AssertionError(FAILURE_MESSAGE);
        doThrow(failure).when(publisher).publishEvent(any(Object.class));
        register(receipt(INVALIDATED, BEFORE, AFTER));
        assertThatThrownBy(() -> onlySynchronization().afterCommit()).isSameAs(failure);
        verify(publisher, times(1)).publishEvent(any(Object.class));
        assertThat(warnings.list).isEmpty();
    }

    private ILoggingEvent onlyWarning() {
        assertThat(warnings.list).hasSize(1);
        ILoggingEvent warning = warnings.list.get(0);
        assertThat(warning.getLevel()).isEqualTo(Level.WARN);
        assertThat(warning.getMessage()).isEqualTo(
                "Committed Release audit notification failed auditId={} releaseId={} action={} causeClass={}");
        assertThat(warning.getThrowableProxy()).isNull();
        return warning;
    }

    private static void transaction(boolean actual, boolean synchronizedState, boolean readOnly) {
        TransactionSynchronizationManager.setActualTransactionActive(actual);
        TransactionSynchronizationManager.setCurrentTransactionReadOnly(readOnly);
        if (synchronizedState) {
            TransactionSynchronizationManager.initSynchronization();
        }
    }

    private void register(AuditDto.Record receipt) {
        helper.register(receipt, WORKSPACE, RELEASE, INVALIDATED);
    }

    private void assertNoRegistrationOrPublication() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            assertThat(TransactionSynchronizationManager.getSynchronizations()).isEmpty();
        }
        verifyNoInteractions(publisher);
        assertThat(warnings.list).isEmpty();
    }

    private static TransactionSynchronization onlySynchronization() {
        assertThat(TransactionSynchronizationManager.getSynchronizations()).hasSize(1);
        return TransactionSynchronizationManager.getSynchronizations().get(0);
    }

    private AuditDto.Record publishedReceipt() {
        ArgumentCaptor<AuditDto.Record> capture = ArgumentCaptor.forClass(AuditDto.Record.class);
        verify(publisher, times(1)).publishEvent(capture.capture());
        return capture.getValue();
    }

    private AuditDto.Record receipt(String action, String before, String after) {
        ObjectNode metadata = json.createObjectNode();
        ObjectNode nested = metadata.putObject("nested");
        nested.put("value", METADATA);
        nested.putArray("labels").add("original-label");
        return new AuditDto.Record(AUDIT, WORKSPACE, ACTOR, action, "AGENT_RELEASE", RELEASE,
                before, after, metadata, OCCURRED);
    }

    private static AuditDto.Record facts(UUID id, UUID workspace, String action, String resource,
                                         UUID release, Instant occurred) {
        return new AuditDto.Record(id, workspace, ACTOR, action, resource, release, BEFORE, AFTER, null, occurred);
    }

    private static AuditDto.Record withMetadata(AuditDto.Record receipt, JsonNode metadata) {
        return new AuditDto.Record(receipt.id(), receipt.workspaceId(), receipt.actorId(), receipt.action(),
                receipt.resourceType(), receipt.resourceId(), receipt.beforeDigest(), receipt.afterDigest(), metadata,
                receipt.occurredAt());
    }

    private static final class ExceptionClassWithAnIntentionallyLongNameUsedToVerifyBoundedCauseClassLoggingWithoutPublishingAnyExceptionMessageOrStackTrace
            extends RuntimeException {
        private ExceptionClassWithAnIntentionallyLongNameUsedToVerifyBoundedCauseClassLoggingWithoutPublishingAnyExceptionMessageOrStackTrace() {
            super(FAILURE_MESSAGE);
        }
    }
}
