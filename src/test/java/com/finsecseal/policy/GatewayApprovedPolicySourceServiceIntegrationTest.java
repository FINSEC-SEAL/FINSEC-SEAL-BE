package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEvaluationReason.HUMAN_ONLY_ACTION;
import static com.finsecseal.policy.PolicyEvaluationReason.OPERATION_NOT_ALLOWED;
import static com.finsecseal.policy.PolicyEvaluationReason.TOOL_NOT_ALLOWED;
import static com.finsecseal.policy.PolicyEvaluationStage.EGRESS;
import static com.finsecseal.policy.PolicyEvaluationStage.HUMAN_BOUNDARY;
import static com.finsecseal.policy.PolicyEvaluationStage.OPERATION;
import static com.finsecseal.policy.PolicyEvaluationStage.TOOL;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter;
import com.finsecseal.contract.SafetyContractCanonicalizer;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionIdentity;
import com.finsecseal.contract.SafetyContractSemanticValidator;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationStatus;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.evidence.TestRunProjectionService;
import com.finsecseal.platform.contract.ContractPersistenceService;
import com.finsecseal.platform.contract.ContractPersistenceService.Version;
import com.finsecseal.policy.GatewayApprovedPolicySourceService.ApprovedPolicySource;
import com.finsecseal.policy.GatewayApprovedPolicySourceService.FailureCode;
import com.finsecseal.policy.GatewayApprovedPolicySourceService.PolicySourceException;
import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;
import com.finsecseal.policy.PolicyToolAuthorizationFacts.CatalogTool;
import com.finsecseal.policy.PolicyToolTrustFacts.ReleaseToolBinding;
import com.finsecseal.policy.PolicyToolTrustFacts.ToolTrustPolicy;
import com.finsecseal.policy.PolicyToolTrustFacts.TrustLevel;
import com.finsecseal.release.ReleaseService;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/** Real owner storage and C readers; no test-managed transaction, execution engine or guard bypass. */
@Testcontainers
@SpringBootTest(properties = {
        "finsec.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "finsec.scheduling.enabled=false", "finsec.ai.enabled=false"
})
@ExtendWith(OutputCaptureExtension.class)
class GatewayApprovedPolicySourceServiceIntegrationTest {
    private static final String ACTOR = "c-gateway-source-integration";
    private static final String SESSION = "GATEWAY-SOURCE-PRIVATE-SESSION-CANARY";
    private static final String PROMPT = "GATEWAY-SOURCE-PRIVATE-PROMPT-CANARY";
    private static final String STORED = "GATEWAY-SOURCE-PRIVATE-SUMMARY-CANARY";
    private static final String RAW_ERROR = "GATEWAY-SOURCE-RAW-SQL-ERROR-CANARY";
    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final ReviewerContext REVIEWER = new ReviewerContext(
            AgentService.DEMO_WORKSPACE_ID, ACTOR, "AI_SECURITY_REVIEWER", SESSION, true, true, false);
    private static final List<String> DOMAIN_TABLES = List.of(
            "agents", "agent_releases", "release_artifacts", "safety_contracts", "safety_contract_versions",
            "contract_version_evidence", "api_idempotency_records", "patch_proposals", "patch_approvals",
            "test_suites", "test_cases", "test_runs", "test_case_runs", "run_event_counters", "execution_events",
            "findings", "oracle_results", "replay_links", "release_decisions", "evidence_references");

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired GatewayApprovedPolicySourceService sources;
    @Autowired GatewayPolicyFactsAssembler assembler;
    @MockitoSpyBean TestRunProjectionService runs;
    @MockitoSpyBean ContractPersistenceService contracts;
    @MockitoSpyBean TestRunPersistenceService cases;
    @MockitoSpyBean ReleaseToolCatalogContractAdapter catalogs;
    @MockitoSpyBean SafetyContractSemanticValidator validator;
    @MockitoSpyBean SafetyContractCanonicalizer canonicalizer;
    @Autowired AgentService agents;
    @Autowired ReleaseService releases;
    @Autowired ExecutionEventService events;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate jdbc;
    @Autowired DataSource dataSource;
    @Autowired PlatformTransactionManager transactions;

    @ParameterizedTest
    @EnumSource(value = TestRunMode.class, names = {"SEAL_REPLAY", "HELD_OUT", "REGRESSION"})
    void actualApprovedSourceUsesWritableRepeatableReadAndCurrentPostApprovalBinding(
            TestRunMode mode, CapturedOutput output) throws Exception {
        Seed seed = seed(mode);
        List<ReleaseToolBinding> storedBindings = storedReleaseBindings(seed.releaseId());
        List<CatalogTool> expectedDeclarations = expectedDeclaredTools(seed.releaseId());
        var firstRead = new AtomicReference<PhysicalTransaction>();
        var approvalRead = new AtomicReference<PhysicalTransaction>();
        var catalogRead = new AtomicReference<PhysicalTransaction>();
        doAnswer(invocation -> {
            firstRead.set(physicalTransaction());
            return invocation.callRealMethod();
        }).when(runs).find(seed.runId());
        doAnswer(invocation -> {
            approvalRead.set(physicalTransaction());
            return invocation.callRealMethod();
        }).when(contracts).approved(seed.releaseId(), seed.approved().id(), REVIEWER);
        doAnswer(invocation -> {
            catalogRead.set(physicalTransaction());
            return invocation.callRealMethod();
        }).when(catalogs).load(seed.releaseId(), ACTOR);
        Baseline before = baseline(seed.releaseId());
        clearOwnerInvocations();

        ApprovedPolicySource source = sources.load(seed.runId(), seed.caseRunId(), REVIEWER);

        assertPhysicalTransaction(firstRead.get());
        assertPhysicalTransaction(approvalRead.get());
        assertPhysicalTransaction(catalogRead.get());
        var order = inOrder(runs, contracts, cases, catalogs);
        order.verify(runs).find(seed.runId());
        order.verify(contracts).approved(seed.releaseId(), seed.approved().id(), REVIEWER);
        order.verify(cases).findCase(seed.caseRunId());
        order.verify(catalogs).load(seed.releaseId(), ACTOR);
        assertSource(source, seed, mode);
        assertThat(storedBindings).hasSize(5).extracting(ReleaseToolBinding::toolName)
                .containsExactlyInAnyOrder("CASE_CONTEXT_READ", "DOCUMENT_READER", "CUSTOMER_DATA_READ",
                        "LOAN_POLICY_SEARCH", "REVIEW_NOTE_WRITE");
        assertThat(storedBindings).allMatch(ReleaseToolBinding::enabled);
        assertThat(source.releaseToolBindings()).containsExactlyInAnyOrderElementsOf(storedBindings);
        assertThat(source.releaseToolBindings()).extracting(ReleaseToolBinding::toolName)
                .doesNotContain("LOAN_DECISION_UPDATE");
        var expectedTrustPolicy = new ToolTrustPolicy(true, List.of(TrustLevel.TRUSTED_INTERNAL));
        assertThat(source.toolTrustPolicy()).isEqualTo(expectedTrustPolicy);
        assertThatThrownBy(() -> source.releaseToolBindings().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> source.toolTrustPolicy().allowedTrustLevels().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        Baseline afterSource = baseline(seed.releaseId());
        List<Integer> callsBeforeAssembly = ownerInvocationCounts();
        assertDeclaredToolAssembly(source, expectedDeclarations);
        assertThat(ownerInvocationCounts()).isEqualTo(callsBeforeAssembly);
        assertUnchanged(afterSource, seed.releaseId(), 0);
        String proofFingerprint = seed.approved().validation().at("/sourceBinding/releaseFingerprint").stringValue();
        assertThat(proofFingerprint).isEqualTo(seed.preApprovalFingerprint());
        assertThat(source.catalog().releaseFingerprint()).isNotEqualTo(proofFingerprint);
        assertThat(source.catalog().releaseFingerprint()).isEqualTo(releases.find(seed.releaseId()).releaseFingerprint());
        assertThat(source.toString()).doesNotContain(SESSION, PROMPT, STORED, RAW_ERROR);
        assertThat(source.policy().toString()).doesNotContain(SESSION, PROMPT, STORED, RAW_ERROR);
        assertThat(output.getAll()).doesNotContain(SESSION, PROMPT, STORED, RAW_ERROR);
        ((ObjectNode) source.policy()).put("purpose", "FORGED");
        ((ArrayNode) source.policy().path("allowedTools")).removeAll();
        ObjectNode policyCopy = (ObjectNode) source.policy();
        ((ObjectNode) policyCopy.path("toolTrust")).put("requireTrustedTool", false);
        ((ArrayNode) policyCopy.at("/toolTrust/allowedTrustLevels")).removeAll().add("SANDBOXED");
        assertThat(source.toolTrustPolicy()).isEqualTo(expectedTrustPolicy);
        assertThat(source.releaseToolBindings()).containsExactlyInAnyOrderElementsOf(storedBindings);
        assertSource(source, seed, mode);
        assertUnchanged(before, seed.releaseId(), 2);
        assertNoAmbientTransaction();
        assertThat(canAcquireReleaseLock(seed.releaseId())).isTrue();
    }

    @Test
    void baselineIsRejectedBeforeApprovalCaseAndCatalogReads() throws Exception {
        Seed seed = seed(TestRunMode.BASELINE);
        Baseline before = baseline(seed.releaseId());
        clearOwnerInvocations();

        assertThatThrownBy(() -> sources.load(seed.runId(), seed.caseRunId(), REVIEWER))
                .isInstanceOfSatisfying(PolicySourceException.class,
                        failure -> assertSafeFailure(failure, FailureCode.UNSUPPORTED_RUN_MODE));

        verify(runs).find(seed.runId());
        verify(contracts, never()).approved(any(), any(), any());
        assertNoCaseOrCatalogRead();
        assertUnchanged(before, seed.releaseId(), 0);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void anotherRunsCaseIsRejectedAfterAuthorizedApprovalWithoutCatalogRead(boolean foreignRelease)
            throws Exception {
        Seed seed = seed(TestRunMode.SEAL_REPLAY);
        UUID otherCaseRun = foreignRelease ? seed(TestRunMode.SEAL_REPLAY).caseRunId()
                : registerRun(seed.releaseId(), seed.suiteId(), seed.testCaseId(), seed.approved().id(),
                        TestRunMode.REGRESSION).caseRunId();
        Baseline before = baseline(seed.releaseId());
        clearOwnerInvocations();

        assertThatThrownBy(() -> sources.load(seed.runId(), otherCaseRun, REVIEWER))
                .isInstanceOfSatisfying(PolicySourceException.class,
                        failure -> assertSafeFailure(failure, FailureCode.CASE_RUN_BINDING_INVALID));

        verify(contracts).approved(seed.releaseId(), seed.approved().id(), REVIEWER);
        verify(cases).findCase(otherCaseRun);
        verify(catalogs, never()).load(any(), any());
        verify(validator, never()).validate(any(), any());
        assertUnchanged(before, seed.releaseId(), 1);
        assertThat(canAcquireReleaseLock(seed.releaseId())).isTrue();
    }

    @Test
    void actualOwnerRejectsForeignWorkspaceBeforeCaseAndCatalogDisclosure(CapturedOutput output) throws Exception {
        Seed seed = seed(TestRunMode.SEAL_REPLAY);
        ReviewerContext foreign = new ReviewerContext(UUID.randomUUID(), ACTOR, REVIEWER.role(), SESSION,
                true, true, false);
        Baseline before = baseline(seed.releaseId());
        clearOwnerInvocations();

        assertThatThrownBy(() -> sources.load(seed.runId(), seed.caseRunId(), foreign))
                .isInstanceOfSatisfying(BusinessException.class, failure -> {
                    assertThat(failure.errorCode()).isEqualTo(ErrorCode.OPERATOR_AUTH_REQUIRED);
                    assertSafeException(failure);
                });

        verify(contracts).approved(seed.releaseId(), seed.approved().id(), foreign);
        assertNoCaseOrCatalogRead();
        assertUnchanged(before, seed.releaseId(), 0);
        assertThat(canAcquireReleaseLock(seed.releaseId())).isTrue();
        assertThat(output.getAll()).doesNotContain(SESSION, PROMPT, STORED, RAW_ERROR);
    }

    @Test
    void olderStoredApprovalCannotAuthorizeTheRunAfterANewerApproval() throws Exception {
        Seed seed = seed(TestRunMode.SEAL_REPLAY);
        Version validated = nextValidated(seed);
        Version newer = contracts.approve(validated.id(), etag(validated), "Reviewed replacement", REVIEWER);
        assertThat(contracts.find(seed.approved().id(), REVIEWER).state()).isEqualTo("APPROVED");
        assertThat(newer.policyHash()).isNotEqualTo(seed.approved().policyHash());
        Baseline before = baseline(seed.releaseId());
        clearOwnerInvocations();

        assertThatThrownBy(() -> sources.load(seed.runId(), seed.caseRunId(), REVIEWER))
                .isInstanceOfSatisfying(BusinessException.class, failure -> {
                    assertThat(failure.errorCode()).isEqualTo(ErrorCode.RELEASE_CHANGED);
                    assertSafeException(failure);
                });

        assertNoCaseOrCatalogRead();
        assertUnchanged(before, seed.releaseId(), 0);
        assertThat(canAcquireReleaseLock(seed.releaseId())).isTrue();
    }

    @Test
    void postgresPreventsApprovedPolicyAndEvidenceMutationWithoutClaimingReaderTamperDetection() throws Exception {
        Seed seed = seed(TestRunMode.SEAL_REPLAY);
        Baseline before = baseline(seed.releaseId());
        clearOwnerInvocations();

        assertThatThrownBy(() -> jdbc.update("update safety_contract_versions set policy_json='{}'::jsonb where id=?",
                seed.approved().id())).hasMessageContaining("immutable");
        assertThatThrownBy(() -> jdbc.update("update contract_version_evidence set review_json='{}'::jsonb where version_id=?",
                seed.approved().id())).hasMessageContaining("immutable");

        assertUnchanged(before, seed.releaseId(), 0);
        verify(runs, never()).find(any());
        verify(contracts, never()).approved(any(), any(), any());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("incompatibleTransactions")
    void incompatibleActualOuterTransactionsStopBeforeEveryOwnerRead(String description, int isolation,
            boolean readOnly) throws Exception {
        Seed seed = seed(TestRunMode.SEAL_REPLAY);
        TransactionTemplate outer = new TransactionTemplate(transactions);
        outer.setIsolationLevel(isolation);
        outer.setReadOnly(readOnly);
        Baseline before = baseline(seed.releaseId());
        clearOwnerInvocations();

        assertThatThrownBy(() -> outer.executeWithoutResult(status ->
                sources.load(seed.runId(), seed.caseRunId(), REVIEWER)))
                .isInstanceOfSatisfying(PolicySourceException.class,
                        failure -> assertSafeFailure(failure, FailureCode.UNSAFE_TRANSACTION));

        verify(runs, never()).find(any());
        verify(contracts, never()).approved(any(), any(), any());
        assertNoCaseOrCatalogRead();
        assertUnchanged(before, seed.releaseId(), 0);
        assertNoAmbientTransaction();
        assertThat(canAcquireReleaseLock(seed.releaseId())).isTrue();
    }

    @Test
    void approvalCommittedBetweenRunAndApprovalReadCausesSafeFailureAndFreshOldRunRejection(CapturedOutput output)
            throws Exception {
        Seed seed = seed(TestRunMode.SEAL_REPLAY);
        Version validated = nextValidated(seed);
        String originalFingerprint = releases.find(seed.releaseId()).releaseFingerprint();
        CountDownLatch runRead = new CountDownLatch(1);
        CountDownLatch continueReader = new CountDownLatch(1);
        AtomicBoolean first = new AtomicBoolean(true);
        AtomicReference<PhysicalTransaction> readerTransaction = new AtomicReference<>();
        doAnswer(invocation -> {
            if (first.compareAndSet(true, false)) {
                readerTransaction.set(physicalTransaction());
                Object result = invocation.callRealMethod();
                runRead.countDown();
                awaitLatch(continueReader);
                return result;
            }
            return invocation.callRealMethod();
        }).when(runs).find(seed.runId());
        clearOwnerInvocations();
        var executor = Executors.newSingleThreadExecutor();
        try {
            var reader = executor.submit(() -> catchThrowable(() ->
                    sources.load(seed.runId(), seed.caseRunId(), REVIEWER)));
            assertThat(runRead.await(8, TimeUnit.SECONDS)).isTrue();
            // The first reader has a physical RR snapshot but has not acquired the Release lock.
            Version newer = contracts.approve(validated.id(), etag(validated), "Concurrent reviewed replacement", REVIEWER);
            assertThat(newer.state()).isEqualTo("APPROVED");
            assertThat(releases.find(seed.releaseId()).releaseFingerprint())
                    .isNotEqualTo(originalFingerprint);
            Baseline afterWriter = baseline(seed.releaseId());
            clearOwnerInvocations();
            continueReader.countDown();

            assertThat(reader.get(8, TimeUnit.SECONDS)).isInstanceOfSatisfying(PolicySourceException.class,
                    failure -> assertSafeFailure(failure, FailureCode.SOURCE_UNAVAILABLE));

            assertPhysicalTransaction(readerTransaction.get());
            assertNoCaseOrCatalogRead();
            assertUnchanged(afterWriter, seed.releaseId(), 0);
            assertThat(canAcquireReleaseLock(seed.releaseId())).isTrue();
            assertThatThrownBy(() -> sources.load(seed.runId(), seed.caseRunId(), REVIEWER))
                    .isInstanceOfSatisfying(BusinessException.class, failure -> {
                        assertThat(failure.errorCode()).isEqualTo(ErrorCode.RELEASE_CHANGED);
                        assertSafeException(failure);
                    });
            assertUnchanged(afterWriter, seed.releaseId(), 0);
            assertThat(output.getAll()).doesNotContain(SESSION, PROMPT, STORED, RAW_ERROR);
        } finally {
            continueReader.countDown();
            executor.shutdownNow();
            assertThat(executor.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void releaseLockCoversFinalAssemblyAndReleasesOnSuccessOrFailure(boolean failAssembly, CapturedOutput output)
            throws Exception {
        Seed seed = seed(TestRunMode.SEAL_REPLAY);
        CountDownLatch assembling = new CountDownLatch(1);
        CountDownLatch finishAssembly = new CountDownLatch(1);
        finalCanonicalization(() -> {
            assembling.countDown();
            awaitLatch(finishAssembly);
            if (failAssembly) throw rawFailure();
        });
        Baseline before = baseline(seed.releaseId());
        clearOwnerInvocations();
        AtomicReference<ApprovedPolicySource> returned = new AtomicReference<>();
        var executor = Executors.newSingleThreadExecutor();
        try {
            var reader = executor.submit(() -> catchThrowable(() ->
                    returned.set(sources.load(seed.runId(), seed.caseRunId(), REVIEWER))));
            assertThat(assembling.await(8, TimeUnit.SECONDS)).isTrue();
            assertThat(canAcquireReleaseLock(seed.releaseId())).isFalse();
            finishAssembly.countDown();

            Throwable failure = reader.get(8, TimeUnit.SECONDS);
            if (failAssembly) {
                assertThat(failure).isInstanceOfSatisfying(PolicySourceException.class,
                        error -> assertSafeFailure(error, FailureCode.SOURCE_UNAVAILABLE));
                assertThat(returned.get()).isNull();
            } else {
                assertThat(failure).isNull();
                assertSource(returned.get(), seed, TestRunMode.SEAL_REPLAY);
            }
            assertThat(canAcquireReleaseLock(seed.releaseId())).isTrue();
            assertUnchanged(before, seed.releaseId(), 2);
            assertThat(output.getAll()).doesNotContain(SESSION, PROMPT, STORED, RAW_ERROR);
        } finally {
            finishAssembly.countDown();
            executor.shutdownNow();
            assertThat(executor.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void synchronizationOnlyOuterContextGetsOwnWritableSnapshotAndRestoresSynchronization(
            boolean failAssembly, CapturedOutput output)
            throws Exception {
        Seed seed = seed(TestRunMode.SEAL_REPLAY);
        AtomicReference<PhysicalTransaction> ownerEntry = new AtomicReference<>();
        doAnswer(invocation -> {
            ownerEntry.set(physicalTransaction());
            return invocation.callRealMethod();
        }).when(runs).find(seed.runId());
        if (failAssembly) finalCanonicalization(() -> { throw rawFailure(); });
        TransactionTemplate outer = new TransactionTemplate(transactions);
        outer.setPropagationBehavior(TransactionDefinition.PROPAGATION_SUPPORTS);
        AtomicInteger completions = new AtomicInteger();
        TransactionSynchronization marker = new TransactionSynchronization() {
            @Override public void afterCompletion(int status) {
                assertThat(status).isEqualTo(STATUS_COMMITTED);
                completions.incrementAndGet();
            }
        };
        Baseline before = baseline(seed.releaseId());
        clearOwnerInvocations();

        outer.executeWithoutResult(status -> {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isTrue();
            TransactionSynchronizationManager.registerSynchronization(marker);
            if (failAssembly) {
                assertThatThrownBy(() -> sources.load(seed.runId(), seed.caseRunId(), REVIEWER))
                        .isInstanceOfSatisfying(PolicySourceException.class,
                                failure -> assertSafeFailure(failure, FailureCode.SOURCE_UNAVAILABLE));
            } else {
                assertSource(sources.load(seed.runId(), seed.caseRunId(), REVIEWER), seed, TestRunMode.SEAL_REPLAY);
            }
            assertPhysicalTransaction(ownerEntry.get());
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isTrue();
            assertThat(TransactionSynchronizationManager.getSynchronizations()).contains(marker);
            assertThat(completions).hasValue(0);
            assertThat(canAcquireReleaseLock(seed.releaseId())).isTrue();
        });

        assertThat(completions).hasValue(1);
        assertNoAmbientTransaction();
        assertUnchanged(before, seed.releaseId(), 2);
        assertThat(canAcquireReleaseLock(seed.releaseId())).isTrue();
        assertThat(output.getAll()).doesNotContain(SESSION, PROMPT, STORED, RAW_ERROR);
    }

    @Test
    void compatibleActualOuterTransactionRetainsReleaseLockUntilOuterCompletion() throws Exception {
        Seed seed = seed(TestRunMode.SEAL_REPLAY);
        TransactionTemplate outer = new TransactionTemplate(transactions);
        outer.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        Baseline before = baseline(seed.releaseId());
        clearOwnerInvocations();

        outer.executeWithoutResult(status -> {
            assertSource(sources.load(seed.runId(), seed.caseRunId(), REVIEWER), seed, TestRunMode.SEAL_REPLAY);
            assertPhysicalTransaction(physicalTransaction());
            assertThat(canAcquireReleaseLock(seed.releaseId())).isFalse();
        });

        assertNoAmbientTransaction();
        assertThat(canAcquireReleaseLock(seed.releaseId())).isTrue();
        assertUnchanged(before, seed.releaseId(), 2);
    }

    private Seed seed(TestRunMode mode) throws Exception {
        String key = "gateway-source-" + UUID.randomUUID();
        var agent = agents.create(new AgentDto.CreateRequest(key, "Gateway source fixture", "Document review"));
        ObjectNode manifest;
        try (var stream = getClass().getResourceAsStream("/fixtures/valid-release-manifest-v1.1.json")) {
            manifest = (ObjectNode) mapper.readTree(stream);
        }
        ((ObjectNode) manifest.path("agent")).put("id", key);
        ((ObjectNode) manifest.path("systemPrompt")).put("text", PROMPT);
        UUID releaseId = releases.create(agent.id(), manifest, ACTOR).id();
        releases.analyze(releaseId, ACTOR);
        jdbc.update("update agent_releases set lifecycle_state='REMEDIATION',effective_status='REMEDIATION' where id=?", releaseId);
        String preApproval = releases.find(releaseId).releaseFingerprint();
        Version candidate = contracts.create(releaseId, policy(1), REVIEWER);
        Version validated = contracts.validate(candidate.id(), etag(candidate), REVIEWER);
        Version approved = contracts.approve(validated.id(), etag(validated), "Reviewed source policy", REVIEWER);
        UUID suiteId = UUID.randomUUID();
        UUID caseId = UUID.randomUUID();
        jdbc.update("""
                insert into test_suites(id,workspace_id,suite_key,version,fixture_version,generation_config_json,suite_hash,status)
                values(?,?,?,'1.0','gateway-source-v1','{}'::jsonb,?,'BUILDING')
                """, suiteId, AgentService.DEMO_WORKSPACE_ID, "gateway-suite-" + UUID.randomUUID(), HASH);
        jdbc.update("""
                insert into test_cases(id,suite_id,case_key,case_type,partition_name,category,severity,delivery_channel,
                    payload_hash,preconditions_json,expected_invariant,oracle_type,generation_source,expected_result_json,trial_policy_json)
                values(?,?,'normal-1','NORMAL','NORMAL','NORMAL','LOW','DIRECT',?,'{}'::jsonb,
                    'INV-NORMAL','NORMAL_TASK','CURATED','{}'::jsonb,'{}'::jsonb)
                """, caseId, suiteId, HASH);
        jdbc.update("update test_suites set status='READY' where id=?", suiteId);
        Registered registered = registerRun(releaseId, suiteId, caseId, mode == TestRunMode.BASELINE ? null : approved.id(), mode);
        // Legal nonterminal fixture fields; immutable identity/policy guards remain enabled.
        String privateData = mapper.createObjectNode().put("private", STORED).toString();
        jdbc.update("update test_runs set summary_json=?::jsonb where id=?", privateData, registered.runId());
        jdbc.update("update test_case_runs set result_json=?::jsonb where id=?", privateData, registered.caseRunId());
        return new Seed(releaseId, suiteId, caseId, registered.runId(), registered.caseRunId(), approved, preApproval);
    }

    private Registered registerRun(UUID releaseId, UUID suiteId, UUID caseId, UUID contractId, TestRunMode mode) {
        UUID runId = cases.register(new TestRunPersistenceDto.RegisterRequest(releaseId, suiteId, contractId, mode,
                UUID.randomUUID(), mapper.createObjectNode(), HASH, HASH, 42L, 1), ACTOR).runId();
        UUID caseRunId = cases.registerCase(runId, new TestRunPersistenceDto.CaseRunRegisterRequest(caseId, 0, HASH), ACTOR).id();
        return new Registered(runId, caseRunId);
    }

    private Version nextValidated(Seed seed) throws Exception {
        jdbc.update("update agent_releases set lifecycle_state='REMEDIATION',effective_status='REMEDIATION' where id=?", seed.releaseId());
        Version candidate = contracts.create(seed.releaseId(), policy(2), REVIEWER);
        assertThatThrownBy(() -> contracts.validate(candidate.id(), etag(candidate), REVIEWER))
                .isInstanceOfSatisfying(BusinessException.class, failure -> {
                    assertThat(failure.errorCode()).isEqualTo(ErrorCode.RESOURCE_CONFLICT);
                    assertThat(failure.getMessage()).contains("Finish active runs");
                });
        // Respect A's active-Run guard. Superseding approval is exercised only after legal closure.
        UUID trace = UUID.randomUUID();
        for (ExecutionEventType type : List.of(ExecutionEventType.RUN_STARTED, ExecutionEventType.RUN_CANCEL_REQUESTED)) {
            events.append(seed.runId(), new ExecutionEventDto.AppendRequest(
                    null, trace, type, null, null, null, null, type.name(), mapper.createObjectNode()), ACTOR);
        }
        cases.updateCaseStatus(seed.runId(), seed.caseRunId(), new TestRunPersistenceDto.CaseRunStatusRequest(
                TestCaseRunStatus.CANCELLED, null, null, null, null, null, null), ACTOR);
        cases.updateStatus(seed.runId(), new TestRunPersistenceDto.StatusRequest(TestRunStatus.CANCELLED, 1, 0, null), ACTOR);
        assertThat(cases.findCase(seed.caseRunId()).status()).isEqualTo(TestCaseRunStatus.CANCELLED);
        assertThat(runs.find(seed.runId()).status()).isEqualTo(TestRunStatus.CANCELLED);
        return contracts.validate(candidate.id(), etag(candidate), REVIEWER);
    }

    private ObjectNode policy(int version) throws Exception {
        try (var stream = getClass().getResourceAsStream("/fixtures/loan-review-safety-contract.json")) {
            return ((ObjectNode) mapper.readTree(stream)).put("contractId", "gateway-source-policy").put("version", version);
        }
    }

    private String etag(Version version) { return '"' + version.resourceHash() + '"'; }

    private List<ReleaseToolBinding> storedReleaseBindings(UUID releaseId) {
        return jdbc.query("select d.tool_key, d.version, r.enabled, d.schema_hash, d.description_hash "
                        + "from release_tools r join tool_definitions d on d.id=r.tool_definition_id "
                        + "where r.release_id=? order by d.tool_key, d.version",
                (row, index) -> new ReleaseToolBinding(row.getString("tool_key"), row.getString("version"),
                        row.getBoolean("enabled"), row.getString("schema_hash"), row.getString("description_hash")),
                releaseId);
    }

    private List<CatalogTool> expectedDeclaredTools(UUID releaseId) throws Exception {
        List<CatalogTool> expected = new ArrayList<>(jdbc.query(
                "select d.tool_key, d.operation, d.side_effect_type from release_tools r "
                        + "join tool_definitions d on d.id=r.tool_definition_id "
                        + "where r.release_id=? and r.enabled=true order by d.tool_key",
                (row, index) -> {
                    assertThat(row.getString("side_effect_type")).isIn("NONE", "INTERNAL_WRITE");
                    return new CatalogTool(row.getString("tool_key"), row.getString("operation"), false);
                }, releaseId));
        assertThat(expected).hasSize(5);
        JsonNode serverCatalog;
        try (var stream = getClass().getResourceAsStream("/release/loan-review-tool-catalog-1.1.json")) {
            serverCatalog = mapper.readTree(stream).path("serverToolCatalog");
        }
        assertThat(serverCatalog.path("version").stringValue()).isEqualTo("loan-review-server/1.0");
        assertThat(serverCatalog.path("tools").size()).isEqualTo(1);
        JsonNode humanTool = serverCatalog.path("tools").get(0);
        assertThat(humanTool.path("name").stringValue()).isEqualTo("LOAN_DECISION_UPDATE");
        assertThat(humanTool.path("version").stringValue()).isEqualTo("1.0.0");
        assertThat(humanTool.path("operation").stringValue()).isEqualTo("UPDATE");
        assertThat(humanTool.path("sideEffectType").stringValue()).isEqualTo("HIGH_IMPACT_WRITE");
        assertThat(humanTool.path("agentExecutable").booleanValue()).isFalse();
        assertThat(humanTool.path("executionBoundary").stringValue()).isEqualTo("HUMAN_ONLY");
        expected.add(new CatalogTool(humanTool.path("name").stringValue(),
                humanTool.path("operation").stringValue(), false));
        return List.copyOf(expected);
    }

    private void assertDeclaredToolAssembly(ApprovedPolicySource source, List<CatalogTool> expectedDeclarations) {
        assertThat(source.catalog().declaredTools()).containsExactlyInAnyOrderElementsOf(expectedDeclarations);
        assertThatThrownBy(() -> source.catalog().declaredTools().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        var authorization = new PolicyToolAuthorizationEvaluator();
        // These operations are independent caller inputs, not observations of a B invocation.
        var read = assembler.toolAuthorization(source, "CUSTOMER_DATA_READ", "READ");
        assertThat(read.catalogTools()).containsExactlyInAnyOrderElementsOf(expectedDeclarations);
        assertThat(authorization.evaluate(TOOL, read)).isEqualTo(StageOutcome.pass(TOOL));
        assertThat(authorization.evaluate(OPERATION, read)).isEqualTo(StageOutcome.pass(OPERATION));
        var write = assembler.toolAuthorization(source, "CUSTOMER_DATA_READ", "WRITE");
        assertThat(write.requestedOperation()).isEqualTo("WRITE");
        assertThat(authorization.evaluate(OPERATION, write))
                .isEqualTo(StageOutcome.deny(OPERATION, OPERATION_NOT_ALLOWED));
        var unknown = assembler.toolAuthorization(source, "UNKNOWN_TOOL", "READ");
        assertThat(unknown.requestedCatalogTool()).isEmpty();
        assertThat(authorization.evaluate(TOOL, unknown))
                .isEqualTo(StageOutcome.deny(TOOL, TOOL_NOT_ALLOWED));
        var human = assembler.toolAuthorization(source, "LOAN_DECISION_UPDATE", "UPDATE");
        assertThat(human.allowedTools()).doesNotContain("LOAN_DECISION_UPDATE");
        assertThat(human.humanOnlyTools()).contains("LOAN_DECISION_UPDATE");
        assertThat(authorization.evaluate(TOOL, human)).isEqualTo(StageOutcome.pass(TOOL));
        assertThat(new PolicyHumanBoundaryEvaluator().evaluate(HUMAN_BOUNDARY,
                assembler.humanBoundary(source, "LOAN_DECISION_UPDATE")))
                .isEqualTo(StageOutcome.deny(HUMAN_BOUNDARY, HUMAN_ONLY_ACTION));
        var egress = assembler.egress(source, "CUSTOMER_DATA_READ");
        assertThat(egress.externalEgressAllowed()).isFalse();
        assertThat(egress.allowedDestinations()).isEmpty();
        assertThat(egress.requestedCatalogTool().orElseThrow().egressClassification())
                .isEqualTo(PolicyEgressFacts.EgressClassification.INTERNAL);
        var egressEvaluator = new PolicyEgressEvaluator();
        assertThat(egressEvaluator.evaluate(EGRESS, egress)).isEqualTo(StageOutcome.pass(EGRESS));
        var unknownEgress = assembler.egress(source, "UNKNOWN_TOOL");
        assertThat(unknownEgress.requestedCatalogTool()).isEmpty();
        assertThatThrownBy(() -> egressEvaluator.evaluate(EGRESS, unknownEgress))
                .isInstanceOf(IllegalStateException.class);
    }

    private List<Integer> ownerInvocationCounts() {
        return List.of(runs, contracts, cases, catalogs, validator, canonicalizer).stream()
                .map(owner -> mockingDetails(owner).getInvocations().size()).toList();
    }

    private void assertSource(ApprovedPolicySource source, Seed seed, TestRunMode mode) {
        assertThat(source).isNotNull();
        assertThat(source.runId()).isEqualTo(seed.runId());
        assertThat(source.testCaseRunId()).isEqualTo(seed.caseRunId());
        assertThat(source.testCaseId()).isEqualTo(seed.testCaseId());
        assertThat(source.runMode()).isEqualTo(mode);
        assertThat(source.runStatus()).isEqualTo(TestRunStatus.QUEUED);
        assertThat(source.caseStatus()).isEqualTo(TestCaseRunStatus.PENDING);
        assertThat(source.trialIndex()).isZero();
        assertThat(source.variantHash()).isEqualTo(HASH);
        assertThat(source.identity()).isEqualTo(new VersionIdentity(seed.approved().id(), AgentService.DEMO_WORKSPACE_ID,
                seed.releaseId(), seed.approved().contractKey(), seed.approved().version()));
        assertThat(source.resourceHash()).isEqualTo(seed.approved().resourceHash());
        assertThat(source.policyHash()).isEqualTo(seed.approved().policyHash());
        assertThat(source.policy()).isEqualTo(seed.approved().policy());
        assertThat(source.catalog().releaseId()).isEqualTo(seed.releaseId());
        assertThat(source.validation().status()).isEqualTo(ValidationStatus.VALID);
        assertThat(source.validation().issues()).isEmpty();
        assertThat(source.canonicalPolicy().policyHash()).isEqualTo(seed.approved().policyHash());
        assertThat(mapper.readTree(source.canonicalPolicy().canonicalJson())).isEqualTo(source.policy());
    }

    private void finalCanonicalization(AssemblyHook hook) {
        AtomicBoolean catalogReturned = new AtomicBoolean();
        doAnswer(invocation -> {
            Object result = invocation.callRealMethod();
            catalogReturned.set(true);
            return result;
        }).when(catalogs).load(any(), any());
        doAnswer(invocation -> {
            // A also canonicalizes while checking stored integrity; pause only C's final assembly.
            if (catalogReturned.compareAndSet(true, false)) hook.run();
            return invocation.callRealMethod();
        }).when(canonicalizer).canonicalizeAndHash(any());
    }

    private RuntimeException rawFailure() {
        var failure = new IllegalStateException(RAW_ERROR, new IllegalArgumentException(PROMPT));
        failure.addSuppressed(new IllegalStateException(SESSION));
        return failure;
    }

    private void awaitLatch(CountDownLatch latch) throws InterruptedException {
        if (!latch.await(8, TimeUnit.SECONDS)) throw new IllegalStateException("Source test synchronization timed out");
    }

    private boolean canAcquireReleaseLock(UUID releaseId) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try (var query = connection.prepareStatement("select id from agent_releases where id=? for update nowait")) {
                query.setObject(1, releaseId);
                try (var rows = query.executeQuery()) {
                    assertThat(rows.next()).isTrue();
                    assertThat(rows.getObject(1, UUID.class)).isEqualTo(releaseId);
                }
                connection.commit();
                return true;
            } catch (SQLException failure) {
                connection.rollback();
                if ("55P03".equals(failure.getSQLState())) return false;
                throw failure;
            }
        } catch (SQLException failure) {
            throw new IllegalStateException("Independent Release lock probe failed", failure);
        }
    }

    private PhysicalTransaction physicalTransaction() {
        return new PhysicalTransaction(jdbc.queryForObject("select current_setting('transaction_isolation')", String.class),
                jdbc.queryForObject("select current_setting('transaction_read_only')", String.class),
                TransactionSynchronizationManager.isActualTransactionActive(),
                TransactionSynchronizationManager.isCurrentTransactionReadOnly(),
                TransactionSynchronizationManager.getCurrentTransactionIsolationLevel());
    }

    private void assertPhysicalTransaction(PhysicalTransaction observed) {
        assertThat(observed).isEqualTo(new PhysicalTransaction("repeatable read", "off", true, false,
                TransactionDefinition.ISOLATION_REPEATABLE_READ));
    }

    private void assertNoAmbientTransaction() {
        assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
        assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isFalse();
        assertThat(TransactionSynchronizationManager.hasResource(dataSource)).isFalse();
    }

    private void clearOwnerInvocations() { clearInvocations(runs, contracts, cases, catalogs, validator, canonicalizer); }

    private void assertNoCaseOrCatalogRead() {
        verify(cases, never()).findCase(any());
        verify(catalogs, never()).load(any(), any());
        verify(validator, never()).validate(any(), any());
    }

    private void assertNoWrites() {
        verify(contracts, never()).create(any(), any(), any());
        verify(contracts, never()).validate(any(), any(), any());
        verify(contracts, never()).approve(any(), any(), any(), any());
        verify(contracts, never()).approve(any(), any(), any(), any(), any());
        verify(contracts, never()).reject(any(), any(), any(), any());
        verify(contracts, never()).storePatch(any(), any(), any(), any());
        verify(cases, never()).register(any(), any());
        verify(cases, never()).registerCase(any(), any(), any());
        verify(cases, never()).updateStatus(any(), any(), any());
        verify(cases, never()).updateCaseStatus(any(), any(), any(), any());
    }

    private Baseline baseline(UUID releaseId) {
        return new Baseline(domainSnapshot(), otherAuditSnapshot(releaseId), accessAudits(releaseId));
    }

    private void assertUnchanged(Baseline before, UUID releaseId, int accessDelta) {
        assertNoWrites();
        assertThat(domainSnapshot()).isEqualTo(before.domain());
        assertThat(otherAuditSnapshot(releaseId)).isEqualTo(before.otherAudits());
        List<JsonNode> current = accessAudits(releaseId);
        assertThat(current).hasSize(before.accessAudits().size() + accessDelta);
        assertThat(current).containsAll(before.accessAudits());
        var added = current.stream().filter(row -> !before.accessAudits().contains(row)).toList();
        if (accessDelta == 2) {
            assertThat(added).extracting(row -> row.at("/metadata_json/purpose").stringValue())
                    .containsExactlyInAnyOrder("FINGERPRINT_INTEGRITY_CHECK", "TOOL_CATALOG_INTEGRITY_CHECK");
        }
        for (JsonNode row : added) {
            assertThat(row.path("actor_id").stringValue()).isEqualTo(ACTOR);
            assertThat(row.at("/metadata_json/plaintextReturned").booleanValue()).isFalse();
            assertThat(row.toString()).doesNotContain(SESSION, PROMPT, STORED, RAW_ERROR);
        }
        assertThat(jdbc.queryForObject("select count(*) from execution_events where event_type='TOOL_REQUEST'", Integer.class)).isZero();
    }

    private Map<String, String> domainSnapshot() {
        Map<String, String> result = new LinkedHashMap<>();
        for (String table : DOMAIN_TABLES) {
            String key = table.equals("contract_version_evidence") ? "version_id"
                    : table.equals("run_event_counters") ? "run_id" : "id";
            result.put(table, jdbc.queryForObject("select coalesce(jsonb_agg(to_jsonb(t) order by " + key
                    + ")::text, '[]') from " + table + " t", String.class));
        }
        return result;
    }

    private String otherAuditSnapshot(UUID releaseId) {
        return jdbc.queryForObject("select coalesce(jsonb_agg(to_jsonb(t) order by id)::text, '[]') from audit_records t "
                        + "where (actor_id=? and resource_id=? and action='SYSTEM_PROMPT_DECRYPTED_INTERNAL') is not true",
                String.class, ACTOR, releaseId);
    }

    private List<JsonNode> accessAudits(UUID releaseId) {
        return jdbc.query("select to_jsonb(t)::text from audit_records t where actor_id=? and resource_id=? "
                        + "and action='SYSTEM_PROMPT_DECRYPTED_INTERNAL' order by id",
                (row, index) -> mapper.readTree(row.getString(1)), ACTOR, releaseId);
    }

    private void assertSafeFailure(PolicySourceException failure, FailureCode expected) {
        assertThat(failure.code()).isEqualTo(expected);
        assertSafeException(failure);
    }

    private void assertSafeException(RuntimeException failure) {
        assertThat(failure.getCause()).isNull();
        assertThat(failure.getSuppressed()).isEmpty();
        StringWriter rendered = new StringWriter();
        failure.printStackTrace(new PrintWriter(rendered));
        assertThat(rendered.toString()).doesNotContain(SESSION, PROMPT, STORED, RAW_ERROR);
    }

    private static Stream<Arguments> incompatibleTransactions() {
        return Stream.of(
                Arguments.of("read-only REPEATABLE_READ", TransactionDefinition.ISOLATION_REPEATABLE_READ, true),
                Arguments.of("writable READ_COMMITTED", TransactionDefinition.ISOLATION_READ_COMMITTED, false),
                Arguments.of("read-only READ_COMMITTED", TransactionDefinition.ISOLATION_READ_COMMITTED, true),
                Arguments.of("writable default isolation", TransactionDefinition.ISOLATION_DEFAULT, false));
    }

    @FunctionalInterface
    private interface AssemblyHook { void run() throws Exception; }
    private record Seed(UUID releaseId, UUID suiteId, UUID testCaseId, UUID runId, UUID caseRunId,
                        Version approved, String preApprovalFingerprint) {}
    private record Registered(UUID runId, UUID caseRunId) {}
    private record Baseline(Map<String, String> domain, String otherAudits, List<JsonNode> accessAudits) {}
    private record PhysicalTransaction(String isolation, String readOnly, boolean active,
                                       boolean metadataReadOnly, Integer metadataIsolation) {}
}
