package com.finsecseal.contract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionIdentity;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionState;
import com.finsecseal.contract.SafetyContractReviewDiff.ChangeKind;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationStatus;
import com.finsecseal.contract.StoredSafetyContractReviewService.ReviewException;
import com.finsecseal.contract.StoredSafetyContractReviewService.ReviewView;
import com.finsecseal.platform.contract.ContractPersistenceService;
import com.finsecseal.platform.contract.ContractPersistenceService.Version;
import com.finsecseal.release.ReleaseService;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.UnexpectedRollbackException;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/** Real stored review evidence; fixture lifecycle setup does not represent B/D execution. */
@Testcontainers
@SpringBootTest(properties = "finsec.scheduling.enabled=false")
class StoredSafetyContractReviewServiceIntegrationTest {
    private static final String ACTOR = "c-stored-review-integration";
    private static final String COMMENT = "Reviewed scope and normal-workflow impact";
    private static final String FAILURE_CANARY = "STORED-REVIEW-SQL-FAILURE-CANARY";
    private static final ReviewerContext REVIEWER = new ReviewerContext(
            AgentService.DEMO_WORKSPACE_ID, ACTOR, "AI_SECURITY_REVIEWER",
            "STORED-REVIEW-PRIVATE-SESSION", true, true, false);
    private static final List<String> SNAPSHOT_TABLES = List.of(
            "agent_releases", "release_artifacts", "safety_contracts", "safety_contract_versions",
            "contract_version_evidence", "audit_records", "api_idempotency_records",
            "patch_proposals", "patch_approvals", "test_runs", "test_case_runs", "execution_events",
            "findings", "oracle_results", "replay_links", "release_decisions", "evidence_references");

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired StoredSafetyContractReviewService reviews;
    @MockitoSpyBean ContractPersistenceService contracts;
    @Autowired SafetyContractCanonicalizer canonicalizer;
    @Autowired AgentService agents;
    @Autowired ReleaseService releases;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate jdbc;
    @Autowired PlatformTransactionManager transactions;

    // No test-managed transaction: the actual Spring service proxy must establish its boundary.
    @Test
    void initialCandidateUsesPhysicalReadOnlyRepeatableReadAndDoesNotInventABaseline() throws Exception {
        Version candidate = contracts.create(release(), policy(1), REVIEWER);
        assertThat(candidate.basePolicyHash()).isNull();
        AtomicReference<PhysicalTransaction> observed = new AtomicReference<>();
        doAnswer(invocation -> {
            Object result = invocation.callRealMethod();
            observed.set(physicalTransaction());
            return result;
        }).when(contracts).find(candidate.id(), REVIEWER);
        Map<String, String> before = databaseSnapshot();
        clearInvocations(contracts);

        ReviewView result = reviews.review(candidate.id(), REVIEWER);

        assertPhysicalReadOnlyRepeatableRead(observed.get());
        assertStoredTarget(result, candidate);
        assertThat(result.state()).isEqualTo(VersionState.CANDIDATE);
        assertThat(result.validation()).isEmpty();
        assertThat(result.review()).isEmpty();
        assertThat(result.baseline()).isEmpty();
        assertThat(result.changes()).singleElement().satisfies(change -> {
            assertThat(change.pointer()).isEmpty();
            assertThat(change.kind()).isEqualTo(ChangeKind.ADDED);
            assertThat(change.beforeJson()).isNull();
            assertThat(mapper.readTree(change.afterJson())).isEqualTo(candidate.policy());
        });
        verify(contracts, never()).list(any(), any());
        verifyNoAuthorityCalls();
        assertThat(databaseSnapshot()).isEqualTo(before);
    }

    @Test
    void historicalApprovedBaselineRemainsReviewableAfterAnotherPolicyBecomesCurrent() throws Exception {
        UUID releaseId = release();
        Version first = approveNext(releaseId, 1);
        Version second = approveNext(releaseId, 2);
        Version third = contracts.create(releaseId, policy(3), REVIEWER);
        assertThat(second.basePolicyHash()).isEqualTo(first.policyHash());
        assertThat(third.basePolicyHash()).isEqualTo(second.policyHash());
        assertThat(releases.find(releaseId).safetyContractHash()).isEqualTo(second.policyHash());
        // A's current-authority API deliberately cannot supply this historical baseline.
        assertThatThrownBy(() -> contracts.approved(releaseId, first.id(), REVIEWER))
                .isInstanceOfSatisfying(BusinessException.class,
                        failure -> assertThat(failure.errorCode()).isEqualTo(ErrorCode.RELEASE_CHANGED));
        Map<String, String> before = databaseSnapshot();
        clearInvocations(contracts);

        ReviewView historical = reviews.review(second.id(), REVIEWER);
        ReviewView candidate = reviews.review(third.id(), REVIEWER);

        assertStoredTarget(historical, second);
        assertThat(historical.state()).isEqualTo(VersionState.APPROVED);
        assertThat(historical.baseline()).get().satisfies(baseline -> {
            assertThat(baseline.identity()).isEqualTo(identity(first));
            assertThat(baseline.policyHash()).isEqualTo(first.policyHash());
        });
        assertThat(historical.validation()).get().satisfies(validation ->
                assertThat(validation.status()).isEqualTo(ValidationStatus.VALID));
        assertThat(historical.review()).get().satisfies(review -> {
            assertThat(review.actorId()).isEqualTo(ACTOR);
            assertThat(review.role()).isEqualTo(REVIEWER.role());
            assertThat(review.comment()).isEqualTo(COMMENT);
            assertThat(review.decision()).isEqualTo("APPROVED");
        });
        assertThat(historical.changes()).singleElement().satisfies(change -> {
            assertThat(change.pointer()).isEqualTo("/version");
            assertThat(change.kind()).isEqualTo(ChangeKind.MODIFIED);
            assertThat(change.beforeJson()).isEqualTo("1");
            assertThat(change.afterJson()).isEqualTo("2");
        });
        assertStoredTarget(candidate, third);
        assertThat(candidate.baseline()).get().satisfies(baseline ->
                assertThat(baseline.identity()).isEqualTo(identity(second)));
        assertThat(candidate.validation()).isEmpty();
        assertThat(mapper.writeValueAsString(historical)).doesNotContain(REVIEWER.sessionId());
        assertThatThrownBy(() -> historical.changes().clear()).isInstanceOf(UnsupportedOperationException.class);
        ((ObjectNode) mapper.readTree(historical.storedPolicyJson())).put("purpose", "LOCAL-ONLY");
        ((ObjectNode) second.policy()).put("purpose", "MUTATED-CALLER-RECORD");
        assertThat(reviews.review(second.id(), REVIEWER)).isEqualTo(historical);
        verifyNoAuthorityCalls();
        assertThat(databaseSnapshot()).isEqualTo(before);
    }

    @Test
    void semanticallyInvalidStoredCandidateDisplaysActualValidationWithoutChangingIt() throws Exception {
        ObjectNode policy = policy(1);
        ((ArrayNode) policy.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed")).add("accountNumber");
        Version candidate = contracts.create(release(), policy, REVIEWER);
        Version invalid = contracts.validate(candidate.id(), etag(candidate), REVIEWER);
        assertThat(invalid.state()).isEqualTo("CANDIDATE");
        Map<String, String> before = databaseSnapshot();
        clearInvocations(contracts);

        ReviewView result = reviews.review(invalid.id(), REVIEWER);

        assertStoredTarget(result, invalid);
        assertThat(result.state()).isEqualTo(VersionState.CANDIDATE);
        assertThat(result.review()).isEmpty();
        assertThat(result.validation()).get().satisfies(validation -> {
            assertThat(validation.status()).isEqualTo(ValidationStatus.INVALID);
            assertThat(validation.issues()).isNotEmpty();
            assertThatThrownBy(() -> validation.issues().clear()).isInstanceOf(UnsupportedOperationException.class);
        });
        assertThat(result.storedPolicyJson()).contains("accountNumber");
        verifyNoAuthorityCalls();
        assertThat(databaseSnapshot()).isEqualTo(before);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("unsafeTransactions")
    void rejectsWeakerOrWritableOuterTransactionBeforeAnyARead(
            String description, int isolation, boolean readOnly
    ) throws Exception {
        Version candidate = contracts.create(release(), policy(1), REVIEWER);
        TransactionTemplate outer = transaction(isolation, readOnly);
        Map<String, String> before = databaseSnapshot();
        clearInvocations(contracts);

        assertThatThrownBy(() -> outer.execute(status -> reviews.review(candidate.id(), REVIEWER)))
                .isInstanceOfSatisfying(ReviewException.class,
                        failure -> assertSafeFailure(failure, "UNSAFE_TRANSACTION"));

        verify(contracts, never()).find(any(), any());
        verify(contracts, never()).list(any(), any());
        verifyNoAuthorityCalls();
        assertThat(databaseSnapshot()).isEqualTo(before);
    }

    @Test
    void preservesASafeWorkspaceDenialAndDoesNotWriteEvidenceOnFailure() throws Exception {
        Version candidate = contracts.create(release(), policy(1), REVIEWER);
        ReviewerContext foreign = new ReviewerContext(UUID.randomUUID(), ACTOR, REVIEWER.role(),
                REVIEWER.sessionId(), true, true, false);
        Map<String, String> before = databaseSnapshot();
        clearInvocations(contracts);

        assertThatThrownBy(() -> reviews.review(candidate.id(), foreign))
                .isInstanceOfSatisfying(BusinessException.class,
                        failure -> assertThat(failure.errorCode()).isEqualTo(ErrorCode.OPERATOR_AUTH_REQUIRED));

        verify(contracts, never()).list(any(), any());
        verifyNoAuthorityCalls();
        assertThat(databaseSnapshot()).isEqualTo(before);
    }

    @Test
    void corruptStoredPolicyFailsAIntegrityVerificationWithoutReviewSideEffects() throws Exception {
        Version candidate = contracts.create(release(), policy(1), REVIEWER);
        // Corrupt only this nonterminal test fixture; no production integrity implementation is bypassed.
        assertThat(jdbc.update("update safety_contract_versions set policy_hash=? where id=?",
                "sha256:" + "f".repeat(64), candidate.id())).isEqualTo(1);
        Map<String, String> before = databaseSnapshot();
        clearInvocations(contracts);

        assertThatThrownBy(() -> reviews.review(candidate.id(), REVIEWER))
                .isInstanceOfSatisfying(BusinessException.class,
                        failure -> assertThat(failure.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE));

        verify(contracts, never()).list(any(), any());
        verifyNoAuthorityCalls();
        assertThat(databaseSnapshot()).isEqualTo(before);
    }

    @Test
    @SuppressWarnings("unchecked")
    void concurrentCommittedValidationCannotMixFindAndListSnapshots() throws Exception {
        UUID releaseId = release();
        Version approved = approveNext(releaseId, 1);
        Version candidate = contracts.create(releaseId, policy(2), REVIEWER);
        CountDownLatch targetRead = new CountDownLatch(1);
        CountDownLatch resumeReview = new CountDownLatch(1);
        AtomicBoolean firstRead = new AtomicBoolean(true);
        AtomicReference<PhysicalTransaction> physical = new AtomicReference<>();
        AtomicReference<List<Version>> observedList = new AtomicReference<>();
        doAnswer(invocation -> {
            Object result = invocation.callRealMethod();
            if (firstRead.compareAndSet(true, false)) {
                physical.set(physicalTransaction());
                targetRead.countDown();
                if (!resumeReview.await(8, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("Review test synchronization timed out");
                }
            }
            return result;
        }).when(contracts).find(candidate.id(), REVIEWER);
        doAnswer(invocation -> {
            List<Version> result = (List<Version>) invocation.callRealMethod();
            observedList.set(result);
            return result;
        }).when(contracts).list(releaseId, REVIEWER);

        try (var executor = Executors.newFixedThreadPool(2)) {
            var reader = executor.submit(() -> reviews.review(candidate.id(), REVIEWER));
            try {
                assertThat(targetRead.await(8, TimeUnit.SECONDS)).isTrue();
                var writer = executor.submit(() -> contracts.validate(candidate.id(), etag(candidate), REVIEWER));
                Version validated = writer.get(8, TimeUnit.SECONDS); // Commit must finish before the reader resumes.
                assertThat(validated.state()).isEqualTo("VALIDATED");
                assertThat(validated.resourceHash()).isNotEqualTo(candidate.resourceHash());
                Map<String, String> afterWriter = databaseSnapshot();
                resumeReview.countDown();
                ReviewView result = reader.get(8, TimeUnit.SECONDS);

                assertPhysicalReadOnlyRepeatableRead(physical.get());
                assertStoredTarget(result, candidate);
                assertThat(result.validation()).isEmpty();
                assertThat(result.baseline()).get().satisfies(baseline ->
                        assertThat(baseline.identity()).isEqualTo(identity(approved)));
                // Checking only the final diff would also pass under READ_COMMITTED.
                assertThat(observedList.get()).filteredOn(version -> version.id().equals(candidate.id()))
                        .singleElement().satisfies(version -> {
                            assertThat(version.state()).isEqualTo("CANDIDATE");
                            assertThat(version.resourceHash()).isEqualTo(candidate.resourceHash());
                            assertThat(version.validation()).isEmpty();
                        });
                assertThat(contracts.find(candidate.id(), REVIEWER)).isEqualTo(validated);
                assertThat(reviews.review(candidate.id(), REVIEWER).resourceHash()).isEqualTo(validated.resourceHash());
                assertThat(databaseSnapshot()).isEqualTo(afterWriter);
            } finally {
                resumeReview.countDown();
            }
        }
    }

    @Test
    void realPostgresFailureIsSanitizedAndMarksTheSharedTransactionRollbackOnly() throws Exception {
        Version candidate = contracts.create(release(), policy(1), REVIEWER);
        Map<String, String> before = databaseSnapshot();
        doAnswer(invocation -> {
            invocation.callRealMethod();
            // A real SQL failure aborts the PostgreSQL transaction; this is not a mocked exception.
            return jdbc.queryForObject("select cast('" + FAILURE_CANARY + "' as integer)", Integer.class);
        }).when(contracts).find(candidate.id(), REVIEWER);
        TransactionTemplate outer = transaction(TransactionDefinition.ISOLATION_REPEATABLE_READ, true);
        clearInvocations(contracts);

        assertThatThrownBy(() -> reviews.review(candidate.id(), REVIEWER))
                .isInstanceOfSatisfying(ReviewException.class,
                        failure -> assertSafeFailure(failure, "REVIEW_UNAVAILABLE"));
        assertThat(databaseSnapshot()).isEqualTo(before);

        assertThatThrownBy(() -> outer.executeWithoutResult(status -> {
            assertThatThrownBy(() -> reviews.review(candidate.id(), REVIEWER))
                    .isInstanceOfSatisfying(ReviewException.class,
                            failure -> assertSafeFailure(failure, "REVIEW_UNAVAILABLE"));
            assertThat(status.isRollbackOnly()).isTrue();
        })).isInstanceOf(UnexpectedRollbackException.class);

        verify(contracts, never()).list(any(), any());
        verifyNoAuthorityCalls();
        assertThat(databaseSnapshot()).isEqualTo(before);
    }

    private UUID release() throws Exception {
        String key = "stored-review-" + UUID.randomUUID();
        var agent = agents.create(new AgentDto.CreateRequest(key, "Stored review test", "Document review"));
        ObjectNode manifest = (ObjectNode) fixture("valid-release-manifest-v1.1.json");
        ((ObjectNode) manifest.get("agent")).put("id", key);
        UUID releaseId = releases.create(agent.id(), manifest, ACTOR).id();
        releases.analyze(releaseId, ACTOR);
        return releaseId;
    }

    private Version approveNext(UUID releaseId, int version) throws Exception {
        // Supplied B/D lifecycle precondition only: these tests do not run attacks, Replay or a release gate.
        assertThat(jdbc.update("update agent_releases set lifecycle_state='REMEDIATION', "
                + "effective_status='REMEDIATION' where id=?", releaseId)).isEqualTo(1);
        Version candidate = contracts.create(releaseId, policy(version), REVIEWER);
        Version validated = contracts.validate(candidate.id(), etag(candidate), REVIEWER);
        assertThat(validated.state()).isEqualTo("VALIDATED");
        Version approved = contracts.approve(candidate.id(), etag(validated), COMMENT, REVIEWER);
        assertThat(approved.state()).isEqualTo("APPROVED");
        assertThat(releases.find(releaseId).lifecycleState().name()).isEqualTo("VERIFYING");
        return approved;
    }

    private ObjectNode policy(int version) throws Exception {
        return ((ObjectNode) fixture("loan-review-safety-contract.json")).put("version", version);
    }

    private JsonNode fixture(String name) throws Exception {
        try (var input = getClass().getResourceAsStream("/fixtures/" + name)) {
            return mapper.readTree(input);
        }
    }

    private void assertStoredTarget(ReviewView result, Version stored) {
        assertThat(result.identity()).isEqualTo(identity(stored));
        assertThat(result.state().name()).isEqualTo(stored.state());
        assertThat(result.policyHash()).isEqualTo(stored.policyHash());
        assertThat(result.resourceHash()).isEqualTo(stored.resourceHash());
        // PostgreSQL jsonb has its own key order; the create() return is not the reloaded stored tree.
        String storedText = jdbc.queryForObject("select policy_json::text from safety_contract_versions where id=?",
                (row, index) -> mapper.writeValueAsString(mapper.readTree(row.getString(1))), stored.id());
        assertThat(result.storedPolicyJson()).isEqualTo(storedText);
        assertThat(result.canonicalPolicyJson()).isEqualTo(canonicalizer.canonicalizeAndHash(stored.policy()).canonicalJson());
    }

    private VersionIdentity identity(Version version) {
        return new VersionIdentity(version.id(), version.workspaceId(), version.releaseId(),
                version.contractKey(), version.version());
    }

    private String etag(Version version) {
        return '"' + version.resourceHash() + '"';
    }

    private void verifyNoAuthorityCalls() {
        verify(contracts, never()).create(any(), any(), any());
        verify(contracts, never()).validate(any(), any(), any());
        verify(contracts, never()).approve(any(), any(), any(), any());
        verify(contracts, never()).reject(any(), any(), any(), any());
        verify(contracts, never()).approved(any(), any(), any());
    }

    private TransactionTemplate transaction(int isolation, boolean readOnly) {
        TransactionTemplate template = new TransactionTemplate(transactions);
        template.setIsolationLevel(isolation);
        template.setReadOnly(readOnly);
        return template;
    }

    private PhysicalTransaction physicalTransaction() {
        return new PhysicalTransaction(
                jdbc.queryForObject("select current_setting('transaction_isolation')", String.class),
                jdbc.queryForObject("select current_setting('transaction_read_only')", String.class),
                TransactionSynchronizationManager.isActualTransactionActive(),
                TransactionSynchronizationManager.isCurrentTransactionReadOnly(),
                TransactionSynchronizationManager.getCurrentTransactionIsolationLevel());
    }

    private void assertPhysicalReadOnlyRepeatableRead(PhysicalTransaction observed) {
        assertThat(observed).isNotNull();
        assertThat(observed.isolation()).isEqualTo("repeatable read");
        assertThat(observed.readOnly()).isEqualTo("on");
        assertThat(observed.active()).isTrue();
        assertThat(observed.metadataReadOnly()).isTrue();
        assertThat(observed.metadataIsolation()).isEqualTo(TransactionDefinition.ISOLATION_REPEATABLE_READ);
    }

    private void assertSafeFailure(ReviewException failure, String code) {
        assertThat(failure.code().name()).isEqualTo(code);
        assertThat(failure.getCause()).isNull();
        assertThat(failure.getSuppressed()).isEmpty();
        assertThat(failure.getMessage()).doesNotContain(FAILURE_CANARY, REVIEWER.sessionId(), "PSQLException");
    }

    private Map<String, String> databaseSnapshot() {
        Map<String, String> result = new LinkedHashMap<>();
        for (String table : SNAPSHOT_TABLES) {
            // Names are fixed test constants; include every row and column, not just row counts.
            result.put(table, jdbc.queryForObject("select coalesce(jsonb_agg(to_jsonb(t) "
                    + "order by to_jsonb(t)::text)::text, '[]') from " + table + " t", String.class));
        }
        return result;
    }

    private static Stream<Arguments> unsafeTransactions() {
        return Stream.of(
                Arguments.of("read-only READ_COMMITTED", TransactionDefinition.ISOLATION_READ_COMMITTED, true),
                Arguments.of("read-only default isolation", TransactionDefinition.ISOLATION_DEFAULT, true),
                Arguments.of("writable REPEATABLE_READ", TransactionDefinition.ISOLATION_REPEATABLE_READ, false));
    }

    private record PhysicalTransaction(
            String isolation, String readOnly, boolean active, boolean metadataReadOnly, Integer metadataIsolation
    ) {}
}
