package com.finsecseal.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.ReleaseLifecycleState;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.LifecyclePolicyException;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.RejectionCode;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.evidence.TestRunProjectionService;
import com.finsecseal.policy.GatewayBaselinePolicySourceService.BaselinePolicySource;
import com.finsecseal.policy.GatewayBaselinePolicySourceService.BaselineSourceException;
import com.finsecseal.policy.GatewayBaselinePolicySourceService.FailureCode;
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
import java.util.stream.Stream;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
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
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/** Real A registration and PostgreSQL snapshots; this source fixture grants no execution authority. */
@Testcontainers
@SpringBootTest(properties = {
        "finsec.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "finsec.scheduling.enabled=false", "finsec.ai.enabled=false"
})
@ExtendWith(OutputCaptureExtension.class)
class GatewayBaselinePolicySourceServiceIntegrationTest {
    private static final String ACTOR = "c-baseline-source-integration";
    private static final String SESSION = "BASELINE-SOURCE-PRIVATE-SESSION-CANARY";
    private static final String PROMPT = "BASELINE-SOURCE-PRIVATE-PROMPT-CANARY";
    private static final String STORED = "BASELINE-SOURCE-PRIVATE-RESULT-CANARY";
    private static final String RAW_ERROR = "BASELINE-SOURCE-RAW-ERROR-CANARY";
    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final ReviewerContext REVIEWER = new ReviewerContext(
            AgentService.DEMO_WORKSPACE_ID, ACTOR, "AI_SECURITY_REVIEWER", SESSION, true, true, false);
    private static final List<String> DOMAIN_TABLES = List.of(
            "agents", "agent_releases", "release_artifacts", "safety_contracts", "safety_contract_versions",
            "contract_version_evidence", "api_idempotency_records", "patch_proposals", "patch_approvals",
            "test_suites", "test_cases", "test_runs", "test_case_runs", "run_event_counters", "execution_events",
            "findings", "oracle_results", "replay_links", "release_decisions", "evidence_references");

    @Container @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");
    @Autowired GatewayBaselinePolicySourceService sources;
    @MockitoSpyBean TestRunProjectionService runs;
    @MockitoSpyBean TestRunPersistenceService cases;
    @MockitoSpyBean ReleaseToolCatalogContractAdapter catalogs;
    @MockitoSpyBean ReleaseService releases;
    @MockitoSpyBean AgentService agents;
    @Autowired ExecutionEventService events;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate jdbc;
    @Autowired DataSource dataSource;
    @Autowired PlatformTransactionManager transactions;

    @Test
    void contractFreeAnalyzedReleaseUsesOneLockedVerifiedSnapshotAndCopies(CapturedOutput output) throws Exception {
        Seed seed = seed(true, true);
        var physical = new ArrayList<PhysicalTransaction>();
        doAnswer(call -> { physical.add(physicalTransaction()); return call.callRealMethod(); })
                .when(runs).find(seed.runId());
        doAnswer(call -> { physical.add(physicalTransaction()); return call.callRealMethod(); })
                .when(cases).findCase(seed.caseRunId());
        doAnswer(call -> { physical.add(physicalTransaction()); return call.callRealMethod(); })
                .when(agents).getRequired(seed.agentId());
        var catalogReturned = new AtomicBoolean();
        doAnswer(call -> {
            physical.add(physicalTransaction());
            Object result = call.callRealMethod();
            catalogReturned.set(true);
            return result;
        }).when(catalogs).load(seed.releaseId(), ACTOR);
        doAnswer(call -> {
            physical.add(physicalTransaction());
            if (catalogReturned.get()) assertThat(canAcquireReleaseLock(seed.releaseId())).isFalse();
            return call.callRealMethod();
        }).when(releases).getRequired(seed.releaseId());
        Baseline before = baseline(seed.releaseId());

        BaselinePolicySource source = sources.load(seed.runId(), seed.caseRunId(), REVIEWER);

        assertThat(physical).hasSizeGreaterThanOrEqualTo(6).allSatisfy(this::assertPhysicalTransaction);
        var order = inOrder(runs, releases, agents, cases, catalogs);
        order.verify(runs).find(seed.runId());
        order.verify(releases).getRequired(seed.releaseId());
        order.verify(agents).getRequired(seed.agentId());
        order.verify(cases).findCase(seed.caseRunId());
        order.verify(catalogs).load(seed.releaseId(), ACTOR);
        order.verify(releases).getRequired(seed.releaseId());
        verify(catalogs).load(seed.releaseId(), ACTOR);
        verify(releases).toolCatalog(seed.releaseId(), ACTOR);
        verify(releases, times(2)).getRequired(seed.releaseId());
        verify(releases, never()).fingerprint(any(), any());
        assertThat(source.runId()).isEqualTo(seed.runId());
        assertThat(source.testCaseRunId()).isEqualTo(seed.caseRunId());
        assertThat(source.testCaseId()).isEqualTo(seed.testCaseId());
        assertThat(source.releaseId()).isEqualTo(seed.releaseId());
        assertThat(source.workspaceId()).isEqualTo(AgentService.DEMO_WORKSPACE_ID);
        assertThat(source.referencedContractVersionId()).isNull();
        assertThat(source.runMode()).isEqualTo(TestRunMode.BASELINE);
        assertThat(source.runStatus()).isEqualTo(TestRunStatus.RUNNING);
        assertThat(source.caseStatus()).isEqualTo(TestCaseRunStatus.EXECUTING);
        assertThat(source.trialIndex()).isZero();
        assertThat(source.variantHash()).isEqualTo(HASH);
        assertThat(source.fixtureVersion()).isEqualTo("baseline-source-v1");
        assertThat(source.fixtureDigest()).isEqualTo(HASH);
        assertThat(source.catalog().releaseId()).isEqualTo(seed.releaseId());
        assertThat(source.catalog().manifestSchemaVersion()).isEqualTo("1.1");
        assertThat(source.releasePurpose()).isEqualTo("LOAN_DOCUMENT_COMPLETENESS_REVIEW");
        assertThat(source.releaseDeclarations()).isEqualTo(seed.declarations());
        assertThat(source.releaseDeclarations().size()).isEqualTo(4);
        assertThat(source.normalToolNames()).containsExactlyInAnyOrder("CASE_CONTEXT_READ", "DOCUMENT_READER",
                "CUSTOMER_DATA_READ", "LOAN_POLICY_SEARCH", "REVIEW_NOTE_WRITE");
        assertThat(source.normalToolNames()).doesNotContain("LOAN_DECISION_UPDATE");
        ((ObjectNode) source.releaseDeclarations().path("businessPurpose")).put("code", "TAMPERED");
        ((ObjectNode) source.catalog().inputSchemas().get("CUSTOMER_DATA_READ")).removeAll();
        assertThatThrownBy(() -> source.normalToolNames().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThat(source.releaseDeclarations()).isEqualTo(seed.declarations());
        assertThat(source.catalog().inputSchemas().get("CUSTOMER_DATA_READ").path("type").stringValue()).isEqualTo("object");
        assertThat(source.toString() + source.releaseDeclarations()).doesNotContain(SESSION, PROMPT, STORED, RAW_ERROR);
        assertUnchanged(before, seed.releaseId(), 1);
        assertThat(canAcquireReleaseLock(seed.releaseId())).isTrue();
        assertNoAmbientTransaction();
        assertThat(output.getAll()).doesNotContain(SESSION, PROMPT, STORED, RAW_ERROR);
    }

    @Test
    void foreignReviewerWorkspaceStopsBeforeCaseAndCatalog() throws Exception {
        Seed seed = seed(true, true);
        var foreign = new ReviewerContext(UUID.randomUUID(), ACTOR, "AI_SECURITY_REVIEWER", SESSION, true, true, false);
        Baseline before = baseline(seed.releaseId());
        assertThatThrownBy(() -> sources.load(seed.runId(), seed.caseRunId(), foreign))
                .isInstanceOfSatisfying(LifecyclePolicyException.class,
                        failure -> assertThat(failure.code()).isEqualTo(RejectionCode.REVIEWER_WORKSPACE_MISMATCH));
        verify(cases, never()).findCase(any());
        verify(catalogs, never()).load(any(), any());
        assertUnchanged(before, seed.releaseId(), 0);
        assertNoAmbientTransaction();
    }

    @Test
    void caseFromDifferentRunStopsBeforeCatalog() throws Exception {
        Seed seed = seed(true, true);
        Seed other = seed(true, true);
        Baseline before = baseline(seed.releaseId());
        assertSafeFailure(catchThrowable(() -> sources.load(seed.runId(), other.caseRunId(), REVIEWER)),
                FailureCode.CASE_RUN_BINDING_INVALID);
        verify(catalogs, never()).load(any(), any());
        assertUnchanged(before, seed.releaseId(), 0);
        assertNoAmbientTransaction();
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void nonExecutingRunOrCaseStopsBeforeCatalog(boolean running) throws Exception {
        Seed seed = seed(running, false);
        Baseline before = baseline(seed.releaseId());
        assertSafeFailure(catchThrowable(() -> sources.load(seed.runId(), seed.caseRunId(), REVIEWER)),
                running ? FailureCode.CASE_NOT_EXECUTING : FailureCode.RUN_NOT_EXECUTING);
        if (!running) verify(cases, never()).findCase(any());
        verify(catalogs, never()).load(any(), any());
        assertUnchanged(before, seed.releaseId(), 0);
        assertNoAmbientTransaction();
    }

    @ParameterizedTest @MethodSource("incompatibleTransactions")
    void incompatibleOuterTransactionStopsBeforeAnyOwner(String name, int isolation, boolean readOnly) throws Exception {
        Seed seed = seed(true, true);
        Baseline before = baseline(seed.releaseId());
        TransactionTemplate outer = new TransactionTemplate(transactions);
        outer.setIsolationLevel(isolation);
        outer.setReadOnly(readOnly);
        assertSafeFailure(catchThrowable(() -> outer.executeWithoutResult(status ->
                sources.load(seed.runId(), seed.caseRunId(), REVIEWER))), FailureCode.UNSAFE_TRANSACTION);
        verify(runs, never()).find(any());
        verify(releases, never()).getRequired(any());
        verify(agents, never()).getRequired(any());
        verify(cases, never()).findCase(any());
        verify(catalogs, never()).load(any(), any());
        assertUnchanged(before, seed.releaseId(), 0);
        assertNoAmbientTransaction();
    }

    @Test
    void finalProjectionFailureSanitizesErrorReleasesLockAndRetainsOnlyAccessAudit(CapturedOutput output) throws Exception {
        Seed seed = seed(true, true);
        beforeFinalProjection(() -> {
            assertPhysicalTransaction(physicalTransaction());
            assertThat(canAcquireReleaseLock(seed.releaseId())).isFalse();
            var raw = new IllegalStateException(RAW_ERROR, new IllegalArgumentException(PROMPT));
            raw.addSuppressed(new IllegalStateException(SESSION));
            throw raw;
        });
        Baseline before = baseline(seed.releaseId());
        assertSafeFailure(catchThrowable(() -> sources.load(seed.runId(), seed.caseRunId(), REVIEWER)),
                FailureCode.SOURCE_UNAVAILABLE);
        assertThat(canAcquireReleaseLock(seed.releaseId())).isTrue();
        assertUnchanged(before, seed.releaseId(), 1);
        assertNoAmbientTransaction();
        assertThat(output.getAll()).doesNotContain(SESSION, PROMPT, STORED, RAW_ERROR);
    }

    @Test
    void committedConcurrentLifecycleTransitionCannotMixWithEarlierRunSnapshot() throws Exception {
        Seed seed = seed(true, true);
        var firstRead = new CountDownLatch(1);
        var writerCommitted = new CountDownLatch(1);
        doAnswer(call -> {
            Object result = call.callRealMethod();
            assertPhysicalTransaction(physicalTransaction());
            firstRead.countDown();
            await(writerCommitted);
            return result;
        }).when(runs).find(seed.runId());
        try (var executor = Executors.newSingleThreadExecutor()) {
            var reader = executor.submit(() -> {
                Throwable failure = catchThrowable(() -> sources.load(seed.runId(), seed.caseRunId(), REVIEWER));
                assertNoAmbientTransaction();
                return failure;
            });
            Baseline afterWriter;
            try {
                await(firstRead);
                // Test-only competing writer uses A's legal entity transition; all immutable guards remain active.
                new TransactionTemplate(transactions).executeWithoutResult(status ->
                        releases.getRequired(seed.releaseId()).transitionTo(ReleaseLifecycleState.TESTING));
                afterWriter = baseline(seed.releaseId());
            } finally {
                writerCommitted.countDown();
            }
            assertSafeFailure(reader.get(10, TimeUnit.SECONDS), FailureCode.SOURCE_UNAVAILABLE);
            assertUnchanged(afterWriter, seed.releaseId(), 0);
        }
        assertThat(canAcquireReleaseLock(seed.releaseId())).isTrue();
        assertNoAmbientTransaction();
    }

    @Test
    void standaloneFiveSecondTimeoutStopsBlockedCatalogAndCleansUp() throws Exception {
        Seed seed = seed(true, true);
        Baseline before = baseline(seed.releaseId());
        var readerCleanedUp = new AtomicBoolean();
        try (var executor = Executors.newSingleThreadExecutor(); Connection blocker = dataSource.getConnection()) {
            blocker.setAutoCommit(false);
            try (var query = blocker.prepareStatement("select id from agent_releases where id=? for update")) {
                query.setObject(1, seed.releaseId());
                try (var row = query.executeQuery()) { assertThat(row.next()).isTrue(); }
            }
            long started = System.nanoTime();
            var reader = executor.submit(() -> {
                Throwable failure = catchThrowable(() -> sources.load(seed.runId(), seed.caseRunId(), REVIEWER));
                assertNoAmbientTransaction();
                readerCleanedUp.set(true);
                return failure;
            });
            try {
                assertSafeFailure(reader.get(12, TimeUnit.SECONDS), FailureCode.SOURCE_UNAVAILABLE);
                assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)).isBetween(3000L, 12000L);
            } finally {
                blocker.rollback();
            }
        }
        assertThat(readerCleanedUp).isTrue();
        assertThat(canAcquireReleaseLock(seed.releaseId())).isTrue();
        assertUnchanged(before, seed.releaseId(), 0);
        assertNoAmbientTransaction();
    }

    @Test
    void compatibleOuterTransactionOwnsDeadlineAndRetainsLockUntilItsCommit() throws Exception {
        Seed seed = seed(true, true);
        beforeFinalProjection(() -> {
            assertPhysicalTransaction(physicalTransaction());
            // Real database wait proves the nested five-second setting does not replace the caller's deadline.
            assertThat(jdbc.queryForObject("select 1 from pg_sleep(6)", Integer.class)).isEqualTo(1);
        });
        Baseline before = baseline(seed.releaseId());
        TransactionTemplate outer = new TransactionTemplate(transactions);
        outer.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        outer.setTimeout(12);
        long started = System.nanoTime();
        outer.executeWithoutResult(status -> {
            assertThat(sources.load(seed.runId(), seed.caseRunId(), REVIEWER).runId()).isEqualTo(seed.runId());
            assertPhysicalTransaction(physicalTransaction());
            assertThat(canAcquireReleaseLock(seed.releaseId())).isFalse();
        });
        assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)).isGreaterThanOrEqualTo(6000L);
        assertThat(canAcquireReleaseLock(seed.releaseId())).isTrue();
        assertUnchanged(before, seed.releaseId(), 1);
        assertNoAmbientTransaction();
    }

    private Seed seed(boolean running, boolean executing) throws Exception {
        String key = "baseline-source-" + UUID.randomUUID();
        UUID agentId = agents.create(new AgentDto.CreateRequest(key, "Baseline source fixture", "Document review"), ACTOR).id();
        ObjectNode manifest;
        try (var stream = getClass().getResourceAsStream("/fixtures/valid-release-manifest-v1.1.json")) {
            manifest = (ObjectNode) mapper.readTree(stream);
        }
        ((ObjectNode) manifest.path("agent")).put("id", key);
        ((ObjectNode) manifest.path("systemPrompt")).put("text", PROMPT);
        UUID releaseId = releases.create(agentId, manifest, ACTOR).id();
        releases.analyze(releaseId, ACTOR);
        assertThat(jdbc.queryForObject("select count(*) from safety_contract_versions v join safety_contracts c on c.id=v.contract_id where c.release_id=?",
                Integer.class, releaseId)).isZero();
        assertThat(jdbc.queryForObject("select lifecycle_state from agent_releases where id=?", String.class, releaseId)).isEqualTo("ANALYZED");
        UUID suiteId = UUID.randomUUID();
        UUID caseId = UUID.randomUUID();
        jdbc.update("""
                insert into test_suites(id,workspace_id,suite_key,version,fixture_version,generation_config_json,suite_hash,status)
                values(?,?,?,'1.0','baseline-source-v1','{}'::jsonb,?,'BUILDING')
                """, suiteId, AgentService.DEMO_WORKSPACE_ID, "baseline-suite-" + UUID.randomUUID(), HASH);
        jdbc.update("""
                insert into test_cases(id,suite_id,case_key,case_type,partition_name,category,severity,delivery_channel,
                    payload_hash,preconditions_json,expected_invariant,oracle_type,generation_source,expected_result_json,trial_policy_json)
                values(?,?,'normal-1','NORMAL','NORMAL','NORMAL','LOW','DIRECT',?,'{}'::jsonb,
                    'INV-NORMAL','NORMAL_TASK','CURATED','{}'::jsonb,'{}'::jsonb)
                """, caseId, suiteId, HASH);
        jdbc.update("update test_suites set status='READY' where id=?", suiteId);
        UUID runId = cases.register(new TestRunPersistenceDto.RegisterRequest(releaseId, suiteId, null, TestRunMode.BASELINE,
                UUID.randomUUID(), mapper.createObjectNode(), HASH, HASH, 42L, 1), ACTOR).runId();
        UUID caseRunId = cases.registerCase(runId, new TestRunPersistenceDto.CaseRunRegisterRequest(caseId, 0, HASH), ACTOR).id();
        if (running) {
            events.append(runId, new ExecutionEventDto.AppendRequest(null, UUID.randomUUID(), ExecutionEventType.RUN_STARTED,
                    null, null, null, null, "BASELINE", mapper.createObjectNode()), ACTOR);
            cases.updateStatus(runId, new TestRunPersistenceDto.StatusRequest(TestRunStatus.PREPARING, 0, 0,
                    mapper.createObjectNode().put("private", STORED)), ACTOR);
            cases.updateStatus(runId, new TestRunPersistenceDto.StatusRequest(TestRunStatus.RUNNING, 0, 0, null), ACTOR);
        }
        if (executing) cases.updateCaseStatus(runId, caseRunId, new TestRunPersistenceDto.CaseRunStatusRequest(
                TestCaseRunStatus.EXECUTING, null, null, null, null, null, mapper.createObjectNode().put("private", STORED)), ACTOR);
        JsonNode declarations = mapper.readTree(jdbc.queryForObject("""
                select jsonb_build_object('businessPurpose',manifest_json->'businessPurpose',
                    'businessWorkflow',manifest_json->'businessWorkflow','tools',manifest_json->'tools',
                    'serverToolCatalog',manifest_json->'serverToolCatalog')::text from agent_releases where id=?
                """, String.class, releaseId));
        clearInvocations(runs, cases, catalogs, releases, agents);
        assertNoAmbientTransaction();
        return new Seed(agentId, releaseId, caseId, runId, caseRunId, declarations);
    }

    private void beforeFinalProjection(Runnable hook) {
        var catalogReturned = new AtomicBoolean();
        doAnswer(call -> { Object value = call.callRealMethod(); catalogReturned.set(true); return value; })
                .when(catalogs).load(any(), any());
        doAnswer(call -> { if (catalogReturned.compareAndSet(true, false)) hook.run(); return call.callRealMethod(); })
                .when(releases).getRequired(any());
    }

    private void await(CountDownLatch latch) throws InterruptedException {
        if (!latch.await(8, TimeUnit.SECONDS)) throw new IllegalStateException("Source test synchronization timed out");
    }

    private boolean canAcquireReleaseLock(UUID releaseId) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try (var query = connection.prepareStatement("select id from agent_releases where id=? for update nowait")) {
                query.setObject(1, releaseId);
                try (var rows = query.executeQuery()) { assertThat(rows.next()).isTrue(); }
                connection.commit();
                return true;
            } catch (SQLException failure) {
                connection.rollback();
                if ("55P03".equals(failure.getSQLState())) return false;
                throw failure;
            }
        } catch (SQLException failure) { throw new IllegalStateException("Independent Release lock probe failed", failure); }
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

    private Baseline baseline(UUID releaseId) { return new Baseline(domainSnapshot(), otherAuditSnapshot(releaseId), accessAudits(releaseId)); }

    private void assertUnchanged(Baseline before, UUID releaseId, int accessDelta) {
        verify(cases, never()).register(any(), any());
        verify(cases, never()).registerCase(any(), any(), any());
        verify(cases, never()).updateStatus(any(), any(), any());
        verify(cases, never()).updateCaseStatus(any(), any(), any(), any());
        assertThat(domainSnapshot()).isEqualTo(before.domain());
        assertThat(otherAuditSnapshot(releaseId)).isEqualTo(before.otherAudits());
        List<JsonNode> current = accessAudits(releaseId);
        assertThat(current).hasSize(before.accessAudits().size() + accessDelta).containsAll(before.accessAudits());
        var added = current.stream().filter(row -> !before.accessAudits().contains(row)).toList();
        if (accessDelta == 1) assertThat(added).extracting(row -> row.at("/metadata_json/purpose").stringValue())
                .containsExactly("TOOL_CATALOG_INTEGRITY_CHECK");
        assertThat(added).noneMatch(row -> "FINGERPRINT_INTEGRITY_CHECK".equals(row.at("/metadata_json/purpose").stringValue()));
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
            String key = table.equals("contract_version_evidence") ? "version_id" : table.equals("run_event_counters") ? "run_id" : "id";
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

    private void assertSafeFailure(Throwable thrown, FailureCode expected) {
        assertThat(thrown).isInstanceOf(BaselineSourceException.class);
        var failure = (BaselineSourceException) thrown;
        assertThat(failure.code()).isEqualTo(expected);
        assertThat(failure.getMessage()).isEqualTo(expected.name());
        assertThat(failure.getCause()).isNull();
        assertThat(failure.getSuppressed()).isEmpty();
        StringWriter rendered = new StringWriter();
        failure.printStackTrace(new PrintWriter(rendered));
        assertThat(rendered.toString()).doesNotContain(SESSION, PROMPT, STORED, RAW_ERROR);
    }

    private static Stream<Arguments> incompatibleTransactions() {
        return Stream.of(Arguments.of("read-only REPEATABLE_READ", TransactionDefinition.ISOLATION_REPEATABLE_READ, true),
                Arguments.of("writable READ_COMMITTED", TransactionDefinition.ISOLATION_READ_COMMITTED, false),
                Arguments.of("writable default isolation", TransactionDefinition.ISOLATION_DEFAULT, false));
    }

    private record Seed(UUID agentId, UUID releaseId, UUID testCaseId, UUID runId, UUID caseRunId, JsonNode declarations) {}
    private record Baseline(Map<String, String> domain, String otherAudits, List<JsonNode> accessAudits) {}
    private record PhysicalTransaction(String isolation, String readOnly, boolean active, boolean metadataReadOnly, Integer metadataIsolation) {}
}
