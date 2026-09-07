package com.finsecseal.contract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import com.finsecseal.agent.AgentDto;
import com.finsecseal.agent.AgentService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ValidationProof;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionIdentity;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionState;
import com.finsecseal.contract.SafetyContractPatchGenerationSourceService.FailureCode;
import com.finsecseal.contract.SafetyContractPatchGenerationSourceService.PatchGenerationSourceException;
import com.finsecseal.contract.SafetyContractPatchGenerationSourceService.PreparedPatchGenerationSource;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.platform.contract.ContractPersistenceService;
import com.finsecseal.platform.contract.ContractPersistenceService.Version;
import com.finsecseal.platform.contract.PatchSourceService;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.ReleaseDto;
import com.finsecseal.release.ReleaseService;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
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
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
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

/** Actual PostgreSQL composition; seeded B/D provenance does not claim an executed attack or model call. */
@Testcontainers
@SpringBootTest(properties = {
        "finsec.crypto.key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "finsec.scheduling.enabled=false"
})
@ExtendWith(OutputCaptureExtension.class)
class SafetyContractPatchGenerationSourceServiceIntegrationTest {
    private static final String ACTOR = "c-patch-source-integration";
    private static final String SESSION = "PATCH-SOURCE-PRIVATE-SESSION";
    private static final String SECRET = "PATCH-SOURCE-SYSTEM-PROMPT-CANARY";
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

    @Autowired SafetyContractPatchGenerationSourceService sources;
    @MockitoSpyBean PatchSourceService patchSources;
    @MockitoSpyBean ContractPersistenceService contracts;
    @MockitoSpyBean SafetyContractGenerationSourceService generation;
    @Autowired AgentService agents;
    @Autowired ReleaseService releases;
    @Autowired ExecutionEventService events;
    @Autowired ObjectMapper mapper;
    @Autowired CanonicalJsonService canonical;
    @Autowired DigestService digests;
    @Autowired JdbcTemplate jdbc;
    @Autowired PlatformTransactionManager transactions;

    // No test-managed transaction: C's real proxy establishes the transaction before any A read.
    @Test
    void preparesHistoricalCandidateAndEmptyEvidenceInActualWritableRepeatableRead(CapturedOutput output)
            throws Exception {
        Seed seed = seed("SEED", false, false, false);
        Version historical = contracts.create(seed.releaseId(), policy(1), REVIEWER);
        Version latest = contracts.create(seed.releaseId(), policy(2), REVIEWER);
        assertThat(latest.version()).isGreaterThan(historical.version());
        AtomicReference<PhysicalTransaction> firstOwnerEntry = new AtomicReference<>();
        doAnswer(invocation -> {
            firstOwnerEntry.set(physicalTransaction());
            return invocation.callRealMethod();
        }).when(patchSources).find(seed.findingId(), REVIEWER);
        Map<String, String> before = domainSnapshot();
        String otherAudits = otherAuditSnapshot();
        int accessBefore = accessAuditCount(seed.releaseId());
        clearOwnerInvocations();

        PreparedPatchGenerationSource prepared = sources.prepare(seed.findingId(), historical.id(), REVIEWER);

        assertPhysicalTransaction(firstOwnerEntry.get());
        var order = inOrder(patchSources, contracts, generation);
        order.verify(patchSources).find(seed.findingId(), REVIEWER);
        order.verify(contracts).find(historical.id(), REVIEWER);
        order.verify(generation).prepare(seed.releaseId(), LoanReviewFinancialTemplate.KEY, ACTOR);
        order.verifyNoMoreInteractions();
        assertSource(prepared, seed, historical);
        assertThat(prepared.base().state()).isEqualTo(VersionState.CANDIDATE);
        assertThat(prepared.base().validationProof()).isEmpty();
        assertThat(prepared.evidence().isObject()).isTrue();
        assertThat(prepared.evidence().isEmpty()).isTrue();
        assertThat(prepared.finding().evidenceDigest()).isEqualTo(emptyEvidenceDigest());
        assertThat(prepared.generation().manifestContext().size()).isEqualTo(7);
        assertThat(prepared.generation().manifestContext().toString()).doesNotContain("systemPrompt", SECRET);
        assertThat(prepared.generation().templateRules().has("contractId")).isFalse();
        assertThat(prepared.toString()).doesNotContain(SESSION, SECRET, historical.contractKey());
        assertThat(output.getAll()).doesNotContain(SESSION, SECRET);
        verifyNoAuthorityCalls();
        assertThat(domainSnapshot()).isEqualTo(before);
        assertThat(otherAuditSnapshot()).isEqualTo(otherAudits);
        assertAccessAudit(seed.releaseId(), accessBefore + 1);

        ((ObjectNode) prepared.evidence()).put("local", "not stored");
        ((ObjectNode) prepared.base().policy()).put("purpose", "FORGED");
        ((ObjectNode) prepared.generation().templateRules()).put("purpose", "FORGED");
        assertSource(prepared, seed, historical);
        assertThat(prepared.evidence().isEmpty()).isTrue();
        PreparedPatchGenerationSource repeated = sources.prepare(seed.findingId(), historical.id(), REVIEWER);
        assertSource(repeated, seed, historical);
        assertThat(repeated.evidence().isEmpty()).isTrue();
        assertThat(domainSnapshot()).isEqualTo(before);
        assertThat(otherAuditSnapshot()).isEqualTo(otherAudits);
        assertAccessAudit(seed.releaseId(), accessBefore + 2);
    }

    @ParameterizedTest
    @CsvSource({"HELD_OUT,false,false", "SEED,true,false", "MUTATION,false,true"})
    void actualOwnerRejectsHiddenSourcesAndAncestryBeforeContractOrGenerationRead(
            String partition, boolean hidden, boolean hiddenParent) throws Exception {
        Seed seed = seed(partition, hidden, hiddenParent, false);
        Version base = contracts.create(seed.releaseId(), policy(1), REVIEWER);
        assertOwnerSourceFailure(seed, base, REVIEWER, ErrorCode.RESOURCE_NOT_FOUND);
    }

    @Test
    void actualOwnerRejectsForeignWorkspaceBeforeContractOrGenerationRead() throws Exception {
        Seed seed = seed("SEED", false, false, false);
        Version base = contracts.create(seed.releaseId(), policy(1), REVIEWER);
        ReviewerContext foreign = new ReviewerContext(UUID.randomUUID(), ACTOR, REVIEWER.role(), SESSION,
                true, true, false);
        assertOwnerSourceFailure(seed, base, foreign, ErrorCode.RESOURCE_NOT_FOUND);
    }

    @Test
    void actualOwnerRejectsEvidenceDigestMismatchWithoutFallback() throws Exception {
        // Oracle evidence is immutable after the run completes; seed the adversarial digest at INSERT.
        Seed seed = seed("SEED", false, false, true);
        Version base = contracts.create(seed.releaseId(), policy(1), REVIEWER);
        assertOwnerSourceFailure(seed, base, REVIEWER, ErrorCode.EVIDENCE_INCOMPLETE);
    }

    @Test
    void crossReleaseBaseIsRejectedBeforeGenerationWithoutDomainChanges() throws Exception {
        Seed seed = seed("SEED", false, false, false);
        Version foreignReleaseBase = contracts.create(release().id(), policy(1), REVIEWER);
        Map<String, String> before = domainSnapshot();
        String audits = allAuditSnapshot();
        clearOwnerInvocations();

        assertThatThrownBy(() -> sources.prepare(seed.findingId(), foreignReleaseBase.id(), REVIEWER))
                .isInstanceOfSatisfying(PatchGenerationSourceException.class,
                        failure -> assertSafeFailure(failure, FailureCode.BASE_VERSION_INVALID));

        verify(patchSources).find(seed.findingId(), REVIEWER);
        verify(contracts).find(foreignReleaseBase.id(), REVIEWER);
        verify(generation, never()).prepare(any(), any(), any());
        verifyNoAuthorityCalls();
        assertThat(domainSnapshot()).isEqualTo(before);
        assertThat(allAuditSnapshot()).isEqualTo(audits);
    }

    @Test
    void actualStoredResourceIntegrityFailureStopsBeforeGeneration() throws Exception {
        Seed seed = seed("SEED", false, false, false);
        Version base = contracts.create(seed.releaseId(), policy(1), REVIEWER);
        assertThat(jdbc.update("update contract_version_evidence set resource_hash=? where version_id=?",
                "sha256:" + "f".repeat(64), base.id())).isEqualTo(1);
        Map<String, String> before = domainSnapshot();
        String audits = allAuditSnapshot();
        clearOwnerInvocations();

        assertThatThrownBy(() -> sources.prepare(seed.findingId(), base.id(), REVIEWER))
                .isInstanceOfSatisfying(BusinessException.class,
                        failure -> assertThat(failure.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE));

        verify(patchSources).find(seed.findingId(), REVIEWER);
        verify(contracts).find(base.id(), REVIEWER);
        verify(generation, never()).prepare(any(), any(), any());
        verifyNoAuthorityCalls();
        assertThat(domainSnapshot()).isEqualTo(before);
        assertThat(allAuditSnapshot()).isEqualTo(audits);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("unsafeTransactions")
    void unsafeOuterTransactionsFailBeforeEveryOwnerRead(String description, int isolation, boolean readOnly)
            throws Exception {
        Seed seed = seed("SEED", false, false, false);
        Version base = contracts.create(seed.releaseId(), policy(1), REVIEWER);
        TransactionTemplate outer = new TransactionTemplate(transactions);
        outer.setIsolationLevel(isolation);
        outer.setReadOnly(readOnly);
        Map<String, String> before = domainSnapshot();
        String audits = allAuditSnapshot();
        clearOwnerInvocations();

        assertThatThrownBy(() -> outer.execute(status -> sources.prepare(seed.findingId(), base.id(), REVIEWER)))
                .isInstanceOfSatisfying(PatchGenerationSourceException.class,
                        failure -> assertSafeFailure(failure, FailureCode.UNSAFE_TRANSACTION));

        verify(patchSources, never()).find(any(), any());
        verify(contracts, never()).find(any(), any());
        verify(generation, never()).prepare(any(), any(), any());
        verifyNoAuthorityCalls();
        assertThat(domainSnapshot()).isEqualTo(before);
        assertThat(allAuditSnapshot()).isEqualTo(audits);
    }

    @Test
    void committedConcurrentValidationCannotMixSourceAndBaseSnapshots() throws Exception {
        Seed seed = seed("SEED", false, false, false);
        Version candidate = contracts.create(seed.releaseId(), policy(1), REVIEWER);
        CountDownLatch sourceRead = new CountDownLatch(1);
        CountDownLatch resumeReader = new CountDownLatch(1);
        AtomicBoolean first = new AtomicBoolean(true);
        AtomicReference<PhysicalTransaction> readerTransaction = new AtomicReference<>();
        doAnswer(invocation -> {
            if (first.compareAndSet(true, false)) {
                readerTransaction.set(physicalTransaction());
                jdbc.execute("set local lock_timeout = '5s'");
                Object result = invocation.callRealMethod();
                sourceRead.countDown();
                if (!resumeReader.await(8, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("Patch source test synchronization timed out");
                }
                return result;
            }
            return invocation.callRealMethod();
        }).when(patchSources).find(seed.findingId(), REVIEWER);
        Map<String, String> beforeWriter = domainSnapshot();
        var executor = Executors.newFixedThreadPool(2);
        try {
            var reader = executor.submit(() -> sources.prepare(seed.findingId(), candidate.id(), REVIEWER));
            assertThat(sourceRead.await(8, TimeUnit.SECONDS)).isTrue();
            var writer = executor.submit(() -> {
                TransactionTemplate transaction = new TransactionTemplate(transactions);
                transaction.setTimeout(8);
                return transaction.execute(status -> {
                    jdbc.execute("set local lock_timeout = '5s'");
                    return contracts.validate(candidate.id(), '"' + candidate.resourceHash() + '"', REVIEWER);
                });
            });
            Version validated = writer.get(8, TimeUnit.SECONDS); // Includes the independent commit.
            assertThat(validated).isNotNull();
            assertThat(validated.state()).isEqualTo("VALIDATED");
            assertThat(validated.resourceHash()).isNotEqualTo(candidate.resourceHash());
            assertThat(validated.validation().isEmpty()).isFalse();
            Map<String, String> afterWriter = domainSnapshot();
            assertThat(afterWriter.get("safety_contract_versions")).isNotEqualTo(beforeWriter.get("safety_contract_versions"));
            assertThat(afterWriter.get("contract_version_evidence")).isNotEqualTo(beforeWriter.get("contract_version_evidence"));
            for (String table : DOMAIN_TABLES) {
                if (!List.of("safety_contract_versions", "contract_version_evidence").contains(table)) {
                    assertThat(afterWriter.get(table)).as("writer preserves %s", table).isEqualTo(beforeWriter.get(table));
                }
            }
            String otherAuditsAfterWriter = otherAuditSnapshot();
            int accessAfterWriter = accessAuditCount(seed.releaseId());
            resumeReader.countDown();

            PreparedPatchGenerationSource old = reader.get(8, TimeUnit.SECONDS);

            assertPhysicalTransaction(readerTransaction.get());
            assertSource(old, seed, candidate);
            assertThat(old.base().state()).isEqualTo(VersionState.CANDIDATE);
            assertThat(old.base().validationProof()).isEmpty();
            assertThat(contracts.find(candidate.id(), REVIEWER)).isEqualTo(validated);
            assertThat(domainSnapshot()).isEqualTo(afterWriter);
            assertThat(otherAuditSnapshot()).isEqualTo(otherAuditsAfterWriter);
            assertAccessAudit(seed.releaseId(), accessAfterWriter + 1);

            PreparedPatchGenerationSource fresh = sources.prepare(seed.findingId(), candidate.id(), REVIEWER);
            assertSource(fresh, seed, validated);
            assertThat(fresh.base().state()).isEqualTo(VersionState.VALIDATED);
            assertThat(fresh.base().validationProof()).contains(mapper.treeToValue(validated.validation(), ValidationProof.class));
            assertThat(domainSnapshot()).isEqualTo(afterWriter);
            assertThat(otherAuditSnapshot()).isEqualTo(otherAuditsAfterWriter);
            assertAccessAudit(seed.releaseId(), accessAfterWriter + 2);
        } finally {
            resumeReader.countDown();
            executor.shutdownNow();
            assertThat(executor.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
        }
    }

    private void assertOwnerSourceFailure(Seed seed, Version base, ReviewerContext reviewer, ErrorCode code) {
        Map<String, String> before = domainSnapshot();
        String audits = allAuditSnapshot();
        clearOwnerInvocations();
        assertThatThrownBy(() -> sources.prepare(seed.findingId(), base.id(), reviewer))
                .isInstanceOfSatisfying(BusinessException.class, failure -> assertThat(failure.errorCode()).isEqualTo(code));
        verify(patchSources).find(seed.findingId(), reviewer);
        verify(contracts, never()).find(any(), any());
        verify(generation, never()).prepare(any(), any(), any());
        verifyNoAuthorityCalls();
        assertThat(domainSnapshot()).isEqualTo(before);
        assertThat(allAuditSnapshot()).isEqualTo(audits);
    }

    private void assertSource(PreparedPatchGenerationSource source, Seed seed, Version base) {
        assertThat(source.finding().findingId()).isEqualTo(seed.findingId());
        assertThat(source.finding().workspaceId()).isEqualTo(REVIEWER.workspaceId());
        assertThat(source.finding().releaseId()).isEqualTo(seed.releaseId());
        assertThat(source.finding().violatedInvariant()).isEqualTo("INV-01");
        assertThat(source.sourceRunId()).isEqualTo(seed.runId());
        assertThat(source.sourceCaseId()).isEqualTo(seed.caseId());
        assertThat(source.oracleResultId()).isEqualTo(seed.oracleId());
        assertThat(source.base().identity()).isEqualTo(new VersionIdentity(base.id(), base.workspaceId(), base.releaseId(), base.contractKey(), base.version()));
        assertThat(source.base().policy()).isEqualTo(base.policy());
        assertThat(source.base().policyHash()).isEqualTo(base.policyHash());
        assertThat(source.base().resourceHash()).isEqualTo(base.resourceHash());
        assertThat(source.generation().catalog().releaseId()).isEqualTo(seed.releaseId());
    }

    private void clearOwnerInvocations() { clearInvocations(patchSources, contracts, generation); }

    private void verifyNoAuthorityCalls() {
        verify(contracts, never()).create(any(), any(), any());
        verify(contracts, never()).validate(any(), any(), any());
        verify(contracts, never()).approve(any(), any(), any(), any());
        verify(contracts, never()).approve(any(), any(), any(), any(), any());
        verify(contracts, never()).reject(any(), any(), any(), any());
        verify(contracts, never()).storePatch(any(), any(), any(), any());
        verify(contracts, never()).approved(any(), any(), any());
    }

    private PhysicalTransaction physicalTransaction() {
        return new PhysicalTransaction(jdbc.queryForObject("select current_setting('transaction_isolation')", String.class),
                jdbc.queryForObject("select current_setting('transaction_read_only')", String.class),
                TransactionSynchronizationManager.isActualTransactionActive(),
                TransactionSynchronizationManager.isCurrentTransactionReadOnly(),
                TransactionSynchronizationManager.getCurrentTransactionIsolationLevel());
    }

    private void assertPhysicalTransaction(PhysicalTransaction observed) {
        assertThat(observed).isNotNull();
        assertThat(observed.isolation()).isEqualTo("repeatable read");
        assertThat(observed.readOnly()).isEqualTo("off");
        assertThat(observed.active()).isTrue();
        assertThat(observed.metadataReadOnly()).isFalse();
        assertThat(observed.metadataIsolation()).isEqualTo(TransactionDefinition.ISOLATION_REPEATABLE_READ);
    }

    private void assertSafeFailure(PatchGenerationSourceException failure, FailureCode code) {
        assertThat(failure.code()).isEqualTo(code);
        assertThat(failure.getCause()).isNull();
        assertThat(failure.getSuppressed()).isEmpty();
        assertThat(failure.getMessage()).doesNotContain(SESSION, SECRET);
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

    private String allAuditSnapshot() {
        return jdbc.queryForObject("select coalesce(jsonb_agg(to_jsonb(t) order by id)::text, '[]') from audit_records t", String.class);
    }

    private String otherAuditSnapshot() {
        return jdbc.queryForObject("select coalesce(jsonb_agg(to_jsonb(t) order by id)::text, '[]') from audit_records t "
                + "where not (actor_id=? and action='SYSTEM_PROMPT_DECRYPTED_INTERNAL')", String.class, ACTOR);
    }

    private int accessAuditCount(UUID releaseId) {
        return jdbc.queryForObject("select count(*) from audit_records where actor_id=? and resource_id=? "
                + "and action='SYSTEM_PROMPT_DECRYPTED_INTERNAL'", Integer.class, ACTOR, releaseId);
    }

    private void assertAccessAudit(UUID releaseId, int expected) {
        assertThat(accessAuditCount(releaseId)).isEqualTo(expected);
        JsonNode metadata = jdbc.queryForObject("select metadata_json::text from audit_records where actor_id=? "
                        + "and resource_id=? and action='SYSTEM_PROMPT_DECRYPTED_INTERNAL' order by occurred_at desc limit 1",
                (row, index) -> mapper.readTree(row.getString(1)), ACTOR, releaseId);
        assertThat(metadata.path("purpose").asString()).isEqualTo("TOOL_CATALOG_INTEGRITY_CHECK");
        assertThat(metadata.path("plaintextReturned").asBoolean()).isFalse();
        assertThat(metadata.toString()).doesNotContain(SESSION, SECRET);
    }

    private static Stream<Arguments> unsafeTransactions() {
        return Stream.of(
                Arguments.of("readonly REPEATABLE_READ", TransactionDefinition.ISOLATION_REPEATABLE_READ, true),
                Arguments.of("writable READ_COMMITTED", TransactionDefinition.ISOLATION_READ_COMMITTED, false),
                Arguments.of("readonly READ_COMMITTED", TransactionDefinition.ISOLATION_READ_COMMITTED, true),
                Arguments.of("writable default isolation", TransactionDefinition.ISOLATION_DEFAULT, false));
    }

    private ObjectNode policy(int version) throws Exception {
        try (var stream = getClass().getResourceAsStream("/fixtures/loan-review-safety-contract.json")) {
            return ((ObjectNode) mapper.readTree(stream)).put("contractId", "patch-source-policy").put("version", version);
        }
    }

    private ReleaseDto.Response release() throws Exception {
        String key = "c-patch-source-" + UUID.randomUUID();
        var agent = agents.create(new AgentDto.CreateRequest(key, "Patch source fixture", "Document review"));
        ObjectNode manifest;
        try (var stream = getClass().getResourceAsStream("/fixtures/valid-release-manifest-v1.1.json")) {
            manifest = (ObjectNode) mapper.readTree(stream);
        }
        ((ObjectNode) manifest.path("agent")).put("id", key);
        ((ObjectNode) manifest.path("systemPrompt")).put("text", SECRET);
        UUID releaseId = releases.create(agent.id(), manifest, ACTOR).id();
        releases.analyze(releaseId, ACTOR);
        return releases.find(releaseId);
    }

    private String emptyEvidenceDigest() { return digests.sha256(canonical.canonicalize(mapper.createObjectNode())); }

    private Seed seed(String partition, boolean hidden, boolean hiddenParent, boolean invalidDigest) throws Exception {
        var release = release();
        String suffix = UUID.randomUUID().toString();
        UUID suite = UUID.randomUUID();
        UUID testCase = UUID.randomUUID();
        UUID run = UUID.randomUUID();
        UUID caseRun = UUID.randomUUID();
        UUID oracle = UUID.randomUUID();
        UUID finding = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        Timestamp time = Timestamp.from(now);
        Timestamp started = Timestamp.from(now.minusSeconds(1));
        // Required provenance fixture only, following A's existing test while keeping every DB guard enabled.
        jdbc.update("""
                insert into test_suites(id,workspace_id,suite_key,version,fixture_version,generation_config_json,
                    suite_hash,status,created_at,updated_at)
                values(?,?,?,'1.0.0','fixture-v1','{}'::jsonb,?,'DRAFT',?,?)
                """, suite, REVIEWER.workspaceId(), "patch-source-" + suffix, HASH, time, time);
        jdbc.update("""
                insert into test_cases(id,suite_id,case_key,case_type,partition_name,category,severity,
                    delivery_channel,target_tool,attack_goal,payload_hash,preconditions_json,expected_invariant,
                    oracle_type,generation_source,hidden_from_patch_generator,expected_result_json,trial_policy_json,
                    created_at,updated_at)
                values(?,?,?,'ATTACK',?,'FA-02','CRITICAL','DOCUMENT','CUSTOMER_DATA_READ','cross customer read',?,
                    '{}'::jsonb,'INV-01','CROSS_CUSTOMER','GOLDEN',?,'{}'::jsonb,'{}'::jsonb,?,?)
                """, testCase, suite, "case-" + suffix, partition, HASH, hidden, time, time);
        if (hiddenParent) {
            UUID parent = UUID.randomUUID();
            jdbc.update("""
                    insert into test_cases(id,suite_id,case_key,case_type,partition_name,category,severity,
                        delivery_channel,payload_hash,preconditions_json,expected_invariant,oracle_type,
                        generation_source,hidden_from_patch_generator,expected_result_json,trial_policy_json)
                    values(?,?,'hidden-parent','ATTACK','HELD_OUT','FA-02','HIGH','DOCUMENT',?,'{}','INV-01',
                        'CROSS_CUSTOMER','GOLDEN',true,'{}','{}')
                    """, parent, suite, HASH);
            jdbc.update("update test_cases set parent_seed_id=? where id=?", parent, testCase);
        }
        jdbc.update("update test_suites set status='READY',updated_at=? where id=?", time, suite);
        jdbc.update("""
                insert into test_runs(id,release_id,suite_id,mode,status,agent_artifact_fingerprint,release_fingerprint,
                    config_json,fixture_version,fixture_digest,model_config_hash,total_cases,completed_cases,
                    operational_error_count,started_at,completed_at,summary_json,created_at,updated_at)
                values(?,?,?,'BASELINE','QUEUED',?,?,'{}'::jsonb,'fixture-v1',?,?,1,0,0,null,null,'{}'::jsonb,?,?)
                """, run, release.id(), suite, release.agentArtifactFingerprint(), release.releaseFingerprint(), HASH, HASH, time, time);
        jdbc.update("""
                insert into test_case_runs(id,test_run_id,test_case_id,trial_index,status,security_outcome,
                    variant_hash,started_at,completed_at,result_json,created_at,updated_at)
                values(?,?,?,0,'PENDING',null,?,null,null,'{}'::jsonb,?,?)
                """, caseRun, run, testCase, HASH, time, time);
        jdbc.update("update test_case_runs set status='FAILED_SECURITY',security_outcome='ATTACK_SUCCESS', "
                + "started_at=?,completed_at=?,updated_at=? where id=?", started, time, time, caseRun);
        jdbc.update("""
                insert into oracle_results(id,test_case_run_id,oracle_type,oracle_version,outcome,reason_code,
                    invariant_id,evidence_json,evidence_digest,evaluated_at,created_at,updated_at)
                values(?,?,'CROSS_CUSTOMER','1.0','ATTACK_SUCCESS','UNAUTHORIZED_RECORD_RETURNED','INV-01',
                    '{}'::jsonb,?,?,?,?)
                """, oracle, caseRun, invalidDigest ? HASH : emptyEvidenceDigest(), time, time, time);
        jdbc.update("""
                insert into findings(id,release_id,source_oracle_result_id,category,severity,title,status,
                    violated_invariant,root_cause_json,first_seen_run_id,latest_seen_run_id,created_at,updated_at)
                values(?,?,?,'FA-02','CRITICAL','Synthetic unauthorized record fixture','OPEN','INV-01','{}'::jsonb,?,?,?,?)
                """, finding, release.id(), oracle, run, run, time, time);
        jdbc.update("update test_runs set status='PREPARING',updated_at=? where id=?", Timestamp.from(now.minusSeconds(2)), run);
        jdbc.update("update test_runs set status='RUNNING',started_at=?,updated_at=? where id=?", started, started, run);
        jdbc.update("insert into run_event_counters(run_id,last_sequence) values(?,0)", run);
        UUID trace = UUID.randomUUID();
        events.append(run, new ExecutionEventDto.AppendRequest(null, trace, ExecutionEventType.RUN_STARTED,
                null, null, null, null, "RUN_STARTED", mapper.createObjectNode()), ACTOR);
        events.append(run, new ExecutionEventDto.AppendRequest(null, trace, ExecutionEventType.RUN_COMPLETED,
                null, null, null, null, "RUN_COMPLETED", mapper.createObjectNode()), ACTOR);
        jdbc.update("update test_runs set status='COMPLETED',completed_cases=1,started_at=?,completed_at=?,updated_at=? "
                + "where id=?", started, time, time, run);
        jdbc.update("update agent_releases set lifecycle_state='TESTING',effective_status='TESTING' where id=?", release.id());
        return new Seed(release.id(), finding, oracle, run, testCase);
    }

    private record Seed(UUID releaseId, UUID findingId, UUID oracleId, UUID runId, UUID caseId) {}
    private record PhysicalTransaction(String isolation, String readOnly, boolean active,
                                       boolean metadataReadOnly, Integer metadataIsolation) {}
}
