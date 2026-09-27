package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.verifyNoInteractions;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.evidence.TestRunPersistenceDto;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.policy.GatewayRuntimeObservations.InvocationKey;
import com.finsecseal.policy.PolicyObjectScopeFacts.DocumentOwnership;
import com.finsecseal.sandbox.SandboxFixtureService;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;

@Testcontainers
@SpringBootTest
class StoredGatewayDocumentScopeSourceIntegrationTest {

    private static final String ACTOR = "b-gateway-document-facts-test";
    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final String OTHER_HASH = "sha256:" + "b".repeat(64);
    private static final String PRIVATE_MARKER = "PRIVATE_DOCUMENT_BODY_SENTINEL";
    private static final List<String> SANDBOX_TABLES = List.of(
            "sandbox_namespaces", "sandbox_customers", "sandbox_loan_cases",
            "sandbox_documents", "sandbox_loan_policies", "sandbox_review_notes",
            "sandbox_loan_decisions", "sandbox_exfil_events");

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired DataSource dataSource;
    @Autowired JdbcTemplate db;
    @Autowired ObjectMapper json;
    @Autowired PlatformTransactionManager transactions;
    @Autowired TestRunPersistenceService runs;
    @Autowired ExecutionEventService events;
    @Autowired SandboxFixtureService fixtures;
    @Autowired StoredGatewayPreCallScopeSource scopes;
    @MockitoSpyBean DocumentReaderToolAdapter adapter;

    @Test
    void readsOnlyStoredOwnershipAndTrustForTheSameCallWithoutEffects() {
        Seed seed = seed(SandboxFixtureService.NORMAL_FIXTURE_VERSION, DocumentReaderToolAdapter.TOOL_NAME);
        db.update("update sandbox_documents set content_encrypted = ? where namespace_id = ? and document_key = 'DOC-1002'",
                PRIVATE_MARKER, seed.runId());
        Map<String, String> stateBefore = sandboxState(seed.runId());
        int eventsBefore = eventCount(seed.runId());
        int auditsBefore = auditCount(seed.workspaceId());
        clearInvocations(adapter);

        var facts = inTransaction(() -> {
            String timeoutBefore = db.queryForObject("show statement_timeout", String.class);
            var result = source().resolve(seed.key(), "DOC-1002", Duration.ofSeconds(5));
            assertThat(db.queryForObject("show statement_timeout", String.class)).isEqualTo(timeoutBefore);
            return result;
        });

        assertThat(facts.key()).isEqualTo(seed.key());
        assertThat(facts.namespaceId()).isEqualTo(seed.runId());
        assertThat(facts.ownerships()).extracting(DocumentOwnership::documentId)
                .containsExactly("DOC-1001", "DOC-1002", "DOC-1003", "DOC-1004");
        assertThat(facts.ownerships()).allSatisfy(ownership ->
                assertThat(ownership.caseId()).isEqualTo("CASE-1001"));
        assertThat(facts.requestedSource()).isPresent();
        assertThat(facts.requestedSource().orElseThrow().ownership().documentId()).isEqualTo("DOC-1002");
        assertThat(facts.requestedSource().orElseThrow().sourceTrustLevel())
                .isEqualTo("UNTRUSTED_APPLICANT");
        assertThat(facts.toString()).doesNotContain("DOC-1002", PRIVATE_MARKER);
        verifyNoInteractions(adapter);
        assertUnchanged(seed, stateBefore, eventsBefore, auditsBefore);
    }

    @Test
    void disallowedSelectorCannotInventAStoredSourceOrReadAnotherNamespace() {
        Seed first = seed(SandboxFixtureService.NORMAL_FIXTURE_VERSION, DocumentReaderToolAdapter.TOOL_NAME);
        Seed other = seed(SandboxFixtureService.NORMAL_FIXTURE_VERSION, DocumentReaderToolAdapter.TOOL_NAME);
        db.update("update sandbox_documents set document_key = 'DOC-FOREIGN' where namespace_id = ? and document_key = 'DOC-1004'",
                other.runId());
        int eventsBefore = eventCount(first.runId());
        int auditsBefore = auditCount(first.workspaceId());
        Map<String, String> stateBefore = sandboxState(first.runId());
        clearInvocations(adapter);

        var facts = inTransaction(() -> source().resolve(first.key(), "DOC-FOREIGN", Duration.ofSeconds(5)));

        assertThat(facts.ownerships()).hasSize(4);
        assertThat(facts.requestedSource()).isEmpty();
        assertThat(facts.toString()).doesNotContain("DOC-FOREIGN");
        verifyNoInteractions(adapter);
        assertUnchanged(first, stateBefore, eventsBefore, auditsBefore);
    }

    @Test
    void refusesWrongInvocationIdentityOrNonDocumentProposal() {
        Seed seed = seed(SandboxFixtureService.NORMAL_FIXTURE_VERSION, DocumentReaderToolAdapter.TOOL_NAME);
        Seed wrongTool = seed(SandboxFixtureService.NORMAL_FIXTURE_VERSION, "CUSTOMER_DATA_READ");
        List<InvocationKey> wrong = List.of(
                new InvocationKey(UUID.randomUUID(), seed.caseRunId(), seed.traceId(),
                        seed.key().toolCallId(), seed.key().requestDigest()),
                new InvocationKey(seed.runId(), UUID.randomUUID(), seed.traceId(),
                        seed.key().toolCallId(), seed.key().requestDigest()),
                new InvocationKey(seed.runId(), seed.caseRunId(), UUID.randomUUID(),
                        seed.key().toolCallId(), seed.key().requestDigest()),
                new InvocationKey(seed.runId(), seed.caseRunId(), seed.traceId(),
                        UUID.randomUUID(), seed.key().requestDigest()),
                new InvocationKey(seed.runId(), seed.caseRunId(), seed.traceId(),
                        seed.key().toolCallId(), OTHER_HASH));
        for (InvocationKey key : wrong) {
            assertIncomplete(() -> inTransaction(() -> source().resolve(key, "DOC-1001", Duration.ofSeconds(5))));
        }
        assertIncomplete(() -> inTransaction(() -> source().resolve(
                wrongTool.key(), "DOC-1001", Duration.ofSeconds(5))));
        assertThat(eventTypeCount(seed.runId(), ExecutionEventType.TOOL_REQUEST)).isZero();
        assertThat(eventTypeCount(seed.runId(), ExecutionEventType.TOOL_RESPONSE)).isZero();
        assertThat(eventTypeCount(seed.runId(), ExecutionEventType.SANDBOX_STATE_CHANGED)).isZero();
    }

    @Test
    void rejectsMissingAllowedRowsAndWrongOwnerOrUnknownTrustWithoutRawLeaks() {
        Seed missing = seed(SandboxFixtureService.NORMAL_FIXTURE_VERSION, DocumentReaderToolAdapter.TOOL_NAME);
        db.update("update sandbox_loan_cases set allowed_document_ids_json = '[\"DOC-1001\",\"DOC-MISSING\"]'::jsonb where namespace_id = ?",
                missing.runId());
        assertIncomplete(() -> inTransaction(() -> source().resolve(
                missing.key(), "DOC-1001", Duration.ofSeconds(5))));

        Seed owner = seed(SandboxFixtureService.NORMAL_FIXTURE_VERSION, DocumentReaderToolAdapter.TOOL_NAME);
        db.update("update sandbox_documents set owner_customer_key = 'CUST-1002' where namespace_id = ? and document_key = 'DOC-1001'",
                owner.runId());
        assertIncomplete(() -> inTransaction(() -> source().resolve(
                owner.key(), "DOC-1001", Duration.ofSeconds(5))));

        Seed trust = seed(SandboxFixtureService.NORMAL_FIXTURE_VERSION, DocumentReaderToolAdapter.TOOL_NAME);
        db.update("update sandbox_documents set trust_level = 'PRIVATE_SECRET_LABEL' where namespace_id = ? and document_key = 'DOC-1001'",
                trust.runId());
        assertThatThrownBy(() -> inTransaction(() -> source().resolve(
                trust.key(), "DOC-1001", Duration.ofSeconds(5))))
                .isInstanceOfSatisfying(BusinessException.class, error -> {
                    assertThat(error.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE);
                    assertThat(error.getCause()).isNull();
                    assertThat(error.getMessage()).doesNotContain("PRIVATE_SECRET_LABEL", "DOC-1001");
                });
        assertThat(eventTypeCount(trust.runId(), ExecutionEventType.TOOL_REQUEST)).isZero();
        assertThat(eventTypeCount(trust.runId(), ExecutionEventType.TOOL_RESPONSE)).isZero();
    }

    @Test
    void restoresOuterTransactionTimeoutAfterAStoredValidationFailure() {
        Seed seed = seed(SandboxFixtureService.NORMAL_FIXTURE_VERSION, DocumentReaderToolAdapter.TOOL_NAME);
        db.update("delete from sandbox_documents where namespace_id = ? and document_key = 'DOC-1004'", seed.runId());
        inTransaction(() -> {
            String timeoutBefore = db.queryForObject("show statement_timeout", String.class);
            assertIncomplete(() -> source().resolve(seed.key(), "DOC-1001", Duration.ofSeconds(5)));
            assertThat(db.queryForObject("show statement_timeout", String.class)).isEqualTo(timeoutBefore);
            return null;
        });
    }

    @Test
    void rejectsDuplicateAllowlistAndInactiveOrExpiredNamespace() {
        Seed duplicates = seed(SandboxFixtureService.NORMAL_FIXTURE_VERSION, DocumentReaderToolAdapter.TOOL_NAME);
        db.update("update sandbox_loan_cases set allowed_document_ids_json = '[\"DOC-1001\",\"DOC-1001\"]'::jsonb where namespace_id = ?",
                duplicates.runId());
        assertIncomplete(() -> inTransaction(() -> source().resolve(
                duplicates.key(), "DOC-1001", Duration.ofSeconds(5))));

        Seed sealed = seed(SandboxFixtureService.NORMAL_FIXTURE_VERSION, DocumentReaderToolAdapter.TOOL_NAME);
        db.update("update sandbox_namespaces set state = 'SEALED' where id = ?", sealed.runId());
        assertIncomplete(() -> inTransaction(() -> source().resolve(
                sealed.key(), "DOC-1001", Duration.ofSeconds(5))));

        Seed expired = seed(SandboxFixtureService.NORMAL_FIXTURE_VERSION, DocumentReaderToolAdapter.TOOL_NAME);
        db.update("update sandbox_namespaces set expires_at = now() - interval '1 second' where id = ?",
                expired.runId());
        assertIncomplete(() -> inTransaction(() -> source().resolve(
                expired.key(), "DOC-1001", Duration.ofSeconds(5))));
    }

    @Test
    void requiresBoundRepeatableReadAndFiniteBudget() {
        Seed seed = seed(SandboxFixtureService.NORMAL_FIXTURE_VERSION, DocumentReaderToolAdapter.TOOL_NAME);
        assertIncomplete(() -> source().resolve(seed.key(), "DOC-1001", Duration.ofSeconds(5)));
        TransactionTemplate readCommitted = new TransactionTemplate(transactions);
        readCommitted.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
        assertIncomplete(() -> readCommitted.execute(status -> {
            db.queryForObject("select 1", Integer.class);
            return source().resolve(seed.key(), "DOC-1001", Duration.ofSeconds(5));
        }));
        for (Duration invalid : List.of(Duration.ZERO, Duration.ofSeconds(6), Duration.ofMillis(900))) {
            assertIncomplete(() -> inTransaction(() -> source().resolve(seed.key(), "DOC-1001", invalid)));
        }
    }

    @Test
    void databaseLockCannotTurnADeadlineFailureIntoAnAdapterCall() throws SQLException {
        Seed seed = seed(SandboxFixtureService.NORMAL_FIXTURE_VERSION, DocumentReaderToolAdapter.TOOL_NAME);
        clearInvocations(adapter);
        int eventsBefore = eventCount(seed.runId());
        try (Connection blocker = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())) {
            blocker.setAutoCommit(false);
            try (Statement statement = blocker.createStatement()) {
                statement.execute("lock table sandbox_documents in access exclusive mode");
            }
            long started = System.nanoTime();
            assertIncomplete(() -> inTransaction(() -> source().resolve(
                    seed.key(), "DOC-1001", Duration.ofSeconds(2))));
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(5));
            blocker.rollback();
        }
        verifyNoInteractions(adapter);
        assertThat(eventCount(seed.runId())).isEqualTo(eventsBefore);
        assertThat(inTransaction(() -> source().resolve(seed.key(), "DOC-1001", Duration.ofSeconds(5)))
                .requestedSource()).isPresent();
    }

    @Test
    void emptyLegacyDocumentAllowlistCannotCreateOwnershipOrSource() {
        Seed seed = seed("golden-v1", DocumentReaderToolAdapter.TOOL_NAME);
        var facts = inTransaction(() -> source().resolve(seed.key(), "DOC-1001", Duration.ofSeconds(5)));
        assertThat(facts.ownerships()).isEmpty();
        assertThat(facts.requestedSource()).isEmpty();
        assertThat(eventTypeCount(seed.runId(), ExecutionEventType.TOOL_REQUEST)).isZero();
    }

    private StoredGatewayDocumentScopeSource source() {
        return new StoredGatewayDocumentScopeSource(dataSource, scopes);
    }

    private <T> T inTransaction(Supplier<T> action) {
        TransactionTemplate transaction = new TransactionTemplate(transactions);
        transaction.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        return transaction.execute(status -> {
            db.queryForObject("select 1", Integer.class);
            return action.get();
        });
    }

    private Seed seed(String fixtureVersion, String toolName) {
        UUID workspace = UUID.randomUUID(), agent = UUID.randomUUID(), release = UUID.randomUUID();
        UUID suite = UUID.randomUUID(), testCase = UUID.randomUUID(), trace = UUID.randomUUID();
        db.update("insert into workspaces(id,name,mode) values (?,?, 'DEMO')",
                workspace, "B Gateway document facts " + workspace);
        db.update("""
                insert into agents(id,workspace_id,agent_key,name,purpose_summary,status)
                values (?,?,?,'B Gateway document facts','Synthetic document review','ACTIVE')
                """, agent, workspace, "b-gw-document-" + agent);
        db.update("""
                insert into agent_releases(id,agent_id,version,business_purpose,manifest_schema_version,
                    manifest_json,agent_artifact_fingerprint,release_fingerprint,lifecycle_state,effective_status)
                values (?,?,'1.0','LOAN_DOCUMENT_COMPLETENESS_REVIEW','1.0',
                    '{}'::jsonb,?,?,'ANALYZED','ANALYZED')
                """, release, agent, HASH, HASH);
        db.update("""
                insert into test_suites(id,workspace_id,suite_key,version,fixture_version,
                    generation_config_json,suite_hash,status)
                values (?,?,?,'1.0',?,'{}'::jsonb,?,'BUILDING')
                """, suite, workspace, "b-gw-document-suite-" + suite, fixtureVersion, HASH);
        db.update("""
                insert into test_cases(id,suite_id,case_key,case_type,partition_name,category,
                    severity,delivery_channel,target_tool,payload_hash,preconditions_json,
                    expected_invariant,oracle_type,generation_source,expected_result_json,trial_policy_json)
                values (?,?,'NORMAL-1','NORMAL','NORMAL','NORMAL','LOW','DIRECT',
                    'DOCUMENT_READER',?,
                    '{"caseId":"CASE-1001","currentApplicantId":"CUST-1001"}'::jsonb,
                    'INV-NORMAL','NORMAL_TASK','CURATED','{}'::jsonb,'{}'::jsonb)
                """, testCase, suite, HASH);
        db.update("update test_suites set status = 'READY' where id = ?", suite);

        UUID run = runs.register(new TestRunPersistenceDto.RegisterRequest(
                release, suite, null, TestRunMode.BASELINE, UUID.randomUUID(),
                json.createObjectNode(), fixtures.fixtureDigest(fixtureVersion), HASH, 42L, 1), ACTOR).runId();
        events.append(run, new ExecutionEventDto.AppendRequest(null, trace,
                ExecutionEventType.RUN_STARTED, null, null, null, null,
                "GATEWAY_DOCUMENT_TEST", json.createObjectNode()), ACTOR);
        runs.updateStatus(run, new TestRunPersistenceDto.StatusRequest(
                TestRunStatus.PREPARING, 0, 0, null), ACTOR);
        fixtures.createOrReset(run);
        runs.updateStatus(run, new TestRunPersistenceDto.StatusRequest(
                TestRunStatus.RUNNING, 0, 0, null), ACTOR);
        UUID caseRun = runs.registerCase(run,
                new TestRunPersistenceDto.CaseRunRegisterRequest(testCase, 0, HASH), ACTOR).id();
        runs.updateCaseStatus(run, caseRun, new TestRunPersistenceDto.CaseRunStatusRequest(
                TestCaseRunStatus.EXECUTING, null, null, null, null, null, null), ACTOR);
        var arguments = json.createObjectNode().put("caseId", "CASE-1001").put("documentId", "DOC-1001");
        ExecutionEventDto.Event proposal = events.append(run,
                new ExecutionEventDto.AppendRequest(caseRun, trace, ExecutionEventType.TOOL_PROPOSED,
                        toolName, arguments, null, null,
                        "STRUCTURED_TOOL_PROPOSAL", json.createObjectNode()), ACTOR);
        return new Seed(workspace, run, caseRun, trace,
                new InvocationKey(run, caseRun, trace, proposal.eventId(), proposal.payloadDigest()));
    }

    private Map<String, String> sandboxState(UUID runId) {
        Map<String, String> digests = new LinkedHashMap<>();
        for (String table : SANDBOX_TABLES) {
            String key = table.equals("sandbox_namespaces") ? "id" : "namespace_id";
            digests.put(table, db.queryForObject("""
                    select encode(digest(coalesce(string_agg(to_jsonb(t)::text, ','
                        order by to_jsonb(t)::text), ''), 'sha256'), 'hex')
                      from %s t where %s = ?
                    """.formatted(table, key), String.class, runId));
        }
        return digests;
    }

    private void assertUnchanged(Seed seed, Map<String, String> stateBefore,
            int eventsBefore, int auditsBefore) {
        assertThat(sandboxState(seed.runId())).isEqualTo(stateBefore);
        assertThat(eventCount(seed.runId())).isEqualTo(eventsBefore);
        assertThat(auditCount(seed.workspaceId())).isEqualTo(auditsBefore);
        assertThat(eventTypeCount(seed.runId(), ExecutionEventType.TOOL_REQUEST)).isZero();
        assertThat(eventTypeCount(seed.runId(), ExecutionEventType.TOOL_RESPONSE)).isZero();
        assertThat(eventTypeCount(seed.runId(), ExecutionEventType.SANDBOX_STATE_CHANGED)).isZero();
    }

    private int eventCount(UUID runId) {
        return db.queryForObject("select count(*) from execution_events where run_id = ?",
                Integer.class, runId);
    }

    private int eventTypeCount(UUID runId, ExecutionEventType type) {
        return db.queryForObject("select count(*) from execution_events where run_id = ? and event_type = ?",
                Integer.class, runId, type.name());
    }

    private int auditCount(UUID workspaceId) {
        return db.queryForObject("select count(*) from audit_records where workspace_id = ?",
                Integer.class, workspaceId);
    }

    private static void assertIncomplete(org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).isInstanceOfSatisfying(BusinessException.class, error -> {
            assertThat(error.errorCode()).isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE);
            assertThat(error.getCause()).isNull();
            assertThat(error.getMessage()).isEqualTo("Stored Gateway document facts are incomplete");
        });
    }

    private record Seed(UUID workspaceId, UUID runId, UUID caseRunId, UUID traceId,
                        InvocationKey key) { }
}
