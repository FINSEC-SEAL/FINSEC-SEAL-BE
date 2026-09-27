package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
import com.finsecseal.sandbox.SandboxFixtureService;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;

@Testcontainers
@SpringBootTest
class StoredGatewayPreCallScopeSourceIntegrationTest {

    private static final String ACTOR = "b-gateway-scope-test";
    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final String OTHER_HASH = "sha256:" + "b".repeat(64);

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired JdbcTemplate db;
    @Autowired ObjectMapper json;
    @Autowired PlatformTransactionManager transactions;
    @Autowired TestRunPersistenceService runs;
    @Autowired ExecutionEventService events;
    @Autowired SandboxFixtureService fixtures;
    @Autowired StoredGatewayPreCallScopeSource source;

    @Test
    void resolvesOnlyStoredCallScopeAndRestoresTransactionTimeout() {
        Seed seed = seed();
        int eventsBefore = eventCount(seed.runId());
        int auditsBefore = auditCount(seed.workspaceId());

        StoredGatewayPreCallScopeSource.ScopeSnapshot scope = inTransaction(() -> {
            String timeoutBefore = db.queryForObject("show statement_timeout", String.class);
            var resolved = source.resolve(seed.key(), Duration.ofSeconds(5));
            assertThat(db.queryForObject("show statement_timeout", String.class))
                    .isEqualTo(timeoutBefore);
            return resolved;
        });

        assertThat(scope.key()).isEqualTo(seed.key());
        assertThat(scope.serverContext().runId()).isEqualTo(seed.runId());
        assertThat(scope.serverContext().caseRunId()).isEqualTo(seed.caseRunId());
        assertThat(scope.serverContext().traceId()).isEqualTo(seed.traceId());
        assertThat(scope.serverContext().mode()).isEqualTo(TestRunMode.BASELINE);
        assertThat(scope.serverContext().caseKey()).isEqualTo("CASE-1001");
        assertThat(scope.serverContext().currentApplicantId()).isEqualTo("CUST-1001");
        assertThat(scope.namespace().namespaceId()).isEqualTo(seed.runId());
        assertThat(scope.namespace().fixtureVersion()).isEqualTo("golden-v1");
        assertThat(scope.namespace().fixtureDigest()).isEqualTo(fixtures.fixtureDigest());
        assertThat(scope.namespace().state()).isEqualTo("ACTIVE");
        assertThat(scope.toolName()).isEqualTo("CUSTOMER_DATA_READ");
        assertThat(scope.workflowStage()).isEqualTo("DOCUMENT_REVIEW");
        assertThat(scope.allowedDocumentIds()).containsExactly("DOC-1001", "DOC-1002");
        assertThatThrownBy(() -> scope.allowedDocumentIds().add("DOC-OTHER"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(eventCount(seed.runId())).isEqualTo(eventsBefore);
        assertThat(auditCount(seed.workspaceId())).isEqualTo(auditsBefore);
        assertThat(db.queryForObject("""
                select count(*) from execution_events
                 where run_id = ? and event_type in ('TOOL_REQUEST','TOOL_RESPONSE','MODEL_REQUEST','MODEL_RESPONSE')
                """, Integer.class, seed.runId())).isZero();
        assertThat(db.queryForObject("""
                select count(*) from sandbox_exfil_events where namespace_id = ?
                """, Integer.class, seed.runId())).isZero();
    }

    @Test
    void rejectsWrongStoredProposalIdentityWithoutReadingToolArguments() {
        Seed seed = seed();
        InvocationKey key = seed.key();
        assertIncomplete(() -> resolve(new InvocationKey(UUID.randomUUID(), key.caseRunId(),
                key.traceId(), key.toolCallId(), key.requestDigest())));
        assertIncomplete(() -> resolve(new InvocationKey(key.runId(), UUID.randomUUID(),
                key.traceId(), key.toolCallId(), key.requestDigest())));
        assertIncomplete(() -> resolve(new InvocationKey(key.runId(), key.caseRunId(),
                UUID.randomUUID(), key.toolCallId(), key.requestDigest())));
        assertIncomplete(() -> resolve(new InvocationKey(key.runId(), key.caseRunId(),
                key.traceId(), UUID.randomUUID(), key.requestDigest())));
        assertIncomplete(() -> resolve(new InvocationKey(key.runId(), key.caseRunId(),
                key.traceId(), key.toolCallId(), OTHER_HASH)));
        assertThat(resolve(key).serverContext().currentApplicantId()).isEqualTo("CUST-1001");
    }

    @Test
    void rejectsInactiveRunCaseAndNamespace() {
        Seed stoppedRun = seed();
        db.update("update test_runs set status = 'CANCELLING' where id = ?", stoppedRun.runId());
        assertIncomplete(() -> resolve(stoppedRun.key()));

        Seed stoppedCase = seed();
        db.update("update test_case_runs set status = 'EVALUATING' where id = ?", stoppedCase.caseRunId());
        assertIncomplete(() -> resolve(stoppedCase.key()));

        Seed sealed = seed();
        db.update("update sandbox_namespaces set state = 'SEALED' where id = ?", sealed.runId());
        assertIncomplete(() -> resolve(sealed.key()));

        Seed expired = seed();
        db.update("update sandbox_namespaces set expires_at = now() - interval '1 second' where id = ?",
                expired.runId());
        assertIncomplete(() -> resolve(expired.key()));
    }

    @Test
    void rejectsMissingOrMalformedStoredCaseAndDocumentScope() {
        Seed missingCase = seed("{}");
        assertIncomplete(() -> resolve(missingCase.key()));

        Seed wrongApplicant = seed("{\"caseId\":\"CASE-1001\",\"currentApplicantId\":\"CUST-OTHER\"}");
        assertIncomplete(() -> resolve(wrongApplicant.key()));

        for (String documentJson : List.of("{}", "[1]", "[\"DOC-1\",\"DOC-1\"]", "[\"\"]")) {
            Seed malformed = seed();
            db.update("""
                    update sandbox_loan_cases set allowed_document_ids_json = ?::jsonb
                     where namespace_id = ? and case_key = 'CASE-1001'
                    """, documentJson, malformed.runId());
            assertIncomplete(() -> resolve(malformed.key()));
        }
    }

    @Test
    void rejectsMissingBoundTransactionAndUnsafeDeadline() {
        Seed seed = seed();
        assertIncomplete(() -> source.resolve(seed.key(), Duration.ofSeconds(5)));
        assertIncomplete(() -> inTransaction(() -> source.resolve(seed.key(), Duration.ZERO)));
        assertIncomplete(() -> inTransaction(() -> source.resolve(seed.key(), Duration.ofSeconds(6))));
        assertIncomplete(() -> inTransaction(() -> source.resolve(seed.key(), Duration.ofMillis(900))));
    }

    @Test
    void boundedPostgresQueryFailureRollsBackWithoutChangingStoredEvidence() throws Exception {
        Seed seed = seed();
        int eventsBefore = eventCount(seed.runId());
        int auditsBefore = auditCount(seed.workspaceId());
        String originalTimeout = inTransaction(() -> db.queryForObject("show statement_timeout", String.class));

        try (Connection blocker = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())) {
            blocker.setAutoCommit(false);
            try (Statement lock = blocker.createStatement()) {
                lock.execute("lock table test_runs in access exclusive mode");
            }
            long started = System.nanoTime();
            assertIncomplete(() -> inTransaction(() -> source.resolve(seed.key(), Duration.ofSeconds(3))));
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(6));
            blocker.rollback();
        }

        assertThat(inTransaction(() -> db.queryForObject("show statement_timeout", String.class)))
                .isEqualTo(originalTimeout);
        assertThat(eventCount(seed.runId())).isEqualTo(eventsBefore);
        assertThat(auditCount(seed.workspaceId())).isEqualTo(auditsBefore);
        assertThat(resolve(seed.key()).namespace().namespaceId()).isEqualTo(seed.runId());
    }

    private StoredGatewayPreCallScopeSource.ScopeSnapshot resolve(InvocationKey key) {
        return inTransaction(() -> source.resolve(key, Duration.ofSeconds(5)));
    }

    private <T> T inTransaction(Supplier<T> action) {
        TransactionTemplate transaction = new TransactionTemplate(transactions);
        transaction.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        return transaction.execute(status -> {
            db.queryForObject("select 1", Integer.class);
            return action.get();
        });
    }

    private Seed seed() {
        return seed("{\"caseId\":\"CASE-1001\",\"currentApplicantId\":\"CUST-1001\"}");
    }

    private Seed seed(String preconditions) {
        UUID workspace = UUID.randomUUID(), agent = UUID.randomUUID(), release = UUID.randomUUID();
        UUID suite = UUID.randomUUID(), testCase = UUID.randomUUID();
        UUID trace = UUID.randomUUID();
        db.update("insert into workspaces(id,name,mode) values (?,?, 'DEMO')",
                workspace, "B Gateway scope " + workspace);
        db.update("""
                insert into agents(id,workspace_id,agent_key,name,purpose_summary,status)
                values (?,?,?,'B Gateway scope','Synthetic review','ACTIVE')
                """, agent, workspace, "b-gw-scope-" + agent);
        db.update("""
                insert into agent_releases(id,agent_id,version,business_purpose,manifest_schema_version,
                    manifest_json,agent_artifact_fingerprint,release_fingerprint,lifecycle_state,effective_status)
                values (?,?,'1.0','LOAN_DOCUMENT_COMPLETENESS_REVIEW','1.0',
                    '{}'::jsonb,?,?,'ANALYZED','ANALYZED')
                """, release, agent, HASH, HASH);
        db.update("""
                insert into test_suites(id,workspace_id,suite_key,version,fixture_version,
                    generation_config_json,suite_hash,status)
                values (?,?,?,'1.0','golden-v1','{}'::jsonb,?,'BUILDING')
                """, suite, workspace, "b-gw-scope-suite-" + suite, HASH);
        db.update("""
                insert into test_cases(id,suite_id,case_key,case_type,partition_name,category,
                    severity,delivery_channel,target_tool,payload_hash,preconditions_json,
                    expected_invariant,oracle_type,generation_source,expected_result_json,trial_policy_json)
                values (?,?,'NORMAL-1','NORMAL','NORMAL','NORMAL','LOW','DIRECT',
                    'CUSTOMER_DATA_READ',?,?::jsonb,
                    'INV-NORMAL','NORMAL_TASK','CURATED','{}'::jsonb,'{}'::jsonb)
                """, testCase, suite, HASH, preconditions);
        db.update("update test_suites set status = 'READY' where id = ?", suite);

        UUID run = runs.register(new TestRunPersistenceDto.RegisterRequest(
                release, suite, null, TestRunMode.BASELINE, UUID.randomUUID(),
                json.createObjectNode(), fixtures.fixtureDigest(), HASH, 42L, 1), ACTOR).runId();
        events.append(run, new ExecutionEventDto.AppendRequest(null, trace,
                ExecutionEventType.RUN_STARTED, null, null, null, null,
                "GATEWAY_SCOPE_TEST", json.createObjectNode()), ACTOR);
        runs.updateStatus(run, new TestRunPersistenceDto.StatusRequest(
                TestRunStatus.PREPARING, 0, 0, null), ACTOR);
        fixtures.createOrReset(run);
        runs.updateStatus(run, new TestRunPersistenceDto.StatusRequest(
                TestRunStatus.RUNNING, 0, 0, null), ACTOR);
        UUID caseRun = runs.registerCase(run,
                new TestRunPersistenceDto.CaseRunRegisterRequest(testCase, 0, HASH), ACTOR).id();
        runs.updateCaseStatus(run, caseRun, new TestRunPersistenceDto.CaseRunStatusRequest(
                TestCaseRunStatus.EXECUTING, null, null, null, null, null, null), ACTOR);
        db.update("""
                update sandbox_loan_cases
                   set status = 'DOCUMENT_REVIEW',
                       allowed_document_ids_json = '["DOC-1001","DOC-1002"]'::jsonb
                 where namespace_id = ? and case_key = 'CASE-1001'
                """, run);
        var arguments = json.createObjectNode();
        arguments.putArray("customerIds").add("CUST-1001");
        arguments.putArray("fields").add("incomeBand");
        ExecutionEventDto.Event proposal = events.append(run,
                new ExecutionEventDto.AppendRequest(caseRun, trace, ExecutionEventType.TOOL_PROPOSED,
                        "CUSTOMER_DATA_READ", arguments, null, null,
                        "STRUCTURED_TOOL_PROPOSAL", json.createObjectNode()), ACTOR);
        return new Seed(workspace, run, caseRun, testCase, trace,
                new InvocationKey(run, caseRun, trace, proposal.eventId(), proposal.payloadDigest()));
    }

    private int eventCount(UUID runId) {
        return db.queryForObject("select count(*) from execution_events where run_id = ?",
                Integer.class, runId);
    }

    private int auditCount(UUID workspaceId) {
        return db.queryForObject("select count(*) from audit_records where workspace_id = ?",
                Integer.class, workspaceId);
    }

    private static void assertIncomplete(org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).isInstanceOf(BusinessException.class)
                .satisfies(error -> assertThat(((BusinessException) error).errorCode())
                        .isEqualTo(ErrorCode.EVIDENCE_INCOMPLETE))
                .hasMessage("Stored Gateway Tool scope is incomplete");
    }

    private record Seed(UUID workspaceId, UUID runId, UUID caseRunId, UUID testCaseId,
                        UUID traceId, InvocationKey key) {
    }
}
