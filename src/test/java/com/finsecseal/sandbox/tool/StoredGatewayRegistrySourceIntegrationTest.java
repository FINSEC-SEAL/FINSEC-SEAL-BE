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
import com.finsecseal.policy.GatewayRuntimeObservations.RegistryObservation;
import com.finsecseal.policy.PolicyToolTrustFacts.ToolRegistryEntry;
import com.finsecseal.policy.PolicyToolTrustFacts.TrustLevel;
import com.finsecseal.sandbox.SandboxFixtureService;
import java.sql.Connection;
import java.sql.DriverManager;
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
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;

@Testcontainers
@SpringBootTest
class StoredGatewayRegistrySourceIntegrationTest {

    private static final String ACTOR = "b-gateway-registry-test";
    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final String OTHER_HASH = "sha256:" + "b".repeat(64);
    private static final List<String> BUSINESS_TABLES = List.of("sandbox_customers",
            "sandbox_loan_cases", "sandbox_documents", "sandbox_loan_policies",
            "sandbox_review_notes", "sandbox_loan_decisions", "sandbox_exfil_events");

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
    @Autowired StoredGatewayPreCallScopeSource scope;
    @Autowired StoredGatewayRegistrySource source;
    @Autowired List<ToolAdapter> adapters;

    @Test
    void observesOnlyRunBoundReleaseRowsAndRestoresTimeoutWithoutSideEffects() {
        ToolSpec customer = tool("CUSTOMER_DATA_READ", true, "TRUSTED_INTERNAL");
        ToolSpec otherFirst = tool("LOAN_POLICY_SEARCH", true, "TRUSTED_INTERNAL");
        ToolSpec otherSecond = tool("LOAN_POLICY_SEARCH", false, "MIXED");
        Seed seed = seed(List.of(customer, otherFirst, otherSecond));
        Seed anotherRelease = seed(List.of(tool("CUSTOMER_DATA_READ", true, "MIXED")));
        int eventsBefore = eventCount(seed.runId());
        int auditsBefore = auditCount(seed.workspaceId());
        Map<String, String> stateBefore = businessState(seed.runId());

        RegistryObservation observed = inTransaction(() -> {
            String previousTimeout = db.queryForObject("show statement_timeout", String.class);
            RegistryObservation value = source.observe(seed.key(), Duration.ofSeconds(5));
            assertThat(db.queryForObject("show statement_timeout", String.class))
                    .isEqualTo(previousTimeout);
            return value;
        });

        assertThat(observed.key()).isEqualTo(seed.key());
        assertThat(observed.observedReleaseFingerprint()).isEqualTo(seed.fingerprint())
                .isNotEqualTo(anotherRelease.fingerprint());
        assertThat(observed.entries()).containsExactly(customer.entry(), otherFirst.entry(), otherSecond.entry());
        assertThatThrownBy(() -> observed.entries().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(observe(anotherRelease.key()).entries())
                .containsExactly(anotherRelease.tools().getFirst().entry());
        assertThat(eventCount(seed.runId())).isEqualTo(eventsBefore);
        assertThat(auditCount(seed.workspaceId())).isEqualTo(auditsBefore);
        assertThat(businessState(seed.runId())).isEqualTo(stateBefore);
        assertThat(db.queryForObject("""
                select count(*) from execution_events where run_id = ?
                   and event_type in ('TOOL_REQUEST','TOOL_RESPONSE','MODEL_REQUEST','MODEL_RESPONSE')
                """, Integer.class, seed.runId())).isZero();
    }

    @Test
    void rejectsForgedInvocationAndMissingRequestedStoredLink() {
        Seed seed = seed(List.of(tool("CUSTOMER_DATA_READ", true, "TRUSTED_INTERNAL")));
        InvocationKey key = seed.key();
        assertIncomplete(() -> observe(new InvocationKey(UUID.randomUUID(), key.caseRunId(),
                key.traceId(), key.toolCallId(), key.requestDigest())));
        assertIncomplete(() -> observe(new InvocationKey(key.runId(), UUID.randomUUID(),
                key.traceId(), key.toolCallId(), key.requestDigest())));
        assertIncomplete(() -> observe(new InvocationKey(key.runId(), key.caseRunId(),
                UUID.randomUUID(), key.toolCallId(), key.requestDigest())));
        assertIncomplete(() -> observe(new InvocationKey(key.runId(), key.caseRunId(),
                key.traceId(), UUID.randomUUID(), key.requestDigest())));
        assertIncomplete(() -> observe(new InvocationKey(key.runId(), key.caseRunId(),
                key.traceId(), key.toolCallId(), OTHER_HASH)));
        Seed noCustomerLink = seed(List.of(tool("LOAN_POLICY_SEARCH", true, "TRUSTED_INTERNAL")));
        assertIncomplete(() -> observe(noCustomerLink.key()));
        assertThat(observe(key).entries()).hasSize(1);
    }

    @Test
    void preservesRequestedAndUnrelatedDisabledLinksForPolicyToJudge() {
        ToolSpec requested = tool("CUSTOMER_DATA_READ", false, "TRUSTED_INTERNAL");
        ToolSpec unrelated = tool("LOAN_POLICY_SEARCH", false, "MIXED");
        Seed seed = seed(List.of(requested, unrelated));

        assertThat(observe(seed.key()).entries()).containsExactly(requested.entry(), unrelated.entry());
        assertThat(db.queryForObject("""
                select count(*) from release_tools where release_id = ? and enabled = false
                """, Integer.class, seed.releaseId())).isEqualTo(2);
    }

    @Test
    void rejectsMalformedStoredTrustAndMissingOrDuplicateRuntimeAdapter() {
        Seed malformed = seed(List.of(tool("CUSTOMER_DATA_READ", true, "NOT_A_TRUST_LEVEL")));
        assertIncomplete(() -> observe(malformed.key()));

        Seed valid = seed(List.of(tool("CUSTOMER_DATA_READ", true, "TRUSTED_INTERNAL")));
        StoredGatewayRegistrySource absent = new StoredGatewayRegistrySource(dataSource, scope, List.of());
        assertIncomplete(() -> inTransaction(() -> absent.observe(valid.key(), Duration.ofSeconds(5))));
        ToolAdapter customer = adapters.stream().filter(adapter ->
                "CUSTOMER_DATA_READ".equals(adapter.toolName())).findFirst().orElseThrow();
        StoredGatewayRegistrySource duplicate = new StoredGatewayRegistrySource(dataSource, scope,
                List.of(customer, customer));
        assertIncomplete(() -> inTransaction(() -> duplicate.observe(valid.key(), Duration.ofSeconds(5))));
    }

    @Test
    void rejectsInactiveScopeMissingTransactionAndUnsafeDeadline() {
        Seed seed = seed(List.of(tool("CUSTOMER_DATA_READ", true, "TRUSTED_INTERNAL")));
        assertIncomplete(() -> source.observe(seed.key(), Duration.ofSeconds(5)));
        assertIncomplete(() -> inTransaction(() -> source.observe(seed.key(), Duration.ZERO)));
        assertIncomplete(() -> inTransaction(() -> source.observe(seed.key(), Duration.ofSeconds(6))));
        assertIncomplete(() -> inTransaction(() -> source.observe(seed.key(), Duration.ofMillis(900))));
        db.update("update test_case_runs set status = 'EVALUATING' where id = ?", seed.caseRunId());
        assertIncomplete(() -> observe(seed.key()));

        Seed sealed = seed(List.of(tool("CUSTOMER_DATA_READ", true, "TRUSTED_INTERNAL")));
        db.update("update sandbox_namespaces set state = 'SEALED' where id = ?", sealed.runId());
        assertIncomplete(() -> observe(sealed.key()));
    }

    @Test
    void boundedRegistryQueryFailureRollsBackWithoutChangingStoredEvidence() throws Exception {
        Seed seed = seed(List.of(tool("CUSTOMER_DATA_READ", true, "TRUSTED_INTERNAL")));
        int eventsBefore = eventCount(seed.runId());
        int auditsBefore = auditCount(seed.workspaceId());
        Map<String, String> stateBefore = businessState(seed.runId());
        String originalTimeout = inTransaction(() -> db.queryForObject("show statement_timeout", String.class));

        try (Connection blocker = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())) {
            blocker.setAutoCommit(false);
            try (Statement lock = blocker.createStatement()) {
                lock.execute("lock table release_tools in access exclusive mode");
            }
            long started = System.nanoTime();
            assertIncomplete(() -> inTransaction(() -> source.observe(seed.key(), Duration.ofSeconds(3))));
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(6));
            blocker.rollback();
        }

        assertThat(inTransaction(() -> db.queryForObject("show statement_timeout", String.class)))
                .isEqualTo(originalTimeout);
        assertThat(eventCount(seed.runId())).isEqualTo(eventsBefore);
        assertThat(auditCount(seed.workspaceId())).isEqualTo(auditsBefore);
        assertThat(businessState(seed.runId())).isEqualTo(stateBefore);
        assertThat(observe(seed.key()).entries()).hasSize(1);
    }

    private RegistryObservation observe(InvocationKey key) {
        return inTransaction(() -> source.observe(key, Duration.ofSeconds(5)));
    }

    private <T> T inTransaction(Supplier<T> action) {
        TransactionTemplate transaction = new TransactionTemplate(transactions);
        transaction.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        return transaction.execute(status -> {
            db.queryForObject("select 1", Integer.class);
            return action.get();
        });
    }

    private ToolSpec tool(String name, boolean enabled, String trust) {
        return new ToolSpec(name, "v-" + UUID.randomUUID(), trust, HASH, OTHER_HASH, enabled);
    }

    private Seed seed(List<ToolSpec> tools) {
        UUID workspace = UUID.randomUUID(), agent = UUID.randomUUID(), release = UUID.randomUUID();
        UUID suite = UUID.randomUUID(), testCase = UUID.randomUUID(), trace = UUID.randomUUID();
        String fingerprint = "sha256:" + UUID.randomUUID().toString().replace("-", "")
                + UUID.randomUUID().toString().replace("-", "");
        db.update("insert into workspaces(id,name,mode) values (?,?, 'DEMO')",
                workspace, "B Gateway registry " + workspace);
        db.update("""
                insert into agents(id,workspace_id,agent_key,name,purpose_summary,status)
                values (?,?,?,'B Gateway registry','Synthetic review','ACTIVE')
                """, agent, workspace, "b-gw-registry-" + agent);
        db.update("""
                insert into agent_releases(id,agent_id,version,business_purpose,manifest_schema_version,
                    manifest_json,agent_artifact_fingerprint,release_fingerprint,lifecycle_state,effective_status)
                values (?,?,'1.0','LOAN_DOCUMENT_COMPLETENESS_REVIEW','1.0',
                    '{}'::jsonb,?,?,'DRAFT','DRAFT')
                """, release, agent, HASH, fingerprint);
        int ordinal = 0;
        for (ToolSpec tool : tools) {
            UUID definition = UUID.randomUUID();
            db.update("""
                    insert into tool_definitions(id,tool_key,version,operation,input_schema_json,
                        output_schema_json,description,trust_level,risk_level,
                        data_classifications_json,side_effect_type,adapter_key,
                        schema_hash,description_hash)
                    values (?,?,?,'READ','{}'::jsonb,'{}'::jsonb,'Synthetic registry test',?,
                        'LOW','[]'::jsonb,'NONE',?,?,?)
                    """, definition, tool.name(), tool.version(), tool.trust(),
                    tool.name().toLowerCase(), tool.schemaDigest(), tool.descriptionDigest());
            db.update("""
                    insert into release_tools(release_id,tool_definition_id,enabled,ordinal)
                    values (?,?,?,?)
                    """, release, definition, tool.enabled(), ordinal++);
        }
        db.update("""
                update agent_releases set lifecycle_state = 'ANALYZED', effective_status = 'ANALYZED'
                 where id = ?
                """, release);
        db.update("""
                insert into test_suites(id,workspace_id,suite_key,version,fixture_version,
                    generation_config_json,suite_hash,status)
                values (?,?,?,'1.0','golden-v1','{}'::jsonb,?,'BUILDING')
                """, suite, workspace, "b-gw-registry-suite-" + suite, HASH);
        db.update("""
                insert into test_cases(id,suite_id,case_key,case_type,partition_name,category,
                    severity,delivery_channel,target_tool,payload_hash,preconditions_json,
                    expected_invariant,oracle_type,generation_source,expected_result_json,trial_policy_json)
                values (?,?,'NORMAL-1','NORMAL','NORMAL','NORMAL','LOW','DIRECT',
                    'CUSTOMER_DATA_READ',?,'{"caseId":"CASE-1001","currentApplicantId":"CUST-1001"}'::jsonb,
                    'INV-NORMAL','NORMAL_TASK','CURATED','{}'::jsonb,'{}'::jsonb)
                """, testCase, suite, HASH);
        db.update("update test_suites set status = 'READY' where id = ?", suite);
        UUID run = runs.register(new TestRunPersistenceDto.RegisterRequest(
                release, suite, null, TestRunMode.BASELINE, UUID.randomUUID(),
                json.createObjectNode(), fixtures.fixtureDigest(), HASH, 42L, 1), ACTOR).runId();
        events.append(run, new ExecutionEventDto.AppendRequest(null, trace,
                ExecutionEventType.RUN_STARTED, null, null, null, null,
                "GATEWAY_REGISTRY_TEST", json.createObjectNode()), ACTOR);
        runs.updateStatus(run, new TestRunPersistenceDto.StatusRequest(
                TestRunStatus.PREPARING, 0, 0, null), ACTOR);
        fixtures.createOrReset(run);
        runs.updateStatus(run, new TestRunPersistenceDto.StatusRequest(
                TestRunStatus.RUNNING, 0, 0, null), ACTOR);
        UUID caseRun = runs.registerCase(run,
                new TestRunPersistenceDto.CaseRunRegisterRequest(testCase, 0, HASH), ACTOR).id();
        runs.updateCaseStatus(run, caseRun, new TestRunPersistenceDto.CaseRunStatusRequest(
                TestCaseRunStatus.EXECUTING, null, null, null, null, null, null), ACTOR);
        var arguments = json.createObjectNode();
        arguments.putArray("customerIds").add("CUST-1001");
        arguments.putArray("fields").add("incomeBand");
        ExecutionEventDto.Event proposal = events.append(run,
                new ExecutionEventDto.AppendRequest(caseRun, trace, ExecutionEventType.TOOL_PROPOSED,
                        "CUSTOMER_DATA_READ", arguments, null, null,
                        "STRUCTURED_TOOL_PROPOSAL", json.createObjectNode()), ACTOR);
        return new Seed(workspace, release, run, caseRun, trace, fingerprint, tools,
                new InvocationKey(run, caseRun, trace, proposal.eventId(), proposal.payloadDigest()));
    }

    private Map<String, String> businessState(UUID runId) {
        Map<String, String> values = new LinkedHashMap<>();
        for (String table : BUSINESS_TABLES) {
            values.put(table, db.queryForObject("select coalesce(jsonb_agg(to_jsonb(t) "
                    + "order by to_jsonb(t)::text)::text, '[]') from " + table
                    + " t where namespace_id = ?", String.class, runId));
        }
        return Map.copyOf(values);
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
                .hasMessage("Stored Gateway Tool registry is incomplete")
                .hasNoCause();
    }

    private record ToolSpec(String name, String version, String trust, String schemaDigest,
                            String descriptionDigest, boolean enabled) {
        ToolRegistryEntry entry() {
            return new ToolRegistryEntry(name, version, TrustLevel.valueOf(trust),
                    schemaDigest, descriptionDigest);
        }
    }

    private record Seed(UUID workspaceId, UUID releaseId, UUID runId, UUID caseRunId, UUID traceId,
                        String fingerprint, List<ToolSpec> tools, InvocationKey key) { }
}
