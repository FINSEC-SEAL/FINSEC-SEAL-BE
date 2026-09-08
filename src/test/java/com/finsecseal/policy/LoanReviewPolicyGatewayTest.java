package com.finsecseal.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.finsecseal.agent.AgentEntity;
import com.finsecseal.agent.AgentService;
import com.finsecseal.audit.AuditService;
import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.ReleaseLifecycleState;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.contract.LoanReviewFinancialTemplate;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter;
import com.finsecseal.contract.SafetyContractCanonicalizer;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.contract.SafetyContractSchemaValidator;
import com.finsecseal.contract.SafetyContractSemanticValidator;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventDto.AppendRequest;
import com.finsecseal.evidence.ExecutionEventDto.Event;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.evidence.RedactionService;
import com.finsecseal.evidence.TestRunDto.Projection;
import com.finsecseal.evidence.TestRunPersistenceDto.CaseRun;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.evidence.TestRunProjectionService;
import com.finsecseal.platform.contract.ContractPersistenceService;
import com.finsecseal.platform.contract.ContractPersistenceService.ApprovedContract;
import com.finsecseal.platform.contract.ContractPersistenceService.Version;
import com.finsecseal.policy.EnforcePolicyPostCallDecision.PostCallCheck;
import com.finsecseal.policy.GatewayRuntimeObservations.Completion;
import com.finsecseal.policy.GatewayRuntimeObservations.InvocationKey;
import com.finsecseal.policy.GatewayRuntimeObservations.NamespaceObservation;
import com.finsecseal.policy.GatewayRuntimeObservations.PreCall;
import com.finsecseal.policy.GatewayRuntimeObservations.RegistryObservation;
import com.finsecseal.policy.GatewayRuntimeObservations.StateCapture;
import com.finsecseal.policy.GatewayRuntimeObservations.StateChange;
import com.finsecseal.policy.GatewayRuntimeObservations.StateEntity;
import com.finsecseal.policy.LoanReviewPolicyGateway.FailureCode;
import com.finsecseal.policy.LoanReviewPolicyGateway.GatewayException;
import com.finsecseal.policy.PolicyToolTrustFacts.ToolRegistryEntry;
import com.finsecseal.policy.PolicyToolTrustFacts.TrustLevel;
import com.finsecseal.release.AgentReleaseEntity;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.FingerprintService;
import com.finsecseal.release.ReleaseDto.ToolCatalogResponse;
import com.finsecseal.release.ReleaseService;
import com.finsecseal.runtime.ToolInvocation;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.runtime.ToolProposalValidator;
import com.finsecseal.sandbox.SandboxExecutionContext;
import com.finsecseal.sandbox.tool.PolicyGateway.GatewayResult;
import com.finsecseal.sandbox.tool.CustomerDataReadToolAdapter;
import com.finsecseal.sandbox.tool.StateChangingToolExecutionService;
import com.finsecseal.sandbox.tool.ToolAdapter;
import com.finsecseal.sandbox.tool.ToolEffect;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.transaction.support.DefaultTransactionStatus;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/** Real C composition and A digest checking over mocked owners; commit recording is not PostgreSQL evidence. */
@ExtendWith(OutputCaptureExtension.class)
class LoanReviewPolicyGatewayTest {
    private static final UUID WORKSPACE = UUID.randomUUID(), RELEASE = UUID.randomUUID(), AGENT = UUID.randomUUID();
    private static final UUID RUN = UUID.randomUUID(), CASE_RUN = UUID.randomUUID(), TEST_CASE = UUID.randomUUID();
    private static final UUID VERSION = UUID.randomUUID(), TRACE = UUID.randomUUID(), CALL = UUID.randomUUID(), CAPTURE = UUID.randomUUID();
    private static final String ACTOR = "gateway-unit-reviewer", TOOL = "CUSTOMER_DATA_READ", PURPOSE = LoanReviewFinancialTemplate.PURPOSE;
    private static final String HASH = "sha256:" + "a".repeat(64), ARTIFACT = "sha256:" + "b".repeat(64), FINGERPRINT = "sha256:" + "c".repeat(64);
    private static final String CASE = "CASE-1001", CUSTOMER = "CUST-1001", PRIVATE = "GATEWAY-PRIVATE-SQL-PROMPT-CANARY";
    private static final ReviewerContext REVIEWER = new ReviewerContext(WORKSPACE, ACTOR, "AI_SECURITY_REVIEWER", PRIVATE, true, true, false);
    // Independent specification literals: never derive expected order or enforcement from production helpers.
    private static final List<String> FULL_ORDER = List.of("PREFLIGHT", "TOOL", "OPERATION", "BUSINESS_CONTEXT",
            "OBJECT_SCOPE", "FIELD_SCOPE", "CARDINALITY", "EGRESS", "WORKFLOW", "HUMAN_BOUNDARY", "TOOL_TRUST");
    private static final List<String> BASELINE_PASS_ROWS = List.of(
            "PREFLIGHT|PASS|ENFORCED|-", "TOOL|PASS|ENFORCED|-", "OPERATION|PASS|ENFORCED|-",
            "BUSINESS_CONTEXT|PASS|ENFORCED|-", "OBJECT_SCOPE|PASS|OBSERVED|-", "FIELD_SCOPE|PASS|OBSERVED|-",
            "CARDINALITY|PASS|OBSERVED|-", "EGRESS|PASS|OBSERVED|-", "WORKFLOW|PASS|ENFORCED|-",
            "HUMAN_BOUNDARY|PASS|OBSERVED|-", "TOOL_TRUST|PASS|ENFORCED|-");
    private static final List<String> BASELINE_FIELD_ROWS = List.of(
            "PREFLIGHT|PASS|ENFORCED|-", "TOOL|PASS|ENFORCED|-", "OPERATION|PASS|ENFORCED|-",
            "BUSINESS_CONTEXT|PASS|ENFORCED|-", "OBJECT_SCOPE|PASS|OBSERVED|-", "FIELD_SCOPE|DENY|OBSERVED|FIELD_SCOPE_VIOLATION",
            "CARDINALITY|SKIPPED|OBSERVED|-", "EGRESS|SKIPPED|OBSERVED|-", "WORKFLOW|PASS|ENFORCED|-",
            "HUMAN_BOUNDARY|SKIPPED|OBSERVED|-", "TOOL_TRUST|PASS|ENFORCED|-");
    private final ObjectMapper json = new ObjectMapper();
    private final CanonicalJsonService canonical = new CanonicalJsonService(json);
    private final DigestService digests = new DigestService();
    private final RedactionService redaction = new RedactionService(json, canonical, digests, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    private final JdbcTemplate jdbc = mock(JdbcTemplate.class);
    private final TestRunProjectionService runs = mock(TestRunProjectionService.class);
    private final TestRunPersistenceService cases = mock(TestRunPersistenceService.class);
    private final ContractPersistenceService contracts = mock(ContractPersistenceService.class);
    private final ReleaseService releases = mock(ReleaseService.class);
    private final AgentService agents = mock(AgentService.class);
    private final GatewayRuntimeObservations observations = mock(GatewayRuntimeObservations.class);
    private final StateChangingToolExecutionService mutations = mock(StateChangingToolExecutionService.class);
    private final ToolAdapter adapter = mock(ToolAdapter.class);
    private final List<Event> committed = new ArrayList<>(), pending = new ArrayList<>();
    private final List<Duration> deadlines = new ArrayList<>();
    private final RecordingTransactions transactions = new RecordingTransactions();
    private ExecutionEventService events;
    private GatewayApprovedPolicySourceService approved;
    private GatewayBaselinePolicySourceService baseline;
    private GatewayPolicyFactsAssembler facts;
    private AgentReleaseEntity release;
    private ObjectNode manifest, policy, args, output;
    private SandboxExecutionContext context;
    private ToolInvocation invocation;
    private InvocationKey key;
    private TestRunMode mode;
    private int executions;
    private Supplier<ReviewerContext> reviewers = () -> REVIEWER;

    @BeforeEach
    void setup() throws Exception {
        manifest = resource("/fixtures/valid-release-manifest-v1.1.json");
        policy = resource("/fixtures/loan-review-safety-contract.json");
        ((ObjectNode) manifest.path("systemPrompt")).put("text", PRIVATE);
        release = mock(AgentReleaseEntity.class);
        when(release.getId()).thenReturn(RELEASE);
        when(release.getAgentId()).thenReturn(AGENT);
        when(release.getManifestSchemaVersion()).thenReturn("1.1");
        when(release.getAgentArtifactFingerprint()).thenReturn(ARTIFACT);
        when(release.getReleaseFingerprint()).thenReturn(FINGERPRINT);
        when(release.getBusinessPurpose()).thenReturn(PURPOSE);
        when(release.getManifestJson()).thenReturn(manifest);
        when(release.getAnalyzedAt()).thenReturn(Instant.parse("2026-09-08T00:00:00Z"));
        when(release.getLifecycleState()).thenReturn(ReleaseLifecycleState.ANALYZED);
        when(releases.getRequired(RELEASE)).thenReturn(release);
        var agent = mock(AgentEntity.class);
        when(agent.getId()).thenReturn(AGENT);
        when(agent.getWorkspaceId()).thenReturn(WORKSPACE);
        when(agents.getRequired(AGENT)).thenReturn(agent);
        String serverHash = new FingerprintService(canonical, digests, json).fingerprint(manifest, null)
                .componentDigests().get("serverToolCatalogHash");
        when(releases.toolCatalog(RELEASE, ACTOR)).thenReturn(new ToolCatalogResponse(RELEASE, "1.1", ARTIFACT,
                FINGERPRINT, serverHash, manifest.path("tools"), manifest.path("serverToolCatalog")));
        var catalogs = new ReleaseToolCatalogContractAdapter(releases, canonical, digests, json);
        var schema = new SafetyContractSchemaValidator();
        var canonicalizer = new SafetyContractCanonicalizer(schema, canonical, digests);
        var version = new Version(VERSION, WORKSPACE, RELEASE, policy.path("contractId").stringValue(), 1, "APPROVED", policy,
                canonicalizer.canonicalizeAndHash(policy).policyHash(), HASH, null,
                json.createObjectNode().put("status", "VALID"), json.createObjectNode().put("decision", "APPROVED"));
        when(contracts.approved(RELEASE, VERSION, REVIEWER)).thenReturn(new ApprovedContract(version, ARTIFACT, FINGERPRINT));
        when(runs.find(RUN)).thenAnswer(call -> projection(mode, FINGERPRINT));
        when(cases.findCase(CASE_RUN)).thenReturn(new CaseRun(CASE_RUN, RUN, TEST_CASE, 0, TestCaseRunStatus.EXECUTING,
                null, null, HASH, null, null, null, json.createObjectNode()));
        approved = spy(new GatewayApprovedPolicySourceService(runs, contracts, cases, catalogs,
                new SafetyContractSemanticValidator(schema), canonicalizer));
        baseline = spy(new GatewayBaselinePolicySourceService(runs, cases, catalogs, releases, agents));
        events = spy(new ExecutionEventService(jdbc, json, redaction, canonical, digests, mock(AuditService.class)));
        doAnswer(call -> {
            AppendRequest request = call.getArgument(1);
            Event event = event(UUID.randomUUID(), request, committed.size() + pending.size() + 1);
            if (TransactionSynchronizationManager.isActualTransactionActive()) pending.add(event);
            else committed.add(event);
            return event;
        }).when(events).append(any(), any(), any());
        doAnswer(call -> proposalEvent()).when(events).findById(CALL);
        when(adapter.toolName()).thenAnswer(call -> invocation.proposal().toolName());
        when(adapter.effect()).thenReturn(ToolEffect.READ_ONLY);
        doAnswer(call -> {
            executions++;
            assertThat(committed).extracting(Event::eventType).contains(ExecutionEventType.POLICY_EVALUATED, ExecutionEventType.TOOL_REQUEST);
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            return new ToolAdapter.ToolExecutionResult(output, false);
        }).when(adapter).execute(any(), any());
        facts = new GatewayPolicyFactsAssembler(new ToolProposalValidator(json,
                List.of(new CustomerDataReadToolAdapter(jdbc, json))));
        when(observations.resolve(any(), any())).thenAnswer(call -> { deadline(call.getArgument(1)); return preCall(namespace()); });
        when(observations.registry(any(), any())).thenAnswer(call -> { deadline(call.getArgument(1)); return new RegistryObservation(key, FINGERPRINT, registry()); });
        when(observations.begin(any(), any())).thenAnswer(call -> { deadline(call.getArgument(1)); return capture(); });
        when(observations.complete(any(), any(), any())).thenAnswer(call -> { deadline(call.getArgument(2)); return completion(); });
        configure(TestRunMode.SEAL_REPLAY, TOOL, customerArguments());
        clearInvocations(runs, cases, contracts, releases, agents, observations, adapter, events);
    }

    @AfterEach
    void noSqlOrRuntimeLifecycleAndNoRawErrors(CapturedOutput captured) {
        verifyNoInteractions(jdbc);
        verify(cases, never()).updateStatus(any(), any(), any());
        verify(cases, never()).updateCaseStatus(any(), any(), any(), any());
        assertThat(captured.getAll()).doesNotContain(PRIVATE);
        assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
        assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isFalse();
    }

    @ParameterizedTest @EnumSource(value = TestRunMode.class, names = {"BASELINE", "SEAL_REPLAY"})
    void safeReadUsesRealSourcesAndCommitsDecisionAndRequestBeforeCallingAdapter(TestRunMode selected) {
        configure(selected, TOOL, customerArguments());
        output.put("status", new BigDecimal("200.0")); // Schema's mathematical integer remains compatible with the customer guard.
        String expectedInputDigest = redaction.redact(args.deepCopy()).originalDigest();
        String expectedContextDigest = redaction.redact(json.valueToTree(preCall(namespace()))).originalDigest();
        String expectedPolicyHash = new SafetyContractCanonicalizer(new SafetyContractSchemaValidator(), canonical, digests)
                .canonicalizeAndHash(policy.deepCopy()).policyHash();
        GatewayResult result = gateway().invoke(context, invocation, ACTOR);
        assertThat(result.policyDecision().allowed()).isTrue();
        assertThat(result.execution().output()).isEqualTo(output);
        assertThat(executions).isEqualTo(1);
        assertThat(committed).extracting(Event::eventType).containsExactly(ExecutionEventType.POLICY_EVALUATED,
                ExecutionEventType.TOOL_REQUEST, ExecutionEventType.TOOL_RESPONSE);
        assertThat(result.responseEvent().metadata().path("deliveredToAgent").booleanValue()).isFalse();
        assertThat(result.responseEvent().metadata().path("deliveryState").stringValue()).isEqualTo("PENDING");
        assertThat(result.policyEvent().policyDecision().path("evaluationMode").stringValue())
                .isEqualTo(selected == TestRunMode.BASELINE ? "BASELINE" : "ENFORCE");
        assertThat(result.policyEvent().metadata().path("policyReference").stringValue())
                .isEqualTo(selected == TestRunMode.BASELINE ? LoanReviewFinancialTemplate.KEY : VERSION.toString());
        JsonNode decision = result.policyEvent().policyDecision();
        JsonNode metadata = result.policyEvent().metadata();
        assertThat(decision.path("allowed").booleanValue()).isTrue();
        assertThat(decision.path("decisionType").stringValue()).isEqualTo("ALLOW");
        assertThat(decision.path("successfulSecurityBlock").booleanValue()).isFalse();
        assertThat(decision.has("failedStage")).isFalse();
        assertThat(decision.has("failedCheck")).isFalse();
        assertThat(decision.path("inputDigest").stringValue()).isEqualTo(expectedInputDigest).isNotEqualTo(invocation.requestDigest());
        assertThat(decision.path("contextDigest").stringValue()).isEqualTo(expectedContextDigest);
        assertThat(metadata.path("contextDigest").stringValue()).isEqualTo(expectedContextDigest);
        assertThat(decision.path("releaseFingerprint").stringValue()).isEqualTo(FINGERPRINT);
        assertThat(metadata.path("releaseFingerprint").stringValue()).isEqualTo(FINGERPRINT);
        assertThat(metadata.path("toolCallId").stringValue()).isEqualTo(CALL.toString());
        assertThat(metadata.path("mode").stringValue()).isEqualTo(selected.name());
        assertThat(decision.path("schemaVersion").stringValue()).isEqualTo("1.0");
        assertThat(UUID.fromString(decision.path("decisionId").stringValue())).isNotNull();
        assertThat(Instant.parse(decision.path("evaluatedAt").stringValue())).isNotNull();
        assertThat(decision.path("durationMs").isNumber()).isTrue();
        assertThat(Double.isFinite(decision.path("durationMs").doubleValue())).isTrue();
        assertThat(decision.path("durationMs").doubleValue()).isGreaterThanOrEqualTo(0.0);
        assertThat(metadata.path("evaluationDurationNanos").isIntegralNumber()).isTrue();
        assertThat(metadata.path("evaluationDurationNanos").longValue()).isGreaterThanOrEqualTo(0L);
        if (selected == TestRunMode.BASELINE) {
            assertBaselineRows(decision, BASELINE_PASS_ROWS);
            assertThat(decision.path("reasonCode").stringValue()).isEqualTo("BASELINE_ALLOW");
            assertThat(decision.has("observedReasonCode")).isFalse();
            assertThat(decision.has("observedFailedStage")).isFalse();
            assertThat(decision.has("policyVersionId")).isFalse();
            assertThat(decision.has("policyHash")).isFalse();
            assertThat(metadata.has("contractVersionId")).isFalse();
            assertThat(metadata.has("policyHash")).isFalse();
        } else {
            assertEnforceOrder(decision, FULL_ORDER, null);
            assertThat(decision.path("reasonCode").stringValue()).isEqualTo("ALLOW");
            assertThat(decision.path("policyVersionId").stringValue()).isEqualTo(VERSION.toString());
            assertThat(metadata.path("contractVersionId").stringValue()).isEqualTo(VERSION.toString());
            assertThat(decision.path("policyHash").stringValue()).isEqualTo(expectedPolicyHash);
            assertThat(metadata.path("policyHash").stringValue()).isEqualTo(expectedPolicyHash);
        }
        verify(events).matchesToolProposalPayloadDigest(any(), any());
        verify(observations).registry(any(), any());
        assertThat(deadlines).isNotEmpty().allSatisfy(value -> assertThat(value.toNanos()).isBetween(1L, Duration.ofSeconds(5).toNanos()));
        assertThat(transactions.definitions).hasSize(3).allSatisfy(value -> {
            assertThat(value.getIsolationLevel()).isEqualTo(TransactionDefinition.ISOLATION_REPEATABLE_READ);
            assertThat(value.getTimeout()).isEqualTo(5);
            assertThat(value.isReadOnly()).isFalse();
        });
        verifyNoInteractions(mutations);
    }

    @ParameterizedTest @MethodSource("namespaceFailures")
    void namespacePreflightFailuresInBothModesProduceNoPolicyOrExecutionEvents(TestRunMode selected, String problem) {
        configure(selected, TOOL, customerArguments());
        doAnswer(call -> {
            if (problem.equals("missing")) return null;
            if (problem.equals("null-namespace")) return preCall(null);
            return preCall(new NamespaceObservation(problem.equals("namespace") ? UUID.randomUUID() : RUN,
                    problem.equals("version") ? "other-fixture" : problem.equals("bad-version") ? " fixture/1 " : "fixture/1",
                    problem.equals("digest") ? ARTIFACT : problem.equals("bad-digest") ? PRIVATE : HASH,
                    problem.equals("inactive") ? "EXPIRED" : problem.equals("unknown-state") ? "OTHER" : "ACTIVE"));
        }).when(observations).resolve(any(), any());
        safe(catchThrowable(() -> gateway().invoke(context, invocation, ACTOR)), FailureCode.INVALID_OBSERVATION);
        assertNoExecutionOrEvents();
        verify(observations, never()).registry(any(), any());
        verify(observations, never()).begin(any(), any());
        verify(observations, never()).complete(any(), any(), any());
    }

    @ParameterizedTest @EnumSource(value = TestRunMode.class, names = {"BASELINE", "SEAL_REPLAY"})
    void authenticatedSecondRunReadMustStillMatchSourceFingerprint(TestRunMode selected) {
        configure(selected, TOOL, customerArguments());
        when(runs.find(RUN)).thenReturn(projection(selected, FINGERPRINT), projection(selected, ARTIFACT));
        safe(catchThrowable(() -> gateway().invoke(context, invocation, ACTOR)), FailureCode.SOURCE_BINDING_INVALID);
        assertNoExecutionOrEvents();
    }

    @ParameterizedTest @MethodSource("duplicateCustomerRequests")
    void duplicateRequestValuesFailPreflightBeforeForeignCustomerPolicyInBothModes(
            TestRunMode selected, String duplicateArray, CapturedOutput logs) {
        ObjectNode request = customerArguments();
        request.putArray("customerIds").add("CUST-FOREIGN-" + PRIVATE);
        if (duplicateArray.equals("customerIds")) {
            ((ArrayNode) request.path("customerIds")).add("CUST-FOREIGN-" + PRIVATE);
        } else {
            request.putArray("fields").add("incomeBand").add("incomeBand");
        }
        configure(selected, TOOL, request);
        String originalRequest = request.toString();

        Throwable error = catchThrowable(() -> gateway().invoke(context, invocation, ACTOR));

        safe(error, FailureCode.POLICY_EVALUATION_FAILED);
        GatewayException failure = (GatewayException) error;
        assertThat(failure.reason()).contains(PolicyEvaluationReason.INVALID_REQUEST_SCHEMA);
        assertThat(failure.postCallCheck()).isEmpty();
        assertThat(failure.successfulSecurityBlock()).isFalse();
        assertThat(committed).extracting(Event::eventType).containsExactly(ExecutionEventType.POLICY_EVALUATED);
        JsonNode decision = committed.getFirst().policyDecision();
        assertThat(decision.path("evaluationMode").stringValue())
                .isEqualTo(selected == TestRunMode.BASELINE ? "BASELINE" : "ENFORCE");
        assertThat(decision.path("allowed").booleanValue()).isFalse();
        assertThat(decision.path("decisionType").stringValue()).isEqualTo("ERROR");
        assertThat(decision.path("reasonCode").stringValue()).isEqualTo("INVALID_REQUEST_SCHEMA");
        assertThat(decision.path("failedStage").stringValue()).isEqualTo("PREFLIGHT");
        assertThat(decision.path("failedCheck").stringValue()).isEqualTo("PREFLIGHT");
        assertThat(decision.path("successfulSecurityBlock").booleanValue()).isFalse();
        assertThat(decision.has("observedReasonCode")).isFalse();
        assertThat(decision.has("observedFailedStage")).isFalse();
        if (selected == TestRunMode.BASELINE) {
            assertBaselineRows(decision, List.of("PREFLIGHT|ERROR|ENFORCED|INVALID_REQUEST_SCHEMA"));
        } else {
            assertEnforceOrder(decision, List.of("PREFLIGHT"), "PREFLIGHT");
        }
        assertThat(decision.toString()).doesNotContain(PRIVATE, "CUST-FOREIGN-", "incomeBand");
        assertThat(committed.getFirst().metadata().toString()).doesNotContain(PRIVATE, "CUST-FOREIGN-");
        assertThat(logs.getAll()).doesNotContain(PRIVATE, "CUST-FOREIGN-");
        assertThat(request.toString()).isEqualTo(originalRequest);
        assertNoAdapter();
        verify(observations, never()).registry(any(), any());
        verify(observations, never()).begin(any(), any());
        verify(observations, never()).complete(any(), any(), any());
        verifyNoInteractions(mutations);
    }

    @ParameterizedTest @ValueSource(strings = {"unknown", "customer", "field", "human"})
    void earlierEnforceDenialKeepsExactPrefixAndDoesNotReadRegistry(String boundary) {
        ObjectNode request = customerArguments();
        String name = TOOL;
        String reason = "CUSTOMER_SCOPE_VIOLATION";
        switch (boundary) {
            case "unknown" -> { name = "A".repeat(100); reason = "TOOL_NOT_ALLOWED"; }
            case "customer" -> request.putArray("customerIds").add("CUST-OTHER");
            case "field" -> { request.putArray("fields").add("accountNumber"); reason = "FIELD_SCOPE_VIOLATION"; }
            case "human" -> { name = "LOAN_DECISION_UPDATE"; request = json.createObjectNode().put("caseId", CASE).put("decision", "APPROVED"); reason = "HUMAN_ONLY_ACTION"; }
            default -> throw new IllegalArgumentException(boundary);
        }
        configure(TestRunMode.SEAL_REPLAY, name, request);
        var result = gateway().invoke(context, invocation, ACTOR);
        assertThat(result.policyDecision().allowed()).isFalse();
        assertThat(result.policyDecision().reasonCode()).isEqualTo(reason);
        assertThat(result.policyEvent().policyDecision().path("successfulSecurityBlock").booleanValue()).isTrue();
        JsonNode decision = result.policyEvent().policyDecision();
        assertThat(decision.path("allowed").booleanValue()).isFalse();
        assertThat(decision.path("decisionType").stringValue()).isEqualTo("DENY");
        assertThat(decision.path("reasonCode").stringValue()).isEqualTo(reason);
        switch (boundary) {
            case "unknown" -> assertEnforceOrder(decision, List.of("PREFLIGHT", "TOOL"), "TOOL");
            case "customer" -> assertEnforceOrder(decision, List.of("PREFLIGHT", "TOOL", "OPERATION", "BUSINESS_CONTEXT", "OBJECT_SCOPE"), "OBJECT_SCOPE");
            case "field" -> assertEnforceOrder(decision, List.of("PREFLIGHT", "TOOL", "OPERATION", "BUSINESS_CONTEXT", "OBJECT_SCOPE", "FIELD_SCOPE"), "FIELD_SCOPE");
            case "human" -> assertEnforceOrder(decision, List.of("PREFLIGHT", "TOOL", "OPERATION", "BUSINESS_CONTEXT", "OBJECT_SCOPE",
                    "FIELD_SCOPE", "CARDINALITY", "EGRESS", "WORKFLOW", "HUMAN_BOUNDARY"), "HUMAN_BOUNDARY");
            default -> throw new IllegalArgumentException(boundary);
        }
        assertThat(result.execution()).isNull();
        assertThat(committed).extracting(Event::eventType).containsExactly(ExecutionEventType.POLICY_EVALUATED);
        verify(observations, never()).registry(any(), any());
        verify(observations, never()).begin(any(), any());
        verify(observations, never()).complete(any(), any(), any());
        verifyNoInteractions(mutations);
        assertNoAdapter();
    }

    @ParameterizedTest @ValueSource(strings = {"accountNumber", "unknownField"})
    void baselineObservesFieldViolationWithoutFabricatingAnEnforceDenial(String field) {
        ObjectNode request = customerArguments();
        request.putArray("fields").add(field);
        configure(TestRunMode.BASELINE, TOOL, request);
        output.putArray("rows"); // The actual schema permits an empty response; no unknown output fields are invented.
        var result = gateway().invoke(context, invocation, ACTOR);
        assertThat(result.policyDecision().allowed()).isTrue();
        JsonNode decision = result.policyEvent().policyDecision();
        assertThat(decision.path("observedReasonCode").stringValue()).isEqualTo("FIELD_SCOPE_VIOLATION");
        assertThat(decision.path("observedFailedStage").stringValue()).isEqualTo("FIELD_SCOPE");
        assertThat(decision.path("allowed").booleanValue()).isTrue();
        assertThat(decision.path("decisionType").stringValue()).isEqualTo("ALLOW");
        assertThat(decision.path("reasonCode").stringValue()).isEqualTo("BASELINE_ALLOW");
        assertThat(decision.path("successfulSecurityBlock").booleanValue()).isFalse();
        assertThat(decision.has("failedStage")).isFalse();
        assertThat(decision.has("failedCheck")).isFalse();
        assertBaselineRows(decision, BASELINE_FIELD_ROWS);
        assertThat(executions).isEqualTo(1);
        verify(observations).registry(any(), any());
    }

    @ParameterizedTest @MethodSource("nonemptyBaselineBusinessResponses")
    void baselinePreservesNonemptyBusinessViolatingResponsesAndObservesFirstPostCallFailure(
            String scenario, String expectedCheck, String expectedReason) {
        ObjectNode request = customerArguments();
        String returnedCustomer = scenario.equals("object") ? "CUST-OTHER" : CUSTOMER;
        request.putArray("customerIds").add(returnedCustomer);
        if (!scenario.equals("cardinality")) request.putArray("fields").add("accountNumber");
        configure(TestRunMode.BASELINE, TOOL, request);
        // Explicitly synthetic schema-valid output, not an assertion about normal B adapter behavior.
        ArrayNode rows = output.putArray("rows");
        for (int index = 0; index < 2; index++) {
            ObjectNode fields = rows.addObject().put("customerId", returnedCustomer).putObject("fields");
            if (scenario.equals("cardinality")) {
                fields.put("incomeBand", PRIVATE).put("employmentStatus", "EMPLOYED");
            } else {
                fields.put("accountNumber", PRIVATE);
            }
        }
        ObjectNode originalOutput = output.deepCopy();
        String originalJson = output.toString();
        StateCapture before = capture();
        Completion after = completion();
        doAnswer(call -> {
            assertThat(call.<InvocationKey>getArgument(0)).isEqualTo(key);
            deadline(call.getArgument(1));
            return before;
        }).when(observations).begin(any(), any());
        doAnswer(call -> {
            assertThat(call.<InvocationKey>getArgument(0)).isEqualTo(key);
            assertThat(call.<StateCapture>getArgument(1)).isSameAs(before);
            deadline(call.getArgument(2));
            return after;
        }).when(observations).complete(any(), any(), any());

        GatewayResult result = gateway().invoke(context, invocation, ACTOR);

        assertThat(result.policyDecision().allowed()).isTrue();
        assertThat(result.policyDecision().reasonCode()).isEqualTo("BASELINE_ALLOW");
        JsonNode decision = result.policyEvent().policyDecision();
        assertThat(decision.path("decisionType").stringValue()).isEqualTo("ALLOW");
        assertThat(decision.path("allowed").booleanValue()).isTrue();
        assertThat(decision.path("successfulSecurityBlock").booleanValue()).isFalse();
        assertThat(decision.has("failedStage")).isFalse();
        assertThat(decision.has("failedCheck")).isFalse();
        assertThat(result.execution().stateChanged()).isFalse();
        assertThat(result.execution().output()).isEqualTo(originalOutput).isNotSameAs(output);
        assertThat(result.execution().output().toString()).isEqualTo(originalJson).contains(PRIVATE);
        assertThat(output).isEqualTo(originalOutput);
        assertThat(result.execution().output().path("rows").size()).isEqualTo(2);
        assertThat(invocation.proposal().arguments().path("customerIds").size()).isEqualTo(1);
        JsonNode metadata = result.responseEvent().metadata();
        assertThat(metadata.path("observedPostCall")).isEqualTo(json.createObjectNode()
                .put("check", expectedCheck).put("reasonCode", expectedReason));
        assertThat(metadata.path("deliveredToAgent").booleanValue()).isFalse();
        assertThat(metadata.path("deliveryState").stringValue()).isEqualTo("PENDING");
        assertThat(metadata.path("stateChanged").booleanValue()).isFalse();
        assertThat(result.responseEvent().output()).isEqualTo(redaction.redact(originalOutput).redacted());
        assertThat(committed).extracting(Event::eventType).containsExactly(ExecutionEventType.POLICY_EVALUATED,
                ExecutionEventType.TOOL_REQUEST, ExecutionEventType.TOOL_RESPONSE);
        assertThat(before.complete()).isTrue();
        assertThat(after.complete()).isTrue();
        assertThat(after.captureId()).isEqualTo(before.captureId());
        assertThat(after.namespaceId()).isEqualTo(before.namespaceId()).isEqualTo(RUN);
        assertThat(after.afterStateDigest()).isEqualTo(before.beforeStateDigest());
        assertThat(after.changes()).isEmpty();
        assertThat(executions).isEqualTo(1);
        verify(observations).registry(any(), any());
        verify(observations).begin(any(), any());
        verify(observations).complete(any(), any(), any());
        verifyNoInteractions(mutations);
    }

    @ParameterizedTest @ValueSource(strings = {"workflow", "trust"})
    void baselineObservedFieldFailureCannotMaskLaterEnforcedFailure(String terminal) throws Exception {
        ObjectNode request = customerArguments();
        request.putArray("fields").add("accountNumber");
        configure(TestRunMode.BASELINE, TOOL, request);
        JsonNode decision;
        if (terminal.equals("workflow")) {
            // An independent runtime fixture value, without translating IN_REVIEW into DOCUMENT_REVIEW.
            doReturn(new PreCall(key, context, namespace(), Optional.of(PURPOSE), Optional.of(PURPOSE),
                    Optional.of("IN_REVIEW"), Optional.of(List.of("DOC-1")), Optional.empty(), Optional.empty(), "READ"))
                    .when(observations).resolve(any(), any());
            GatewayResult result = gateway().invoke(context, invocation, ACTOR);
            assertThat(result.policyDecision().allowed()).isFalse();
            assertThat(result.policyDecision().reasonCode()).isEqualTo("INVALID_WORKFLOW_STAGE");
            assertThat(result.execution()).isNull();
            decision = result.policyEvent().policyDecision();
            assertThat(decision.path("decisionType").stringValue()).isEqualTo("DENY");
            assertThat(decision.path("reasonCode").stringValue()).isEqualTo("INVALID_WORKFLOW_STAGE");
            assertThat(decision.path("failedStage").stringValue()).isEqualTo("WORKFLOW");
            assertThat(decision.path("failedCheck").stringValue()).isEqualTo("WORKFLOW");
            assertThat(decision.path("successfulSecurityBlock").booleanValue()).isTrue();
            assertBaselineRows(decision, List.of(
                    "PREFLIGHT|PASS|ENFORCED|-", "TOOL|PASS|ENFORCED|-", "OPERATION|PASS|ENFORCED|-",
                    "BUSINESS_CONTEXT|PASS|ENFORCED|-", "OBJECT_SCOPE|PASS|OBSERVED|-", "FIELD_SCOPE|DENY|OBSERVED|FIELD_SCOPE_VIOLATION",
                    "CARDINALITY|SKIPPED|OBSERVED|-", "EGRESS|SKIPPED|OBSERVED|-", "WORKFLOW|DENY|ENFORCED|INVALID_WORKFLOW_STAGE"));
            verify(observations, never()).registry(any(), any());
        } else {
            doReturn(new RegistryObservation(key, ARTIFACT, registry())).when(observations).registry(any(), any());
            Throwable error = catchThrowable(() -> gateway().invoke(context, invocation, ACTOR));
            safe(error, FailureCode.POLICY_EVALUATION_FAILED);
            assertThat(((GatewayException) error).reason()).contains(PolicyEvaluationReason.TOOL_INTEGRITY_FAILURE);
            assertThat(((GatewayException) error).successfulSecurityBlock()).isFalse();
            decision = committed.getFirst().policyDecision();
            assertThat(decision.path("decisionType").stringValue()).isEqualTo("ERROR");
            assertThat(decision.path("reasonCode").stringValue()).isEqualTo("TOOL_INTEGRITY_FAILURE");
            assertThat(decision.path("failedStage").stringValue()).isEqualTo("TOOL_TRUST");
            assertThat(decision.path("failedCheck").stringValue()).isEqualTo("TOOL_TRUST");
            assertThat(decision.path("successfulSecurityBlock").booleanValue()).isFalse();
            assertBaselineRows(decision, List.of(
                    "PREFLIGHT|PASS|ENFORCED|-", "TOOL|PASS|ENFORCED|-", "OPERATION|PASS|ENFORCED|-",
                    "BUSINESS_CONTEXT|PASS|ENFORCED|-", "OBJECT_SCOPE|PASS|OBSERVED|-", "FIELD_SCOPE|DENY|OBSERVED|FIELD_SCOPE_VIOLATION",
                    "CARDINALITY|SKIPPED|OBSERVED|-", "EGRESS|SKIPPED|OBSERVED|-", "WORKFLOW|PASS|ENFORCED|-",
                    "HUMAN_BOUNDARY|SKIPPED|OBSERVED|-", "TOOL_TRUST|ERROR|ENFORCED|TOOL_INTEGRITY_FAILURE"));
            verify(observations).registry(any(), any());
        }
        assertThat(decision.path("allowed").booleanValue()).isFalse();
        assertThat(decision.path("observedReasonCode").stringValue()).isEqualTo("FIELD_SCOPE_VIOLATION");
        assertThat(decision.path("observedFailedStage").stringValue()).isEqualTo("FIELD_SCOPE");
        assertThat(committed).extracting(Event::eventType).containsExactly(ExecutionEventType.POLICY_EVALUATED);
        verify(observations, never()).begin(any(), any());
        verify(observations, never()).complete(any(), any(), any());
        verifyNoInteractions(mutations);
        assertNoAdapter();
    }

    @Test
    void returnedCardinalityFailurePreservesDedicatedConsumerCodeAndQuarantinesResponse() {
        // Both rows satisfy the real output schema, applicant scope, classifications and field projection.
        ((ArrayNode) output.path("rows")).add(output.path("rows").get(0).deepCopy());
        Throwable error = catchThrowable(() -> gateway().invoke(context, invocation, ACTOR));
        safe(error, FailureCode.RESPONSE_CARDINALITY_VIOLATION);
        assertThat(((GatewayException) error).postCallCheck()).contains(PostCallCheck.RETURNED_CARDINALITY);
        assertThat(((GatewayException) error).successfulSecurityBlock()).isFalse();
        assertThat(executions).isEqualTo(1);
        assertThat(committed).extracting(Event::eventType).containsExactly(ExecutionEventType.POLICY_EVALUATED, ExecutionEventType.TOOL_REQUEST);
        assertThat(committed.getFirst().policyDecision().path("successfulSecurityBlock").booleanValue()).isFalse();
        verify(observations).complete(any(), any(), any());
        verifyNoInteractions(mutations);
    }

    @Test
    void policyCommitFailurePreventsRequestAndAdapter() {
        transactions.failCommit = true;
        safe(catchThrowable(() -> gateway().invoke(context, invocation, ACTOR)), FailureCode.EVIDENCE_FAILURE);
        assertThat(committed).isEmpty();
        assertNoAdapter();
    }

    @Test
    void wholeProposalEnvelopeDigestMismatchFailsBeforeAnyDecision() {
        ObjectNode changed = (ObjectNode) args.deepCopy();
        changed.putArray("fields").add("accountNumber");
        var tampered = new ToolInvocation(new ToolProposal(TOOL, changed), CALL, invocation.requestDigest());
        safe(catchThrowable(() -> gateway().invoke(context, tampered, ACTOR)), FailureCode.INVALID_INVOCATION);
        assertNoExecutionOrEvents();
    }

    @Test
    void legacyProposalAndMissingReviewerDoNotCreateAnInvocationOrReadOwners() {
        safe(catchThrowable(() -> gateway().invoke(context, invocation.proposal(), ACTOR)), FailureCode.INVALID_INVOCATION);
        reviewers = () -> null;
        safe(catchThrowable(() -> gateway().invoke(context, invocation, ACTOR)), FailureCode.AUTHENTICATION_REQUIRED);
        verifyNoInteractions(runs, cases, contracts, releases, agents, observations);
        assertNoExecutionOrEvents();
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void anyAmbientTransactionOrSynchronizationIsRejectedBeforeOwners(boolean actual) {
        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(actual);
        try {
            safe(catchThrowable(() -> gateway().invoke(context, invocation, ACTOR)), FailureCode.UNSAFE_TRANSACTION);
        } finally { TransactionSynchronizationManager.clear(); }
        verifyNoInteractions(runs, cases, contracts, releases, agents, observations);
        assertNoExecutionOrEvents();
    }

    @ParameterizedTest @ValueSource(strings = {"key", "capture", "namespace", "body-digest", "incomplete", "classification", "state-digest", "foreign-change"})
    void postObservationBindingAndCoverageFailuresNeverPersistOrDeliverRawResponse(String problem) {
        doAnswer(call -> new Completion(
                problem.equals("key") ? new InvocationKey(RUN, CASE_RUN, TRACE, UUID.randomUUID(), invocation.requestDigest()) : key,
                problem.equals("capture") ? UUID.randomUUID() : CAPTURE,
                problem.equals("namespace") ? UUID.randomUUID() : RUN,
                problem.equals("body-digest") ? ARTIFACT : redaction.redact(output).originalDigest(),
                problem.equals("classification") ? classifications().put("incomeBand", "NORMAL") : classifications(),
                problem.equals("state-digest") || problem.equals("foreign-change") ? ARTIFACT : HASH,
                !problem.equals("incomplete"), problem.equals("foreign-change") ? List.of(new StateChange(StateEntity.REVIEW_NOTE,
                        UUID.randomUUID(), HASH, Optional.of(CASE), OptionalLong.empty(), OptionalLong.of(0),
                        Optional.empty(), Optional.of(ARTIFACT))) : List.of()))
                .when(observations).complete(any(), any(), any());
        Throwable error = catchThrowable(() -> gateway().invoke(context, invocation, ACTOR));
        safe(error,
                problem.equals("classification") || problem.equals("state-digest") || problem.equals("foreign-change")
                        ? FailureCode.ADAPTER_CONTRACT_FAILURE : FailureCode.INVALID_OBSERVATION);
        assertThat(((GatewayException) error).successfulSecurityBlock()).isFalse();
        if (problem.equals("classification")) {
            assertThat(((GatewayException) error).postCallCheck()).contains(PostCallCheck.CLASSIFICATION);
        }
        assertThat(executions).isEqualTo(1);
        assertThat(committed).extracting(Event::eventType).containsExactly(ExecutionEventType.POLICY_EVALUATED, ExecutionEventType.TOOL_REQUEST);
        verifyNoInteractions(mutations);
    }

    @Test
    void incompleteBeforeCaptureFailsWithoutExecutingAdapter() {
        doReturn(new StateCapture(key, CAPTURE, RUN, HASH, false)).when(observations).begin(any(), any());
        safe(catchThrowable(() -> gateway().invoke(context, invocation, ACTOR)), FailureCode.INVALID_OBSERVATION);
        assertNoAdapter();
        verify(observations, never()).complete(any(), any(), any());
    }

    @Test
    void ownerAndObservationAliasesCannotChangeCapturedPurposeSchemaRequestOrReturnedBody() {
        ObjectNode originalArgs = (ObjectNode) args.deepCopy(), originalOutput = (ObjectNode) output.deepCopy();
        doAnswer(call -> {
            PreCall observed = preCall(namespace());
            when(release.getBusinessPurpose()).thenReturn("MUTATED_PURPOSE");
            ((ObjectNode) manifest.path("businessPurpose")).put("code", "MUTATED_PURPOSE");
            for (JsonNode tool : manifest.path("tools")) {
                if (TOOL.equals(tool.path("name").stringValue())) {
                    ((ObjectNode) tool.at("/outputSchema/properties/status")).put("const", 500);
                }
            }
            return observed;
        }).when(observations).resolve(any(), any());
        doAnswer(call -> {
            executions++;
            ((ObjectNode) call.<JsonNode>getArgument(1)).removeAll();
            return new ToolAdapter.ToolExecutionResult(output, false);
        }).when(adapter).execute(any(), any());
        doAnswer(call -> {
            Completion observed = completion();
            output.removeAll();
            ((ObjectNode) policy.at("/fieldPolicy/CUSTOMER_DATA_READ")).putArray("allowed").add("accountNumber");
            return observed;
        }).when(observations).complete(any(), any(), any());
        var result = gateway().invoke(context, invocation, ACTOR);
        assertThat(release.getBusinessPurpose()).isEqualTo("MUTATED_PURPOSE");
        assertThat(manifest.at("/businessPurpose/code").stringValue()).isEqualTo("MUTATED_PURPOSE");
        for (JsonNode tool : manifest.path("tools")) {
            if (TOOL.equals(tool.path("name").stringValue())) {
                assertThat(tool.at("/outputSchema/properties/status/const").intValue()).isEqualTo(500);
            }
        }
        assertThat(result.policyDecision().allowed()).isTrue();
        assertEnforceOrder(result.policyEvent().policyDecision(), FULL_ORDER, null);
        assertThat(executions).isEqualTo(1);
        assertThat(args).isEqualTo(originalArgs);
        assertThat(result.execution().output()).isEqualTo(originalOutput);
        assertThat(result.responseEvent().output()).isEqualTo(redaction.redact(originalOutput).redacted());
    }

    @Test
    void replayedStateChangingResultIsRejectedWithoutInvokingDelegateOrAppendingResponse() {
        configure(TestRunMode.SEAL_REPLAY, "REVIEW_NOTE_WRITE", json.createObjectNode().put("caseId", CASE));
        ObjectNode review = args.putObject("reviewResult").put("reviewStatus", "READY_FOR_HUMAN_REVIEW");
        review.putArray("missingDocuments");
        review.putArray("evidence");
        bindInvocation();
        when(adapter.effect()).thenReturn(ToolEffect.STATE_CHANGING);
        when(mutations.execute(any(), any(), any(), any())).thenReturn(new StateChangingToolExecutionService.Execution(null, null, null, null, true));
        safe(catchThrowable(() -> gateway().invoke(context, invocation, ACTOR)), FailureCode.REPLAY_RESPONSE_UNAVAILABLE);
        verify(mutations).execute(any(), any(), any(), any());
        assertNoAdapter();
        assertThat(committed).extracting(Event::eventType).containsExactly(ExecutionEventType.POLICY_EVALUATED);
    }

    @Test
    void observationRecordsCopyMutableCollectionsAndClassificationTrees() {
        var documents = new ArrayList<>(List.of("DOC-1"));
        var pre = new PreCall(key, context, namespace(), Optional.of(PURPOSE), Optional.of(PURPOSE), Optional.of("DOCUMENT_REVIEW"),
                Optional.of(documents), Optional.empty(), Optional.empty(), "READ");
        ObjectNode classification = classifications();
        var complete = new Completion(key, CAPTURE, RUN, HASH, classification, HASH, true, List.of());
        documents.clear(); classification.removeAll();
        ((ObjectNode) complete.classificationMap()).removeAll();
        assertThat(pre.allowedDocumentIds()).contains(List.of("DOC-1"));
        assertThatThrownBy(() -> pre.allowedDocumentIds().orElseThrow().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThat(complete.classificationMap()).isEqualTo(classifications());
        assertThat(pre.toString() + complete).doesNotContain(CUSTOMER, PRIVATE, "FINANCIAL");
    }

    @Test
    void registryIntegrityFailureIsOperationalAndIsRecordedOnlyAtStageTen() throws Exception {
        doReturn(new RegistryObservation(key, ARTIFACT, registry())).when(observations).registry(any(), any());
        Throwable error = catchThrowable(() -> gateway().invoke(context, invocation, ACTOR));
        safe(error, FailureCode.POLICY_EVALUATION_FAILED);
        assertThat(((GatewayException) error).successfulSecurityBlock()).isFalse();
        assertThat(((GatewayException) error).reason()).contains(PolicyEvaluationReason.TOOL_INTEGRITY_FAILURE);
        assertThat(committed).extracting(Event::eventType).containsExactly(ExecutionEventType.POLICY_EVALUATED);
        JsonNode decision = committed.getFirst().policyDecision();
        assertEnforceOrder(decision, FULL_ORDER, "TOOL_TRUST");
        assertThat(decision.path("decisionType").stringValue()).isEqualTo("ERROR");
        assertThat(decision.path("reasonCode").stringValue()).isEqualTo("TOOL_INTEGRITY_FAILURE");
        assertThat(decision.path("successfulSecurityBlock").booleanValue()).isFalse();
        verify(observations).registry(any(), any());
        verify(observations, never()).begin(any(), any());
        verify(observations, never()).complete(any(), any(), any());
        verifyNoInteractions(mutations);
        assertNoAdapter();
    }

    @Test
    void observationDeadlineAndMalformedShapesFailWithSafeConsumerCodes() {
        assertThat(GatewayRuntimeObservations.requireTimeout(Duration.ofSeconds(5))).isEqualTo(Duration.ofSeconds(5));
        for (Duration timeout : new Duration[]{null, Duration.ZERO, Duration.ofMillis(-1), Duration.ofSeconds(6)}) {
            assertThatThrownBy(() -> GatewayRuntimeObservations.requireTimeout(timeout))
                    .isInstanceOfSatisfying(GatewayRuntimeObservations.ObservationException.class,
                            error -> assertThat(error.code()).isEqualTo(GatewayRuntimeObservations.FailureCode.INVALID_DEADLINE));
        }
        assertThatThrownBy(() -> new Completion(key, CAPTURE, RUN, HASH, json.createArrayNode(), HASH, true, List.of()))
                .isInstanceOf(GatewayRuntimeObservations.ObservationException.class);
        assertThatThrownBy(() -> new NamespaceObservation(RUN, "fixture/1", HASH, " ACTIVE "))
                .isInstanceOf(GatewayRuntimeObservations.ObservationException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"CUSTOMER_DATA_READ", "CASE_CONTEXT_READ", "DOCUMENT_READER", "LOAN_POLICY_SEARCH"})
    void normalReadStateScopeRequiresFalseFlagEmptyChangesAndEqualDigests(String tool) {
        var proposal = new ToolProposal(tool, json.createObjectNode());
        assertThat(permittedState(proposal, false, stateAfter(HASH, List.of()))).isTrue();
        assertThat(permittedState(proposal, true, stateAfter(HASH, List.of()))).isFalse();
        assertThat(permittedState(proposal, false, stateAfter(ARTIFACT, List.of()))).isFalse();
        assertThat(permittedState(proposal, false, stateAfter(ARTIFACT,
                List.of(stateChange(StateEntity.REVIEW_NOTE, RUN, Optional.of(CASE)))))).isFalse();
    }

    @Test
    void reviewNoteScopePermitsNoChangeAndMultipleBoundChangesWithoutCreationOrVersionInference() {
        var proposal = reviewProposal(CASE);
        assertThat(permittedState(proposal, false, stateAfter(HASH, List.of()))).isTrue();
        StateChange first = stateChange(StateEntity.REVIEW_NOTE, RUN, Optional.of(CASE));
        StateChange second = new StateChange(StateEntity.REVIEW_NOTE, RUN, ARTIFACT, Optional.of(CASE),
                OptionalLong.of(9), OptionalLong.of(12), Optional.of(HASH), Optional.of(ARTIFACT));
        // Two changes and non-unit version increments are not a claim that creation/content was verified.
        assertThat(permittedState(proposal, true, stateAfter(ARTIFACT, List.of(first, second)))).isTrue();
    }

    @ParameterizedTest
    @EnumSource(value = StateEntity.class, mode = EnumSource.Mode.EXCLUDE, names = "REVIEW_NOTE")
    void reviewNoteScopeRejectsEveryOtherBusinessEntity(StateEntity entity) {
        assertThat(permittedState(reviewProposal(CASE), true,
                stateAfter(ARTIFACT, List.of(stateChange(entity, RUN, Optional.of(CASE)))))).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"foreign-namespace", "missing-case", "different-case"})
    void reviewNoteScopeRejectsUnboundChanges(String problem) {
        StateChange change = stateChange(StateEntity.REVIEW_NOTE,
                problem.equals("foreign-namespace") ? UUID.randomUUID() : RUN,
                problem.equals("missing-case") ? Optional.empty()
                        : Optional.of(problem.equals("different-case") ? "CASE-OTHER" : CASE));
        assertThat(permittedState(reviewProposal(CASE), true, stateAfter(ARTIFACT, List.of(change)))).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"false-with-change", "false-with-digest-change", "true-with-no-change", "true-with-equal-digest"})
    void reviewNoteScopeRejectsFlagChangeAndDigestContradictions(String problem) {
        boolean reported = problem.startsWith("true");
        List<StateChange> changes = problem.equals("false-with-change") || problem.equals("true-with-equal-digest")
                ? List.of(stateChange(StateEntity.REVIEW_NOTE, RUN, Optional.of(CASE))) : List.of();
        String afterDigest = problem.equals("true-with-equal-digest") ? HASH : ARTIFACT;
        assertThat(permittedState(reviewProposal(CASE), reported, stateAfter(afterDigest, changes))).isFalse();
    }

    @Test
    void baselineObservesCurrentCaseScopeButStillBindsReviewChangesToRequestedCase() {
        var proposal = reviewProposal("CASE-OTHER");
        Completion matchingRequest = stateAfter(ARTIFACT,
                List.of(stateChange(StateEntity.REVIEW_NOTE, RUN, Optional.of("CASE-OTHER"))));
        SandboxExecutionContext baselineContext = new SandboxExecutionContext(RUN, CASE_RUN, TRACE,
                TestRunMode.BASELINE, CASE, CUSTOMER);
        assertThat(LoanReviewPolicyGateway.hasPermittedStateEffects(proposal, context, true, capture(), matchingRequest)).isFalse();
        assertThat(LoanReviewPolicyGateway.hasPermittedStateEffects(proposal, baselineContext, true, capture(), matchingRequest)).isTrue();
        assertThat(LoanReviewPolicyGateway.hasPermittedStateEffects(proposal, baselineContext, true, capture(),
                stateAfter(ARTIFACT, List.of(stateChange(StateEntity.REVIEW_NOTE, RUN, Optional.of(CASE)))))).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"before-incomplete", "after-incomplete", "key", "capture", "before-namespace",
            "after-namespace", "context-run", "context-case-run", "context-trace"})
    void stateScopeRequiresCompleteCaptureAndExactInvocationContext(String problem) {
        StateCapture before = new StateCapture(key, CAPTURE,
                problem.equals("before-namespace") ? UUID.randomUUID() : RUN, HASH, !problem.equals("before-incomplete"));
        InvocationKey observedKey = problem.equals("key")
                ? new InvocationKey(RUN, CASE_RUN, TRACE, UUID.randomUUID(), HASH) : key;
        Completion after = new Completion(observedKey, problem.equals("capture") ? UUID.randomUUID() : CAPTURE,
                problem.equals("after-namespace") ? UUID.randomUUID() : RUN, HASH, json.createObjectNode(), HASH,
                !problem.equals("after-incomplete"), List.of());
        SandboxExecutionContext observedContext = new SandboxExecutionContext(
                problem.equals("context-run") ? UUID.randomUUID() : RUN,
                problem.equals("context-case-run") ? UUID.randomUUID() : CASE_RUN,
                problem.equals("context-trace") ? UUID.randomUUID() : TRACE, mode, CASE, CUSTOMER);
        assertThat(LoanReviewPolicyGateway.hasPermittedStateEffects(
                invocation.proposal(), observedContext, false, before, after)).isFalse();
    }

    @Test
    void stateScopeDoesNotInventSupportOrMissingRequestBindings() {
        Completion after = stateAfter(HASH, List.of());
        assertThat(permittedState(new ToolProposal("UNKNOWN_TOOL", json.createObjectNode()), false, after)).isFalse();
        assertThat(permittedState(new ToolProposal("REVIEW_NOTE_WRITE", json.createObjectNode()), false, after)).isFalse();
        assertThat(permittedState(new ToolProposal("REVIEW_NOTE_WRITE", json.createObjectNode().putNull("caseId")), false, after)).isFalse();
        assertThat(permittedState(new ToolProposal("REVIEW_NOTE_WRITE", json.createObjectNode().put("caseId", 42)), false, after)).isFalse();
        assertThat(LoanReviewPolicyGateway.hasPermittedStateEffects(null, context, false, capture(), after)).isFalse();
        assertThat(LoanReviewPolicyGateway.hasPermittedStateEffects(invocation.proposal(), null, false, capture(), after)).isFalse();
        assertThat(LoanReviewPolicyGateway.hasPermittedStateEffects(invocation.proposal(), context, false, null, after)).isFalse();
        assertThat(LoanReviewPolicyGateway.hasPermittedStateEffects(invocation.proposal(), context, false, capture(), null)).isFalse();
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void actualNoncustomerReadChecksStateThenRetainsUnsupportedClassificationQuarantine(boolean stateViolation, CapturedOutput logs) {
        configure(TestRunMode.SEAL_REPLAY, "LOAN_POLICY_SEARCH", json.createObjectNode().put("query", "fixture"));
        output = json.createObjectNode();
        output.putArray("policies").addObject().put("policyId", "POLICY-1").put("version", "1.1")
                .put("productType", "fixture").put("ruleCode", "RULE-1").put("requirement", PRIVATE)
                .put("sourceTrustLevel", "TRUSTED_INTERNAL");
        doAnswer(call -> new PreCall(key, context, namespace(), Optional.of(PURPOSE), Optional.of(PURPOSE),
                Optional.of("DOCUMENT_REVIEW"), Optional.of(List.of("DOC-1")), Optional.empty(), Optional.empty(), "SEARCH"))
                .when(observations).resolve(any(), any());
        doAnswer(call -> stateAfter(stateViolation ? ARTIFACT : HASH, List.of()))
                .when(observations).complete(any(), any(), any());
        Throwable error = catchThrowable(() -> gateway().invoke(context, invocation, ACTOR));
        assertStateConsumerQuarantine(error, stateViolation, logs);
        assertThat(committed).extracting(Event::eventType).containsExactly(
                ExecutionEventType.POLICY_EVALUATED, ExecutionEventType.TOOL_REQUEST);
        verifyNoInteractions(mutations);
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void actualReviewDelegatePropagatesStateFailureAndDoesNotPromotePermittedScope(boolean foreignChange, CapturedOutput logs) {
        configure(TestRunMode.SEAL_REPLAY, "REVIEW_NOTE_WRITE", json.createObjectNode().put("caseId", CASE));
        ObjectNode review = args.putObject("reviewResult").put("reviewStatus", "READY_FOR_HUMAN_REVIEW");
        review.putArray("missingDocuments"); review.putArray("evidence");
        bindInvocation();
        output = json.createObjectNode().put("caseId", CASE).put("reviewStatus", "READY_FOR_HUMAN_REVIEW");
        output.putArray("missingDocuments");
        output.putArray("evidence").addObject().put("rule", "fixture").put("reason", PRIVATE);
        when(adapter.effect()).thenReturn(ToolEffect.STATE_CHANGING);
        doAnswer(call -> {
            executions++;
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isTrue();
            return new ToolAdapter.ToolExecutionResult(output, true);
        }).when(adapter).execute(any(), any());
        doAnswer(call -> stateAfter(ARTIFACT, List.of(stateChange(StateEntity.REVIEW_NOTE,
                foreignChange ? UUID.randomUUID() : RUN, Optional.of(CASE)))))
                .when(observations).complete(any(), any(), any());
        // Real C validating delegate over recording transactions; actual B rollback is a separate PG test.
        doAnswer(call -> new TransactionTemplate(transactions).execute(status -> {
            ToolAdapter delegate = call.getArgument(2);
            delegate.execute(call.getArgument(0), invocation.proposal().arguments().deepCopy());
            throw new AssertionError("Noncustomer classification must remain quarantined");
        })).when(mutations).execute(any(), any(), any(), any());
        Throwable error = catchThrowable(() -> gateway().invoke(context, invocation, ACTOR));
        assertStateConsumerQuarantine(error, foreignChange, logs);
        verify(mutations).execute(any(), any(), any(), any());
        assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
        assertThat(committed).extracting(Event::eventType).containsExactly(ExecutionEventType.POLICY_EVALUATED);
        assertThat(pending).isEmpty();
    }

    private boolean permittedState(ToolProposal proposal, boolean changed, Completion after) {
        return LoanReviewPolicyGateway.hasPermittedStateEffects(proposal, context, changed, capture(), after);
    }

    private ToolProposal reviewProposal(String caseId) {
        return new ToolProposal("REVIEW_NOTE_WRITE", json.createObjectNode().put("caseId", caseId));
    }

    private StateChange stateChange(StateEntity entity, UUID namespace, Optional<String> caseId) {
        return new StateChange(entity, namespace, HASH, caseId, OptionalLong.empty(), OptionalLong.empty(),
                Optional.of(HASH), Optional.of(ARTIFACT));
    }

    private Completion stateAfter(String afterDigest, List<StateChange> changes) {
        return new Completion(key, CAPTURE, RUN, redaction.redact(output).originalDigest(),
                classifications(), afterDigest, true, changes);
    }

    private void assertStateConsumerQuarantine(Throwable error, boolean stateFailure, CapturedOutput logs) {
        safe(error, FailureCode.ADAPTER_CONTRACT_FAILURE);
        GatewayException failure = (GatewayException) error;
        assertThat(failure.postCallCheck()).isEqualTo(stateFailure
                ? Optional.of(PostCallCheck.STATE_DELTA_PROVENANCE) : Optional.empty());
        assertThat(failure.successfulSecurityBlock()).isFalse();
        assertThat(executions).isEqualTo(1);
        verify(observations).complete(any(), any(), any());
        assertThat(committed).extracting(Event::eventType).doesNotContain(
                ExecutionEventType.TOOL_RESPONSE, ExecutionEventType.MODEL_REQUEST, ExecutionEventType.MODEL_RESPONSE);
        assertThat(committed.getFirst().policyDecision().path("allowed").booleanValue()).isTrue();
        assertThat(committed.getFirst().policyDecision().path("successfulSecurityBlock").booleanValue()).isFalse();
        assertThat(committed.toString()).doesNotContain(PRIVATE);
        assertThat(logs.getAll()).doesNotContain(PRIVATE);
    }

    private void assertEnforceOrder(JsonNode decision, List<String> expected, String failedStage) {
        assertThat(decision.path("evaluatedStages")).isEqualTo(json.valueToTree(expected));
        assertThat(decision.path("evaluatedChecks")).isEqualTo(json.valueToTree(expected));
        if (failedStage == null) {
            assertThat(decision.has("failedStage")).isFalse();
            assertThat(decision.has("failedCheck")).isFalse();
        } else {
            assertThat(decision.path("failedStage").stringValue()).isEqualTo(failedStage);
            assertThat(decision.path("failedCheck").stringValue()).isEqualTo(failedStage);
        }
    }

    private void assertBaselineRows(JsonNode decision, List<String> expected) {
        assertThat(decision.has("evaluatedStages")).isFalse();
        assertThat(decision.has("evaluatedChecks")).isFalse();
        assertThat(decision.path("stageOutcomes").isArray()).isTrue();
        List<String> actual = new ArrayList<>();
        for (JsonNode row : decision.path("stageOutcomes")) {
            actual.add(row.path("stage").stringValue() + "|" + row.path("outcomeType").stringValue() + "|"
                    + row.path("enforcement").stringValue() + "|" + (row.has("reasonCode") ? row.path("reasonCode").stringValue() : "-"));
        }
        assertThat(actual).containsExactlyElementsOf(expected);
    }

    private LoanReviewPolicyGateway gateway() {
        return new LoanReviewPolicyGateway(transactions, reviewers, observations, approved, baseline, runs, releases,
                facts, events, mutations, redaction, json, new LoanReviewFinancialTemplate(json), List.of(adapter));
    }

    private void configure(TestRunMode selected, String tool, ObjectNode arguments) {
        mode = selected;
        args = arguments;
        context = new SandboxExecutionContext(RUN, CASE_RUN, TRACE, mode, CASE, CUSTOMER);
        invocation = new ToolInvocation(new ToolProposal(tool, args), CALL, HASH);
        bindInvocation();
        output = json.createObjectNode().put("status", 200);
        output.putArray("rows").addObject().put("customerId", CUSTOMER).putObject("fields")
                .put("incomeBand", "MIDDLE").put("employmentStatus", "EMPLOYED");
    }

    private void bindInvocation() {
        invocation = new ToolInvocation(invocation.proposal(), CALL, proposalEvent().payloadDigest());
        key = new InvocationKey(RUN, CASE_RUN, TRACE, CALL, invocation.requestDigest());
    }

    private Projection projection(TestRunMode selected, String fingerprint) {
        return new Projection(RUN, RELEASE, UUID.randomUUID(), selected == TestRunMode.BASELINE ? null : VERSION,
                selected, TestRunStatus.RUNNING, ARTIFACT, fingerprint, "fixture/1", HASH, 1, 0, 0, 0,
                null, null, json.createObjectNode().put("private", PRIVATE), null, null, null);
    }

    private ObjectNode customerArguments() {
        ObjectNode value = json.createObjectNode();
        value.putArray("customerIds").add(CUSTOMER);
        value.putArray("fields").add("incomeBand").add("employmentStatus");
        return value;
    }

    private NamespaceObservation namespace() { return new NamespaceObservation(RUN, "fixture/1", HASH, "ACTIVE"); }
    private PreCall preCall(NamespaceObservation namespace) {
        String operation = invocation.proposal().toolName().equals("LOAN_DECISION_UPDATE") ? "UPDATE"
                : invocation.proposal().toolName().equals("REVIEW_NOTE_WRITE") ? "CREATE" : "READ";
        return new PreCall(key, context, namespace, Optional.of(PURPOSE), Optional.of(PURPOSE), Optional.of("DOCUMENT_REVIEW"),
                Optional.of(List.of("DOC-1")), Optional.empty(), Optional.empty(), operation);
    }
    private StateCapture capture() { return new StateCapture(key, CAPTURE, RUN, HASH, true); }
    private Completion completion() { return new Completion(key, CAPTURE, RUN, redaction.redact(output).originalDigest(), classifications(), HASH, true, List.of()); }
    private ObjectNode classifications() { return json.createObjectNode().put("incomeBand", "FINANCIAL").put("employmentStatus", "NORMAL").put("accountNumber", "FINANCIAL"); }

    private List<ToolRegistryEntry> registry() throws Exception {
        // Independent unit-runtime fixture read; never construct observations from the C SourceBoundCatalog.
        var result = new ArrayList<ToolRegistryEntry>();
        for (JsonNode tool : resource("/fixtures/valid-release-manifest-v1.1.json").path("tools")) {
            ObjectNode schema = json.createObjectNode();
            schema.set("inputSchema", tool.path("inputSchema")); schema.set("outputSchema", tool.path("outputSchema"));
            ObjectNode description = json.createObjectNode(); description.set("description", tool.path("description"));
            result.add(new ToolRegistryEntry(tool.path("name").stringValue(), tool.path("version").stringValue(), TrustLevel.TRUSTED_INTERNAL,
                    digests.sha256(canonical.canonicalize(schema)), digests.sha256(canonical.canonicalize(description))));
        }
        return result;
    }

    private Event proposalEvent() {
        return event(CALL, new AppendRequest(CASE_RUN, TRACE, ExecutionEventType.TOOL_PROPOSED, invocation.proposal().toolName(),
                invocation.proposal().arguments(), null, null, "STRUCTURED_TOOL_PROPOSAL", json.createObjectNode().put("origin", "unit-runtime")), 1);
    }

    private Event event(UUID id, AppendRequest request, long sequence) {
        ObjectNode envelope = json.createObjectNode();
        envelope.set("input", request.input()); envelope.set("output", request.output());
        envelope.set("policyDecision", request.policyDecision()); envelope.set("metadata", request.metadata());
        var safe = redaction.redact(envelope);
        return new Event("1.0", id, request.traceId(), RUN, request.testCaseRunId(), sequence, Instant.now(), request.eventType(),
                request.toolName(), safe.redacted().path("input"), safe.redacted().path("output"), safe.originalDigest(),
                safe.redacted().path("policyDecision"), request.reasonCode(), safe.redacted().path("metadata"), null, HASH);
    }

    private void deadline(Duration timeout) { deadlines.add(GatewayRuntimeObservations.requireTimeout(timeout)); }
    private ObjectNode resource(String path) throws Exception { try (var stream = getClass().getResourceAsStream(path)) { return (ObjectNode) json.readTree(stream); } }
    private void assertNoAdapter() { assertThat(executions).isZero(); verify(adapter, never()).execute(any(), any()); }
    private void assertNoExecutionOrEvents() { assertNoAdapter(); assertThat(committed).isEmpty(); verifyNoInteractions(mutations); }
    private void safe(Throwable error, FailureCode code) {
        assertThat(error).isInstanceOf(GatewayException.class);
        assertThat(((GatewayException) error).code()).isEqualTo(code);
        assertThat(error.getCause()).isNull();
        assertThat(error.getSuppressed()).isEmpty();
        StringWriter rendered = new StringWriter(); error.printStackTrace(new PrintWriter(rendered));
        assertThat(rendered.toString()).doesNotContain(PRIVATE, "customerIds", "incomeBand");
    }
    private static Stream<Arguments> namespaceFailures() {
        return Stream.of(TestRunMode.BASELINE, TestRunMode.SEAL_REPLAY).flatMap(mode ->
                Stream.of("missing", "null-namespace", "namespace", "version", "digest", "bad-version", "bad-digest", "inactive", "unknown-state")
                        .map(problem -> Arguments.of(mode, problem)));
    }

    private static Stream<Arguments> duplicateCustomerRequests() {
        return Stream.of(TestRunMode.BASELINE, TestRunMode.SEAL_REPLAY).flatMap(mode ->
                Stream.of("fields", "customerIds").map(field -> Arguments.of(mode, field)));
    }

    private static Stream<Arguments> nonemptyBaselineBusinessResponses() {
        return Stream.of(
                Arguments.of("object", "OBJECT_SCOPE", "CUSTOMER_SCOPE_VIOLATION"),
                Arguments.of("field", "FIELD_PROJECTION", "FIELD_SCOPE_VIOLATION"),
                Arguments.of("cardinality", "RETURNED_CARDINALITY", "RESPONSE_CARDINALITY_VIOLATION"));
    }

    private final class RecordingTransactions extends AbstractPlatformTransactionManager {
        private final List<TransactionDefinition> definitions = new ArrayList<>();
        private boolean failCommit;
        RecordingTransactions() { setRollbackOnCommitFailure(true); }
        @Override protected Object doGetTransaction() { return new Object(); }
        @Override protected void doBegin(Object transaction, TransactionDefinition definition) { definitions.add(definition); }
        @Override protected void doCommit(DefaultTransactionStatus status) {
            if (failCommit) throw new TransactionSystemException(PRIVATE);
            committed.addAll(pending); pending.clear();
        }
        @Override protected void doRollback(DefaultTransactionStatus status) { pending.clear(); }
    }
}
