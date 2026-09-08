package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEvaluationDecision.OutcomeType.PASS;
import static com.finsecseal.policy.PolicyEvaluationStage.PREFLIGHT;

import com.finsecseal.common.domain.ExecutionEventType;
import com.finsecseal.common.domain.Sensitivity;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.contract.LoanReviewFinancialTemplate;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.SourceBoundCatalog;
import com.finsecseal.contract.SafetyContractLifecyclePolicy;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.evidence.ExecutionEventDto;
import com.finsecseal.evidence.ExecutionEventDto.Event;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.evidence.RedactionService;
import com.finsecseal.evidence.TestRunProjectionService;
import com.finsecseal.policy.EnforcePolicyPostCallDecision.PostCallCheck;
import com.finsecseal.policy.GatewayApprovedPolicySourceService.ApprovedPolicySource;
import com.finsecseal.policy.GatewayPolicyFactsAssembler.PolicyInputs;
import com.finsecseal.policy.GatewayRuntimeObservations.Completion;
import com.finsecseal.policy.GatewayRuntimeObservations.InvocationKey;
import com.finsecseal.policy.GatewayRuntimeObservations.PreCall;
import com.finsecseal.policy.GatewayRuntimeObservations.StateCapture;
import com.finsecseal.policy.GatewayRuntimeObservations.StateEntity;
import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;
import com.finsecseal.release.ReleaseService;
import com.finsecseal.runtime.ToolInvocation;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.sandbox.SandboxExecutionContext;
import com.finsecseal.sandbox.tool.PolicyGateway;
import com.finsecseal.sandbox.tool.StateChangingToolExecutionService;
import com.finsecseal.sandbox.tool.ToolAdapter;
import com.finsecseal.sandbox.tool.ToolAdapter.ToolExecutionResult;
import com.finsecseal.sandbox.tool.ToolEffect;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * C's local Gateway composition. Source authorization and the decision share one short snapshot;
 * no adapter runs until that decision commits. Runtime observations and authenticated identity
 * are mandatory owner implementations. Constructing this class does not activate a runtime bean.
 */
public final class LoanReviewPolicyGateway implements PolicyGateway {
    private static final String CUSTOMER = "CUSTOMER_DATA_READ";
    private static final EnumSet<PolicyEvaluationStage> OBSERVE_ONLY = EnumSet.of(
            PolicyEvaluationStage.OBJECT_SCOPE, PolicyEvaluationStage.FIELD_SCOPE,
            PolicyEvaluationStage.CARDINALITY, PolicyEvaluationStage.EGRESS,
            PolicyEvaluationStage.HUMAN_BOUNDARY);
    private final TransactionTemplate transaction;
    private final Supplier<ReviewerContext> reviewers;
    private final GatewayRuntimeObservations observations;
    private final GatewayApprovedPolicySourceService approved;
    private final GatewayBaselinePolicySourceService baseline;
    private final TestRunProjectionService runs;
    private final ReleaseService releases;
    private final GatewayPolicyFactsAssembler facts;
    private final ExecutionEventService events;
    private final StateChangingToolExecutionService mutations;
    private final RedactionService redaction;
    private final ObjectMapper json;
    private final LoanReviewFinancialTemplate template;
    private final Map<String, ToolAdapter> adapters;
    private final CatalogBoundInputSchemaEvaluator input = new CatalogBoundInputSchemaEvaluator();
    private final CatalogJsonSchemaValidator schemas = new CatalogJsonSchemaValidator();
    private final EnforcePolicyEvaluator evaluator = new EnforcePolicyEvaluator();
    private final EnforcePolicyPostCallResponseGuard customerGuard = new EnforcePolicyPostCallResponseGuard();
    private final NonCustomerResponseSemanticsEvaluator otherResponses = new NonCustomerResponseSemanticsEvaluator();

    public LoanReviewPolicyGateway(PlatformTransactionManager transactions, Supplier<ReviewerContext> reviewers,
            GatewayRuntimeObservations observations, GatewayApprovedPolicySourceService approved,
            GatewayBaselinePolicySourceService baseline, TestRunProjectionService runs, ReleaseService releases,
            GatewayPolicyFactsAssembler facts, ExecutionEventService events,
            StateChangingToolExecutionService mutations, RedactionService redaction, ObjectMapper json,
            LoanReviewFinancialTemplate template, List<ToolAdapter> adapters) {
        transaction = new TransactionTemplate(Objects.requireNonNull(transactions));
        transaction.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        transaction.setTimeout(5);
        transaction.setReadOnly(false);
        this.reviewers = Objects.requireNonNull(reviewers);
        this.observations = Objects.requireNonNull(observations);
        this.approved = Objects.requireNonNull(approved);
        this.baseline = Objects.requireNonNull(baseline);
        this.runs = Objects.requireNonNull(runs);
        this.releases = Objects.requireNonNull(releases);
        this.facts = Objects.requireNonNull(facts);
        this.events = Objects.requireNonNull(events);
        this.mutations = Objects.requireNonNull(mutations);
        this.redaction = Objects.requireNonNull(redaction);
        this.json = Objects.requireNonNull(json);
        this.template = Objects.requireNonNull(template);
        var indexed = new HashMap<String, ToolAdapter>();
        for (ToolAdapter adapter : List.copyOf(adapters)) {
            if (!CatalogBoundInputSchemaEvaluator.validToolName(adapter.toolName())
                    || indexed.putIfAbsent(adapter.toolName(), adapter) != null) {
                throw failure(FailureCode.ADAPTER_UNAVAILABLE);
            }
        }
        this.adapters = Map.copyOf(indexed);
    }

    @Override
    public GatewayResult invoke(SandboxExecutionContext context, ToolProposal proposal, String actorId) {
        // A proposal alone cannot establish the server-owned TOOL_PROPOSED event identity.
        throw failure(FailureCode.INVALID_INVOCATION);
    }

    @Override
    public GatewayResult invoke(SandboxExecutionContext context, ToolInvocation invocation, String actorId) {
        requireNoTransaction();
        try {
            requireInvocation(context, invocation, actorId);
            // Capture before any owner callback. Every owner receives its own copy, never this master.
            JsonNode arguments = CatalogBoundInputSchemaEvaluator.snapshotArguments(invocation.proposal().arguments());
            if (arguments == null) throw failure(FailureCode.INVALID_INVOCATION);
            var call = new ToolInvocation(new ToolProposal(invocation.proposal().toolName(), arguments),
                    invocation.toolCallId(), invocation.requestDigest());
            ReviewerContext reviewer = reviewers.get();
            if (reviewer == null || !reviewer.authenticated() || !actorId.equals(reviewer.actorId())) {
                throw failure(FailureCode.AUTHENTICATION_REQUIRED);
            }
            Deadline sourceDeadline = new Deadline(Duration.ofSeconds(5));
            Prepared prepared = transaction.execute(status -> prepare(context, call, reviewer, sourceDeadline));
            requireNoTransaction();
            if (prepared == null) throw failure(FailureCode.EVIDENCE_FAILURE);
            if (prepared.decision.error()) {
                throw new GatewayException(FailureCode.POLICY_EVALUATION_FAILED, prepared.decision.reason);
            }
            PolicyDecision decision = new PolicyDecision(prepared.decision.allowed, prepared.decision.reasonCode());
            if (!decision.allowed()) return new GatewayResult(decision, prepared.policyEvent, null, null, null);
            ToolAdapter adapter = adapters.get(call.proposal().toolName());
            if (adapter == null) throw failure(FailureCode.ADAPTER_UNAVAILABLE);
            ToolEffect expectedEffect = "REVIEW_NOTE_WRITE".equals(adapter.toolName())
                    ? ToolEffect.STATE_CHANGING : ToolEffect.READ_ONLY;
            if (adapter.effect() != expectedEffect) throw failure(FailureCode.ADAPTER_CONTRACT_FAILURE);
            return expectedEffect == ToolEffect.STATE_CHANGING
                    ? executeMutation(prepared, adapter, actorId) : executeRead(prepared, adapter, actorId);
        } catch (GatewayException exception) {
            throw exception;
        } catch (GatewayRuntimeObservations.ObservationException exception) {
            throw failure(FailureCode.INVALID_OBSERVATION);
        } catch (EnforcePolicyEvaluator.PolicyEvaluationTimeoutException exception) {
            throw failure(FailureCode.POLICY_EVALUATION_TIMEOUT);
        } catch (PolicyEvaluationSequence.PolicyEvaluationException exception) {
            if (exception.getCause() instanceof GatewayException safe) throw safe;
            if (exception.getCause() instanceof GatewayRuntimeObservations.ObservationException) {
                throw failure(FailureCode.INVALID_OBSERVATION);
            }
            throw failure(FailureCode.POLICY_EVALUATION_FAILED);
        } catch (TransactionException exception) {
            throw failure(FailureCode.EVIDENCE_FAILURE);
        } catch (RuntimeException exception) {
            // Owner exceptions can contain SQL, stored policies or raw adapter output.
            throw failure(FailureCode.POLICY_EVALUATION_FAILED);
        }
    }

    private Prepared prepare(SandboxExecutionContext context, ToolInvocation call, ReviewerContext reviewer,
            Deadline deadline) {
        boolean isBaseline = context.mode() == TestRunMode.BASELINE;
        ApprovedPolicySource approvedSource = null;
        SourceBoundCatalog catalog;
        PolicyInputs inputs;
        UUID releaseId;
        UUID contractId;
        UUID workspace;
        String baselineFixtureVersion = null;
        String baselineFixtureDigest = null;
        if (isBaseline) {
            var source = baseline.load(context.runId(), context.caseRunId(), reviewer);
            require(source != null && context.runId().equals(source.runId())
                    && context.caseRunId().equals(source.testCaseRunId()) && source.runMode() == context.mode()
                    && source.runStatus() == TestRunStatus.RUNNING
                    && source.caseStatus() == TestCaseRunStatus.EXECUTING, FailureCode.SOURCE_BINDING_INVALID);
            catalog = source.catalog(); releaseId = source.releaseId(); workspace = source.workspaceId();
            contractId = source.referencedContractVersionId();
            baselineFixtureVersion = source.fixtureVersion(); baselineFixtureDigest = source.fixtureDigest();
            inputs = facts.baselineInputs(source, template);
        } else {
            approvedSource = approved.load(context.runId(), context.caseRunId(), reviewer);
            require(approvedSource != null && context.runId().equals(approvedSource.runId())
                    && context.caseRunId().equals(approvedSource.testCaseRunId())
                    && approvedSource.runMode() == context.mode() && approvedSource.runStatus() == TestRunStatus.RUNNING
                    && approvedSource.caseStatus() == TestCaseRunStatus.EXECUTING,
                    FailureCode.SOURCE_BINDING_INVALID);
            catalog = approvedSource.catalog(); releaseId = approvedSource.identity().releaseId();
            workspace = approvedSource.identity().workspaceId(); contractId = approvedSource.identity().versionId();
            inputs = facts.approvedInputs(approvedSource);
        }
        SafetyContractLifecyclePolicy.requireReviewerContext(reviewer, workspace);
        deadline.remaining();
        // Expected fixture metadata must come from the actual authorized Run in this same snapshot.
        var run = runs.find(context.runId());
        require(run != null && context.runId().equals(run.id()) && releaseId.equals(run.releaseId())
                && Objects.equals(contractId, run.contractVersionId()) && run.mode() == context.mode()
                && run.status() == TestRunStatus.RUNNING && catalog != null
                && releaseId.equals(catalog.releaseId())
                && Objects.equals(run.agentArtifactFingerprint(), catalog.agentArtifactFingerprint())
                && Objects.equals(run.releaseFingerprint(), catalog.releaseFingerprint()), FailureCode.SOURCE_BINDING_INVALID);
        require(!isBaseline || Objects.equals(baselineFixtureVersion, run.fixtureVersion())
                && Objects.equals(baselineFixtureDigest, run.fixtureDigest()), FailureCode.SOURCE_BINDING_INVALID);
        var release = releases.getRequired(releaseId);
        require(release != null && releaseId.equals(release.getId())
                && Objects.equals(run.agentArtifactFingerprint(), release.getAgentArtifactFingerprint())
                && Objects.equals(run.releaseFingerprint(), release.getReleaseFingerprint()), FailureCode.SOURCE_BINDING_INVALID);
        JsonNode manifest = release.getManifestJson();
        String purpose = release.getBusinessPurpose();
        require(manifest != null && manifest.isObject()
                && manifest.path("businessPurpose").isObject()
                && manifest.at("/businessPurpose/code").isString()
                && Objects.equals(purpose, manifest.at("/businessPurpose/code").stringValue())
                && LoanReviewFinancialTemplate.PURPOSE.equals(purpose), FailureCode.SOURCE_BINDING_INVALID);
        // Capture only the needed schema before another owner callback; retain no prompt/manifest alias.
        JsonNode capturedOutputSchema = outputSchema(manifest, call.proposal().toolName());
        InvocationKey key = key(context, call);
        PreCall observed = observations.resolve(key, deadline.remaining());
        deadline.remaining();
        require(observed != null && key.equals(observed.key()) && context.equals(observed.serverContext())
                && context.namespaceId().equals(observed.namespace().namespaceId())
                && Objects.equals(run.fixtureVersion(), observed.namespace().fixtureVersion())
                && Objects.equals(run.fixtureDigest(), observed.namespace().fixtureDigest())
                && "ACTIVE".equals(observed.namespace().state()), FailureCode.INVALID_OBSERVATION);
        requireProposal(context, call);
        deadline.remaining();
        long evaluationStarted = System.nanoTime();
        Evaluation decision = evaluate(inputs, call.proposal(), observed, purpose);
        long evaluationDurationNanos = System.nanoTime() - evaluationStarted;
        // Unknown tools reach TOOL_NOT_ALLOWED before output-schema or adapter availability checks.
        if (decision.allowed) require(capturedOutputSchema != null
                && (capturedOutputSchema.isObject() || capturedOutputSchema.isBoolean()), FailureCode.SOURCE_BINDING_INVALID);
        String reference = isBaseline ? LoanReviewFinancialTemplate.KEY : contractId.toString();
        String contextDigest = redaction.redact(json.valueToTree(observed)).originalDigest();
        String inputDigest = redaction.redact(call.proposal().arguments().deepCopy()).originalDigest();
        require(validDigest(contextDigest), FailureCode.INVALID_OBSERVATION);
        require(validDigest(inputDigest), FailureCode.INVALID_INVOCATION);
        decision.json.put("schemaVersion", "1.0").put("decisionId", UUID.randomUUID().toString())
                .put("releaseFingerprint", catalog.releaseFingerprint()).put("contextDigest", contextDigest)
                .put("inputDigest", inputDigest).put("evaluatedAt", Instant.now().toString())
                .put("durationMs", evaluationDurationNanos / 1_000_000.0);
        if (decision.json.has("failedStage")) decision.json.set("failedCheck", decision.json.get("failedStage"));
        if (!isBaseline) decision.json.set("evaluatedChecks", decision.json.get("evaluatedStages").deepCopy());
        ObjectNode metadata = metadata(key).put("mode", context.mode().name()).put("policyReference", reference)
                .put("evaluationDurationNanos", evaluationDurationNanos)
                .put("releaseFingerprint", catalog.releaseFingerprint()).put("contextDigest", contextDigest);
        if (approvedSource != null) {
            decision.json.put("policyVersionId", approvedSource.identity().versionId().toString())
                    .put("policyHash", approvedSource.policyHash());
            metadata.put("contractVersionId", approvedSource.identity().versionId().toString())
                    .put("policyHash", approvedSource.policyHash());
        }
        Event policy = append(context, ExecutionEventType.POLICY_EVALUATED, call.proposal().toolName(),
                null, null, decision.json, decision.reasonCode(), metadata, reviewer.actorId());
        deadline.remaining();
        return new Prepared(context, call, key, observed, inputs, approvedSource, catalog,
                purpose, capturedOutputSchema, decision, policy);
    }

    private void requireProposal(SandboxExecutionContext context, ToolInvocation call) {
        try {
            Event event = events.findById(call.toolCallId());
            require(event != null && call.toolCallId().equals(event.eventId())
                    && event.eventType() == ExecutionEventType.TOOL_PROPOSED
                    && context.runId().equals(event.runId()) && context.caseRunId().equals(event.testCaseRunId())
                    && context.traceId().equals(event.traceId()) && call.proposal().toolName().equals(event.toolName())
                    && call.requestDigest().equals(event.payloadDigest())
                    && events.matchesToolProposalPayloadDigest(copyEvent(event), call.proposal().arguments().deepCopy()),
                    FailureCode.INVALID_INVOCATION);
        } catch (GatewayException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw failure(FailureCode.INVALID_INVOCATION);
        }
    }

    private Evaluation evaluate(PolicyInputs inputs, ToolProposal proposal, PreCall observed, String purpose) {
        Deadline deadline = new Deadline(Duration.ofMillis(100));
        Supplier<StageOutcome> preflight = () -> switch (input.evaluateCatalog(inputs.catalog(), proposal)) {
            case MATCH, TOOL_NOT_IN_CATALOG -> StageOutcome.pass(PREFLIGHT);
            case INVALID_REQUEST_SCHEMA -> StageOutcome.error(PREFLIGHT, PolicyEvaluationReason.INVALID_REQUEST_SCHEMA);
        };
        if (!inputs.baseline()) {
            var result = evaluator.evaluateStages(preflight::get,
                    stage -> stage(inputs, proposal, observed, purpose, stage, deadline));
            ObjectNode decision = json.createObjectNode().put("evaluationMode", "ENFORCE")
                    .put("decisionType", result.decisionType().name())
                    .put("allowed", result.decisionType() == PolicyEvaluationDecision.DecisionType.ALLOW)
                    .put("successfulSecurityBlock", result.successfulSecurityBlock());
            var order = decision.putArray("evaluatedStages");
            result.evaluatedStages().forEach(value -> order.add(value.name()));
            result.failedStage().ifPresent(value -> decision.put("failedStage", value.name()));
            String reason = result.reason().map(Enum::name).orElse("ALLOW");
            decision.put("reasonCode", reason);
            return new Evaluation(decision.path("allowed").booleanValue(), result.reason(), decision);
        }
        ObjectNode decision = json.createObjectNode().put("evaluationMode", "BASELINE");
        var outcomes = decision.putArray("stageOutcomes");
        Optional<PolicyEvaluationReason> actualReason = Optional.empty();
        boolean observedTerminal = false;
        for (var stage : PolicyEvaluationStage.completeOrder()) {
            deadline.remaining();
            boolean enforced = !OBSERVE_ONLY.contains(stage);
            ObjectNode entry = outcomes.addObject().put("stage", stage.name())
                    .put("enforcement", enforced ? "ENFORCED" : "OBSERVED");
            if (!enforced && observedTerminal) {
                entry.put("outcomeType", "SKIPPED");
                continue;
            }
            StageOutcome outcome = stage == PREFLIGHT ? preflight.get()
                    : stage(inputs, proposal, observed, purpose, stage, deadline);
            deadline.remaining();
            entry.put("outcomeType", outcome.outcomeType().name());
            outcome.reason().ifPresent(value -> entry.put("reasonCode", value.name()));
            if (outcome.outcomeType() != PASS) {
                // Operational failures never become successful baseline observations.
                if (enforced || outcome.outcomeType() == PolicyEvaluationDecision.OutcomeType.ERROR) {
                    actualReason = outcome.reason(); decision.put("failedStage", stage.name()); break;
                }
                observedTerminal = true;
                decision.put("observedReasonCode", outcome.reason().orElseThrow().name())
                        .put("observedFailedStage", stage.name());
            }
        }
        deadline.remaining();
        boolean allowed = actualReason.isEmpty();
        String type = actualReason.map(value -> value.classification().name()).orElse("ALLOW");
        decision.put("allowed", allowed).put("decisionType", type)
                .put("reasonCode", actualReason.map(Enum::name).orElse("BASELINE_ALLOW"))
                .put("successfulSecurityBlock", "DENY".equals(type));
        return new Evaluation(allowed, actualReason, decision);
    }

    private StageOutcome stage(PolicyInputs inputs, ToolProposal proposal, PreCall observed, String purpose,
            PolicyEvaluationStage stage, Deadline deadline) {
        String tool = proposal.toolName();
        return switch (stage) {
            case TOOL, OPERATION -> new PolicyToolAuthorizationEvaluator().evaluate(stage,
                    facts.authorizationFor(inputs, tool, observed.requestedOperation()));
            case BUSINESS_CONTEXT -> new PolicyBusinessContextEvaluator().evaluate(stage,
                    businessContext(inputs, observed, purpose));
            case OBJECT_SCOPE -> new PolicyObjectScopeEvaluator().evaluate(stage, objectScope(inputs, proposal, observed));
            case FIELD_SCOPE -> new PolicyFieldScopeEvaluator().evaluate(stage, facts.fieldScopeFor(inputs, proposal));
            case CARDINALITY -> new PolicyCardinalityEvaluator().evaluate(stage, facts.cardinalityFor(inputs, proposal));
            case EGRESS -> new PolicyEgressEvaluator().evaluate(stage, facts.egressFor(inputs, tool));
            case WORKFLOW -> new PolicyWorkflowEvaluator().evaluate(stage,
                    facts.workflowFor(inputs, tool, observed.workflowStage().orElseThrow(
                            () -> failure(FailureCode.INVALID_OBSERVATION))));
            case HUMAN_BOUNDARY -> new PolicyHumanBoundaryEvaluator().evaluate(stage, facts.humanBoundaryFor(inputs, tool));
            case TOOL_TRUST -> {
                var registry = observations.registry(observed.key(), deadline.remaining());
                deadline.remaining();
                require(registry != null && observed.key().equals(registry.key()), FailureCode.INVALID_OBSERVATION);
                yield new PolicyToolTrustEvaluator().evaluate(stage, facts.toolTrustFor(inputs, tool,
                        registry.observedReleaseFingerprint(), registry.entries()));
            }
            case PREFLIGHT -> throw failure(FailureCode.POLICY_EVALUATION_FAILED);
        };
    }

    private PolicyBusinessContextFacts businessContext(PolicyInputs inputs, PreCall observed, String purpose) {
        var context = observed.serverContext();
        return facts.businessContextFor(inputs, true, Optional.of(purpose), observed.runPurpose(), observed.casePurpose(),
                Optional.of(context.namespaceId().toString()), Optional.of(context.caseKey()),
                Optional.of(context.currentApplicantId()), observed.workflowStage(), observed.allowedDocumentIds());
    }

    private PolicyObjectScopeFacts objectScope(PolicyInputs inputs, ToolProposal proposal, PreCall observed) {
        var args = proposal.arguments();
        var context = observed.serverContext();
        return facts.objectScopeFor(inputs, proposal.toolName(), optionalText(args.get("caseId")),
                optionalSingle(args.get("documentId")), optionalStrings(args.get("customerIds")),
                Optional.of(context.caseKey()), Optional.of(context.currentApplicantId()),
                observed.allowedDocumentIds(), observed.documentOwnerships());
    }

    private GatewayResult executeRead(Prepared prepared, ToolAdapter adapter, String actor) {
        Event request = committedAppend(prepared, ExecutionEventType.TOOL_REQUEST,
                prepared.call.proposal().arguments(), null, null, metadata(prepared.key), actor);
        CheckedOutput checked = executeAndValidate(prepared, adapter);
        ToolExecutionResult result = checked.result();
        ObjectNode metadata = metadata(prepared.key).put("deliveredToAgent", false)
                .put("deliveryState", "PENDING").put("stateChanged", result.stateChanged());
        checked.observation().ifPresent(value -> metadata.set("observedPostCall", json.createObjectNode()
                .put("check", value.check()).put("reasonCode", value.reason())));
        Event response = committedAppend(prepared, ExecutionEventType.TOOL_RESPONSE, null,
                result.output(), "TOOL_EXECUTED", metadata, actor);
        return result(prepared, request, response, result);
    }

    private GatewayResult executeMutation(Prepared prepared, ToolAdapter adapter, String actor) {
        final class ValidatingDelegate implements ToolAdapter {
            private CheckedOutput validated;
            @Override public String toolName() { return adapter.toolName(); }
            @Override public ToolEffect effect() { return ToolEffect.STATE_CHANGING; }
            @Override public ToolExecutionResult execute(SandboxExecutionContext context, JsonNode arguments) {
                require(TransactionSynchronizationManager.isActualTransactionActive(), FailureCode.UNSAFE_TRANSACTION);
                require(validated == null && prepared.context.equals(context)
                        && prepared.call.proposal().arguments().equals(arguments), FailureCode.INVALID_INVOCATION);
                validated = executeAndValidate(prepared, adapter);
                return copyResult(validated.result());
            }
        }
        var delegate = new ValidatingDelegate();
        StateChangingToolExecutionService.Execution execution;
        try {
            execution = mutations.execute(prepared.context, copyInvocation(prepared.call), delegate, actor);
        } catch (GatewayException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw failure(FailureCode.ADAPTER_CONTRACT_FAILURE);
        }
        requireNoTransaction();
        if (execution == null || execution.replayed() || delegate.validated == null) {
            // Stored receipts contain redacted bodies. Do not re-execute or certify them as raw responses.
            throw failure(FailureCode.REPLAY_RESPONSE_UNAVAILABLE);
        }
        require(execution.result() != null && execution.result().stateChanged() == delegate.validated.result().stateChanged()
                && delegate.validated.result().output().equals(execution.result().output()), FailureCode.ADAPTER_CONTRACT_FAILURE);
        return result(prepared, execution.requestEvent(), execution.responseEvent(), delegate.validated.result());
    }

    private CheckedOutput executeAndValidate(Prepared prepared, ToolAdapter adapter) {
        try {
            Deadline captureDeadline = new Deadline(Duration.ofSeconds(5));
            StateCapture before = observations.begin(prepared.key, captureDeadline.remaining());
            captureDeadline.remaining();
            require(before != null && before.complete() && prepared.key.equals(before.key())
                    && prepared.context.namespaceId().equals(before.namespaceId()), FailureCode.INVALID_OBSERVATION);
            ToolExecutionResult raw = adapter.execute(prepared.context, prepared.call.proposal().arguments().deepCopy());
            JsonNode body = raw == null ? null : CatalogBoundInputSchemaEvaluator.snapshotResponse(raw.output());
            require(body != null && schemas.matches(prepared.outputSchema, body), FailureCode.ADAPTER_CONTRACT_FAILURE);
            // Body-only digest, independently compared with complete(); requestDigest is an event-envelope digest.
            RedactionService.Result digest = redaction.redact(body.deepCopy());
            require(digest != null && validDigest(digest.originalDigest()), FailureCode.ADAPTER_CONTRACT_FAILURE);
            Deadline completionDeadline = new Deadline(Duration.ofSeconds(5));
            Completion completed = observations.complete(prepared.key, before, completionDeadline.remaining());
            completionDeadline.remaining();
            require(completed != null && completed.complete() && prepared.key.equals(completed.key())
                    && before.captureId().equals(completed.captureId())
                    && before.namespaceId().equals(completed.namespaceId())
                    && digest.originalDigest().equals(completed.rawOutputDigest()), FailureCode.INVALID_OBSERVATION);
            Optional<PostCallObservation> observation;
            if (CUSTOMER.equals(prepared.call.proposal().toolName())) {
                observation = validateCustomer(prepared, body, completed);
            } else {
                validatePartialNonCustomer(prepared, body);
                observation = Optional.empty();
            }
            ToolEffect expectedEffect = "REVIEW_NOTE_WRITE".equals(prepared.call.proposal().toolName())
                    ? ToolEffect.STATE_CHANGING : ToolEffect.READ_ONLY;
            if (adapter.effect() != expectedEffect || !hasPermittedStateEffects(
                    prepared.call.proposal(), prepared.context, raw.stateChanged(), before, completed)) {
                throw new GatewayException(FailureCode.ADAPTER_CONTRACT_FAILURE,
                        Optional.empty(), Optional.of(PostCallCheck.STATE_DELTA_PROVENANCE));
            }
            if (!CUSTOMER.equals(prepared.call.proposal().toolName())) {
                // State scope is checked, but the noncustomer field/path classification contract is unresolved.
                // Partial comparisons grant neither successful creation nor full post-call PASS/delivery.
                throw failure(FailureCode.ADAPTER_CONTRACT_FAILURE);
            }
            // A returned mutable JSON node is a caller-owned copy, never an alias of adapter/observation data.
            return new CheckedOutput(new ToolExecutionResult(body.deepCopy(), false), observation);
        } catch (GatewayException exception) {
            throw exception;
        } catch (GatewayRuntimeObservations.ObservationException exception) {
            throw failure(FailureCode.INVALID_OBSERVATION);
        } catch (RuntimeException exception) {
            throw failure(FailureCode.ADAPTER_CONTRACT_FAILURE);
        }
    }

    /** State-scope comparison only; true grants neither successful creation nor response delivery. */
    static boolean hasPermittedStateEffects(ToolProposal proposal, SandboxExecutionContext context,
            boolean reportedStateChanged, StateCapture before, Completion after) {
        if (proposal == null || proposal.toolName() == null || context == null || context.mode() == null
                || before == null || after == null || !before.complete() || !after.complete()
                || !before.key().equals(after.key()) || !before.captureId().equals(after.captureId())
                || !before.key().runId().equals(context.runId())
                || !before.key().caseRunId().equals(context.caseRunId())
                || !before.key().traceId().equals(context.traceId())
                || !before.namespaceId().equals(context.namespaceId())
                || !after.namespaceId().equals(context.namespaceId())) return false;
        boolean emptyChanges = after.changes().isEmpty();
        boolean sameDigest = before.beforeStateDigest().equals(after.afterStateDigest());
        return switch (proposal.toolName()) {
            case CUSTOMER, "CASE_CONTEXT_READ", "DOCUMENT_READER", "LOAN_POLICY_SEARCH" ->
                    !reportedStateChanged && emptyChanges && sameDigest;
            case "REVIEW_NOTE_WRITE" -> {
                JsonNode arguments = proposal.arguments();
                JsonNode requestedCase = arguments == null ? null : arguments.path("caseId");
                if (requestedCase == null || !requestedCase.isString() || requestedCase.stringValue().isBlank()) {
                    yield false;
                }
                String caseId = requestedCase.stringValue();
                if (context.mode() != TestRunMode.BASELINE && !caseId.equals(context.caseKey())) yield false;
                // Even BASELINE must preserve the requested resource and namespace. Its current-case
                // business policy remains observe-only; this is not proof of the stored note contents.
                if (!reportedStateChanged) yield emptyChanges && sameDigest;
                if (emptyChanges || sameDigest) yield false;
                yield after.changes().stream().allMatch(change -> change.entityType() == StateEntity.REVIEW_NOTE
                        && change.namespaceId().equals(context.namespaceId())
                        && change.caseId().filter(caseId::equals).isPresent());
            }
            default -> false;
        };
    }

    private Optional<PostCallObservation> validateCustomer(Prepared prepared, JsonNode body, Completion completion) {
        if (prepared.inputs.baseline()) {
            var expected = new HashMap<String, Sensitivity>();
            for (var field : prepared.catalog.customerOutputFields()) {
                require(expected.putIfAbsent(field.fieldName(), field.classification()) == null,
                        FailureCode.SOURCE_BINDING_INVALID);
            }
            require(!expected.isEmpty() && EnforcePolicyPostCallResponseGuard.hasExactClassifications(
                    completion.classificationMap(), expected), FailureCode.ADAPTER_CONTRACT_FAILURE);
            // BASELINE business scope/projection/count are observation-only. Unknown requested fields
            // can be omitted by the actual adapter; do not fabricate an ENFORCE Facts object to filter them.
            return observeCustomerResponse(prepared, body);
        }
        ToolProposal proposal = prepared.call.proposal();
        JsonNode policy = prepared.inputs.policy();
        JsonNode returnedLimit = policy.at("/cardinality/CUSTOMER_DATA_READ/maxReturnedRecords");
        require(returnedLimit.isIntegralNumber() && returnedLimit.canConvertToInt() && returnedLimit.intValue() > 0,
                FailureCode.SOURCE_BINDING_INVALID);
        var fieldPolicy = facts.fieldScopeFor(prepared.inputs, proposal).requestedFieldPolicy().orElseThrow();
        var responseFacts = new EnforcePolicyPostCallFacts(CUSTOMER, prepared.context.currentApplicantId(),
                strings(proposal.arguments().path("customerIds")), strings(proposal.arguments().path("fields")),
                fieldPolicy.allowedFields(), prepared.catalog.customerOutputFields(), returnedLimit.intValue(),
                prepared.context.namespaceId().toString(), prepared.context.caseRunId(), body,
                completion.classificationMap(), null);
        var responseDecision = customerGuard.evaluate(responseFacts);
        if (responseDecision.outcome() != EnforcePolicyPostCallDecision.Outcome.PASS) {
            FailureCode code = responseDecision.reason().orElseThrow()
                    == EnforcePolicyPostCallDecision.OperationalReason.RESPONSE_CARDINALITY_VIOLATION
                    ? FailureCode.RESPONSE_CARDINALITY_VIOLATION : FailureCode.ADAPTER_CONTRACT_FAILURE;
            throw new GatewayException(code, Optional.empty(), responseDecision.failedCheck());
        }
        return Optional.empty();
    }

    private Optional<PostCallObservation> observeCustomerResponse(Prepared prepared, JsonNode body) {
        JsonNode args = prepared.call.proposal().arguments();
        List<String> customers = strings(args.path("customerIds"));
        List<String> fields = strings(args.path("fields"));
        List<String> projection = facts.fieldScopeFor(prepared.inputs, prepared.call.proposal())
                .requestedFieldPolicy().orElseThrow().allowedFields();
        JsonNode limit = prepared.inputs.policy().at("/cardinality/CUSTOMER_DATA_READ/maxReturnedRecords");
        require(limit.isIntegralNumber() && limit.canConvertToInt() && limit.intValue() > 0,
                FailureCode.SOURCE_BINDING_INVALID);
        for (JsonNode row : body.path("rows")) {
            String customer = row.path("customerId").stringValue();
            if (!prepared.context.currentApplicantId().equals(customer) || !customers.contains(customer)) {
                return Optional.of(new PostCallObservation("OBJECT_SCOPE", "CUSTOMER_SCOPE_VIOLATION"));
            }
        }
        for (JsonNode row : body.path("rows")) {
            for (var field : row.path("fields").properties()) {
                if (!fields.contains(field.getKey()) || !projection.contains(field.getKey())) {
                    return Optional.of(new PostCallObservation("FIELD_PROJECTION", "FIELD_SCOPE_VIOLATION"));
                }
            }
        }
        return body.path("rows").size() > limit.intValue()
                ? Optional.of(new PostCallObservation("RETURNED_CARDINALITY", "RESPONSE_CARDINALITY_VIOLATION"))
                : Optional.empty();
    }

    private void validatePartialNonCustomer(Prepared prepared, JsonNode body) {
        var proposal = prepared.call.proposal();
        NonCustomerResponseSemanticsEvaluator.Outcome outcome = switch (proposal.toolName()) {
            case "CASE_CONTEXT_READ" -> otherResponses.caseContext(
                    businessContext(prepared.inputs, prepared.observed, prepared.purpose), body);
            case "DOCUMENT_READER" -> otherResponses.document(objectScope(prepared.inputs, proposal, prepared.observed),
                    prepared.observed.documentSource().orElseThrow(() -> failure(FailureCode.INVALID_OBSERVATION)), body);
            case "REVIEW_NOTE_WRITE" -> {
                if (prepared.approvedSource == null) yield NonCustomerResponseSemanticsEvaluator.Outcome.MATCH;
                yield otherResponses.reviewNote(prepared.approvedSource,
                        objectScope(prepared.inputs, proposal, prepared.observed), body);
            }
            default -> NonCustomerResponseSemanticsEvaluator.Outcome.MATCH;
        };
        require(outcome == NonCustomerResponseSemanticsEvaluator.Outcome.MATCH, FailureCode.ADAPTER_CONTRACT_FAILURE);
    }

    private Event committedAppend(Prepared prepared, ExecutionEventType type, JsonNode input, JsonNode output,
            String reason, ObjectNode metadata, String actor) {
        requireNoTransaction();
        return transaction.execute(status -> append(prepared.context, type, prepared.call.proposal().toolName(),
                input, output, null, reason, metadata, actor));
    }

    private Event append(SandboxExecutionContext context, ExecutionEventType type, String tool, JsonNode input,
            JsonNode output, JsonNode policy, String reason, ObjectNode metadata, String actor) {
        try {
            Event event = events.append(context.runId(), new ExecutionEventDto.AppendRequest(context.caseRunId(),
                    context.traceId(), type, tool, copy(input), copy(output), copy(policy), reason, metadata.deepCopy()), actor);
            requireEvent(event, context, tool, type);
            return copyEvent(event);
        } catch (RuntimeException exception) {
            throw failure(FailureCode.EVIDENCE_FAILURE);
        }
    }

    private GatewayResult result(Prepared prepared, Event request, Event response, ToolExecutionResult output) {
        String tool = prepared.call.proposal().toolName();
        requireEvent(request, prepared.context, tool, ExecutionEventType.TOOL_REQUEST);
        requireEvent(response, prepared.context, tool, ExecutionEventType.TOOL_RESPONSE);
        return new GatewayResult(new PolicyDecision(true, prepared.decision.reasonCode()), prepared.policyEvent,
                copyEvent(request), copyEvent(response), copyResult(output));
    }

    private static void requireEvent(Event event, SandboxExecutionContext context, String tool, ExecutionEventType type) {
        require(event != null && event.eventId() != null && context.runId().equals(event.runId())
                && context.caseRunId().equals(event.testCaseRunId()) && context.traceId().equals(event.traceId())
                && tool.equals(event.toolName()) && type == event.eventType(), FailureCode.EVIDENCE_FAILURE);
    }

    private JsonNode outputSchema(JsonNode manifest, String tool) {
        JsonNode tools = manifest.path("tools");
        require(tools.isArray(), FailureCode.SOURCE_BINDING_INVALID);
        JsonNode selected = null;
        boolean found = false;
        for (JsonNode declaration : tools) {
            if (tool.equals(declaration.path("name").stringValue())) {
                require(!found, FailureCode.SOURCE_BINDING_INVALID);
                found = true;
                selected = declaration.get("outputSchema");
            }
        }
        return copy(selected);
    }

    private ObjectNode metadata(InvocationKey key) {
        return json.createObjectNode().put("toolCallId", key.toolCallId().toString());
    }

    private static InvocationKey key(SandboxExecutionContext context, ToolInvocation call) {
        return new InvocationKey(context.runId(), context.caseRunId(), context.traceId(), call.toolCallId(), call.requestDigest());
    }

    private static void requireInvocation(SandboxExecutionContext context, ToolInvocation call, String actor) {
        require(context != null && context.runId() != null && context.caseRunId() != null && context.traceId() != null
                && context.mode() != null && exactText(context.caseKey()) && exactText(context.currentApplicantId())
                && call != null && CatalogBoundInputSchemaEvaluator.validToolName(call.proposal().toolName())
                && exactText(actor), FailureCode.INVALID_INVOCATION);
    }

    private static void requireNoTransaction() {
        require(!TransactionSynchronizationManager.isActualTransactionActive()
                && !TransactionSynchronizationManager.isSynchronizationActive(), FailureCode.UNSAFE_TRANSACTION);
    }

    private static boolean exactText(String value) {
        return value != null && !value.isBlank() && value.equals(value.strip());
    }

    private static Optional<String> optionalText(JsonNode value) {
        if (value == null) return Optional.empty();
        require(value.isString(), FailureCode.INVALID_INVOCATION);
        return Optional.of(value.stringValue());
    }

    private static Optional<List<String>> optionalSingle(JsonNode value) {
        return optionalText(value).map(List::of);
    }

    private static Optional<List<String>> optionalStrings(JsonNode value) {
        return value == null ? Optional.empty() : Optional.of(strings(value));
    }

    private static List<String> strings(JsonNode value) {
        require(value != null && value.isArray(), FailureCode.INVALID_INVOCATION);
        var values = new ArrayList<String>();
        for (JsonNode item : value) {
            require(item.isString(), FailureCode.INVALID_INVOCATION); values.add(item.stringValue());
        }
        return List.copyOf(values);
    }

    private static JsonNode copy(JsonNode value) { return value == null ? null : value.deepCopy(); }
    private static ToolInvocation copyInvocation(ToolInvocation call) {
        return new ToolInvocation(new ToolProposal(call.proposal().toolName(), copy(call.proposal().arguments())),
                call.toolCallId(), call.requestDigest());
    }
    private static ToolExecutionResult copyResult(ToolExecutionResult result) {
        return new ToolExecutionResult(copy(result.output()), result.stateChanged());
    }
    private static Event copyEvent(Event event) {
        return new Event(event.schemaVersion(), event.eventId(), event.traceId(), event.runId(), event.testCaseRunId(),
                event.sequence(), event.occurredAt(), event.eventType(), event.toolName(), copy(event.input()), copy(event.output()),
                event.payloadDigest(), copy(event.policyDecision()), event.reasonCode(), copy(event.metadata()),
                event.prevEventHash(), event.eventHash());
    }
    private static boolean validDigest(String digest) { return digest != null && digest.matches("sha256:[0-9a-f]{64}"); }
    private static void require(boolean condition, FailureCode code) { if (!condition) throw failure(code); }
    private static GatewayException failure(FailureCode code) { return new GatewayException(code, Optional.empty()); }

    private record PostCallObservation(String check, String reason) { }
    private record CheckedOutput(ToolExecutionResult result, Optional<PostCallObservation> observation) { }
    private record Prepared(SandboxExecutionContext context, ToolInvocation call, InvocationKey key,
            PreCall observed, PolicyInputs inputs, ApprovedPolicySource approvedSource, SourceBoundCatalog catalog,
            String purpose, JsonNode outputSchema, Evaluation decision, Event policyEvent) { }
    private record Evaluation(boolean allowed, Optional<PolicyEvaluationReason> reason, ObjectNode json) {
        String reasonCode() { return json.path("reasonCode").stringValue(); }
        boolean error() { return "ERROR".equals(json.path("decisionType").stringValue()); }
    }
    private static final class Deadline {
        private final long started = System.nanoTime();
        private final long budget;
        Deadline(Duration duration) { budget = GatewayRuntimeObservations.requireTimeout(duration).toNanos(); }
        Duration remaining() {
            long remaining = budget - (System.nanoTime() - started);
            if (remaining <= 0) throw failure(FailureCode.POLICY_EVALUATION_TIMEOUT);
            return GatewayRuntimeObservations.requireTimeout(Duration.ofNanos(remaining));
        }
    }
    public enum FailureCode {
        INVALID_INVOCATION, UNSAFE_TRANSACTION, AUTHENTICATION_REQUIRED, SOURCE_BINDING_INVALID,
        INVALID_OBSERVATION, POLICY_EVALUATION_FAILED, POLICY_EVALUATION_TIMEOUT, EVIDENCE_FAILURE,
        ADAPTER_UNAVAILABLE, ADAPTER_CONTRACT_FAILURE, RESPONSE_CARDINALITY_VIOLATION, REPLAY_RESPONSE_UNAVAILABLE
    }
    /** Operational failure: no raw output/cause, fabricated DENY, lifecycle mutation or block credit. */
    public static final class GatewayException extends RuntimeException {
        private final FailureCode code;
        private final Optional<PolicyEvaluationReason> reason;
        private final Optional<EnforcePolicyPostCallDecision.PostCallCheck> postCallCheck;
        private GatewayException(FailureCode code, Optional<PolicyEvaluationReason> reason) {
            this(code, reason, Optional.empty());
        }
        private GatewayException(FailureCode code, Optional<PolicyEvaluationReason> reason,
                Optional<EnforcePolicyPostCallDecision.PostCallCheck> postCallCheck) {
            super(code.name(), null, false, true); this.code = code; this.reason = reason;
            this.postCallCheck = postCallCheck;
        }
        public FailureCode code() { return code; }
        public Optional<PolicyEvaluationReason> reason() { return reason; }
        public Optional<EnforcePolicyPostCallDecision.PostCallCheck> postCallCheck() { return postCallCheck; }
        public boolean successfulSecurityBlock() { return false; }
    }
}
