package com.finsecseal.policy;

import com.finsecseal.contract.LoanReviewFinancialTemplate;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.SourceBoundCatalog;
import com.finsecseal.contract.SafetyContractSemanticValidator.ContractValidationCatalog;
import com.finsecseal.policy.EnforcePolicyPostCallFacts.CatalogOutputField;
import com.finsecseal.policy.GatewayApprovedPolicySourceService.ApprovedPolicySource;
import com.finsecseal.policy.GatewayBaselinePolicySourceService.BaselinePolicySource;
import com.finsecseal.policy.PolicyCardinalityFacts.CardinalityPolicy;
import com.finsecseal.policy.PolicyFieldScopeFacts.FieldPolicy;
import com.finsecseal.policy.PolicyFieldScopeFacts.ToolOutputSchema;
import com.finsecseal.policy.PolicyHumanBoundaryFacts.BoundaryMode;
import com.finsecseal.policy.PolicyHumanBoundaryFacts.HighImpactAction;
import com.finsecseal.policy.PolicyObjectScopeFacts.DocumentOwnership;
import com.finsecseal.policy.PolicyObjectScopeFacts.ObjectScopePolicy;
import com.finsecseal.policy.PolicyToolTrustFacts.ReleaseToolBinding;
import com.finsecseal.policy.PolicyToolTrustFacts.ToolRegistryEntry;
import com.finsecseal.policy.PolicyToolTrustFacts.ToolTrustPolicy;
import com.finsecseal.policy.PolicyToolTrustFacts.TrustLevel;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.runtime.ToolProposalValidator;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;
import java.util.UUID;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;

/** Projects policy expectations and request values into stage facts; grants no execution authority. */
@Component
public final class GatewayPolicyFactsAssembler {
    private static final String CUSTOMER_DATA_READ = "CUSTOMER_DATA_READ";
    private static final String LOAN_DECISION_UPDATE = "LOAN_DECISION_UPDATE";
    private final ToolProposalValidator proposals;

    public GatewayPolicyFactsAssembler(ToolProposalValidator proposals) {
        this.proposals = Objects.requireNonNull(proposals);
    }

    /** Internal source expectations only; no runtime observation or stage result is constructed. */
    PolicyInputs approvedInputs(ApprovedPolicySource source) {
        try {
            return new PolicyInputs(policy(source), source.catalog(), null);
        } catch (RuntimeException exception) {
            throw invalidSource();
        }
    }

    PolicyInputs baselineInputs(BaselinePolicySource source, LoanReviewFinancialTemplate template) {
        try {
            if (source == null || template == null) throw invalidSource();
            JsonNode rules = object(template.policyRules());
            if (!LoanReviewFinancialTemplate.KEY.equals(rules.at("/metadata/templateVersion").stringValue())
                    || !LoanReviewFinancialTemplate.PURPOSE.equals(rules.path("purpose").stringValue())
                    || !LoanReviewFinancialTemplate.PURPOSE.equals(source.releasePurpose())
                    || source.catalog() == null || !source.catalog().releaseId().equals(source.releaseId())) {
                throw invalidSource();
            }
            JsonNode workflow = object(source.releaseDeclarations().path("businessWorkflow"));
            return new PolicyInputs(rules, source.catalog(), workflow);
        } catch (RuntimeException exception) {
            throw invalidSource();
        }
    }

    PolicyToolAuthorizationFacts authorizationFor(PolicyInputs inputs, String requestedTool,
            String requestedOperation) {
        requireStageToolName(requestedTool);
        if (requestedOperation == null || requestedOperation.isBlank()) throw failure(FailureCode.INVALID_REQUEST);
        try {
            requireInputs(inputs);
            var declarations = declaredTools(inputs.catalog);
            if (inputs.baseline()) {
                // Server-known HUMAN_ONLY is not a BASELINE mock-experiment execution permission.
                var normal = inputs.catalog.semanticCatalog().enabledReleaseTools().stream()
                        .map(tool -> tool.toolName()).toList();
                return new PolicyToolAuthorizationFacts(requestedTool, requestedOperation, declarations,
                        normal, false, List.of());
            }
            var egress = egress(inputs.policy, requestedTool, declarations);
            var human = humanBoundary(inputs.policy, inputs.catalog.semanticCatalog(), requestedTool);
            var allowed = policyValues(inputs.policy.path("allowedTools"));
            for (String tool : allowed) {
                if (!inputs.catalog.semanticCatalog().hasEnabledTool(tool)
                        || inputs.catalog.semanticCatalog().hasHighImpactTool(tool)) throw invalidSource();
            }
            return new PolicyToolAuthorizationFacts(requestedTool, requestedOperation, declarations,
                    allowed, !egress.externalEgressAllowed(),
                    human.highImpactActions().stream().map(HighImpactAction::toolName).toList());
        } catch (RuntimeException exception) {
            throw invalidSource();
        }
    }

    PolicyBusinessContextFacts businessContextFor(PolicyInputs inputs, boolean serverResolved,
            Optional<String> releasePurpose, Optional<String> runPurpose, Optional<String> casePurpose,
            Optional<String> namespaceId, Optional<String> caseId, Optional<String> currentApplicantId,
            Optional<String> workflowStage, Optional<List<String>> allowedDocumentIds) {
        String purpose;
        try {
            JsonNode value = requireInputs(inputs).policy.path("purpose");
            if (!value.isString() || value.stringValue().isBlank()) throw invalidSource();
            purpose = value.stringValue();
        } catch (RuntimeException exception) {
            throw invalidSource();
        }
        try {
            return new PolicyBusinessContextFacts(serverResolved, Optional.of(purpose), releasePurpose,
                    runPurpose, casePurpose, namespaceId, caseId, currentApplicantId, workflowStage, allowedDocumentIds);
        } catch (RuntimeException exception) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
    }

    PolicyObjectScopeFacts objectScopeFor(PolicyInputs inputs, String requestedTool,
            Optional<String> requestedCaseId, Optional<List<String>> requestedDocumentIds,
            Optional<List<String>> requestedCustomerIds, Optional<String> currentCaseId,
            Optional<String> currentApplicantId, Optional<List<String>> allowedDocumentIds,
            Optional<List<DocumentOwnership>> documentOwnerships) {
        requireStageToolName(requestedTool);
        List<String> tools;
        List<ObjectScopePolicy> scopes;
        try {
            var catalog = requireInputs(inputs).catalog.semanticCatalog();
            tools = catalogToolNames(catalog);
            scopes = objectScopes(inputs.policy, catalog);
        } catch (RuntimeException exception) {
            throw invalidSource();
        }
        try {
            return new PolicyObjectScopeFacts(requestedTool, tools, scopes, requestedCaseId,
                    requestedDocumentIds, requestedCustomerIds, currentCaseId, currentApplicantId,
                    allowedDocumentIds, documentOwnerships);
        } catch (InvalidPolicyScopeRequestException | PolicyScopeContextIntegrityException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
    }

    /** Reads only fields, not customerIds or the later cardinality rule; C preflight runs first. */
    PolicyFieldScopeFacts fieldScopeFor(PolicyInputs inputs, ToolProposal request) {
        String tool = stageRequestTool(request);
        Optional<List<String>> fields = CUSTOMER_DATA_READ.equals(tool)
                ? Optional.of(stageRequestValues(request, "fields")) : Optional.empty();
        List<ToolOutputSchema> schemas;
        List<FieldPolicy> policies;
        try {
            var catalog = requireInputs(inputs).catalog.semanticCatalog();
            schemas = new ArrayList<>();
            catalog.enabledReleaseTools().forEach(value ->
                    schemas.add(new ToolOutputSchema(value.toolName(), value.outputFields())));
            // Empty fields express membership for a no-rule human Tool, not its real output schema.
            for (String human : catalog.highImpactToolNames()) schemas.add(new ToolOutputSchema(human, List.of()));
            JsonNode fieldPolicies = object(inputs.policy.path("fieldPolicy"));
            if (CUSTOMER_DATA_READ.equals(tool)) {
                policies = List.of(customerFieldPolicy(inputs.policy));
            } else {
                if (fieldPolicies.has(tool)) throw invalidSource();
                policies = List.of();
            }
        } catch (RuntimeException exception) {
            throw invalidSource();
        }
        try {
            return new PolicyFieldScopeFacts(tool, fields, schemas, policies);
        } catch (InvalidPolicyScopeRequestException exception) {
            throw failure(FailureCode.INVALID_REQUEST);
        } catch (RuntimeException exception) {
            throw invalidSource();
        }
    }

    /** Counts raw request entries without deduplication and never reads the Field Scope inputs. */
    PolicyCardinalityFacts cardinalityFor(PolicyInputs inputs, ToolProposal request) {
        String tool = stageRequestTool(request);
        // Zero is unused when no rule exists; it is not an observation of returned or requested rows.
        int count = CUSTOMER_DATA_READ.equals(tool)
                ? stageRequestValues(request, "customerIds").size() : 0;
        try {
            var catalog = requireInputs(inputs).catalog.semanticCatalog();
            JsonNode rules = object(inputs.policy.path("cardinality"));
            List<CardinalityPolicy> policies;
            if (CUSTOMER_DATA_READ.equals(tool)) {
                JsonNode limit = object(rules.path(tool)).path("maxRequestedRecords");
                if (!limit.isIntegralNumber() || !limit.canConvertToInt() || limit.intValue() <= 0) throw invalidSource();
                policies = List.of(new CardinalityPolicy(tool, limit.intValue()));
            } else {
                // Includes return-only rules: unsupported active rules must not become no-rule PASS.
                if (rules.has(tool)) throw invalidSource();
                policies = List.of();
            }
            return new PolicyCardinalityFacts(tool, count, catalogToolNames(catalog), policies);
        } catch (RuntimeException exception) {
            throw invalidSource();
        }
    }

    PolicyEgressFacts egressFor(PolicyInputs inputs, String requestedTool) {
        requireStageToolName(requestedTool);
        try {
            requireInputs(inputs);
            return egress(inputs.policy, requestedTool, declaredTools(inputs.catalog));
        } catch (RuntimeException exception) {
            throw invalidSource();
        }
    }

    PolicyWorkflowFacts workflowFor(PolicyInputs inputs, String requestedTool, String serverWorkflowStage) {
        requireStageToolName(requestedTool);
        if (serverWorkflowStage == null || serverWorkflowStage.isBlank()) throw failure(FailureCode.INVALID_REQUEST);
        try {
            requireInputs(inputs);
            JsonNode workflow = inputs.baseline() ? inputs.baselineWorkflow : object(inputs.policy.path("workflow"));
            var stages = policyValues(workflow.path("allowedStages"));
            var tools = catalogToolNames(inputs.catalog.semanticCatalog()).stream()
                    .map(name -> new PolicyWorkflowFacts.CatalogTool(name, "CASE_CONTEXT_READ".equals(name))).toList();
            return new PolicyWorkflowFacts(requestedTool, serverWorkflowStage, stages, tools);
        } catch (RuntimeException exception) {
            throw invalidSource();
        }
    }

    PolicyHumanBoundaryFacts humanBoundaryFor(PolicyInputs inputs, String requestedTool) {
        requireStageToolName(requestedTool);
        try {
            requireInputs(inputs);
            return humanBoundary(inputs.policy, inputs.catalog.semanticCatalog(), requestedTool);
        } catch (RuntimeException exception) {
            throw invalidSource();
        }
    }

    /** Called only at TOOL_TRUST; observed registry entries are never filled from declarations. */
    PolicyToolTrustFacts toolTrustFor(PolicyInputs inputs, String requestedTool,
            String observedReleaseFingerprint, List<ToolRegistryEntry> observedRegistry) {
        requireStageToolName(requestedTool);
        String expectedFingerprint;
        List<ReleaseToolBinding> bindings;
        ToolTrustPolicy trust;
        try {
            requireInputs(inputs);
            expectedFingerprint = inputs.catalog.releaseFingerprint();
            bindings = inputs.catalog.releaseToolBindings();
            JsonNode rules = object(inputs.policy.path("toolTrust"));
            JsonNode required = rules.path("requireTrustedTool");
            if (!required.isBoolean()) throw invalidSource();
            var levels = policyValues(rules.path("allowedTrustLevels")).stream().map(TrustLevel::valueOf).toList();
            trust = new ToolTrustPolicy(required.booleanValue(), levels);
        } catch (RuntimeException exception) {
            throw invalidSource();
        }
        try {
            // Keep complete bindings/observations, including constructor checks for unrelated entries.
            return new PolicyToolTrustFacts(requestedTool, expectedFingerprint, observedReleaseFingerprint,
                    observedRegistry, bindings, trust);
        } catch (RuntimeException exception) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
    }

    /** No applicant identity, Run/Case binding, preflight or other policy stage is established here. */
    public CustomerDataReadFacts customerDataRead(ApprovedPolicySource source, ToolProposal proposal) {
        ToolProposal snapshot = customerRequest(proposal);
        List<String> fields = requestValues(snapshot.arguments().path("fields"));
        List<String> customerIds = requestValues(snapshot.arguments().path("customerIds"));
        try {
            JsonNode policy = policy(source);
            ContractValidationCatalog catalog = catalog(source);
            FieldPolicy fieldPolicy = customerFieldPolicy(policy);
            JsonNode limit = object(policy.at("/cardinality/" + CUSTOMER_DATA_READ)).path("maxRequestedRecords");
            if (!limit.isIntegralNumber() || !limit.canConvertToInt() || limit.intValue() <= 0) {
                throw invalidSource();
            }
            var schemas = catalog.enabledReleaseTools().stream()
                    .map(tool -> new ToolOutputSchema(tool.toolName(), tool.outputFields())).toList();
            var tools = catalog.enabledReleaseTools().stream().map(tool -> tool.toolName()).toList();
            return new CustomerDataReadFacts(
                    new PolicyFieldScopeFacts(CUSTOMER_DATA_READ, Optional.of(fields), schemas,
                            List.of(fieldPolicy)),
                    new PolicyCardinalityFacts(CUSTOMER_DATA_READ, customerIds.size(), tools,
                            List.of(new CardinalityPolicy(CUSTOMER_DATA_READ, limit.intValue()))));
        } catch (FactAssemblyException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw invalidSource();
        }
    }

    /** Only projects the human boundary. Tool authorization must precede evaluation of these facts. */
    public PolicyHumanBoundaryFacts humanBoundary(ApprovedPolicySource source, String requestedTool) {
        requireToolName(requestedTool);
        try {
            return humanBoundary(policy(source), catalog(source), requestedTool);
        } catch (FactAssemblyException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw invalidSource();
        }
    }

    /** Requested operation is independent runtime input, never inferred from a declaration. */
    public PolicyToolAuthorizationFacts toolAuthorization(ApprovedPolicySource source,
            String requestedTool, String requestedOperation) {
        requireToolName(requestedTool);
        if (requestedOperation == null || requestedOperation.isBlank()) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
        try {
            JsonNode policy = policy(source);
            var declarations = declaredTools(source);
            var egress = egress(policy, requestedTool, declarations);
            var human = humanBoundary(source, requestedTool);
            var allowed = policyValues(policy.path("allowedTools"));
            ContractValidationCatalog catalog = catalog(source);
            for (String tool : allowed) {
                if (!catalog.hasEnabledTool(tool) || catalog.hasHighImpactTool(tool)) throw invalidSource();
            }
            return new PolicyToolAuthorizationFacts(requestedTool, requestedOperation, declarations,
                    allowed, !egress.externalEgressAllowed(),
                    human.highImpactActions().stream().map(HighImpactAction::toolName).toList());
        } catch (FactAssemblyException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw invalidSource();
        }
    }

    /** Declared egress classification only; does not establish an observed registry or Tool-stage pass. */
    public PolicyEgressFacts egress(ApprovedPolicySource source, String requestedTool) {
        requireToolName(requestedTool);
        try {
            return egress(policy(source), requestedTool, declaredTools(source));
        } catch (FactAssemblyException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw invalidSource();
        }
    }

    /** Server stage is independent input; only CASE_CONTEXT_READ is a workflow bootstrap. */
    public PolicyWorkflowFacts workflow(ApprovedPolicySource source, String requestedTool,
            String serverWorkflowStage) {
        requireToolName(requestedTool);
        if (serverWorkflowStage == null || serverWorkflowStage.isBlank()) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
        try {
            var stages = policyValues(object(policy(source).path("workflow")).path("allowedStages"));
            var tools = catalogToolNames(source).stream()
                    .map(name -> new PolicyWorkflowFacts.CatalogTool(name, "CASE_CONTEXT_READ".equals(name)))
                    .toList();
            return new PolicyWorkflowFacts(requestedTool, serverWorkflowStage, stages, tools);
        } catch (RuntimeException exception) {
            throw invalidSource();
        }
    }

    /** Only contractPurpose comes from policy; caller context is not repaired or authenticated here. */
    public PolicyBusinessContextFacts businessContext(ApprovedPolicySource source, boolean serverResolved,
            Optional<String> releasePurpose, Optional<String> runPurpose, Optional<String> casePurpose,
            Optional<String> namespaceId, Optional<String> caseId, Optional<String> currentApplicantId,
            Optional<String> workflowStage, Optional<List<String>> allowedDocumentIds) {
        String contractPurpose;
        try {
            JsonNode purpose = policy(source).path("purpose");
            if (!purpose.isString() || purpose.stringValue().isBlank()) throw invalidSource();
            contractPurpose = purpose.stringValue();
        } catch (RuntimeException exception) {
            throw invalidSource();
        }
        try {
            return new PolicyBusinessContextFacts(serverResolved, Optional.of(contractPurpose),
                    releasePurpose, runPurpose, casePurpose, namespaceId, caseId, currentApplicantId,
                    workflowStage, allowedDocumentIds);
        } catch (RuntimeException exception) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
    }

    /** Keeps malformed request identities distinct from missing/ambiguous server context. */
    public PolicyObjectScopeFacts objectScope(ApprovedPolicySource source, String requestedTool,
            Optional<String> requestedCaseId, Optional<List<String>> requestedDocumentIds,
            Optional<List<String>> requestedCustomerIds, Optional<String> currentCaseId,
            Optional<String> currentApplicantId, Optional<List<String>> allowedDocumentIds,
            Optional<List<DocumentOwnership>> documentOwnerships) {
        requireToolName(requestedTool);
        List<String> tools;
        List<ObjectScopePolicy> scopes;
        try {
            tools = catalogToolNames(source);
            scopes = objectScopes(policy(source), catalog(source));
        } catch (RuntimeException exception) {
            throw invalidSource();
        }
        try {
            return new PolicyObjectScopeFacts(requestedTool, tools, scopes, requestedCaseId,
                    requestedDocumentIds, requestedCustomerIds, currentCaseId, currentApplicantId,
                    allowedDocumentIds, documentOwnerships);
        } catch (InvalidPolicyScopeRequestException | PolicyScopeContextIntegrityException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
    }

    /** Builds response expectations; invocation authenticity and actual execution remain caller obligations. */
    public EnforcePolicyPostCallFacts customerDataReadPostCall(ApprovedPolicySource source,
            ToolProposal executedProposal, String currentApplicantId, JsonNode adapterResponse,
            JsonNode adapterClassificationMap, JsonNode adapterStateDeltaProvenance) {
        ToolProposal request = customerRequest(executedProposal);
        List<String> fields = requestValues(request.arguments().path("fields"));
        List<String> customers = requestValues(request.arguments().path("customerIds"));
        if (currentApplicantId == null || currentApplicantId.isBlank()) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
        List<CatalogOutputField> expectedFields;
        List<String> projection;
        int returnedLimit;
        String namespace;
        UUID caseRunId;
        var catalogNames = new HashSet<String>();
        try {
            JsonNode policy = policy(source);
            if (!LoanReviewFinancialTemplate.PURPOSE.equals(policy.path("purpose").stringValue())
                    || !LoanReviewFinancialTemplate.KEY.equals(
                            policy.at("/metadata/templateVersion").stringValue())) throw invalidSource();
            projection = customerFieldPolicy(policy).allowedFields();
            var semanticFields = catalog(source).enabledReleaseTools().stream()
                    .filter(tool -> CUSTOMER_DATA_READ.equals(tool.toolName())).findFirst()
                    .orElseThrow(GatewayPolicyFactsAssembler::invalidSource).outputFields();
            expectedFields = List.copyOf(source.catalog().customerOutputFields());
            for (var field : expectedFields) {
                if (!catalogNames.add(field.fieldName())) throw invalidSource();
            }
            if (catalogNames.isEmpty() || !catalogNames.equals(new HashSet<>(semanticFields))
                    || !catalogNames.containsAll(projection)) throw invalidSource();
            JsonNode limit = object(policy.at("/cardinality/" + CUSTOMER_DATA_READ)).path("maxReturnedRecords");
            if (!limit.isIntegralNumber() || !limit.canConvertToInt() || limit.intValue() <= 0) {
                throw invalidSource();
            }
            returnedLimit = limit.intValue();
            if (source.runId() == null || source.testCaseRunId() == null) throw invalidSource();
            // Current B SandboxExecutionContext/FixtureService contract: namespace UUID == Run UUID.
            // This is an expected identity, not proof of namespace state or execution provenance.
            namespace = source.runId().toString();
            caseRunId = source.testCaseRunId();
        } catch (RuntimeException exception) {
            throw invalidSource();
        }
        if (!catalogNames.containsAll(fields)) throw failure(FailureCode.INVALID_REQUEST);
        try {
            // Raw malformed/null adapter values are snapshotted by Facts for the existing guard.
            return new EnforcePolicyPostCallFacts(CUSTOMER_DATA_READ, currentApplicantId, customers, fields,
                    projection, expectedFields, returnedLimit, namespace, caseRunId,
                    adapterResponse, adapterClassificationMap, adapterStateDeltaProvenance);
        } catch (RuntimeException exception) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
    }

    private static FieldPolicy customerFieldPolicy(JsonNode policy) {
        JsonNode fieldPolicy = object(policy.at("/fieldPolicy/" + CUSTOMER_DATA_READ));
        JsonNode denyUnknown = fieldPolicy.path("denyUnknown");
        if (!denyUnknown.isBoolean() || !denyUnknown.booleanValue()) throw invalidSource();
        return new FieldPolicy(CUSTOMER_DATA_READ, policyValues(fieldPolicy.path("allowed")), true);
    }

    private static PolicyHumanBoundaryFacts humanBoundary(JsonNode policy, ContractValidationCatalog catalog,
            String requestedTool) {
        JsonNode actions = object(policy.path("highImpactActions"));
        if (!"HUMAN_ONLY".equals(actions.path(LOAN_DECISION_UPDATE).stringValue())) throw invalidSource();
        // Do not use allowedTools: human-only operations deliberately live outside that allowlist.
        var tools = new LinkedHashSet<String>();
        catalog.enabledReleaseTools().forEach(tool -> tools.add(tool.toolName()));
        tools.addAll(catalog.highImpactToolNames());
        var mappings = new ArrayList<HighImpactAction>();
        for (var entry : actions.properties()) {
            if (!catalog.hasHighImpactTool(entry.getKey()) || !entry.getValue().isString()
                    || !"HUMAN_ONLY".equals(entry.getValue().stringValue())) throw invalidSource();
            mappings.add(new HighImpactAction(entry.getKey(), BoundaryMode.HUMAN_ONLY));
        }
        for (String tool : catalog.highImpactToolNames()) {
            if (!actions.has(tool)) throw invalidSource();
        }
        return new PolicyHumanBoundaryFacts(requestedTool, List.copyOf(tools), mappings);
    }

    private static List<ObjectScopePolicy> objectScopes(JsonNode policy, ContractValidationCatalog catalog) {
        JsonNode resources = object(policy.path("resourcePolicies"));
        var scopes = new TreeMap<String, ObjectScopePolicy>();
        for (var entry : resources.properties()) {
            String tool = entry.getKey();
            if (!catalog.hasEnabledTool(tool)) throw invalidSource();
            JsonNode resource = object(entry.getValue());
            boolean caseOnly = false;
            boolean documentsOnly = false;
            for (var rule : resource.properties()) {
                if (!rule.getValue().isString()) throw invalidSource();
                switch (rule.getKey()) {
                    case "caseScope" -> {
                        if (!"CURRENT_CASE_ONLY".equals(rule.getValue().stringValue())) throw invalidSource();
                        caseOnly = true;
                    }
                    case "documentScope" -> {
                        if (!"ALLOWED_DOCUMENTS_ONLY".equals(rule.getValue().stringValue())) throw invalidSource();
                        documentsOnly = true;
                    }
                    default -> throw invalidSource();
                }
            }
            // Existing policy type rejects empty rules rather than treating them as unrestricted.
            scopes.put(tool, new ObjectScopePolicy(tool, caseOnly, documentsOnly, false));
        }
        var document = scopes.get("DOCUMENT_READER");
        var note = scopes.get("REVIEW_NOTE_WRITE");
        if (document == null || !document.currentCaseOnly() || !document.allowedDocumentsOnly()
                || note == null || !note.currentCaseOnly()) throw invalidSource();
        JsonNode customer = object(policy.path("customerScope"));
        if (!"CURRENT_APPLICANT_ONLY".equals(customer.path("type").stringValue())
                || !catalog.hasEnabledTool(CUSTOMER_DATA_READ)) throw invalidSource();
        var existing = scopes.get(CUSTOMER_DATA_READ);
        scopes.put(CUSTOMER_DATA_READ, new ObjectScopePolicy(CUSTOMER_DATA_READ,
                existing != null && existing.currentCaseOnly(),
                existing != null && existing.allowedDocumentsOnly(), true));
        return List.copyOf(scopes.values());
    }

    private static List<String> catalogToolNames(ApprovedPolicySource source) {
        return catalogToolNames(catalog(source));
    }

    private static List<String> catalogToolNames(ContractValidationCatalog catalog) {
        var names = new LinkedHashSet<String>();
        for (var tool : catalog.enabledReleaseTools()) {
            if (!names.add(tool.toolName())) throw invalidSource();
        }
        for (String tool : catalog.highImpactToolNames()) {
            if (!names.add(tool)) throw invalidSource();
        }
        if (names.isEmpty()) throw invalidSource();
        return List.copyOf(names);
    }

    private static PolicyEgressFacts egress(JsonNode policy, String requestedTool,
            List<PolicyToolAuthorizationFacts.CatalogTool> declarations) {
        JsonNode egress = object(policy.path("externalEgress"));
        JsonNode allowed = egress.path("allowed");
        JsonNode destinations = egress.path("allowedDestinations");
        if (!allowed.isBoolean() || !destinations.isArray()) throw invalidSource();
        var values = new ArrayList<String>();
        for (JsonNode destination : destinations) {
            if (!destination.isString()) throw invalidSource();
            values.add(destination.stringValue());
        }
        var catalog = declarations.stream().map(tool -> new PolicyEgressFacts.CatalogTool(tool.name(),
                tool.externalEgressTool() ? PolicyEgressFacts.EgressClassification.EXTERNAL
                        : PolicyEgressFacts.EgressClassification.INTERNAL)).toList();
        // Existing facts enforce P0 false + empty destinations; never supply a fallback policy.
        return new PolicyEgressFacts(requestedTool, catalog, allowed.booleanValue(), values);
    }

    private static List<PolicyToolAuthorizationFacts.CatalogTool> declaredTools(ApprovedPolicySource source) {
        ContractValidationCatalog catalog = catalog(source);
        return declaredTools(source.catalog(), catalog);
    }

    private static List<PolicyToolAuthorizationFacts.CatalogTool> declaredTools(SourceBoundCatalog source) {
        return declaredTools(source, source.semanticCatalog());
    }

    private static List<PolicyToolAuthorizationFacts.CatalogTool> declaredTools(SourceBoundCatalog source,
            ContractValidationCatalog catalog) {
        var expected = new HashSet<String>();
        catalog.enabledReleaseTools().forEach(tool -> expected.add(tool.toolName()));
        for (String tool : catalog.highImpactToolNames()) {
            if (!expected.add(tool)) throw invalidSource();
        }
        var declarations = List.copyOf(source.declaredTools());
        var actual = new HashSet<String>();
        for (var tool : declarations) {
            if (!actual.add(tool.name())) throw invalidSource();
        }
        if (actual.isEmpty() || !actual.equals(expected)) throw invalidSource();
        return declarations;
    }

    /** New stage entrypoints consume C's bounded schema-checked request, never B validation hooks. */
    private static String stageRequestTool(ToolProposal proposal) {
        try {
            if (proposal == null) throw failure(FailureCode.INVALID_REQUEST);
            requireStageToolName(proposal.toolName());
            if (proposal.arguments() == null || !proposal.arguments().isObject()) throw failure(FailureCode.INVALID_REQUEST);
            return proposal.toolName();
        } catch (RuntimeException exception) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
    }

    private static List<String> stageRequestValues(ToolProposal request, String field) {
        try {
            JsonNode array = request.arguments().path(field);
            if (array == null || !array.isArray() || array.isEmpty()) throw failure(FailureCode.INVALID_REQUEST);
            var values = new ArrayList<String>();
            var unique = new HashSet<String>();
            for (JsonNode item : array) {
                if (!item.isString() || item.stringValue().isBlank() || !unique.add(item.stringValue())) {
                    throw failure(FailureCode.INVALID_REQUEST);
                }
                values.add(item.stringValue());
            }
            return List.copyOf(values);
        } catch (RuntimeException exception) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
    }

    private static PolicyInputs requireInputs(PolicyInputs inputs) {
        if (inputs == null) throw invalidSource();
        return inputs;
    }

    private static void requireStageToolName(String tool) {
        if (!CatalogBoundInputSchemaEvaluator.validToolName(tool)) throw failure(FailureCode.INVALID_REQUEST);
    }

    private ToolProposal customerRequest(ToolProposal proposal) {
        if (proposal == null) throw failure(FailureCode.INVALID_REQUEST);
        requireToolName(proposal.toolName());
        if (!CUSTOMER_DATA_READ.equals(proposal.toolName())) throw failure(FailureCode.UNSUPPORTED_TOOL);
        try {
            if (proposal.arguments() == null) throw failure(FailureCode.INVALID_REQUEST);
            var snapshot = new ToolProposal(proposal.toolName(), proposal.arguments().deepCopy());
            // Existing B validation hook only: never adapter.execute, dispatch, or persist a decision.
            proposals.validate(snapshot);
            return snapshot;
        } catch (RuntimeException exception) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
    }

    private static void requireToolName(String tool) {
        if (tool == null || tool.isBlank() || tool.length() > 80 || !tool.matches("[A-Z0-9_:-]+")) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
    }

    private static List<String> requestValues(JsonNode array) {
        // B validates shape and limits. C additionally rejects duplicates rather than reducing counts.
        var values = new ArrayList<String>();
        var unique = new HashSet<String>();
        for (JsonNode item : array) {
            String value = item.stringValue();
            if (!unique.add(value)) throw failure(FailureCode.INVALID_REQUEST);
            values.add(value);
        }
        return List.copyOf(values);
    }

    private static JsonNode policy(ApprovedPolicySource source) {
        if (source == null) throw invalidSource();
        return object(source.policy());
    }

    private static ContractValidationCatalog catalog(ApprovedPolicySource source) {
        if (source.catalog() == null || source.catalog().semanticCatalog() == null) throw invalidSource();
        return source.catalog().semanticCatalog();
    }

    private static JsonNode object(JsonNode value) {
        if (value == null || !value.isObject()) throw invalidSource();
        return value;
    }

    private static List<String> policyValues(JsonNode array) {
        if (!array.isArray() || array.isEmpty()) throw invalidSource();
        var values = new ArrayList<String>();
        for (JsonNode value : array) {
            if (!value.isString()) throw invalidSource();
            values.add(value.stringValue());
        }
        return values;
    }

    /** Policy expectations, not proof of approval or observed runtime context. */
    static final class PolicyInputs {
        private final JsonNode policy;
        private final SourceBoundCatalog catalog;
        private final JsonNode baselineWorkflow;

        private PolicyInputs(JsonNode policy, SourceBoundCatalog catalog, JsonNode baselineWorkflow) {
            this.policy = object(policy).deepCopy();
            this.catalog = Objects.requireNonNull(catalog);
            Objects.requireNonNull(catalog.semanticCatalog());
            this.baselineWorkflow = baselineWorkflow == null ? null : object(baselineWorkflow).deepCopy();
        }

        JsonNode policy() { return policy.deepCopy(); }
        SourceBoundCatalog catalog() { return catalog; }
        boolean baseline() { return baselineWorkflow != null; }
    }

    public record CustomerDataReadFacts(PolicyFieldScopeFacts fieldScope, PolicyCardinalityFacts cardinality) {
        public CustomerDataReadFacts {
            Objects.requireNonNull(fieldScope);
            Objects.requireNonNull(cardinality);
        }
    }

    public enum FailureCode { INVALID_REQUEST, UNSUPPORTED_TOOL, INVALID_POLICY_SOURCE }

    public static final class FactAssemblyException extends RuntimeException {
        private final FailureCode code;

        private FactAssemblyException(FailureCode code) {
            super("Gateway policy facts unavailable: " + code.name(), null, false, true);
            this.code = code;
        }

        public FailureCode code() { return code; }
    }

    private static FactAssemblyException invalidSource() { return failure(FailureCode.INVALID_POLICY_SOURCE); }

    private static FactAssemblyException failure(FailureCode code) { return new FactAssemblyException(code); }
}
