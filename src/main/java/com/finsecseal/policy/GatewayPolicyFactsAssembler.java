package com.finsecseal.policy;

import com.finsecseal.contract.SafetyContractSemanticValidator.ContractValidationCatalog;
import com.finsecseal.policy.GatewayApprovedPolicySourceService.ApprovedPolicySource;
import com.finsecseal.policy.PolicyCardinalityFacts.CardinalityPolicy;
import com.finsecseal.policy.PolicyFieldScopeFacts.FieldPolicy;
import com.finsecseal.policy.PolicyFieldScopeFacts.ToolOutputSchema;
import com.finsecseal.policy.PolicyHumanBoundaryFacts.BoundaryMode;
import com.finsecseal.policy.PolicyHumanBoundaryFacts.HighImpactAction;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.runtime.ToolProposalValidator;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;

/** Projects approved policy and request values into stage facts; grants no execution authority. */
@Component
public final class GatewayPolicyFactsAssembler {
    private static final String CUSTOMER_DATA_READ = "CUSTOMER_DATA_READ";
    private static final String LOAN_DECISION_UPDATE = "LOAN_DECISION_UPDATE";
    private final ToolProposalValidator proposals;

    public GatewayPolicyFactsAssembler(ToolProposalValidator proposals) {
        this.proposals = Objects.requireNonNull(proposals);
    }

    /** No applicant identity, Run/Case binding, preflight or other policy stage is established here. */
    public CustomerDataReadFacts customerDataRead(ApprovedPolicySource source, ToolProposal proposal) {
        ToolProposal snapshot = customerRequest(proposal);
        List<String> fields = requestValues(snapshot.arguments().path("fields"));
        List<String> customerIds = requestValues(snapshot.arguments().path("customerIds"));
        try {
            JsonNode policy = policy(source);
            ContractValidationCatalog catalog = catalog(source);
            JsonNode fieldPolicy = object(policy.at("/fieldPolicy/" + CUSTOMER_DATA_READ));
            JsonNode denyUnknown = fieldPolicy.path("denyUnknown");
            if (!denyUnknown.isBoolean() || !denyUnknown.booleanValue()) throw invalidSource();
            List<String> allowed = policyValues(fieldPolicy.path("allowed"));
            JsonNode limit = object(policy.at("/cardinality/" + CUSTOMER_DATA_READ)).path("maxRequestedRecords");
            if (!limit.isIntegralNumber() || !limit.canConvertToInt() || limit.intValue() <= 0) {
                throw invalidSource();
            }
            var schemas = catalog.enabledReleaseTools().stream()
                    .map(tool -> new ToolOutputSchema(tool.toolName(), tool.outputFields())).toList();
            var tools = catalog.enabledReleaseTools().stream().map(tool -> tool.toolName()).toList();
            return new CustomerDataReadFacts(
                    new PolicyFieldScopeFacts(CUSTOMER_DATA_READ, Optional.of(fields), schemas,
                            List.of(new FieldPolicy(CUSTOMER_DATA_READ, allowed, true))),
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
            JsonNode actions = object(policy(source).path("highImpactActions"));
            ContractValidationCatalog catalog = catalog(source);
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
        } catch (FactAssemblyException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw invalidSource();
        }
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
