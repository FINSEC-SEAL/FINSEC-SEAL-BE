package com.finsecseal.contract;

import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.SourceBoundCatalog;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ContractVersionSnapshot;
import com.finsecseal.contract.SafetyContractPatchOperation.AddConstraint;
import com.finsecseal.contract.SafetyContractPatchOperation.ConstraintKind;
import com.finsecseal.contract.SafetyContractPatchOperation.DenyTool;
import com.finsecseal.contract.SafetyContractPatchOperation.LimitKind;
import com.finsecseal.contract.SafetyContractPatchOperation.LowerLimit;
import com.finsecseal.contract.SafetyContractPatchOperation.NarrowSet;
import com.finsecseal.contract.SafetyContractPatchOperation.OperationType;
import com.finsecseal.contract.SafetyContractPatchOperation.SetHumanOnly;
import com.finsecseal.contract.SafetyContractPatchOperation.SetKind;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.FindingSourceFacts;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.ProposalDecision;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.ProposedPatch;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.springframework.stereotype.Component;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/** Parses untrusted model content and delegates judgment against caller-supplied source facts. */
@Component
public final class SafetyContractPatchResponseProcessor {

    // Local parsing limits; the existing policy owns permission and workflow rules.
    public static final int MAX_RESPONSE_BYTES = 65_536;
    public static final int MAX_DEPTH = 32;
    public static final int MAX_STRING_LENGTH = 8_192;
    public static final int MAX_NAME_LENGTH = 256;
    public static final int MAX_NUMBER_LENGTH = 100;
    public static final int MAX_TOKEN_COUNT = 16_384;

    private static final Set<String> RESPONSE_FIELDS = Set.of(
            "resultPolicy", "operations", "rootCause", "normalWorkflowImpact", "rollback");

    private static final ObjectMapper RESPONSE_MAPPER = JsonMapper.builder(JsonFactory.builder()
                    .streamReadConstraints(StreamReadConstraints.builder()
                            .maxNestingDepth(MAX_DEPTH)
                            .maxStringLength(MAX_STRING_LENGTH)
                            .maxNameLength(MAX_NAME_LENGTH)
                            .maxNumberLength(MAX_NUMBER_LENGTH)
                            .maxTokenCount(MAX_TOKEN_COUNT)
                            .build())
                    .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                    .disable(StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION)
                    .build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY)
            .enable(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS)
            .build();

    private final SafetyContractPatchProposalPolicy policy;

    public SafetyContractPatchResponseProcessor(SafetyContractPatchProposalPolicy policy) {
        this.policy = Objects.requireNonNull(policy, "policy must not be null");
    }

    public PatchAssessment process(FindingSourceFacts source, ContractVersionSnapshot base,
            SourceBoundCatalog catalog, String content) {
        if (source == null || base == null || base.identity() == null
                || base.identity().contractKey() == null || base.identity().contractKey().isBlank()
                || catalog == null || content == null) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
        // Check UTF-16 length before allocating bytes, then enforce the actual UTF-8 limit.
        if (content.length() > MAX_RESPONSE_BYTES
                || content.getBytes(StandardCharsets.UTF_8).length > MAX_RESPONSE_BYTES) {
            throw failure(FailureCode.RESPONSE_TOO_LARGE);
        }

        ProposedPatch candidate = parse(content);
        JsonNode contractKey = candidate.resultPolicy().path("contractId");
        if (!contractKey.isString()
                || !base.identity().contractKey().equals(contractKey.stringValue())) {
            throw failure(FailureCode.IDENTITY_MISMATCH);
        }

        try {
            ProposalDecision decision = Objects.requireNonNull(
                    policy.evaluate(source, base, candidate, catalog), "proposal decision");
            return new PatchAssessment(candidate, decision);
        } catch (RuntimeException exception) {
            // Engine failures are not invalid-policy judgments and must not expose model content.
            throw failure(FailureCode.PROCESSING_FAILURE);
        }
    }

    private ProposedPatch parse(String content) {
        try {
            JsonNode response = RESPONSE_MAPPER.readTree(content);
            requireFields(response, RESPONSE_FIELDS);
            JsonNode resultPolicy = response.path("resultPolicy");
            JsonNode operations = response.path("operations");
            if (!resultPolicy.isObject() || !operations.isArray()) {
                throw failure(FailureCode.MALFORMED_RESPONSE);
            }
            List<SafetyContractPatchOperation> parsedOperations = new ArrayList<>();
            for (JsonNode operation : operations) {
                parsedOperations.add(operation(operation));
            }
            return new ProposedPatch(resultPolicy, parsedOperations,
                    string(response, "rootCause"), string(response, "normalWorkflowImpact"),
                    string(response, "rollback"));
        } catch (RuntimeException exception) {
            // Neither parser diagnostics nor constructor errors are safe response content.
            throw failure(FailureCode.MALFORMED_RESPONSE);
        }
    }

    private SafetyContractPatchOperation operation(JsonNode node) {
        OperationType type = enumValue(node, "type", OperationType.class);
        return switch (type) {
            case ADD_CONSTRAINT -> {
                ConstraintKind kind = enumValue(node, "constraintKind", ConstraintKind.class);
                requireFields(node, kind.toolRequired()
                        ? Set.of("type", "constraintKind", "toolName")
                        : Set.of("type", "constraintKind"));
                yield kind.toolRequired() ? new AddConstraint(kind, string(node, "toolName"))
                        : new AddConstraint(kind);
            }
            case NARROW_SET -> {
                SetKind kind = enumValue(node, "setKind", SetKind.class);
                requireFields(node, kind.toolRequired()
                        ? Set.of("type", "setKind", "toolName", "retainedValues")
                        : Set.of("type", "setKind", "retainedValues"));
                List<String> values = strings(node.path("retainedValues"));
                yield kind.toolRequired() ? new NarrowSet(kind, string(node, "toolName"), values)
                        : new NarrowSet(kind, values);
            }
            case LOWER_LIMIT -> {
                requireFields(node, Set.of("type", "limitKind", "toolName", "newLimit"));
                JsonNode limit = node.path("newLimit");
                if (!limit.isIntegralNumber()) {
                    throw failure(FailureCode.MALFORMED_RESPONSE);
                }
                yield new LowerLimit(enumValue(node, "limitKind", LimitKind.class),
                        string(node, "toolName"), limit.bigIntegerValue());
            }
            case DENY_TOOL -> {
                requireFields(node, Set.of("type", "toolName"));
                yield new DenyTool(string(node, "toolName"));
            }
            case SET_HUMAN_ONLY -> {
                requireFields(node, Set.of("type", "toolName"));
                yield new SetHumanOnly(string(node, "toolName"));
            }
        };
    }

    private static void requireFields(JsonNode node, Set<String> fields) {
        if (node == null || !node.isObject() || node.size() != fields.size()
                || node.properties().stream().anyMatch(entry -> !fields.contains(entry.getKey()))) {
            throw failure(FailureCode.MALFORMED_RESPONSE);
        }
    }

    private static String string(JsonNode node, String field) {
        JsonNode value = node.path(field);
        if (!value.isString()) {
            throw failure(FailureCode.MALFORMED_RESPONSE);
        }
        return value.stringValue();
    }

    private static List<String> strings(JsonNode node) {
        if (!node.isArray()) {
            throw failure(FailureCode.MALFORMED_RESPONSE);
        }
        List<String> values = new ArrayList<>();
        for (JsonNode value : node) {
            if (!value.isString()) {
                throw failure(FailureCode.MALFORMED_RESPONSE);
            }
            values.add(value.stringValue());
        }
        return values;
    }

    private static <E extends Enum<E>> E enumValue(JsonNode node, String field, Class<E> type) {
        return Enum.valueOf(type, string(node, field));
    }

    /**
     * An unpersisted assessment, not proof of source authorization, held-out isolation, a model
     * call, current source freshness, saved validation, approval or execution permission.
     */
    public static final class PatchAssessment {
        private final ProposedPatch candidate;
        private final ProposalDecision decision;

        private PatchAssessment(ProposedPatch candidate, ProposalDecision decision) {
            this.candidate = candidate;
            this.decision = decision;
        }

        public ProposedPatch candidate() { return candidate; }
        public ProposalDecision decision() { return decision; }
    }

    public enum FailureCode {
        INVALID_REQUEST, RESPONSE_TOO_LARGE, MALFORMED_RESPONSE, IDENTITY_MISMATCH, PROCESSING_FAILURE
    }

    public static final class PatchResponseException extends RuntimeException {
        private final FailureCode code;

        private PatchResponseException(FailureCode code) {
            super("Contract patch response could not be processed: " + code.name(), null, false, true);
            this.code = code;
        }

        public FailureCode code() { return code; }
    }

    private static PatchResponseException failure(FailureCode code) {
        return new PatchResponseException(code);
    }
}
