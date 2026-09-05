package com.finsecseal.contract;

import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

@Component
public class SafetyContractCanonicalizer {

    private final SafetyContractSchemaValidator schemaValidator;
    private final CanonicalJsonService canonicalJsonService;
    private final DigestService digestService;

    public SafetyContractCanonicalizer(
            SafetyContractSchemaValidator schemaValidator,
            CanonicalJsonService canonicalJsonService,
            DigestService digestService
    ) {
        this.schemaValidator = Objects.requireNonNull(schemaValidator);
        this.canonicalJsonService = Objects.requireNonNull(canonicalJsonService);
        this.digestService = Objects.requireNonNull(digestService);
    }

    public CanonicalPolicy canonicalizeAndHash(JsonNode contract) {
        SafetyContractSchemaValidator.ValidationResult validation = schemaValidator.validate(contract);
        if (!validation.valid()) {
            throw new InvalidSafetyContractException(validation.issues());
        }

        ObjectNode normalized = ((ObjectNode) contract).deepCopy();
        sortTextSet(normalized, "allowedTools");
        sortDynamicTextSets(normalized.path("fieldPolicy"), "allowed");
        sortNestedTextSet(normalized, "externalEgress", "allowedDestinations");
        sortNestedTextSet(normalized, "workflow", "allowedStages");
        sortNestedTextSet(normalized, "toolTrust", "allowedTrustLevels");
        sortNestedTextSet(normalized, "outputPolicy", "reviewStatusAllowed");

        byte[] canonicalBytes = canonicalJsonService.canonicalize(normalized);
        return new CanonicalPolicy(
                new String(canonicalBytes, StandardCharsets.UTF_8),
                digestService.sha256(canonicalBytes)
        );
    }

    private void sortDynamicTextSets(JsonNode dynamicObject, String fieldName) {
        if (!dynamicObject.isObject()) {
            return;
        }
        dynamicObject.properties().forEach(entry -> {
            if (entry.getValue() instanceof ObjectNode object) {
                sortTextSet(object, fieldName);
            }
        });
    }

    private void sortNestedTextSet(ObjectNode root, String objectField, String arrayField) {
        if (root.path(objectField) instanceof ObjectNode object) {
            sortTextSet(object, arrayField);
        }
    }

    private void sortTextSet(ObjectNode parent, String fieldName) {
        if (!(parent.path(fieldName) instanceof ArrayNode array)) {
            return;
        }
        List<JsonNode> values = new ArrayList<>();
        array.forEach(values::add);
        Comparator<JsonNode> comparator = Comparator.comparing(
                node -> SafetyContractTextNormalizer.normalize(node.stringValue())
        );
        values.sort(comparator);
        array.removeAll();
        values.forEach(array::add);
    }

    public record CanonicalPolicy(String canonicalJson, String policyHash) {
        public CanonicalPolicy {
            Objects.requireNonNull(canonicalJson);
            Objects.requireNonNull(policyHash);
        }
    }

    public static class InvalidSafetyContractException extends IllegalArgumentException {

        private final List<SafetyContractSchemaValidator.Issue> issues;

        public InvalidSafetyContractException(List<SafetyContractSchemaValidator.Issue> issues) {
            super("Safety Contract failed structural validation");
            this.issues = List.copyOf(issues);
        }

        public List<SafetyContractSchemaValidator.Issue> issues() {
            return issues;
        }
    }
}
