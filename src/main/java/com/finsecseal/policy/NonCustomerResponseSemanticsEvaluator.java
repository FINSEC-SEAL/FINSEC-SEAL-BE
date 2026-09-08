package com.finsecseal.policy;

import com.finsecseal.policy.GatewayApprovedPolicySourceService.ApprovedPolicySource;
import com.finsecseal.policy.PolicyObjectScopeFacts.DocumentOwnership;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import tools.jackson.databind.JsonNode;

/**
 * Partial response comparisons against independently resolved pre-call facts and stored document labels.
 * The caller binds those facts to the invocation and applies schema validation to the same response snapshot.
 * MATCH grants neither complete post-call PASS nor model delivery: classification and state checks remain separate.
 */
public final class NonCustomerResponseSemanticsEvaluator {
    private static final Set<String> DOCUMENT_LABELS = Set.of("UNTRUSTED_APPLICANT", "TRUSTED_INTERNAL");

    public Outcome caseContext(PolicyBusinessContextFacts serverContext, JsonNode adapterBody) {
        if (serverContext == null || !serverContext.serverResolved()) throw invalidContext();
        String caseId = required(serverContext.caseId());
        String applicant = required(serverContext.currentApplicantId());
        String stage = required(serverContext.workflowStage());
        List<String> documentIds = requiredList(serverContext.allowedDocumentIds());
        var expectedDocuments = new HashSet<String>();
        for (String id : documentIds) {
            if (id == null || id.isBlank() || !expectedDocuments.add(id)) throw invalidContext();
        }
        if (!matchesText(adapterBody, "caseId", caseId)
                || !matchesText(adapterBody, "currentApplicantId", applicant)
                || !matchesText(adapterBody, "workflowStage", stage)) return mismatch();
        JsonNode documents = adapterBody.path("allowedDocumentIds");
        if (!documents.isArray()) return mismatch();
        var returnedDocuments = new HashSet<String>();
        for (JsonNode id : documents) {
            if (!id.isString()) return mismatch();
            returnedDocuments.add(id.stringValue());
        }
        // The schema has no uniqueItems rule; document order and repeated response IDs do not change the set.
        return expectedDocuments.equals(returnedDocuments) ? Outcome.MATCH : mismatch();
    }

    public Outcome document(PolicyObjectScopeFacts invocationFacts,
            DocumentSource storedDocument, JsonNode adapterBody) {
        String caseId = boundCase(invocationFacts, "DOCUMENT_READER");
        List<String> requested = requiredList(invocationFacts.requestedDocumentIds());
        if (requested.size() != 1 || storedDocument == null) throw invalidContext();
        String documentId = requested.getFirst();
        List<String> allowed = requiredList(invocationFacts.allowedDocumentIds());
        List<DocumentOwnership> ownerships = requiredList(invocationFacts.documentOwnerships());
        DocumentOwnership storedOwnership = storedDocument.ownership();
        if (!allowed.contains(documentId) || !documentId.equals(storedOwnership.documentId())
                || !caseId.equals(storedOwnership.caseId()) || !ownerships.contains(storedOwnership)) {
            throw invalidContext();
        }
        return matchesText(adapterBody, "caseId", caseId)
                && matchesText(adapterBody, "documentId", documentId)
                && matchesText(adapterBody, "sourceTrustLevel", storedDocument.sourceTrustLevel())
                ? Outcome.MATCH : mismatch();
    }

    public Outcome reviewNote(ApprovedPolicySource approvedSource,
            PolicyObjectScopeFacts invocationFacts, JsonNode adapterBody) {
        String caseId = boundCase(invocationFacts, "REVIEW_NOTE_WRITE");
        Set<String> statuses = approvedStatuses(approvedSource);
        if (!matchesText(adapterBody, "caseId", caseId)) return mismatch();
        JsonNode status = adapterBody.path("reviewStatus");
        return status.isString() && statuses.contains(status.stringValue()) ? Outcome.MATCH : mismatch();
    }

    private Set<String> approvedStatuses(ApprovedPolicySource source) {
        try {
            if (source == null) throw invalidSource();
            JsonNode policy = source.policy();
            if (policy == null || !policy.isObject() || !policy.path("outputPolicy").isObject()) {
                throw invalidSource();
            }
            JsonNode allowed = policy.at("/outputPolicy/reviewStatusAllowed");
            if (!allowed.isArray() || allowed.isEmpty()) throw invalidSource();
            var statuses = new HashSet<String>();
            for (JsonNode status : allowed) {
                if (!status.isString() || status.stringValue().isBlank() || !statuses.add(status.stringValue())) {
                    throw invalidSource();
                }
            }
            return statuses;
        } catch (SemanticInputException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw invalidSource();
        }
    }

    private String boundCase(PolicyObjectScopeFacts facts, String tool) {
        if (facts == null || !tool.equals(facts.requestedTool()) || !facts.isRequestedToolCatalogKnown()) {
            throw invalidContext();
        }
        String currentCase = required(facts.currentCaseId());
        if (!currentCase.equals(required(facts.requestedCaseId()))) throw invalidContext();
        return currentCase;
    }

    private static String required(Optional<String> value) {
        if (value == null || value.isEmpty() || value.orElseThrow().isBlank()) throw invalidContext();
        return value.orElseThrow();
    }

    private static <T> List<T> requiredList(Optional<List<T>> value) {
        if (value == null || value.isEmpty()) throw invalidContext();
        return value.orElseThrow();
    }

    private boolean matchesText(JsonNode body, String field, String expected) {
        return body != null && body.isObject() && body.path(field).isString()
                && expected.equals(body.path(field).stringValue());
    }

    private Outcome mismatch() { return Outcome.ADAPTER_CONTRACT_FAILURE; }

    private static SemanticInputException invalidContext() {
        return new SemanticInputException(FailureCode.INVALID_EXPECTED_CONTEXT);
    }

    private static SemanticInputException invalidSource() {
        return new SemanticInputException(FailureCode.INVALID_APPROVED_SOURCE);
    }

    /** Trust label from the stored snapshot of this exact document, never from the adapter response. */
    public record DocumentSource(DocumentOwnership ownership, String sourceTrustLevel) {
        public DocumentSource {
            if (ownership == null || sourceTrustLevel == null || !DOCUMENT_LABELS.contains(sourceTrustLevel)) {
                throw invalidContext();
            }
        }
    }

    public enum Outcome { MATCH, ADAPTER_CONTRACT_FAILURE }

    public enum FailureCode { INVALID_EXPECTED_CONTEXT, INVALID_APPROVED_SOURCE }

    /** Safe input failure without document content, raw policy, owner exception or cause. */
    public static final class SemanticInputException extends RuntimeException {
        private final FailureCode code;

        private SemanticInputException(FailureCode code) {
            super(code.name());
            this.code = code;
        }

        public FailureCode code() { return code; }
    }
}
