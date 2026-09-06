package com.finsecseal.policy;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Immutable, prevalidated request and server facts for Object Scope policy.
 */
public record PolicyObjectScopeFacts(
        String requestedTool,
        List<String> catalogTools,
        List<ObjectScopePolicy> scopePolicies,
        Optional<String> requestedCaseId,
        Optional<List<String>> requestedDocumentIds,
        Optional<List<String>> requestedCustomerIds,
        Optional<String> currentCaseId,
        Optional<String> currentApplicantId,
        Optional<List<String>> allowedDocumentIds,
        Optional<List<DocumentOwnership>> documentOwnerships
) {

    public PolicyObjectScopeFacts {
        requestedTool = requireConfigurationText(requestedTool, "requestedTool");
        catalogTools = copyUniqueCatalogTools(catalogTools);
        scopePolicies = copyUniqueScopePolicies(scopePolicies);
        validatePolicyCatalogReferences(catalogTools, scopePolicies);

        requestedCaseId = copyRequestText(requestedCaseId, "requestedCaseId");
        requestedDocumentIds = copyRequestIds(
                requestedDocumentIds,
                "requestedDocumentIds"
        );
        requestedCustomerIds = copyRequestIds(
                requestedCustomerIds,
                "requestedCustomerIds"
        );

        currentCaseId = copyContextText(currentCaseId, "currentCaseId");
        currentApplicantId = copyContextText(
                currentApplicantId,
                "currentApplicantId"
        );
        allowedDocumentIds = copyContextIds(
                allowedDocumentIds,
                "allowedDocumentIds"
        );
        documentOwnerships = copyOwnerships(documentOwnerships);

        Optional<ObjectScopePolicy> activePolicy = findPolicy(
                scopePolicies,
                requestedTool
        );
        if (activePolicy.isPresent()) {
            validateActiveScopeRequiredness(
                    activePolicy.orElseThrow(),
                    requestedCaseId,
                    requestedDocumentIds,
                    requestedCustomerIds,
                    currentCaseId,
                    currentApplicantId,
                    allowedDocumentIds,
                    documentOwnerships
            );
        }
    }

    public boolean isRequestedToolCatalogKnown() {
        return catalogTools.contains(requestedTool);
    }

    public Optional<ObjectScopePolicy> requestedScopePolicy() {
        return findPolicy(scopePolicies, requestedTool);
    }

    private static List<String> copyUniqueCatalogTools(List<String> values) {
        if (values == null) {
            throw new IllegalArgumentException("catalogTools must not be null");
        }

        Set<String> unique = new HashSet<>();
        for (int index = 0; index < values.size(); index++) {
            String value = requireConfigurationText(
                    values.get(index),
                    "catalogTools[" + index + "]"
            );
            if (!unique.add(value)) {
                throw new IllegalArgumentException(
                        "catalogTools must not contain duplicate tool names"
                );
            }
        }
        return List.copyOf(values);
    }

    private static List<ObjectScopePolicy> copyUniqueScopePolicies(
            List<ObjectScopePolicy> values
    ) {
        if (values == null) {
            throw new IllegalArgumentException("scopePolicies must not be null");
        }

        Set<String> unique = new HashSet<>();
        for (ObjectScopePolicy policy : values) {
            if (policy == null) {
                throw new IllegalArgumentException(
                        "scopePolicies must not contain null entries"
                );
            }
            if (!unique.add(policy.toolName())) {
                throw new IllegalArgumentException(
                        "scopePolicies must not contain duplicate tool names"
                );
            }
        }
        return List.copyOf(values);
    }

    private static void validatePolicyCatalogReferences(
            List<String> catalogTools,
            List<ObjectScopePolicy> scopePolicies
    ) {
        Set<String> catalogNames = Set.copyOf(catalogTools);
        for (ObjectScopePolicy policy : scopePolicies) {
            if (!catalogNames.contains(policy.toolName())) {
                throw new IllegalArgumentException(
                        "scopePolicies must reference catalog tools"
                );
            }
        }
    }

    private static Optional<String> copyRequestText(
            Optional<String> value,
            String field
    ) {
        if (value == null) {
            throw invalidRequest(field + " must not be null");
        }
        if (value.isPresent() && value.orElseThrow().isBlank()) {
            throw invalidRequest(field + " must not be blank");
        }
        return value;
    }

    private static Optional<List<String>> copyRequestIds(
            Optional<List<String>> values,
            String field
    ) {
        if (values == null) {
            throw invalidRequest(field + " must not be null");
        }
        if (values.isEmpty()) {
            return Optional.empty();
        }

        List<String> source = values.orElseThrow();
        if (source == null) {
            throw invalidRequest(field + " must not contain null");
        }
        List<String> snapshot = new ArrayList<>(source);
        Set<String> unique = new HashSet<>();
        for (int index = 0; index < snapshot.size(); index++) {
            String value = snapshot.get(index);
            if (value == null || value.isBlank()) {
                throw invalidRequest(
                        field + "[" + index + "] must not be blank"
                );
            }
            if (!unique.add(value)) {
                throw invalidRequest(field + " must not contain duplicates");
            }
        }
        return Optional.of(List.copyOf(snapshot));
    }

    private static Optional<String> copyContextText(
            Optional<String> value,
            String field
    ) {
        if (value == null) {
            throw contextIntegrity(field + " must not be null");
        }
        if (value.isPresent() && value.orElseThrow().isBlank()) {
            throw contextIntegrity(field + " must not be blank");
        }
        return value;
    }

    private static Optional<List<String>> copyContextIds(
            Optional<List<String>> values,
            String field
    ) {
        if (values == null) {
            throw contextIntegrity(field + " must not be null");
        }
        if (values.isEmpty()) {
            return Optional.empty();
        }

        List<String> source = values.orElseThrow();
        if (source == null) {
            throw contextIntegrity(field + " must not contain null");
        }
        List<String> snapshot = new ArrayList<>(source);
        Set<String> unique = new HashSet<>();
        for (int index = 0; index < snapshot.size(); index++) {
            String value = snapshot.get(index);
            if (value == null || value.isBlank()) {
                throw contextIntegrity(
                        field + "[" + index + "] must not be blank"
                );
            }
            if (!unique.add(value)) {
                throw contextIntegrity(field + " must not contain duplicates");
            }
        }
        return Optional.of(List.copyOf(snapshot));
    }

    private static Optional<List<DocumentOwnership>> copyOwnerships(
            Optional<List<DocumentOwnership>> values
    ) {
        if (values == null) {
            throw contextIntegrity("documentOwnerships must not be null");
        }
        if (values.isEmpty()) {
            return Optional.empty();
        }

        List<DocumentOwnership> source = values.orElseThrow();
        if (source == null) {
            throw contextIntegrity("documentOwnerships must not contain null");
        }
        List<DocumentOwnership> snapshot = new ArrayList<>(source);
        Set<String> uniqueDocuments = new HashSet<>();
        for (int index = 0; index < snapshot.size(); index++) {
            DocumentOwnership ownership = snapshot.get(index);
            if (ownership == null) {
                throw contextIntegrity(
                        "documentOwnerships must not contain null entries"
                );
            }
            if (!uniqueDocuments.add(ownership.documentId())) {
                throw contextIntegrity(
                        "documentOwnerships must not contain duplicate or conflicting rows"
                );
            }
        }
        return Optional.of(List.copyOf(snapshot));
    }

    private static void validateActiveScopeRequiredness(
            ObjectScopePolicy policy,
            Optional<String> requestedCaseId,
            Optional<List<String>> requestedDocumentIds,
            Optional<List<String>> requestedCustomerIds,
            Optional<String> currentCaseId,
            Optional<String> currentApplicantId,
            Optional<List<String>> allowedDocumentIds,
            Optional<List<DocumentOwnership>> documentOwnerships
    ) {
        if (policy.currentCaseOnly()) {
            requireRequestValue(requestedCaseId, "requestedCaseId");
            requireContextValue(currentCaseId, "currentCaseId");
        }

        if (policy.allowedDocumentsOnly()) {
            List<String> documents = requireNonEmptyRequestIds(
                    requestedDocumentIds,
                    "requestedDocumentIds"
            );
            requireContextValue(currentCaseId, "currentCaseId");
            List<String> allowedDocuments = requireContextList(
                    allowedDocumentIds,
                    "allowedDocumentIds"
            );
            List<DocumentOwnership> ownerships = requireContextList(
                    documentOwnerships,
                    "documentOwnerships"
            );
            for (String documentId : documents) {
                if (allowedDocuments.contains(documentId)) {
                    DocumentOwnership ownership = ownerships.stream()
                            .filter(candidate -> candidate.documentId()
                                    .equals(documentId))
                            .findFirst()
                            .orElseThrow(() -> contextIntegrity(
                                    "documentOwnerships must resolve every allowed requested document"
                            ));
                    if (!ownership.caseId().equals(currentCaseId.orElseThrow())) {
                        throw contextIntegrity(
                                "allowlisted document ownership must match currentCaseId"
                        );
                    }
                }
            }
        }

        if (policy.currentApplicantOnly()) {
            requireNonEmptyRequestIds(
                    requestedCustomerIds,
                    "requestedCustomerIds"
            );
            requireContextValue(currentApplicantId, "currentApplicantId");
        }
    }

    private static <T> T requireRequestValue(
            Optional<T> value,
            String field
    ) {
        return value.orElseThrow(() ->
                invalidRequest(field + " is required by the active scope"));
    }

    private static List<String> requireNonEmptyRequestIds(
            Optional<List<String>> value,
            String field
    ) {
        List<String> ids = requireRequestValue(value, field);
        if (ids.isEmpty()) {
            throw invalidRequest(field + " must not be empty for the active scope");
        }
        return ids;
    }

    private static <T> T requireContextValue(
            Optional<T> value,
            String field
    ) {
        return value.orElseThrow(() ->
                contextIntegrity(field + " is required by the active scope"));
    }

    private static <T> List<T> requireContextList(
            Optional<List<T>> value,
            String field
    ) {
        return requireContextValue(value, field);
    }

    private static Optional<ObjectScopePolicy> findPolicy(
            List<ObjectScopePolicy> policies,
            String toolName
    ) {
        return policies.stream()
                .filter(policy -> policy.toolName().equals(toolName))
                .findFirst();
    }

    private static String requireConfigurationText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }

    private static InvalidPolicyScopeRequestException invalidRequest(
            String message
    ) {
        return new InvalidPolicyScopeRequestException(message);
    }

    private static PolicyScopeContextIntegrityException contextIntegrity(
            String message
    ) {
        return new PolicyScopeContextIntegrityException(message);
    }

    public record ObjectScopePolicy(
            String toolName,
            boolean currentCaseOnly,
            boolean allowedDocumentsOnly,
            boolean currentApplicantOnly
    ) {

        public ObjectScopePolicy {
            toolName = requireConfigurationText(toolName, "scope policy tool name");
            if (!currentCaseOnly
                    && !allowedDocumentsOnly
                    && !currentApplicantOnly) {
                throw new IllegalArgumentException(
                        "object scope policy must enable at least one scope"
                );
            }
        }
    }

    public record DocumentOwnership(String documentId, String caseId) {

        public DocumentOwnership {
            if (documentId == null || documentId.isBlank()) {
                throw contextIntegrity("ownership documentId must not be blank");
            }
            if (caseId == null || caseId.isBlank()) {
                throw contextIntegrity("ownership caseId must not be blank");
            }
        }
    }
}
