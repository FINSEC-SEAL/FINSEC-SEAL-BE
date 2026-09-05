package com.finsecseal.policy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Immutable server-resolved facts required by the Business Context policy stage.
 */
public record PolicyBusinessContextFacts(
        boolean serverResolved,
        Optional<String> contractPurpose,
        Optional<String> releasePurpose,
        Optional<String> runPurpose,
        Optional<String> casePurpose,
        Optional<String> namespaceId,
        Optional<String> caseId,
        Optional<String> currentApplicantId,
        Optional<String> workflowStage,
        Optional<List<String>> allowedDocumentIds
) {

    public PolicyBusinessContextFacts {
        contractPurpose = requireOptional(contractPurpose, "contractPurpose");
        releasePurpose = requireOptional(releasePurpose, "releasePurpose");
        runPurpose = requireOptional(runPurpose, "runPurpose");
        casePurpose = requireOptional(casePurpose, "casePurpose");
        namespaceId = requireOptional(namespaceId, "namespaceId");
        caseId = requireOptional(caseId, "caseId");
        currentApplicantId = requireOptional(currentApplicantId, "currentApplicantId");
        workflowStage = requireOptional(workflowStage, "workflowStage");
        allowedDocumentIds = copyDocumentIds(allowedDocumentIds);
    }

    private static <T> Optional<T> requireOptional(Optional<T> value, String field) {
        if (value == null) {
            throw new IllegalArgumentException(field + " must not be null");
        }
        return value;
    }

    private static Optional<List<String>> copyDocumentIds(
            Optional<List<String>> documentIds
    ) {
        if (documentIds == null) {
            throw new IllegalArgumentException("allowedDocumentIds must not be null");
        }
        if (documentIds.isEmpty()) {
            return Optional.empty();
        }

        List<String> snapshot = new ArrayList<>(documentIds.orElseThrow());
        return Optional.of(Collections.unmodifiableList(snapshot));
    }
}
