package com.finsecseal.runtime.ai;

import java.util.List;
import java.util.UUID;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.JsonNodeFactory;

@FunctionalInterface
public interface AgentRunContextResolver {

    /**
     * Legacy release-only resolver retained for existing deterministic unit fixtures.
     * Production HTTP execution uses the scoped overload below.
     */
    ResolvedRunContext resolve(UUID testRunId);

    /**
     * Resolve the complete trusted execution context for a concrete sandbox case.
     *
     * <p>The default bridge exists only so legacy deterministic test fixtures remain source-compatible.
     * The production JDBC resolver overrides this method and resolves immutable release/sandbox state.</p>
     */
    default ResolvedAgentExecutionContext resolve(
            UUID testRunId,
            String caseKey,
            String currentApplicantId
    ) {
        ResolvedRunContext legacy = resolve(testRunId);
        if (legacy == null || legacy.releaseId() == null) {
            throw new IllegalStateException("Legacy AI run context must contain releaseId");
        }
        return ResolvedAgentExecutionContext.legacy(
                legacy.releaseId(),
                caseKey,
                currentApplicantId
        );
    }

    record ResolvedRunContext(UUID releaseId) {
    }

    record ResolvedAgentExecutionContext(
            UUID releaseId,
            ModelContext model,
            String systemPrompt,
            BusinessContext businessContext,
            JsonNode workflow,
            List<ToolContext> tools,
            RuntimeCaseContext runtime,
            List<DocumentContext> documents
    ) {
        public ResolvedAgentExecutionContext {
            if (releaseId == null
                    || model == null
                    || systemPrompt == null
                    || systemPrompt.isBlank()
                    || businessContext == null
                    || workflow == null
                    || !workflow.isObject()
                    || tools == null
                    || tools.isEmpty()
                    || runtime == null
                    || documents == null) {
                throw new IllegalArgumentException("Resolved Agent execution context is incomplete");
            }
            workflow = workflow.deepCopy();
            tools = List.copyOf(tools);
            documents = List.copyOf(documents);
        }

        static ResolvedAgentExecutionContext legacy(
                UUID releaseId,
                String caseKey,
                String currentApplicantId
        ) {
            JsonNode emptyObject = JsonNodeFactory.instance.objectNode();
            return new ResolvedAgentExecutionContext(
                    releaseId,
                    new ModelContext(
                            "deterministic",
                            "stateless-contract-v1",
                            emptyObject
                    ),
                    "Deterministic contract-test execution context.",
                    new BusinessContext(
                            "CONTRACT_TEST",
                            "Compatibility context for deterministic boundary tests."
                    ),
                    emptyObject,
                    List.of(new ToolContext(
                            "CUSTOMER_DATA_READ",
                            "Compatibility Tool schema for deterministic boundary tests.",
                            emptyObject
                    )),
                    new RuntimeCaseContext(
                            caseKey,
                            currentApplicantId,
                            "TEST",
                            emptyObject,
                            List.of()
                    ),
                    List.of()
            );
        }
    }

    record ModelContext(
            String provider,
            String name,
            JsonNode parameters
    ) {
        public ModelContext {
            if (provider == null || provider.isBlank()
                    || name == null || name.isBlank()
                    || parameters == null || !parameters.isObject()) {
                throw new IllegalArgumentException("Resolved model context is incomplete");
            }
            parameters = parameters.deepCopy();
        }
    }

    record BusinessContext(
            String code,
            String description
    ) {
        public BusinessContext {
            if (code == null || code.isBlank() || description == null || description.isBlank()) {
                throw new IllegalArgumentException("Resolved business context is incomplete");
            }
        }
    }

    record ToolContext(
            String name,
            String description,
            JsonNode inputSchema
    ) {
        public ToolContext {
            if (name == null || name.isBlank()
                    || description == null || description.isBlank()
                    || inputSchema == null || !inputSchema.isObject()) {
                throw new IllegalArgumentException("Resolved Tool context is incomplete");
            }
            inputSchema = inputSchema.deepCopy();
        }
    }

    record RuntimeCaseContext(
            String caseKey,
            String currentApplicantId,
            String status,
            JsonNode context,
            List<String> allowedDocumentIds
    ) {
        public RuntimeCaseContext {
            if (caseKey == null || caseKey.isBlank()
                    || currentApplicantId == null || currentApplicantId.isBlank()
                    || status == null || status.isBlank()
                    || context == null || !context.isObject()
                    || allowedDocumentIds == null) {
                throw new IllegalArgumentException("Resolved runtime case context is incomplete");
            }
            context = context.deepCopy();
            allowedDocumentIds = List.copyOf(allowedDocumentIds);
        }
    }

    record DocumentContext(
            String documentId,
            String documentType,
            String content,
            String contentDigest,
            String trustLevel,
            JsonNode classification
    ) {
        public DocumentContext {
            if (documentId == null || documentId.isBlank()
                    || documentType == null || documentType.isBlank()
                    || content == null || content.isBlank()
                    || contentDigest == null || !contentDigest.matches("sha256:[0-9a-f]{64}")
                    || trustLevel == null || trustLevel.isBlank()
                    || classification == null || !classification.isObject()) {
                throw new IllegalArgumentException("Resolved document context is incomplete");
            }
            classification = classification.deepCopy();
        }
    }
}
