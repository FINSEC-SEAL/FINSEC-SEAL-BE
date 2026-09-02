package com.finsecseal.release;

import tools.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;

@Service
public class ManifestValidationService {

    private static final Pattern SEMVER = Pattern.compile("^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-[0-9A-Za-z.-]+)?$");
    private static final Pattern DIGEST = Pattern.compile("^sha256:[0-9a-f]{64}$");
    private static final Pattern IDENTIFIER = Pattern.compile("^[A-Z][A-Z0-9_]{1,99}$");
    private static final Pattern BUSINESS_KEY = Pattern.compile("^[a-z0-9][a-z0-9-]{2,79}$");
    private static final Pattern HOST_LABEL = Pattern.compile("^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$");
    private static final Map<String, ToolContract> NORMAL_TOOL_REGISTRY = Map.of(
            "CASE_CONTEXT_READ", new ToolContract(
                    "1.0.0", "READ", "TRUSTED_INTERNAL", "LOW", Set.of("NORMAL"),
                    "NONE", "case_context_read"
            ),
            "DOCUMENT_READER", new ToolContract(
                    "1.0.0", "READ", "MIXED", "MEDIUM", Set.of("NORMAL", "PII"),
                    "NONE", "document_reader"
            ),
            "CUSTOMER_DATA_READ", new ToolContract(
                    "1.0.0", "READ", "TRUSTED_INTERNAL", "HIGH",
                    Set.of("NORMAL", "PII", "SENSITIVE_PII", "FINANCIAL", "CREDIT"),
                    "NONE", "customer_data_read"
            ),
            "LOAN_POLICY_SEARCH", new ToolContract(
                    "1.0.0", "SEARCH", "TRUSTED_INTERNAL", "LOW", Set.of("NORMAL"),
                    "NONE", "loan_policy_search"
            ),
            "REVIEW_NOTE_WRITE", new ToolContract(
                    "1.0.0", "CREATE", "TRUSTED_INTERNAL", "MEDIUM", Set.of("NORMAL"),
                    "INTERNAL_WRITE", "review_note_write"
            )
    );
    private static final Set<String> REQUIRED_RUNTIME_CONTEXT = Set.of(
            "caseId", "currentApplicantId", "workflowStage", "allowedDocumentIds"
    );
    private static final Set<String> CONFIGURED_PROVIDER_HOSTS = Set.of("configured-provider-host");
    private static final Set<String> TOP_LEVEL_FIELDS = Set.of(
            "schemaVersion", "agent", "release", "businessPurpose", "model", "systemPrompt", "tools",
            "ragSources", "networkRequirements", "businessWorkflow", "humanApprovalBoundaries",
            "runtimeContextRequirements", "safetyContractRef"
    );
    private static final Set<String> TOOL_FIELDS = Set.of(
            "name", "version", "operation", "description", "inputSchema", "outputSchema", "trustLevel",
            "riskLevel", "dataClassifications", "sideEffectType", "adapterKey"
    );

    private final DigestService digestService;

    public ManifestValidationService(DigestService digestService) {
        this.digestService = digestService;
    }

    public ValidationResult validate(JsonNode manifest) {
        List<Issue> issues = new ArrayList<>();
        if (manifest == null || !manifest.isObject()) {
            return new ValidationResult(false, List.of(error("/", "TYPE", "Manifest must be a JSON object")));
        }
        if (manifest.toString().getBytes(StandardCharsets.UTF_8).length > 2 * 1024 * 1024) {
            issues.add(error("/", "SIZE", "Manifest must not exceed 2 MB"));
        }
        rejectUnknown(manifest, "/", TOP_LEVEL_FIELDS, issues);
        rejectUnknown(manifest.path("agent"), "/agent", Set.of("id", "name"), issues);
        rejectUnknown(manifest.path("release"), "/release", Set.of("version"), issues);
        rejectUnknown(manifest.path("businessPurpose"), "/businessPurpose", Set.of("code", "description"), issues);
        rejectUnknown(manifest.path("model"), "/model", Set.of("provider", "name", "parameters"), issues);
        rejectUnknown(
                manifest.path("model").path("parameters"),
                "/model/parameters",
                Set.of("temperature", "topP", "maxTokens", "seed"),
                issues
        );
        rejectUnknown(manifest.path("systemPrompt"), "/systemPrompt", Set.of("text", "declaredSha256"), issues);
        rejectUnknown(
                manifest.path("networkRequirements"),
                "/networkRequirements",
                Set.of("modelProvider", "agentExternalEgress", "allowedHosts"),
                issues
        );
        rejectUnknown(
                manifest.path("businessWorkflow"),
                "/businessWorkflow",
                Set.of("allowedStages", "contextSourceTool", "orderedSteps"),
                issues
        );
        requireText(manifest, "/schemaVersion", "1.0", issues);
        String agentId = text(manifest, "/agent/id");
        if (agentId == null || !BUSINESS_KEY.matcher(agentId).matches()) {
            issues.add(error("/agent/id", "FORMAT", "Agent id must be a lowercase stable business key"));
        }
        requireBoundedText(manifest, "/agent/name", 100, issues);
        String version = text(manifest, "/release/version");
        if (version == null || !SEMVER.matcher(version).matches()) {
            issues.add(error("/release/version", "SEMVER", "Release version must be semantic versioning"));
        }
        requireText(manifest, "/businessPurpose/code", "LOAN_DOCUMENT_COMPLETENESS_REVIEW", issues);
        requireBoundedText(manifest, "/businessPurpose/description", 500, issues);
        requireText(manifest, "/model/provider", "openai-compatible", issues);
        requireBoundedText(manifest, "/model/name", 200, issues);
        requireObject(manifest, "/model/parameters", issues);
        validateModelParameters(manifest.path("model").path("parameters"), issues);
        String prompt = text(manifest, "/systemPrompt/text");
        if (prompt == null || prompt.isBlank() || prompt.length() > 100_000) {
            issues.add(error("/systemPrompt/text", "LENGTH", "System prompt must contain 1 to 100,000 characters"));
        }
        String declared = text(manifest, "/systemPrompt/declaredSha256");
        String normalizedPrompt = prompt == null ? "" : Normalizer.normalize(
                prompt.replace("\r\n", "\n").replace('\r', '\n'),
                Normalizer.Form.NFC
        );
        JsonNode declaredNode = manifest.at("/systemPrompt/declaredSha256");
        if (!declaredNode.isMissingNode() && !declaredNode.isNull() && !declaredNode.isString()) {
            issues.add(error(
                    "/systemPrompt/declaredSha256",
                    "TYPE",
                    "declaredSha256 must be a string when present"
            ));
        } else if (declared != null && (!DIGEST.matcher(declared).matches()
                || !declared.equals(digestService.sha256(normalizedPrompt)))) {
            issues.add(error("/systemPrompt/declaredSha256", "DIGEST_MISMATCH", "Declared prompt digest does not match"));
        }
        validateTools(manifest.path("tools"), issues);
        if (!manifest.path("ragSources").isArray()) {
            issues.add(error("/ragSources", "TYPE", "ragSources must be an array"));
        } else {
            validateRagSources(manifest.path("ragSources"), issues);
        }
        requireObject(manifest, "/networkRequirements", issues);
        JsonNode modelProvider = manifest.at("/networkRequirements/modelProvider");
        if (!modelProvider.isBoolean() || !modelProvider.booleanValue()) {
            issues.add(error(
                    "/networkRequirements/modelProvider",
                    "PROVIDER_REQUIRED",
                    "P0 requires the configured model provider route"
            ));
        }
        JsonNode externalEgress = manifest.at("/networkRequirements/agentExternalEgress");
        if (!externalEgress.isBoolean() || externalEgress.booleanValue()) {
            issues.add(error("/networkRequirements/agentExternalEgress", "EGRESS", "Agent external egress must be false"));
        }
        JsonNode allowedHosts = manifest.at("/networkRequirements/allowedHosts");
        if (!allowedHosts.isArray() || allowedHosts.isEmpty()) {
            issues.add(error(
                    "/networkRequirements/allowedHosts",
                    "TYPE",
                    "allowedHosts must contain at least one configured provider host label"
            ));
        } else {
            Set<String> actualHosts = new HashSet<>();
            for (int index = 0; index < allowedHosts.size(); index++) {
                JsonNode host = allowedHosts.get(index);
                if (!host.isString() || !HOST_LABEL.matcher(host.asString()).matches()
                        || host.asString().contains("://") || !actualHosts.add(host.asString())) {
                    issues.add(error(
                            "/networkRequirements/allowedHosts/" + index,
                            "HOST_LABEL_ONLY",
                            "allowedHosts accepts configured host labels, not URLs"
                    ));
                }
            }
            if (!actualHosts.equals(CONFIGURED_PROVIDER_HOSTS)) {
                issues.add(error(
                        "/networkRequirements/allowedHosts",
                        "PROVIDER_HOST_SCOPE",
                        "allowedHosts must exactly match the configured provider host labels"
                ));
            }
        }
        requireObject(manifest, "/businessWorkflow", issues);
        validateBusinessWorkflow(manifest.path("businessWorkflow"), issues);
        validateHumanBoundary(manifest.path("humanApprovalBoundaries"), issues);
        JsonNode contexts = manifest.path("runtimeContextRequirements");
        if (!contexts.isArray() || contexts.isEmpty()) {
            issues.add(error("/runtimeContextRequirements", "REQUIRED", "Runtime context requirements are required"));
        } else {
            Set<String> actual = new HashSet<>();
            for (int index = 0; index < contexts.size(); index++) {
                JsonNode context = contexts.get(index);
                if (!context.isString() || context.asString().isBlank() || !actual.add(context.asString())) {
                    issues.add(error(
                            "/runtimeContextRequirements/" + index,
                            "UNIQUE_TEXT",
                            "Runtime context entries must be unique non-blank strings"
                    ));
                }
            }
            Set<String> missing = new HashSet<>(REQUIRED_RUNTIME_CONTEXT);
            missing.removeAll(actual);
            if (!missing.isEmpty()) {
                issues.add(error(
                        "/runtimeContextRequirements",
                        "REQUIRED_CONTEXT",
                        "Required runtime context is missing: " + missing
                ));
            }
        }
        if (!manifest.path("safetyContractRef").isMissingNode()
                && !manifest.path("safetyContractRef").isNull()) {
            issues.add(error(
                    "/safetyContractRef",
                    "SERVER_OWNED",
                    "Safety Contract references are attached by the approval workflow, not by uploaded manifests"
            ));
        }
        return new ValidationResult(issues.stream().noneMatch(issue -> issue.severity() == Severity.ERROR), issues);
    }

    private void validateTools(JsonNode tools, List<Issue> issues) {
        if (!tools.isArray() || tools.isEmpty() || tools.size() > 50) {
            issues.add(error("/tools", "SIZE", "tools must contain 1 to 50 entries"));
            return;
        }
        Set<String> names = new HashSet<>();
        for (int index = 0; index < tools.size(); index++) {
            JsonNode tool = tools.get(index);
            String prefix = "/tools/" + index;
            if (!tool.isObject()) {
                issues.add(error(prefix, "TYPE", "Tool entry must be an object"));
                continue;
            }
            rejectUnknown(tool, prefix, TOOL_FIELDS, issues);
            String name = text(tool, "/name");
            if (name == null || !IDENTIFIER.matcher(name).matches() || !names.add(name)) {
                issues.add(error(prefix + "/name", "UNIQUE", "Tool name is required and must be unique"));
            }
            String toolVersion = text(tool, "/version");
            if (toolVersion == null || !SEMVER.matcher(toolVersion).matches()) {
                issues.add(error(prefix + "/version", "SEMVER", "Tool version must be semantic versioning"));
            }
            requireEnum(
                    tool,
                    "/operation",
                    Set.of("READ", "SEARCH", "CREATE", "WRITE", "UPDATE", "POST"),
                    issues,
                    prefix
            );
            String description = text(tool, "/description");
            if (description == null || description.isBlank() || description.length() > 1_000) {
                issues.add(error(prefix + "/description", "LENGTH", "Description must contain 1 to 1,000 characters"));
            }
            requireObject(tool, "/inputSchema", issues, prefix);
            requireObject(tool, "/outputSchema", issues, prefix);
            validateJsonSchema(tool.path("inputSchema"), prefix + "/inputSchema", issues);
            validateJsonSchema(tool.path("outputSchema"), prefix + "/outputSchema", issues);
            requireEnum(tool, "/trustLevel", Set.of("TRUSTED_INTERNAL", "MIXED", "SANDBOXED"), issues, prefix);
            requireEnum(tool, "/riskLevel", Set.of("LOW", "MEDIUM", "HIGH", "CRITICAL"), issues, prefix);
            requireEnum(
                    tool,
                    "/sideEffectType",
                    Set.of("NONE", "INTERNAL_WRITE", "HIGH_IMPACT_WRITE", "MOCK_EXTERNAL_WRITE"),
                    issues,
                    prefix
            );
            Set<String> classifications = new HashSet<>();
            if (!tool.path("dataClassifications").isArray() || tool.path("dataClassifications").isEmpty()) {
                issues.add(error(prefix + "/dataClassifications", "TYPE", "dataClassifications must be an array"));
            } else {
                for (int classificationIndex = 0;
                        classificationIndex < tool.path("dataClassifications").size();
                        classificationIndex++) {
                    JsonNode classification = tool.path("dataClassifications").get(classificationIndex);
                    if (!classification.isString()
                            || !Set.of("NORMAL", "PII", "SENSITIVE_PII", "FINANCIAL", "CREDIT")
                                    .contains(classification.asString())
                            || !classifications.add(classification.asString())) {
                        issues.add(error(
                                prefix + "/dataClassifications/" + classificationIndex,
                                "CLASSIFICATION",
                                "Classification must be allowed and unique"
                        ));
                    }
                }
            }
            String adapter = text(tool, "/adapterKey");
            ToolContract contract = NORMAL_TOOL_REGISTRY.get(name);
            if (contract == null) {
                issues.add(error(
                        prefix + "/name",
                        "NORMAL_TOOL_SCOPE",
                        "Only the server-registered normal Release tools may be declared"
                ));
            } else if (!contract.matches(
                    toolVersion,
                    text(tool, "/operation"),
                    text(tool, "/trustLevel"),
                    text(tool, "/riskLevel"),
                    classifications,
                    text(tool, "/sideEffectType"),
                    adapter
            )) {
                issues.add(error(
                        prefix,
                        "TOOL_CONTRACT_MISMATCH",
                        "Tool version/operation/trust/risk/classification/side-effect/adapter must match "
                                + "the server registry"
                ));
            }
        }
        Set<String> missing = new HashSet<>(NORMAL_TOOL_REGISTRY.keySet());
        missing.removeAll(names);
        if (!missing.isEmpty()) {
            issues.add(error("/tools", "REQUIRED_TOOL", "Required tools are missing: " + missing));
        }
    }

    private void validateHumanBoundary(JsonNode boundaries, List<Issue> issues) {
        if (!boundaries.isArray()) {
            issues.add(error("/humanApprovalBoundaries", "TYPE", "Human approval boundaries must be an array"));
            return;
        }
        if (boundaries.size() != 1) {
            issues.add(error(
                    "/humanApprovalBoundaries",
                    "P0_BOUNDARY_SCOPE",
                    "P0 requires exactly one LoanDecision human-only boundary"
            ));
        }
        boolean loanDecisionBoundary = false;
        for (JsonNode boundary : boundaries) {
            if (!boundary.isObject()) {
                issues.add(error("/humanApprovalBoundaries", "TYPE", "Boundary entry must be an object"));
                continue;
            }
            rejectUnknown(boundary, "/humanApprovalBoundaries", Set.of("resource", "operations", "mode"), issues);
            Set<String> operations = new HashSet<>();
            if (boundary.path("operations").isArray()) {
                for (int index = 0; index < boundary.path("operations").size(); index++) {
                    JsonNode operation = boundary.path("operations").get(index);
                    if (!operation.isString() || !operations.add(operation.asString())) {
                        issues.add(error(
                                "/humanApprovalBoundaries/operations/" + index,
                                "UNIQUE_TEXT",
                                "Boundary operations must be unique strings"
                        ));
                    }
                }
            } else {
                issues.add(error("/humanApprovalBoundaries/operations", "TYPE", "operations must be an array"));
            }
            if ("LoanDecision".equals(boundary.path("resource").asString(""))
                    && "HUMAN_ONLY".equals(boundary.path("mode").asString(""))
                    && operations.equals(Set.of("APPROVED", "REJECTED"))) {
                loanDecisionBoundary = true;
            }
        }
        if (!loanDecisionBoundary) {
            issues.add(error("/humanApprovalBoundaries", "HUMAN_BOUNDARY", "LoanDecision must be HUMAN_ONLY"));
        }
    }

    private void requireText(JsonNode root, String pointer, String expected, List<Issue> issues) {
        requireText(root, pointer, expected, issues, "");
    }

    private void requireText(JsonNode root, String pointer, String expected, List<Issue> issues, String prefix) {
        String value = text(root, pointer);
        if (value == null || value.isBlank() || (expected != null && !expected.equals(value))) {
            issues.add(error(prefix + pointer, "REQUIRED", expected == null ? "Required text field" : "Must equal " + expected));
        }
    }

    private void requireObject(JsonNode root, String pointer, List<Issue> issues) {
        requireObject(root, pointer, issues, "");
    }

    private void requireObject(JsonNode root, String pointer, List<Issue> issues, String prefix) {
        if (!root.at(pointer).isObject()) {
            issues.add(error(prefix + pointer, "TYPE", "Required object field"));
        }
    }

    private void requireBoundedText(JsonNode root, String pointer, int maximum, List<Issue> issues) {
        String value = text(root, pointer);
        if (value == null || value.isBlank() || value.length() > maximum) {
            issues.add(error(pointer, "LENGTH", "Text must contain 1 to " + maximum + " characters"));
        }
    }

    private void requireEnum(
            JsonNode root,
            String pointer,
            Set<String> allowed,
            List<Issue> issues,
            String prefix
    ) {
        String value = text(root, pointer);
        if (value == null || !allowed.contains(value)) {
            issues.add(error(prefix + pointer, "ENUM", "Value must be one of " + allowed));
        }
    }

    private String text(JsonNode root, String pointer) {
        JsonNode node = root.at(pointer);
        return node.isString() ? node.stringValue() : null;
    }

    private Issue error(String path, String code, String message) {
        return new Issue(path, code, Severity.ERROR, message);
    }

    private void rejectUnknown(JsonNode node, String path, Set<String> allowed, List<Issue> issues) {
        if (!node.isObject()) {
            return;
        }
        node.propertyNames().stream()
                .filter(field -> !allowed.contains(field))
                .sorted()
                .forEach(field -> issues.add(error(
                        ("/".equals(path) ? "" : path) + "/" + field,
                        "UNKNOWN_FIELD",
                        "Unknown field is not allowed"
                )));
    }

    private void validateModelParameters(JsonNode parameters, List<Issue> issues) {
        if (!parameters.isObject()) {
            return;
        }
        if (parameters.has("temperature")) {
            JsonNode temperature = parameters.path("temperature");
            if (!temperature.isNumber()) {
                issues.add(error("/model/parameters/temperature", "TYPE", "temperature must be a number"));
            } else if (!Double.isFinite(temperature.doubleValue())
                    || temperature.doubleValue() < 0 || temperature.doubleValue() > 2) {
                issues.add(error("/model/parameters/temperature", "RANGE", "temperature must be between 0 and 2"));
            }
        }
        if (parameters.has("topP")) {
            JsonNode topP = parameters.path("topP");
            if (!topP.isNumber()) {
                issues.add(error("/model/parameters/topP", "TYPE", "topP must be a number"));
            } else if (!Double.isFinite(topP.doubleValue())
                    || topP.doubleValue() < 0 || topP.doubleValue() > 1) {
                issues.add(error("/model/parameters/topP", "RANGE", "topP must be between 0 and 1"));
            }
        }
        if (!parameters.path("maxTokens").isInt()
                || parameters.path("maxTokens").intValue() <= 0
                || parameters.path("maxTokens").intValue() > 1_000_000) {
            issues.add(error("/model/parameters/maxTokens", "RANGE", "maxTokens must be positive"));
        }
        if (parameters.has("seed") && !parameters.path("seed").isIntegralNumber()) {
            issues.add(error("/model/parameters/seed", "TYPE", "seed must be an integer"));
        }
    }

    private void validateRagSources(JsonNode sources, List<Issue> issues) {
        if (sources.size() > 20) {
            issues.add(error("/ragSources", "SIZE", "ragSources must contain at most 20 entries"));
        }
        Set<String> identities = new HashSet<>();
        for (int index = 0; index < sources.size(); index++) {
            JsonNode source = sources.get(index);
            String path = "/ragSources/" + index;
            if (!source.isObject()) {
                issues.add(error(path, "TYPE", "RAG source entry must be an object"));
                continue;
            }
            rejectUnknown(
                    source,
                    path,
                    Set.of("sourceId", "version", "trustLevel", "retrievalConfig", "contentDigest"),
                    issues
            );
            String sourceId = text(source, "/sourceId");
            String version = text(source, "/version");
            if (sourceId == null || !BUSINESS_KEY.matcher(sourceId).matches()
                    || version == null || version.isBlank() || version.length() > 50
                    || !identities.add(sourceId + "@" + version)) {
                issues.add(error(path, "UNIQUE", "RAG sourceId/version must be present and unique"));
            }
            if (!"TRUSTED_INTERNAL".equals(text(source, "/trustLevel"))) {
                issues.add(error(path + "/trustLevel", "TRUST", "P0 RAG sources must be TRUSTED_INTERNAL"));
            }
            requireObject(source, "/retrievalConfig", issues, path);
            String digest = text(source, "/contentDigest");
            if (digest == null || !DIGEST.matcher(digest).matches()) {
                issues.add(error(path + "/contentDigest", "DIGEST", "contentDigest must be sha256"));
            }
        }
    }

    private void validateBusinessWorkflow(JsonNode workflow, List<Issue> issues) {
        if (!workflow.isObject()) {
            return;
        }
        JsonNode stages = workflow.path("allowedStages");
        if (!stages.isArray() || stages.isEmpty()) {
            issues.add(error("/businessWorkflow/allowedStages", "TYPE", "allowedStages must be a non-empty array"));
        } else {
            Set<String> values = new HashSet<>();
            for (int index = 0; index < stages.size(); index++) {
                JsonNode stage = stages.get(index);
                String path = "/businessWorkflow/allowedStages/" + index;
                if (!stage.isString() || stage.asString().isBlank()) {
                    issues.add(error(path, "TYPE", "allowedStages entries must be non-blank strings"));
                } else if (!values.add(stage.asString())) {
                    issues.add(error(path, "UNIQUE", "allowedStages entries must be unique"));
                }
            }
            if (!values.contains("DOCUMENT_REVIEW")) {
                issues.add(error(
                        "/businessWorkflow/allowedStages",
                        "WORKFLOW_SCOPE",
                        "P0 workflow must include DOCUMENT_REVIEW"
                ));
            }
        }
        if (!"CASE_CONTEXT_READ".equals(text(workflow, "/contextSourceTool"))) {
            issues.add(error(
                    "/businessWorkflow/contextSourceTool",
                    "WORKFLOW_CONTEXT",
                    "contextSourceTool must be CASE_CONTEXT_READ"
            ));
        }
        JsonNode orderedSteps = workflow.path("orderedSteps");
        if (!orderedSteps.isMissingNode() && !orderedSteps.isArray()) {
            issues.add(error("/businessWorkflow/orderedSteps", "TYPE", "orderedSteps must be an array"));
        }
    }

    private void validateJsonSchema(JsonNode schema, String path, List<Issue> issues) {
        if (schema.isObject()) {
            schema.properties().forEach(entry -> {
                String field = entry.getKey();
                JsonNode value = entry.getValue();
                if ("$ref".equals(field) && (!value.isString() || !value.asString("").startsWith("#"))) {
                    issues.add(error(path + "/$ref", "REMOTE_REF", "Only local JSON Schema references are allowed"));
                }
                if ("pattern".equals(field) && value.isString()
                        && (value.asString().contains("(?=") || value.asString().contains("(?<"))) {
                    issues.add(error(path + "/pattern", "REGEX_LOOKAROUND", "Regex lookaround is not allowed"));
                }
                validateJsonSchema(value, path + "/" + field, issues);
            });
        } else if (schema.isArray()) {
            for (int index = 0; index < schema.size(); index++) {
                validateJsonSchema(schema.get(index), path + "/" + index, issues);
            }
        }
    }

    public enum Severity {
        ERROR,
        WARNING
    }

    public record Issue(String path, String code, Severity severity, String message) {
    }

    public record ValidationResult(boolean valid, List<Issue> issues) {
    }

    private record ToolContract(
            String version,
            String operation,
            String trustLevel,
            String riskLevel,
            Set<String> dataClassifications,
            String sideEffectType,
            String adapterKey
    ) {
        private boolean matches(
                String actualVersion,
                String actualOperation,
                String actualTrustLevel,
                String actualRiskLevel,
                Set<String> actualClassifications,
                String actualSideEffectType,
                String actualAdapter
        ) {
            return version.equals(actualVersion)
                    && operation.equals(actualOperation)
                    && trustLevel.equals(actualTrustLevel)
                    && riskLevel.equals(actualRiskLevel)
                    && dataClassifications.equals(actualClassifications)
                    && sideEffectType.equals(actualSideEffectType)
                    && adapterKey.equals(actualAdapter);
        }
    }
}
