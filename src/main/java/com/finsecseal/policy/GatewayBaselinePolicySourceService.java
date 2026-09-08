package com.finsecseal.policy;

import com.finsecseal.agent.AgentEntity;
import com.finsecseal.agent.AgentService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.domain.ReleaseLifecycleState;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.SourceBoundCatalog;
import com.finsecseal.contract.SafetyContractLifecyclePolicy;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.LifecyclePolicyException;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.evidence.TestRunDto.Projection;
import com.finsecseal.evidence.TestRunPersistenceDto.CaseRun;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.evidence.TestRunProjectionService;
import com.finsecseal.release.AgentReleaseEntity;
import com.finsecseal.release.ReleaseService;
import java.sql.Connection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/** Verified declarations for live BASELINE calls; this snapshot grants no execution authority. */
@Service
public class GatewayBaselinePolicySourceService {
    private final TestRunProjectionService runs;
    private final TestRunPersistenceService cases;
    private final ReleaseToolCatalogContractAdapter catalogs;
    private final ReleaseService releases;
    private final AgentService agents;

    public GatewayBaselinePolicySourceService(TestRunProjectionService runs,
            TestRunPersistenceService cases, ReleaseToolCatalogContractAdapter catalogs,
            ReleaseService releases, AgentService agents) {
        this.runs = Objects.requireNonNull(runs);
        this.cases = Objects.requireNonNull(cases);
        this.catalogs = Objects.requireNonNull(catalogs);
        this.releases = Objects.requireNonNull(releases);
        this.agents = Objects.requireNonNull(agents);
    }

    /**
     * A's verified catalog read writes its existing access audit and holds the Release lock.
     * A compatible outer transaction retains the lock and owns its own timeout; the five-second
     * transaction timeout applies when this method starts the transaction itself.
     */
    @Transactional(isolation = Isolation.REPEATABLE_READ, timeout = 5)
    public BaselinePolicySource load(UUID runId, UUID testCaseRunId, ReviewerContext reviewer) {
        requireSnapshotTransaction();
        if (runId == null || testCaseRunId == null || reviewer == null) throw failure(FailureCode.INVALID_REQUEST);
        try {
            Projection run = runs.find(runId);
            requireRun(run, runId);
            // The first entity read is used only for identity/workspace authorization, not integrity.
            AgentReleaseEntity identity = releases.getRequired(run.releaseId());
            if (identity == null || !run.releaseId().equals(identity.getId()) || identity.getAgentId() == null) {
                throw failure(FailureCode.RELEASE_BINDING_INVALID);
            }
            UUID agentId = identity.getAgentId();
            AgentEntity agent = agents.getRequired(agentId);
            if (agent == null || !agentId.equals(agent.getId()) || agent.getWorkspaceId() == null) {
                throw failure(FailureCode.WORKSPACE_BINDING_INVALID);
            }
            UUID workspaceId = agent.getWorkspaceId();
            SafetyContractLifecyclePolicy.requireReviewerContext(reviewer, workspaceId);

            CaseRun caseRun = cases.findCase(testCaseRunId);
            requireCase(caseRun, runId, testCaseRunId);
            SourceBoundCatalog catalog = catalogs.load(run.releaseId(), reviewer.actorId());
            requireCatalog(catalog, run);
            // Only this read, after A's verification/lock and in the same snapshot, is projected.
            AgentReleaseEntity release = releases.getRequired(run.releaseId());
            requireRelease(release, catalog, agentId);
            JsonNode declarations = declarations(release, catalog);
            return new BaselinePolicySource(run, caseRun, workspaceId, catalog, declarations);
        } catch (BaselineSourceException | LifecyclePolicyException | BusinessException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw failure(FailureCode.SOURCE_UNAVAILABLE);
        }
    }

    private static void requireRun(Projection run, UUID runId) {
        if (run == null || !runId.equals(run.id()) || run.releaseId() == null
                || run.mode() == null || !hash(run.agentArtifactFingerprint()) || !hash(run.releaseFingerprint())
                || !text(run.fixtureVersion()) || !hash(run.fixtureDigest())) {
            throw failure(FailureCode.RUN_BINDING_INVALID);
        }
        if (run.mode() != TestRunMode.BASELINE) throw failure(FailureCode.UNSUPPORTED_RUN_MODE);
        if (run.status() != TestRunStatus.RUNNING) throw failure(FailureCode.RUN_NOT_EXECUTING);
    }

    private static void requireCase(CaseRun caseRun, UUID runId, UUID caseRunId) {
        if (caseRun == null || !caseRunId.equals(caseRun.id()) || !runId.equals(caseRun.testRunId())
                || caseRun.testCaseId() == null || caseRun.trialIndex() < 0 || !hash(caseRun.variantHash())) {
            throw failure(FailureCode.CASE_RUN_BINDING_INVALID);
        }
        if (caseRun.status() != TestCaseRunStatus.EXECUTING) throw failure(FailureCode.CASE_NOT_EXECUTING);
    }

    private static void requireCatalog(SourceBoundCatalog catalog, Projection run) {
        if (catalog == null || !run.releaseId().equals(catalog.releaseId())
                || !run.agentArtifactFingerprint().equals(catalog.agentArtifactFingerprint())
                || !run.releaseFingerprint().equals(catalog.releaseFingerprint())
                || !text(catalog.manifestSchemaVersion()) || !hash(catalog.serverToolCatalogHash())
                || catalog.semanticCatalog() == null) throw failure(FailureCode.CATALOG_BINDING_INVALID);
        var normal = new HashSet<String>();
        for (var tool : catalog.semanticCatalog().enabledReleaseTools()) {
            if (tool == null || !text(tool.toolName()) || !normal.add(tool.toolName())) {
                throw failure(FailureCode.CATALOG_BINDING_INVALID);
            }
        }
        if (normal.isEmpty()) throw failure(FailureCode.CATALOG_BINDING_INVALID);
        var all = new HashSet<>(normal);
        for (String tool : catalog.semanticCatalog().highImpactToolNames()) {
            if (!text(tool) || !all.add(tool)) throw failure(FailureCode.CATALOG_BINDING_INVALID);
        }
        var bound = new HashSet<String>();
        for (var binding : catalog.releaseToolBindings()) {
            if (binding == null || !binding.enabled() || !text(binding.version())
                    || !hash(binding.schemaDigest()) || !hash(binding.descriptionDigest())
                    || !bound.add(binding.toolName())) throw failure(FailureCode.CATALOG_BINDING_INVALID);
        }
        var declared = new HashSet<String>();
        for (var tool : catalog.declaredTools()) {
            if (tool == null || !text(tool.operation()) || !declared.add(tool.name())) {
                throw failure(FailureCode.CATALOG_BINDING_INVALID);
            }
        }
        if (!normal.equals(bound) || !all.equals(declared) || !all.equals(catalog.inputSchemas().keySet())) {
            throw failure(FailureCode.CATALOG_BINDING_INVALID);
        }
    }

    private static void requireRelease(AgentReleaseEntity release, SourceBoundCatalog catalog, UUID agentId) {
        if (release == null || !catalog.releaseId().equals(release.getId())
                || !agentId.equals(release.getAgentId())
                || !catalog.manifestSchemaVersion().equals(release.getManifestSchemaVersion())
                || !catalog.agentArtifactFingerprint().equals(release.getAgentArtifactFingerprint())
                || !catalog.releaseFingerprint().equals(release.getReleaseFingerprint())) {
            throw failure(FailureCode.RELEASE_BINDING_INVALID);
        }
        if (release.getAnalyzedAt() == null || release.getLifecycleState() == null
                || release.getLifecycleState() == ReleaseLifecycleState.DRAFT) {
            throw failure(FailureCode.RELEASE_NOT_ANALYZED);
        }
    }

    private static JsonNode declarations(AgentReleaseEntity release, SourceBoundCatalog catalog) {
        JsonNode manifest = release.getManifestJson();
        if (manifest == null || !manifest.isObject()
                || !catalog.manifestSchemaVersion().equals(manifest.path("schemaVersion").stringValue())
                || !manifest.path("businessPurpose").isObject()
                || !manifest.at("/businessPurpose/code").isString()
                || !text(release.getBusinessPurpose())
                || !release.getBusinessPurpose().equals(manifest.at("/businessPurpose/code").stringValue())) {
            throw failure(FailureCode.SOURCE_CONTENT_INVALID);
        }
        JsonNode workflow = manifest.path("businessWorkflow");
        if (!workflow.isObject() || !workflow.path("allowedStages").isArray()
                || workflow.path("allowedStages").isEmpty()
                || !"CASE_CONTEXT_READ".equals(workflow.path("contextSourceTool").stringValue())) {
            throw failure(FailureCode.SOURCE_CONTENT_INVALID);
        }
        var stages = new HashSet<String>();
        for (JsonNode stage : workflow.path("allowedStages")) {
            if (!stage.isString() || !text(stage.stringValue()) || !stages.add(stage.stringValue())) {
                throw failure(FailureCode.SOURCE_CONTENT_INVALID);
            }
        }
        var normal = new HashSet<String>();
        catalog.semanticCatalog().enabledReleaseTools().forEach(tool -> normal.add(tool.toolName()));
        var human = Set.copyOf(catalog.semanticCatalog().highImpactToolNames());
        Map<String, JsonNode> inputs = catalog.inputSchemas();
        requireToolDeclarations(manifest.path("tools"), normal, inputs, catalog, false);
        JsonNode server = manifest.path("serverToolCatalog");
        if (!server.isObject() || !server.path("version").isString() || !text(server.path("version").stringValue())) {
            throw failure(FailureCode.SOURCE_CONTENT_INVALID);
        }
        requireToolDeclarations(server.path("tools"), human, inputs, catalog, true);
        ObjectNode result = JsonNodeFactory.instance.objectNode();
        for (String field : List.of("businessPurpose", "businessWorkflow", "tools", "serverToolCatalog")) {
            result.set(field, manifest.path(field).deepCopy());
        }
        return result;
    }

    private static void requireToolDeclarations(JsonNode tools, Set<String> expected,
            Map<String, JsonNode> inputs, SourceBoundCatalog catalog, boolean human) {
        if (!tools.isArray()) throw failure(FailureCode.SOURCE_CONTENT_INVALID);
        var seen = new HashSet<String>();
        for (JsonNode tool : tools) {
            String name = tool.path("name").stringValue();
            if (!tool.isObject() || !text(name) || !expected.contains(name) || !seen.add(name)
                    || !tool.path("inputSchema").isObject() || !tool.path("outputSchema").isObject()
                    || !tool.path("inputSchema").equals(inputs.get(name))) {
                throw failure(FailureCode.SOURCE_CONTENT_INVALID);
            }
            var declaration = catalog.declaredTools().stream().filter(value -> value.name().equals(name))
                    .findFirst().orElseThrow(() -> failure(FailureCode.SOURCE_CONTENT_INVALID));
            if (!declaration.operation().equals(tool.path("operation").stringValue())
                    || !tool.path("adapterKey").isString() || !text(tool.path("adapterKey").stringValue())
                    || !tool.path("sideEffectType").isString() || !text(tool.path("sideEffectType").stringValue())) {
                throw failure(FailureCode.SOURCE_CONTENT_INVALID);
            }
            // The actual server HUMAN_ONLY declaration has no dataClassifications property.
            if (!human && (!tool.path("dataClassifications").isArray() || tool.path("dataClassifications").isEmpty())) {
                throw failure(FailureCode.SOURCE_CONTENT_INVALID);
            }
            if (human && (!tool.path("agentExecutable").isBoolean() || tool.path("agentExecutable").booleanValue()
                    || !"HUMAN_ONLY".equals(tool.path("executionBoundary").stringValue()))) {
                throw failure(FailureCode.SOURCE_CONTENT_INVALID);
            }
        }
        if (!expected.equals(seen)) throw failure(FailureCode.SOURCE_CONTENT_INVALID);
    }

    private static boolean text(String value) { return value != null && !value.isBlank() && value.equals(value.strip()); }
    private static boolean hash(String value) { return value != null && value.matches("sha256:[0-9a-f]{64}"); }

    private static void requireSnapshotTransaction() {
        if (!TransactionSynchronizationManager.isActualTransactionActive()
                || TransactionSynchronizationManager.isCurrentTransactionReadOnly()
                || !Objects.equals(TransactionSynchronizationManager.getCurrentTransactionIsolationLevel(),
                        Connection.TRANSACTION_REPEATABLE_READ)) throw failure(FailureCode.UNSAFE_TRANSACTION);
    }

    public static final class BaselinePolicySource {
        private final UUID runId, testCaseRunId, testCaseId, releaseId, workspaceId, referencedContractVersionId;
        private final TestRunMode runMode;
        private final TestRunStatus runStatus;
        private final TestCaseRunStatus caseStatus;
        private final int trialIndex;
        private final String variantHash, fixtureVersion, fixtureDigest;
        private final SourceBoundCatalog catalog;
        private final JsonNode releaseDeclarations;

        private BaselinePolicySource(Projection run, CaseRun caseRun, UUID workspaceId,
                SourceBoundCatalog catalog, JsonNode declarations) {
            this.runId = run.id(); this.testCaseRunId = caseRun.id(); this.testCaseId = caseRun.testCaseId();
            this.releaseId = run.releaseId(); this.workspaceId = workspaceId;
            this.referencedContractVersionId = run.contractVersionId();
            this.runMode = run.mode(); this.runStatus = run.status(); this.caseStatus = caseRun.status();
            this.trialIndex = caseRun.trialIndex(); this.variantHash = caseRun.variantHash();
            this.fixtureVersion = run.fixtureVersion(); this.fixtureDigest = run.fixtureDigest();
            this.catalog = catalog; this.releaseDeclarations = declarations.deepCopy();
        }

        public UUID runId() { return runId; }
        public UUID testCaseRunId() { return testCaseRunId; }
        public UUID testCaseId() { return testCaseId; }
        public UUID releaseId() { return releaseId; }
        public UUID workspaceId() { return workspaceId; }
        /** Stored reference only: no contract is read, approved or applied by this source. */
        public UUID referencedContractVersionId() { return referencedContractVersionId; }
        public TestRunMode runMode() { return runMode; }
        public TestRunStatus runStatus() { return runStatus; }
        public TestCaseRunStatus caseStatus() { return caseStatus; }
        public int trialIndex() { return trialIndex; }
        public String variantHash() { return variantHash; }
        public String fixtureVersion() { return fixtureVersion; }
        public String fixtureDigest() { return fixtureDigest; }
        public SourceBoundCatalog catalog() { return catalog; }
        public JsonNode releaseDeclarations() { return releaseDeclarations.deepCopy(); }
        public String releasePurpose() { return releaseDeclarations.at("/businessPurpose/code").stringValue(); }
        public List<String> normalToolNames() {
            return catalog.semanticCatalog().enabledReleaseTools().stream().map(tool -> tool.toolName()).toList();
        }
    }

    public enum FailureCode {
        INVALID_REQUEST, UNSAFE_TRANSACTION, RUN_BINDING_INVALID, UNSUPPORTED_RUN_MODE, RUN_NOT_EXECUTING,
        WORKSPACE_BINDING_INVALID, CASE_RUN_BINDING_INVALID, CASE_NOT_EXECUTING, CATALOG_BINDING_INVALID,
        RELEASE_BINDING_INVALID, RELEASE_NOT_ANALYZED, SOURCE_CONTENT_INVALID, SOURCE_UNAVAILABLE
    }

    public static final class BaselineSourceException extends RuntimeException {
        private final FailureCode code;
        private BaselineSourceException(FailureCode code) {
            super(code.name(), null, false, true); this.code = code;
        }
        public FailureCode code() { return code; }
    }

    private static BaselineSourceException failure(FailureCode code) { return new BaselineSourceException(code); }
}
