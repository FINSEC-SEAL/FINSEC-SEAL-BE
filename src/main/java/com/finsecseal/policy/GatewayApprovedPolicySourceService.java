package com.finsecseal.policy;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.SourceBoundCatalog;
import com.finsecseal.contract.SafetyContractCanonicalizer;
import com.finsecseal.contract.SafetyContractCanonicalizer.CanonicalPolicy;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionIdentity;
import com.finsecseal.contract.SafetyContractSemanticValidator;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationResult;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationStatus;
import com.finsecseal.evidence.TestRunDto.Projection;
import com.finsecseal.evidence.TestRunPersistenceDto.CaseRun;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.evidence.TestRunProjectionService;
import com.finsecseal.platform.contract.ContractPersistenceService;
import com.finsecseal.platform.contract.ContractPersistenceService.ApprovedContract;
import com.finsecseal.platform.contract.ContractPersistenceService.Version;
import com.finsecseal.policy.PolicyToolTrustFacts.ReleaseToolBinding;
import com.finsecseal.policy.PolicyToolTrustFacts.ToolTrustPolicy;
import com.finsecseal.policy.PolicyToolTrustFacts.TrustLevel;
import java.math.BigInteger;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.JsonNode;

/** Reads current approved policy sources. A snapshot is neither preflight PASS nor execution authority. */
@Service
public class GatewayApprovedPolicySourceService {
    private final TestRunProjectionService runs;
    private final ContractPersistenceService contracts;
    private final TestRunPersistenceService cases;
    private final ReleaseToolCatalogContractAdapter catalogs;
    private final SafetyContractSemanticValidator validator;
    private final SafetyContractCanonicalizer canonicalizer;

    public GatewayApprovedPolicySourceService(TestRunProjectionService runs,
            ContractPersistenceService contracts, TestRunPersistenceService cases,
            ReleaseToolCatalogContractAdapter catalogs, SafetyContractSemanticValidator validator,
            SafetyContractCanonicalizer canonicalizer) {
        this.runs = Objects.requireNonNull(runs);
        this.contracts = Objects.requireNonNull(contracts);
        this.cases = Objects.requireNonNull(cases);
        this.catalogs = Objects.requireNonNull(catalogs);
        this.validator = Objects.requireNonNull(validator);
        this.canonicalizer = Objects.requireNonNull(canonicalizer);
    }

    /**
     * A's approval lookup holds the Release lock and its integrity reads append access audits.
     * A compatible outer transaction retains that lock until the outer transaction ends.
     * Call without an outer transaction when a self-contained short source read is required.
     */
    @Transactional(isolation = Isolation.REPEATABLE_READ)
    public ApprovedPolicySource load(UUID runId, UUID testCaseRunId, ReviewerContext reviewer) {
        requireSnapshotTransaction();
        if (runId == null || testCaseRunId == null || reviewer == null) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
        try {
            Projection run = runs.find(runId);
            requireRun(run, runId);
            // A authorizes the supplied context and verifies stored approval/current Release binding.
            // Do not replace this lookup with find(), or construct a reviewer from an actor string.
            ApprovedContract approved = contracts.approved(run.releaseId(), run.contractVersionId(), reviewer);
            Version version = requireApproval(approved, run, reviewer);
            JsonNode policy = version.policy().deepCopy();

            // Only load the case projection after the approval lookup's workspace authorization.
            CaseRun caseRun = cases.findCase(testCaseRunId);
            if (caseRun == null || !testCaseRunId.equals(caseRun.id())
                    || !runId.equals(caseRun.testRunId()) || caseRun.testCaseId() == null
                    || caseRun.status() == null || caseRun.trialIndex() < 0 || !hash(caseRun.variantHash())) {
                throw failure(FailureCode.CASE_RUN_BINDING_INVALID);
            }
            SourceBoundCatalog catalog = catalogs.load(run.releaseId(), reviewer.actorId());
            if (catalog == null || !run.releaseId().equals(catalog.releaseId())
                    || !run.agentArtifactFingerprint().equals(catalog.agentArtifactFingerprint())
                    || !run.releaseFingerprint().equals(catalog.releaseFingerprint())) {
                throw failure(FailureCode.CATALOG_BINDING_INVALID);
            }
            List<ReleaseToolBinding> bindings = requireToolBindings(catalog);
            ValidationResult validation = validator.validate(policy, catalog.semanticCatalog());
            if (validation == null || validation.status() == ValidationStatus.INVALID) {
                throw failure(FailureCode.POLICY_INVALID);
            }
            CanonicalPolicy canonical = canonicalizer.canonicalizeAndHash(policy);
            if (canonical == null || !version.policyHash().equals(canonical.policyHash())) {
                throw failure(FailureCode.POLICY_INTEGRITY_FAILURE);
            }
            return new ApprovedPolicySource(run, caseRun, version, policy, catalog, validation, canonical,
                    bindings, toolTrustPolicy(policy));
        } catch (PolicySourceException | BusinessException exception) {
            // Preserve A's established authorization/not-found/integrity error contract.
            throw exception;
        } catch (RuntimeException exception) {
            // Raw owner/catalog/engine exceptions can contain stored text or SQL details.
            throw failure(FailureCode.SOURCE_UNAVAILABLE);
        }
    }

    private static List<ReleaseToolBinding> requireToolBindings(SourceBoundCatalog catalog) {
        List<ReleaseToolBinding> bindings = catalog.releaseToolBindings();
        if (bindings == null || bindings.isEmpty()) {
            throw failure(FailureCode.CATALOG_BINDING_INVALID);
        }
        Set<String> expectedNames = new HashSet<>();
        catalog.semanticCatalog().enabledReleaseTools().forEach(tool -> expectedNames.add(tool.toolName()));
        Set<String> actualNames = new HashSet<>();
        for (ReleaseToolBinding binding : bindings) {
            if (binding == null || !binding.enabled() || !actualNames.add(binding.toolName())
                    || binding.version() == null || binding.version().isBlank()
                    || !binding.version().equals(binding.version().strip())
                    || !hash(binding.schemaDigest()) || !hash(binding.descriptionDigest())) {
                throw failure(FailureCode.CATALOG_BINDING_INVALID);
            }
        }
        if (!expectedNames.equals(actualNames)) {
            throw failure(FailureCode.CATALOG_BINDING_INVALID);
        }
        return List.copyOf(bindings);
    }

    private static ToolTrustPolicy toolTrustPolicy(JsonNode policy) {
        JsonNode required = policy.at("/toolTrust/requireTrustedTool");
        JsonNode allowed = policy.at("/toolTrust/allowedTrustLevels");
        if (!required.isBoolean() || !allowed.isArray()) {
            throw failure(FailureCode.POLICY_INVALID);
        }
        List<TrustLevel> levels = new ArrayList<>();
        try {
            for (JsonNode level : allowed) {
                if (!level.isString()) {
                    throw failure(FailureCode.POLICY_INVALID);
                }
                levels.add(TrustLevel.valueOf(level.stringValue()));
            }
            return new ToolTrustPolicy(required.booleanValue(), levels);
        } catch (IllegalArgumentException exception) {
            throw failure(FailureCode.POLICY_INVALID);
        }
    }

    private static void requireRun(Projection run, UUID runId) {
        if (run == null || !runId.equals(run.id()) || run.releaseId() == null
                || run.mode() == null || run.status() == null
                || !hash(run.agentArtifactFingerprint()) || !hash(run.releaseFingerprint())) {
            throw failure(FailureCode.RUN_BINDING_INVALID);
        }
        if (run.mode() == TestRunMode.BASELINE) {
            throw failure(FailureCode.UNSUPPORTED_RUN_MODE);
        }
        if (run.contractVersionId() == null) {
            throw failure(FailureCode.CONTRACT_NOT_APPROVED);
        }
    }

    private static Version requireApproval(ApprovedContract approved, Projection run, ReviewerContext reviewer) {
        if (approved == null || approved.version() == null) {
            throw failure(FailureCode.CONTRACT_NOT_APPROVED);
        }
        Version version = approved.version();
        JsonNode policy = version.policy();
        if (!run.contractVersionId().equals(version.id()) || !run.releaseId().equals(version.releaseId())
                || version.workspaceId() == null || !version.workspaceId().equals(reviewer.workspaceId())
                || !"APPROVED".equals(version.state()) || version.contractKey() == null
                || version.contractKey().isBlank() || version.version() <= 0
                || policy == null || !policy.isObject()
                || !policy.path("contractId").isString()
                || !version.contractKey().equals(policy.path("contractId").stringValue())
                || !policy.path("version").isIntegralNumber()
                || !BigInteger.valueOf(version.version()).equals(policy.path("version").bigIntegerValue())
                || !hash(version.policyHash()) || !hash(version.resourceHash())
                || version.validation() == null || !version.validation().isObject() || version.validation().isEmpty()
                || version.review() == null || !version.review().isObject() || version.review().isEmpty()) {
            throw failure(FailureCode.CONTRACT_NOT_APPROVED);
        }
        if (!run.agentArtifactFingerprint().equals(approved.agentArtifactFingerprint())
                || !run.releaseFingerprint().equals(approved.releaseFingerprint())) {
            throw failure(FailureCode.POLICY_INTEGRITY_FAILURE);
        }
        // Validation proof may bind the pre-approval Release fingerprint. A approval changes it;
        // current Run/approved/catalog fingerprints, not that historical value, must agree here.
        return version;
    }

    private static boolean hash(String value) {
        return value != null && value.matches("sha256:[0-9a-f]{64}");
    }

    private static void requireSnapshotTransaction() {
        if (!TransactionSynchronizationManager.isActualTransactionActive()
                || TransactionSynchronizationManager.isCurrentTransactionReadOnly()
                || !Objects.equals(TransactionSynchronizationManager.getCurrentTransactionIsolationLevel(),
                        Connection.TRANSACTION_REPEATABLE_READ)) {
            throw failure(FailureCode.UNSAFE_TRANSACTION);
        }
    }

    /** No Run summary, case result, session, approval review or raw manifest is retained. */
    public static final class ApprovedPolicySource {
        private final UUID runId;
        private final UUID testCaseRunId;
        private final UUID testCaseId;
        private final TestRunMode runMode;
        private final TestRunStatus runStatus;
        private final TestCaseRunStatus caseStatus;
        private final int trialIndex;
        private final String variantHash;
        private final VersionIdentity identity;
        private final String resourceHash;
        private final JsonNode policy;
        private final SourceBoundCatalog catalog;
        private final ValidationResult validation;
        private final CanonicalPolicy canonicalPolicy;
        private final List<ReleaseToolBinding> releaseToolBindings;
        private final ToolTrustPolicy toolTrustPolicy;

        private ApprovedPolicySource(Projection run, CaseRun caseRun, Version version, JsonNode policy,
                SourceBoundCatalog catalog, ValidationResult validation, CanonicalPolicy canonicalPolicy,
                List<ReleaseToolBinding> releaseToolBindings, ToolTrustPolicy toolTrustPolicy) {
            this.runId = run.id();
            this.testCaseRunId = caseRun.id();
            this.testCaseId = caseRun.testCaseId();
            this.runMode = run.mode();
            this.runStatus = run.status();
            this.caseStatus = caseRun.status();
            this.trialIndex = caseRun.trialIndex();
            this.variantHash = caseRun.variantHash();
            this.identity = new VersionIdentity(version.id(), version.workspaceId(), version.releaseId(),
                    version.contractKey(), version.version());
            this.resourceHash = version.resourceHash();
            this.policy = policy.deepCopy();
            this.catalog = catalog;
            this.validation = validation;
            this.canonicalPolicy = canonicalPolicy;
            this.releaseToolBindings = releaseToolBindings;
            this.toolTrustPolicy = toolTrustPolicy;
        }

        public UUID runId() { return runId; }
        public UUID testCaseRunId() { return testCaseRunId; }
        public UUID testCaseId() { return testCaseId; }
        public TestRunMode runMode() { return runMode; }
        public TestRunStatus runStatus() { return runStatus; }
        public TestCaseRunStatus caseStatus() { return caseStatus; }
        public int trialIndex() { return trialIndex; }
        public String variantHash() { return variantHash; }
        public VersionIdentity identity() { return identity; }
        public String policyHash() { return canonicalPolicy.policyHash(); }
        public String resourceHash() { return resourceHash; }
        public JsonNode policy() { return policy.deepCopy(); }
        public SourceBoundCatalog catalog() { return catalog; }
        public ValidationResult validation() { return validation; }
        public CanonicalPolicy canonicalPolicy() { return canonicalPolicy; }
        /** Expected declarations only; runtime registry observations must come from their owner. */
        public List<ReleaseToolBinding> releaseToolBindings() { return releaseToolBindings; }
        public ToolTrustPolicy toolTrustPolicy() { return toolTrustPolicy; }
    }

    public enum FailureCode {
        INVALID_REQUEST, UNSAFE_TRANSACTION, UNSUPPORTED_RUN_MODE, RUN_BINDING_INVALID,
        CONTRACT_NOT_APPROVED, CASE_RUN_BINDING_INVALID, CATALOG_BINDING_INVALID,
        POLICY_INTEGRITY_FAILURE, POLICY_INVALID, SOURCE_UNAVAILABLE
    }

    public static final class PolicySourceException extends RuntimeException {
        private final FailureCode code;

        private PolicySourceException(FailureCode code) {
            super("Approved policy source unavailable: " + code.name(), null, false, true);
            this.code = code;
        }

        public FailureCode code() { return code; }
    }

    private static PolicySourceException failure(FailureCode code) {
        return new PolicySourceException(code);
    }
}
