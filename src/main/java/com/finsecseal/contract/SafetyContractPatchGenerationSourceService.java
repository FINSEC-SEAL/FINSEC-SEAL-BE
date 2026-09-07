package com.finsecseal.contract;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.contract.SafetyContractGenerationSourceService.GenerationSourceException;
import com.finsecseal.contract.SafetyContractGenerationSourceService.PreparedGenerationSource;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ContractVersionSnapshot;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ValidationProof;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionIdentity;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionState;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.FindingSourceFacts;
import com.finsecseal.platform.contract.ContractPersistenceService;
import com.finsecseal.platform.contract.ContractPersistenceService.Version;
import com.finsecseal.platform.contract.PatchSourceService;
import com.finsecseal.platform.contract.PatchSourceService.PatchSource;
import java.math.BigInteger;
import java.sql.Connection;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/** Composes owner-authorized patch inputs without a model call or contract lifecycle mutation. */
@Service
public class SafetyContractPatchGenerationSourceService {
    private final PatchSourceService patchSources;
    private final ContractPersistenceService contracts;
    private final SafetyContractGenerationSourceService generationSources;
    private final ObjectMapper json;

    public SafetyContractPatchGenerationSourceService(PatchSourceService patchSources,
            ContractPersistenceService contracts, SafetyContractGenerationSourceService generationSources,
            ObjectMapper json) {
        this.patchSources = Objects.requireNonNull(patchSources);
        this.contracts = Objects.requireNonNull(contracts);
        this.generationSources = Objects.requireNonNull(generationSources);
        this.json = Objects.requireNonNull(json);
    }

    /** A's verified catalog read retains a Release lock and records its existing access audit. */
    @Transactional(isolation = Isolation.REPEATABLE_READ)
    public PreparedPatchGenerationSource prepare(UUID findingId, UUID baseContractVersionId,
            ReviewerContext reviewer) {
        requirePreparationTransaction();
        if (findingId == null || baseContractVersionId == null || reviewer == null) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
        try {
            PatchSource source = patchSources.find(findingId, reviewer);
            if (source == null) {
                throw failure(FailureCode.SOURCE_BINDING_INVALID);
            }
            FindingSourceFacts finding = source.facts();
            if (finding == null || !findingId.equals(finding.findingId())
                    || finding.workspaceId() == null || finding.releaseId() == null
                    || !finding.workspaceId().equals(reviewer.workspaceId())
                    || source.sourceRunId() == null || source.sourceCaseId() == null
                    || source.oracleResultId() == null) {
                throw failure(FailureCode.SOURCE_BINDING_INVALID);
            }
            JsonNode evidence = copyEvidence(source);

            ContractVersionSnapshot base = snapshot(
                    contracts.find(baseContractVersionId, reviewer), baseContractVersionId, finding);
            PreparedGenerationSource generation = generationSources.prepare(
                    finding.releaseId(), LoanReviewFinancialTemplate.KEY, reviewer.actorId());
            if (generation == null || generation.catalog() == null
                    || !finding.releaseId().equals(generation.catalog().releaseId())) {
                throw failure(FailureCode.SOURCE_BINDING_INVALID);
            }
            return new PreparedPatchGenerationSource(finding, source.sourceRunId(), source.sourceCaseId(),
                    source.oracleResultId(), evidence, base, generation);
        } catch (PatchGenerationSourceException | BusinessException | GenerationSourceException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            // Preserve rollback and failure without retaining owner JSON, credentials or SQL details.
            throw failure(FailureCode.SOURCE_UNAVAILABLE);
        }
    }

    private JsonNode copyEvidence(PatchSource source) {
        if (source.evidence() == null
                || source.evidence().isMissingNode() || source.evidence().isNull()) {
            throw failure(FailureCode.SOURCE_BINDING_INVALID);
        }
        // Copy before any subsequent owner read. A has already filtered and verified this evidence.
        return source.evidence().deepCopy();
    }

    private ContractVersionSnapshot snapshot(Version source, UUID requestedId, FindingSourceFacts finding) {
        if (source == null || source.policy() == null || source.validation() == null) {
            throw failure(FailureCode.BASE_VERSION_INVALID);
        }
        JsonNode policy = source.policy().deepCopy();
        JsonNode validation = source.validation().deepCopy();
        if (!requestedId.equals(source.id()) || !finding.workspaceId().equals(source.workspaceId())
                || !finding.releaseId().equals(source.releaseId())
                || source.contractKey() == null || source.contractKey().isBlank() || source.version() <= 0
                || !policy.isObject() || !policy.path("contractId").isString()
                || !source.contractKey().equals(policy.path("contractId").stringValue())
                || !policy.path("version").isIntegralNumber()
                || !BigInteger.valueOf(source.version()).equals(policy.path("version").bigIntegerValue())
                || !hash(source.policyHash()) || !hash(source.resourceHash())
                || (source.basePolicyHash() != null && !hash(source.basePolicyHash()))
                || !validation.isObject() || source.state() == null) {
            throw failure(FailureCode.BASE_VERSION_INVALID);
        }
        VersionState state;
        try {
            state = VersionState.valueOf(source.state());
        } catch (IllegalArgumentException exception) {
            throw failure(FailureCode.BASE_VERSION_INVALID);
        }
        Optional<ValidationProof> proof = validation.isEmpty() ? Optional.empty()
                : Optional.of(json.treeToValue(validation, ValidationProof.class));
        return new ContractVersionSnapshot(new VersionIdentity(source.id(), source.workspaceId(),
                source.releaseId(), source.contractKey(), source.version()), state, policy, source.policyHash(),
                source.resourceHash(), Optional.ofNullable(source.basePolicyHash()), proof);
    }

    private static boolean hash(String value) {
        return value != null && value.matches("sha256:[0-9a-f]{64}");
    }

    private static void requirePreparationTransaction() {
        // REQUIRED cannot upgrade an outer transaction; reject unsuitable callers before owner reads.
        if (!TransactionSynchronizationManager.isActualTransactionActive()
                || TransactionSynchronizationManager.isCurrentTransactionReadOnly()
                || !Objects.equals(TransactionSynchronizationManager.getCurrentTransactionIsolationLevel(),
                        Connection.TRANSACTION_REPEATABLE_READ)) {
            throw failure(FailureCode.UNSAFE_TRANSACTION);
        }
    }

    /**
     * Immutable generation inputs only. This is not a generated patch, current approval authority,
     * a redaction or model-send authorization guarantee, or proof that an attack was blocked.
     */
    public static final class PreparedPatchGenerationSource {
        private final FindingSourceFacts finding;
        private final UUID sourceRunId;
        private final UUID sourceCaseId;
        private final UUID oracleResultId;
        private final JsonNode evidence;
        private final ContractVersionSnapshot base;
        private final PreparedGenerationSource generation;

        private PreparedPatchGenerationSource(FindingSourceFacts finding, UUID sourceRunId, UUID sourceCaseId,
                UUID oracleResultId, JsonNode evidence, ContractVersionSnapshot base, PreparedGenerationSource generation) {
            this.finding = finding;
            this.sourceRunId = sourceRunId;
            this.sourceCaseId = sourceCaseId;
            this.oracleResultId = oracleResultId;
            this.evidence = evidence.deepCopy();
            this.base = base;
            this.generation = generation;
        }

        public FindingSourceFacts finding() { return finding; }
        public UUID sourceRunId() { return sourceRunId; }
        public UUID sourceCaseId() { return sourceCaseId; }
        public UUID oracleResultId() { return oracleResultId; }
        public JsonNode evidence() { return evidence.deepCopy(); }
        public ContractVersionSnapshot base() { return base; }
        public PreparedGenerationSource generation() { return generation; }
    }

    public enum FailureCode {
        INVALID_REQUEST, UNSAFE_TRANSACTION, SOURCE_BINDING_INVALID, BASE_VERSION_INVALID, SOURCE_UNAVAILABLE
    }

    public static final class PatchGenerationSourceException extends RuntimeException {
        private final FailureCode code;

        private PatchGenerationSourceException(FailureCode code) {
            super("Patch generation source could not be prepared: " + code.name(), null, false, true);
            this.code = code;
        }

        public FailureCode code() { return code; }
    }

    private static PatchGenerationSourceException failure(FailureCode code) {
        return new PatchGenerationSourceException(code);
    }
}
