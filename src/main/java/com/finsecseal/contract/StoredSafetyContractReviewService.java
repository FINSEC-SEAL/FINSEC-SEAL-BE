package com.finsecseal.contract;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionIdentity;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionState;
import com.finsecseal.contract.SafetyContractReviewDiff.ChangeKind;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationResult;
import com.finsecseal.platform.contract.ContractPersistenceService;
import com.finsecseal.platform.contract.ContractPersistenceService.Version;
import java.math.BigInteger;
import java.sql.Connection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/** Composes a stored review snapshot; persistence, authorization and transitions remain A-owned. */
@Service
public class StoredSafetyContractReviewService {
    private final ContractPersistenceService persistence;
    private final SafetyContractReviewDiff diff;
    private final SafetyContractCanonicalizer canonicalizer;
    private final ObjectMapper json;

    public StoredSafetyContractReviewService(ContractPersistenceService persistence,
            SafetyContractReviewDiff diff, SafetyContractCanonicalizer canonicalizer, ObjectMapper json) {
        this.persistence = Objects.requireNonNull(persistence);
        this.diff = Objects.requireNonNull(diff);
        this.canonicalizer = Objects.requireNonNull(canonicalizer);
        this.json = Objects.requireNonNull(json);
    }

    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public ReviewView review(UUID versionId, ReviewerContext reviewer) {
        requireSnapshotTransaction();
        if (versionId == null) {
            throw failure(FailureCode.INVALID_REQUEST);
        }
        try {
            Snapshot target = snapshot(persistence.find(versionId, reviewer), FailureCode.STORED_VERSION_INVALID);
            if (!versionId.equals(target.identity().versionId()) || reviewer == null
                    || !target.identity().workspaceId().equals(reviewer.workspaceId())) {
                throw failure(FailureCode.STORED_VERSION_INVALID);
            }
            Optional<Snapshot> base = baseline(target, reviewer);
            var comparison = diff.compare(base.map(Snapshot::policy), target.policy());
            var canonical = canonicalizer.canonicalizeAndHash(target.policy());
            if (!target.policyHash().equals(comparison.afterHash())
                    || !target.policyHash().equals(canonical.policyHash())
                    || !comparison.beforeHash().equals(Optional.ofNullable(target.basePolicyHash()))) {
                throw failure(FailureCode.STORED_VERSION_INVALID);
            }
            List<ChangeView> changes = comparison.changes().stream().map(change -> new ChangeView(
                    change.pointer(), change.kind(), change.before().map(json::writeValueAsString).orElse(null),
                    change.after().map(json::writeValueAsString).orElse(null))).toList();
            return new ReviewView(target.identity(), target.state(), target.policyHash(), target.resourceHash(),
                    json.writeValueAsString(target.policy()), canonical.canonicalJson(),
                    base.map(value -> new Baseline(value.identity(), value.policyHash())),
                    validation(target.validation()), reviewMetadata(target.review()), changes);
        } catch (ReviewException | BusinessException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            // A proxied read can mark the transaction rollback-only. Propagate a fresh safe failure,
            // rather than returning partial data and failing later during transaction completion.
            throw failure(FailureCode.REVIEW_UNAVAILABLE);
        }
    }

    private Optional<Snapshot> baseline(Snapshot target, ReviewerContext reviewer) {
        if (target.basePolicyHash() == null) {
            return Optional.empty();
        }
        List<Snapshot> matches = List.copyOf(persistence.list(target.identity().releaseId(), reviewer)).stream()
                .filter(value -> target.basePolicyHash().equals(value.policyHash()))
                .map(value -> snapshot(value, FailureCode.BASELINE_UNAVAILABLE)).toList();
        if (matches.size() != 1) {
            throw failure(FailureCode.BASELINE_UNAVAILABLE);
        }
        Snapshot base = matches.getFirst();
        if (base.identity().versionId().equals(target.identity().versionId())
                || !base.identity().workspaceId().equals(target.identity().workspaceId())
                || !base.identity().releaseId().equals(target.identity().releaseId())
                || base.state() != VersionState.APPROVED) {
            throw failure(FailureCode.BASELINE_UNAVAILABLE);
        }
        return Optional.of(base);
    }

    private Snapshot snapshot(Version source, FailureCode code) {
        try {
            if (source == null) {
                throw failure(code);
            }
            JsonNode policy = source.policy().deepCopy();
            JsonNode validation = source.validation().deepCopy();
            JsonNode review = source.review().deepCopy();
            if (source.id() == null || source.workspaceId() == null || source.releaseId() == null
                    || source.contractKey() == null || source.contractKey().isBlank() || source.version() <= 0
                    || !policy.isObject() || !policy.path("contractId").isString()
                    || !source.contractKey().equals(policy.path("contractId").stringValue())
                    || !policy.path("version").isIntegralNumber()
                    || !BigInteger.valueOf(source.version()).equals(policy.path("version").bigIntegerValue())
                    || !hash(source.policyHash()) || !hash(source.resourceHash())
                    || (source.basePolicyHash() != null && !hash(source.basePolicyHash()))
                    || !validation.isObject() || !review.isObject()) {
                throw failure(code);
            }
            return new Snapshot(new VersionIdentity(source.id(), source.workspaceId(), source.releaseId(),
                    source.contractKey(), source.version()), VersionState.valueOf(source.state()), policy,
                    source.policyHash(), source.resourceHash(), source.basePolicyHash(), validation, review);
        } catch (RuntimeException exception) {
            throw failure(code);
        }
    }

    private Optional<ValidationResult> validation(JsonNode stored) {
        if (stored.isEmpty()) {
            return Optional.empty();
        }
        if (!stored.path("result").isObject()) {
            throw failure(FailureCode.STORED_VERSION_INVALID);
        }
        return Optional.of(json.treeToValue(stored.path("result"), ValidationResult.class));
    }

    private Optional<ReviewMetadata> reviewMetadata(JsonNode stored) {
        if (stored.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new ReviewMetadata(text(stored, "actorId"), text(stored, "role"),
                text(stored, "comment"), text(stored, "decision")));
    }

    private String text(JsonNode node, String field) {
        if (!node.path(field).isString()) {
            throw failure(FailureCode.STORED_VERSION_INVALID);
        }
        return node.path(field).stringValue();
    }

    private static boolean hash(String value) {
        return value != null && value.matches("sha256:[0-9a-f]{64}");
    }

    private static void requireSnapshotTransaction() {
        // REQUIRED joins an outer transaction; the annotation alone cannot upgrade its isolation.
        if (!TransactionSynchronizationManager.isActualTransactionActive()
                || !TransactionSynchronizationManager.isCurrentTransactionReadOnly()
                || !Objects.equals(TransactionSynchronizationManager.getCurrentTransactionIsolationLevel(),
                        Connection.TRANSACTION_REPEATABLE_READ)) {
            throw failure(FailureCode.UNSAFE_TRANSACTION);
        }
    }

    private record Snapshot(VersionIdentity identity, VersionState state, JsonNode policy,
            String policyHash, String resourceHash, String basePolicyHash, JsonNode validation, JsonNode review) {}

    public record Baseline(VersionIdentity identity, String policyHash) {}
    public record ReviewMetadata(String actorId, String role, String comment, String decision) {}
    /** A null side means absence; JSON null, strings and large numbers are encoded as JSON text. */
    public record ChangeView(String pointer, ChangeKind kind, String beforeJson, String afterJson) {}
    public record ReviewView(VersionIdentity identity, VersionState state, String policyHash, String resourceHash,
            String storedPolicyJson, String canonicalPolicyJson, Optional<Baseline> baseline,
            Optional<ValidationResult> validation, Optional<ReviewMetadata> review, List<ChangeView> changes) {
        public ReviewView {
            changes = List.copyOf(changes);
        }
    }

    public enum FailureCode {
        INVALID_REQUEST, UNSAFE_TRANSACTION, STORED_VERSION_INVALID, BASELINE_UNAVAILABLE, REVIEW_UNAVAILABLE
    }

    public static final class ReviewException extends RuntimeException {
        private final FailureCode code;

        private ReviewException(FailureCode code) {
            super("Stored contract review unavailable: " + code.name(), null, false, true);
            this.code = code;
        }

        public FailureCode code() { return code; }
    }

    private static ReviewException failure(FailureCode code) {
        return new ReviewException(code);
    }
}
