package com.finsecseal.contract;

import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.SourceBoundCatalog;
import com.finsecseal.contract.SafetyContractCanonicalizer.CanonicalPolicy;
import com.finsecseal.contract.SafetyContractCanonicalizer.InvalidSafetyContractException;
import com.finsecseal.contract.SafetyContractSemanticValidator.Issue;
import com.finsecseal.contract.SafetyContractSemanticValidator.IssueSeverity;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationResult;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationStatus;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * Role C's deterministic judgment boundary for Safety Contract validation and approval.
 *
 * <p>This component never persists a state transition. It returns immutable compare-and-set
 * commands that a Role A owner may apply atomically after preserving its own audit evidence.</p>
 */
@Component
public final class SafetyContractLifecyclePolicy {

    private static final String REVIEWER_ROLE = "AI_SECURITY_REVIEWER";
    private static final int MAX_ACTOR_LENGTH = 120;
    private static final int MAX_SESSION_LENGTH = 200;
    private static final int MAX_COMMENT_LENGTH = 1000;
    private static final Pattern DIGEST = Pattern.compile("^sha256:[0-9a-f]{64}$");
    private static final Pattern STRONG_IF_MATCH = Pattern.compile(
            "^\"(sha256:[0-9a-f]{64})\"$"
    );
    private static final Comparator<Issue> ISSUE_ORDER = Comparator
            .comparing(Issue::jsonPointer)
            .thenComparing(Issue::code)
            .thenComparing(issue -> issue.severity().name())
            .thenComparing(Issue::message);

    private final VerifiedCatalogLoader catalogLoader;
    private final SafetyContractCanonicalizer canonicalizer;
    private final SafetyContractSemanticValidator semanticValidator;
    private final CanonicalJsonService canonicalJsonService;
    private final DigestService digestService;
    private final ObjectMapper objectMapper;

    /**
     * Production constructor. The authoritative Role A adapter is deliberately the only
     * injectable source of validation catalog data at the Spring boundary.
     */
    @Autowired
    public SafetyContractLifecyclePolicy(
            ReleaseToolCatalogContractAdapter catalogAdapter,
            SafetyContractCanonicalizer canonicalizer,
            SafetyContractSemanticValidator semanticValidator,
            CanonicalJsonService canonicalJsonService,
            DigestService digestService,
            ObjectMapper objectMapper
    ) {
        this(
                loaderFor(catalogAdapter),
                canonicalizer,
                semanticValidator,
                canonicalJsonService,
                digestService,
                objectMapper
        );
    }

    /** Test seam kept package-private so production wiring cannot inject an unattested catalog. */
    SafetyContractLifecyclePolicy(
            VerifiedCatalogLoader catalogLoader,
            SafetyContractCanonicalizer canonicalizer,
            SafetyContractSemanticValidator semanticValidator,
            CanonicalJsonService canonicalJsonService,
            DigestService digestService,
            ObjectMapper objectMapper
    ) {
        this.catalogLoader = Objects.requireNonNull(catalogLoader, "catalogLoader");
        this.canonicalizer = Objects.requireNonNull(canonicalizer, "canonicalizer");
        this.semanticValidator = Objects.requireNonNull(
                semanticValidator,
                "semanticValidator"
        );
        this.canonicalJsonService = Objects.requireNonNull(
                canonicalJsonService,
                "canonicalJsonService"
        );
        this.digestService = Objects.requireNonNull(digestService, "digestService");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }

    /**
     * Evaluates a candidate and returns deterministic evidence. A transition command is emitted
     * only for a VALID or WARN result containing no ERROR issue.
     */
    public ValidationDecision validate(
            ContractVersionSnapshot snapshot,
            String validatorActorId
    ) {
        requireSnapshot(snapshot);
        if (snapshot.state() != VersionState.CANDIDATE) {
            throw rejection(RejectionCode.INVALID_STATE_TRANSITION);
        }
        requireExactText(
                validatorActorId,
                MAX_ACTOR_LENGTH,
                RejectionCode.INVALID_ACTOR
        );

        CanonicalPolicy canonical = canonicalPolicy(snapshot.policy());
        requirePolicyBinding(snapshot, canonical);

        SourceBoundCatalog source = loadCatalog(
                snapshot.identity().releaseId(),
                validatorActorId
        );
        requireReleaseBinding(snapshot.identity(), source);

        ValidationResult result = evaluate(snapshot.policy(), source);
        String validatorVersion = validatorVersion(canonical);
        if (isApprovalEligible(result) && !isExactText(validatorVersion, 100)) {
            throw rejection(RejectionCode.VALIDATION_FAILURE);
        }
        ValidationProof proof = createProof(
                snapshot,
                canonical.policyHash(),
                validatorVersion,
                source,
                result
        );
        Optional<ValidationTransitionCommand> transition = Optional.empty();
        if (isApprovalEligible(result)) {
            transition = Optional.of(new ValidationTransitionCommand(
                    snapshot.identity(),
                    VersionState.CANDIDATE,
                    VersionState.VALIDATED,
                    snapshot.resourceHash(),
                    canonical.policyHash(),
                    snapshot.basePolicyHash(),
                    proof.validationHash(),
                    proof,
                    validatorActorId
            ));
        }
        return new ValidationDecision(proof, transition);
    }

    /**
     * Reproduces validation from the current authoritative source before returning an approval
     * CAS command. Stored proof data is never treated as executable authority on its own.
     */
    public ApprovalTransitionCommand approve(
            ContractVersionSnapshot snapshot,
            String ifMatch,
            ReviewerContext reviewer,
            String comment
    ) {
        requireSnapshot(snapshot);
        if (snapshot.state() != VersionState.VALIDATED) {
            throw rejection(RejectionCode.INVALID_STATE_TRANSITION);
        }

        requireReview(snapshot, ifMatch, reviewer, comment);

        CanonicalPolicy canonical = canonicalPolicy(snapshot.policy());
        requirePolicyBinding(snapshot, canonical);

        ValidationProof storedProof = snapshot.validationProof()
                .orElseThrow(() -> rejection(RejectionCode.VALIDATION_PROOF_REQUIRED));
        String validatorVersion = validatorVersion(canonical);
        requireStoredProofBinding(
                snapshot,
                canonical.policyHash(),
                validatorVersion,
                storedProof
        );
        if (!isApprovalEligible(storedProof.result())) {
            throw rejection(RejectionCode.VALIDATION_NOT_ELIGIBLE);
        }

        SourceBoundCatalog currentSource = loadCatalog(
                snapshot.identity().releaseId(),
                reviewer.actorId()
        );
        requireReleaseBinding(snapshot.identity(), currentSource);
        SourceBinding currentBinding = SourceBinding.from(currentSource);
        if (!currentBinding.equals(storedProof.sourceBinding())) {
            throw rejection(RejectionCode.VALIDATION_SOURCE_CHANGED);
        }

        ValidationResult reproducedResult = evaluate(snapshot.policy(), currentSource);
        if (!isApprovalEligible(reproducedResult)) {
            throw rejection(RejectionCode.VALIDATION_NOT_ELIGIBLE);
        }
        ValidationProof reproducedProof = createProof(
                snapshot,
                canonical.policyHash(),
                validatorVersion,
                currentSource,
                reproducedResult,
                storedProof.validatedFromResourceHash()
        );
        if (!reproducedProof.equals(storedProof)) {
            throw rejection(RejectionCode.VALIDATION_BINDING_MISMATCH);
        }

        return new ApprovalTransitionCommand(
                snapshot.identity(),
                VersionState.VALIDATED,
                VersionState.APPROVED,
                snapshot.resourceHash(),
                canonical.policyHash(),
                snapshot.basePolicyHash(),
                storedProof.validationHash(),
                storedProof,
                reviewer.copy(),
                comment
        );
    }

    /**
     * Returns rejection preconditions for the persistence owner to apply atomically and audit.
     * Invalid candidates can be discarded without revalidation or catalog availability. Stored
     * hashes identify the expected snapshot; they are not new policy validation evidence.
     */
    public RejectionTransitionCommand reject(
            ContractVersionSnapshot snapshot,
            String ifMatch,
            ReviewerContext reviewer,
            String comment
    ) {
        requireSnapshot(snapshot);
        if (snapshot.state() != VersionState.CANDIDATE
                && snapshot.state() != VersionState.VALIDATED) {
            throw rejection(RejectionCode.INVALID_STATE_TRANSITION);
        }
        requireReview(snapshot, ifMatch, reviewer, comment);

        return new RejectionTransitionCommand(
                snapshot.identity(),
                snapshot.state(),
                VersionState.REJECTED,
                snapshot.resourceHash(),
                snapshot.policyHash(),
                snapshot.basePolicyHash(),
                reviewer.copy(),
                comment
        );
    }

    private static void requireReview(
            ContractVersionSnapshot snapshot,
            String ifMatch,
            ReviewerContext reviewer,
            String comment
    ) {
        String expectedResourceHash = parseIfMatch(ifMatch);
        if (!constantTimeEqual(expectedResourceHash, snapshot.resourceHash())) {
            throw rejection(RejectionCode.STALE_RESOURCE);
        }
        requireReviewer(reviewer, snapshot.identity().workspaceId());
        requireExactText(comment, MAX_COMMENT_LENGTH, RejectionCode.INVALID_COMMENT);
    }

    private static VerifiedCatalogLoader loaderFor(
            ReleaseToolCatalogContractAdapter catalogAdapter
    ) {
        ReleaseToolCatalogContractAdapter trustedAdapter = Objects.requireNonNull(
                catalogAdapter,
                "catalogAdapter"
        );
        return trustedAdapter::load;
    }

    private CanonicalPolicy canonicalPolicy(JsonNode policy) {
        try {
            return canonicalizer.canonicalizeAndHash(policy);
        } catch (InvalidSafetyContractException exception) {
            throw rejection(RejectionCode.STRUCTURAL_POLICY_INVALID, exception);
        } catch (RuntimeException exception) {
            throw rejection(RejectionCode.POLICY_CANONICALIZATION_FAILURE, exception);
        }
    }

    private void requirePolicyBinding(
            ContractVersionSnapshot snapshot,
            CanonicalPolicy canonical
    ) {
        if (!constantTimeEqual(canonical.policyHash(), snapshot.policyHash())) {
            throw rejection(RejectionCode.POLICY_HASH_MISMATCH);
        }

        JsonNode policy = snapshot.policy();
        JsonNode contractId = policy.get("contractId");
        JsonNode version = policy.get("version");
        boolean identityMatches = contractId != null
                && contractId.isString()
                && snapshot.identity().contractKey().equals(contractId.stringValue())
                && version != null
                && version.isIntegralNumber()
                && BigInteger.valueOf(snapshot.identity().version())
                .equals(version.bigIntegerValue());
        if (!identityMatches) {
            throw rejection(RejectionCode.POLICY_IDENTITY_MISMATCH);
        }
    }

    private SourceBoundCatalog loadCatalog(UUID releaseId, String actorId) {
        SourceBoundCatalog source;
        try {
            source = catalogLoader.load(releaseId, actorId);
        } catch (RuntimeException exception) {
            throw rejection(RejectionCode.CATALOG_SOURCE_FAILURE, exception);
        }
        if (source == null) {
            throw rejection(RejectionCode.CATALOG_SOURCE_UNAVAILABLE);
        }
        return source;
    }

    private static void requireReleaseBinding(
            VersionIdentity identity,
            SourceBoundCatalog source
    ) {
        if (!identity.releaseId().equals(source.releaseId())) {
            throw rejection(RejectionCode.RELEASE_BINDING_MISMATCH);
        }
    }

    private ValidationResult evaluate(JsonNode policy, SourceBoundCatalog source) {
        ValidationResult result;
        try {
            result = semanticValidator.validate(
                    policy.deepCopy(),
                    source.semanticCatalog()
            );
        } catch (RuntimeException exception) {
            throw rejection(RejectionCode.VALIDATION_FAILURE, exception);
        }
        if (result == null) {
            throw rejection(RejectionCode.VALIDATION_FAILURE);
        }
        try {
            List<Issue> orderedIssues = new ArrayList<>(result.issues());
            orderedIssues.sort(ISSUE_ORDER);
            return ValidationResult.fromIssues(orderedIssues);
        } catch (RuntimeException exception) {
            throw rejection(RejectionCode.VALIDATION_FAILURE, exception);
        }
    }

    private ValidationProof createProof(
            ContractVersionSnapshot snapshot,
            String policyHash,
            String validatorVersion,
            SourceBoundCatalog source,
            ValidationResult result
    ) {
        return createProof(
                snapshot,
                policyHash,
                validatorVersion,
                source,
                result,
                snapshot.resourceHash()
        );
    }

    private ValidationProof createProof(
            ContractVersionSnapshot snapshot,
            String policyHash,
            String validatorVersion,
            SourceBoundCatalog source,
            ValidationResult result,
            String validatedFromResourceHash
    ) {
        SourceBinding sourceBinding = SourceBinding.from(source);
        String validationHash = validationHash(
                snapshot.identity(),
                policyHash,
                snapshot.basePolicyHash(),
                validatedFromResourceHash,
                validatorVersion,
                sourceBinding,
                result
        );
        return new ValidationProof(
                snapshot.identity(),
                policyHash,
                snapshot.basePolicyHash(),
                validatedFromResourceHash,
                validatorVersion,
                sourceBinding,
                result,
                validationHash
        );
    }

    private void requireStoredProofBinding(
            ContractVersionSnapshot snapshot,
            String policyHash,
            String validatorVersion,
            ValidationProof proof
    ) {
        if (proof == null
                || !snapshot.identity().equals(proof.identity())
                || !constantTimeEqual(policyHash, proof.policyHash())
                || !snapshot.basePolicyHash().equals(proof.basePolicyHash())
                || !isExactText(validatorVersion, 100)
                || !validatorVersion.equals(proof.validatorVersion())
                || !isDigest(proof.validatedFromResourceHash())
                || proof.sourceBinding() == null
                || proof.result() == null
                || !isDigest(proof.validationHash())) {
            throw rejection(RejectionCode.VALIDATION_BINDING_MISMATCH);
        }

        String expectedValidationHash;
        try {
            expectedValidationHash = validationHash(
                    proof.identity(),
                    proof.policyHash(),
                    proof.basePolicyHash(),
                    proof.validatedFromResourceHash(),
                    proof.validatorVersion(),
                    proof.sourceBinding(),
                    normalizeProofResult(proof.result())
            );
        } catch (LifecyclePolicyException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw rejection(RejectionCode.VALIDATION_BINDING_MISMATCH, exception);
        }
        if (!constantTimeEqual(expectedValidationHash, proof.validationHash())) {
            throw rejection(RejectionCode.VALIDATION_BINDING_MISMATCH);
        }
    }

    private static ValidationResult normalizeProofResult(ValidationResult result) {
        try {
            List<Issue> orderedIssues = new ArrayList<>(result.issues());
            orderedIssues.sort(ISSUE_ORDER);
            ValidationResult normalized = ValidationResult.fromIssues(orderedIssues);
            if (!normalized.equals(result)) {
                throw rejection(RejectionCode.VALIDATION_BINDING_MISMATCH);
            }
            return normalized;
        } catch (LifecyclePolicyException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw rejection(RejectionCode.VALIDATION_BINDING_MISMATCH, exception);
        }
    }

    private String validationHash(
            VersionIdentity identity,
            String policyHash,
            Optional<String> basePolicyHash,
            String validatedFromResourceHash,
            String validatorVersion,
            SourceBinding sourceBinding,
            ValidationResult result
    ) {
        try {
            ObjectNode root = objectMapper.createObjectNode();
            root.put("schemaVersion", "safety-contract-validation-proof/1");

            ObjectNode identityNode = objectMapper.createObjectNode();
            identityNode.put("versionId", identity.versionId().toString());
            identityNode.put("workspaceId", identity.workspaceId().toString());
            identityNode.put("releaseId", identity.releaseId().toString());
            identityNode.put("contractKey", identity.contractKey());
            identityNode.put("version", identity.version());
            root.set("identity", identityNode);

            root.put("policyHash", policyHash);
            if (basePolicyHash.isPresent()) {
                root.put("basePolicyHash", basePolicyHash.orElseThrow());
            } else {
                root.putNull("basePolicyHash");
            }
            root.put("validatedFromResourceHash", validatedFromResourceHash);
            root.put("validatorVersion", validatorVersion);

            ObjectNode sourceNode = objectMapper.createObjectNode();
            sourceNode.put("releaseId", sourceBinding.releaseId().toString());
            sourceNode.put("manifestSchemaVersion", sourceBinding.manifestSchemaVersion());
            sourceNode.put(
                    "agentArtifactFingerprint",
                    sourceBinding.agentArtifactFingerprint()
            );
            sourceNode.put("releaseFingerprint", sourceBinding.releaseFingerprint());
            sourceNode.put("serverToolCatalogHash", sourceBinding.serverToolCatalogHash());
            root.set("sourceBinding", sourceNode);

            ObjectNode resultNode = objectMapper.createObjectNode();
            resultNode.put("status", result.status().name());
            ArrayNode issuesNode = objectMapper.createArrayNode();
            for (Issue issue : result.issues()) {
                ObjectNode issueNode = objectMapper.createObjectNode();
                issueNode.put("jsonPointer", issue.jsonPointer());
                issueNode.put("code", issue.code());
                issueNode.put("severity", issue.severity().name());
                issueNode.put("message", issue.message());
                issuesNode.add(issueNode);
            }
            resultNode.set("issues", issuesNode);
            root.set("result", resultNode);

            return digestService.sha256(canonicalJsonService.canonicalize(root));
        } catch (RuntimeException exception) {
            throw rejection(RejectionCode.VALIDATION_FAILURE, exception);
        }
    }

    /**
     * Reads the version from the canonical snapshot. It becomes approval evidence only when the
     * authoritative semantic validator accepts that same snapshot without an ERROR issue.
     */
    private String validatorVersion(CanonicalPolicy canonical) {
        try {
            JsonNode canonicalPolicy = objectMapper.readTree(canonical.canonicalJson());
            JsonNode value = canonicalPolicy.at("/metadata/validatorVersion");
            return value.isString() ? value.stringValue() : "";
        } catch (Exception exception) {
            throw rejection(RejectionCode.VALIDATION_FAILURE, exception);
        }
    }

    private static boolean isApprovalEligible(ValidationResult result) {
        if (result == null
                || (result.status() != ValidationStatus.VALID
                && result.status() != ValidationStatus.WARN)) {
            return false;
        }
        return result.issues().stream()
                .noneMatch(issue -> issue.severity() == IssueSeverity.ERROR);
    }

    private static void requireSnapshot(ContractVersionSnapshot snapshot) {
        if (snapshot == null
                || snapshot.identity() == null
                || snapshot.state() == null
                || snapshot.policy() == null
                || !snapshot.policy().isObject()
                || !isDigest(snapshot.policyHash())
                || !isDigest(snapshot.resourceHash())
                || snapshot.basePolicyHash() == null
                || snapshot.validationProof() == null
                || snapshot.basePolicyHash().stream().anyMatch(hash -> !isDigest(hash))) {
            throw rejection(RejectionCode.INVALID_SNAPSHOT);
        }
        VersionIdentity identity = snapshot.identity();
        if (identity.versionId() == null
                || identity.workspaceId() == null
                || identity.releaseId() == null
                || !isExactText(identity.contractKey(), 200)
                || identity.version() <= 0) {
            throw rejection(RejectionCode.INVALID_SNAPSHOT);
        }
    }

    private static String parseIfMatch(String ifMatch) {
        if (ifMatch == null) {
            throw rejection(RejectionCode.INVALID_IF_MATCH);
        }
        Matcher matcher = STRONG_IF_MATCH.matcher(ifMatch);
        if (!matcher.matches()) {
            throw rejection(RejectionCode.INVALID_IF_MATCH);
        }
        return matcher.group(1);
    }

    private static void requireReviewer(
            ReviewerContext reviewer,
            UUID expectedWorkspaceId
    ) {
        if (reviewer == null) {
            throw rejection(RejectionCode.REVIEWER_CONTEXT_REQUIRED);
        }
        if (!Objects.equals(expectedWorkspaceId, reviewer.workspaceId())) {
            throw rejection(RejectionCode.REVIEWER_WORKSPACE_MISMATCH);
        }
        requireExactText(
                reviewer.actorId(),
                MAX_ACTOR_LENGTH,
                RejectionCode.INVALID_REVIEWER_IDENTITY
        );
        if (!REVIEWER_ROLE.equals(reviewer.role())) {
            throw rejection(RejectionCode.REVIEWER_ROLE_REQUIRED);
        }
        requireExactText(
                reviewer.sessionId(),
                MAX_SESSION_LENGTH,
                RejectionCode.INVALID_REVIEWER_SESSION
        );
        if (!reviewer.authenticated()) {
            throw rejection(RejectionCode.REVIEWER_AUTHENTICATION_REQUIRED);
        }
        if (!reviewer.csrfVerified()) {
            throw rejection(RejectionCode.REVIEWER_CSRF_REQUIRED);
        }
    }

    private static void requireExactText(
            String value,
            int maxLength,
            RejectionCode code
    ) {
        if (!isExactText(value, maxLength)) {
            throw rejection(code);
        }
    }

    private static boolean isExactText(String value, int maxLength) {
        return value != null
                && !value.isBlank()
                && value.equals(value.strip())
                && value.length() <= maxLength;
    }

    private static boolean isDigest(String value) {
        return value != null && DIGEST.matcher(value).matches();
    }

    private static boolean constantTimeEqual(String left, String right) {
        if (left == null || right == null || left.length() != right.length()) {
            return false;
        }
        int difference = 0;
        for (int index = 0; index < left.length(); index++) {
            difference |= left.charAt(index) ^ right.charAt(index);
        }
        return difference == 0;
    }

    private static LifecyclePolicyException rejection(RejectionCode code) {
        return new LifecyclePolicyException(code, null);
    }

    private static LifecyclePolicyException rejection(
            RejectionCode code,
            Throwable cause
    ) {
        return new LifecyclePolicyException(code, cause);
    }

    @FunctionalInterface
    interface VerifiedCatalogLoader {
        SourceBoundCatalog load(UUID releaseId, String actorId);
    }

    public enum VersionState {
        CANDIDATE,
        VALIDATED,
        APPROVED,
        REJECTED,
        SUPERSEDED
    }

    public enum RejectionCode {
        INVALID_SNAPSHOT("Contract version snapshot is invalid"),
        INVALID_ACTOR("Validator actor is invalid"),
        INVALID_STATE_TRANSITION("Safety Contract state transition is invalid"),
        STRUCTURAL_POLICY_INVALID("Safety Contract structure is invalid"),
        POLICY_CANONICALIZATION_FAILURE("Safety Contract canonicalization failed"),
        POLICY_HASH_MISMATCH("Safety Contract policy hash does not match"),
        POLICY_IDENTITY_MISMATCH("Safety Contract identity does not match its version"),
        CATALOG_SOURCE_UNAVAILABLE("Authoritative Tool catalog is unavailable"),
        CATALOG_SOURCE_FAILURE("Authoritative Tool catalog could not be loaded"),
        RELEASE_BINDING_MISMATCH("Authoritative Tool catalog release does not match"),
        VALIDATION_FAILURE("Deterministic Safety Contract validation failed"),
        VALIDATION_PROOF_REQUIRED("Deterministic validation proof is required"),
        VALIDATION_BINDING_MISMATCH("Deterministic validation proof does not match"),
        VALIDATION_NOT_ELIGIBLE("Validation result is not eligible for approval"),
        VALIDATION_SOURCE_CHANGED("Authoritative validation source has changed"),
        INVALID_IF_MATCH("If-Match must be one exact strong quoted resource hash"),
        STALE_RESOURCE("Safety Contract resource is stale"),
        REVIEWER_CONTEXT_REQUIRED("Trusted reviewer context is required"),
        INVALID_REVIEWER_IDENTITY("Reviewer identity is invalid"),
        INVALID_REVIEWER_SESSION("Reviewer session is invalid"),
        REVIEWER_AUTHENTICATION_REQUIRED("Reviewer authentication is required"),
        REVIEWER_CSRF_REQUIRED("Reviewer CSRF verification is required"),
        REVIEWER_ROLE_REQUIRED("AI_SECURITY_REVIEWER role is required"),
        REVIEWER_WORKSPACE_MISMATCH("Reviewer workspace does not match"),
        INVALID_COMMENT("Review comment is invalid");

        private final String safeMessage;

        RejectionCode(String safeMessage) {
            this.safeMessage = safeMessage;
        }

        public String safeMessage() {
            return safeMessage;
        }
    }

    public static final class LifecyclePolicyException extends RuntimeException {

        private final RejectionCode code;

        private LifecyclePolicyException(RejectionCode code, Throwable cause) {
            super(Objects.requireNonNull(code, "code").safeMessage(), cause);
            this.code = code;
        }

        public RejectionCode code() {
            return code;
        }
    }

    public record VersionIdentity(
            UUID versionId,
            UUID workspaceId,
            UUID releaseId,
            String contractKey,
            int version
    ) {
    }

    public record ContractVersionSnapshot(
            VersionIdentity identity,
            VersionState state,
            JsonNode policy,
            String policyHash,
            String resourceHash,
            Optional<String> basePolicyHash,
            Optional<ValidationProof> validationProof
    ) {

        public ContractVersionSnapshot {
            policy = policy == null ? null : policy.deepCopy();
            basePolicyHash = basePolicyHash == null
                    ? null
                    : basePolicyHash.map(String::valueOf);
            validationProof = validationProof == null
                    ? null
                    : validationProof.map(ValidationProof::copy);
        }

        @Override
        public JsonNode policy() {
            return policy == null ? null : policy.deepCopy();
        }

        @Override
        public Optional<ValidationProof> validationProof() {
            return validationProof == null
                    ? null
                    : validationProof.map(ValidationProof::copy);
        }
    }

    public record SourceBinding(
            UUID releaseId,
            String manifestSchemaVersion,
            String agentArtifactFingerprint,
            String releaseFingerprint,
            String serverToolCatalogHash
    ) {

        private static SourceBinding from(SourceBoundCatalog source) {
            return new SourceBinding(
                    source.releaseId(),
                    source.manifestSchemaVersion(),
                    source.agentArtifactFingerprint(),
                    source.releaseFingerprint(),
                    source.serverToolCatalogHash()
            );
        }
    }

    public record ValidationProof(
            VersionIdentity identity,
            String policyHash,
            Optional<String> basePolicyHash,
            String validatedFromResourceHash,
            String validatorVersion,
            SourceBinding sourceBinding,
            ValidationResult result,
            String validationHash
    ) {

        public ValidationProof {
            basePolicyHash = basePolicyHash == null
                    ? null
                    : basePolicyHash.map(String::valueOf);
            if (result != null) {
                result = new ValidationResult(result.status(), result.issues());
            }
        }

        private ValidationProof copy() {
            return new ValidationProof(
                    identity,
                    policyHash,
                    basePolicyHash,
                    validatedFromResourceHash,
                    validatorVersion,
                    sourceBinding,
                    result,
                    validationHash
            );
        }
    }

    public record ReviewerContext(
            UUID workspaceId,
            String actorId,
            String role,
            String sessionId,
            boolean authenticated,
            boolean csrfVerified,
            boolean demoMode
    ) {

        private ReviewerContext copy() {
            return new ReviewerContext(
                    workspaceId,
                    actorId,
                    role,
                    sessionId,
                    authenticated,
                    csrfVerified,
                    demoMode
            );
        }
    }

    public record ValidationTransitionCommand(
            VersionIdentity identity,
            VersionState expectedState,
            VersionState targetState,
            String expectedResourceHash,
            String policyHash,
            Optional<String> basePolicyHash,
            String validationHash,
            ValidationProof validationProof,
            String validatorActorId
    ) {

        public ValidationTransitionCommand {
            Objects.requireNonNull(identity, "identity");
            Objects.requireNonNull(expectedState, "expectedState");
            Objects.requireNonNull(targetState, "targetState");
            Objects.requireNonNull(expectedResourceHash, "expectedResourceHash");
            Objects.requireNonNull(policyHash, "policyHash");
            basePolicyHash = Objects.requireNonNull(basePolicyHash, "basePolicyHash");
            Objects.requireNonNull(validationHash, "validationHash");
            validationProof = Objects.requireNonNull(
                    validationProof,
                    "validationProof"
            ).copy();
            Objects.requireNonNull(validatorActorId, "validatorActorId");
        }

        @Override
        public ValidationProof validationProof() {
            return validationProof.copy();
        }
    }

    public record ValidationDecision(
            ValidationProof validationProof,
            Optional<ValidationTransitionCommand> transitionCommand
    ) {

        public ValidationDecision {
            validationProof = Objects.requireNonNull(
                    validationProof,
                    "validationProof"
            ).copy();
            transitionCommand = Objects.requireNonNull(
                    transitionCommand,
                    "transitionCommand"
            );
        }

        @Override
        public ValidationProof validationProof() {
            return validationProof.copy();
        }
    }

    public record RejectionTransitionCommand(
            VersionIdentity identity,
            VersionState expectedState,
            VersionState targetState,
            String expectedResourceHash,
            String policyHash,
            Optional<String> basePolicyHash,
            ReviewerContext reviewer,
            String comment
    ) {

        public RejectionTransitionCommand {
            Objects.requireNonNull(identity, "identity");
            Objects.requireNonNull(expectedState, "expectedState");
            Objects.requireNonNull(targetState, "targetState");
            Objects.requireNonNull(expectedResourceHash, "expectedResourceHash");
            Objects.requireNonNull(policyHash, "policyHash");
            basePolicyHash = Objects.requireNonNull(basePolicyHash, "basePolicyHash");
            reviewer = Objects.requireNonNull(reviewer, "reviewer").copy();
            Objects.requireNonNull(comment, "comment");
        }

        @Override
        public ReviewerContext reviewer() {
            return reviewer.copy();
        }
    }

    public record ApprovalTransitionCommand(
            VersionIdentity identity,
            VersionState expectedState,
            VersionState targetState,
            String expectedResourceHash,
            String policyHash,
            Optional<String> basePolicyHash,
            String validationHash,
            ValidationProof validationProof,
            ReviewerContext reviewer,
            String comment
    ) {

        public ApprovalTransitionCommand {
            Objects.requireNonNull(identity, "identity");
            Objects.requireNonNull(expectedState, "expectedState");
            Objects.requireNonNull(targetState, "targetState");
            Objects.requireNonNull(expectedResourceHash, "expectedResourceHash");
            Objects.requireNonNull(policyHash, "policyHash");
            basePolicyHash = Objects.requireNonNull(basePolicyHash, "basePolicyHash");
            Objects.requireNonNull(validationHash, "validationHash");
            validationProof = Objects.requireNonNull(
                    validationProof,
                    "validationProof"
            ).copy();
            reviewer = Objects.requireNonNull(reviewer, "reviewer").copy();
            Objects.requireNonNull(comment, "comment");
        }

        @Override
        public ValidationProof validationProof() {
            return validationProof.copy();
        }

        @Override
        public ReviewerContext reviewer() {
            return reviewer.copy();
        }
    }
}
