package com.finsecseal.contract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionState;
import com.finsecseal.contract.SafetyContractSemanticValidator.Issue;
import com.finsecseal.contract.SafetyContractSemanticValidator.IssueSeverity;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationResult;
import com.finsecseal.contract.StoredSafetyContractReviewService.FailureCode;
import com.finsecseal.contract.StoredSafetyContractReviewService.ReviewException;
import com.finsecseal.platform.contract.ContractPersistenceService;
import com.finsecseal.platform.contract.ContractPersistenceService.Version;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import java.math.BigInteger;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

class StoredSafetyContractReviewServiceTest {
    private static final UUID WORKSPACE = UUID.randomUUID();
    private static final UUID RELEASE = UUID.randomUUID();
    private static final String RESOURCE = "sha256:" + "a".repeat(64);
    private static final String CANARY = "STORED-REVIEW-SECRET-CANARY";
    private final ReviewerContext reviewer = new ReviewerContext(WORKSPACE, "reviewer", "AI_SECURITY_REVIEWER",
            "private-session", true, true, false);
    private ObjectMapper json;
    private SafetyContractCanonicalizer canonicalizer;
    private SafetyContractReviewDiff diff;
    private ContractPersistenceService persistence;
    private StoredSafetyContractReviewService service;
    private ObjectNode policy;

    @BeforeEach
    void setup() throws Exception {
        json = new ObjectMapper();
        var schema = new SafetyContractSchemaValidator();
        canonicalizer = new SafetyContractCanonicalizer(schema, new CanonicalJsonService(json), new DigestService());
        diff = new SafetyContractReviewDiff(schema, canonicalizer);
        persistence = mock(ContractPersistenceService.class);
        service = new StoredSafetyContractReviewService(persistence, diff, canonicalizer, json);
        try (var input = getClass().getResourceAsStream("/fixtures/loan-review-safety-contract.json")) {
            policy = (ObjectNode) json.readTree(input);
        }
        // Application logic fixture only. The separate PostgreSQL tests prove actual isolation.
        TransactionSynchronizationManager.setActualTransactionActive(true);
        TransactionSynchronizationManager.setCurrentTransactionReadOnly(true);
        TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(Connection.TRANSACTION_REPEATABLE_READ);
    }

    @AfterEach
    void clearTransactionMetadata() {
        TransactionSynchronizationManager.clear();
    }

    @Test
    void initialStoredVersionHasExplicitAbsentBaseAndNeverListsOrWrites() {
        Version target = version(policy, "CANDIDATE", null);
        when(persistence.find(target.id(), reviewer)).thenReturn(target);

        var view = service.review(target.id(), reviewer);

        assertThat(view.identity().versionId()).isEqualTo(target.id());
        assertThat(view.identity().workspaceId()).isEqualTo(WORKSPACE);
        assertThat(view.identity().releaseId()).isEqualTo(RELEASE);
        assertThat(view.state()).isEqualTo(VersionState.CANDIDATE);
        assertThat(view.resourceHash()).isEqualTo(RESOURCE);
        assertThat(view.policyHash()).isEqualTo(target.policyHash());
        assertThat(view.baseline()).isEmpty();
        assertThat(view.validation()).isEmpty();
        assertThat(view.review()).isEmpty();
        assertThat(json.readTree(view.storedPolicyJson())).isEqualTo(policy);
        assertThat(view.canonicalPolicyJson()).isEqualTo(canonicalizer.canonicalizeAndHash(policy).canonicalJson());
        assertThat(view.changes()).hasSize(1);
        assertThat(view.changes().getFirst().pointer()).isEmpty();
        assertThat(view.changes().getFirst().beforeJson()).isNull();
        assertThat(json.readTree(view.changes().getFirst().afterJson())).isEqualTo(policy);
        verify(persistence).find(target.id(), reviewer);
        verifyNoMoreInteractions(persistence);
    }

    @Test
    void selectsRecordedHistoricalApprovedBaseWithoutCurrentApprovalOrAdjacencyAssumptions() {
        Version base = version(policy, "APPROVED", null);
        ObjectNode changed = policy.deepCopy().put("contractId", "another-contract").put("version", 7);
        Version target = version(changed, "REJECTED", base.policyHash());
        Version newer = version(policy.deepCopy().put("version", 9), "APPROVED", target.policyHash());
        when(persistence.find(target.id(), reviewer)).thenReturn(target);
        when(persistence.list(RELEASE, reviewer)).thenReturn(List.of(newer, target, base));

        var view = service.review(target.id(), reviewer);

        assertThat(view.baseline().orElseThrow().identity().versionId()).isEqualTo(base.id());
        assertThat(view.baseline().orElseThrow().policyHash()).isEqualTo(base.policyHash());
        assertThat(view.changes()).extracting(StoredSafetyContractReviewService.ChangeView::pointer)
                .containsExactly("/contractId", "/version");
        verify(persistence).find(target.id(), reviewer);
        verify(persistence).list(RELEASE, reviewer);
        verifyNoMoreInteractions(persistence);
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "ambiguous", "self", "candidate", "rejected", "superseded",
            "foreignWorkspace", "foreignRelease", "corruptHash", "nullList", "nullRow"})
    void unavailableBaselineNeverBecomesCreationOrPartialComparison(String problem) {
        Version base = version(policy, "APPROVED", null);
        Version target = version(policy.deepCopy().put("version", 2), "CANDIDATE", base.policyHash());
        List<Version> values = new ArrayList<>(List.of(base, target));
        switch (problem) {
            case "missing" -> values = List.of(target);
            case "ambiguous" -> values.add(version(policy, "APPROVED", null));
            case "self" -> target = copy(target.id(), WORKSPACE, RELEASE, target.contractKey(),
                    target.version(), "APPROVED", target.policy(), target.policyHash(), RESOURCE, target.policyHash(),
                    target.validation(), target.review());
            case "candidate", "rejected", "superseded" -> values.set(0, copy(base.id(), WORKSPACE, RELEASE,
                    base.contractKey(), base.version(), problem.equals("candidate") ? "CANDIDATE" : problem.toUpperCase(),
                    base.policy(), base.policyHash(), RESOURCE, null, base.validation(), base.review()));
            case "foreignWorkspace", "foreignRelease" -> values.set(0, copy(base.id(),
                    problem.equals("foreignWorkspace") ? UUID.randomUUID() : WORKSPACE,
                    problem.equals("foreignRelease") ? UUID.randomUUID() : RELEASE, base.contractKey(), base.version(),
                    base.state(), base.policy(), base.policyHash(), RESOURCE, null, base.validation(), base.review()));
            case "corruptHash" -> values.set(0, copy(base.id(), WORKSPACE, RELEASE, base.contractKey(), base.version(),
                    base.state(), policy.deepCopy().put("purpose", "TAMPERED"), base.policyHash(), RESOURCE, null,
                    base.validation(), base.review()));
            case "nullList" -> values = null;
            case "nullRow" -> values.add(null);
            default -> throw new AssertionError(problem);
        }
        if (problem.equals("self")) values = List.of(target);
        when(persistence.find(target.id(), reviewer)).thenReturn(target);
        when(persistence.list(RELEASE, reviewer)).thenReturn(values);
        UUID id = target.id();
        assertSafeFailure(() -> service.review(id, reviewer), null);
    }

    @Test
    void unrelatedCandidateIdentityDoesNotReplaceOrInvalidateTheRecordedBaseline() {
        Version base = version(policy, "APPROVED", null);
        Version target = version(policy.deepCopy().put("version", 2), "CANDIDATE", base.policyHash());
        // Synthetic inconsistent boundary input, not a state created by A's public API.
        ObjectNode unrelatedPolicy = policy.deepCopy().put("contractId", "another-contract")
                .put("version", new BigInteger("4294967297"));
        Version unrelated = new Version(UUID.randomUUID(), WORKSPACE, RELEASE, "another-contract", 1,
                "CANDIDATE", unrelatedPolicy, canonicalizer.canonicalizeAndHash(unrelatedPolicy).policyHash(),
                RESOURCE, null, json.createObjectNode(), json.createObjectNode());
        when(persistence.find(target.id(), reviewer)).thenReturn(target);
        when(persistence.list(RELEASE, reviewer)).thenReturn(List.of(unrelated, target, base));

        assertThat(service.review(target.id(), reviewer).baseline().orElseThrow().identity().versionId())
                .isEqualTo(base.id());
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "id", "workspace", "nullWorkspace", "nullRelease", "key", "blankKey",
            "versionZero", "versionNegative", "versionMismatch", "versionOverflow", "versionFloat", "state",
            "policyHash", "hashFormat", "resourceHash", "baseHash", "nullPolicy", "validation", "review"})
    void rejectsInvalidStoredIdentityStateAndHashWithoutLeakingSource(String problem) {
        Version valid = version(policy, "CANDIDATE", null);
        UUID id = valid.id();
        UUID storedId = id;
        UUID workspace = WORKSPACE;
        UUID release = RELEASE;
        String key = valid.contractKey();
        int number = valid.version();
        String state = valid.state();
        JsonNode body = policy.deepCopy();
        String policyHash = valid.policyHash();
        String resourceHash = RESOURCE;
        String baseHash = null;
        JsonNode validation = valid.validation();
        JsonNode review = valid.review();
        switch (problem) {
            case "null" -> { }
            case "id" -> storedId = UUID.randomUUID();
            case "workspace" -> workspace = UUID.randomUUID();
            case "nullWorkspace" -> workspace = null;
            case "nullRelease" -> release = null;
            case "key" -> key = CANARY;
            case "blankKey" -> key = " ";
            case "versionZero" -> number = 0;
            case "versionNegative" -> number = -1;
            case "versionMismatch" -> ((ObjectNode) body).put("version", 2);
            case "versionOverflow" -> ((ObjectNode) body).put("version", new BigInteger("4294967297"));
            case "versionFloat" -> ((ObjectNode) body).put("version", 1.0);
            case "state" -> state = CANARY;
            case "policyHash" -> policyHash = "sha256:" + "b".repeat(64);
            case "hashFormat" -> policyHash = CANARY;
            case "resourceHash" -> resourceHash = CANARY;
            case "baseHash" -> baseHash = CANARY;
            case "nullPolicy" -> body = null;
            case "validation" -> validation = json.valueToTree(CANARY);
            case "review" -> review = json.valueToTree(CANARY);
            default -> throw new AssertionError(problem);
        }
        Version invalid = problem.equals("null") ? null : copy(storedId, workspace, release, key, number,
                state, body, policyHash, resourceHash, baseHash, validation, review);
        when(persistence.find(id, reviewer)).thenReturn(invalid);
        assertSafeFailure(() -> service.review(id, reviewer), FailureCode.STORED_VERSION_INVALID);
    }

    @Test
    void copiesMutableOwnerInputsBeforeSubsequentReadsAndReturnsOnlyImmutableValues() {
        Version base = version(policy, "APPROVED", null);
        Version target = version(policy.deepCopy().put("version", 2), "CANDIDATE", base.policyHash());
        String expected = target.policy().toString();
        when(persistence.find(target.id(), reviewer)).thenReturn(target);
        doAnswer(invocation -> {
            ((ObjectNode) target.policy()).put("purpose", CANARY);
            return new ArrayList<>(List.of(base));
        }).when(persistence).list(RELEASE, reviewer);

        var view = service.review(target.id(), reviewer);
        ((ObjectNode) base.policy()).put("purpose", CANARY);
        assertThat(view.storedPolicyJson()).isEqualTo(expected).doesNotContain(CANARY);
        assertThatThrownBy(() -> view.changes().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThat(view.changes().getFirst().beforeJson()).isEqualTo("1");
        assertThat(view.changes().getFirst().afterJson()).isEqualTo("2");
    }

    @Test
    void preservesRawUnicodeNewlinesAndLargeIntegerDiffSidesSeparatelyFromCanonicalJson() {
        ObjectNode before = policy.deepCopy().put("purpose", "\u1100\u1161\r\n");
        ((ObjectNode) before.at("/cardinality/CUSTOMER_DATA_READ")).put("maxRequestedRecords", new BigInteger("9007199254740993"));
        Version base = version(before, "APPROVED", null);
        ObjectNode after = before.deepCopy().put("version", 2).put("purpose", "\uac00\n");
        ((ObjectNode) after.at("/cardinality/CUSTOMER_DATA_READ")).put("maxRequestedRecords", new BigInteger("9007199254740994"));
        Version target = version(after, "CANDIDATE", base.policyHash());
        when(persistence.find(target.id(), reviewer)).thenReturn(target);
        when(persistence.list(RELEASE, reviewer)).thenReturn(List.of(base, target));

        var view = service.review(target.id(), reviewer);

        assertThat(view.storedPolicyJson()).isEqualTo(json.writeValueAsString(after));
        assertThat(json.readTree(view.storedPolicyJson()).at("/cardinality/CUSTOMER_DATA_READ/maxRequestedRecords")
                .bigIntegerValue()).isEqualTo(new BigInteger("9007199254740994"));
        assertThat(view.changes()).anySatisfy(change -> {
            assertThat(change.pointer()).isEqualTo("/cardinality/CUSTOMER_DATA_READ/maxRequestedRecords");
            assertThat(change.beforeJson()).isEqualTo("9007199254740993");
            assertThat(change.afterJson()).isEqualTo("9007199254740994");
        }).anySatisfy(change -> {
            assertThat(change.pointer()).isEqualTo("/purpose");
            assertThat(json.readTree(change.beforeJson()).stringValue()).isEqualTo("\u1100\u1161\r\n");
            assertThat(json.readTree(change.afterJson()).stringValue()).isEqualTo("\uac00\n");
        });
    }

    @Test
    void projectsProvidedInvalidResultAndLimitedReviewMetadataWithoutGrantingValidation() {
        ObjectNode invalidPolicy = policy.deepCopy();
        ((ObjectNode) invalidPolicy.path("externalEgress")).put("allowed", true);
        Version target = version(invalidPolicy, "REJECTED", null);
        ValidationResult result = ValidationResult.fromIssues(List.of(new Issue("/externalEgress/allowed",
                "EGRESS_FORBIDDEN", IssueSeverity.ERROR, "External egress is not allowed")));
        ((ObjectNode) target.validation()).set("result", json.valueToTree(result));
        ((ObjectNode) target.validation()).put("privateExtra", CANARY);
        ((ObjectNode) target.review()).put("actorId", "reviewer").put("role", "AI_SECURITY_REVIEWER")
                .put("comment", "검토 의견\r\n수정 필요").put("decision", "REJECTED").put("sessionId", CANARY);
        when(persistence.find(target.id(), reviewer)).thenReturn(target);

        var view = service.review(target.id(), reviewer);

        assertThat(view.validation()).contains(result);
        assertThat(view.review().orElseThrow().comment()).isEqualTo("검토 의견\r\n수정 필요");
        assertThat(json.writeValueAsString(view)).doesNotContain(CANARY, "sessionId", "privateExtra");
        assertThatThrownBy(() -> view.validation().orElseThrow().issues().clear()).isInstanceOf(UnsupportedOperationException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"missingResult", "invalidResult", "malformedReview", "schema"})
    void malformedDisplayInputsFailWithoutSourceOrPartialData(String problem) {
        Version target = version(policy, "CANDIDATE", null);
        switch (problem) {
            case "missingResult" -> ((ObjectNode) target.validation()).put("secret", CANARY);
            case "invalidResult" -> ((ObjectNode) target.validation()).putObject("result").put("status", CANARY);
            case "malformedReview" -> ((ObjectNode) target.review()).put("actorId", CANARY);
            case "schema" -> ((ObjectNode) target.policy()).put("unknown", CANARY);
            default -> throw new AssertionError(problem);
        }
        when(persistence.find(target.id(), reviewer)).thenReturn(target);
        assertSafeFailure(() -> service.review(target.id(), reviewer), null);
    }

    @ParameterizedTest
    @ValueSource(strings = {"inactive", "writable", "readCommitted", "unknownIsolation", "serializable"})
    void rejectsUnsafeTransactionBeforeOwnerReads(String mode) {
        switch (mode) {
            case "inactive" -> TransactionSynchronizationManager.setActualTransactionActive(false);
            case "writable" -> TransactionSynchronizationManager.setCurrentTransactionReadOnly(false);
            case "readCommitted" -> TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(Connection.TRANSACTION_READ_COMMITTED);
            case "unknownIsolation" -> TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(null);
            case "serializable" -> TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(Connection.TRANSACTION_SERIALIZABLE);
            default -> throw new AssertionError(mode);
        }
        assertSafeFailure(() -> service.review(UUID.randomUUID(), reviewer), FailureCode.UNSAFE_TRANSACTION);
        verifyNoInteractions(persistence);
    }

    @Test
    void nullRequestIsRejectedBeforeOwnerReads() {
        assertSafeFailure(() -> service.review(null, reviewer), FailureCode.INVALID_REQUEST);
        verifyNoInteractions(persistence);
    }

    @ParameterizedTest
    @ValueSource(strings = {"find", "list", "diff", "canonicalizer", "parser"})
    void dependencyExceptionsAreReplacedWithFixedSafeFailure(String dependency) {
        Version base = version(policy, "APPROVED", null);
        Version target = version(policy.deepCopy().put("version", 2), "CANDIDATE", base.policyHash());
        var sourceException = new IllegalStateException(CANARY, new RuntimeException(CANARY));
        sourceException.addSuppressed(new RuntimeException(CANARY));
        when(persistence.find(target.id(), reviewer)).thenReturn(target);
        when(persistence.list(RELEASE, reviewer)).thenReturn(List.of(base, target));
        switch (dependency) {
            case "find" -> when(persistence.find(target.id(), reviewer)).thenThrow(sourceException);
            case "list" -> when(persistence.list(RELEASE, reviewer)).thenThrow(sourceException);
            case "diff" -> {
                var broken = mock(SafetyContractReviewDiff.class);
                when(broken.compare(any(), any())).thenThrow(sourceException);
                service = new StoredSafetyContractReviewService(persistence, broken, canonicalizer, json);
            }
            case "canonicalizer" -> {
                var broken = mock(SafetyContractCanonicalizer.class);
                when(broken.canonicalizeAndHash(any())).thenThrow(sourceException);
                service = new StoredSafetyContractReviewService(persistence, diff, broken, json);
            }
            case "parser" -> {
                ((ObjectNode) target.validation()).putObject("result").put("status", CANARY);
            }
            default -> throw new AssertionError(dependency);
        }
        assertSafeFailure(() -> service.review(target.id(), reviewer), FailureCode.REVIEW_UNAVAILABLE);
    }

    @Test
    void preservesOwnerAuthorizationNotFoundAndIntegrityErrors() {
        UUID id = UUID.randomUUID();
        for (ErrorCode code : List.of(ErrorCode.OPERATOR_AUTH_REQUIRED, ErrorCode.RESOURCE_NOT_FOUND, ErrorCode.EVIDENCE_INCOMPLETE)) {
            var failure = new BusinessException(code, "Safe owner failure");
            doThrow(failure).when(persistence).find(id, reviewer);
            assertThatThrownBy(() -> service.review(id, reviewer)).isSameAs(failure);
        }
    }

    private Version version(ObjectNode body, String state, String baseHash) {
        return new Version(UUID.randomUUID(), WORKSPACE, RELEASE, body.path("contractId").stringValue(),
                body.path("version").intValue(), state, body.deepCopy(), canonicalizer.canonicalizeAndHash(body).policyHash(),
                RESOURCE, baseHash, json.createObjectNode(), json.createObjectNode());
    }

    private Version copy(UUID id, UUID workspace, UUID release, String key, int number,
            String state, JsonNode body, String policyHash, String resourceHash, String baseHash,
            JsonNode validation, JsonNode review) {
        return new Version(id, workspace, release, key, number, state, body, policyHash, resourceHash, baseHash, validation, review);
    }

    private void assertSafeFailure(Runnable action, FailureCode expected) {
        assertThatThrownBy(action::run).isInstanceOf(ReviewException.class).satisfies(error -> {
            if (expected != null) assertThat(((ReviewException) error).code()).isEqualTo(expected);
            assertThat(error.getMessage()).doesNotContain(CANARY);
            assertThat(error.getCause()).isNull();
            assertThat(error.getSuppressed()).isEmpty();
            var rendered = new java.io.StringWriter();
            error.printStackTrace(new java.io.PrintWriter(rendered));
            assertThat(rendered.toString()).doesNotContain(CANARY);
        });
    }
}
