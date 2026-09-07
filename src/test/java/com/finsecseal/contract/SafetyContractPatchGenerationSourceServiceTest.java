package com.finsecseal.contract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ReleaseLifecycleState;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.SourceBoundCatalog;
import com.finsecseal.contract.SafetyContractGenerationSourceService.GenerationSourceException;
import com.finsecseal.contract.SafetyContractGenerationSourceService.PreparedGenerationSource;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.SourceBinding;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ValidationProof;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionIdentity;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.VersionState;
import com.finsecseal.contract.SafetyContractPatchGenerationSourceService.FailureCode;
import com.finsecseal.contract.SafetyContractPatchGenerationSourceService.PatchGenerationSourceException;
import com.finsecseal.contract.SafetyContractPatchGenerationSourceService.PreparedPatchGenerationSource;
import com.finsecseal.contract.SafetyContractPatchProposalFacts.FindingSourceFacts;
import com.finsecseal.contract.SafetyContractSemanticValidator.ContractValidationCatalog;
import com.finsecseal.contract.SafetyContractSemanticValidator.EnabledTool;
import com.finsecseal.contract.SafetyContractSemanticValidator.Issue;
import com.finsecseal.contract.SafetyContractSemanticValidator.IssueSeverity;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationResult;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationStatus;
import com.finsecseal.platform.contract.ContractPersistenceService;
import com.finsecseal.platform.contract.ContractPersistenceService.Version;
import com.finsecseal.platform.contract.PatchSourceService;
import com.finsecseal.platform.contract.PatchSourceService.PatchSource;
import com.finsecseal.release.AgentReleaseEntity;
import com.finsecseal.release.ReleaseService;
import java.math.BigInteger;
import java.sql.Connection;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.MissingNode;
import tools.jackson.databind.node.ObjectNode;

class SafetyContractPatchGenerationSourceServiceTest {
    private static final UUID WORKSPACE = UUID.fromString("0198f200-0000-7000-8000-000000000401");
    private static final UUID RELEASE = UUID.fromString("0198f200-0000-7000-8000-000000000402");
    private static final UUID FINDING = UUID.fromString("0198f200-0000-7000-8000-000000000403");
    private static final UUID BASE = UUID.fromString("0198f200-0000-7000-8000-000000000404");
    private static final UUID RUN = UUID.fromString("0198f200-0000-7000-8000-000000000405");
    private static final UUID CASE = UUID.fromString("0198f200-0000-7000-8000-000000000406");
    private static final UUID ORACLE = UUID.fromString("0198f200-0000-7000-8000-000000000407");
    private static final UUID OTHER = UUID.fromString("0198f200-0000-7000-8000-000000000499");
    private static final String ACTOR = "c-patch-source";
    private static final String CANARY = "PATCH-SOURCE-PRIVATE-CANARY";
    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final String RESOURCE = "sha256:" + "b".repeat(64);
    private static final String BASE_HASH = "sha256:" + "c".repeat(64);
    private static final String ARTIFACT = "sha256:" + "d".repeat(64);
    private static final String FINGERPRINT = "sha256:" + "e".repeat(64);
    private static final ReviewerContext REVIEWER = new ReviewerContext(
            WORKSPACE, ACTOR, "AI_SECURITY_REVIEWER", "private-patch-session", true, true, false);

    private ObjectMapper json;
    private PatchSourceService patchSources;
    private ContractPersistenceService contracts;
    private SafetyContractGenerationSourceService generationSources;
    private SafetyContractPatchGenerationSourceService service;
    private ObjectNode policy;
    private PatchSource source;
    private Version base;
    private PreparedGenerationSource generation;

    @BeforeEach
    void setup() throws Exception {
        json = new ObjectMapper();
        patchSources = mock(PatchSourceService.class);
        contracts = mock(ContractPersistenceService.class);
        generationSources = mock(SafetyContractGenerationSourceService.class);
        service = new SafetyContractPatchGenerationSourceService(patchSources, contracts, generationSources, json);
        try (var input = getClass().getResourceAsStream("/fixtures/loan-review-safety-contract.json")) {
            policy = ((ObjectNode) json.readTree(input)).put("version", 3);
        }
        source = new PatchSource(new FindingSourceFacts(FINDING, WORKSPACE, RELEASE, "OPEN", "SEED", false,
                HASH, "INV-01"), RUN, CASE, ORACLE, json.createObjectNode());
        // Mock owner results represent already authorized/verified data, not evidence of those guarantees.
        base = version("CANDIDATE", null, json.createObjectNode());
        generation = generation(RELEASE);
        when(patchSources.find(FINDING, REVIEWER)).thenReturn(source);
        when(contracts.find(BASE, REVIEWER)).thenReturn(base);
        when(generationSources.prepare(RELEASE, LoanReviewFinancialTemplate.KEY, ACTOR)).thenReturn(generation);
        // Application guard fixture only; physical isolation belongs to the separate PostgreSQL tests.
        TransactionSynchronizationManager.setActualTransactionActive(true);
        TransactionSynchronizationManager.setCurrentTransactionReadOnly(false);
        TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(Connection.TRANSACTION_REPEATABLE_READ);
    }

    @AfterEach
    void clearTransactionMetadata() {
        TransactionSynchronizationManager.clear();
    }

    @Test
    void composesExactOwnerSourcesOnceWithoutListingCurrentApprovalOrWriting() {
        PreparedPatchGenerationSource result = prepare();

        assertThat(result.finding()).isEqualTo(source.facts());
        assertThat(result.sourceRunId()).isEqualTo(RUN);
        assertThat(result.sourceCaseId()).isEqualTo(CASE);
        assertThat(result.oracleResultId()).isEqualTo(ORACLE);
        assertThat(result.evidence().isObject()).isTrue();
        assertThat(result.evidence().isEmpty()).isTrue();
        assertThat(result.base().identity()).isEqualTo(identity(base));
        assertThat(result.base().policy().toString()).isEqualTo(base.policy().toString());
        assertThat(result.base().policyHash()).isEqualTo(HASH);
        assertThat(result.base().resourceHash()).isEqualTo(RESOURCE);
        assertThat(result.base().basePolicyHash()).isEmpty();
        assertThat(result.base().validationProof()).isEmpty();
        assertThat(result.generation()).isSameAs(generation);
        assertThat(result.toString()).doesNotContain(REVIEWER.sessionId(), "contractId", "INV-01");

        var order = inOrder(patchSources, contracts, generationSources);
        order.verify(patchSources).find(FINDING, REVIEWER);
        order.verify(contracts).find(BASE, REVIEWER);
        order.verify(generationSources).prepare(RELEASE, LoanReviewFinancialTemplate.KEY, ACTOR);
        verifyNoMoreInteractions(patchSources, contracts, generationSources);
    }

    @ParameterizedTest
    @EnumSource(VersionState.class)
    void preservesEveryStoredStateWithoutAnApprovedOrCurrentOnlyRule(VersionState state) {
        base = version(state.name(), BASE_HASH, json.createObjectNode());
        when(contracts.find(BASE, REVIEWER)).thenReturn(base);

        var result = prepare();

        assertThat(result.base().state()).isEqualTo(state);
        assertThat(result.base().basePolicyHash()).contains(BASE_HASH);
        assertThat(result.base().resourceHash()).isEqualTo(RESOURCE);
        assertThat(result.base().validationProof()).isEmpty();
        verify(contracts).find(BASE, REVIEWER);
        verifyNoMoreInteractions(contracts);
    }

    @ParameterizedTest
    @ValueSource(strings = {"loan-review-default", "loan-e\u0301\r\nreview", "한글 계약 / ~ : key"})
    void preservesGeneralStringContractIdentityExactly(String key) {
        policy.put("contractId", key);
        base = version("CANDIDATE", null, json.createObjectNode());
        when(contracts.find(BASE, REVIEWER)).thenReturn(base);

        var result = prepare();

        assertThat(result.base().identity().contractKey()).isEqualTo(key);
        assertThat(result.base().policy().path("contractId").stringValue()).isEqualTo(key);
        assertThat(result.base().policy().path("version").bigIntegerValue()).isEqualTo(BigInteger.valueOf(3));
    }

    @ParameterizedTest
    @ValueSource(strings = {"VALIDATED", "CANDIDATE"})
    void preservesStoredTypedProofWithoutRevalidatingOrPromotingItsState(String state) {
        ValidationProof proof = proof(state.equals("VALIDATED") ? ValidationStatus.WARN : ValidationStatus.INVALID);
        base = version(state, BASE_HASH, json.valueToTree(proof));
        when(contracts.find(BASE, REVIEWER)).thenReturn(base);

        var snapshot = prepare().base();

        assertThat(snapshot.validationProof()).contains(proof);
        assertThat(snapshot.state()).isEqualTo(VersionState.valueOf(state));
        assertThat(snapshot.policyHash()).isEqualTo(HASH);
        assertThat(snapshot.resourceHash()).isEqualTo(RESOURCE);
        assertThat(snapshot.basePolicyHash()).contains(BASE_HASH);
        assertThatThrownBy(() -> snapshot.validationProof().orElseThrow().result().issues().clear())
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void copiesEachMutableOwnerValueBeforeTheNextRead() {
        ((ObjectNode) source.evidence()).put("message", CANARY);
        ValidationProof proof = proof(ValidationStatus.WARN);
        base = version("VALIDATED", BASE_HASH, json.valueToTree(proof));
        String expectedPolicy = base.policy().toString();
        String expectedEvidence = source.evidence().toString();
        when(contracts.find(BASE, REVIEWER)).thenAnswer(invocation -> {
            ((ObjectNode) source.evidence()).put("message", "later owner mutation");
            return base;
        });
        when(generationSources.prepare(RELEASE, LoanReviewFinancialTemplate.KEY, ACTOR)).thenAnswer(invocation -> {
            ((ObjectNode) base.policy()).put("contractId", CANARY);
            ((ObjectNode) base.validation()).removeAll();
            return generation;
        });

        var result = prepare();

        assertThat(result.evidence().toString()).isEqualTo(expectedEvidence);
        assertThat(result.base().policy().toString()).isEqualTo(expectedPolicy);
        assertThat(result.base().validationProof()).contains(proof);
        assertThat(result.toString()).doesNotContain(CANARY, REVIEWER.sessionId());
    }

    @Test
    void returnedJsonCannotChangeCapturedOrSubsequentlyPreparedData() {
        var result = prepare();
        String expectedPolicy = result.base().policy().toString();
        String expectedManifest = result.generation().manifestContext().toString();
        String expectedTemplate = result.generation().templateRules().toString();

        ((ObjectNode) result.evidence()).put("message", CANARY);
        ((ObjectNode) result.base().policy()).put("contractId", CANARY);
        ((ObjectNode) result.generation().manifestContext()).removeAll();
        ((ObjectNode) result.generation().templateRules()).removeAll();

        for (var checked : List.of(result, prepare())) {
            assertThat(checked.evidence().isEmpty()).isTrue();
            assertThat(checked.base().policy().toString()).isEqualTo(expectedPolicy);
            assertThat(checked.generation().manifestContext().toString()).isEqualTo(expectedManifest);
            assertThat(checked.generation().templateRules().toString()).isEqualTo(expectedTemplate);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"finding", "base", "reviewer"})
    void nullRequestsFailBeforeAnyOwnerCall(String missing) {
        assertSafeFailure(() -> service.prepare(missing.equals("finding") ? null : FINDING,
                missing.equals("base") ? null : BASE, missing.equals("reviewer") ? null : REVIEWER),
                FailureCode.INVALID_REQUEST);
        verifyNoInteractions(patchSources, contracts, generationSources);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("unsafeTransactions")
    void unsafeTransactionFailsBeforeAnyOwnerCall(String description, boolean active,
            boolean readOnly, Integer isolation) {
        TransactionSynchronizationManager.setActualTransactionActive(active);
        TransactionSynchronizationManager.setCurrentTransactionReadOnly(readOnly);
        TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(isolation);

        assertSafeFailure(this::prepare, FailureCode.UNSAFE_TRANSACTION);
        verifyNoInteractions(patchSources, contracts, generationSources);
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "facts", "finding", "workspace", "nullWorkspace", "release",
            "run", "case", "oracle", "nullEvidence", "jsonNullEvidence", "missingEvidence"})
    void invalidSourceProjectionStopsBeforeBaseAndManifestReads(String problem) {
        FindingSourceFacts facts = source.facts();
        UUID run = RUN;
        UUID caseId = CASE;
        UUID oracle = ORACLE;
        JsonNode evidence = source.evidence();
        switch (problem) {
            case "null" -> { }
            case "facts" -> facts = null;
            case "finding", "workspace", "nullWorkspace", "release" -> facts = new FindingSourceFacts(
                    problem.equals("finding") ? OTHER : FINDING,
                    problem.equals("workspace") ? OTHER : problem.equals("nullWorkspace") ? null : WORKSPACE,
                    problem.equals("release") ? null : RELEASE, "OPEN", "SEED", false, HASH, "INV-01");
            case "run" -> run = null;
            case "case" -> caseId = null;
            case "oracle" -> oracle = null;
            case "nullEvidence" -> evidence = null;
            case "jsonNullEvidence" -> evidence = json.nullNode();
            case "missingEvidence" -> evidence = MissingNode.getInstance();
            default -> throw new AssertionError(problem);
        }
        PatchSource invalid = problem.equals("null") ? null : new PatchSource(facts, run, caseId, oracle, evidence);
        when(patchSources.find(FINDING, REVIEWER)).thenReturn(invalid);

        assertSafeFailure(this::prepare, FailureCode.SOURCE_BINDING_INVALID);
        verify(patchSources).find(FINDING, REVIEWER);
        verifyNoMoreInteractions(patchSources);
        verifyNoInteractions(contracts, generationSources);
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "id", "workspace", "release", "nullKey", "blankKey", "differentKey",
            "normalizedKey", "versionZero", "versionMismatch", "versionString", "versionDecimal", "versionHuge",
            "nullPolicy", "arrayPolicy", "nullState", "unknownState", "policyHash", "resourceHash", "baseHash",
            "nullValidation", "arrayValidation"})
    void invalidStoredProjectionStopsBeforeManifestRead(String problem) {
        UUID id = BASE;
        UUID workspace = WORKSPACE;
        UUID release = RELEASE;
        String key = base.contractKey();
        int number = base.version();
        String state = base.state();
        JsonNode body = base.policy().deepCopy();
        String policyHash = HASH;
        String resourceHash = RESOURCE;
        String baseHash = null;
        JsonNode validation = json.createObjectNode();
        switch (problem) {
            case "null" -> { }
            case "id" -> id = OTHER;
            case "workspace" -> workspace = OTHER;
            case "release" -> release = OTHER;
            case "nullKey" -> key = null;
            case "blankKey" -> key = " ";
            case "differentKey" -> key = CANARY;
            case "normalizedKey" -> { key = "loan-e\u0301"; ((ObjectNode) body).put("contractId", "loan-é"); }
            case "versionZero" -> number = 0;
            case "versionMismatch" -> ((ObjectNode) body).put("version", 4);
            case "versionString" -> ((ObjectNode) body).put("version", "3");
            case "versionDecimal" -> ((ObjectNode) body).put("version", 3.0);
            case "versionHuge" -> ((ObjectNode) body).put("version", new BigInteger("4294967299"));
            case "nullPolicy" -> body = null;
            case "arrayPolicy" -> body = json.createArrayNode();
            case "nullState" -> state = null;
            case "unknownState" -> state = CANARY;
            case "policyHash" -> policyHash = CANARY;
            case "resourceHash" -> resourceHash = null;
            case "baseHash" -> baseHash = CANARY;
            case "nullValidation" -> validation = null;
            case "arrayValidation" -> validation = json.createArrayNode();
            default -> throw new AssertionError(problem);
        }
        Version invalid = problem.equals("null") ? null : new Version(id, workspace, release, key, number,
                state, body, policyHash, resourceHash, baseHash, validation, json.createObjectNode());
        when(contracts.find(BASE, REVIEWER)).thenReturn(invalid);

        assertSafeFailure(this::prepare, FailureCode.BASE_VERSION_INVALID);
        verify(contracts).find(BASE, REVIEWER);
        verifyNoMoreInteractions(contracts);
        verifyNoInteractions(generationSources);
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "release"})
    void missingOrMismatchedGenerationSourceCannotProduceAResult(String problem) throws Exception {
        PreparedGenerationSource prepared = problem.equals("null") ? null : generation(OTHER);
        when(generationSources.prepare(RELEASE, LoanReviewFinancialTemplate.KEY, ACTOR))
                .thenReturn(prepared);

        assertSafeFailure(this::prepare, FailureCode.SOURCE_BINDING_INVALID);
        verify(generationSources).prepare(RELEASE, LoanReviewFinancialTemplate.KEY, ACTOR);
        verifyNoMoreInteractions(generationSources);
    }

    @ParameterizedTest
    @ValueSource(strings = {"source", "base"})
    void preservesSafeOwnerErrorsAndStopsSubsequentReads(String owner) {
        var failure = new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE, "Safe owner integrity failure");
        if (owner.equals("source")) when(patchSources.find(FINDING, REVIEWER)).thenThrow(failure);
        else when(contracts.find(BASE, REVIEWER)).thenThrow(failure);

        assertThatThrownBy(this::prepare).isSameAs(failure);
        verifyNoInteractions(generationSources);
        if (owner.equals("source")) verifyNoInteractions(contracts);
    }

    @Test
    void letsTheOwnerAuthorizeNonNullReviewerRatherThanAcceptingAnActorString() {
        var untrusted = new ReviewerContext(WORKSPACE, ACTOR, "VIEWER", REVIEWER.sessionId(), false, false, false);
        var failure = new BusinessException(ErrorCode.OPERATOR_AUTH_REQUIRED, "Trusted reviewer required");
        when(patchSources.find(FINDING, untrusted)).thenThrow(failure);

        assertThatThrownBy(() -> service.prepare(FINDING, BASE, untrusted)).isSameAs(failure);
        verify(patchSources).find(FINDING, untrusted);
        verifyNoInteractions(contracts, generationSources);
    }

    @Test
    void unavailableOwnerSourceDoesNotTriggerAHiddenSourceProbeOrFallback() {
        var failure = new BusinessException(ErrorCode.RESOURCE_NOT_FOUND, "Eligible patch source not found");
        when(patchSources.find(FINDING, REVIEWER)).thenThrow(failure);

        assertThatThrownBy(this::prepare).isSameAs(failure);
        verify(patchSources).find(FINDING, REVIEWER);
        verifyNoMoreInteractions(patchSources);
        verifyNoInteractions(contracts, generationSources);
    }

    @Test
    void preservesExistingGenerationSourceFailure() {
        var realGeneration = new SafetyContractGenerationSourceService(mock(ReleaseToolCatalogContractAdapter.class),
                mock(ReleaseService.class), new LoanReviewFinancialTemplate(json), json);
        GenerationSourceException failure = catchThrowableOfType(
                GenerationSourceException.class, () -> realGeneration.prepare(RELEASE, "unsupported-template", ACTOR));
        when(generationSources.prepare(RELEASE, LoanReviewFinancialTemplate.KEY, ACTOR)).thenThrow(failure);

        assertThatThrownBy(this::prepare).isSameAs(failure);
        verify(generationSources).prepare(RELEASE, LoanReviewFinancialTemplate.KEY, ACTOR);
        verifyNoMoreInteractions(generationSources);
    }

    @ParameterizedTest
    @ValueSource(strings = {"source", "base", "generation", "proofMapper"})
    void unexpectedDependencyFailuresLoseRawCauseAndNeverReturnPartialInputs(String dependency) {
        var failure = new IllegalStateException(CANARY, new RuntimeException(REVIEWER.sessionId()));
        failure.addSuppressed(new RuntimeException(CANARY));
        switch (dependency) {
            case "source" -> when(patchSources.find(FINDING, REVIEWER)).thenThrow(failure);
            case "base" -> when(contracts.find(BASE, REVIEWER)).thenThrow(failure);
            case "generation" -> when(generationSources.prepare(RELEASE, LoanReviewFinancialTemplate.KEY, ACTOR))
                    .thenThrow(failure);
            case "proofMapper" -> {
                base = version("VALIDATED", BASE_HASH, json.valueToTree(proof(ValidationStatus.WARN)));
                when(contracts.find(BASE, REVIEWER)).thenReturn(base);
                ObjectMapper broken = mock(ObjectMapper.class);
                when(broken.treeToValue(any(JsonNode.class), eq(ValidationProof.class))).thenThrow(failure);
                service = new SafetyContractPatchGenerationSourceService(patchSources, contracts, generationSources, broken);
            }
            default -> throw new AssertionError(dependency);
        }

        assertSafeFailure(this::prepare, FailureCode.SOURCE_UNAVAILABLE);
        if (dependency.equals("source")) verifyNoInteractions(contracts);
        if (!dependency.equals("generation")) verifyNoInteractions(generationSources);
    }

    @Test
    void unreadableTypedProofFailsWithoutLeakingStoredContent() {
        ObjectNode validation = json.valueToTree(proof(ValidationStatus.WARN));
        ((ObjectNode) validation.path("result")).put("status", CANARY);
        base = version("VALIDATED", BASE_HASH, validation);
        when(contracts.find(BASE, REVIEWER)).thenReturn(base);

        assertSafeFailure(this::prepare, FailureCode.SOURCE_UNAVAILABLE);
        verifyNoInteractions(generationSources);
    }

    private PreparedPatchGenerationSource prepare() {
        return service.prepare(FINDING, BASE, REVIEWER);
    }

    private Version version(String state, String baseHash, JsonNode validation) {
        return new Version(BASE, WORKSPACE, RELEASE, policy.path("contractId").stringValue(), 3,
                state, policy.deepCopy(), HASH, RESOURCE, baseHash, validation, json.createObjectNode());
    }

    private VersionIdentity identity(Version version) {
        return new VersionIdentity(version.id(), version.workspaceId(), version.releaseId(),
                version.contractKey(), version.version());
    }

    private ValidationProof proof(ValidationStatus status) {
        var issue = new Issue("/allowedTools", "RECORDED_ISSUE",
                status == ValidationStatus.INVALID ? IssueSeverity.ERROR : IssueSeverity.WARNING, "Recorded validation");
        return new ValidationProof(identity(base), HASH, Optional.of(BASE_HASH), RESOURCE, "1.0",
                new SourceBinding(RELEASE, "1.1", ARTIFACT, FINGERPRINT, HASH),
                new ValidationResult(status, List.of(issue)), BASE_HASH);
    }

    private PreparedGenerationSource generation(UUID releaseId) throws Exception {
        ObjectNode manifest;
        try (var input = getClass().getResourceAsStream("/fixtures/valid-release-manifest-v1.1.json")) {
            manifest = (ObjectNode) json.readTree(input);
        }
        // Exercise the existing immutable C source value; A reads remain explicit unit-test doubles.
        var catalogs = mock(ReleaseToolCatalogContractAdapter.class);
        var releases = mock(ReleaseService.class);
        var entity = mock(AgentReleaseEntity.class);
        var catalog = new SourceBoundCatalog(releaseId, "1.1", ARTIFACT, FINGERPRINT, HASH,
                new ContractValidationCatalog(List.of(new EnabledTool("CUSTOMER_DATA_READ",
                        List.of("incomeBand", "employmentStatus"))), List.of("LOAN_DECISION_UPDATE")));
        when(catalogs.load(releaseId, ACTOR)).thenReturn(catalog);
        when(releases.getRequired(releaseId)).thenReturn(entity);
        when(entity.getId()).thenReturn(releaseId);
        when(entity.getManifestSchemaVersion()).thenReturn("1.1");
        when(entity.getAgentArtifactFingerprint()).thenReturn(ARTIFACT);
        when(entity.getReleaseFingerprint()).thenReturn(FINGERPRINT);
        when(entity.getBusinessPurpose()).thenReturn(LoanReviewFinancialTemplate.PURPOSE);
        when(entity.getAnalyzedAt()).thenReturn(Instant.parse("2026-09-07T00:00:00Z"));
        when(entity.getLifecycleState()).thenReturn(ReleaseLifecycleState.ANALYZED);
        when(entity.getManifestJson()).thenReturn(manifest);
        return new SafetyContractGenerationSourceService(catalogs, releases, new LoanReviewFinancialTemplate(json), json)
                .prepare(releaseId, LoanReviewFinancialTemplate.KEY, ACTOR);
    }

    private void assertSafeFailure(Runnable action, FailureCode expected) {
        assertThatThrownBy(action::run).isInstanceOfSatisfying(PatchGenerationSourceException.class, error -> {
            assertThat(error.code()).isEqualTo(expected);
            assertThat(error.getCause()).isNull();
            assertThat(error.getSuppressed()).isEmpty();
            var stack = new java.io.StringWriter();
            error.printStackTrace(new java.io.PrintWriter(stack));
            assertThat(error.getMessage()).doesNotContain(CANARY, REVIEWER.sessionId());
            assertThat(stack.toString()).doesNotContain(CANARY, REVIEWER.sessionId());
        });
    }

    private static Stream<Arguments> unsafeTransactions() {
        return Stream.of(
                Arguments.of("no actual transaction", false, false, Connection.TRANSACTION_REPEATABLE_READ),
                Arguments.of("read-only RR", true, true, Connection.TRANSACTION_REPEATABLE_READ),
                Arguments.of("writable READ_COMMITTED", true, false, Connection.TRANSACTION_READ_COMMITTED),
                Arguments.of("unknown outer isolation", true, false, null));
    }
}
