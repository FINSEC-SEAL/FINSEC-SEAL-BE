package com.finsecseal.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.SourceBoundCatalog;
import com.finsecseal.contract.SafetyContractCanonicalizer;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.contract.SafetyContractSchemaValidator;
import com.finsecseal.contract.SafetyContractSemanticValidator;
import com.finsecseal.contract.SafetyContractSemanticValidator.ContractValidationCatalog;
import com.finsecseal.contract.SafetyContractSemanticValidator.EnabledTool;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationStatus;
import com.finsecseal.contract.SafetyContractSemanticValidator.ValidationResult;
import com.finsecseal.contract.SafetyContractSemanticValidator.Issue;
import com.finsecseal.contract.SafetyContractSemanticValidator.IssueSeverity;
import com.finsecseal.policy.GatewayApprovedPolicySourceService.ApprovedPolicySource;
import com.finsecseal.evidence.TestRunDto.Projection;
import com.finsecseal.evidence.TestRunPersistenceDto.CaseRun;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.evidence.TestRunProjectionService;
import com.finsecseal.platform.contract.ContractPersistenceService;
import com.finsecseal.platform.contract.ContractPersistenceService.ApprovedContract;
import com.finsecseal.platform.contract.ContractPersistenceService.Version;
import com.finsecseal.policy.GatewayApprovedPolicySourceService.FailureCode;
import com.finsecseal.policy.GatewayApprovedPolicySourceService.PolicySourceException;
import com.finsecseal.policy.PolicyToolTrustFacts.ReleaseToolBinding;
import com.finsecseal.policy.PolicyToolTrustFacts.TrustLevel;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import java.math.BigInteger;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

@ExtendWith(OutputCaptureExtension.class)
class GatewayApprovedPolicySourceServiceTest {
    private static final UUID WORKSPACE = UUID.randomUUID();
    private static final UUID RELEASE = UUID.randomUUID();
    private static final UUID RUN = UUID.randomUUID();
    private static final UUID CASE_RUN = UUID.randomUUID();
    private static final UUID TEST_CASE = UUID.randomUUID();
    private static final UUID VERSION = UUID.randomUUID();
    private static final UUID OTHER = UUID.randomUUID();
    private static final String ARTIFACT = "sha256:" + "a".repeat(64);
    private static final String FINGERPRINT = "sha256:" + "b".repeat(64);
    private static final String HASH = "sha256:" + "c".repeat(64);
    private static final String CANARY = "PRIVATE-SOURCE-SQL-SESSION-CANARY";
    private static final ReviewerContext REVIEWER = new ReviewerContext(
            WORKSPACE, "gateway-source-test", "AI_SECURITY_REVIEWER", CANARY, true, true, false);
    private final ObjectMapper json = new ObjectMapper();
    private TestRunProjectionService runs;
    private ContractPersistenceService contracts;
    private TestRunPersistenceService cases;
    private ReleaseToolCatalogContractAdapter catalogs;
    private SafetyContractSemanticValidator validator;
    private SafetyContractCanonicalizer canonicalizer;
    private GatewayApprovedPolicySourceService service;
    private Projection run;
    private CaseRun caseRun;
    private Version version;
    private SourceBoundCatalog catalog;

    @BeforeEach
    void setup() throws Exception {
        runs = mock(TestRunProjectionService.class);
        contracts = mock(ContractPersistenceService.class);
        cases = mock(TestRunPersistenceService.class);
        catalogs = mock(ReleaseToolCatalogContractAdapter.class);
        var schema = new SafetyContractSchemaValidator();
        validator = spy(new SafetyContractSemanticValidator(schema));
        canonicalizer = spy(new SafetyContractCanonicalizer(schema, new CanonicalJsonService(json), new DigestService()));
        service = new GatewayApprovedPolicySourceService(runs, contracts, cases, catalogs, validator, canonicalizer);
        ObjectNode policy;
        try (var input = getClass().getResourceAsStream("/fixtures/loan-review-safety-contract.json")) {
            policy = (ObjectNode) json.readTree(input);
        }
        version = new Version(VERSION, WORKSPACE, RELEASE, policy.path("contractId").stringValue(), 1,
                "APPROVED", policy, canonicalizer.canonicalizeAndHash(policy).policyHash(), HASH, null,
                json.createObjectNode().put("historicalReleaseFingerprint", HASH),
                json.createObjectNode().put("decision", "APPROVED").put("private", CANARY));
        run = new Projection(RUN, RELEASE, OTHER, VERSION, TestRunMode.SEAL_REPLAY, TestRunStatus.RUNNING,
                ARTIFACT, FINGERPRINT, "fixture/1", HASH, 1, 0, 0, 0, null, null,
                json.createObjectNode().put("private", CANARY), null, null, null);
        caseRun = new CaseRun(CASE_RUN, RUN, TEST_CASE, 0, TestCaseRunStatus.EXECUTING,
                null, null, HASH, null, null, null, json.createObjectNode().put("private", CANARY));
        catalog = new SourceBoundCatalog(RELEASE, "1.1", ARTIFACT, FINGERPRINT, HASH,
                new ContractValidationCatalog(List.of(
                        new EnabledTool("CASE_CONTEXT_READ", List.of()),
                        new EnabledTool("DOCUMENT_READER", List.of()),
                        new EnabledTool("CUSTOMER_DATA_READ", List.of("incomeBand", "employmentStatus")),
                        new EnabledTool("LOAN_POLICY_SEARCH", List.of()),
                        new EnabledTool("REVIEW_NOTE_WRITE", List.of())), List.of("LOAN_DECISION_UPDATE")),
                fixtureBindings());
        when(runs.find(RUN)).thenReturn(run);
        approved(version);
        when(cases.findCase(CASE_RUN)).thenReturn(caseRun);
        when(catalogs.load(RELEASE, REVIEWER.actorId())).thenReturn(catalog);
        // Thread-local guard fixture only; separate PostgreSQL tests prove physical transaction behavior.
        TransactionSynchronizationManager.setActualTransactionActive(true);
        TransactionSynchronizationManager.setCurrentTransactionReadOnly(false);
        TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(Connection.TRANSACTION_REPEATABLE_READ);
    }

    @AfterEach
    void cleanup() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) finishSynchronization(false);
        TransactionSynchronizationManager.clear();
    }

    @ParameterizedTest
    @EnumSource(value = TestRunMode.class, names = {"SEAL_REPLAY", "HELD_OUT", "REGRESSION"})
    void bindsExactApprovedSourcesWithoutInventingExecutionAuthority(TestRunMode mode) {
        when(runs.find(RUN)).thenReturn(change(run, Projection.class, "mode", mode));
        var result = service.load(RUN, CASE_RUN, REVIEWER);
        assertThat(result.runId()).isEqualTo(RUN);
        assertThat(result.testCaseRunId()).isEqualTo(CASE_RUN);
        assertThat(result.testCaseId()).isEqualTo(TEST_CASE);
        assertThat(result.runMode()).isEqualTo(mode);
        assertThat(result.runStatus()).isEqualTo(TestRunStatus.RUNNING);
        assertThat(result.caseStatus()).isEqualTo(TestCaseRunStatus.EXECUTING);
        assertThat(result.trialIndex()).isZero();
        assertThat(result.variantHash()).isEqualTo(HASH);
        assertThat(result.identity().versionId()).isEqualTo(VERSION);
        assertThat(result.identity().releaseId()).isEqualTo(RELEASE);
        assertThat(result.identity().workspaceId()).isEqualTo(WORKSPACE);
        assertThat(result.identity().contractKey()).isEqualTo(version.contractKey());
        assertThat(result.identity().version()).isEqualTo(1);
        assertThat(result.policyHash()).isEqualTo(version.policyHash());
        assertThat(result.resourceHash()).isEqualTo(HASH);
        assertThat(result.catalog()).isEqualTo(catalog);
        assertThat(result.releaseToolBindings()).containsExactlyElementsOf(fixtureBindings());
        assertThat(result.releaseToolBindings()).extracting(ReleaseToolBinding::toolName)
                .containsExactly("CASE_CONTEXT_READ", "CUSTOMER_DATA_READ", "DOCUMENT_READER",
                        "LOAN_POLICY_SEARCH", "REVIEW_NOTE_WRITE");
        assertThat(result.toolTrustPolicy().requireTrustedTool()).isTrue();
        assertThat(result.toolTrustPolicy().allowedTrustLevels()).containsExactly(TrustLevel.TRUSTED_INTERNAL);
        assertThat(result.validation().status()).isEqualTo(ValidationStatus.VALID);
        assertThat(result.canonicalPolicy().policyHash()).isEqualTo(result.policyHash());
        var order = inOrder(runs, contracts, cases, catalogs);
        order.verify(runs).find(RUN);
        order.verify(contracts).approved(RELEASE, VERSION, REVIEWER);
        order.verify(cases).findCase(CASE_RUN);
        order.verify(catalogs).load(RELEASE, REVIEWER.actorId());
        verifyNoMoreInteractions(runs, contracts, cases, catalogs);
    }

    @Test
    void snapshotDefensivelyCopiesPolicyAndExcludesPrivateOwnerProjections() {
        var result = service.load(RUN, CASE_RUN, REVIEWER);
        JsonNode expected = result.policy();
        List<ReleaseToolBinding> expectedBindings = List.copyOf(result.releaseToolBindings());
        ((ObjectNode) version.policy()).put("contractId", CANARY);
        ((ObjectNode) version.policy().path("toolTrust")).put("requireTrustedTool", false);
        ((ArrayNode) version.policy().at("/toolTrust/allowedTrustLevels")).add("SANDBOXED");
        ((ObjectNode) result.policy()).put("contractId", CANARY);
        ((ObjectNode) result.policy().path("customerScope")).put("type", CANARY);
        ((ObjectNode) result.policy().path("toolTrust")).put("requireTrustedTool", false);
        ((ArrayNode) result.policy().at("/toolTrust/allowedTrustLevels")).removeAll();
        assertThat(result.policy()).isEqualTo(expected);
        assertThat(canonicalizer.canonicalizeAndHash(result.policy())).isEqualTo(result.canonicalPolicy());
        assertThatThrownBy(() -> result.validation().issues().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> result.catalog().semanticCatalog().enabledReleaseTools().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(result.releaseToolBindings()).containsExactlyElementsOf(expectedBindings);
        assertThatThrownBy(() -> result.releaseToolBindings().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(result.toolTrustPolicy().requireTrustedTool()).isTrue();
        assertThat(result.toolTrustPolicy().allowedTrustLevels()).containsExactly(TrustLevel.TRUSTED_INTERNAL);
        assertThatThrownBy(() -> result.toolTrustPolicy().allowedTrustLevels().add(TrustLevel.SANDBOXED))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(result.toString()).doesNotContain(CANARY, "contractId", "private");
        assertThat(result.getClass().getDeclaredFields()).noneMatch(field ->
                List.of(Projection.class, CaseRun.class, Version.class, ReviewerContext.class).contains(field.getType()));
    }

    @Test
    void canonicalEquivalentPropertyOrderDoesNotChangeApprovalHash() {
        var entries = new ArrayList<>(version.policy().properties());
        Collections.reverse(entries);
        var reordered = json.createObjectNode();
        entries.forEach(entry -> reordered.set(entry.getKey(), entry.getValue()));
        approved(change(version, Version.class, "policy", reordered));
        assertThat(service.load(RUN, CASE_RUN, REVIEWER).policyHash()).isEqualTo(version.policyHash());
    }

    @ParameterizedTest
    @ValueSource(strings = {"runId", "caseRunId", "reviewer"})
    void missingRequestStopsBeforeOwnerReads(String field) {
        safe(() -> service.load(field.equals("runId") ? null : RUN,
                field.equals("caseRunId") ? null : CASE_RUN, field.equals("reviewer") ? null : REVIEWER),
                FailureCode.INVALID_REQUEST);
        verifyNoInteractions(runs, contracts, cases, catalogs);
    }

    @ParameterizedTest
    @ValueSource(strings = {"none", "readOnly", "readCommitted", "default", "unknown"})
    void incompatibleTransactionMetadataStopsBeforeOwnerReads(String kind) {
        switch (kind) {
            case "none" -> TransactionSynchronizationManager.setActualTransactionActive(false);
            case "readOnly" -> TransactionSynchronizationManager.setCurrentTransactionReadOnly(true);
            case "readCommitted" -> TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(Connection.TRANSACTION_READ_COMMITTED);
            case "default" -> TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(null);
            case "unknown" -> TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(-10);
            default -> throw new AssertionError(kind);
        }
        safeLoad(FailureCode.UNSAFE_TRANSACTION);
        verifyNoInteractions(runs, contracts, cases, catalogs);
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "id", "releaseId", "mode", "status", "agentArtifactFingerprint", "releaseFingerprint", "contractVersionId", "baseline"})
    void invalidRunNeverSelectsFallbackPolicy(String field) {
        Projection invalid = field.equals("null") ? null : change(run, Projection.class,
                field.equals("baseline") ? "mode" : field,
                field.equals("id") ? OTHER : field.equals("baseline") ? TestRunMode.BASELINE : null);
        when(runs.find(RUN)).thenReturn(invalid);
        safeLoad(field.equals("baseline") ? FailureCode.UNSUPPORTED_RUN_MODE
                : field.equals("contractVersionId") ? FailureCode.CONTRACT_NOT_APPROVED : FailureCode.RUN_BINDING_INVALID);
        verifyNoInteractions(contracts, cases, catalogs);
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "id", "releaseId", "workspaceId", "state", "contractKey", "version", "policy",
            "policyHash", "resourceHash", "validation", "review", "emptyValidation", "emptyReview", "policyVersionHuge", "policyVersionDecimal"})
    void invalidApprovalStopsBeforeCaseAndCatalog(String field) {
        Version invalid = version;
        if (field.equals("null")) invalid = null;
        else if (field.startsWith("policyVersion")) {
            ObjectNode policy = (ObjectNode) version.policy().deepCopy();
            if (field.equals("policyVersionHuge")) policy.put("version", new BigInteger("4294967297"));
            else policy.put("version", 1.0);
            invalid = change(version, Version.class, "policy", policy);
        } else {
            String name = field.equals("emptyValidation") ? "validation" : field.equals("emptyReview") ? "review" : field;
            Object value = switch (field) {
                case "id", "releaseId", "workspaceId" -> OTHER;
                case "state" -> "VALIDATED";
                case "contractKey" -> CANARY;
                case "version" -> 2;
                case "emptyValidation", "emptyReview" -> json.createObjectNode();
                default -> null;
            };
            invalid = change(version, Version.class, name, value);
        }
        approved(invalid);
        safeLoad(FailureCode.CONTRACT_NOT_APPROVED);
        verifyNoInteractions(cases, catalogs);
    }

    @ParameterizedTest
    @ValueSource(strings = {"artifact", "release"})
    void staleApprovalFingerprintCannotBeCombinedWithRun(String field) {
        when(contracts.approved(RELEASE, VERSION, REVIEWER)).thenReturn(new ApprovedContract(version,
                field.equals("artifact") ? HASH : ARTIFACT, field.equals("release") ? HASH : FINGERPRINT));
        safeLoad(FailureCode.POLICY_INTEGRITY_FAILURE);
        verifyNoInteractions(cases, catalogs);
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "id", "testRunId", "testCaseId", "status", "trialIndex", "variantHash"})
    void unrelatedOrMalformedCaseRunStopsBeforeCatalog(String field) {
        CaseRun invalid = field.equals("null") ? null : change(caseRun, CaseRun.class, field,
                field.equals("id") || field.equals("testRunId") ? OTHER : field.equals("trialIndex") ? -1 : null);
        when(cases.findCase(CASE_RUN)).thenReturn(invalid);
        safeLoad(FailureCode.CASE_RUN_BINDING_INVALID);
        verifyNoInteractions(catalogs);
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "release", "artifact", "fingerprint"})
    void catalogMustBindTheSameCurrentRelease(String field) {
        when(catalogs.load(RELEASE, REVIEWER.actorId())).thenReturn(field.equals("null") ? null
                : new SourceBoundCatalog(field.equals("release") ? OTHER : RELEASE, "1.1",
                field.equals("artifact") ? HASH : ARTIFACT, field.equals("fingerprint") ? HASH : FINGERPRINT,
                HASH, catalog.semanticCatalog(), catalog.releaseToolBindings()));
        safeLoad(FailureCode.CATALOG_BINDING_INVALID);
        verifyNoInteractions(validator);
    }

    @ParameterizedTest
    @ValueSource(strings = {"semanticOnly", "empty", "missing", "extra", "replacement", "duplicate",
            "sameNameDifferentVersion", "disabled", "paddedVersion"})
    void incompleteExpectedToolBindingsNeverReachPolicyValidation(String kind) {
        List<ReleaseToolBinding> bindings = new ArrayList<>(fixtureBindings());
        ReleaseToolBinding first = bindings.getFirst();
        switch (kind) {
            case "semanticOnly", "empty" -> bindings.clear();
            case "missing" -> bindings.removeFirst();
            case "extra" -> bindings.add(new ReleaseToolBinding("LOAN_DECISION_UPDATE", "1.1.0", true, HASH, ARTIFACT));
            case "replacement" -> bindings.set(0, new ReleaseToolBinding("LOAN_DECISION_UPDATE", first.version(),
                    true, first.schemaDigest(), first.descriptionDigest()));
            case "duplicate" -> bindings.add(first);
            case "sameNameDifferentVersion" -> bindings.add(new ReleaseToolBinding(first.toolName(), "2.0.0",
                    true, first.schemaDigest(), first.descriptionDigest()));
            case "disabled" -> bindings.set(0, new ReleaseToolBinding(first.toolName(), first.version(),
                    false, first.schemaDigest(), first.descriptionDigest()));
            case "paddedVersion" -> bindings.set(0, new ReleaseToolBinding(first.toolName(), " 1.1.0 ",
                    true, first.schemaDigest(), first.descriptionDigest()));
            default -> throw new AssertionError(kind);
        }
        SourceBoundCatalog invalid = kind.equals("semanticOnly")
                ? new SourceBoundCatalog(RELEASE, "1.1", ARTIFACT, FINGERPRINT, HASH, catalog.semanticCatalog())
                : catalogWithBindings(bindings);
        when(catalogs.load(RELEASE, REVIEWER.actorId())).thenReturn(invalid);
        clearInvocations(canonicalizer);

        safeLoad(FailureCode.CATALOG_BINDING_INVALID);

        verifyNoInteractions(validator, canonicalizer);
        verify(runs).find(RUN);
        verify(contracts).approved(RELEASE, VERSION, REVIEWER);
        verify(cases).findCase(CASE_RUN);
        verify(catalogs).load(RELEASE, REVIEWER.actorId());
        verifyNoMoreInteractions(runs, contracts, cases, catalogs);
    }

    @ParameterizedTest
    @ValueSource(strings = {"list", "entry"})
    void nullExpectedBindingsAreRejectedAtTheActualCatalogConstructorBoundary(String kind) {
        List<ReleaseToolBinding> bindings = new ArrayList<>(fixtureBindings());
        bindings.add(null);

        assertThatThrownBy(() -> catalogWithBindings(kind.equals("list") ? null : bindings))
                .isInstanceOf(NullPointerException.class);
        verifyNoInteractions(runs, contracts, cases, catalogs);
    }

    @ParameterizedTest
    @ValueSource(strings = {"versionNull", "versionEmpty", "versionBlank", "schemaNull", "schemaMalformed",
            "descriptionNull", "descriptionMalformed"})
    void malformedBindingValuesAreRejectedAtTheActualValueConstructorBoundary(String kind) {
        String versionValue = switch (kind) {
            case "versionNull" -> null;
            case "versionEmpty" -> "";
            case "versionBlank" -> "  ";
            default -> "1.1.0";
        };
        String schema = kind.equals("schemaNull") ? null : kind.equals("schemaMalformed") ? CANARY : HASH;
        String description = kind.equals("descriptionNull") ? null : kind.equals("descriptionMalformed") ? CANARY : ARTIFACT;

        assertThatThrownBy(() -> new ReleaseToolBinding("CUSTOMER_DATA_READ", versionValue, true, schema, description))
                .isInstanceOf(IllegalArgumentException.class);
        verifyNoInteractions(runs, contracts, cases, catalogs);
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "null", "wrongType", "missingRequired", "falseRequired", "stringRequired",
            "missingLevels", "nullLevels", "wrongTypeLevels", "emptyLevels", "unsupportedLevel", "duplicateLevel"})
    void invalidToolTrustPoliciesUseTheRealValidatorWithoutDefaultProjection(String kind) {
        ObjectNode policy = (ObjectNode) version.policy().deepCopy();
        ObjectNode trust = (ObjectNode) policy.path("toolTrust");
        switch (kind) {
            case "missing" -> policy.remove("toolTrust");
            case "null" -> policy.putNull("toolTrust");
            case "wrongType" -> policy.put("toolTrust", CANARY);
            case "missingRequired" -> trust.remove("requireTrustedTool");
            case "falseRequired" -> trust.put("requireTrustedTool", false);
            case "stringRequired" -> trust.put("requireTrustedTool", "true");
            case "missingLevels" -> trust.remove("allowedTrustLevels");
            case "nullLevels" -> trust.putNull("allowedTrustLevels");
            case "wrongTypeLevels" -> trust.put("allowedTrustLevels", "TRUSTED_INTERNAL");
            case "emptyLevels" -> trust.putArray("allowedTrustLevels");
            case "unsupportedLevel" -> ((ArrayNode) trust.path("allowedTrustLevels")).add("SANDBOXED");
            case "duplicateLevel" -> ((ArrayNode) trust.path("allowedTrustLevels")).add("TRUSTED_INTERNAL");
            default -> throw new AssertionError(kind);
        }
        approved(change(version, Version.class, "policy", policy));
        clearInvocations(canonicalizer);

        safeLoad(FailureCode.POLICY_INVALID);

        verify(validator).validate(any(), any());
        verifyNoInteractions(canonicalizer);
        assertThat(validator.validate(policy, catalog.semanticCatalog()).status()).isEqualTo(ValidationStatus.INVALID);
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "unknown", "duplicate", "allToolsDenied", "humanOnlyAllowed", "unknownOutputField"})
    void realValidatorRejectsInvalidPoliciesDespiteMockApprovedMetadata(String kind) {
        ObjectNode policy = (ObjectNode) version.policy().deepCopy();
        switch (kind) {
            case "missing" -> policy.remove("customerScope");
            case "unknown" -> policy.put("unexpected", CANARY);
            case "duplicate" -> ((ArrayNode) policy.path("allowedTools")).add("CUSTOMER_DATA_READ");
            case "allToolsDenied" -> policy.putArray("allowedTools");
            case "humanOnlyAllowed" -> ((ArrayNode) policy.path("allowedTools")).add("LOAN_DECISION_UPDATE");
            case "unknownOutputField" -> ((ArrayNode) policy.at("/fieldPolicy/CUSTOMER_DATA_READ/allowed"))
                    .add("undeclaredField");
            default -> throw new AssertionError(kind);
        }
        approved(change(version, Version.class, "policy", policy));
        safeLoad(FailureCode.POLICY_INVALID);
        var actual = validator.validate(policy, catalog.semanticCatalog());
        String required = switch (kind) {
            case "allToolsDenied" -> "REQUIRED_TOOL_MISSING";
            case "humanOnlyAllowed" -> "HUMAN_ONLY_TOOL_ALLOWED";
            case "unknownOutputField" -> "FIELD_NOT_IN_TOOL_OUTPUT";
            default -> null;
        };
        assertThat(actual.status()).isEqualTo(ValidationStatus.INVALID);
        if (required != null) assertThat(actual.issues()).anySatisfy(issue -> {
            assertThat(issue.code()).isEqualTo(required);
            assertThat(issue.severity().name()).isEqualTo("ERROR");
        });
    }

    @Test
    void semanticallyValidChangedPolicyUnderOldHashIsRejected() {
        ObjectNode changed = (ObjectNode) version.policy().deepCopy();
        changed.put("version", 2);
        approved(change(change(version, Version.class, "version", 2), Version.class, "policy", changed));
        safeLoad(FailureCode.POLICY_INTEGRITY_FAILURE);
    }

    @ParameterizedTest
    @ValueSource(strings = {"run", "approval", "case", "catalog", "validator", "canonical"})
    void dependencyFailuresAreSafeAndStopLaterReads(String dependency, CapturedOutput output) {
        var error = new IllegalStateException(CANARY);
        switch (dependency) {
            case "run" -> when(runs.find(RUN)).thenThrow(error);
            case "approval" -> when(contracts.approved(RELEASE, VERSION, REVIEWER)).thenThrow(error);
            case "case" -> when(cases.findCase(CASE_RUN)).thenThrow(error);
            case "catalog" -> when(catalogs.load(RELEASE, REVIEWER.actorId())).thenThrow(error);
            case "validator" -> doThrow(error).when(validator).validate(any(), any());
            case "canonical" -> doThrow(error).when(canonicalizer).canonicalizeAndHash(any());
            default -> throw new AssertionError(dependency);
        }
        safeLoad(FailureCode.SOURCE_UNAVAILABLE);
        if (dependency.equals("run")) verifyNoInteractions(contracts);
        if (List.of("run", "approval").contains(dependency)) verifyNoInteractions(cases);
        if (List.of("run", "approval", "case").contains(dependency)) verifyNoInteractions(catalogs);
        assertThat(output.getAll()).doesNotContain(CANARY);
    }

    @ParameterizedTest
    @ValueSource(strings = {"approval", "validator", "canonical"})
    void missingDependencyResultCannotProduceSnapshot(String dependency) {
        FailureCode expected;
        switch (dependency) {
            case "approval" -> { when(contracts.approved(RELEASE, VERSION, REVIEWER)).thenReturn(null); expected = FailureCode.CONTRACT_NOT_APPROVED; }
            case "validator" -> { doReturn(null).when(validator).validate(any(), any()); expected = FailureCode.POLICY_INVALID; }
            case "canonical" -> { doReturn(null).when(canonicalizer).canonicalizeAndHash(any()); expected = FailureCode.POLICY_INTEGRITY_FAILURE; }
            default -> throw new AssertionError(dependency);
        }
        safeLoad(expected);
    }

    @Test
    void ownerAuthorizesUnchangedReviewerAndNoFallbackLookupOccurs() {
        var untrusted = new ReviewerContext(WORKSPACE, REVIEWER.actorId(), "VIEWER", CANARY, false, false, false);
        var denied = new BusinessException(ErrorCode.OPERATOR_AUTH_REQUIRED, "Trusted reviewer required");
        when(contracts.approved(RELEASE, VERSION, untrusted)).thenThrow(denied);
        assertThatThrownBy(() -> service.load(RUN, CASE_RUN, untrusted)).isSameAs(denied);
        verify(contracts).approved(RELEASE, VERSION, untrusted);
        verifyNoMoreInteractions(contracts);
        verifyNoInteractions(cases, catalogs);
    }

    @Test
    void committedValidationIsReusedButCurrentOwnersHashAndNewSnapshotsAreAlwaysRead() {
        cacheService(128, 128);
        var first = committedLoad();
        when(runs.find(RUN)).thenReturn(change(run, Projection.class, "status", TestRunStatus.COMPLETED));
        when(cases.findCase(CASE_RUN)).thenReturn(change(caseRun, CaseRun.class, "status", TestCaseRunStatus.PASSED));
        List<ReleaseToolBinding> changedBindings = new ArrayList<>(fixtureBindings());
        changedBindings.set(0, fixtureBinding("CASE_CONTEXT_READ", "b", "c"));
        var freshCatalog = catalogWithBindings(changedBindings);
        when(catalogs.load(RELEASE, REVIEWER.actorId())).thenReturn(freshCatalog);
        var second = committedLoad();

        verify(validator).validate(any(), any());
        verify(canonicalizer, times(2)).canonicalizeAndHash(any());
        verify(runs, times(2)).find(RUN);
        verify(contracts, times(2)).approved(RELEASE, VERSION, REVIEWER);
        verify(cases, times(2)).findCase(CASE_RUN);
        verify(catalogs, times(2)).load(RELEASE, REVIEWER.actorId());
        assertThat(second).isNotSameAs(first);
        assertThat(first.runStatus()).isEqualTo(TestRunStatus.RUNNING);
        assertThat(second.runStatus()).isEqualTo(TestRunStatus.COMPLETED);
        assertThat(second.caseStatus()).isEqualTo(TestCaseRunStatus.PASSED);
        assertThat(second.catalog()).isSameAs(freshCatalog);
        assertThat(second.releaseToolBindings()).containsExactlyElementsOf(changedBindings);
        ((ObjectNode) first.policy()).put("private", CANARY);
        assertThat(second.policy().has("private")).isFalse();
        assertThatThrownBy(() -> second.validation().issues().clear()).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void exactEqualCopiedSemanticCatalogCanReuseValidation() {
        cacheService(128, 128);
        committedLoad();
        var copy = new ContractValidationCatalog(new ArrayList<>(catalog.semanticCatalog().enabledReleaseTools()),
                new ArrayList<>(catalog.semanticCatalog().highImpactToolNames()));
        when(catalogs.load(RELEASE, REVIEWER.actorId())).thenReturn(catalogWithSemantic(copy));
        committedLoad();
        verify(validator).validate(any(), any());
        verify(canonicalizer, times(2)).canonicalizeAndHash(any());
    }

    @ParameterizedTest
    @ValueSource(strings = {"workspace", "release", "version", "resourceHash", "artifact", "releaseFingerprint",
            "manifestVersion", "serverCatalogHash", "semanticCatalog", "rawPolicyDigest"})
    void everyIndependentReusableIdentityComponentSeparatesValidation(String changed) {
        cacheService(128, 128);
        committedLoad();
        ReviewerContext reviewer = REVIEWER;
        Version nextVersion = version;
        Projection nextRun = run;
        SourceBoundCatalog nextCatalog = catalog;
        switch (changed) {
            case "workspace" -> {
                reviewer = new ReviewerContext(OTHER, REVIEWER.actorId(), REVIEWER.role(), CANARY, true, true, false);
                nextVersion = change(version, Version.class, "workspaceId", OTHER);
            }
            case "release" -> {
                nextVersion = change(version, Version.class, "releaseId", OTHER);
                nextRun = change(run, Projection.class, "releaseId", OTHER);
                nextCatalog = change(catalog, SourceBoundCatalog.class, "releaseId", OTHER);
            }
            case "version" -> {
                nextVersion = change(version, Version.class, "id", OTHER);
                nextRun = change(run, Projection.class, "contractVersionId", OTHER);
            }
            case "resourceHash" -> nextVersion = change(version, Version.class, "resourceHash", ARTIFACT);
            case "artifact" -> {
                nextRun = change(run, Projection.class, "agentArtifactFingerprint", HASH);
                nextCatalog = change(catalog, SourceBoundCatalog.class, "agentArtifactFingerprint", HASH);
            }
            case "releaseFingerprint" -> {
                nextRun = change(run, Projection.class, "releaseFingerprint", HASH);
                nextCatalog = change(catalog, SourceBoundCatalog.class, "releaseFingerprint", HASH);
            }
            case "manifestVersion" -> {
                // Synthetic adapter-result key test only: the real constructor accepts only 1.1.
                nextCatalog = spy(catalog);
                doReturn("future-schema-key").when(nextCatalog).manifestSchemaVersion();
            }
            case "serverCatalogHash" -> nextCatalog = change(catalog, SourceBoundCatalog.class, "serverToolCatalogHash", ARTIFACT);
            case "semanticCatalog" -> nextCatalog = catalogWithDocumentFields(List.of("lookupKey"));
            case "rawPolicyDigest" -> {
                var entries = new ArrayList<>(version.policy().properties());
                Collections.reverse(entries);
                ObjectNode reordered = json.createObjectNode();
                entries.forEach(entry -> reordered.set(entry.getKey(), entry.getValue()));
                nextVersion = change(version, Version.class, "policy", reordered);
            }
            default -> throw new AssertionError(changed);
        }
        when(runs.find(RUN)).thenReturn(nextRun);
        when(contracts.approved(nextRun.releaseId(), nextRun.contractVersionId(), reviewer))
                .thenReturn(new ApprovedContract(nextVersion, nextRun.agentArtifactFingerprint(), nextRun.releaseFingerprint()));
        when(catalogs.load(nextRun.releaseId(), reviewer.actorId())).thenReturn(nextCatalog);
        beginSynchronization();
        service.load(RUN, CASE_RUN, reviewer);
        finishSynchronization(true);
        verify(validator, times(2)).validate(any(), any());
        verify(canonicalizer, times(2)).canonicalizeAndHash(any());
    }

    @Test
    void changedClaimedPolicyHashDoesNotHitOrFillDespiteIdenticalCurrentPolicy() {
        cacheService(128, 128);
        committedLoad();
        approved(change(version, Version.class, "policyHash", ARTIFACT));
        for (int attempt = 0; attempt < 2; attempt++) {
            beginSynchronization();
            safeLoad(FailureCode.POLICY_INTEGRITY_FAILURE);
            assertThat(TransactionSynchronizationManager.getSynchronizations()).isEmpty();
            finishSynchronization(true);
        }
        verify(validator, times(3)).validate(any(), any());
        verify(canonicalizer, times(3)).canonicalizeAndHash(any());
    }

    @Test
    void canonicallyEqualUnicodePolicyCannotReuseDifferentRawFieldSemantics() {
        // Defensive mocked owner DTO, not a claim that A approves unnormalized stored policy.
        catalog = catalogWithDocumentFields(List.of("lookupKey"));
        when(catalogs.load(RELEASE, REVIEWER.actorId())).thenReturn(catalog);
        ObjectNode valid = (ObjectNode) version.policy().deepCopy();
        ObjectNode fields = ((ObjectNode) valid.path("fieldPolicy")).putObject("DOCUMENT_READER");
        fields.putArray("allowed").add("lookupKey");
        fields.put("denyUnknown", true);
        String actualHash = canonicalizer.canonicalizeAndHash(valid).policyHash();
        version = change(change(version, Version.class, "policy", valid), Version.class, "policyHash", actualHash);
        approved(version);
        ObjectNode different = valid.deepCopy();
        ((ObjectNode) different.at("/fieldPolicy/DOCUMENT_READER")).putArray("allowed").add("lookup\u212Aey");
        assertThat(canonicalizer.canonicalizeAndHash(different).policyHash()).isEqualTo(actualHash);
        assertThat(validator.validate(different, catalog.semanticCatalog()).issues())
                .anyMatch(issue -> issue.code().equals("FIELD_NOT_IN_TOOL_OUTPUT"));
        cacheService(128, 128);
        committedLoad();
        approved(change(version, Version.class, "policy", different));
        clearInvocations(canonicalizer);
        beginSynchronization();
        safeLoad(FailureCode.POLICY_INVALID);
        assertThat(TransactionSynchronizationManager.getSynchronizations()).isEmpty();
        finishSynchronization(true);
        verify(validator, times(2)).validate(any(), any());
        verifyNoInteractions(canonicalizer);
    }

    @ParameterizedTest
    @ValueSource(strings = {"malformed", "validStaleHash", "nullCanonical", "throwCanonical", "authorization", "case", "catalog"})
    void warmedCacheNeverOverridesCurrentFailures(String kind, CapturedOutput output) {
        cacheService(128, 128);
        committedLoad();
        clearInvocations(runs, contracts, cases, catalogs, validator, canonicalizer);
        FailureCode expected = FailureCode.POLICY_INTEGRITY_FAILURE;
        switch (kind) {
            case "malformed" -> {
                ObjectNode policy = (ObjectNode) version.policy().deepCopy();
                policy.put("unexpected", CANARY);
                approved(change(version, Version.class, "policy", policy));
                expected = FailureCode.POLICY_INVALID;
            }
            case "validStaleHash" -> {
                ObjectNode policy = (ObjectNode) version.policy().deepCopy();
                policy.put("version", 2);
                approved(change(change(version, Version.class, "version", 2), Version.class, "policy", policy));
            }
            case "nullCanonical" -> doReturn(null).when(canonicalizer).canonicalizeAndHash(any());
            case "throwCanonical" -> {
                doThrow(new IllegalStateException(CANARY)).when(canonicalizer).canonicalizeAndHash(any());
                expected = FailureCode.SOURCE_UNAVAILABLE;
            }
            case "authorization" -> {
                var denied = new BusinessException(ErrorCode.OPERATOR_AUTH_REQUIRED, "Trusted reviewer required");
                when(contracts.approved(RELEASE, VERSION, REVIEWER)).thenThrow(denied);
                assertThatThrownBy(() -> service.load(RUN, CASE_RUN, REVIEWER)).isSameAs(denied);
                verifyNoInteractions(cases, catalogs, validator, canonicalizer);
                return;
            }
            case "case" -> {
                when(cases.findCase(CASE_RUN)).thenReturn(change(caseRun, CaseRun.class, "testRunId", OTHER));
                expected = FailureCode.CASE_RUN_BINDING_INVALID;
            }
            case "catalog" -> {
                when(catalogs.load(RELEASE, REVIEWER.actorId())).thenReturn(change(catalog, SourceBoundCatalog.class, "releaseFingerprint", HASH));
                expected = FailureCode.CATALOG_BINDING_INVALID;
            }
            default -> throw new AssertionError(kind);
        }
        beginSynchronization();
        safeLoad(expected);
        assertThat(TransactionSynchronizationManager.getSynchronizations()).isEmpty();
        finishSynchronization(true);
        if (kind.equals("malformed")) verifyNoInteractions(canonicalizer);
        if (List.of("case", "catalog").contains(kind)) verifyNoInteractions(validator, canonicalizer);
        if (List.of("nullCanonical", "throwCanonical").contains(kind)) verifyNoInteractions(validator);
        assertThat(output.getAll()).doesNotContain(CANARY);
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "invalid", "throw"})
    void unsuccessfulColdValidationIsNeverPublished(String kind) {
        cacheService(128, 128);
        switch (kind) {
            case "null" -> doReturn(null).when(validator).validate(any(), any());
            case "invalid" -> doReturn(ValidationResult.fromIssues(List.of(
                    new Issue("/", "INVALID", IssueSeverity.ERROR, "Rejected")))).when(validator).validate(any(), any());
            case "throw" -> doThrow(new IllegalStateException(CANARY)).when(validator).validate(any(), any());
            default -> throw new AssertionError(kind);
        }
        for (int i = 0; i < 2; i++) {
            beginSynchronization();
            safeLoad(kind.equals("throw") ? FailureCode.SOURCE_UNAVAILABLE : FailureCode.POLICY_INVALID);
            assertThat(TransactionSynchronizationManager.getSynchronizations()).isEmpty();
            finishSynchronization(true);
        }
        verify(validator, times(2)).validate(any(), any());
        verifyNoInteractions(canonicalizer);
    }

    @Test
    void warningOnlyImmutableValidationRemainsAcceptedAndReusable() {
        cacheService(128, 128);
        // Exercise the validator's immutable WARN result contract, not a new policy warning rule.
        List<Issue> issues = new ArrayList<>(List.of(new Issue("/", "REVIEW", IssueSeverity.WARNING, "Review")));
        var warning = ValidationResult.fromIssues(issues);
        doReturn(warning).when(validator).validate(any(), any());
        var first = committedLoad();
        issues.clear();
        var second = committedLoad();
        assertThat(first.validation().status()).isEqualTo(ValidationStatus.WARN);
        assertThat(second.validation().issues()).hasSize(1);
        assertThatThrownBy(() -> second.validation().issues().clear()).isInstanceOf(UnsupportedOperationException.class);
        verify(validator).validate(any(), any());
    }

    @Test
    void ttlStartsAtCommitExpiresExactlyAtFiveMinutesAndHitsDoNotRenewIt() {
        AtomicLong clock = cacheService(128, 128);
        beginSynchronization();
        service.load(RUN, CASE_RUN, REVIEWER);
        clock.set(TimeUnit.MINUTES.toNanos(20));
        finishSynchronization(true);
        clock.addAndGet(TimeUnit.MINUTES.toNanos(5) - 1);
        committedLoad();
        verify(validator).validate(any(), any());
        clock.incrementAndGet();
        committedLoad();
        verify(validator, times(2)).validate(any(), any());
        clock.addAndGet(TimeUnit.MINUTES.toNanos(5) - 1);
        committedLoad();
        verify(validator, times(2)).validate(any(), any());
    }

    @Test
    void pendingResultsAreNotVisibleBeforeCommitAndRollbackNeverPublishes() {
        cacheService(128, 128);
        beginSynchronization();
        service.load(RUN, CASE_RUN, REVIEWER);
        service.load(RUN, CASE_RUN, REVIEWER);
        verify(validator, times(2)).validate(any(), any());
        assertThat(TransactionSynchronizationManager.getSynchronizations()).hasSize(2);
        finishSynchronization(false);
        committedLoad();
        committedLoad();
        verify(validator, times(3)).validate(any(), any());
    }

    @Test
    void absentSynchronizationPreservesSixArgumentSuccessButDoesNotCache() {
        clearInvocations(canonicalizer);
        service.load(RUN, CASE_RUN, REVIEWER);
        service.load(RUN, CASE_RUN, REVIEWER);
        verify(validator, times(2)).validate(any(), any());
        verify(canonicalizer, times(2)).canonicalizeAndHash(any());
        assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isFalse();
    }

    @Test
    void entryCapacityEvictsOldestWriteWithoutPromotingHits() {
        cacheService(2, 2);
        committedLoad();
        approved(change(version, Version.class, "resourceHash", ARTIFACT));
        committedLoad();
        approved(version);
        committedLoad();
        approved(change(version, Version.class, "resourceHash", FINGERPRINT));
        committedLoad();
        approved(version);
        committedLoad();
        verify(validator, times(4)).validate(any(), any());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void pendingCapacityIsBoundedAndCompletionRestoresAdmission(boolean commit) {
        cacheService(128, 1);
        beginSynchronization();
        service.load(RUN, CASE_RUN, REVIEWER);
        approved(change(version, Version.class, "resourceHash", ARTIFACT));
        service.load(RUN, CASE_RUN, REVIEWER);
        assertThat(TransactionSynchronizationManager.getSynchronizations()).hasSize(1);
        finishSynchronization(commit);
        committedLoad();
        committedLoad();
        verify(validator, times(3)).validate(any(), any());
    }

    @ParameterizedTest
    @ValueSource(strings = {"catalogCount", "catalogCharacters", "resultCount", "resultCharacters",
            "combinedCount", "combinedCharacters"})
    void oversizeMetadataOnlySkipsAdmissionWithoutRejectingSource(String kind) {
        cacheService(128, 128);
        if (kind.startsWith("catalog")) {
            List<String> fields = kind.equals("catalogCount")
                    ? java.util.stream.IntStream.range(0, 1024).mapToObj(i -> "unused" + i).toList()
                    : List.of("unused".repeat(6000));
            when(catalogs.load(RELEASE, REVIEWER.actorId())).thenReturn(catalogWithDocumentFields(fields));
        } else {
            if (kind.startsWith("combined")) {
                List<String> fields = kind.equals("combinedCount")
                        ? java.util.stream.IntStream.range(0, 600).mapToObj(i -> "unused" + i).toList()
                        : List.of("x".repeat(17000));
                when(catalogs.load(RELEASE, REVIEWER.actorId())).thenReturn(catalogWithDocumentFields(fields));
            }
            List<Issue> issues = kind.equals("resultCount") || kind.equals("combinedCount")
                    ? java.util.stream.IntStream.range(0, kind.equals("combinedCount") ? 150 : 400)
                            .mapToObj(i -> new Issue("/" + i, "REVIEW", IssueSeverity.WARNING, "Review")).toList()
                    : List.of(new Issue("/", "REVIEW", IssueSeverity.WARNING,
                            "x".repeat(kind.equals("combinedCharacters") ? 17000 : 32768)));
            doReturn(ValidationResult.fromIssues(issues)).when(validator).validate(any(), any());
        }
        for (int i = 0; i < 2; i++) {
            beginSynchronization();
            assertThat(service.load(RUN, CASE_RUN, REVIEWER)).isNotNull();
            assertThat(TransactionSynchronizationManager.getSynchronizations()).isEmpty();
            finishSynchronization(true);
        }
        verify(validator, times(2)).validate(any(), any());
        verify(canonicalizer, times(2)).canonicalizeAndHash(any());
    }

    @Test
    void rawSerializationFailureSkipsCacheAndPreservesRealValidationAndCanonicalization() {
        ObjectNode policy = spy((ObjectNode) version.policy().deepCopy());
        doAnswer(invocation -> {
            ObjectNode copied = spy((ObjectNode) version.policy().deepCopy());
            doThrow(new IllegalStateException(CANARY)).when(copied).toString();
            return copied;
        }).when(policy).deepCopy();
        // Only the optional raw-digest serialization fails; actual engine methods remain real.
        Version supplied = new Version(version.id(), version.workspaceId(), version.releaseId(), version.contractKey(),
                version.version(), version.state(), policy, version.policyHash(), version.resourceHash(),
                version.basePolicyHash(), version.validation(), version.review());
        approved(supplied);
        cacheService(128, 128);
        for (int i = 0; i < 2; i++) {
            beginSynchronization();
            assertThat(service.load(RUN, CASE_RUN, REVIEWER).policyHash()).isEqualTo(version.policyHash());
            assertThat(TransactionSynchronizationManager.getSynchronizations()).isEmpty();
            finishSynchronization(true);
        }
        verify(validator, times(2)).validate(any(), any());
        verify(canonicalizer, times(2)).canonicalizeAndHash(any());
    }

    @Test
    void failedSynchronizationRegistrationReleasesReservationAndDoesNotRejectSource() {
        cacheService(128, 1);
        beginSynchronization();
        try (var tx = mockStatic(TransactionSynchronizationManager.class, CALLS_REAL_METHODS)) {
            tx.when(() -> TransactionSynchronizationManager.registerSynchronization(any()))
                    .thenThrow(new IllegalStateException(CANARY));
            assertThat(service.load(RUN, CASE_RUN, REVIEWER)).isNotNull();
            assertThat(TransactionSynchronizationManager.getSynchronizations()).isEmpty();
        }
        finishSynchronization(true);
        committedLoad();
        committedLoad();
        verify(validator, times(2)).validate(any(), any());
    }

    @Test
    void sourceProjectionFailureCannotReserveOrPublishPreviouslyValidatedResult() {
        ObjectNode malformed = (ObjectNode) version.policy().deepCopy();
        ((ObjectNode) malformed.path("toolTrust")).putArray("allowedTrustLevels").add("UNKNOWN_LEVEL");
        String actualHash = canonicalizer.canonicalizeAndHash(malformed).policyHash();
        approved(change(change(version, Version.class, "policy", malformed), Version.class, "policyHash", actualHash));
        cacheService(128, 1);
        // Faulty validator output exercises the later source-construction guard, not valid policy.
        doReturn(ValidationResult.fromIssues(List.of())).when(validator).validate(any(), any());
        beginSynchronization();
        safeLoad(FailureCode.POLICY_INVALID);
        assertThat(TransactionSynchronizationManager.getSynchronizations()).isEmpty();
        finishSynchronization(true);
        approved(version);
        committedLoad();
        committedLoad();
        verify(validator, times(2)).validate(any(), any());
    }

    @Test
    void publicConstructorBoundsPendingCallbacksAt128() {
        clearInvocations(validator, canonicalizer);
        beginSynchronization();
        for (int i = 0; i < 129; i++) service.load(RUN, CASE_RUN, REVIEWER);
        assertThat(TransactionSynchronizationManager.getSynchronizations()).hasSize(128);
        finishSynchronization(false);
        committedLoad();
        committedLoad();
        verify(validator, times(130)).validate(any(), any());
    }

    @Test
    void releaseEvictionRemovesOnlyItsCommittedEntries() {
        cacheService(128, 128);
        committedLoad();
        bindOtherRelease();
        committedLoad();
        service.invalidateRelease(RELEASE);
        committedLoad();
        verify(validator, times(2)).validate(any(), any());
        when(runs.find(RUN)).thenReturn(run);
        committedLoad();
        verify(validator, times(3)).validate(any(), any());
    }

    @Test
    void invalidationWhileFillWaitsForCommitPreventsRepopulation() {
        cacheService(128, 128);
        beginSynchronization();
        service.load(RUN, CASE_RUN, REVIEWER);
        service.invalidateRelease(RELEASE);
        finishSynchronization(true);
        committedLoad();
        committedLoad();
        verify(validator, times(2)).validate(any(), any());
    }

    @ParameterizedTest
    @ValueSource(strings = {"owner", "validator"})
    void invalidationDoesNotWaitForOwnerOrValidatorAndCancelsEarlierRead(String blocked) throws Exception {
        cacheService(128, 128);
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        if (blocked.equals("owner")) {
            when(runs.find(RUN)).thenAnswer(invocation -> {
                entered.countDown();
                assertThat(release.await(5, TimeUnit.SECONDS)).isTrue();
                return run;
            });
        } else {
            doAnswer(invocation -> {
                entered.countDown();
                assertThat(release.await(5, TimeUnit.SECONDS)).isTrue();
                return invocation.callRealMethod();
            }).when(validator).validate(any(), any());
        }
        try (var executor = Executors.newFixedThreadPool(2)) {
            var load = executor.submit(() -> {
                TransactionSynchronizationManager.setActualTransactionActive(true);
                TransactionSynchronizationManager.setCurrentTransactionReadOnly(false);
                TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(Connection.TRANSACTION_REPEATABLE_READ);
                try { return committedLoad(); }
                finally { TransactionSynchronizationManager.clear(); }
            });
            try {
                assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
                executor.submit(() -> service.invalidateRelease(RELEASE)).get(5, TimeUnit.SECONDS);
            } finally {
                release.countDown();
            }
            assertThat(load.get(5, TimeUnit.SECONDS)).isNotNull();
        }
        committedLoad();
        committedLoad();
        verify(validator, times(2)).validate(any(), any());
    }

    @Test
    void invalidReleaseRequestUsesExistingSafeErrorWithoutOwnerCalls() {
        safe(() -> service.invalidateRelease(null), FailureCode.INVALID_REQUEST);
        verifyNoInteractions(runs, contracts, cases, catalogs, validator);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1})
    void cacheCapacitySeamRejectsInvalidBounds(int invalid) {
        assertThatThrownBy(() -> new GatewayApprovedPolicySourceService(runs, contracts, cases, catalogs,
                validator, canonicalizer, System::nanoTime, invalid, 128)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new GatewayApprovedPolicySourceService(runs, contracts, cases, catalogs,
                validator, canonicalizer, System::nanoTime, 128, invalid)).isInstanceOf(IllegalArgumentException.class);
    }

    private AtomicLong cacheService(int entries, int pending) {
        AtomicLong clock = new AtomicLong();
        service = new GatewayApprovedPolicySourceService(runs, contracts, cases, catalogs,
                validator, canonicalizer, clock::get, entries, pending);
        clearInvocations(validator, canonicalizer);
        return clock;
    }

    /** Explicit callback fixture only; the PG suite proves actual Spring commit/rollback behavior. */
    private void beginSynchronization() { TransactionSynchronizationManager.initSynchronization(); }

    private void finishSynchronization(boolean committed) {
        var callbacks = TransactionSynchronizationManager.getSynchronizations();
        try {
            if (committed) callbacks.forEach(TransactionSynchronization::afterCommit);
        } finally {
            callbacks.forEach(callback -> callback.afterCompletion(committed
                    ? TransactionSynchronization.STATUS_COMMITTED : TransactionSynchronization.STATUS_ROLLED_BACK));
            TransactionSynchronizationManager.clearSynchronization();
        }
    }

    private ApprovedPolicySource committedLoad() {
        beginSynchronization();
        var source = service.load(RUN, CASE_RUN, REVIEWER);
        finishSynchronization(true);
        return source;
    }

    private SourceBoundCatalog catalogWithSemantic(ContractValidationCatalog semantic) {
        return new SourceBoundCatalog(catalog.releaseId(), catalog.manifestSchemaVersion(), catalog.agentArtifactFingerprint(),
                catalog.releaseFingerprint(), catalog.serverToolCatalogHash(), semantic, fixtureBindings());
    }

    private SourceBoundCatalog catalogWithDocumentFields(List<String> fields) {
        List<EnabledTool> tools = catalog.semanticCatalog().enabledReleaseTools().stream()
                .map(tool -> tool.toolName().equals("DOCUMENT_READER") ? new EnabledTool(tool.toolName(), fields) : tool)
                .toList();
        return catalogWithSemantic(new ContractValidationCatalog(tools, catalog.semanticCatalog().highImpactToolNames()));
    }

    private void bindOtherRelease() {
        Projection otherRun = change(run, Projection.class, "releaseId", OTHER);
        Version otherVersion = change(version, Version.class, "releaseId", OTHER);
        when(runs.find(RUN)).thenReturn(otherRun);
        when(contracts.approved(OTHER, VERSION, REVIEWER)).thenReturn(new ApprovedContract(otherVersion, ARTIFACT, FINGERPRINT));
        when(catalogs.load(OTHER, REVIEWER.actorId())).thenReturn(change(catalog, SourceBoundCatalog.class, "releaseId", OTHER));
    }

    private void approved(Version value) {
        when(contracts.approved(RELEASE, VERSION, REVIEWER)).thenReturn(new ApprovedContract(value, ARTIFACT, FINGERPRINT));
    }

    private SourceBoundCatalog catalogWithBindings(List<ReleaseToolBinding> bindings) {
        return new SourceBoundCatalog(RELEASE, "1.1", ARTIFACT, FINGERPRINT, HASH, catalog.semanticCatalog(), bindings);
    }

    /** Synthetic unit digests only; the separate PostgreSQL test compares Role A's stored hashes. */
    private List<ReleaseToolBinding> fixtureBindings() {
        return List.of(
                fixtureBinding("CASE_CONTEXT_READ", "1", "6"),
                fixtureBinding("CUSTOMER_DATA_READ", "2", "7"),
                fixtureBinding("DOCUMENT_READER", "3", "8"),
                fixtureBinding("LOAN_POLICY_SEARCH", "4", "9"),
                fixtureBinding("REVIEW_NOTE_WRITE", "5", "a")
        );
    }

    private ReleaseToolBinding fixtureBinding(String name, String schemaHex, String descriptionHex) {
        return new ReleaseToolBinding(name, "1.1.0", true,
                "sha256:" + schemaHex.repeat(64), "sha256:" + descriptionHex.repeat(64));
    }

    private <T> T change(T value, Class<T> type, String field, Object replacement) {
        ObjectNode node = json.valueToTree(value);
        node.set(field, json.valueToTree(replacement));
        return json.treeToValue(node, type);
    }

    private void safeLoad(FailureCode code) { safe(() -> service.load(RUN, CASE_RUN, REVIEWER), code); }

    private void safe(org.assertj.core.api.ThrowableAssert.ThrowingCallable action, FailureCode code) {
        PolicySourceException failure = catchThrowableOfType(PolicySourceException.class, action);
        assertThat(failure).isNotNull();
        assertThat(failure.code()).isEqualTo(code);
        assertThat(failure.getMessage()).isEqualTo("Approved policy source unavailable: " + code.name());
        assertThat(failure.getCause()).isNull();
        assertThat(failure.getSuppressed()).isEmpty();
        failure.addSuppressed(new IllegalStateException(CANARY));
        assertThat(failure.getSuppressed()).isEmpty();
    }
}
