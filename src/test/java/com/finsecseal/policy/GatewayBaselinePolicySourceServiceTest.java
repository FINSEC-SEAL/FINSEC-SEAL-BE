package com.finsecseal.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.finsecseal.agent.AgentEntity;
import com.finsecseal.agent.AgentService;
import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.ReleaseLifecycleState;
import com.finsecseal.common.domain.TestCaseRunStatus;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.common.domain.TestRunStatus;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.SourceBoundCatalog;
import com.finsecseal.contract.SafetyContractLifecyclePolicy;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.LifecyclePolicyException;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.RejectionCode;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.evidence.TestRunDto.Projection;
import com.finsecseal.evidence.TestRunPersistenceDto.CaseRun;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.evidence.TestRunProjectionService;
import com.finsecseal.policy.GatewayBaselinePolicySourceService.BaselineSourceException;
import com.finsecseal.policy.GatewayBaselinePolicySourceService.FailureCode;
import com.finsecseal.release.AgentReleaseEntity;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.FingerprintService;
import com.finsecseal.release.ReleaseDto.ToolCatalogResponse;
import com.finsecseal.release.ReleaseService;
import java.sql.Connection;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/** Owner reads are mocked here; the separate PostgreSQL test proves physical source provenance. */
@ExtendWith(OutputCaptureExtension.class)
class GatewayBaselinePolicySourceServiceTest {
    private static final UUID WORKSPACE = UUID.randomUUID();
    private static final UUID AGENT = UUID.randomUUID();
    private static final UUID RELEASE = UUID.randomUUID();
    private static final UUID RUN = UUID.randomUUID();
    private static final UUID CASE_RUN = UUID.randomUUID();
    private static final UUID TEST_CASE = UUID.randomUUID();
    private static final UUID OTHER = UUID.randomUUID();
    private static final String ARTIFACT = "sha256:" + "a".repeat(64);
    private static final String FINGERPRINT = "sha256:" + "b".repeat(64);
    private static final String HASH = "sha256:" + "c".repeat(64);
    private static final String PURPOSE = "LOAN_DOCUMENT_COMPLETENESS_REVIEW";
    private static final String CANARY = "PRIVATE-BASELINE-SQL-SESSION-CANARY";
    private static final ReviewerContext REVIEWER = new ReviewerContext(
            WORKSPACE, "baseline-source-test", "AI_SECURITY_REVIEWER", CANARY, true, true, false);
    private static final List<String> NORMAL_TOOLS = List.of(
            "CASE_CONTEXT_READ", "CUSTOMER_DATA_READ", "DOCUMENT_READER",
            "LOAN_POLICY_SEARCH", "REVIEW_NOTE_WRITE");

    private final ObjectMapper json = new ObjectMapper();
    private TestRunProjectionService runs;
    private TestRunPersistenceService cases;
    private ReleaseToolCatalogContractAdapter catalogs;
    private ReleaseService releases;
    private AgentService agents;
    private GatewayBaselinePolicySourceService service;
    private Projection run;
    private CaseRun caseRun;
    private AgentReleaseEntity release;
    private AgentEntity agent;
    private ObjectNode manifest;
    private SourceBoundCatalog catalog;

    @BeforeEach
    void setup() throws Exception {
        runs = mock(TestRunProjectionService.class);
        cases = mock(TestRunPersistenceService.class);
        catalogs = mock(ReleaseToolCatalogContractAdapter.class);
        releases = mock(ReleaseService.class);
        agents = mock(AgentService.class);
        service = new GatewayBaselinePolicySourceService(runs, cases, catalogs, releases, agents);
        try (var input = getClass().getResourceAsStream("/fixtures/valid-release-manifest-v1.1.json")) {
            assertThat(input).isNotNull();
            manifest = (ObjectNode) json.readTree(input);
        }
        ((ObjectNode) manifest.path("systemPrompt")).put("text", CANARY);
        ((ObjectNode) manifest.path("model")).put("private", CANARY);
        catalog = fixtureCatalog();
        release = releaseEntity();
        agent = mock(AgentEntity.class);
        when(agent.getId()).thenReturn(AGENT);
        when(agent.getWorkspaceId()).thenReturn(WORKSPACE);
        run = new Projection(RUN, RELEASE, OTHER, null, TestRunMode.BASELINE, TestRunStatus.RUNNING,
                ARTIFACT, FINGERPRINT, "fixture/1", HASH, 1, 0, 0, 0, null, null,
                json.createObjectNode().put("private", CANARY), null, null, null);
        caseRun = new CaseRun(CASE_RUN, RUN, TEST_CASE, 2, TestCaseRunStatus.EXECUTING,
                null, null, HASH, null, null, null, json.createObjectNode().put("private", CANARY));
        when(runs.find(RUN)).thenReturn(run);
        when(releases.getRequired(RELEASE)).thenReturn(release);
        when(agents.getRequired(AGENT)).thenReturn(agent);
        when(cases.findCase(CASE_RUN)).thenReturn(caseRun);
        when(catalogs.load(RELEASE, REVIEWER.actorId())).thenReturn(catalog);
        // These flags test the guard only, not physical transactions or Release locks.
        TransactionSynchronizationManager.setActualTransactionActive(true);
        TransactionSynchronizationManager.setCurrentTransactionReadOnly(false);
        TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(Connection.TRANSACTION_REPEATABLE_READ);
    }

    @AfterEach
    void cleanup() {
        TransactionSynchronizationManager.clear();
    }

    @Test
    void bindsContractFreeLiveBaselineToClosedVerifiedDeclarationsInOwnerReadOrder() {
        var result = service.load(RUN, CASE_RUN, REVIEWER);
        assertThat(result.runId()).isEqualTo(RUN);
        assertThat(result.testCaseRunId()).isEqualTo(CASE_RUN);
        assertThat(result.testCaseId()).isEqualTo(TEST_CASE);
        assertThat(result.releaseId()).isEqualTo(RELEASE);
        assertThat(result.workspaceId()).isEqualTo(WORKSPACE);
        assertThat(result.referencedContractVersionId()).isNull();
        assertThat(result.runMode()).isEqualTo(TestRunMode.BASELINE);
        assertThat(result.runStatus()).isEqualTo(TestRunStatus.RUNNING);
        assertThat(result.caseStatus()).isEqualTo(TestCaseRunStatus.EXECUTING);
        assertThat(result.trialIndex()).isEqualTo(2);
        assertThat(result.variantHash()).isEqualTo(HASH);
        assertThat(result.fixtureVersion()).isEqualTo("fixture/1");
        assertThat(result.fixtureDigest()).isEqualTo(HASH);
        assertThat(result.catalog()).isEqualTo(catalog);
        assertThat(result.releasePurpose()).isEqualTo(PURPOSE);
        assertThat(result.normalToolNames()).containsExactlyElementsOf(NORMAL_TOOLS);
        assertThat(result.releaseDeclarations().properties().stream().map(entry -> entry.getKey()).toList())
                .containsExactlyInAnyOrder(
                "businessPurpose", "businessWorkflow", "tools", "serverToolCatalog");
        assertThat(result.releaseDeclarations()).isEqualTo(expectedDeclarations());
        assertThat(result.releaseDeclarations().at("/serverToolCatalog/tools/0/name").stringValue())
                .isEqualTo("LOAN_DECISION_UPDATE");
        assertThat(result.releaseDeclarations().at("/serverToolCatalog/tools/0/agentExecutable").booleanValue())
                .isFalse();
        assertThat(result.releaseDeclarations().at("/serverToolCatalog/tools/0/executionBoundary").stringValue())
                .isEqualTo("HUMAN_ONLY");
        assertThat(result.normalToolNames()).doesNotContain("LOAN_DECISION_UPDATE", "EXTERNAL_HTTP");
        var order = inOrder(runs, releases, agents, cases, catalogs);
        order.verify(runs).find(RUN);
        order.verify(releases).getRequired(RELEASE);
        order.verify(agents).getRequired(AGENT);
        order.verify(cases).findCase(CASE_RUN);
        order.verify(catalogs).load(RELEASE, REVIEWER.actorId());
        order.verify(releases).getRequired(RELEASE);
        verifyNoMoreInteractions(runs, releases, agents, cases, catalogs);
    }

    @Test
    void storedContractReferenceRemainsMetadataAndDoesNotGrantAdditionalPermission() {
        when(runs.find(RUN)).thenReturn(change(run, Projection.class, "contractVersionId", OTHER));
        var result = service.load(RUN, CASE_RUN, REVIEWER);
        assertThat(result.referencedContractVersionId()).isEqualTo(OTHER);
        assertThat(result.normalToolNames()).containsExactlyElementsOf(NORMAL_TOOLS);
        assertThat(result.releaseDeclarations()).isEqualTo(expectedDeclarations());
        assertThat(result.getClass().getDeclaredFields()).noneMatch(field ->
                field.getType().getSimpleName().matches("ApprovedPolicySource|ApprovedContract|Version|ReviewerContext"));
    }

    @Test
    void snapshotsNestedJsonAndKeepsPrivateOwnerDataOutOfTheResult(CapturedOutput output) {
        var result = service.load(RUN, CASE_RUN, REVIEWER);
        JsonNode expected = expectedDeclarations();
        JsonNode expectedSchema = result.catalog().inputSchemas().get("CUSTOMER_DATA_READ");
        ((ObjectNode) manifest.path("businessPurpose")).put("code", CANARY);
        ((ArrayNode) manifest.at("/businessWorkflow/allowedStages")).removeAll();
        ((ObjectNode) manifest.at("/tools/0/outputSchema")).put("private", CANARY);
        ((ObjectNode) result.releaseDeclarations().path("businessPurpose")).put("code", CANARY);
        ((ArrayNode) result.releaseDeclarations().path("tools")).removeAll();
        ((ObjectNode) result.catalog().inputSchemas().get("CUSTOMER_DATA_READ")).removeAll();
        assertThat(result.releaseDeclarations()).isEqualTo(expected);
        assertThat(result.releasePurpose()).isEqualTo(PURPOSE);
        assertThat(result.catalog().inputSchemas().get("CUSTOMER_DATA_READ")).isEqualTo(expectedSchema);
        assertThatThrownBy(() -> result.normalToolNames().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThat(result.releaseDeclarations().toString()).doesNotContain(CANARY, "systemPrompt", "private");
        assertThat(result.toString()).doesNotContain(CANARY, "systemPrompt", "private");
        assertThat(result.getClass().getDeclaredFields()).noneMatch(field ->
                List.of(Projection.class, CaseRun.class, AgentReleaseEntity.class, AgentEntity.class,
                        ReviewerContext.class).contains(field.getType()));
        assertThat(output.getAll()).doesNotContain(CANARY);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void publicReviewerPolicyAcceptsAuthenticatedSameWorkspaceWithoutChangingDemoSemantics(boolean demoMode) {
        ReviewerContext reviewer = new ReviewerContext(WORKSPACE, "a".repeat(120),
                "AI_SECURITY_REVIEWER", "s".repeat(200), true, true, demoMode);
        SafetyContractLifecyclePolicy.requireReviewerContext(reviewer, WORKSPACE);
        verifyNoInteractions(runs, cases, catalogs, releases, agents);
    }

    @ParameterizedTest
    @MethodSource("invalidReviewers")
    void publicReviewerPolicyPreservesExistingRejectionCodes(ReviewerContext reviewer, RejectionCode code) {
        assertReviewerFailure(() -> SafetyContractLifecyclePolicy.requireReviewerContext(reviewer, WORKSPACE), code);
        verifyNoInteractions(runs, cases, catalogs, releases, agents);
        if (reviewer != null) {
            assertReviewerFailure(() -> service.load(RUN, CASE_RUN, reviewer), code);
            verifyNoInteractions(cases, catalogs);
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void publicReviewerPolicyRejectsNullExpectedWorkspaceEvenWhenBothWorkspacesAreNull(boolean bothNull) {
        ReviewerContext reviewer = bothNull
                ? reviewer(null, REVIEWER.actorId(), REVIEWER.role(), REVIEWER.sessionId(), true, true)
                : REVIEWER;
        assertReviewerFailure(() -> SafetyContractLifecyclePolicy.requireReviewerContext(reviewer, null),
                RejectionCode.REVIEWER_WORKSPACE_MISMATCH);
        verifyNoInteractions(runs, cases, catalogs, releases, agents);
    }

    @Test
    void publicReviewerPolicyKeepsWorkspaceFailureAheadOfOtherReviewerFailures() {
        ReviewerContext invalid = reviewer(OTHER, null, "wrong", null, false, false);
        assertReviewerFailure(() -> SafetyContractLifecyclePolicy.requireReviewerContext(invalid, WORKSPACE),
                RejectionCode.REVIEWER_WORKSPACE_MISMATCH);
    }

    @ParameterizedTest
    @ValueSource(strings = {"runId", "caseRunId", "reviewer"})
    void missingRequestStopsBeforeOwnerReads(String field) {
        safe(() -> service.load(field.equals("runId") ? null : RUN,
                field.equals("caseRunId") ? null : CASE_RUN,
                field.equals("reviewer") ? null : REVIEWER), FailureCode.INVALID_REQUEST);
        verifyNoInteractions(runs, cases, catalogs, releases, agents);
    }

    @ParameterizedTest
    @ValueSource(strings = {"none", "readOnly", "readCommitted", "default", "unknown"})
    void incompatibleTransactionGuardStopsBeforeOwnerReads(String kind) {
        switch (kind) {
            case "none" -> TransactionSynchronizationManager.setActualTransactionActive(false);
            case "readOnly" -> TransactionSynchronizationManager.setCurrentTransactionReadOnly(true);
            case "readCommitted" -> TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(
                    Connection.TRANSACTION_READ_COMMITTED);
            case "default" -> TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(null);
            case "unknown" -> TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(-10);
            default -> throw new AssertionError(kind);
        }
        safeLoad(FailureCode.UNSAFE_TRANSACTION);
        verifyNoInteractions(runs, cases, catalogs, releases, agents);
    }

    @ParameterizedTest
    @EnumSource(value = TestRunMode.class, mode = EnumSource.Mode.EXCLUDE, names = "BASELINE")
    void rejectsOtherRunModesBeforeReleaseOrCatalogReads(TestRunMode mode) {
        when(runs.find(RUN)).thenReturn(change(run, Projection.class, "mode", mode));
        safeLoad(FailureCode.UNSUPPORTED_RUN_MODE);
        verifyNoInteractions(releases, agents, cases, catalogs);
    }

    @ParameterizedTest
    @EnumSource(value = TestRunStatus.class, mode = EnumSource.Mode.EXCLUDE, names = "RUNNING")
    void rejectsEveryNonRunningRunBeforeReleaseOrCatalogReads(TestRunStatus status) {
        when(runs.find(RUN)).thenReturn(change(run, Projection.class, "status", status));
        safeLoad(FailureCode.RUN_NOT_EXECUTING);
        verifyNoInteractions(releases, agents, cases, catalogs);
    }

    @ParameterizedTest
    @EnumSource(value = TestCaseRunStatus.class, mode = EnumSource.Mode.EXCLUDE, names = "EXECUTING")
    void rejectsEveryNonExecutingCaseBeforeCatalogReads(TestCaseRunStatus status) {
        when(cases.findCase(CASE_RUN)).thenReturn(change(caseRun, CaseRun.class, "status", status));
        safeLoad(FailureCode.CASE_NOT_EXECUTING);
        verifyNoInteractions(catalogs);
    }

    @Test
    void foreignReviewerCannotReadCaseOrVerifiedCatalog() {
        ReviewerContext foreign = reviewer(OTHER, REVIEWER.actorId(), REVIEWER.role(),
                REVIEWER.sessionId(), true, true);
        assertReviewerFailure(() -> service.load(RUN, CASE_RUN, foreign),
                RejectionCode.REVIEWER_WORKSPACE_MISMATCH);
        verifyNoInteractions(cases, catalogs);
    }

    @ParameterizedTest
    @MethodSource("invalidRunBindings")
    void rejectsMissingOrMalformedRunBindingBeforeReleaseRead(String field, Object value) {
        when(runs.find(RUN)).thenReturn(field.equals("missing") ? null : change(run, Projection.class, field, value));
        safeLoad(FailureCode.RUN_BINDING_INVALID);
        verifyNoInteractions(releases, agents, cases, catalogs);
    }

    @ParameterizedTest
    @MethodSource("invalidCaseBindings")
    void rejectsMissingOrForeignCaseBindingBeforeCatalogRead(String field, Object value) {
        when(cases.findCase(CASE_RUN)).thenReturn(field.equals("missing")
                ? null : change(caseRun, CaseRun.class, field, value));
        safeLoad(FailureCode.CASE_RUN_BINDING_INVALID);
        verifyNoInteractions(catalogs);
    }

    @ParameterizedTest
    @ValueSource(strings = {"run", "case"})
    void missingLiveStatusNeverProducesAUsableSource(String source) {
        if (source.equals("run")) {
            when(runs.find(RUN)).thenReturn(change(run, Projection.class, "status", null));
            safeLoad(FailureCode.RUN_NOT_EXECUTING);
            verifyNoInteractions(releases, agents, cases, catalogs);
        } else {
            when(cases.findCase(CASE_RUN)).thenReturn(change(caseRun, CaseRun.class, "status", null));
            safeLoad(FailureCode.CASE_NOT_EXECUTING);
            verifyNoInteractions(catalogs);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "id", "agentId"})
    void incompleteInitialReleaseIdentityStopsBeforeWorkspaceOrCaseReads(String field) {
        switch (field) {
            case "missing" -> when(releases.getRequired(RELEASE)).thenReturn(null);
            case "id" -> when(release.getId()).thenReturn(OTHER);
            case "agentId" -> when(release.getAgentId()).thenReturn(null);
            default -> throw new AssertionError(field);
        }
        safeLoad(FailureCode.RELEASE_BINDING_INVALID);
        verifyNoInteractions(agents, cases, catalogs);
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "id", "workspaceId"})
    void incompleteActualWorkspaceBindingStopsBeforeCaseDisclosure(String field) {
        switch (field) {
            case "missing" -> when(agents.getRequired(AGENT)).thenReturn(null);
            case "id" -> when(agent.getId()).thenReturn(OTHER);
            case "workspaceId" -> when(agent.getWorkspaceId()).thenReturn(null);
            default -> throw new AssertionError(field);
        }
        safeLoad(FailureCode.WORKSPACE_BINDING_INVALID);
        verifyNoInteractions(cases, catalogs);
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "releaseId", "agentArtifactFingerprint", "releaseFingerprint",
            "releaseToolBindings", "declaredTools", "inputSchemas", "semanticOnly"})
    void rejectsMismatchedOrIncompleteCatalogWithoutAcceptingLegacyEmptyMetadata(String field) {
        SourceBoundCatalog invalid = switch (field) {
            case "missing" -> null;
            case "releaseId" -> change(catalog, SourceBoundCatalog.class, field, OTHER);
            case "agentArtifactFingerprint", "releaseFingerprint" -> change(catalog, SourceBoundCatalog.class, field, HASH);
            case "releaseToolBindings", "declaredTools" -> change(catalog, SourceBoundCatalog.class, field, List.of());
            case "inputSchemas" -> change(catalog, SourceBoundCatalog.class, field, json.createObjectNode());
            case "semanticOnly" -> new SourceBoundCatalog(RELEASE, "1.1", ARTIFACT, FINGERPRINT,
                    catalog.serverToolCatalogHash(), catalog.semanticCatalog());
            default -> throw new AssertionError(field);
        };
        when(catalogs.load(RELEASE, REVIEWER.actorId())).thenReturn(invalid);
        safeLoad(FailureCode.CATALOG_BINDING_INVALID);
        var order = inOrder(releases, catalogs);
        order.verify(releases).getRequired(RELEASE);
        order.verify(catalogs).load(RELEASE, REVIEWER.actorId());
        order.verifyNoMoreInteractions();
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "id", "agentId", "schemaVersion", "artifact", "fingerprint"})
    void verifiedReleaseReadMustStillMatchAuthorizedIdentityAndCatalog(String field) {
        AgentReleaseEntity changed = releaseEntity();
        switch (field) {
            case "missing" -> changed = null;
            case "id" -> when(changed.getId()).thenReturn(OTHER);
            case "agentId" -> when(changed.getAgentId()).thenReturn(OTHER);
            case "schemaVersion" -> when(changed.getManifestSchemaVersion()).thenReturn("1.0");
            case "artifact" -> when(changed.getAgentArtifactFingerprint()).thenReturn(HASH);
            case "fingerprint" -> when(changed.getReleaseFingerprint()).thenReturn(HASH);
            default -> throw new AssertionError(field);
        }
        when(releases.getRequired(RELEASE)).thenReturn(release, changed);
        safeLoad(FailureCode.RELEASE_BINDING_INVALID);
    }

    @ParameterizedTest
    @ValueSource(strings = {"missingTimestamp", "missingState", "draft"})
    void rejectsReleaseWithoutAnalysisEvidence(String kind) {
        switch (kind) {
            case "missingTimestamp" -> when(release.getAnalyzedAt()).thenReturn(null);
            case "missingState" -> when(release.getLifecycleState()).thenReturn(null);
            case "draft" -> when(release.getLifecycleState()).thenReturn(ReleaseLifecycleState.DRAFT);
            default -> throw new AssertionError(kind);
        }
        safeLoad(FailureCode.RELEASE_NOT_ANALYZED);
    }

    @ParameterizedTest
    @ValueSource(strings = {"missingManifest", "scalarManifest", "schemaVersion", "missingPurpose",
            "purposeMismatch", "numericPurpose", "missingWorkflow", "emptyStages", "duplicateStages",
            "wrongContextSource", "missingNormal", "duplicateNormal", "unknownNormal", "inputSchema",
            "inputBinding", "outputSchema", "operation", "adapterKey", "normalClassification",
            "missingServer", "serverVersion", "missingHuman", "humanExecutable", "humanBoundary",
            "humanOutputSchema"})
    void rejectsIncompleteOrMismatchedClosedDeclarations(String kind) {
        ObjectNode firstTool = (ObjectNode) manifest.at("/tools/0");
        ObjectNode human = (ObjectNode) manifest.at("/serverToolCatalog/tools/0");
        switch (kind) {
            case "missingManifest" -> when(release.getManifestJson()).thenReturn(null);
            case "scalarManifest" -> when(release.getManifestJson()).thenReturn(JsonNodeFactory.instance.textNode(CANARY));
            case "schemaVersion" -> manifest.put("schemaVersion", "1.0");
            case "missingPurpose" -> manifest.remove("businessPurpose");
            case "purposeMismatch" -> ((ObjectNode) manifest.path("businessPurpose")).put("code", "OTHER_PURPOSE");
            case "numericPurpose" -> ((ObjectNode) manifest.path("businessPurpose")).put("code", 42);
            case "missingWorkflow" -> manifest.remove("businessWorkflow");
            case "emptyStages" -> ((ArrayNode) manifest.at("/businessWorkflow/allowedStages")).removeAll();
            case "duplicateStages" -> ((ArrayNode) manifest.at("/businessWorkflow/allowedStages")).add("DOCUMENT_REVIEW");
            case "wrongContextSource" -> ((ObjectNode) manifest.path("businessWorkflow")).put("contextSourceTool", "DOCUMENT_READER");
            case "missingNormal" -> ((ArrayNode) manifest.path("tools")).remove(0);
            case "duplicateNormal" -> ((ArrayNode) manifest.path("tools")).add(firstTool.deepCopy());
            case "unknownNormal" -> firstTool.put("name", "UNDECLARED_TOOL");
            case "inputSchema" -> firstTool.putNull("inputSchema");
            case "inputBinding" -> ((ObjectNode) firstTool.path("inputSchema")).put("additionalProperties", true);
            case "outputSchema" -> firstTool.putNull("outputSchema");
            case "operation" -> firstTool.put("operation", "WRITE");
            case "adapterKey" -> firstTool.remove("adapterKey");
            case "normalClassification" -> firstTool.remove("dataClassifications");
            case "missingServer" -> manifest.remove("serverToolCatalog");
            case "serverVersion" -> ((ObjectNode) manifest.path("serverToolCatalog")).put("version", " ");
            case "missingHuman" -> ((ArrayNode) manifest.at("/serverToolCatalog/tools")).removeAll();
            case "humanExecutable" -> human.put("agentExecutable", true);
            case "humanBoundary" -> human.put("executionBoundary", "AGENT_ALLOWED");
            case "humanOutputSchema" -> human.putNull("outputSchema");
            default -> throw new AssertionError(kind);
        }
        safeLoad(FailureCode.SOURCE_CONTENT_INVALID);
    }

    @ParameterizedTest
    @ValueSource(strings = {"run", "release", "agent", "case", "catalog", "verifiedRelease", "manifest"})
    void unexpectedOwnerFailuresAreSanitizedWithoutRawCauseOrLogging(String phase, CapturedOutput output) {
        RuntimeException raw = new IllegalStateException(CANARY);
        switch (phase) {
            case "run" -> when(runs.find(RUN)).thenThrow(raw);
            case "release" -> when(releases.getRequired(RELEASE)).thenThrow(raw);
            case "agent" -> when(agents.getRequired(AGENT)).thenThrow(raw);
            case "case" -> when(cases.findCase(CASE_RUN)).thenThrow(raw);
            case "catalog" -> when(catalogs.load(RELEASE, REVIEWER.actorId())).thenThrow(raw);
            case "verifiedRelease" -> when(releases.getRequired(RELEASE)).thenReturn(release).thenThrow(raw);
            case "manifest" -> when(release.getManifestJson()).thenThrow(raw);
            default -> throw new AssertionError(phase);
        }
        safeLoad(FailureCode.SOURCE_UNAVAILABLE);
        assertThat(output.getAll()).doesNotContain(CANARY);
    }

    @Test
    void preservesExistingSafeOwnerBusinessExceptionIdentity() {
        BusinessException owner = new BusinessException(ErrorCode.EVIDENCE_INCOMPLETE,
                "Baseline source evidence is incomplete");
        when(cases.findCase(CASE_RUN)).thenThrow(owner);
        assertThat(catchThrowable(() -> service.load(RUN, CASE_RUN, REVIEWER))).isSameAs(owner);
        verifyNoInteractions(catalogs);
    }

    @Test
    void preservesExistingLifecyclePolicyExceptionIdentity() {
        LifecyclePolicyException owner = catchThrowableOfType(LifecyclePolicyException.class,
                () -> SafetyContractLifecyclePolicy.requireReviewerContext(null, WORKSPACE));
        when(catalogs.load(RELEASE, REVIEWER.actorId())).thenThrow(owner);
        assertThat(catchThrowable(() -> service.load(RUN, CASE_RUN, REVIEWER))).isSameAs(owner);
    }

    private AgentReleaseEntity releaseEntity() {
        AgentReleaseEntity result = mock(AgentReleaseEntity.class);
        when(result.getId()).thenReturn(RELEASE);
        when(result.getAgentId()).thenReturn(AGENT);
        when(result.getManifestSchemaVersion()).thenReturn("1.1");
        when(result.getAgentArtifactFingerprint()).thenReturn(ARTIFACT);
        when(result.getReleaseFingerprint()).thenReturn(FINGERPRINT);
        when(result.getBusinessPurpose()).thenReturn(PURPOSE);
        when(result.getLifecycleState()).thenReturn(ReleaseLifecycleState.ANALYZED);
        when(result.getAnalyzedAt()).thenReturn(Instant.parse("2026-09-08T00:00:00Z"));
        // Deliberately return the same mutable owner JSON to exercise the source copy boundary.
        when(result.getManifestJson()).thenReturn(manifest);
        return result;
    }

    private SourceBoundCatalog fixtureCatalog() {
        CanonicalJsonService canonical = new CanonicalJsonService(json);
        DigestService digests = new DigestService();
        FingerprintService fingerprints = new FingerprintService(canonical, digests, json);
        String serverHash = fingerprints.fingerprint(manifest, null).componentDigests().get("serverToolCatalogHash");
        ReleaseService fixtureOwner = mock(ReleaseService.class);
        when(fixtureOwner.toolCatalog(RELEASE, REVIEWER.actorId())).thenReturn(new ToolCatalogResponse(
                RELEASE, "1.1", ARTIFACT, FINGERPRINT, serverHash,
                manifest.path("tools"), manifest.path("serverToolCatalog")));
        return new ReleaseToolCatalogContractAdapter(fixtureOwner, canonical, digests, json)
                .load(RELEASE, REVIEWER.actorId());
    }

    private ObjectNode expectedDeclarations() {
        ObjectNode result = json.createObjectNode();
        for (String field : List.of("businessPurpose", "businessWorkflow", "tools", "serverToolCatalog")) {
            result.set(field, manifest.path(field).deepCopy());
        }
        return result;
    }

    private static ReviewerContext reviewer(UUID workspace, String actor, String role, String session,
            boolean authenticated, boolean csrfVerified) {
        return new ReviewerContext(workspace, actor, role, session, authenticated, csrfVerified, false);
    }

    private static Stream<Arguments> invalidReviewers() {
        return Stream.of(
                Arguments.of(null, RejectionCode.REVIEWER_CONTEXT_REQUIRED),
                Arguments.of(reviewer(null, "actor", "AI_SECURITY_REVIEWER", "session", true, true),
                        RejectionCode.REVIEWER_WORKSPACE_MISMATCH),
                Arguments.of(reviewer(OTHER, "actor", "AI_SECURITY_REVIEWER", "session", true, true),
                        RejectionCode.REVIEWER_WORKSPACE_MISMATCH),
                Arguments.of(reviewer(WORKSPACE, null, "AI_SECURITY_REVIEWER", "session", true, true),
                        RejectionCode.INVALID_REVIEWER_IDENTITY),
                Arguments.of(reviewer(WORKSPACE, " actor ", "AI_SECURITY_REVIEWER", "session", true, true),
                        RejectionCode.INVALID_REVIEWER_IDENTITY),
                Arguments.of(reviewer(WORKSPACE, "a".repeat(121), "AI_SECURITY_REVIEWER", "session", true, true),
                        RejectionCode.INVALID_REVIEWER_IDENTITY),
                Arguments.of(reviewer(WORKSPACE, "actor", "OTHER_ROLE", "session", true, true),
                        RejectionCode.REVIEWER_ROLE_REQUIRED),
                Arguments.of(reviewer(WORKSPACE, "actor", "AI_SECURITY_REVIEWER", null, true, true),
                        RejectionCode.INVALID_REVIEWER_SESSION),
                Arguments.of(reviewer(WORKSPACE, "actor", "AI_SECURITY_REVIEWER", " ", true, true),
                        RejectionCode.INVALID_REVIEWER_SESSION),
                Arguments.of(reviewer(WORKSPACE, "actor", "AI_SECURITY_REVIEWER", " session ", true, true),
                        RejectionCode.INVALID_REVIEWER_SESSION),
                Arguments.of(reviewer(WORKSPACE, "actor", "AI_SECURITY_REVIEWER", "s".repeat(201), true, true),
                        RejectionCode.INVALID_REVIEWER_SESSION),
                Arguments.of(reviewer(WORKSPACE, "actor", "AI_SECURITY_REVIEWER", "session", false, true),
                        RejectionCode.REVIEWER_AUTHENTICATION_REQUIRED),
                Arguments.of(reviewer(WORKSPACE, "actor", "AI_SECURITY_REVIEWER", "session", true, false),
                        RejectionCode.REVIEWER_CSRF_REQUIRED));
    }

    private static Stream<Arguments> invalidRunBindings() {
        return Stream.of(
                Arguments.of("missing", null), Arguments.of("id", OTHER),
                Arguments.of("releaseId", null), Arguments.of("mode", null),
                Arguments.of("agentArtifactFingerprint", null),
                Arguments.of("releaseFingerprint", "sha256:invalid"),
                Arguments.of("fixtureVersion", " "), Arguments.of("fixtureDigest", null));
    }

    private static Stream<Arguments> invalidCaseBindings() {
        return Stream.of(
                Arguments.of("missing", null), Arguments.of("id", OTHER),
                Arguments.of("testRunId", OTHER), Arguments.of("testCaseId", null),
                Arguments.of("trialIndex", -1), Arguments.of("variantHash", "sha256:invalid"));
    }

    private <T> T change(T value, Class<T> type, String field, Object replacement) {
        ObjectNode node = json.valueToTree(value);
        node.set(field, json.valueToTree(replacement));
        return json.treeToValue(node, type);
    }

    private void assertReviewerFailure(org.assertj.core.api.ThrowableAssert.ThrowingCallable action,
            RejectionCode code) {
        LifecyclePolicyException failure = catchThrowableOfType(LifecyclePolicyException.class, action);
        assertThat(failure).isNotNull();
        assertThat(failure.code()).isEqualTo(code);
        assertThat(failure.getMessage()).isEqualTo(code.safeMessage()).doesNotContain(CANARY);
        assertThat(failure.getCause()).isNull();
    }

    private void safeLoad(FailureCode code) {
        safe(() -> service.load(RUN, CASE_RUN, REVIEWER), code);
    }

    private void safe(org.assertj.core.api.ThrowableAssert.ThrowingCallable action, FailureCode code) {
        BaselineSourceException failure = catchThrowableOfType(BaselineSourceException.class, action);
        assertThat(failure).isNotNull();
        assertThat(failure.code()).isEqualTo(code);
        assertThat(failure.getMessage()).isEqualTo(code.name()).doesNotContain(CANARY);
        assertThat(failure.getCause()).isNull();
        assertThat(failure.getSuppressed()).isEmpty();
        failure.addSuppressed(new IllegalStateException(CANARY));
        assertThat(failure.getSuppressed()).isEmpty();
    }
}
