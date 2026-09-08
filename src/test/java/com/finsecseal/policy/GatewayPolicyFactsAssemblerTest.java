package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEvaluationReason.FIELD_SCOPE_VIOLATION;
import static com.finsecseal.policy.PolicyEvaluationReason.CASE_SCOPE_VIOLATION;
import static com.finsecseal.policy.PolicyEvaluationReason.CONTEXT_INTEGRITY_FAILURE;
import static com.finsecseal.policy.PolicyEvaluationReason.CUSTOMER_SCOPE_VIOLATION;
import static com.finsecseal.policy.PolicyEvaluationReason.DOCUMENT_SCOPE_VIOLATION;
import static com.finsecseal.policy.PolicyEvaluationReason.EXTERNAL_EGRESS_DENIED;
import static com.finsecseal.policy.PolicyEvaluationReason.HUMAN_ONLY_ACTION;
import static com.finsecseal.policy.PolicyEvaluationReason.INVALID_WORKFLOW_STAGE;
import static com.finsecseal.policy.PolicyEvaluationReason.OPERATION_NOT_ALLOWED;
import static com.finsecseal.policy.PolicyEvaluationReason.RECORD_LIMIT_EXCEEDED;
import static com.finsecseal.policy.PolicyEvaluationReason.TOOL_NOT_ALLOWED;
import static com.finsecseal.policy.PolicyEvaluationStage.CARDINALITY;
import static com.finsecseal.policy.PolicyEvaluationStage.BUSINESS_CONTEXT;
import static com.finsecseal.policy.PolicyEvaluationStage.EGRESS;
import static com.finsecseal.policy.PolicyEvaluationStage.FIELD_SCOPE;
import static com.finsecseal.policy.PolicyEvaluationStage.HUMAN_BOUNDARY;
import static com.finsecseal.policy.PolicyEvaluationStage.OPERATION;
import static com.finsecseal.policy.PolicyEvaluationStage.OBJECT_SCOPE;
import static com.finsecseal.policy.PolicyEvaluationStage.TOOL;
import static com.finsecseal.policy.PolicyEvaluationStage.WORKFLOW;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.finsecseal.common.domain.Sensitivity;
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
import com.finsecseal.evidence.TestRunDto.Projection;
import com.finsecseal.evidence.TestRunPersistenceDto.CaseRun;
import com.finsecseal.evidence.TestRunPersistenceService;
import com.finsecseal.evidence.TestRunProjectionService;
import com.finsecseal.platform.contract.ContractPersistenceService;
import com.finsecseal.platform.contract.ContractPersistenceService.ApprovedContract;
import com.finsecseal.platform.contract.ContractPersistenceService.Version;
import com.finsecseal.policy.GatewayApprovedPolicySourceService.ApprovedPolicySource;
import com.finsecseal.policy.GatewayPolicyFactsAssembler.FactAssemblyException;
import com.finsecseal.policy.GatewayPolicyFactsAssembler.FailureCode;
import com.finsecseal.policy.EnforcePolicyPostCallDecision.OperationalReason;
import com.finsecseal.policy.EnforcePolicyPostCallDecision.PostCallCheck;
import com.finsecseal.policy.EnforcePolicyPostCallFacts.CatalogOutputField;
import com.finsecseal.policy.EnforcePolicyPostCallFacts.OutputValueType;
import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;
import com.finsecseal.policy.PolicyObjectScopeFacts.DocumentOwnership;
import com.finsecseal.policy.PolicyObjectScopeFacts.ObjectScopePolicy;
import com.finsecseal.policy.PolicyToolAuthorizationFacts.CatalogTool;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.runtime.ToolProposalValidator;
import com.finsecseal.sandbox.tool.CustomerDataReadToolAdapter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.NullNode;
import tools.jackson.databind.node.ObjectNode;
import tools.jackson.databind.node.StringNode;

/** Component composition with mocked owner projections; not database approval or runtime enforcement evidence. */
@ExtendWith(OutputCaptureExtension.class)
class GatewayPolicyFactsAssemblerTest {
    private static final String CUSTOMER_TOOL = "CUSTOMER_DATA_READ";
    private static final String HUMAN_TOOL = "LOAN_DECISION_UPDATE";
    private static final String CASE = "CASE-1001";
    private static final String DOCUMENT = "DOC-1001";
    private static final String PURPOSE = "LOAN_DOCUMENT_COMPLETENESS_REVIEW";
    private static final String CUSTOMER_CANARY = "FACT-ASSEMBLY-PRIVATE-CUSTOMER-CANARY";
    private static final String ERROR_CANARY = "FACT-ASSEMBLY-RAW-SOURCE-SQL-CANARY";
    private static final String HASH = "sha256:" + "a".repeat(64);
    private static final String ARTIFACT = "sha256:" + "b".repeat(64);
    private static final String FINGERPRINT = "sha256:" + "c".repeat(64);
    private final ObjectMapper json = new ObjectMapper();
    private final PolicyFieldScopeEvaluator fields = new PolicyFieldScopeEvaluator();
    private final PolicyCardinalityEvaluator cardinality = new PolicyCardinalityEvaluator();
    private final PolicyHumanBoundaryEvaluator human = new PolicyHumanBoundaryEvaluator();
    private final PolicyToolAuthorizationEvaluator authorization = new PolicyToolAuthorizationEvaluator();
    private final PolicyEgressEvaluator egress = new PolicyEgressEvaluator();
    private final PolicyWorkflowEvaluator workflow = new PolicyWorkflowEvaluator();
    private final PolicyBusinessContextEvaluator business = new PolicyBusinessContextEvaluator();
    private final PolicyObjectScopeEvaluator objects = new PolicyObjectScopeEvaluator();
    private final EnforcePolicyPostCallResponseGuard responseGuard = new EnforcePolicyPostCallResponseGuard();
    private final TestRunProjectionService runs = mock(TestRunProjectionService.class);
    private final ContractPersistenceService contracts = mock(ContractPersistenceService.class);
    private final TestRunPersistenceService cases = mock(TestRunPersistenceService.class);
    private final ReleaseToolCatalogContractAdapter catalogs = mock(ReleaseToolCatalogContractAdapter.class);
    private JdbcTemplate jdbc;
    private CustomerDataReadToolAdapter adapter;
    private ToolProposalValidator proposals;
    private GatewayPolicyFactsAssembler assembler;
    private ApprovedPolicySource source;
    private ObjectNode ownerPolicy;

    @BeforeEach
    void setup() throws Exception {
        source = approvedSourceFixture();
        clearInvocations(runs, contracts, cases, catalogs);
        jdbc = mock(JdbcTemplate.class);
        adapter = spy(new CustomerDataReadToolAdapter(jdbc, json));
        proposals = spy(new ToolProposalValidator(json, List.of(adapter)));
        assembler = new GatewayPolicyFactsAssembler(proposals);
        clearInvocations(adapter); // Measure assembly calls after the validator's fixture indexing.
    }

    @AfterEach
    void assemblyNeverExecutesSqlOrReloadsOwnerSources(CapturedOutput output) {
        verify(adapter, never()).execute(any(), any());
        verifyNoInteractions(jdbc, runs, contracts, cases, catalogs);
        assertThat(output.getAll()).doesNotContain(CUSTOMER_CANARY, ERROR_CANARY);
    }

    @Test
    void oneCustomerAndBothAllowedFieldsProducePassingStageFactsWithoutCustomerIdentity() {
        var result = assembler.customerDataRead(source, proposal(arguments()));

        assertThat(result.fieldScope().requestedTool()).isEqualTo(CUSTOMER_TOOL);
        assertThat(result.fieldScope().requestedFields()).contains(List.of("employmentStatus", "incomeBand"));
        assertThat(result.cardinality().normalizedRequestedRecordCount()).isEqualTo(1);
        assertThat(fields.evaluate(FIELD_SCOPE, result.fieldScope())).isEqualTo(StageOutcome.pass(FIELD_SCOPE));
        assertThat(cardinality.evaluate(CARDINALITY, result.cardinality())).isEqualTo(StageOutcome.pass(CARDINALITY));
        assertThat(result.toString()).doesNotContain(CUSTOMER_CANARY, "customerIds", ERROR_CANARY);
        verify(proposals).validate(any());
        verify(adapter).validateArguments(any());
    }

    @ParameterizedTest
    @ValueSource(strings = {"accountNumber", "unknownField", "IncomeBand", "incomeBand ", " employmentStatus"})
    void forbiddenUnknownAndAlteredFieldsRemainExactAndReachTheFieldEvaluator(String requested) {
        ObjectNode arguments = arguments();
        arguments.putArray("fields").add("incomeBand").add(requested);

        var result = assembler.customerDataRead(source, proposal(arguments));

        assertThat(result.fieldScope().requestedFields()).contains(List.of("incomeBand", requested));
        assertThat(fields.evaluate(FIELD_SCOPE, result.fieldScope()))
                .isEqualTo(StageOutcome.deny(FIELD_SCOPE, FIELD_SCOPE_VIOLATION));
        assertThat(cardinality.evaluate(CARDINALITY, result.cardinality())).isEqualTo(StageOutcome.pass(CARDINALITY));
    }

    @Test
    void twoDistinctCustomersRetainCountTwoAndReachCardinalityDenial() {
        ObjectNode arguments = arguments();
        ((ArrayNode) arguments.path("customerIds")).add("ANOTHER-CUSTOMER");

        var result = assembler.customerDataRead(source, proposal(arguments));

        assertThat(result.cardinality().normalizedRequestedRecordCount()).isEqualTo(2);
        assertThat(cardinality.evaluate(CARDINALITY, result.cardinality()))
                .isEqualTo(StageOutcome.deny(CARDINALITY, RECORD_LIMIT_EXCEEDED));
        // Applicant identity and Object Scope must be established by their separate preceding stage.
        assertThat(result.toString()).doesNotContain(CUSTOMER_CANARY, "ANOTHER-CUSTOMER");
    }

    @Test
    void humanOnlyOperationRemainsCatalogKnownOutsideTheAgentAllowlist() {
        for (JsonNode tool : source.policy().path("allowedTools")) {
            assertThat(tool.stringValue()).isNotEqualTo(HUMAN_TOOL);
        }

        var facts = assembler.humanBoundary(source, HUMAN_TOOL);

        assertThat(facts.isRequestedToolCatalogKnown()).isTrue();
        assertThat(facts.catalogTools()).contains(CUSTOMER_TOOL, HUMAN_TOOL);
        assertThat(human.evaluate(HUMAN_BOUNDARY, facts)).isEqualTo(StageOutcome.deny(HUMAN_BOUNDARY, HUMAN_ONLY_ACTION));
        assertThat(human.evaluate(HUMAN_BOUNDARY, assembler.humanBoundary(source, CUSTOMER_TOOL)))
                .isEqualTo(StageOutcome.pass(HUMAN_BOUNDARY));
        verifyNoInteractions(proposals);
    }

    @Test
    void unknownWellFormedHumanToolCannotBypassTheToolStageWithAnImplicitPass() {
        var facts = assembler.humanBoundary(source, "UNKNOWN_TOOL");

        assertThat(facts.requestedTool()).isEqualTo("UNKNOWN_TOOL");
        assertThat(facts.isRequestedToolCatalogKnown()).isFalse();
        assertThatThrownBy(() -> human.evaluate(HUMAN_BOUNDARY, facts))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("Tool stage");
        verifyNoInteractions(proposals);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "customer_data_read", "CUSTOMER_DATA_READ ", "BAD/TOOL", "🦀"})
    void malformedToolNamesAreRequestFailuresForBothEntrypoints(String tool) {
        safe(() -> assembler.customerDataRead(source, new ToolProposal(tool, arguments())), FailureCode.INVALID_REQUEST);
        safe(() -> assembler.humanBoundary(source, tool), FailureCode.INVALID_REQUEST);
        verifyNoInteractions(proposals);
    }

    @Test
    void toolNameLimitIsEightyCharactersWithoutNormalizingUnsupportedTools() {
        String eighty = "A".repeat(80);
        safe(() -> assembler.customerDataRead(source, new ToolProposal(eighty, arguments())), FailureCode.UNSUPPORTED_TOOL);
        var humanFacts = assembler.humanBoundary(source, eighty);
        assertThat(humanFacts.requestedTool()).isEqualTo(eighty);
        assertThatThrownBy(() -> human.evaluate(HUMAN_BOUNDARY, humanFacts)).isInstanceOf(IllegalStateException.class);
        safe(() -> assembler.customerDataRead(source, new ToolProposal(eighty + "A", arguments())), FailureCode.INVALID_REQUEST);
        safe(() -> assembler.humanBoundary(source, eighty + "A"), FailureCode.INVALID_REQUEST);
    }

    @ParameterizedTest
    @ValueSource(strings = {"DOCUMENT_READER", "LOAN_DECISION_UPDATE", "UNKNOWN_TOOL"})
    void wellFormedNonCustomerToolIsUnsupportedBeforeBValidation(String tool) {
        safe(() -> assembler.customerDataRead(source, new ToolProposal(tool, arguments())), FailureCode.UNSUPPORTED_TOOL);
        verifyNoInteractions(proposals);
    }

    @Test
    void nullInputsAndNonObjectArgumentsFailWithoutFacts() {
        safe(() -> assembler.customerDataRead(null, proposal(arguments())), FailureCode.INVALID_POLICY_SOURCE);
        safe(() -> assembler.humanBoundary(null, HUMAN_TOOL), FailureCode.INVALID_POLICY_SOURCE);
        safe(() -> assembler.customerDataRead(source, null), FailureCode.INVALID_REQUEST);
        safe(() -> assembler.customerDataRead(source, proposal(null)), FailureCode.INVALID_REQUEST);
        for (JsonNode invalid : List.of(json.nullNode(), json.createArrayNode(), StringNode.valueOf(ERROR_CANARY))) {
            safe(() -> assembler.customerDataRead(source, proposal(invalid)), FailureCode.INVALID_REQUEST);
        }
    }

    @ParameterizedTest(name = "{0}: {1}")
    @MethodSource("malformedArrays")
    void realAdapterRejectsMalformedArraysAndAssemblerRejectsDuplicates(String field, String problem) {
        ObjectNode arguments = arguments();
        switch (problem) {
            case "missing" -> arguments.remove(field);
            case "null" -> arguments.putNull(field);
            case "non-array" -> arguments.put(field, ERROR_CANARY);
            case "empty" -> arguments.putArray(field);
            case "number" -> arguments.putArray(field).add(7);
            case "boolean" -> arguments.putArray(field).add(true);
            case "object" -> arguments.putArray(field).addObject().put("private", ERROR_CANARY);
            case "null-member" -> arguments.putArray(field).addNull();
            case "blank" -> arguments.putArray(field).add(" ");
            case "81-characters" -> arguments.putArray(field).add("x".repeat(81));
            case "21-entries" -> {
                var values = arguments.putArray(field);
                for (int index = 0; index < 21; index++) values.add("value-" + index);
            }
            case "duplicate" -> arguments.putArray(field).add("duplicate").add("duplicate");
            default -> throw new IllegalArgumentException(problem);
        }

        safe(() -> assembler.customerDataRead(source, proposal(arguments)), FailureCode.INVALID_REQUEST);
        verify(adapter).validateArguments(any());
    }

    @ParameterizedTest
    @ValueSource(strings = {"customerIds", "fields"})
    void realAdapterAcceptsTwentyDistinctEntriesAndEightyCharacterValues(String field) {
        ObjectNode arguments = arguments();
        var values = arguments.putArray(field);
        for (int index = 0; index < 20; index++) values.add(String.format("%02d", index) + "x".repeat(78));

        var result = assembler.customerDataRead(source, proposal(arguments));

        if (field.equals("customerIds")) {
            assertThat(result.cardinality().normalizedRequestedRecordCount()).isEqualTo(20);
            assertThat(cardinality.evaluate(CARDINALITY, result.cardinality()))
                    .isEqualTo(StageOutcome.deny(CARDINALITY, RECORD_LIMIT_EXCEEDED));
        } else {
            assertThat(result.fieldScope().requestedFields().orElseThrow()).hasSize(20)
                    .allMatch(value -> value.length() == 80);
            assertThat(fields.evaluate(FIELD_SCOPE, result.fieldScope()))
                    .isEqualTo(StageOutcome.deny(FIELD_SCOPE, FIELD_SCOPE_VIOLATION));
        }
        verify(adapter).validateArguments(any());
    }

    @ParameterizedTest
    @ValueSource(strings = {"unused", "namespace", "currentApplicant", "humanApprovalPresent"})
    void extraArgumentsCannotSupplyTrustedContextOrApproval(String name) {
        ObjectNode arguments = arguments().put(name, ERROR_CANARY);
        safe(() -> assembler.customerDataRead(source, proposal(arguments)), FailureCode.INVALID_REQUEST);
        verify(adapter).validateArguments(any());
    }

    @Test
    void realBSerializedSizeLimitRejectsBeforeAdapterValidation() {
        ObjectNode arguments = arguments().put("padding", ERROR_CANARY.repeat(1500));
        assertThat(json.writeValueAsBytes(arguments).length).isGreaterThan(32 * 1024);

        safe(() -> assembler.customerDataRead(source, proposal(arguments)), FailureCode.INVALID_REQUEST);

        verify(proposals).validate(any());
        verify(adapter, never()).validateArguments(any());
    }

    @ParameterizedTest
    @ValueSource(strings = {"policy-null", "policy-array", "field-map-missing", "field-map-array", "field-tool-missing",
            "field-tool-array", "allowed-missing", "allowed-null", "allowed-string", "allowed-empty", "allowed-number",
            "allowed-blank", "allowed-duplicate", "allowed-unknown", "deny-missing", "deny-false", "deny-string",
            "cardinality-missing", "cardinality-array", "cardinality-tool-missing", "cardinality-tool-array",
            "limit-missing", "limit-null", "limit-zero", "limit-negative", "limit-fractional", "limit-string",
            "limit-boolean", "limit-overflow", "limit-truncates-to-one"})
    void malformedRequiredCustomerPolicyProjectionNeverBecomesAnImplicitStagePass(String problem) {
        ObjectNode policy = (ObjectNode) source.policy();
        ObjectNode field = (ObjectNode) policy.at("/fieldPolicy/CUSTOMER_DATA_READ");
        ObjectNode count = (ObjectNode) policy.at("/cardinality/CUSTOMER_DATA_READ");
        JsonNode projected = policy;
        switch (problem) {
            case "policy-null" -> projected = null;
            case "policy-array" -> projected = json.createArrayNode();
            case "field-map-missing" -> policy.remove("fieldPolicy");
            case "field-map-array" -> policy.putArray("fieldPolicy");
            case "field-tool-missing" -> ((ObjectNode) policy.path("fieldPolicy")).remove(CUSTOMER_TOOL);
            case "field-tool-array" -> ((ObjectNode) policy.path("fieldPolicy")).putArray(CUSTOMER_TOOL);
            case "allowed-missing" -> field.remove("allowed");
            case "allowed-null" -> field.putNull("allowed");
            case "allowed-string" -> field.put("allowed", ERROR_CANARY);
            case "allowed-empty" -> field.putArray("allowed");
            case "allowed-number" -> field.putArray("allowed").add(1);
            case "allowed-blank" -> field.putArray("allowed").add(" ");
            case "allowed-duplicate" -> field.putArray("allowed").add("incomeBand").add("incomeBand");
            case "allowed-unknown" -> field.putArray("allowed").add(ERROR_CANARY);
            case "deny-missing" -> field.remove("denyUnknown");
            case "deny-false" -> field.put("denyUnknown", false);
            case "deny-string" -> field.put("denyUnknown", "true");
            case "cardinality-missing" -> policy.remove("cardinality");
            case "cardinality-array" -> policy.putArray("cardinality");
            case "cardinality-tool-missing" -> ((ObjectNode) policy.path("cardinality")).remove(CUSTOMER_TOOL);
            case "cardinality-tool-array" -> ((ObjectNode) policy.path("cardinality")).putArray(CUSTOMER_TOOL);
            case "limit-missing" -> count.remove("maxRequestedRecords");
            case "limit-null" -> count.putNull("maxRequestedRecords");
            case "limit-zero" -> count.put("maxRequestedRecords", 0);
            case "limit-negative" -> count.put("maxRequestedRecords", -1);
            case "limit-fractional" -> count.put("maxRequestedRecords", 1.5);
            case "limit-string" -> count.put("maxRequestedRecords", "1");
            case "limit-boolean" -> count.put("maxRequestedRecords", true);
            case "limit-overflow" -> count.put("maxRequestedRecords", new BigInteger("2147483648"));
            case "limit-truncates-to-one" -> count.put("maxRequestedRecords", new BigInteger("4294967297"));
            default -> throw new IllegalArgumentException(problem);
        }
        ApprovedPolicySource malformed = malformedSource(projected, source.catalog());

        safe(() -> assembler.customerDataRead(malformed, proposal(arguments())), FailureCode.INVALID_POLICY_SOURCE);
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "null", "array", "empty", "loan-missing", "wrong-mode", "null-mode",
            "boolean-mode", "unknown-tool"})
    void missingOrMalformedHumanOnlyMappingsNeverBecomeAnImplicitPass(String problem) {
        ObjectNode policy = (ObjectNode) source.policy();
        ObjectNode actions = (ObjectNode) policy.path("highImpactActions");
        switch (problem) {
            case "missing" -> policy.remove("highImpactActions");
            case "null" -> policy.putNull("highImpactActions");
            case "array" -> policy.putArray("highImpactActions");
            case "empty" -> actions.removeAll();
            case "loan-missing" -> { actions.remove(HUMAN_TOOL); actions.put("OTHER_TOOL", "HUMAN_ONLY"); }
            case "wrong-mode" -> actions.put(HUMAN_TOOL, ERROR_CANARY);
            case "null-mode" -> actions.putNull(HUMAN_TOOL);
            case "boolean-mode" -> actions.put(HUMAN_TOOL, true);
            case "unknown-tool" -> actions.put("UNKNOWN_TOOL", "HUMAN_ONLY");
            default -> throw new IllegalArgumentException(problem);
        }
        ApprovedPolicySource malformed = malformedSource(policy, source.catalog());

        safe(() -> assembler.humanBoundary(malformed, HUMAN_TOOL), FailureCode.INVALID_POLICY_SOURCE);
        safe(() -> assembler.toolAuthorization(malformed, HUMAN_TOOL, "UPDATE"), FailureCode.INVALID_POLICY_SOURCE);
        verifyNoInteractions(proposals, adapter);
    }

    @ParameterizedTest
    @ValueSource(strings = {"catalog-null", "semantic-null", "enabled-null", "customer-tool-missing", "output-field-missing"})
    void missingCatalogOrBrokenCustomerPolicyReferencesFailClosed(String problem) {
        SourceBoundCatalog binding = mock(SourceBoundCatalog.class);
        ContractValidationCatalog catalog = mock(ContractValidationCatalog.class);
        when(binding.semanticCatalog()).thenReturn(catalog);
        switch (problem) {
            case "catalog-null" -> binding = null;
            case "semantic-null" -> when(binding.semanticCatalog()).thenReturn(null);
            case "enabled-null" -> when(catalog.enabledReleaseTools()).thenReturn(null);
            case "customer-tool-missing" -> when(catalog.enabledReleaseTools()).thenReturn(List.of());
            case "output-field-missing" -> when(catalog.enabledReleaseTools())
                    .thenReturn(List.of(new EnabledTool(CUSTOMER_TOOL, List.of("incomeBand"))));
            default -> throw new IllegalArgumentException(problem);
        }
        ApprovedPolicySource malformed = malformedSource(source.policy(), binding);

        safe(() -> assembler.customerDataRead(malformed, proposal(arguments())), FailureCode.INVALID_POLICY_SOURCE);
    }

    @Test
    void humanCatalogRequiresMappingsForAllHighImpactNamesAndCannotInventLoanDecisionMembership() {
        ContractValidationCatalog original = source.catalog().semanticCatalog();
        for (List<String> highImpact : List.of(List.<String>of(), List.of(HUMAN_TOOL, "OTHER_HUMAN_ACTION"))) {
            var catalog = new SourceBoundCatalog(source.identity().releaseId(), "1.1", ARTIFACT, FINGERPRINT, HASH,
                    new ContractValidationCatalog(original.enabledReleaseTools(), highImpact));
            var malformed = malformedSource(source.policy(), catalog);
            safe(() -> assembler.humanBoundary(malformed, HUMAN_TOOL), FailureCode.INVALID_POLICY_SOURCE);
        }
    }

    @Test
    void validationReceivesADefensiveRequestAndReturnedCollectionsStayImmutable() {
        ObjectNode originalArguments = arguments();
        ObjectNode expectedArguments = (ObjectNode) originalArguments.deepCopy();
        ToolProposal original = proposal(originalArguments);
        AtomicReference<ToolProposal> received = new AtomicReference<>();
        doAnswer(invocation -> {
            ToolProposal snapshot = invocation.getArgument(0);
            received.set(snapshot);
            assertThat(snapshot).isNotSameAs(original);
            assertThat(snapshot.arguments()).isNotSameAs(originalArguments).isEqualTo(expectedArguments);
            ((ArrayNode) originalArguments.path("customerIds")).add("CHANGED-AFTER-SNAPSHOT");
            originalArguments.putArray("fields").add("accountNumber");
            return invocation.callRealMethod();
        }).when(proposals).validate(any());

        var result = assembler.customerDataRead(source, original);
        var humanFacts = assembler.humanBoundary(source, HUMAN_TOOL);
        ((ObjectNode) received.get().arguments()).putArray("fields").add("AFTER-RETURN");
        for (ObjectNode policy : List.of((ObjectNode) source.policy(), ownerPolicy)) {
            ((ObjectNode) policy.at("/fieldPolicy/CUSTOMER_DATA_READ")).putArray("allowed").add("accountNumber");
            ((ObjectNode) policy.at("/cardinality/CUSTOMER_DATA_READ")).put("maxRequestedRecords", 7);
            ((ObjectNode) policy.path("highImpactActions")).put(HUMAN_TOOL, "AGENT_ALLOWED");
        }

        assertThat(result.fieldScope().requestedFields()).contains(List.of("employmentStatus", "incomeBand"));
        assertThat(result.cardinality().normalizedRequestedRecordCount()).isEqualTo(1);
        assertThat(result.cardinality().requestedCardinalityPolicy().orElseThrow().maxRequestedRecords()).isEqualTo(1);
        assertThat(fields.evaluate(FIELD_SCOPE, result.fieldScope())).isEqualTo(StageOutcome.pass(FIELD_SCOPE));
        assertThat(cardinality.evaluate(CARDINALITY, result.cardinality())).isEqualTo(StageOutcome.pass(CARDINALITY));
        assertThat(human.evaluate(HUMAN_BOUNDARY, humanFacts)).isEqualTo(StageOutcome.deny(HUMAN_BOUNDARY, HUMAN_ONLY_ACTION));
        assertThatThrownBy(() -> result.fieldScope().requestedFields().orElseThrow().add("x"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> result.fieldScope().catalogSchemas().clear()).isInstanceOf(UnsupportedOperationException.class);
        result.fieldScope().catalogSchemas().forEach(schema -> assertThatThrownBy(() -> schema.outputFields().add("x"))
                .isInstanceOf(UnsupportedOperationException.class));
        assertThatThrownBy(() -> result.fieldScope().fieldPolicies().clear()).isInstanceOf(UnsupportedOperationException.class);
        result.fieldScope().fieldPolicies().forEach(policy -> assertThatThrownBy(() -> policy.allowedFields().add("x"))
                .isInstanceOf(UnsupportedOperationException.class));
        assertThatThrownBy(() -> result.cardinality().catalogTools().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> result.cardinality().cardinalityPolicies().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> humanFacts.catalogTools().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> humanFacts.highImpactActions().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThat(result.toString()).doesNotContain(CUSTOMER_CANARY, "CHANGED-AFTER-SNAPSHOT", "customerIds");
    }

    @Test
    void rawDependencyFailuresLoseMessagesCausesAndSuppressedExceptions() {
        var raw = new IllegalStateException(ERROR_CANARY, new IllegalStateException(CUSTOMER_CANARY));
        raw.addSuppressed(new IllegalStateException(ERROR_CANARY));
        doThrow(raw).when(proposals).validate(any());
        safe(() -> assembler.customerDataRead(source, proposal(arguments())), FailureCode.INVALID_REQUEST);

        var malformed = mock(ApprovedPolicySource.class);
        when(malformed.policy()).thenThrow(raw);
        safe(() -> assembler.humanBoundary(malformed, HUMAN_TOOL), FailureCode.INVALID_POLICY_SOURCE);
    }

    @ParameterizedTest
    @MethodSource("declaredOperations")
    void approvedDeclarationsSupplyExactToolOperationAndInternalEgressFacts(String tool, String operation) {
        var toolFacts = assembler.toolAuthorization(source, tool, operation);
        var egressFacts = assembler.egress(source, tool);

        assertThat(toolFacts.requestedTool()).isEqualTo(tool);
        assertThat(toolFacts.requestedOperation()).isEqualTo(operation);
        assertThat(toolFacts.catalogTools()).containsExactlyElementsOf(declarations());
        assertThat(toolFacts.allowedTools()).containsExactly("CASE_CONTEXT_READ", "DOCUMENT_READER", CUSTOMER_TOOL,
                "LOAN_POLICY_SEARCH", "REVIEW_NOTE_WRITE");
        assertThat(toolFacts.humanOnlyTools()).containsExactly(HUMAN_TOOL);
        assertThat(toolFacts.externalEgressExplicitlyDenied()).isTrue();
        assertThat(authorization.evaluate(TOOL, toolFacts)).isEqualTo(StageOutcome.pass(TOOL));
        assertThat(authorization.evaluate(OPERATION, toolFacts)).isEqualTo(StageOutcome.pass(OPERATION));
        assertThat(egressFacts.requestedTool()).isEqualTo(tool);
        assertThat(egressFacts.catalogTools()).containsExactlyElementsOf(declarations().stream()
                .map(value -> new PolicyEgressFacts.CatalogTool(value.name(),
                        PolicyEgressFacts.EgressClassification.INTERNAL)).toList());
        assertThat(egressFacts.externalEgressAllowed()).isFalse();
        assertThat(egressFacts.allowedDestinations()).isEmpty();
        assertThat(egress.evaluate(EGRESS, egressFacts)).isEqualTo(StageOutcome.pass(EGRESS));
        assertThat(toolFacts.toString()).doesNotContain(CUSTOMER_CANARY, ERROR_CANARY, "customerIds");
        assertThat(egressFacts.toString()).doesNotContain(CUSTOMER_CANARY, ERROR_CANARY, "customerIds");
        verifyNoInteractions(proposals, adapter);
    }

    @ParameterizedTest
    @ValueSource(strings = {"READ", "WRITE", "read", "READ ", "UNRECOGNIZED_OPERATION"})
    void independentRequestOperationIsPreservedAndComparedExactly(String requestedOperation) {
        var facts = assembler.toolAuthorization(source, CUSTOMER_TOOL, requestedOperation);

        assertThat(facts.requestedOperation()).isEqualTo(requestedOperation);
        assertThat(facts.requestedCatalogTool().orElseThrow().operation()).isEqualTo("READ");
        assertThat(authorization.evaluate(TOOL, facts)).isEqualTo(StageOutcome.pass(TOOL));
        assertThat(authorization.evaluate(OPERATION, facts)).isEqualTo("READ".equals(requestedOperation)
                ? StageOutcome.pass(OPERATION) : StageOutcome.deny(OPERATION, OPERATION_NOT_ALLOWED));
        verifyNoInteractions(proposals, adapter);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t\n"})
    void missingRequestOperationIsRejectedBeforePolicyAssembly(String requestedOperation) {
        safe(() -> assembler.toolAuthorization(source, CUSTOMER_TOOL, requestedOperation), FailureCode.INVALID_REQUEST);
        verifyNoInteractions(proposals, adapter);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "customer_data_read", "CUSTOMER_DATA_READ ", "BAD/TOOL", "🦀"})
    void malformedToolNamesAreRequestFailuresForNewEntrypoints(String tool) {
        safe(() -> assembler.toolAuthorization(source, tool, "READ"), FailureCode.INVALID_REQUEST);
        safe(() -> assembler.egress(source, tool), FailureCode.INVALID_REQUEST);
        verifyNoInteractions(proposals, adapter);
    }

    @Test
    void unknownToolIsNotInsertedIntoDeclarationsOrGivenAnEgressPass() {
        String unknown = "A".repeat(80);
        var toolFacts = assembler.toolAuthorization(source, unknown, "READ");
        var egressFacts = assembler.egress(source, unknown);

        assertThat(toolFacts.requestedTool()).isEqualTo(unknown);
        assertThat(toolFacts.requestedCatalogTool()).isEmpty();
        assertThat(authorization.evaluate(TOOL, toolFacts)).isEqualTo(StageOutcome.deny(TOOL, TOOL_NOT_ALLOWED));
        assertThat(egressFacts.requestedTool()).isEqualTo(unknown);
        assertThat(egressFacts.requestedCatalogTool()).isEmpty();
        assertThatThrownBy(() -> egress.evaluate(EGRESS, egressFacts))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("Tool stage");
        safe(() -> assembler.toolAuthorization(source, unknown + "A", "READ"), FailureCode.INVALID_REQUEST);
        safe(() -> assembler.egress(source, unknown + "A"), FailureCode.INVALID_REQUEST);
        verifyNoInteractions(proposals, adapter);
    }

    @Test
    void humanOnlyToolDefersToHumanBoundaryWithoutAugmentingTheAgentAllowlist() {
        var facts = assembler.toolAuthorization(source, HUMAN_TOOL, "UPDATE");

        assertThat(facts.allowedTools()).doesNotContain(HUMAN_TOOL);
        assertThat(facts.isRequestedToolAllowed()).isFalse();
        assertThat(facts.isRequestedToolHumanOnly()).isTrue();
        assertThat(authorization.evaluate(TOOL, facts)).isEqualTo(StageOutcome.pass(TOOL));
        assertThat(authorization.evaluate(OPERATION, facts)).isEqualTo(StageOutcome.pass(OPERATION));
        assertThat(human.evaluate(HUMAN_BOUNDARY, assembler.humanBoundary(source, HUMAN_TOOL)))
                .isEqualTo(StageOutcome.deny(HUMAN_BOUNDARY, HUMAN_ONLY_ACTION));
        verifyNoInteractions(proposals, adapter);
    }

    @Test
    void declaredInternalToolOutsideTheSuppliedAllowlistRemainsDenied() {
        ObjectNode policy = (ObjectNode) source.policy();
        policy.putArray("allowedTools").add("REVIEW_NOTE_WRITE").add("CASE_CONTEXT_READ");

        var facts = assembler.toolAuthorization(malformedSource(policy, source.catalog()), CUSTOMER_TOOL, "READ");

        assertThat(facts.allowedTools()).containsExactly("REVIEW_NOTE_WRITE", "CASE_CONTEXT_READ");
        assertThat(facts.isRequestedToolAllowed()).isFalse();
        assertThat(authorization.evaluate(TOOL, facts)).isEqualTo(StageOutcome.deny(TOOL, TOOL_NOT_ALLOWED));
        verifyNoInteractions(proposals, adapter);
    }

    @ParameterizedTest
    @ValueSource(strings = {"six-argument", "seven-argument", "empty", "missing-normal", "missing-human", "extra",
            "duplicate", "same-name-different-operation"})
    void incompleteOrAmbiguousDeclarationsCannotSupplyEitherNewEntryPoint(String problem) {
        var original = source.catalog();
        var declared = new ArrayList<>(original.declaredTools());
        switch (problem) {
            case "empty", "six-argument", "seven-argument" -> declared.clear();
            case "missing-normal" -> declared.removeIf(tool -> tool.name().equals(CUSTOMER_TOOL));
            case "missing-human" -> declared.removeIf(tool -> tool.name().equals(HUMAN_TOOL));
            case "extra" -> declared.add(new CatalogTool(ERROR_CANARY, "READ", false));
            case "duplicate" -> declared.add(declared.getFirst());
            case "same-name-different-operation" -> declared.add(new CatalogTool(CUSTOMER_TOOL, "WRITE", false));
            default -> throw new IllegalArgumentException(problem);
        }
        SourceBoundCatalog catalog = switch (problem) {
            case "six-argument" -> new SourceBoundCatalog(original.releaseId(), "1.1", ARTIFACT, FINGERPRINT, HASH,
                    original.semanticCatalog());
            case "seven-argument" -> new SourceBoundCatalog(original.releaseId(), "1.1", ARTIFACT, FINGERPRINT, HASH,
                    original.semanticCatalog(), original.releaseToolBindings());
            default -> new SourceBoundCatalog(original.releaseId(), "1.1", ARTIFACT, FINGERPRINT, HASH,
                    original.semanticCatalog(), original.releaseToolBindings(), declared);
        };
        var malformed = malformedSource(source.policy(), catalog);

        safe(() -> assembler.toolAuthorization(malformed, CUSTOMER_TOOL, "READ"), FailureCode.INVALID_POLICY_SOURCE);
        safe(() -> assembler.egress(malformed, CUSTOMER_TOOL), FailureCode.INVALID_POLICY_SOURCE);
        verifyNoInteractions(proposals, adapter);
    }

    @ParameterizedTest
    @ValueSource(strings = {"source-null", "catalog-null", "policy-null", "policy-array", "policy-string"})
    void missingSourceOrMalformedPolicyCannotSupplyNewFacts(String problem) {
        ApprovedPolicySource malformed = switch (problem) {
            case "source-null" -> null;
            case "catalog-null" -> malformedSource(source.policy(), null);
            case "policy-null" -> malformedSource(null, source.catalog());
            case "policy-array" -> malformedSource(json.createArrayNode(), source.catalog());
            case "policy-string" -> malformedSource(StringNode.valueOf(ERROR_CANARY), source.catalog());
            default -> throw new IllegalArgumentException(problem);
        };

        safe(() -> assembler.toolAuthorization(malformed, CUSTOMER_TOOL, "READ"), FailureCode.INVALID_POLICY_SOURCE);
        safe(() -> assembler.egress(malformed, CUSTOMER_TOOL), FailureCode.INVALID_POLICY_SOURCE);
        verifyNoInteractions(proposals, adapter);
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "null", "object", "string", "empty", "number-member", "boolean-member",
            "null-member", "blank-member", "duplicate", "unknown", "human-only", "padded", "lowercase"})
    void malformedAgentAllowlistIsNeverRepairedFromCatalogDeclarations(String problem) {
        ObjectNode policy = (ObjectNode) source.policy();
        switch (problem) {
            case "missing" -> policy.remove("allowedTools");
            case "null" -> policy.putNull("allowedTools");
            case "object" -> policy.putObject("allowedTools");
            case "string" -> policy.put("allowedTools", ERROR_CANARY);
            case "empty" -> policy.putArray("allowedTools");
            case "number-member" -> policy.putArray("allowedTools").add(42);
            case "boolean-member" -> policy.putArray("allowedTools").add(false);
            case "null-member" -> policy.putArray("allowedTools").addNull();
            case "blank-member" -> policy.putArray("allowedTools").add(" ");
            case "duplicate" -> policy.putArray("allowedTools").add(CUSTOMER_TOOL).add(CUSTOMER_TOOL);
            case "unknown" -> policy.putArray("allowedTools").add(ERROR_CANARY);
            case "human-only" -> policy.putArray("allowedTools").add(HUMAN_TOOL);
            case "padded" -> policy.putArray("allowedTools").add(CUSTOMER_TOOL + " ");
            case "lowercase" -> policy.putArray("allowedTools").add("customer_data_read");
            default -> throw new IllegalArgumentException(problem);
        }

        safe(() -> assembler.toolAuthorization(malformedSource(policy, source.catalog()), CUSTOMER_TOOL, "READ"),
                FailureCode.INVALID_POLICY_SOURCE);
        verifyNoInteractions(proposals, adapter);
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "null", "array", "string", "allowed-missing", "allowed-null",
            "allowed-string", "allowed-number", "allowed-true", "destinations-missing", "destinations-null",
            "destinations-string", "destinations-object", "number-member", "boolean-member", "object-member",
            "null-member", "blank-member", "duplicate", "nonempty"})
    void sharedMalformedOrPermissiveEgressPolicyRejectsBothNewEntryPoints(String problem) {
        ObjectNode policy = (ObjectNode) source.policy();
        ObjectNode external = (ObjectNode) policy.path("externalEgress");
        switch (problem) {
            case "missing" -> policy.remove("externalEgress");
            case "null" -> policy.putNull("externalEgress");
            case "array" -> policy.putArray("externalEgress");
            case "string" -> policy.put("externalEgress", ERROR_CANARY);
            case "allowed-missing" -> external.remove("allowed");
            case "allowed-null" -> external.putNull("allowed");
            case "allowed-string" -> external.put("allowed", "false");
            case "allowed-number" -> external.put("allowed", 0);
            case "allowed-true" -> external.put("allowed", true);
            case "destinations-missing" -> external.remove("allowedDestinations");
            case "destinations-null" -> external.putNull("allowedDestinations");
            case "destinations-string" -> external.put("allowedDestinations", ERROR_CANARY);
            case "destinations-object" -> external.putObject("allowedDestinations");
            case "number-member" -> external.putArray("allowedDestinations").add(42);
            case "boolean-member" -> external.putArray("allowedDestinations").add(false);
            case "object-member" -> external.putArray("allowedDestinations").addObject().put("raw", ERROR_CANARY);
            case "null-member" -> external.putArray("allowedDestinations").addNull();
            case "blank-member" -> external.putArray("allowedDestinations").add(" ");
            case "duplicate" -> external.putArray("allowedDestinations").add(ERROR_CANARY).add(ERROR_CANARY);
            case "nonempty" -> external.putArray("allowedDestinations").add("https://example.invalid/review");
            default -> throw new IllegalArgumentException(problem);
        }
        var malformed = malformedSource(policy, source.catalog());

        safe(() -> assembler.toolAuthorization(malformed, CUSTOMER_TOOL, "READ"), FailureCode.INVALID_POLICY_SOURCE);
        safe(() -> assembler.egress(malformed, CUSTOMER_TOOL), FailureCode.INVALID_POLICY_SOURCE);
        verifyNoInteractions(proposals, adapter);
    }

    @Test
    void newFactsRemainImmutableAfterCallerPolicyAndSourceCopiesChange() {
        ObjectNode policy = (ObjectNode) source.policy();
        var supplied = malformedSource(policy, source.catalog());
        var toolFacts = assembler.toolAuthorization(supplied, CUSTOMER_TOOL, "READ");
        var egressFacts = assembler.egress(supplied, CUSTOMER_TOOL);

        policy.putArray("allowedTools").add(ERROR_CANARY);
        ((ObjectNode) policy.path("highImpactActions")).put(HUMAN_TOOL, "AGENT_ALLOWED");
        ((ObjectNode) policy.path("externalEgress")).put("allowed", true);
        ((ObjectNode) policy.path("externalEgress")).putArray("allowedDestinations").add(ERROR_CANARY);
        ownerPolicy.putArray("allowedTools").add(ERROR_CANARY);
        ((ObjectNode) source.policy()).putArray("allowedTools").add(ERROR_CANARY);

        assertThat(toolFacts.catalogTools()).containsExactlyElementsOf(declarations());
        assertThat(toolFacts.allowedTools()).containsExactly("CASE_CONTEXT_READ", "DOCUMENT_READER", CUSTOMER_TOOL,
                "LOAN_POLICY_SEARCH", "REVIEW_NOTE_WRITE");
        assertThat(toolFacts.humanOnlyTools()).containsExactly(HUMAN_TOOL);
        assertThat(toolFacts.externalEgressExplicitlyDenied()).isTrue();
        assertThat(authorization.evaluate(TOOL, toolFacts)).isEqualTo(StageOutcome.pass(TOOL));
        assertThat(egressFacts.externalEgressAllowed()).isFalse();
        assertThat(egressFacts.allowedDestinations()).isEmpty();
        assertThat(egress.evaluate(EGRESS, egressFacts)).isEqualTo(StageOutcome.pass(EGRESS));
        assertThatThrownBy(() -> toolFacts.catalogTools().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> toolFacts.allowedTools().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> toolFacts.humanOnlyTools().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> egressFacts.catalogTools().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> egressFacts.allowedDestinations().add(ERROR_CANARY))
                .isInstanceOf(UnsupportedOperationException.class);
        verifyNoInteractions(proposals, adapter);
    }

    @ParameterizedTest
    @ValueSource(strings = {"policy", "catalog"})
    void newEntrypointsSanitizeRawSourceFailuresWithoutCallingB(String brokenAccessor) {
        var raw = new IllegalStateException(ERROR_CANARY, new IllegalStateException(CUSTOMER_CANARY));
        raw.addSuppressed(new IllegalStateException(ERROR_CANARY));
        var malformed = malformedSource(source.policy(), source.catalog());
        if ("policy".equals(brokenAccessor)) when(malformed.policy()).thenThrow(raw);
        else when(malformed.catalog()).thenThrow(raw);

        safe(() -> assembler.toolAuthorization(malformed, CUSTOMER_TOOL, "READ"), FailureCode.INVALID_POLICY_SOURCE);
        safe(() -> assembler.egress(malformed, CUSTOMER_TOOL), FailureCode.INVALID_POLICY_SOURCE);
        verifyNoInteractions(proposals, adapter);
    }

    @ParameterizedTest
    @ValueSource(strings = {"DOCUMENT_REVIEW", "HUMAN_DECISION", "document_review", "DOCUMENT_REVIEW "})
    void workflowPreservesTheIndependentStageAndOnlyTheExactBootstrapBypassesIt(String stage) {
        var facts = assembler.workflow(source, "DOCUMENT_READER", stage);

        assertThat(facts.serverWorkflowStage()).isEqualTo(stage);
        assertThat(facts.allowedStages()).containsExactly("DOCUMENT_REVIEW");
        assertThat(facts.catalogTools()).extracting(PolicyWorkflowFacts.CatalogTool::name)
                .containsExactlyInAnyOrderElementsOf(declarations().stream().map(CatalogTool::name).toList());
        assertThat(facts.catalogTools().stream().filter(PolicyWorkflowFacts.CatalogTool::workflowBootstrap)
                .map(PolicyWorkflowFacts.CatalogTool::name).toList()).containsExactly("CASE_CONTEXT_READ");
        assertThat(workflow.evaluate(WORKFLOW, facts)).isEqualTo("DOCUMENT_REVIEW".equals(stage)
                ? StageOutcome.pass(WORKFLOW) : StageOutcome.deny(WORKFLOW, INVALID_WORKFLOW_STAGE));
        assertThat(workflow.evaluate(WORKFLOW, assembler.workflow(source, "CASE_CONTEXT_READ", stage)))
                .isEqualTo(StageOutcome.pass(WORKFLOW));
        verifyNoInteractions(proposals, adapter);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t\n"})
    void workflowRejectsMissingStageWithoutTakingTheApprovedStageAsADefault(String stage) {
        safe(() -> assembler.workflow(source, CUSTOMER_TOOL, stage), FailureCode.INVALID_REQUEST);
        verifyNoInteractions(proposals, adapter);
    }

    @Test
    void unknownContextToolsStayUnknownAndInvalidToolNamesStayRequestErrors() {
        var workflowFacts = assembler.workflow(source, "UNKNOWN_TOOL", "DOCUMENT_REVIEW");
        var objectFacts = objectFacts(source, "UNKNOWN_TOOL", CASE, DOCUMENT, CUSTOMER_CANARY);

        assertThat(workflowFacts.requestedCatalogTool()).isEmpty();
        assertThat(objectFacts.isRequestedToolCatalogKnown()).isFalse();
        assertThatThrownBy(() -> workflow.evaluate(WORKFLOW, workflowFacts))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("Tool stage");
        assertThatThrownBy(() -> objects.evaluate(OBJECT_SCOPE, objectFacts))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("Tool stage");
        safe(() -> assembler.workflow(source, "CASE_CONTEXT_READ ", "DOCUMENT_REVIEW"), FailureCode.INVALID_REQUEST);
        safe(() -> objectFacts(source, null, CASE, DOCUMENT, CUSTOMER_CANARY), FailureCode.INVALID_REQUEST);
        verifyNoInteractions(proposals, adapter);
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "null", "array", "stages-missing", "stages-string", "stages-empty",
            "stages-null-member", "stages-blank", "stages-duplicate"})
    void malformedWorkflowProjectionCannotBecomeAnUnrestrictedPolicy(String problem) {
        ObjectNode policy = (ObjectNode) source.policy();
        ObjectNode rule = (ObjectNode) policy.path("workflow");
        switch (problem) {
            case "missing" -> policy.remove("workflow");
            case "null" -> policy.putNull("workflow");
            case "array" -> policy.putArray("workflow");
            case "stages-missing" -> rule.remove("allowedStages");
            case "stages-string" -> rule.put("allowedStages", ERROR_CANARY);
            case "stages-empty" -> rule.putArray("allowedStages");
            case "stages-null-member" -> rule.putArray("allowedStages").addNull();
            case "stages-blank" -> rule.putArray("allowedStages").add(" ");
            case "stages-duplicate" -> rule.putArray("allowedStages").add("DOCUMENT_REVIEW").add("DOCUMENT_REVIEW");
            default -> throw new IllegalArgumentException(problem);
        }

        safe(() -> assembler.workflow(malformedSource(policy, source.catalog()), CUSTOMER_TOOL, "DOCUMENT_REVIEW"),
                FailureCode.INVALID_POLICY_SOURCE);
        verifyNoInteractions(proposals, adapter);
    }

    @Test
    void businessContextTakesOnlyContractPurposeFromSourceAndPreservesEveryIndependentValue() {
        var facts = assembler.businessContext(source, true, Optional.of(PURPOSE), Optional.of(PURPOSE),
                Optional.of(PURPOSE), Optional.of("server-namespace"), Optional.of(CASE),
                Optional.of(CUSTOMER_CANARY), Optional.of("DOCUMENT_REVIEW"), Optional.of(List.of(DOCUMENT)));

        assertThat(facts).isEqualTo(new PolicyBusinessContextFacts(true, Optional.of(PURPOSE), Optional.of(PURPOSE),
                Optional.of(PURPOSE), Optional.of(PURPOSE), Optional.of("server-namespace"), Optional.of(CASE),
                Optional.of(CUSTOMER_CANARY), Optional.of("DOCUMENT_REVIEW"), Optional.of(List.of(DOCUMENT))));
        assertThat(facts.namespaceId()).isNotEqualTo(Optional.of(source.runId().toString()));
        assertThat(facts.caseId()).isNotEqualTo(Optional.of(source.testCaseId().toString()));
        assertThat(business.evaluate(BUSINESS_CONTEXT, facts)).isEqualTo(StageOutcome.pass(BUSINESS_CONTEXT));
        verifyNoInteractions(proposals, adapter);
    }

    @ParameterizedTest
    @ValueSource(strings = {"unresolved", "release-missing", "run-mismatch", "case-purpose-blank", "case-missing",
            "workflow-missing", "documents-missing", "documents-duplicate", "documents-blank", "documents-null-member"})
    void incompleteBusinessInputsArePreservedForTheExistingIntegrityEvaluator(String problem) {
        boolean resolved = !"unresolved".equals(problem);
        Optional<String> releasePurpose = "release-missing".equals(problem) ? Optional.empty() : Optional.of(PURPOSE);
        Optional<String> runPurpose = Optional.of("run-mismatch".equals(problem) ? "OTHER_PURPOSE" : PURPOSE);
        Optional<String> casePurpose = Optional.of("case-purpose-blank".equals(problem) ? " " : PURPOSE);
        Optional<String> caseId = "case-missing".equals(problem) ? Optional.empty() : Optional.of(CASE);
        Optional<String> stage = "workflow-missing".equals(problem) ? Optional.empty() : Optional.of("DOCUMENT_REVIEW");
        var documents = new ArrayList<>(List.of(DOCUMENT));
        if ("documents-duplicate".equals(problem)) documents.add(DOCUMENT);
        if ("documents-blank".equals(problem)) documents.add(" ");
        if ("documents-null-member".equals(problem)) documents.add(null);
        Optional<List<String>> documentInput = "documents-missing".equals(problem) ? Optional.empty() : Optional.of(documents);

        var facts = assembler.businessContext(source, resolved, releasePurpose, runPurpose, casePurpose,
                Optional.of("server-namespace"), caseId, Optional.of(CUSTOMER_CANARY), stage, documentInput);

        assertThat(facts).isEqualTo(new PolicyBusinessContextFacts(resolved, Optional.of(PURPOSE), releasePurpose,
                runPurpose, casePurpose, Optional.of("server-namespace"), caseId, Optional.of(CUSTOMER_CANARY),
                stage, documentInput));
        assertThat(business.evaluate(BUSINESS_CONTEXT, facts))
                .isEqualTo(StageOutcome.error(BUSINESS_CONTEXT, CONTEXT_INTEGRITY_FAILURE));
        verifyNoInteractions(proposals, adapter);
    }

    @ParameterizedTest
    @ValueSource(strings = {"release", "run", "purpose", "namespace", "case", "applicant", "stage", "documents"})
    void nullBusinessOptionalWrappersAreRequestFailuresRatherThanFilledDefaults(String field) {
        safe(() -> assembler.businessContext(source, true,
                "release".equals(field) ? null : Optional.of(PURPOSE),
                "run".equals(field) ? null : Optional.of(PURPOSE),
                "purpose".equals(field) ? null : Optional.of(PURPOSE),
                "namespace".equals(field) ? null : Optional.of("server-namespace"),
                "case".equals(field) ? null : Optional.of(CASE),
                "applicant".equals(field) ? null : Optional.of(CUSTOMER_CANARY),
                "stage".equals(field) ? null : Optional.of("DOCUMENT_REVIEW"),
                "documents".equals(field) ? null : Optional.of(List.of(DOCUMENT))), FailureCode.INVALID_REQUEST);
        verifyNoInteractions(proposals, adapter);
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "null", "object", "empty", "blank"})
    void malformedContractPurposeCannotBeReplacedWithCallerPurpose(String problem) {
        ObjectNode policy = (ObjectNode) source.policy();
        switch (problem) {
            case "missing" -> policy.remove("purpose");
            case "null" -> policy.putNull("purpose");
            case "object" -> policy.putObject("purpose");
            case "empty" -> policy.put("purpose", "");
            case "blank" -> policy.put("purpose", " ");
            default -> throw new IllegalArgumentException(problem);
        }

        safe(() -> businessFacts(malformedSource(policy, source.catalog())), FailureCode.INVALID_POLICY_SOURCE);
        verifyNoInteractions(proposals, adapter);
    }

    @ParameterizedTest
    @ValueSource(strings = {"DOCUMENT_READER", "REVIEW_NOTE_WRITE", CUSTOMER_TOOL})
    void objectScopeProjectsAllDefaultFlagsAndKeepsRequestAndServerOperandsSeparate(String tool) {
        var facts = objectFacts(source, tool, CASE, DOCUMENT, CUSTOMER_CANARY);

        assertThat(facts.scopePolicies()).containsExactlyInAnyOrder(
                new ObjectScopePolicy("DOCUMENT_READER", true, true, false),
                new ObjectScopePolicy("REVIEW_NOTE_WRITE", true, false, false),
                new ObjectScopePolicy(CUSTOMER_TOOL, false, false, true));
        assertThat(facts.catalogTools()).containsExactlyInAnyOrderElementsOf(
                declarations().stream().map(CatalogTool::name).toList());
        assertThat(facts.requestedCaseId()).contains(CASE);
        assertThat(facts.requestedDocumentIds()).contains(List.of(DOCUMENT));
        assertThat(facts.requestedCustomerIds()).contains(List.of(CUSTOMER_CANARY));
        assertThat(facts.currentCaseId()).contains(CASE);
        assertThat(facts.currentApplicantId()).contains(CUSTOMER_CANARY);
        assertThat(facts.documentOwnerships()).contains(List.of(new DocumentOwnership(DOCUMENT, CASE)));
        assertThat(objects.evaluate(OBJECT_SCOPE, facts)).isEqualTo(StageOutcome.pass(OBJECT_SCOPE));
        verifyNoInteractions(proposals, adapter);
    }

    @ParameterizedTest
    @ValueSource(strings = {"case", "document", "customer", "case-padding", "customer-padding"})
    void mismatchedObjectRequestsAreNotRewrittenFromServerScope(String problem) {
        String requestedCase = "case".equals(problem) ? "CASE-OTHER" : "case-padding".equals(problem) ? CASE + " " : CASE;
        String requestedDocument = "document".equals(problem) ? "DOC-OTHER" : DOCUMENT;
        boolean customer = problem.startsWith("customer");
        String requestedCustomer = "customer".equals(problem) ? "OTHER-CUSTOMER"
                : "customer-padding".equals(problem) ? CUSTOMER_CANARY + " " : CUSTOMER_CANARY;
        var facts = objectFacts(source, customer ? CUSTOMER_TOOL : "DOCUMENT_READER",
                requestedCase, requestedDocument, requestedCustomer);

        assertThat(facts.requestedCaseId()).contains(requestedCase);
        assertThat(facts.requestedDocumentIds()).contains(List.of(requestedDocument));
        assertThat(facts.requestedCustomerIds()).contains(List.of(requestedCustomer));
        assertThat(facts.currentCaseId()).contains(CASE);
        assertThat(facts.currentApplicantId()).contains(CUSTOMER_CANARY);
        assertThat(objects.evaluate(OBJECT_SCOPE, facts)).isEqualTo(StageOutcome.deny(OBJECT_SCOPE,
                customer ? CUSTOMER_SCOPE_VIOLATION : "document".equals(problem)
                        ? DOCUMENT_SCOPE_VIOLATION : CASE_SCOPE_VIOLATION));
        verifyNoInteractions(proposals, adapter);
    }

    @Test
    void additionalEnabledResourceRuleAndCustomerScopeMergeAreBothEnforced() {
        ObjectNode policy = (ObjectNode) source.policy();
        ObjectNode rules = (ObjectNode) policy.path("resourcePolicies");
        rules.putObject("CASE_CONTEXT_READ").put("caseScope", "CURRENT_CASE_ONLY");
        rules.putObject(CUSTOMER_TOOL).put("caseScope", "CURRENT_CASE_ONLY");
        var supplied = malformedSource(policy, source.catalog());

        var customer = objectFacts(supplied, CUSTOMER_TOOL, "CASE-OTHER", DOCUMENT, CUSTOMER_CANARY);
        var context = objectFacts(supplied, "CASE_CONTEXT_READ", "CASE-OTHER", DOCUMENT, CUSTOMER_CANARY);

        assertThat(customer.scopePolicies()).hasSize(4).contains(
                new ObjectScopePolicy("CASE_CONTEXT_READ", true, false, false),
                new ObjectScopePolicy(CUSTOMER_TOOL, true, false, true));
        assertThat(customer.scopePolicies().stream().filter(rule -> CUSTOMER_TOOL.equals(rule.toolName())).count())
                .isEqualTo(1);
        assertThat(objects.evaluate(OBJECT_SCOPE, customer))
                .isEqualTo(StageOutcome.deny(OBJECT_SCOPE, CASE_SCOPE_VIOLATION));
        assertThat(objects.evaluate(OBJECT_SCOPE, context))
                .isEqualTo(StageOutcome.deny(OBJECT_SCOPE, CASE_SCOPE_VIOLATION));
        assertThat(objects.evaluate(OBJECT_SCOPE, objectFacts(supplied, CUSTOMER_TOOL, CASE, DOCUMENT, "OTHER-CUSTOMER")))
                .isEqualTo(StageOutcome.deny(OBJECT_SCOPE, CUSTOMER_SCOPE_VIOLATION));
        verifyNoInteractions(proposals, adapter);
    }

    @ParameterizedTest
    @ValueSource(strings = {"resources-missing", "resources-null", "resources-array", "document-missing",
            "review-missing", "document-case-missing", "document-scope-missing", "empty-entry", "unsupported-case",
            "unsupported-document", "unknown-field", "unknown-tool", "human-reference", "customer-missing",
            "customer-array", "customer-type-wrong"})
    void malformedObjectPoliciesCannotSilentlyDropARequiredOrAdditionalConstraint(String problem) {
        ObjectNode policy = (ObjectNode) source.policy();
        ObjectNode resources = (ObjectNode) policy.path("resourcePolicies");
        ObjectNode document = (ObjectNode) resources.path("DOCUMENT_READER");
        switch (problem) {
            case "resources-missing" -> policy.remove("resourcePolicies");
            case "resources-null" -> policy.putNull("resourcePolicies");
            case "resources-array" -> policy.putArray("resourcePolicies");
            case "document-missing" -> resources.remove("DOCUMENT_READER");
            case "review-missing" -> resources.remove("REVIEW_NOTE_WRITE");
            case "document-case-missing" -> document.remove("caseScope");
            case "document-scope-missing" -> document.remove("documentScope");
            case "empty-entry" -> resources.putObject("CASE_CONTEXT_READ");
            case "unsupported-case" -> document.put("caseScope", "ANY_CASE");
            case "unsupported-document" -> document.put("documentScope", "ANY_DOCUMENT");
            case "unknown-field" -> document.put("operation", ERROR_CANARY);
            case "unknown-tool" -> resources.putObject("UNKNOWN_TOOL").put("caseScope", "CURRENT_CASE_ONLY");
            case "human-reference" -> resources.putObject(HUMAN_TOOL).put("caseScope", "CURRENT_CASE_ONLY");
            case "customer-missing" -> policy.remove("customerScope");
            case "customer-array" -> policy.putArray("customerScope");
            case "customer-type-wrong" -> ((ObjectNode) policy.path("customerScope")).put("type", ERROR_CANARY);
            default -> throw new IllegalArgumentException(problem);
        }

        safe(() -> objectFacts(malformedSource(policy, source.catalog()), CUSTOMER_TOOL, CASE, DOCUMENT, CUSTOMER_CANARY),
                FailureCode.INVALID_POLICY_SOURCE);
        verifyNoInteractions(proposals, adapter);
    }

    @ParameterizedTest
    @ValueSource(strings = {"case-missing", "case-blank", "documents-empty", "documents-null-wrapper",
            "documents-duplicate", "customers-empty", "customers-duplicate"})
    void malformedObjectRequestsKeepTheExistingRequestException(String problem) {
        Optional<String> requestedCase = "case-missing".equals(problem) ? Optional.empty()
                : Optional.of("case-blank".equals(problem) ? " " : CASE);
        Optional<List<String>> documents = switch (problem) {
            case "documents-empty" -> Optional.of(List.of());
            case "documents-null-wrapper" -> null;
            case "documents-duplicate" -> Optional.of(List.of(DOCUMENT, DOCUMENT));
            default -> Optional.of(List.of(DOCUMENT));
        };
        Optional<List<String>> customers = switch (problem) {
            case "customers-empty" -> Optional.of(List.of());
            case "customers-duplicate" -> Optional.of(List.of(CUSTOMER_CANARY, CUSTOMER_CANARY));
            default -> Optional.of(List.of(CUSTOMER_CANARY));
        };
        String tool = problem.startsWith("customers") ? CUSTOMER_TOOL : "DOCUMENT_READER";

        assertThatThrownBy(() -> assembler.objectScope(source, tool, requestedCase, documents, customers,
                Optional.of(CASE), Optional.of(CUSTOMER_CANARY), Optional.of(List.of(DOCUMENT)),
                Optional.of(List.of(new DocumentOwnership(DOCUMENT, CASE)))))
                .isInstanceOf(InvalidPolicyScopeRequestException.class).hasNoCause()
                .hasMessageNotContaining(CUSTOMER_CANARY).hasMessageNotContaining(ERROR_CANARY);
        verifyNoInteractions(proposals, adapter);
    }

    @ParameterizedTest
    @ValueSource(strings = {"case-missing", "case-blank", "documents-missing", "documents-duplicate",
            "ownership-missing", "ownership-other-case", "ownership-duplicate", "applicant-missing"})
    void incompleteOrConflictingStoredScopeKeepsTheExistingContextIntegrityException(String problem) {
        Optional<String> currentCase = "case-missing".equals(problem) ? Optional.empty()
                : Optional.of("case-blank".equals(problem) ? " " : CASE);
        Optional<String> applicant = "applicant-missing".equals(problem) ? Optional.empty() : Optional.of(CUSTOMER_CANARY);
        Optional<List<String>> documents = "documents-missing".equals(problem) ? Optional.empty()
                : Optional.of("documents-duplicate".equals(problem) ? List.of(DOCUMENT, DOCUMENT) : List.of(DOCUMENT));
        Optional<List<DocumentOwnership>> ownerships = switch (problem) {
            case "ownership-missing" -> Optional.of(List.of());
            case "ownership-other-case" -> Optional.of(List.of(new DocumentOwnership(DOCUMENT, "CASE-OTHER")));
            case "ownership-duplicate" -> Optional.of(List.of(new DocumentOwnership(DOCUMENT, CASE),
                    new DocumentOwnership(DOCUMENT, CASE)));
            default -> Optional.of(List.of(new DocumentOwnership(DOCUMENT, CASE)));
        };
        String tool = "applicant-missing".equals(problem) ? CUSTOMER_TOOL : "DOCUMENT_READER";

        assertThatThrownBy(() -> assembler.objectScope(source, tool, Optional.of(CASE), Optional.of(List.of(DOCUMENT)),
                Optional.of(List.of(CUSTOMER_CANARY)), currentCase, applicant, documents, ownerships))
                .isInstanceOf(PolicyScopeContextIntegrityException.class).hasNoCause()
                .hasMessageNotContaining(CUSTOMER_CANARY).hasMessageNotContaining(ERROR_CANARY);
        verifyNoInteractions(proposals, adapter);
    }

    @Test
    void contextFactsSnapshotPolicyAndCallerCollectionsWithoutExposingMutableResults() {
        ObjectNode policy = (ObjectNode) source.policy();
        var supplied = malformedSource(policy, source.catalog());
        var documents = new ArrayList<>(List.of(DOCUMENT));
        var customers = new ArrayList<>(List.of(CUSTOMER_CANARY));
        var ownerships = new ArrayList<>(List.of(new DocumentOwnership(DOCUMENT, CASE)));
        var workflowFacts = assembler.workflow(supplied, "DOCUMENT_READER", "DOCUMENT_REVIEW");
        var businessFacts = assembler.businessContext(supplied, true, Optional.of(PURPOSE), Optional.of(PURPOSE),
                Optional.of(PURPOSE), Optional.of("server-namespace"), Optional.of(CASE), Optional.of(CUSTOMER_CANARY),
                Optional.of("DOCUMENT_REVIEW"), Optional.of(documents));
        var objectFacts = assembler.objectScope(supplied, "DOCUMENT_READER", Optional.of(CASE), Optional.of(documents),
                Optional.of(customers), Optional.of(CASE), Optional.of(CUSTOMER_CANARY), Optional.of(documents),
                Optional.of(ownerships));
        documents.clear();
        customers.clear();
        ownerships.clear();
        policy.put("purpose", ERROR_CANARY);
        ((ObjectNode) policy.path("workflow")).putArray("allowedStages").add("HUMAN_DECISION");
        ((ObjectNode) policy.path("resourcePolicies")).removeAll();

        assertThat(workflowFacts.allowedStages()).containsExactly("DOCUMENT_REVIEW");
        assertThat(businessFacts.contractPurpose()).contains(PURPOSE);
        assertThat(businessFacts.allowedDocumentIds()).contains(List.of(DOCUMENT));
        assertThat(objectFacts.requestedDocumentIds()).contains(List.of(DOCUMENT));
        assertThat(objectFacts.requestedCustomerIds()).contains(List.of(CUSTOMER_CANARY));
        assertThat(objectFacts.documentOwnerships()).contains(List.of(new DocumentOwnership(DOCUMENT, CASE)));
        assertThat(workflow.evaluate(WORKFLOW, workflowFacts)).isEqualTo(StageOutcome.pass(WORKFLOW));
        assertThat(business.evaluate(BUSINESS_CONTEXT, businessFacts)).isEqualTo(StageOutcome.pass(BUSINESS_CONTEXT));
        assertThat(objects.evaluate(OBJECT_SCOPE, objectFacts)).isEqualTo(StageOutcome.pass(OBJECT_SCOPE));
        assertThatThrownBy(() -> workflowFacts.allowedStages().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> workflowFacts.catalogTools().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> businessFacts.allowedDocumentIds().orElseThrow().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> objectFacts.catalogTools().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> objectFacts.scopePolicies().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> objectFacts.requestedDocumentIds().orElseThrow().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> objectFacts.requestedCustomerIds().orElseThrow().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> objectFacts.allowedDocumentIds().orElseThrow().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> objectFacts.documentOwnerships().orElseThrow().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        verifyNoInteractions(proposals, adapter);
    }

    @ParameterizedTest
    @ValueSource(strings = {"generic", "request-shaped", "context-shaped"})
    void sourceAccessExceptionsAreSanitizedEvenWhenTheyResembleCallerFailures(String kind) {
        RuntimeException raw = switch (kind) {
            case "request-shaped" -> new InvalidPolicyScopeRequestException(ERROR_CANARY);
            case "context-shaped" -> new PolicyScopeContextIntegrityException(ERROR_CANARY);
            default -> new IllegalStateException(ERROR_CANARY, new IllegalStateException(CUSTOMER_CANARY));
        };
        var malformed = mock(ApprovedPolicySource.class);
        when(malformed.catalog()).thenReturn(source.catalog());
        when(malformed.policy()).thenThrow(raw);

        safe(() -> assembler.workflow(malformed, CUSTOMER_TOOL, "DOCUMENT_REVIEW"), FailureCode.INVALID_POLICY_SOURCE);
        safe(() -> businessFacts(malformed), FailureCode.INVALID_POLICY_SOURCE);
        safe(() -> objectFacts(malformed, CUSTOMER_TOOL, CASE, DOCUMENT, CUSTOMER_CANARY), FailureCode.INVALID_POLICY_SOURCE);
        verifyNoInteractions(proposals, adapter);
    }

    @Test
    void syntheticExternalDeclarationReachesSpecificEgressDenialWithoutExecutingATool() {
        // Projection-only synthetic source: the actual A six-tool fixture remains entirely INTERNAL.
        var catalog = source.catalog();
        var declared = catalog.declaredTools().stream().map(tool -> "REVIEW_NOTE_WRITE".equals(tool.name())
                ? new CatalogTool(tool.name(), tool.operation(), true) : tool).toList();
        var synthetic = new SourceBoundCatalog(catalog.releaseId(), catalog.manifestSchemaVersion(),
                catalog.agentArtifactFingerprint(), catalog.releaseFingerprint(), catalog.serverToolCatalogHash(),
                catalog.semanticCatalog(), catalog.releaseToolBindings(), declared);
        ObjectNode policy = (ObjectNode) source.policy();
        policy.putArray("allowedTools").add("CASE_CONTEXT_READ").add("DOCUMENT_READER")
                .add(CUSTOMER_TOOL).add("LOAN_POLICY_SEARCH");
        var supplied = malformedSource(policy, synthetic);

        var toolFacts = assembler.toolAuthorization(supplied, "REVIEW_NOTE_WRITE", "CREATE");
        var egressFacts = assembler.egress(supplied, "REVIEW_NOTE_WRITE");

        assertThat(toolFacts.allowedTools()).doesNotContain("REVIEW_NOTE_WRITE");
        assertThat(authorization.evaluate(TOOL, toolFacts)).isEqualTo(StageOutcome.pass(TOOL));
        assertThat(egressFacts.requestedCatalogTool().orElseThrow().egressClassification())
                .isEqualTo(PolicyEgressFacts.EgressClassification.EXTERNAL);
        assertThat(egress.evaluate(EGRESS, egressFacts)).isEqualTo(StageOutcome.deny(EGRESS, EXTERNAL_EGRESS_DENIED));
        assertThat(source.catalog().declaredTools()).allMatch(tool -> !tool.externalEgressTool());
        verifyNoInteractions(proposals, adapter);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1})
    void postCallFactsBindApprovedProjectionMetadataAndSourceIdsBeforeRealGuardPass(int rowCount) {
        ObjectNode response = customerResponse();
        if (rowCount == 0) response.putArray("rows");

        var facts = postCallFacts(source, response, classifications(), provenance());

        assertThat(facts.requestedTool()).isEqualTo(CUSTOMER_TOOL);
        assertThat(facts.currentApplicantId()).isEqualTo(CUSTOMER_CANARY);
        assertThat(facts.requestedCustomerIds()).containsExactly(CUSTOMER_CANARY);
        assertThat(facts.requestedFields()).containsExactly("employmentStatus", "incomeBand");
        assertThat(facts.approvedProjection()).containsExactly("incomeBand", "employmentStatus");
        assertThat(facts.catalogOutputFields()).containsExactlyElementsOf(customerOutputMetadata());
        assertThat(facts.catalogClassifications()).hasSize(3)
                .containsEntry("accountNumber", Sensitivity.FINANCIAL)
                .containsEntry("employmentStatus", Sensitivity.NORMAL)
                .containsEntry("incomeBand", Sensitivity.FINANCIAL);
        assertThat(facts.maxReturnedRecords()).isEqualTo(1);
        assertThat(facts.expectedNamespaceId()).isEqualTo(source.runId().toString());
        assertThat(facts.expectedTestCaseRunId()).isEqualTo(source.testCaseRunId());
        assertPostCallPassed(responseGuard.evaluate(facts), response);
        verify(proposals).validate(any());
        verify(adapter).validateArguments(any());
    }

    @Test
    void syntheticAsymmetricLimitsUseTheReturnedLimitRatherThanTheRequestedLimit() {
        ObjectNode policy = (ObjectNode) source.policy();
        // Projection probe only: the real approved loan-review/1 policy keeps both limits at one.
        ((ObjectNode) policy.at("/cardinality/" + CUSTOMER_TOOL)).put("maxRequestedRecords", 2);
        ObjectNode response = customerResponse();
        ((ArrayNode) response.path("rows")).add(response.path("rows").get(0).deepCopy());

        var facts = postCallFacts(postCallSource(policy, source.catalog()), response, classifications(), provenance());

        assertThat(facts.maxReturnedRecords()).isEqualTo(1);
        assertPostCallQuarantined(responseGuard.evaluate(facts), PostCallCheck.RETURNED_CARDINALITY);
    }

    @ParameterizedTest
    @ValueSource(strings = {"response-java-null", "response-json-null", "response-array", "unknown-output-field",
            "wrong-output-type", "classification-java-null", "classification-json-null", "classification-missing",
            "classification-wrong", "classification-extra", "other-customer", "forbidden-field", "excess-rows",
            "wrong-namespace", "wrong-case-run", "provenance-json-null", "provenance-empty"})
    void rawAdapterViolationsReachTheRealGuardWithExactQuarantineEvidence(String problem) {
        JsonNode response = customerResponse();
        JsonNode classification = classifications();
        JsonNode provenance = provenance();
        PostCallCheck expected;
        switch (problem) {
            case "response-java-null" -> { response = null; expected = PostCallCheck.OUTPUT_SCHEMA; }
            case "response-json-null" -> { response = NullNode.getInstance(); expected = PostCallCheck.OUTPUT_SCHEMA; }
            case "response-array" -> { response = json.createArrayNode(); expected = PostCallCheck.OUTPUT_SCHEMA; }
            case "unknown-output-field" -> {
                ((ObjectNode) response.at("/rows/0/fields")).put("unknown", ERROR_CANARY);
                ((ObjectNode) classification).remove("incomeBand");
                expected = PostCallCheck.OUTPUT_SCHEMA;
            }
            case "wrong-output-type" -> {
                ((ObjectNode) response.at("/rows/0/fields")).put("incomeBand", 42);
                expected = PostCallCheck.OUTPUT_SCHEMA;
            }
            case "classification-java-null" -> { classification = null; expected = PostCallCheck.CLASSIFICATION; }
            case "classification-json-null" -> { classification = NullNode.getInstance(); expected = PostCallCheck.CLASSIFICATION; }
            case "classification-missing" -> {
                ((ObjectNode) response).putArray("rows");
                ((ObjectNode) classification).remove("accountNumber");
                expected = PostCallCheck.CLASSIFICATION;
            }
            case "classification-wrong" -> {
                ((ObjectNode) classification).put("accountNumber", "NORMAL");
                expected = PostCallCheck.CLASSIFICATION;
            }
            case "classification-extra" -> {
                ((ObjectNode) classification).put("customerId", "NORMAL");
                expected = PostCallCheck.CLASSIFICATION;
            }
            case "other-customer" -> {
                ((ObjectNode) response.at("/rows/0")).put("customerId", "OTHER-CUSTOMER");
                expected = PostCallCheck.OBJECT_SCOPE;
            }
            case "forbidden-field" -> {
                ((ObjectNode) response.at("/rows/0/fields")).put("accountNumber", ERROR_CANARY);
                expected = PostCallCheck.FIELD_PROJECTION;
            }
            case "excess-rows" -> {
                ((ArrayNode) response.path("rows")).add(response.path("rows").get(0).deepCopy());
                expected = PostCallCheck.RETURNED_CARDINALITY;
            }
            case "wrong-namespace" -> {
                ((ObjectNode) provenance).put("namespaceId", "OTHER-NAMESPACE");
                expected = PostCallCheck.STATE_DELTA_PROVENANCE;
            }
            case "wrong-case-run" -> {
                ((ObjectNode) provenance).put("testCaseRunId", UUID.randomUUID().toString());
                expected = PostCallCheck.STATE_DELTA_PROVENANCE;
            }
            case "provenance-json-null" -> { provenance = NullNode.getInstance(); expected = PostCallCheck.STATE_DELTA_PROVENANCE; }
            case "provenance-empty" -> { provenance = json.createObjectNode(); expected = PostCallCheck.STATE_DELTA_PROVENANCE; }
            default -> throw new IllegalArgumentException(problem);
        }

        var facts = postCallFacts(source, response, classification, provenance);

        assertThat(facts.adapterResponse()).isEqualTo(response);
        assertThat(facts.adapterClassificationMap()).isEqualTo(classification);
        assertThat(facts.adapterStateDeltaProvenance()).isEqualTo(Optional.ofNullable(provenance));
        assertPostCallQuarantined(responseGuard.evaluate(facts), expected);
    }

    @Test
    void javaNullProvenanceRetainsTheExistingOptionalAbsenceMeaning() {
        ObjectNode response = customerResponse();
        var facts = postCallFacts(source, response, classifications(), null);

        assertThat(facts.adapterStateDeltaProvenance()).isEmpty();
        assertPostCallPassed(responseGuard.evaluate(facts), response);
    }

    @Test
    void knownForbiddenRequestFieldIsPreservedAndStillQuarantinedByApprovedProjection() {
        ObjectNode request = arguments();
        request.putArray("fields").add("accountNumber");
        ObjectNode response = customerResponse();
        ((ObjectNode) response.at("/rows/0")).putObject("fields").put("accountNumber", ERROR_CANARY);

        var facts = assembler.customerDataReadPostCall(source, proposal(request), CUSTOMER_CANARY,
                response, classifications(), provenance());

        assertThat(facts.requestedFields()).containsExactly("accountNumber");
        assertThat(facts.approvedProjection()).containsExactly("incomeBand", "employmentStatus");
        assertThat(facts.catalogClassifications()).containsEntry("accountNumber", Sensitivity.FINANCIAL);
        assertPostCallQuarantined(responseGuard.evaluate(facts), PostCallCheck.FIELD_PROJECTION);
    }

    @ParameterizedTest
    @ValueSource(strings = {"OTHER-APPLICANT", CUSTOMER_CANARY + " "})
    void independentServerApplicantIsNotReplacedWithTheRequestedCustomer(String applicant) {
        var facts = assembler.customerDataReadPostCall(source, proposal(arguments()), applicant,
                customerResponse(), classifications(), provenance());

        assertThat(facts.currentApplicantId()).isEqualTo(applicant);
        assertThat(facts.requestedCustomerIds()).containsExactly(CUSTOMER_CANARY);
        assertPostCallQuarantined(responseGuard.evaluate(facts), PostCallCheck.OBJECT_SCOPE);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" "})
    void absentServerApplicantIsARequestFailure(String applicant) {
        safe(() -> assembler.customerDataReadPostCall(source, proposal(arguments()), applicant,
                customerResponse(), classifications(), provenance()), FailureCode.INVALID_REQUEST);
    }

    @ParameterizedTest
    @ValueSource(strings = {"proposal-null", "arguments-null", "arguments-array", "fields-duplicate",
            "customers-duplicate", "field-unknown", "fields-empty", "customers-empty", "extra-authority", "other-tool"})
    void malformedPostCallRequestsAreNotRepairedOrMisclassifiedAsPolicySourceFailures(String problem) {
        ObjectNode arguments = arguments();
        switch (problem) {
            case "fields-duplicate" -> arguments.putArray("fields").add("incomeBand").add("incomeBand");
            case "customers-duplicate" -> arguments.putArray("customerIds").add(CUSTOMER_CANARY).add(CUSTOMER_CANARY);
            case "field-unknown" -> arguments.putArray("fields").add(ERROR_CANARY);
            case "fields-empty" -> arguments.putArray("fields");
            case "customers-empty" -> arguments.putArray("customerIds");
            case "extra-authority" -> arguments.put("currentApplicantId", CUSTOMER_CANARY);
            default -> { }
        }
        ToolProposal request = switch (problem) {
            case "proposal-null" -> null;
            case "arguments-null" -> proposal(null);
            case "arguments-array" -> proposal(json.createArrayNode());
            case "other-tool" -> new ToolProposal("DOCUMENT_READER", arguments);
            default -> proposal(arguments);
        };

        safe(() -> assembler.customerDataReadPostCall(source, request, CUSTOMER_CANARY,
                customerResponse(), classifications(), provenance()), "other-tool".equals(problem)
                        ? FailureCode.UNSUPPORTED_TOOL : FailureCode.INVALID_REQUEST);
    }

    @ParameterizedTest
    @ValueSource(strings = {"source-null", "policy-null", "catalog-null", "purpose-other", "purpose-missing",
            "template-other", "template-missing", "metadata-null", "deny-unknown-false", "allowed-missing",
            "allowed-duplicate", "allowed-unknown", "limit-missing", "limit-zero", "limit-negative", "limit-string",
            "limit-decimal", "limit-boolean", "limit-overflow", "run-null", "case-run-null"})
    void malformedPostCallPolicyAndSourceIdentityFailBeforeFactsAreReturned(String problem) {
        ObjectNode policy = (ObjectNode) source.policy();
        ObjectNode fieldPolicy = (ObjectNode) policy.at("/fieldPolicy/" + CUSTOMER_TOOL);
        ObjectNode count = (ObjectNode) policy.at("/cardinality/" + CUSTOMER_TOOL);
        switch (problem) {
            case "purpose-other" -> policy.put("purpose", "OTHER_PURPOSE");
            case "purpose-missing" -> policy.remove("purpose");
            case "template-other" -> ((ObjectNode) policy.path("metadata")).put("templateVersion", "loan-review/2");
            case "template-missing" -> ((ObjectNode) policy.path("metadata")).remove("templateVersion");
            case "metadata-null" -> policy.putNull("metadata");
            case "deny-unknown-false" -> fieldPolicy.put("denyUnknown", false);
            case "allowed-missing" -> fieldPolicy.remove("allowed");
            case "allowed-duplicate" -> fieldPolicy.putArray("allowed").add("incomeBand").add("incomeBand");
            case "allowed-unknown" -> fieldPolicy.putArray("allowed").add(ERROR_CANARY);
            case "limit-missing" -> count.remove("maxReturnedRecords");
            case "limit-zero" -> count.put("maxReturnedRecords", 0);
            case "limit-negative" -> count.put("maxReturnedRecords", -1);
            case "limit-string" -> count.put("maxReturnedRecords", "1");
            case "limit-decimal" -> count.put("maxReturnedRecords", 1.0);
            case "limit-boolean" -> count.put("maxReturnedRecords", true);
            case "limit-overflow" -> count.put("maxReturnedRecords", new BigInteger("4294967297"));
            default -> { }
        }
        ApprovedPolicySource supplied = postCallSource("policy-null".equals(problem) ? null : policy,
                "catalog-null".equals(problem) ? null : source.catalog());
        if ("run-null".equals(problem)) when(supplied.runId()).thenReturn(null);
        if ("case-run-null".equals(problem)) when(supplied.testCaseRunId()).thenReturn(null);
        ApprovedPolicySource selected = "source-null".equals(problem) ? null : supplied;

        safe(() -> postCallFacts(selected, customerResponse(), classifications(), provenance()), FailureCode.INVALID_POLICY_SOURCE);
    }

    @ParameterizedTest
    @ValueSource(strings = {"legacy-empty", "missing-field", "duplicate-field", "extra-field", "customer-absent"})
    void incompleteCustomerMetadataCannotBeDerivedFromRequestOrResponse(String problem) {
        var catalog = source.catalog();
        var metadata = new ArrayList<>(catalog.customerOutputFields());
        var semantic = catalog.semanticCatalog();
        switch (problem) {
            case "missing-field" -> metadata.removeFirst();
            case "duplicate-field" -> metadata.add(metadata.getFirst());
            case "extra-field" -> metadata.add(new CatalogOutputField("unexpected", Sensitivity.NORMAL, OutputValueType.STRING));
            case "customer-absent" -> semantic = new ContractValidationCatalog(semantic.enabledReleaseTools().stream()
                    .filter(tool -> !CUSTOMER_TOOL.equals(tool.toolName())).toList(), semantic.highImpactToolNames());
            default -> { }
        }
        SourceBoundCatalog supplied = "legacy-empty".equals(problem)
                ? new SourceBoundCatalog(catalog.releaseId(), "1.1", ARTIFACT, FINGERPRINT, HASH, semantic,
                        catalog.releaseToolBindings(), catalog.declaredTools())
                : new SourceBoundCatalog(catalog.releaseId(), "1.1", ARTIFACT, FINGERPRINT, HASH, semantic,
                        catalog.releaseToolBindings(), catalog.declaredTools(), metadata);

        safe(() -> postCallFacts(postCallSource(source.policy(), supplied), customerResponse(), classifications(), provenance()),
                FailureCode.INVALID_POLICY_SOURCE);
    }

    @ParameterizedTest
    @ValueSource(strings = {"policy", "catalog", "run", "case-run"})
    void rawPostCallSourceAccessFailuresAreSanitizedWithTheSourceFailureCode(String accessor) {
        var supplied = postCallSource(source.policy(), source.catalog());
        var raw = new IllegalStateException(ERROR_CANARY, new IllegalStateException(CUSTOMER_CANARY));
        switch (accessor) {
            case "policy" -> when(supplied.policy()).thenThrow(raw);
            case "catalog" -> when(supplied.catalog()).thenThrow(raw);
            case "run" -> when(supplied.runId()).thenThrow(raw);
            case "case-run" -> when(supplied.testCaseRunId()).thenThrow(raw);
            default -> throw new IllegalArgumentException(accessor);
        }

        safe(() -> postCallFacts(supplied, customerResponse(), classifications(), provenance()), FailureCode.INVALID_POLICY_SOURCE);
    }

    @Test
    void rawPostCallRequestValidationFailureIsSanitizedWithTheRequestFailureCode() {
        doThrow(new IllegalStateException(ERROR_CANARY, new IllegalStateException(CUSTOMER_CANARY)))
                .when(proposals).validate(any());

        safe(() -> postCallFacts(source, customerResponse(), classifications(), provenance()), FailureCode.INVALID_REQUEST);
    }

    @Test
    void postCallAssemblySnapshotsRequestPolicyRawObservationsAndReturnedOutput() {
        ObjectNode arguments = arguments();
        ObjectNode policy = (ObjectNode) source.policy();
        ObjectNode response = customerResponse();
        ObjectNode classification = classifications();
        ObjectNode provenance = provenance();
        ObjectNode expectedResponse = response.deepCopy();
        ObjectNode expectedClassification = classification.deepCopy();
        ObjectNode expectedProvenance = provenance.deepCopy();
        ToolProposal original = proposal(arguments);
        AtomicReference<ToolProposal> received = new AtomicReference<>();
        doAnswer(invocation -> {
            ToolProposal snapshot = invocation.getArgument(0);
            received.set(snapshot);
            assertThat(snapshot).isNotSameAs(original);
            assertThat(snapshot.arguments()).isNotSameAs(arguments);
            arguments.putArray("fields").add("accountNumber");
            arguments.putArray("customerIds").add("OTHER-CUSTOMER");
            return invocation.callRealMethod();
        }).when(proposals).validate(any());

        var facts = assembler.customerDataReadPostCall(postCallSource(policy, source.catalog()), original, CUSTOMER_CANARY,
                response, classification, provenance);
        ((ObjectNode) received.get().arguments()).putArray("fields").add("accountNumber");
        ((ObjectNode) policy.at("/fieldPolicy/" + CUSTOMER_TOOL)).putArray("allowed").add("accountNumber");
        ((ObjectNode) policy.at("/cardinality/" + CUSTOMER_TOOL)).put("maxReturnedRecords", 9);
        ((ObjectNode) response.at("/rows/0/fields")).put("accountNumber", ERROR_CANARY);
        classification.put("accountNumber", "NORMAL");
        provenance.put("namespaceId", "OTHER-NAMESPACE");
        ((ObjectNode) facts.adapterResponse()).removeAll();
        ((ObjectNode) facts.adapterClassificationMap()).removeAll();
        ((ObjectNode) facts.adapterStateDeltaProvenance().orElseThrow()).removeAll();

        assertThat(facts.requestedFields()).containsExactly("employmentStatus", "incomeBand");
        assertThat(facts.requestedCustomerIds()).containsExactly(CUSTOMER_CANARY);
        assertThat(facts.approvedProjection()).containsExactly("incomeBand", "employmentStatus");
        assertThat(facts.maxReturnedRecords()).isEqualTo(1);
        assertThat(facts.adapterResponse()).isEqualTo(expectedResponse);
        assertThat(facts.adapterClassificationMap()).isEqualTo(expectedClassification);
        assertThat(facts.adapterStateDeltaProvenance()).contains(expectedProvenance);
        assertThatThrownBy(() -> facts.requestedFields().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> facts.requestedCustomerIds().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> facts.approvedProjection().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> facts.catalogOutputFields().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> facts.catalogClassifications().clear()).isInstanceOf(UnsupportedOperationException.class);
        var decision = responseGuard.evaluate(facts);
        assertPostCallPassed(decision, expectedResponse);
        ((ObjectNode) decision.deliverableOutput().orElseThrow()).removeAll();
        assertThat(decision.deliverableOutput()).contains(expectedResponse);
    }

    private EnforcePolicyPostCallFacts postCallFacts(ApprovedPolicySource supplied, JsonNode response,
            JsonNode classification, JsonNode provenance) {
        return assembler.customerDataReadPostCall(supplied, proposal(arguments()), CUSTOMER_CANARY,
                response, classification, provenance);
    }

    private ApprovedPolicySource postCallSource(JsonNode policy, SourceBoundCatalog catalog) {
        var supplied = malformedSource(policy, catalog);
        when(supplied.runId()).thenReturn(source.runId());
        when(supplied.testCaseRunId()).thenReturn(source.testCaseRunId());
        return supplied;
    }

    private ObjectNode customerResponse() {
        ObjectNode response = json.createObjectNode().put("status", 200);
        ObjectNode row = response.putArray("rows").addObject().put("customerId", CUSTOMER_CANARY);
        row.putObject("fields").put("incomeBand", "MIDDLE").put("employmentStatus", "EMPLOYED");
        return response;
    }

    private ObjectNode classifications() {
        return json.createObjectNode().put("accountNumber", "FINANCIAL")
                .put("employmentStatus", "NORMAL").put("incomeBand", "FINANCIAL");
    }

    private ObjectNode provenance() {
        return json.createObjectNode().put("namespaceId", source.runId().toString())
                .put("testCaseRunId", source.testCaseRunId().toString());
    }

    private static List<CatalogOutputField> customerOutputMetadata() {
        // Unit projection of the three actual A catalog fields; physical A binding is verified in the PG suite.
        return List.of(new CatalogOutputField("accountNumber", Sensitivity.FINANCIAL, OutputValueType.STRING),
                new CatalogOutputField("employmentStatus", Sensitivity.NORMAL, OutputValueType.STRING),
                new CatalogOutputField("incomeBand", Sensitivity.FINANCIAL, OutputValueType.STRING));
    }

    private void assertPostCallPassed(EnforcePolicyPostCallDecision decision, JsonNode expectedOutput) {
        assertThat(decision.outcome()).isEqualTo(EnforcePolicyPostCallDecision.Outcome.PASS);
        assertThat(decision.failedCheck()).isEmpty();
        assertThat(decision.reason()).isEmpty();
        assertThat(decision.evaluatedChecks()).containsExactlyElementsOf(PostCallCheck.completeOrder());
        assertThat(decision.deliverableOutput()).contains(expectedOutput);
        assertThat(decision.operationalFailure()).isFalse();
        assertThat(decision.successfulSecurityBlock()).isFalse();
    }

    private void assertPostCallQuarantined(EnforcePolicyPostCallDecision decision, PostCallCheck failed) {
        List<PostCallCheck> order = List.of(PostCallCheck.OUTPUT_SCHEMA, PostCallCheck.CLASSIFICATION,
                PostCallCheck.OBJECT_SCOPE, PostCallCheck.FIELD_PROJECTION, PostCallCheck.RETURNED_CARDINALITY,
                PostCallCheck.STATE_DELTA_PROVENANCE);
        assertThat(decision.outcome()).isEqualTo(EnforcePolicyPostCallDecision.Outcome.QUARANTINE);
        assertThat(decision.failedCheck()).contains(failed);
        assertThat(decision.reason()).contains(failed == PostCallCheck.RETURNED_CARDINALITY
                ? OperationalReason.RESPONSE_CARDINALITY_VIOLATION : OperationalReason.ADAPTER_CONTRACT_FAILURE);
        assertThat(decision.evaluatedChecks()).containsExactlyElementsOf(order.subList(0, order.indexOf(failed) + 1));
        assertThat(decision.deliverableOutput()).isEmpty();
        assertThat(decision.operationalFailure()).isTrue();
        assertThat(decision.successfulSecurityBlock()).isFalse();
        assertThat(decision.toString()).doesNotContain(CUSTOMER_CANARY, ERROR_CANARY);
    }

    private PolicyBusinessContextFacts businessFacts(ApprovedPolicySource supplied) {
        return assembler.businessContext(supplied, true, Optional.of(PURPOSE), Optional.of(PURPOSE), Optional.of(PURPOSE),
                Optional.of("server-namespace"), Optional.of(CASE), Optional.of(CUSTOMER_CANARY),
                Optional.of("DOCUMENT_REVIEW"), Optional.of(List.of(DOCUMENT)));
    }

    private PolicyObjectScopeFacts objectFacts(ApprovedPolicySource supplied, String tool, String requestedCase,
            String requestedDocument, String requestedCustomer) {
        return assembler.objectScope(supplied, tool, Optional.of(requestedCase), Optional.of(List.of(requestedDocument)),
                Optional.of(List.of(requestedCustomer)), Optional.of(CASE), Optional.of(CUSTOMER_CANARY),
                Optional.of(List.of(DOCUMENT)), Optional.of(List.of(new DocumentOwnership(DOCUMENT, CASE))));
    }

    private ApprovedPolicySource approvedSourceFixture() throws Exception {
        UUID workspace = UUID.randomUUID();
        UUID release = UUID.randomUUID();
        UUID run = UUID.randomUUID();
        UUID caseRun = UUID.randomUUID();
        UUID versionId = UUID.randomUUID();
        ReviewerContext reviewer = new ReviewerContext(workspace, "fact-assembly-test", "AI_SECURITY_REVIEWER",
                ERROR_CANARY, true, true, false);
        try (var input = getClass().getResourceAsStream("/fixtures/loan-review-safety-contract.json")) {
            ownerPolicy = (ObjectNode) json.readTree(input);
        }
        var schema = new SafetyContractSchemaValidator();
        var canonicalizer = new SafetyContractCanonicalizer(schema, new CanonicalJsonService(json), new DigestService());
        var validator = new SafetyContractSemanticValidator(schema);
        var version = new Version(versionId, workspace, release, ownerPolicy.path("contractId").stringValue(), 1,
                "APPROVED", ownerPolicy, canonicalizer.canonicalizeAndHash(ownerPolicy).policyHash(), HASH, null,
                json.createObjectNode().put("historicalReleaseFingerprint", HASH),
                json.createObjectNode().put("decision", "APPROVED").put("private", ERROR_CANARY));
        when(runs.find(run)).thenReturn(new Projection(run, release, UUID.randomUUID(), versionId,
                TestRunMode.SEAL_REPLAY, TestRunStatus.RUNNING, ARTIFACT, FINGERPRINT, "fixture/1", HASH,
                1, 0, 0, 0, null, null, json.createObjectNode(), null, null, null));
        when(contracts.approved(release, versionId, reviewer)).thenReturn(new ApprovedContract(version, ARTIFACT, FINGERPRINT));
        when(cases.findCase(caseRun)).thenReturn(new CaseRun(caseRun, run, UUID.randomUUID(), 0,
                TestCaseRunStatus.EXECUTING, null, null, HASH, null, null, null, json.createObjectNode()));
        var semanticCatalog = new ContractValidationCatalog(List.of(
                        new EnabledTool("CASE_CONTEXT_READ", List.of()), new EnabledTool("DOCUMENT_READER", List.of()),
                        new EnabledTool(CUSTOMER_TOOL, List.of("incomeBand", "employmentStatus", "accountNumber")),
                        new EnabledTool("LOAN_POLICY_SEARCH", List.of()), new EnabledTool("REVIEW_NOTE_WRITE", List.of())),
                        List.of(HUMAN_TOOL));
        // Synthetic unit-source binding; the separate PostgreSQL suite verifies A's stored hashes.
        var bindings = semanticCatalog.enabledReleaseTools().stream()
                .map(tool -> new PolicyToolTrustFacts.ReleaseToolBinding(tool.toolName(), "1.0.0", true, HASH, HASH))
                .toList();
        when(catalogs.load(release, reviewer.actorId())).thenReturn(new SourceBoundCatalog(release, "1.1", ARTIFACT,
                FINGERPRINT, HASH, semanticCatalog, bindings, declarations(), customerOutputMetadata()));
        var loader = new GatewayApprovedPolicySourceService(runs, contracts, cases, catalogs, validator, canonicalizer);
        // Guard fixture only: actual owner approval and physical PostgreSQL transactions are not simulated here.
        boolean active = TransactionSynchronizationManager.isActualTransactionActive();
        boolean readOnly = TransactionSynchronizationManager.isCurrentTransactionReadOnly();
        Integer isolation = TransactionSynchronizationManager.getCurrentTransactionIsolationLevel();
        try {
            TransactionSynchronizationManager.setActualTransactionActive(true);
            TransactionSynchronizationManager.setCurrentTransactionReadOnly(false);
            TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(Connection.TRANSACTION_REPEATABLE_READ);
            return loader.load(run, caseRun, reviewer);
        } finally {
            TransactionSynchronizationManager.setActualTransactionActive(active);
            TransactionSynchronizationManager.setCurrentTransactionReadOnly(readOnly);
            TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(isolation);
        }
    }

    private ApprovedPolicySource malformedSource(JsonNode policy, SourceBoundCatalog catalog) {
        // Only defensive malformed-source tests bypass the real loader's validated immutable result.
        var malformed = mock(ApprovedPolicySource.class);
        when(malformed.policy()).thenReturn(policy);
        when(malformed.catalog()).thenReturn(catalog);
        return malformed;
    }

    private ObjectNode arguments() {
        ObjectNode result = json.createObjectNode();
        result.putArray("customerIds").add(CUSTOMER_CANARY);
        result.putArray("fields").add("employmentStatus").add("incomeBand");
        return result;
    }

    private ToolProposal proposal(JsonNode arguments) { return new ToolProposal(CUSTOMER_TOOL, arguments); }

    private void safe(ThrowingCallable action, FailureCode expected) {
        assertThatThrownBy(action).isInstanceOfSatisfying(FactAssemblyException.class, failure -> {
            assertThat(failure.code()).isEqualTo(expected);
            assertThat(failure.getMessage()).isEqualTo("Gateway policy facts unavailable: " + expected.name());
            assertThat(failure.getCause()).isNull();
            failure.addSuppressed(new IllegalStateException(ERROR_CANARY));
            assertThat(failure.getSuppressed()).isEmpty();
            StringWriter rendered = new StringWriter();
            failure.printStackTrace(new PrintWriter(rendered));
            assertThat(rendered.toString()).doesNotContain(CUSTOMER_CANARY, ERROR_CANARY);
        });
    }

    private static Stream<Arguments> malformedArrays() {
        return Stream.of("customerIds", "fields").flatMap(field -> Stream.of("missing", "null", "non-array", "empty",
                "number", "boolean", "object", "null-member", "blank", "81-characters", "21-entries", "duplicate")
                .map(problem -> Arguments.of(field, problem)));
    }

    private static List<CatalogTool> declarations() {
        // Same six declared identities as the fixture; these are not observed runtime registry facts.
        return List.of(new CatalogTool("CASE_CONTEXT_READ", "READ", false),
                new CatalogTool(CUSTOMER_TOOL, "READ", false),
                new CatalogTool("DOCUMENT_READER", "READ", false),
                new CatalogTool(HUMAN_TOOL, "UPDATE", false),
                new CatalogTool("LOAN_POLICY_SEARCH", "SEARCH", false),
                new CatalogTool("REVIEW_NOTE_WRITE", "CREATE", false));
    }

    private static Stream<Arguments> declaredOperations() {
        return declarations().stream().map(tool -> Arguments.of(tool.name(), tool.operation()));
    }
}
