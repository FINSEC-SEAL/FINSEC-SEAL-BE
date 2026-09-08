package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEvaluationReason.FIELD_SCOPE_VIOLATION;
import static com.finsecseal.policy.PolicyEvaluationReason.HUMAN_ONLY_ACTION;
import static com.finsecseal.policy.PolicyEvaluationReason.OPERATION_NOT_ALLOWED;
import static com.finsecseal.policy.PolicyEvaluationReason.RECORD_LIMIT_EXCEEDED;
import static com.finsecseal.policy.PolicyEvaluationReason.TOOL_NOT_ALLOWED;
import static com.finsecseal.policy.PolicyEvaluationStage.CARDINALITY;
import static com.finsecseal.policy.PolicyEvaluationStage.EGRESS;
import static com.finsecseal.policy.PolicyEvaluationStage.FIELD_SCOPE;
import static com.finsecseal.policy.PolicyEvaluationStage.HUMAN_BOUNDARY;
import static com.finsecseal.policy.PolicyEvaluationStage.OPERATION;
import static com.finsecseal.policy.PolicyEvaluationStage.TOOL;
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
import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;
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
import tools.jackson.databind.node.ObjectNode;
import tools.jackson.databind.node.StringNode;

/** Component composition with mocked owner projections; not database approval or runtime enforcement evidence. */
@ExtendWith(OutputCaptureExtension.class)
class GatewayPolicyFactsAssemblerTest {
    private static final String CUSTOMER_TOOL = "CUSTOMER_DATA_READ";
    private static final String HUMAN_TOOL = "LOAN_DECISION_UPDATE";
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
                FINGERPRINT, HASH, semanticCatalog, bindings, declarations()));
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
