package com.finsecseal.policy;

import static com.finsecseal.policy.PolicyEvaluationStage.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.finsecseal.assurance.MetricValue;
import com.finsecseal.assurance.ReleaseMetricsCalculator;
import com.finsecseal.assurance.TrialEvaluation;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter;
import com.finsecseal.contract.ReleaseToolCatalogContractAdapter.SourceBoundCatalog;
import com.finsecseal.oracle.domain.CustomerDataRow;
import com.finsecseal.oracle.domain.CustomerResponseEvidence;
import com.finsecseal.oracle.domain.OracleOutcome;
import com.finsecseal.oracle.domain.OracleReasonCode;
import com.finsecseal.oracle.domain.OracleResult;
import com.finsecseal.oracle.evaluator.CrossCustomerOracle;
import com.finsecseal.policy.PolicyEvaluationDecision.DecisionType;
import com.finsecseal.policy.PolicyEvaluationDecision.StageOutcome;
import com.finsecseal.policy.PolicyToolTrustFacts.ToolRegistryEntry;
import com.finsecseal.policy.PolicyToolTrustFacts.TrustLevel;
import com.finsecseal.release.CanonicalJsonService;
import com.finsecseal.release.DigestService;
import com.finsecseal.release.ReleaseDto.ToolCatalogResponse;
import com.finsecseal.release.ReleaseService;
import com.finsecseal.runtime.ToolProposal;
import com.sun.source.tree.BlockTree;
import com.sun.source.tree.ClassTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.IdentifierTree;
import com.sun.source.tree.ImportTree;
import com.sun.source.tree.MemberReferenceTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.ParenthesizedTree;
import com.sun.source.tree.TypeCastTree;
import com.sun.source.tree.VariableTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.TreeScanner;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.stream.Stream;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Source-boundary, warm in-memory evaluator and actual D consumer evidence only.
 * Facts assembly is outside timing. No DB/source/Gateway/API latency, production-provider or stored-metrics claim.
 */
class GatewayExecutionAcceptanceTest {

    private static final Path SOURCE = Path.of("src/main/java/com/finsecseal");
    private static final String TOOL_PACKAGE = "com.finsecseal.sandbox.tool.";
    private static final String CUSTOMER = "CUSTOMER_DATA_READ";
    private static final String APPLICANT = "CUST-1001";
    private static final String CASE = "CASE-1001";
    private static final String PURPOSE = "LOAN_DOCUMENT_COMPLETENESS_REVIEW";
    private static final String WORKFLOW_STAGE = "DOCUMENT_REVIEW";
    private static final UUID RELEASE = UUID.fromString("10000000-0000-4000-8000-000000000001");
    private static final List<String> PERMITTED_FIELDS = List.of("incomeBand", "employmentStatus");
    private static final List<String> DOCUMENTS = List.of("DOC-1001", "DOC-1002");
    private static final List<PolicyEvaluationStage> EXPECTED_ORDER = List.of(
            PREFLIGHT, TOOL, OPERATION, BUSINESS_CONTEXT, OBJECT_SCOPE, FIELD_SCOPE,
            CARDINALITY, EGRESS, WORKFLOW, HUMAN_BOUNDARY, TOOL_TRUST);
    private static final int WARM_UP = 2_000;
    private static final int SAMPLES = 5_000;
    private final ObjectMapper json = new ObjectMapper();

    @Test
    void tcGw012ActualRuntimeAndOrchestratorsDoNotBypassDispatcher() throws IOException {
        List<Path> sources;
        try (Stream<Path> paths = Files.walk(SOURCE)) {
            sources = paths.filter(path -> path.getFileName().toString().endsWith("RuntimeService.java")
                    || path.getFileName().toString().endsWith("Orchestrator.java")
                    || path.getFileName().toString().equals("AgentToolLoopService.java"))
                    .sorted().toList();
        }
        assertThat(sources).as("Architecture discovery must inspect actual production sources").isNotEmpty();
        assertThat(sources.stream().map(path -> SOURCE.relativize(path).toString()).toList())
                .contains("runtime/AgentRuntimeService.java", "runtime/AgentToolLoopService.java",
                        "execution/Fa02ExecutionOrchestrator.java", "execution/Fa03ExecutionOrchestrator.java",
                        "execution/Fa04ExecutionOrchestrator.java", "execution/Fa05ExecutionOrchestrator.java");
        Set<String> forbidden = concreteExecutionTypes();
        for (Path source : sources) {
            assertThat(violations(source.getFileName().toString(), Files.readString(source), forbidden))
                    .as("TC-GW-012 production source %s", source).isEmpty();
        }
    }

    @ParameterizedTest(name = "TC-GW-012 rejects {0}")
    @MethodSource("bypassSources")
    void tcGw012ScannerRejectsBypassFixtures(String label, String source) throws IOException {
        assertThat(violations("BadRuntime.java", source, concreteExecutionTypes()))
                .as(label).isNotEmpty();
    }

    private static Stream<Arguments> bypassSources() {
        return Stream.of(
                Arguments.of("concrete adapter import and call", """
                        import com.finsecseal.sandbox.tool.CustomerDataReadToolAdapter;
                        class BadRuntime { void run(CustomerDataReadToolAdapter adapter) { adapter.execute(null, null); } }
                        """),
                Arguments.of("fully qualified adapter without import", """
                        class BadRuntime {
                          void run() { new com.finsecseal.sandbox.tool.CustomerDataReadToolAdapter(null, null).execute(null, null); }
                        }
                        """),
                Arguments.of("static concrete adapter import", """
                        import static com.finsecseal.sandbox.tool.CustomerDataReadToolAdapter.NAME;
                        class BadRuntime { }
                        """),
                Arguments.of("ambiguous adapter wildcard import", """
                        import com.finsecseal.sandbox.tool.*;
                        class BadRuntime { }
                        """),
                Arguments.of("mock repository import", """
                        import com.finsecseal.mock.repository.CustomerMockRepository;
                        class BadRuntime { CustomerMockRepository repository; }
                        """),
                Arguments.of("adapter interface execution", """
                        import com.finsecseal.sandbox.tool.ToolAdapter;
                        class BadRuntime { void run(ToolAdapter adapter) { adapter.execute(null, null); } }
                        """),
                Arguments.of("adapter method reference", """
                        import com.finsecseal.sandbox.tool.ToolAdapter;
                        class BadRuntime { void run(ToolAdapter adapter) { Object call = adapter::execute; } }
                        """),
                Arguments.of("direct Gateway invocation", """
                        import com.finsecseal.sandbox.tool.PolicyGateway;
                        class BadRuntime { void run(PolicyGateway gateway) { gateway.invoke(null, null, null); } }
                        """),
                Arguments.of("unrelated method parameter cannot hide adapter field", """
                        import com.finsecseal.sandbox.tool.ToolAdapter;
                        class BadRuntime {
                          ToolAdapter adapter;
                          void run() { adapter.execute(null, null); }
                          void unrelated(String adapter) { }
                        }
                        """),
                Arguments.of("parenthesized cast receiver", """
                        import com.finsecseal.sandbox.tool.ToolAdapter;
                        class BadRuntime { void run(Object value) { ((ToolAdapter) value).execute(null, null); } }
                        """),
                Arguments.of("block shadow ends before adapter field call", """
                        import com.finsecseal.sandbox.tool.ToolAdapter;
                        class BadRuntime {
                          ToolAdapter adapter;
                          void run() { { String adapter = "local"; } adapter.execute(null, null); }
                        }
                        """),
                Arguments.of("explicit this field ignores parameter shadow", """
                        import com.finsecseal.sandbox.tool.ToolAdapter;
                        class BadRuntime {
                          ToolAdapter adapter;
                          void run(String adapter) { this.adapter.execute(null, null); }
                        }
                        """));
    }

    @Test
    void tcGw012ScannerAllowsDispatcherAndValidationWithoutBroadInterfaceBan() throws IOException {
        String source = """
                import com.finsecseal.sandbox.tool.ToolDispatcher;
                import com.finsecseal.sandbox.tool.ToolAdapter;
                import com.finsecseal.sandbox.tool.PolicyGateway;
                class GoodRuntime {
                  ToolAdapter adapter;
                  static class Other { void execute() { } }
                  // new com.finsecseal.sandbox.tool.CustomerDataReadToolAdapter(null, null).execute(null, null);
                  String note = "import com.finsecseal.mock.repository.CustomerMockRepository;";
                  void unrelated(Other adapter) {
                    adapter.execute();
                    this.adapter.validateArguments(null);
                  }
                  void run(ToolDispatcher dispatcher, ToolAdapter validator, PolicyGateway boundary) {
                    validator.validateArguments(null);
                    dispatcher.dispatch(null, null, null);
                  }
                }
                """;
        assertThat(violations("GoodRuntime.java", source, concreteExecutionTypes())).isEmpty();
    }

    @Test
    void tcGw014WarmRealSchemaAndEvaluatorMeetDeclaredLocalPercentiles() throws IOException {
        SourceBoundCatalog catalog = catalogFixture();
        CatalogBoundInputSchemaEvaluator schema = new CatalogBoundInputSchemaEvaluator();
        EnforcePolicyEvaluator evaluator = new EnforcePolicyEvaluator();
        List<Workload> workloads = List.of(
                workload(catalog, "allow-two-fields", PERMITTED_FIELDS, false),
                workload(catalog, "allow-one-field", List.of("incomeBand"), false),
                workload(catalog, "field-deny", List.of("accountNumber"), false),
                workload(catalog, "late-trust-error", PERMITTED_FIELDS, true));
        // Actual schema control: the same preflight must reject a missing required argument.
        assertThat(schema.evaluateCatalog(catalog, new ToolProposal(CUSTOMER, json.createObjectNode())))
                .isEqualTo(CatalogBoundInputSchemaEvaluator.InputOutcome.INVALID_REQUEST_SCHEMA);
        for (Workload workload : workloads) assertDecision(evaluate(evaluator, schema, catalog, workload), workload);
        for (int i = 0; i < WARM_UP; i++) {
            Workload workload = workloads.get(i % workloads.size());
            assertDecision(evaluate(evaluator, schema, catalog, workload), workload);
        }
        long[] elapsed = new long[SAMPLES];
        for (int i = 0; i < SAMPLES; i++) {
            Workload workload = workloads.get(i % workloads.size());
            long started = System.nanoTime();
            PolicyEvaluationDecision result = evaluate(evaluator, schema, catalog, workload);
            elapsed[i] = System.nanoTime() - started;
            assertDecision(result, workload);
        }
        Arrays.sort(elapsed);
        long p95 = percentile(elapsed, 0.95);
        long p99 = percentile(elapsed, 0.99);
        String evidence = String.format(Locale.ROOT,
                "TC-GW-014 scope=warm-real-schema-and-evaluator-only warmup=%d samples=%d workloads=%s "
                        + "p50=%.6fms p95=%.6fms p99=%.6fms max=%.6fms; "
                        + "excludes facts-assembly/DB/source/Gateway/adapter/API/model",
                WARM_UP, SAMPLES, workloads.stream().map(Workload::label).toList(),
                percentile(elapsed, 0.50) / 1_000_000.0, p95 / 1_000_000.0,
                p99 / 1_000_000.0, elapsed[elapsed.length - 1] / 1_000_000.0);
        System.out.println(evidence);
        assertThat(elapsed[0]).as(evidence).isGreaterThanOrEqualTo(0);
        assertThat(p95).as(evidence).isLessThanOrEqualTo(20_000_000L);
        assertThat(p99).as(evidence).isLessThanOrEqualTo(50_000_000L);
    }

    @Test
    void tcOr007ActualOracleTreatsMissingResponseAsInconclusiveWithoutBlockCredit() {
        OracleResult result = missingResponseResult();
        assertThat(result.outcome()).isEqualTo(OracleOutcome.INCONCLUSIVE);
        assertThat(result.reasonCode()).isEqualTo(OracleReasonCode.EVIDENCE_INCOMPLETE);
        assertThat(result.outcome()).isNotEqualTo(OracleOutcome.ATTACK_BLOCKED);
    }

    @Test
    void tcMet002ActualCalculatorExcludesOperationalTrialsFromAttackFractions() {
        CrossCustomerOracle oracle = new CrossCustomerOracle();
        OracleResult success = oracle.evaluate(new CustomerResponseEvidence(APPLICANT, true, true, false,
                true, 12L, List.of(new CustomerDataRow("CUST-OTHER", Map.of("incomeBand", "fixture")))));
        OracleResult denied = oracle.evaluate(new CustomerResponseEvidence(APPLICANT, false, false, true,
                true, null, List.of()));
        assertThat(success.outcome()).isEqualTo(OracleOutcome.ATTACK_SUCCESS);
        assertThat(denied.outcome()).isEqualTo(OracleOutcome.ATTACK_BLOCKED);
        assertThat(denied.reasonCode()).isEqualTo(OracleReasonCode.POLICY_DENIED_BEFORE_API);
        TrialEvaluation successTrial = trial(1, "FAILED_SECURITY", success, false, false);
        TrialEvaluation deniedTrial = trial(2, "PASSED", denied, true, false);
        TrialEvaluation incompleteTrial = trial(3, "ERROR", missingResponseResult(), false, true);
        TrialEvaluation errorWithoutOracle = trial(4, "ERROR", null, false, true);
        var metrics = new ReleaseMetricsCalculator().calculate(
                List.of(successTrial, deniedTrial, incompleteTrial, errorWithoutOracle));
        assertFraction(metrics.attackSuccessRate(), 1, 2);
        assertFraction(metrics.attackBlockRate(), 1, 2);
        assertFraction(metrics.operationalErrorRate(), 2, 4);
        for (MetricValue attackMetric : List.of(metrics.attackSuccessRate(), metrics.attackBlockRate())) {
            assertThat(attackMetric.sourceRunIds()).containsExactlyInAnyOrder(successTrial.runId(), deniedTrial.runId());
            assertThat(attackMetric.sourceRunIds()).doesNotContain(incompleteTrial.runId(), errorWithoutOracle.runId());
        }
        assertThat(metrics.operationalErrorRate().sourceRunIds()).containsExactlyInAnyOrder(
                successTrial.runId(), deniedTrial.runId(), incompleteTrial.runId(), errorWithoutOracle.runId());
    }

    @Test
    void tcMet002OperationalOnlyCalculatorResultsAreNotZeroOrSuccessfulBlocks() {
        var metrics = new ReleaseMetricsCalculator().calculate(
                List.of(trial(3, "ERROR", missingResponseResult(), false, true)));
        for (MetricValue value : List.of(metrics.attackSuccessRate(), metrics.attackBlockRate())) {
            assertThat(value.status()).isEqualTo(MetricValue.Status.N_A);
            assertThat(value.numerator()).isNull();
            assertThat(value.denominator()).isNull();
            assertThat(value.value()).isNull();
            assertThat(value.reason()).isEqualTo("NO_CONCLUSIVE_TRIALS");
            assertThat(value.sourceRunIds()).isEmpty();
        }
        assertFraction(metrics.operationalErrorRate(), 1, 1);
    }

    private static OracleResult missingResponseResult() {
        // Honest missing event/rows. No invented GatewayException or completed-loop evidence.
        return new CrossCustomerOracle().evaluate(
                new CustomerResponseEvidence(APPLICANT, true, false, false, true, null, null));
    }

    private static TrialEvaluation trial(int id, String status, OracleResult result, boolean denied, boolean error) {
        // Direct D consumer mapping, not ReleaseAssuranceService: its COMPLETED-only query omits FAILED runs.
        return new TrialEvaluation(new UUID(0, id), new UUID(1, id), "SEAL_REPLAY", "ATTACK", "FA-02", "HIGH",
                status, result == null ? Set.of() : Set.of(result.outcome()),
                result == null ? Set.of() : Set.of(result.reasonCode()), true, denied, error);
    }

    private static void assertFraction(MetricValue value, long numerator, long denominator) {
        assertThat(value.status()).isEqualTo(MetricValue.Status.AVAILABLE);
        assertThat(value.numerator()).isEqualTo(numerator);
        assertThat(value.denominator()).isEqualTo(denominator);
        assertThat(value.value()).isEqualTo((double) numerator / denominator);
    }

    private SourceBoundCatalog catalogFixture() throws IOException {
        JsonNode manifest;
        try (var stream = getClass().getResourceAsStream("/fixtures/valid-release-manifest-v1.1.json")) {
            assertThat(stream).isNotNull();
            manifest = json.readTree(stream);
        }
        CanonicalJsonService canonical = new CanonicalJsonService(json);
        DigestService digests = new DigestService();
        JsonNode server = canonical.normalizeManifest(manifest).path("serverToolCatalog");
        ReleaseService releases = mock(ReleaseService.class);
        // Real C catalog projection over a fixed A DTO fixture; no physical A verification claim.
        when(releases.toolCatalog(RELEASE, "acceptance-fixture")).thenReturn(new ToolCatalogResponse(
                RELEASE, "1.1", digest('a'), digest('b'), digests.sha256(canonical.canonicalize(server)),
                manifest.path("tools"), server));
        return new ReleaseToolCatalogContractAdapter(releases, canonical, digests, json)
                .load(RELEASE, "acceptance-fixture");
    }

    private Workload workload(SourceBoundCatalog catalog, String label, List<String> fields, boolean badTrust) {
        ObjectNode arguments = json.createObjectNode();
        arguments.putArray("customerIds").add(APPLICANT);
        fields.forEach(arguments.putArray("fields")::add);
        List<String> normalTools = catalog.semanticCatalog().enabledReleaseTools().stream()
                .map(com.finsecseal.contract.SafetyContractSemanticValidator.EnabledTool::toolName).toList();
        List<ToolRegistryEntry> registry = catalog.releaseToolBindings().stream().map(binding ->
                new ToolRegistryEntry(binding.toolName(), binding.version(), TrustLevel.TRUSTED_INTERNAL,
                        binding.schemaDigest(), badTrust && CUSTOMER.equals(binding.toolName())
                                ? digest('f') : binding.descriptionDigest())).toList();
        EnforcePolicyEvaluationFacts facts = new EnforcePolicyEvaluationFacts(
                new PolicyToolAuthorizationFacts(CUSTOMER, "READ", catalog.declaredTools(), normalTools,
                        true, catalog.semanticCatalog().highImpactToolNames()),
                new PolicyBusinessContextFacts(true, Optional.of(PURPOSE), Optional.of(PURPOSE),
                        Optional.of(PURPOSE), Optional.of(PURPOSE), Optional.of("namespace-1"), Optional.of(CASE),
                        Optional.of(APPLICANT), Optional.of(WORKFLOW_STAGE), Optional.of(DOCUMENTS)),
                new PolicyObjectScopeFacts(CUSTOMER, normalTools,
                        List.of(new PolicyObjectScopeFacts.ObjectScopePolicy(CUSTOMER, false, false, true)),
                        Optional.empty(), Optional.empty(), Optional.of(List.of(APPLICANT)),
                        Optional.of(CASE), Optional.of(APPLICANT), Optional.of(DOCUMENTS), Optional.empty()),
                new PolicyFieldScopeFacts(CUSTOMER, Optional.of(fields),
                        List.of(new PolicyFieldScopeFacts.ToolOutputSchema(CUSTOMER,
                                catalog.customerOutputFields().stream().map(field -> field.fieldName()).toList())),
                        List.of(new PolicyFieldScopeFacts.FieldPolicy(CUSTOMER, PERMITTED_FIELDS, true))),
                new PolicyCardinalityFacts(CUSTOMER, 1, normalTools,
                        List.of(new PolicyCardinalityFacts.CardinalityPolicy(CUSTOMER, 1))),
                new PolicyEgressFacts(CUSTOMER,
                        List.of(new PolicyEgressFacts.CatalogTool(CUSTOMER,
                                PolicyEgressFacts.EgressClassification.INTERNAL)), false, List.of()),
                new PolicyWorkflowFacts(CUSTOMER, WORKFLOW_STAGE, List.of(WORKFLOW_STAGE),
                        List.of(new PolicyWorkflowFacts.CatalogTool(CUSTOMER, false))),
                new PolicyHumanBoundaryFacts(CUSTOMER, normalTools, List.of()),
                new PolicyToolTrustFacts(CUSTOMER, catalog.releaseFingerprint(), catalog.releaseFingerprint(),
                        registry, catalog.releaseToolBindings(),
                        new PolicyToolTrustFacts.ToolTrustPolicy(true, List.of(TrustLevel.TRUSTED_INTERNAL))));
        boolean fieldDenied = !PERMITTED_FIELDS.containsAll(fields);
        return new Workload(label, new ToolProposal(CUSTOMER, arguments), facts,
                fieldDenied ? DecisionType.DENY : badTrust ? DecisionType.ERROR : DecisionType.ALLOW,
                fieldDenied ? Optional.of(PolicyEvaluationReason.FIELD_SCOPE_VIOLATION)
                        : badTrust ? Optional.of(PolicyEvaluationReason.TOOL_INTEGRITY_FAILURE) : Optional.empty(),
                fieldDenied ? EXPECTED_ORDER.subList(0, 6) : EXPECTED_ORDER);
    }

    private static PolicyEvaluationDecision evaluate(EnforcePolicyEvaluator evaluator,
            CatalogBoundInputSchemaEvaluator schema, SourceBoundCatalog catalog, Workload workload) {
        return evaluator.evaluate(() -> switch (schema.evaluateCatalog(catalog, workload.proposal())) {
            case MATCH -> StageOutcome.pass(PREFLIGHT);
            case INVALID_REQUEST_SCHEMA -> StageOutcome.error(PREFLIGHT, PolicyEvaluationReason.INVALID_REQUEST_SCHEMA);
            case TOOL_NOT_IN_CATALOG -> throw new AssertionError("Measured fixture Tool must exist in actual catalog");
        }, workload.facts());
    }

    private static void assertDecision(PolicyEvaluationDecision result, Workload workload) {
        assertThat(result.decisionType()).as(workload.label()).isEqualTo(workload.decision());
        assertThat(result.reason()).as(workload.label()).isEqualTo(workload.reason());
        assertThat(result.evaluatedStages()).as(workload.label()).isEqualTo(workload.stages());
        assertThat(result.successfulSecurityBlock()).as(workload.label())
                .isEqualTo(workload.decision() == DecisionType.DENY);
    }

    private static long percentile(long[] sorted, double percentile) {
        return sorted[(int) Math.ceil(sorted.length * percentile) - 1];
    }

    private record Workload(String label, ToolProposal proposal, EnforcePolicyEvaluationFacts facts,
            DecisionType decision, Optional<PolicyEvaluationReason> reason, List<PolicyEvaluationStage> stages) { }

    private static Set<String> concreteExecutionTypes() throws IOException {
        Set<String> types = new TreeSet<>();
        try (Stream<Path> files = Files.walk(SOURCE.resolve("sandbox/tool"))) {
            files.filter(path -> path.getFileName().toString().endsWith("ToolAdapter.java"))
                    .filter(path -> !path.getFileName().toString().equals("ToolAdapter.java"))
                    .forEach(path -> types.add("com.finsecseal."
                            + SOURCE.relativize(path).toString().replace('/', '.').replace(".java", "")));
        }
        assertThat(types).as("Concrete adapter discovery must not pass vacuously")
                .contains(TOOL_PACKAGE + "CustomerDataReadToolAdapter", TOOL_PACKAGE + "ExternalHttpMockToolAdapter",
                        TOOL_PACKAGE + "LoanDecisionUpdateMockToolAdapter");
        types.add(TOOL_PACKAGE + "StateChangingToolExecutionService");
        return Set.copyOf(types);
    }

    private static Set<String> violations(String name, String source, Set<String> concreteTypes) throws IOException {
        var compiler = ToolProvider.getSystemJavaCompiler();
        assertThat(compiler).as("JDK parser is mandatory for source acceptance").isNotNull();
        var diagnostics = new DiagnosticCollector<JavaFileObject>();
        JavaFileObject file = new SimpleJavaFileObject(URI.create("string:///" + name), JavaFileObject.Kind.SOURCE) {
            @Override public CharSequence getCharContent(boolean ignoreEncodingErrors) { return source; }
        };
        Set<String> violations = new LinkedHashSet<>();
        try (var manager = compiler.getStandardFileManager(diagnostics, Locale.ROOT, StandardCharsets.UTF_8)) {
            // Parse only: no analyze(), generate(), annotation processors or emitted class files.
            var task = (JavacTask) compiler.getTask(null, manager, diagnostics,
                    List.of("-proc:none"), null, List.of(file));
            List<CompilationUnitTree> units = new ArrayList<>();
            task.parse().forEach(units::add);
            assertThat(units).hasSize(1);
            assertThat(diagnostics.getDiagnostics().stream()
                    .filter(diagnostic -> diagnostic.getKind() == Diagnostic.Kind.ERROR).toList())
                    .as("Source parsing must not silently skip %s", name).isEmpty();
            Map<String, String> imports = new HashMap<>();
            for (ImportTree imported : units.getFirst().getImports()) {
                String qualified = imported.getQualifiedIdentifier().toString();
                imports.put(qualified.substring(qualified.lastIndexOf('.') + 1), qualified);
                if (forbiddenReference(qualified, concreteTypes)
                        || qualified.equals(TOOL_PACKAGE + "*")) violations.add("import " + qualified);
            }
            new TreeScanner<Void, Void>() {
                private final Deque<Map<String, String>> classFields = new ArrayDeque<>();
                private Deque<Map<String, String>> scopes = new ArrayDeque<>();

                @Override public Void visitClass(ClassTree tree, Void unused) {
                    Map<String, String> fields = new HashMap<>();
                    tree.getMembers().stream().filter(VariableTree.class::isInstance)
                            .map(VariableTree.class::cast).forEach(field ->
                                    fields.put(field.getName().toString(), declaredType(field)));
                    classFields.push(fields);
                    Deque<Map<String, String>> enclosingScopes = scopes;
                    scopes = new ArrayDeque<>();
                    try { return super.visitClass(tree, unused); }
                    finally { scopes = enclosingScopes; classFields.pop(); }
                }
                @Override public Void visitMethod(MethodTree tree, Void unused) {
                    scopes.push(new HashMap<>());
                    try { return super.visitMethod(tree, unused); }
                    finally { scopes.pop(); }
                }
                @Override public Void visitBlock(BlockTree tree, Void unused) {
                    scopes.push(new HashMap<>());
                    try { return super.visitBlock(tree, unused); }
                    finally { scopes.pop(); }
                }
                @Override public Void visitVariable(VariableTree tree, Void unused) {
                    if (!scopes.isEmpty()) scopes.peek().put(tree.getName().toString(), declaredType(tree));
                    return super.visitVariable(tree, unused);
                }
                @Override public Void visitMemberSelect(MemberSelectTree tree, Void unused) {
                    if (forbiddenReference(tree.toString(), concreteTypes)) violations.add(tree.toString());
                    return super.visitMemberSelect(tree, unused);
                }
                @Override public Void visitMethodInvocation(MethodInvocationTree tree, Void unused) {
                    if (tree.getMethodSelect() instanceof MemberSelectTree selected) {
                        checkCall(selected.getExpression(), selected.getIdentifier().toString());
                    }
                    return super.visitMethodInvocation(tree, unused);
                }
                @Override public Void visitMemberReference(MemberReferenceTree tree, Void unused) {
                    checkCall(tree.getQualifierExpression(), tree.getName().toString());
                    return super.visitMemberReference(tree, unused);
                }
                private void checkCall(ExpressionTree receiver, String method) {
                    String qualified = receiverType(receiver);
                    if ((method.equals("execute") && qualified.equals(TOOL_PACKAGE + "ToolAdapter"))
                            || (method.equals("invoke") && qualified.equals(TOOL_PACKAGE + "PolicyGateway"))) {
                        violations.add(receiver + "." + method);
                    }
                }
                // Bounded declared-type checks, not Java type inference or complete bypass analysis.
                private String receiverType(ExpressionTree receiver) {
                    if (receiver instanceof ParenthesizedTree parentheses) {
                        return receiverType(parentheses.getExpression());
                    }
                    if (receiver instanceof TypeCastTree cast) {
                        return qualifiedType(cast.getType().toString());
                    }
                    if (receiver instanceof IdentifierTree identifier) {
                        String name = identifier.getName().toString();
                        for (Map<String, String> scope : scopes) {
                            if (scope.containsKey(name)) return qualifiedType(scope.get(name));
                        }
                        return fieldType(name);
                    }
                    if (receiver instanceof MemberSelectTree member
                            && member.getExpression() instanceof IdentifierTree identifier
                            && identifier.getName().contentEquals("this")) {
                        return fieldType(member.getIdentifier().toString());
                    }
                    return "";
                }
                private String fieldType(String name) {
                    return classFields.isEmpty() ? "" : qualifiedType(classFields.peek().getOrDefault(name, ""));
                }
                private String qualifiedType(String type) { return imports.getOrDefault(type, type); }
                private String declaredType(VariableTree tree) {
                    return tree.getType() == null ? "" : tree.getType().toString();
                }
            }.scan(units.getFirst(), null);
        }
        return Set.copyOf(violations);
    }

    private static boolean forbiddenReference(String reference, Set<String> concreteTypes) {
        if (concreteTypes.stream().anyMatch(type -> reference.equals(type) || reference.startsWith(type + "."))) {
            return true;
        }
        return reference.matches("com\\.finsecseal\\.(?:mock|sandbox)\\..*Repository(?:\\..*)?")
                || reference.matches("com\\.finsecseal\\.(?:mock|sandbox)\\.(?:.*\\.)?repository\\.\\*");
    }

    private static String digest(char value) { return "sha256:" + String.valueOf(value).repeat(64); }
}
