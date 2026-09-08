package com.finsecseal.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.common.api.ErrorCode;
import com.finsecseal.common.domain.TestRunMode;
import com.finsecseal.contract.LoanReviewFinancialTemplate;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.evidence.RedactionService;
import com.finsecseal.evidence.TestRunProjectionService;
import com.finsecseal.policy.LoanReviewPolicyGateway.FailureCode;
import com.finsecseal.policy.LoanReviewPolicyGateway.GatewayException;
import com.finsecseal.release.ReleaseService;
import com.finsecseal.runtime.ToolInvocation;
import com.finsecseal.runtime.ToolProposal;
import com.finsecseal.runtime.ToolProposalValidator;
import com.finsecseal.sandbox.SandboxExecutionContext;
import com.finsecseal.sandbox.tool.BaselineToolExecutionPolicy;
import com.finsecseal.sandbox.tool.PolicyGateway;
import com.finsecseal.sandbox.tool.StateChangingToolExecutionService;
import com.finsecseal.sandbox.tool.TemporaryPolicyGatewayBridge;
import com.finsecseal.sandbox.tool.ToolAdapter;
import com.finsecseal.sandbox.tool.ToolDispatcher;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.transaction.PlatformTransactionManager;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/** Spring selection and fail-closed wiring only; all supplied identity/owner controls are synthetic. */
class LoanReviewPolicyGatewayConfigurationTest {
    private static final String ENABLED = "finsec.policy.gateway.enabled=true";
    private static final String REVIEWER_BEAN = "loanReviewGatewayReviewerContext";
    private static final String TOOL = "CUSTOMER_DATA_READ";
    private static final String ACTOR = "configuration-fixture-reviewer";
    private static final String PRIVATE = "CONFIGURATION-PRIVATE-IDENTITY-CANARY";
    private static final UUID RUN = UUID.fromString("10000000-0000-4000-8000-000000000001");
    private static final UUID CASE_RUN = UUID.fromString("10000000-0000-4000-8000-000000000002");
    private static final UUID TRACE = UUID.fromString("10000000-0000-4000-8000-000000000003");
    private static final UUID CALL = UUID.fromString("10000000-0000-4000-8000-000000000004");

    @ParameterizedTest @ValueSource(strings = {"absent", "false"})
    void disabledByDefaultPreservesActualBridgeWithoutAnyCProvider(String setting) {
        Fixture fixture = new Fixture();
        ApplicationContextRunner runner = bridgeRunner(fixture);
        if (!setting.equals("absent")) runner = runner.withPropertyValues("finsec.policy.gateway.enabled=" + setting);
        runner.run(context -> {
            assertThat(context).hasNotFailed().doesNotHaveBean(LoanReviewPolicyGateway.class)
                    .doesNotHaveBean(GatewayRuntimeObservations.class).doesNotHaveBean(REVIEWER_BEAN)
                    .hasSingleBean(PolicyGateway.class).hasSingleBean(ToolDispatcher.class);
            assertThat(context.getBean(PolicyGateway.class)).isSameAs(context.getBean(TemporaryPolicyGatewayBridge.class));
            // Actual Dispatcher/validator reach the actual BASELINE-only bridge, which rejects this mode.
            assertThatThrownBy(() -> context.getBean(ToolDispatcher.class).dispatch(
                    sandbox(TestRunMode.SEAL_REPLAY), invocation(fixture.json), ACTOR))
                    .isInstanceOfSatisfying(BusinessException.class,
                            failure -> assertThat(failure.errorCode()).isEqualTo(ErrorCode.CONFIGURATION_ERROR));
            assertThat(fixture.adapter.validations).isEqualTo(1);
            assertThat(fixture.adapter.executions).isZero();
            verifyNoInteractions(fixture.events, fixture.mutations);
        });
    }

    @Test
    void explicitOptInSelectsPrimaryCAndResolvesIdentityForEveryCallWithoutFallback() {
        Fixture fixture = new Fixture();
        SyntheticReviewerProvider provider = new SyntheticReviewerProvider();
        withCDependencies(bridgeRunner(fixture), fixture).withPropertyValues(ENABLED,
                        "policy.gateway.enabled=false", "policy.gateway.c.enabled=false")
                .withBean(REVIEWER_BEAN, SyntheticReviewerProvider.class, () -> provider)
                .withBean(GatewayRuntimeObservations.class, () -> fixture.observations)
                .run(context -> {
                    assertThat(context).hasNotFailed().hasSingleBean(LoanReviewPolicyGateway.class)
                            .hasSingleBean(TemporaryPolicyGatewayBridge.class).hasSingleBean(ToolDispatcher.class)
                            .hasSingleBean(ToolProposalValidator.class);
                    assertThat(LoanReviewPolicyGatewayConfiguration.REVIEWER_CONTEXT_BEAN).isEqualTo(REVIEWER_BEAN);
                    assertThat(context.getBeansOfType(PolicyGateway.class)).hasSize(2);
                    assertThat(context.getBean(PolicyGateway.class)).isSameAs(context.getBean(LoanReviewPolicyGateway.class));
                    assertThat(provider.resolutions).as("Bean creation must retain, not resolve, the supplier").isZero();
                    ToolDispatcher dispatcher = context.getBean(ToolDispatcher.class);
                    expectAuthenticationFailure(dispatcher, fixture);
                    assertThat(provider.resolutions).isEqualTo(1);
                    provider.current = reviewer(ACTOR, false);
                    expectAuthenticationFailure(dispatcher, fixture);
                    assertThat(provider.resolutions).isEqualTo(2);
                    provider.current = reviewer("different-fixture-actor", true);
                    expectAuthenticationFailure(dispatcher, fixture);
                    assertThat(provider.resolutions).isEqualTo(3);
                    assertThat(fixture.adapter.validations).isEqualTo(3);
                    assertThat(fixture.adapter.executions).isZero();
                    // A BASELINE bridge fallback would append POLICY_EVALUATED; none of its effects occurred.
                    // These references are explicit mocks, never actual @Autowired objects passed to verify().
                    verifyNoInteractions(fixture.events, fixture.mutations, fixture.observations, fixture.transactions,
                            fixture.approved, fixture.baseline, fixture.runs, fixture.releases, fixture.facts);
                });
    }

    @ParameterizedTest @ValueSource(strings = {"missing", "wrong-qualifier"})
    void optInFailsStartupWithoutExactlyQualifiedReviewerProvider(String variant) {
        Fixture fixture = new Fixture();
        ApplicationContextRunner runner = withCDependencies(bridgeRunner(fixture), fixture)
                .withPropertyValues(ENABLED)
                .withBean(GatewayRuntimeObservations.class, () -> fixture.observations);
        if (variant.equals("wrong-qualifier")) {
            runner = runner.withBean("unrelatedReviewerSupplier", SyntheticReviewerProvider.class,
                    SyntheticReviewerProvider::new);
        }
        runner.run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasRootCauseInstanceOf(NoSuchBeanDefinitionException.class)
                    .hasStackTraceContaining(REVIEWER_BEAN);
            assertThat(fixture.adapter.executions).isZero();
        });
    }

    @Test
    void optInFailsStartupWithoutObservationProvider() {
        Fixture fixture = new Fixture();
        withCDependencies(bridgeRunner(fixture), fixture).withPropertyValues(ENABLED)
                .withBean(REVIEWER_BEAN, SyntheticReviewerProvider.class, SyntheticReviewerProvider::new)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasRootCauseInstanceOf(NoSuchBeanDefinitionException.class)
                            .hasStackTraceContaining(GatewayRuntimeObservations.class.getName());
                    assertThat(fixture.adapter.executions).isZero();
                });
    }

    @ParameterizedTest @ValueSource(strings = {"policy.gateway.enabled", "policy.gateway.c.enabled"})
    void optInRejectsEachRemoteGatewayFlagAtStartup(String flag) {
        Fixture fixture = new Fixture();
        completeLocalRunner(fixture).withPropertyValues(flag + "=true").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasRootCauseInstanceOf(IllegalStateException.class)
                    .hasRootCauseMessage("Local C Gateway cannot be combined with a remote Gateway");
            assertThat(fixture.adapter.executions).isZero();
            verifyNoInteractions(fixture.events, fixture.mutations, fixture.observations, fixture.transactions);
        });
    }

    @Test
    void localConfigurationItselfRejectsDuplicateAdapterNames() {
        Fixture fixture = new Fixture();
        // No bridge or B validator is registered here: their earlier duplicate checks cannot mask C's check.
        completeLocalRunner(fixture).withBean("duplicateAdapter", ProbeAdapter.class, ProbeAdapter::new)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = context.getStartupFailure();
                    while (root.getCause() != null) root = root.getCause();
                    assertThat(root).isInstanceOfSatisfying(GatewayException.class, failure -> {
                        assertThat(failure.code()).isEqualTo(FailureCode.ADAPTER_UNAVAILABLE);
                        assertThat(failure.successfulSecurityBlock()).isFalse();
                        assertThat(failure.getCause()).isNull();
                    });
                    assertThat(fixture.adapter.executions).isZero();
                });
    }

    private static ApplicationContextRunner bridgeRunner(Fixture fixture) {
        return commonBeans(new ApplicationContextRunner().withUserConfiguration(
                LoanReviewPolicyGatewayConfiguration.class, ToolDispatcher.class, TemporaryPolicyGatewayBridge.class,
                ToolProposalValidator.class, BaselineToolExecutionPolicy.class), fixture);
    }

    private static ApplicationContextRunner completeLocalRunner(Fixture fixture) {
        return withCDependencies(commonBeans(new ApplicationContextRunner()
                        .withUserConfiguration(LoanReviewPolicyGatewayConfiguration.class), fixture), fixture)
                .withPropertyValues(ENABLED)
                .withBean(REVIEWER_BEAN, SyntheticReviewerProvider.class, SyntheticReviewerProvider::new)
                .withBean(GatewayRuntimeObservations.class, () -> fixture.observations);
    }

    private static ApplicationContextRunner commonBeans(ApplicationContextRunner runner, Fixture fixture) {
        return runner.withBean(ObjectMapper.class, () -> fixture.json)
                .withBean(ExecutionEventService.class, () -> fixture.events)
                .withBean(StateChangingToolExecutionService.class, () -> fixture.mutations)
                .withBean("fixtureAdapter", ProbeAdapter.class, () -> fixture.adapter);
    }

    private static ApplicationContextRunner withCDependencies(ApplicationContextRunner runner, Fixture fixture) {
        return runner.withBean(PlatformTransactionManager.class, () -> fixture.transactions)
                .withBean(GatewayApprovedPolicySourceService.class, () -> fixture.approved)
                .withBean(GatewayBaselinePolicySourceService.class, () -> fixture.baseline)
                .withBean(TestRunProjectionService.class, () -> fixture.runs)
                .withBean(ReleaseService.class, () -> fixture.releases)
                .withBean(GatewayPolicyFactsAssembler.class, () -> fixture.facts)
                .withBean(RedactionService.class, () -> fixture.redaction)
                .withBean(LoanReviewFinancialTemplate.class, () -> new LoanReviewFinancialTemplate(fixture.json));
    }

    private static void expectAuthenticationFailure(ToolDispatcher dispatcher, Fixture fixture) {
        assertThatThrownBy(() -> dispatcher.dispatch(sandbox(TestRunMode.BASELINE), invocation(fixture.json), ACTOR))
                .isInstanceOfSatisfying(GatewayException.class, failure -> {
                    assertThat(failure.code()).isEqualTo(FailureCode.AUTHENTICATION_REQUIRED);
                    assertThat(failure.successfulSecurityBlock()).isFalse();
                    assertThat(failure.getCause()).isNull();
                    assertThat(failure.getSuppressed()).isEmpty();
                    assertThat(failure.toString()).doesNotContain(PRIVATE);
                });
    }

    private static SandboxExecutionContext sandbox(TestRunMode mode) {
        return new SandboxExecutionContext(RUN, CASE_RUN, TRACE, mode, "CASE-1001", "CUST-1001");
    }

    private static ToolInvocation invocation(ObjectMapper json) {
        var arguments = json.createObjectNode();
        arguments.putArray("customerIds").add("CUST-1001");
        arguments.putArray("fields").add("incomeBand");
        return new ToolInvocation(new ToolProposal(TOOL, arguments), CALL, "sha256:" + "a".repeat(64));
    }

    private static ReviewerContext reviewer(String actor, boolean authenticated) {
        return new ReviewerContext(UUID.randomUUID(), actor, "AI_SECURITY_REVIEWER", PRIVATE,
                authenticated, true, false);
    }

    /** Deliberately synthetic and invalid for execution: this fixture does not authenticate any real actor. */
    private static final class SyntheticReviewerProvider implements Supplier<ReviewerContext> {
        private ReviewerContext current;
        private int resolutions;
        @Override public ReviewerContext get() { resolutions++; return current; }
    }

    private static final class ProbeAdapter implements ToolAdapter {
        private int validations;
        private int executions;
        @Override public String toolName() { return TOOL; }
        @Override public void validateArguments(JsonNode arguments) { validations++; }
        @Override public ToolExecutionResult execute(SandboxExecutionContext context, JsonNode arguments) {
            executions++;
            throw new AssertionError("Configuration failures must never execute a fixture adapter");
        }
    }

    private static final class Fixture {
        private final ObjectMapper json = new ObjectMapper();
        private final ProbeAdapter adapter = new ProbeAdapter();
        private final ExecutionEventService events = mock(ExecutionEventService.class);
        private final StateChangingToolExecutionService mutations = mock(StateChangingToolExecutionService.class);
        private final PlatformTransactionManager transactions = mock(PlatformTransactionManager.class);
        private final GatewayApprovedPolicySourceService approved = mock(GatewayApprovedPolicySourceService.class);
        private final GatewayBaselinePolicySourceService baseline = mock(GatewayBaselinePolicySourceService.class);
        private final TestRunProjectionService runs = mock(TestRunProjectionService.class);
        private final ReleaseService releases = mock(ReleaseService.class);
        private final GatewayPolicyFactsAssembler facts = mock(GatewayPolicyFactsAssembler.class);
        private final RedactionService redaction = mock(RedactionService.class);
        private final GatewayRuntimeObservations observations = mock(GatewayRuntimeObservations.class);
    }
}
