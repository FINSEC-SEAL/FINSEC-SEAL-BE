package com.finsecseal.policy;

import com.finsecseal.contract.LoanReviewFinancialTemplate;
import com.finsecseal.contract.SafetyContractLifecyclePolicy.ReviewerContext;
import com.finsecseal.evidence.ExecutionEventService;
import com.finsecseal.evidence.RedactionService;
import com.finsecseal.evidence.TestRunProjectionService;
import com.finsecseal.release.ReleaseService;
import com.finsecseal.sandbox.tool.StateChangingToolExecutionService;
import com.finsecseal.sandbox.tool.ToolAdapter;
import java.util.List;
import java.util.function.Supplier;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.transaction.PlatformTransactionManager;
import tools.jackson.databind.ObjectMapper;

/** Explicit local composition; owner-backed identity and observations are required to enable it. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "finsec.policy.gateway.enabled", havingValue = "true", matchIfMissing = false)
public class LoanReviewPolicyGatewayConfiguration {
    public static final String REVIEWER_CONTEXT_BEAN = "loanReviewGatewayReviewerContext";

    @Bean
    @Primary
    LoanReviewPolicyGateway loanReviewPolicyGateway(PlatformTransactionManager transactions,
            @Qualifier(REVIEWER_CONTEXT_BEAN) Supplier<ReviewerContext> reviewers,
            GatewayRuntimeObservations observations, GatewayApprovedPolicySourceService approved,
            GatewayBaselinePolicySourceService baseline, TestRunProjectionService runs,
            ReleaseService releases, GatewayPolicyFactsAssembler facts, ExecutionEventService events,
            StateChangingToolExecutionService mutations, RedactionService redaction, ObjectMapper json,
            LoanReviewFinancialTemplate template, List<ToolAdapter> adapters, Environment environment) {
        if (Boolean.TRUE.equals(environment.getProperty("policy.gateway.enabled", Boolean.class))
                || Boolean.TRUE.equals(environment.getProperty("policy.gateway.c.enabled", Boolean.class))) {
            throw new IllegalStateException("Local C Gateway cannot be combined with a remote Gateway");
        }
        // Keep the supplier itself: identity must be resolved for each invocation, not at bean creation.
        return new LoanReviewPolicyGateway(transactions, reviewers, observations, approved, baseline, runs,
                releases, facts, events, mutations, redaction, json, template, adapters);
    }
}
