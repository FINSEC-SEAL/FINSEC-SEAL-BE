package com.finsecseal.platform.contract;

import com.finsecseal.contract.SafetyContractCanonicalizer;
import com.finsecseal.contract.SafetyContractNarrowingValidator;
import com.finsecseal.contract.SafetyContractPatchProposalPolicy;
import com.finsecseal.contract.SafetyContractSemanticValidator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ContractPolicyConfiguration {
    @Bean
    @ConditionalOnMissingBean(SafetyContractPatchProposalPolicy.class)
    SafetyContractPatchProposalPolicy patchProposalPolicy(SafetyContractCanonicalizer canonicalizer,
            SafetyContractNarrowingValidator narrowing, SafetyContractSemanticValidator semantic) {
        return new SafetyContractPatchProposalPolicy(canonicalizer, narrowing, semantic);
    }
}
