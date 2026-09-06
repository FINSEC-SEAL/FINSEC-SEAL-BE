package com.finsecseal.runtime.ai;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "finsec.ai", name = "deterministic", havingValue = "true", matchIfMissing = false)
public class AgentAiDeterministicConfiguration {

    @Bean
    AgentAiClient deterministicAgentAiClient() {
        return new DeterministicFakeAgentAiClient();
    }
}
