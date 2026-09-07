package com.finsecseal.runtime.ai;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.finsecseal.evidence.ExecutionEventService;
import tools.jackson.databind.ObjectMapper;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "finsec.ai.openai.mock.enabled", havingValue = "true")
public class AgentAiMockConfiguration {

    @Bean
    @ConditionalOnMissingBean(AgentAiClient.class)
    public AgentAiClient mockOpenAiAgentAiClient(ObjectMapper objectMapper,
                                                 org.springframework.beans.factory.ObjectProvider<com.finsecseal.evidence.ExecutionEventService> eventServiceProvider) {
        return new MockOpenAiAgentAiClient(objectMapper, eventServiceProvider.getIfAvailable());
    }
}
