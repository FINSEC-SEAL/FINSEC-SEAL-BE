package com.finsecseal.runtime.ai;

import java.net.http.HttpClient;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tools.jackson.databind.ObjectMapper;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "finsec.ai.openai.enabled", havingValue = "true")
public class AgentAiOpenAiConfiguration {

    @Bean
    @ConditionalOnMissingBean(AgentAiClient.class)
    OpenAiAgentAiClient openAiAgentAiClient(
            ObjectMapper objectMapper,
            AgentRunContextResolver runContextResolver,
            @Value("${finsec.ai.openai.model:gpt-4o-mini}") String model,
            @Value("${finsec.ai.request-timeout:10s}") Duration requestTimeout
    ) {
        HttpClient httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .build();
        String apiKey = System.getenv("OPENAI_API_KEY");
        String configured = System.getProperty("finsec.ai.api-key");
        if (configured != null && !configured.isBlank()) {
            apiKey = configured;
        }

        return new OpenAiAgentAiClient(
                httpClient,
                objectMapper,
                runContextResolver,
                model,
                requestTimeout,
                apiKey
        );
    }
}
