package com.finsecseal.runtime.ai;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tools.jackson.databind.ObjectMapper;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "finsec.ai.enabled", havingValue = "true")
public class AgentAiHttpConfiguration {

    @Bean
    @ConditionalOnMissingBean(AgentAiClient.class)
    HttpAgentAiClient httpAgentAiClient(
            ObjectMapper objectMapper,
            AgentRunContextResolver runContextResolver,
            @Value("${finsec.ai.base-url:http://localhost:8001}") URI baseUrl,
            @Value("${finsec.ai.connect-timeout:2s}") Duration connectTimeout,
            @Value("${finsec.ai.request-timeout:5s}") Duration requestTimeout
    ) {
        HttpClient httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(connectTimeout)
                .build();
        String apiKey = System.getenv("OPENAI_API_KEY");
        // allow overriding via finsec.ai.api-key property
        // Spring will not inject empty nested placeholders cleanly in all cases, so check system properties too
        String configured = System.getProperty("finsec.ai.api-key");
        if (configured != null && !configured.isBlank()) {
            apiKey = configured;
        }

        return new HttpAgentAiClient(
                httpClient,
                objectMapper,
                runContextResolver,
                baseUrl,
                requestTimeout,
                apiKey
        );
    }
}
