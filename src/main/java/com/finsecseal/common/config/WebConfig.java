package com.finsecseal.common.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    private static final String[] METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"};
    private static final String[] HEADERS = {
            "Authorization", "Content-Type", "Last-Event-ID", "X-Trace-Id",
            "Idempotency-Key", "If-Match", "X-CSRF-Token", "X-Actor-Id",
            "X-Operator-Recovery-Key", "X-Contract-Reviewer-Key"
    };
    private static final String[] EXPOSED_HEADERS = {"X-Trace-Id", "ETag", "Location", "Idempotent-Replayed"};
    private final String[] allowedOrigins;

    public WebConfig(@Value("${finsec.cors.allowed-origins}") String allowedOrigins) {
        this.allowedOrigins = Arrays.stream(allowedOrigins.split(","))
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .toArray(String[]::new);
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOrigins(allowedOrigins)
                .allowedMethods(METHODS)
                .allowedHeaders(HEADERS)
                .exposedHeaders(EXPOSED_HEADERS)
                .allowCredentials(true);
    }

    @Bean
    FilterRegistrationBean<CorsFilter> earlyApiCorsFilter() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of(allowedOrigins));
        configuration.setAllowedMethods(List.of(METHODS));
        configuration.setAllowedHeaders(List.of(HEADERS));
        configuration.setExposedHeaders(List.of(EXPOSED_HEADERS));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", configuration);
        CorsFilter filter = new CorsFilter(source) {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                    FilterChain chain) throws ServletException, IOException {
                // Preflight must still reach route guards before MVC decides whether it is allowed.
                if (CorsUtils.isPreFlightRequest(request)) {
                    chain.doFilter(request, response);
                } else {
                    super.doFilterInternal(request, response, chain);
                }
            }
        };
        FilterRegistrationBean<CorsFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 1);
        return registration;
    }
}
