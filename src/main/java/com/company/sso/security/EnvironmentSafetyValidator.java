package com.company.sso.security;

import com.company.sso.config.SsoProperties;
import jakarta.annotation.PostConstruct;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.Arrays;

@Component
public class EnvironmentSafetyValidator {
    private final Environment environment;
    private final SsoProperties properties;
    public EnvironmentSafetyValidator(Environment environment, SsoProperties properties) {
        this.environment = environment;
        this.properties = properties;
    }
    @PostConstruct
    void validate() {
        boolean securedEnvironment = Arrays.stream(environment.getActiveProfiles()).anyMatch(profile -> profile.equals("test") || profile.equals("prod"));
        if (!securedEnvironment) return;
        if (!properties.getCookie().isSecure()) throw new IllegalStateException("Secure cookie is required outside local profile");
        properties.getClients().values().forEach(client -> {
            if (client.getSecret() == null || client.getSecret().length() < 32) throw new IllegalStateException("A high-entropy client secret is required");
            if (client.getCallbackUrl() == null || !"https".equalsIgnoreCase(URI.create(client.getCallbackUrl()).getScheme())) {
                throw new IllegalStateException("HTTPS callback URL is required outside local profile");
            }
        });
        if (properties.getAllowedOrigins().stream().anyMatch(origin -> origin.equals("*"))) {
            throw new IllegalStateException("Wildcard CORS origin is not permitted");
        }
    }
}
