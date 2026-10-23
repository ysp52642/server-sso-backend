package com.company.sso.config;

import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A dependency-free OpenAPI document for the Phase 1 public contract. It is deliberately
 * absent under the prod profile so production does not disclose its API surface.
 */
@RestController
@Profile("!prod")
public class OpenApiController {
    @GetMapping("/v3/api-docs")
    public Map<String, Object> document() {
        Map<String, Object> paths = new LinkedHashMap<>();
        paths.put("/api/v1/auth/login", operation("post", "Create a central SSO session"));
        paths.put("/api/v1/auth/me", operation("get", "Read the current central SSO identity"));
        paths.put("/api/v1/auth/change-password", operation("post", "Change the current user's password"));
        paths.put("/api/v1/auth/logout", operation("post", "Revoke the current central SSO session"));
        paths.put("/sso/authorize", operation("get", "Issue a single-use SSO ticket"));
        paths.put("/api/v1/sso/ticket/validate", operation("post", "Consume a client-bound SSO ticket"));
        paths.put("/api/v1/sso/users/provision", operation("post", "Provision an Employee Portal identity"));
        paths.put("/api/v1/admin/users", operation("get", "Search SSO users"));
        return Map.of("openapi", "3.1.0", "info", Map.of("title", "Employee SSO API", "version", "v1"), "paths", paths);
    }

    private Map<String, Object> operation(String method, String summary) {
        return Map.of(method, Map.of("summary", summary, "responses", Map.of("200", Map.of("description", "Success"))));
    }
}
