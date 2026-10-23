package com.company.sso.security;

import com.company.sso.common.ApiException;
import com.company.sso.common.CryptoSupport;
import com.company.sso.config.SsoProperties;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

@Service
public class ClientCredentialService {
    private final SsoProperties properties;
    public ClientCredentialService(SsoProperties properties) { this.properties = properties; }

    public SsoProperties.Client requireClient(String authorization) {
        if (authorization == null || !authorization.startsWith("Basic ")) {
            throw unauthorized();
        }
        try {
            String decoded = new String(Base64.getDecoder().decode(authorization.substring(6)), StandardCharsets.UTF_8);
            int separator = decoded.indexOf(':');
            if (separator <= 0) throw unauthorized();
            String id = CryptoSupport.normalizedCode(decoded.substring(0, separator));
            String secret = decoded.substring(separator + 1);
            Optional<SsoProperties.Client> client = properties.getClients().values().stream()
                    .filter(candidate -> CryptoSupport.normalizedCode(candidate.getId()).equals(id)).findFirst();
            if (client.isEmpty() || client.get().getSecret() == null || client.get().getSecret().length() < 32
                    || !CryptoSupport.constantTimeEquals(client.get().getSecret(), secret)) throw unauthorized();
            return client.get();
        } catch (IllegalArgumentException exception) {
            throw unauthorized();
        }
    }

    public SsoProperties.Client requireClientForSystem(String authorization, String system) {
        SsoProperties.Client client = requireClient(authorization);
        if (!CryptoSupport.normalizedCode(client.getId()).equals(CryptoSupport.normalizedCode(system))) throw unauthorized();
        return client;
    }

    public SsoProperties.Client findConfiguredClient(String clientCode) {
        String code = CryptoSupport.normalizedCode(clientCode);
        return properties.getClients().values().stream()
                .filter(candidate -> CryptoSupport.normalizedCode(candidate.getId()).equals(code))
                .filter(candidate -> candidate.getCallbackUrl() != null && !candidate.getCallbackUrl().isBlank())
                .findFirst()
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "INVALID_CLIENT", "Unknown client"));
    }

    private ApiException unauthorized() {
        return new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_CLIENT_CREDENTIALS", "Client authentication failed");
    }
}
