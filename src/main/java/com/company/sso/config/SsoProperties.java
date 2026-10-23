package com.company.sso.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Validated
@ConfigurationProperties("sso")
public class SsoProperties {
    @NotBlank private String frontendBaseUrl;
    private List<String> allowedOrigins = List.of();
    @Valid private Cookie cookie = new Cookie();
    @Valid private Session session = new Session();
    @Valid private Ticket ticket = new Ticket();
    @Valid private Map<String, Client> clients = new LinkedHashMap<>();

    public String getFrontendBaseUrl() { return frontendBaseUrl; }
    public void setFrontendBaseUrl(String frontendBaseUrl) { this.frontendBaseUrl = frontendBaseUrl; }
    public List<String> getAllowedOrigins() { return allowedOrigins; }
    public void setAllowedOrigins(List<String> allowedOrigins) { this.allowedOrigins = allowedOrigins; }
    public Cookie getCookie() { return cookie; }
    public void setCookie(Cookie cookie) { this.cookie = cookie; }
    public Session getSession() { return session; }
    public void setSession(Session session) { this.session = session; }
    public Ticket getTicket() { return ticket; }
    public void setTicket(Ticket ticket) { this.ticket = ticket; }
    public Map<String, Client> getClients() { return clients; }
    public void setClients(Map<String, Client> clients) { this.clients = clients; }

    public static class Cookie {
        @NotBlank private String name = "YSP_SSO_SESSION";
        private boolean secure;
        @NotBlank private String sameSite = "Lax";
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public boolean isSecure() { return secure; }
        public void setSecure(boolean secure) { this.secure = secure; }
        public String getSameSite() { return sameSite; }
        public void setSameSite(String sameSite) { this.sameSite = sameSite; }
    }

    public static class Session {
        private Duration idleTimeout = Duration.ofMinutes(30);
        private Duration absoluteTimeout = Duration.ofHours(8);
        public Duration getIdleTimeout() { return idleTimeout; }
        public void setIdleTimeout(Duration idleTimeout) { this.idleTimeout = idleTimeout; }
        public Duration getAbsoluteTimeout() { return absoluteTimeout; }
        public void setAbsoluteTimeout(Duration absoluteTimeout) { this.absoluteTimeout = absoluteTimeout; }
    }

    public static class Ticket {
        private Duration ttl = Duration.ofSeconds(30);
        public Duration getTtl() { return ttl; }
        public void setTtl(Duration ttl) { this.ttl = ttl; }
    }

    public static class Client {
        @NotBlank private String id;
        private String secret;
        private String callbackUrl;
        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getSecret() { return secret; }
        public void setSecret(String secret) { this.secret = secret; }
        public String getCallbackUrl() { return callbackUrl; }
        public void setCallbackUrl(String callbackUrl) { this.callbackUrl = callbackUrl; }
    }
}
