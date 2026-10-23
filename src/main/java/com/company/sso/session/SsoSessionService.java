package com.company.sso.session;

import com.company.sso.common.CryptoSupport;
import com.company.sso.config.SsoProperties;
import com.company.sso.user.UserIdentity;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;

@Service
public class SsoSessionService {
    private final SessionRepository sessions;
    private final SsoProperties properties;
    public SsoSessionService(SessionRepository sessions, SsoProperties properties) {
        this.sessions = sessions;
        this.properties = properties;
    }

    public String create(UserIdentity user, String ip, String userAgent) {
        Instant now = Instant.now();
        String raw = CryptoSupport.newOpaqueToken();
        sessions.create(user.userId(), CryptoSupport.sha256(raw), now, now.plus(properties.getSession().getIdleTimeout()),
                now.plus(properties.getSession().getAbsoluteTimeout()), ip, userAgent);
        return raw;
    }
    public Optional<SessionRecord> findActive(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) return Optional.empty();
        String hash = CryptoSupport.sha256(rawToken);
        Instant now = Instant.now();
        Optional<SessionRecord> session = sessions.findActive(hash, now);
        session.ifPresent(ignored -> sessions.touch(hash, now, now.plus(properties.getSession().getIdleTimeout())));
        return session;
    }
    public void revoke(String rawToken) {
        if (rawToken != null && !rawToken.isBlank()) sessions.revoke(CryptoSupport.sha256(rawToken), Instant.now());
    }
    public void revokeOtherSessions(long userId, String currentRawToken) {
        sessions.revokeOtherSessions(userId, CryptoSupport.sha256(currentRawToken), Instant.now());
    }
    public void revokeAll(long userId) { sessions.revokeAll(userId, Instant.now()); }
}
