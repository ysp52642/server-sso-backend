package com.company.sso.auth;

import com.company.sso.audit.AuditRepository;
import com.company.sso.common.ApiException;
import com.company.sso.common.CryptoSupport;
import com.company.sso.session.SsoSessionService;
import com.company.sso.user.UserAccount;
import com.company.sso.user.UserIdentity;
import com.company.sso.user.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Map;

@Service
public class AuthService {
    private final UserRepository users;
    private final SsoSessionService sessions;
    private final AuditRepository audit;
    private final PasswordEncoder passwords;
    private final PasswordPolicy policy;
    public AuthService(UserRepository users, SsoSessionService sessions, AuditRepository audit, PasswordEncoder passwords, PasswordPolicy policy) {
        this.users = users;
        this.sessions = sessions;
        this.audit = audit;
        this.passwords = passwords;
        this.policy = policy;
    }

    @Transactional
    public LoginResult login(LoginRequest request, String ip, String userAgent) {
        String username = CryptoSupport.normalizedUsername(request.username());
        UserAccount account = users.findAccountByUsername(username).orElse(null);
        if (account == null) {
            audit.record(null, username, "LOGIN", false, "INVALID_CREDENTIALS", ip, userAgent);
            throw invalidCredentials();
        }
        UserIdentity user = account.identity();
        if (user.locked()) {
            audit.record(user.userId(), username, "LOGIN", false, "ACCOUNT_LOCKED", ip, userAgent);
            throw new ApiException(HttpStatus.LOCKED, "ACCOUNT_LOCKED", "Account is locked");
        }
        if (!user.userEnabled() || !user.employeeEnabled() || !passwords.matches(request.password(), account.passwordHash())) {
            if (user.userEnabled() && user.employeeEnabled()) users.recordFailedLogin(user.userId(), Instant.now());
            audit.record(user.userId(), username, "LOGIN", false, "INVALID_CREDENTIALS", ip, userAgent);
            throw invalidCredentials();
        }
        Instant now = Instant.now();
        users.resetFailedLoginsAndUpdateLogin(user.userId(), now);
        String rawSession = sessions.create(user, ip, userAgent);
        audit.record(user.userId(), username, "LOGIN", true, null, ip, userAgent);
        return new LoginResult(rawSession, UserView.from(user));
    }

    @Transactional
    public void changePassword(UserIdentity user, ChangePasswordRequest request, String currentRawSession) {
        UserAccount account = users.findAccountByUsername(user.username()).orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "UNAUTHENTICATED", "Authentication required"));
        if (!passwords.matches(request.currentPassword(), account.passwordHash())) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "INVALID_CURRENT_PASSWORD", "Current password is incorrect", Map.of("currentPassword", "Current password is incorrect"));
        }
        if (!request.newPassword().equals(request.confirmPassword())) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "PASSWORD_CONFIRMATION_MISMATCH", "New passwords do not match", Map.of("confirmPassword", "Passwords do not match"));
        }
        policy.verify(request.newPassword(), user, request.currentPassword());
        users.changePassword(user.userId(), passwords.encode(request.newPassword()), Instant.now());
        sessions.revokeOtherSessions(user.userId(), currentRawSession);
    }

    @Transactional
    public void logout(UserIdentity user, String rawSession, String ip, String userAgent) {
        sessions.revoke(rawSession);
        audit.record(user.userId(), user.username(), "LOGOUT", true, null, ip, userAgent);
    }

    private ApiException invalidCredentials() {
        return new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", "Invalid username or password");
    }

    public record LoginResult(String rawSession, UserView user) { }
}
