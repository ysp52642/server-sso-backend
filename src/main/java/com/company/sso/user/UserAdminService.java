package com.company.sso.user;

import com.company.sso.auth.PasswordPolicy;
import com.company.sso.auth.UserView;
import com.company.sso.common.ApiException;
import com.company.sso.common.CryptoSupport;
import com.company.sso.session.SsoSessionService;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Service
public class UserAdminService {
    private final UserRepository users;
    private final PasswordEncoder passwords;
    private final PasswordPolicy policy;
    private final SsoSessionService sessions;
    public UserAdminService(UserRepository users, PasswordEncoder passwords, PasswordPolicy policy, SsoSessionService sessions) {
        this.users = users;
        this.passwords = passwords;
        this.policy = policy;
        this.sessions = sessions;
    }

    public UserPage page(String query, int page, int size) {
        int safePage = Math.max(page, 0);
        int safeSize = Math.min(Math.max(size, 1), 100);
        List<UserView> result = users.findPage(query, safeSize, safePage * safeSize).stream().map(UserView::from).toList();
        return new UserPage(result, safePage, safeSize, users.count(query));
    }
    public UserView get(long id) { return UserView.from(requireUser(id)); }

    @Transactional
    public UserView create(AdminUserCreateRequest request) {
        String employeeNo = code(request.employeeNo());
        String username = CryptoSupport.normalizedUsername(request.username());
        if (users.findEmployeeId(employeeNo).isPresent() || users.findIdentityByUsername(username).isPresent()) {
            throw conflict("Employee number or username already exists");
        }
        long orgUnitId = users.ensureOrgUnit(orgCode(request.orgUnitCode()), orgCode(request.orgUnitCode()));
        long employeeId = users.createEmployee(employeeNo, request.displayName().trim(), request.email(), orgUnitId);
        UserIdentity provisional = provisional(0, employeeId, username, employeeNo, request.displayName(), request.email());
        policy.verify(request.temporaryPassword(), provisional, null);
        long userId = users.createUser(employeeId, username, passwords.encode(request.temporaryPassword()), true, true);
        replaceRoles(userId, request.roles() == null || request.roles().isEmpty() ? List.of("EMPLOYEE") : request.roles());
        return UserView.from(requireUser(userId));
    }

    @Transactional
    public UserView provision(ProvisionRequest request) {
        String employeeNo = code(request.employeeNo());
        String username = CryptoSupport.normalizedUsername(request.username());
        Long employeeId = users.findEmployeeId(employeeNo).orElse(null);
        long orgUnitId = users.ensureOrgUnit(orgCode(request.orgUnitCode()), orgCode(request.orgUnitCode()));
        if (employeeId == null) employeeId = users.createEmployee(employeeNo, request.displayName().trim(), request.email(), orgUnitId);
        else users.updateEmployee(employeeId, request.displayName().trim(), request.email(), orgUnitId);
        Long existingUserId = users.findUserIdForEmployee(employeeId).orElse(null);
        if (existingUserId != null) return UserView.from(requireUser(existingUserId));
        if (users.findIdentityByUsername(username).isPresent()) throw conflict("Username already belongs to another employee");
        UserIdentity provisional = provisional(0, employeeId, username, employeeNo, request.displayName(), request.email());
        policy.verify(request.initialPassword(), provisional, null);
        long userId = users.createUser(employeeId, username, passwords.encode(request.initialPassword()), true, true);
        replaceRoles(userId, List.of("EMPLOYEE"));
        return UserView.from(requireUser(userId));
    }

    @Transactional
    public UserView setEnabled(long id, boolean enabled) {
        requireUser(id);
        users.setEnabled(id, enabled);
        if (!enabled) sessions.revokeAll(id);
        return UserView.from(requireUser(id));
    }

    @Transactional
    public UserView unlock(long id) {
        requireUser(id);
        users.unlock(id);
        return UserView.from(requireUser(id));
    }

    @Transactional
    public void resetPassword(long id, String password) {
        UserIdentity user = requireUser(id);
        policy.verify(password, user, null);
        users.setPasswordForReset(id, passwords.encode(password), Instant.now());
        sessions.revokeAll(id);
    }

    @Transactional
    public UserView updateRoles(long id, List<String> roles) {
        requireUser(id);
        replaceRoles(id, roles);
        return UserView.from(requireUser(id));
    }

    private void replaceRoles(long userId, List<String> roles) {
        Set<String> codes = new LinkedHashSet<>();
        for (String role : roles) codes.add(code(role));
        try {
            users.replaceRoles(userId, codes);
        } catch (IllegalArgumentException exception) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "INVALID_ROLE", "One or more specified roles do not exist");
        }
    }
    private UserIdentity requireUser(long id) {
        return users.findIdentity(id).orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "USER_NOT_FOUND", "User was not found"));
    }
    private UserIdentity provisional(long id, long employeeId, String username, String employeeNo, String displayName, String email) {
        return new UserIdentity(id, employeeId, username, employeeNo, displayName, email, null, true, true, false, true, List.of());
    }
    private String code(String value) { return value == null ? "" : value.trim().toUpperCase(Locale.ROOT); }
    private String orgCode(String value) { return value == null || value.isBlank() ? "SYSTEM" : code(value); }
    private ApiException conflict(String message) { return new ApiException(HttpStatus.CONFLICT, "DUPLICATE_USER", message); }
}
