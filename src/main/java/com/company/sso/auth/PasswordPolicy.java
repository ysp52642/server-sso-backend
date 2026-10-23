package com.company.sso.auth;

import com.company.sso.common.ApiException;
import com.company.sso.user.UserIdentity;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Map;

@Component
public class PasswordPolicy {
    public void verify(String value, UserIdentity user, String currentPassword) {
        if (value == null || value.length() < 10 || value.length() > 200 || !value.matches(".*[A-Za-z].*") || !value.matches(".*\\d.*")) {
            throw invalid("New password must be 10–200 characters and contain both a letter and a number");
        }
        String normalized = value.toLowerCase(Locale.ROOT);
        if (normalized.equals(user.username().toLowerCase(Locale.ROOT)) || normalized.equals(user.employeeNo().toLowerCase(Locale.ROOT))) {
            throw invalid("New password must not equal the username or employee number");
        }
        if (currentPassword != null && value.equals(currentPassword)) throw invalid("New password must differ from current password");
    }
    private ApiException invalid(String message) {
        return new ApiException(HttpStatus.BAD_REQUEST, "INVALID_PASSWORD", message, Map.of("newPassword", message));
    }
}
