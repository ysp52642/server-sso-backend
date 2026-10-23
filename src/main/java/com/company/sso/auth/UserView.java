package com.company.sso.auth;

import com.company.sso.user.UserIdentity;

import java.util.List;

public record UserView(long userId, long employeeId, String username, String employeeNo, String displayName,
                       String email, String orgUnit, List<String> roles, boolean mustChangePassword) {
    public static UserView from(UserIdentity user) {
        return new UserView(user.userId(), user.employeeId(), user.username(), user.employeeNo(), user.displayName(),
                user.email(), user.orgUnitName(), user.roles(), user.mustChangePassword());
    }
}
