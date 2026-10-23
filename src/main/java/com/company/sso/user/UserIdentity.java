package com.company.sso.user;

import java.util.List;

public record UserIdentity(long userId, long employeeId, String username, String employeeNo,
                           String displayName, String email, String orgUnitName,
                           boolean userEnabled, boolean employeeEnabled, boolean locked,
                           boolean mustChangePassword, List<String> roles) {
    public boolean canAuthenticate() {
        return userEnabled && employeeEnabled && !locked;
    }
}
