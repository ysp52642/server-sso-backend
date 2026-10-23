package com.company.sso.ticket;

import com.company.sso.user.UserIdentity;

import java.util.List;

public record TicketIdentity(long userId, long employeeId, String employeeNo, String displayName, String email, List<String> roles) {
    static TicketIdentity from(UserIdentity user) {
        return new TicketIdentity(user.userId(), user.employeeId(), user.employeeNo(), user.displayName(), user.email(), user.roles());
    }
}
