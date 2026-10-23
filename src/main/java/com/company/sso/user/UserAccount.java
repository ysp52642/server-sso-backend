package com.company.sso.user;

public record UserAccount(UserIdentity identity, String passwordHash, int failedLoginCount) { }
