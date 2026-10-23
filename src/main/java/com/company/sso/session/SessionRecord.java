package com.company.sso.session;

import com.company.sso.user.UserIdentity;

public record SessionRecord(long id, UserIdentity user) { }
