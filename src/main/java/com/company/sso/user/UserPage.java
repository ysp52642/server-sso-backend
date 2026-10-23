package com.company.sso.user;

import com.company.sso.auth.UserView;

import java.util.List;

public record UserPage(List<UserView> items, int page, int size, long total) { }
