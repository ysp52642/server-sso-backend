package com.company.sso.user;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.List;

public record RoleUpdateRequest(@NotEmpty List<@NotBlank @Size(max = 50) String> roles) { }
