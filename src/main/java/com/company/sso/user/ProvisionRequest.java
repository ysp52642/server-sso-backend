package com.company.sso.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ProvisionRequest(
        @NotBlank @Size(max = 50) String employeeNo,
        @NotBlank @Size(max = 200) String displayName,
        @Email @Size(max = 320) String email,
        @Size(max = 50) String orgUnitCode,
        @NotBlank @Size(max = 100) String username,
        @NotBlank @Size(min = 10, max = 200) String initialPassword) { }
