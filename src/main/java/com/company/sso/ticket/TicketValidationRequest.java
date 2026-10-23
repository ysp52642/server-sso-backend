package com.company.sso.ticket;

import jakarta.validation.constraints.NotBlank;

public record TicketValidationRequest(@NotBlank String ticket, @NotBlank String system) { }
