package com.company.sso.ticket;

import com.company.sso.common.ApiResponse;
import com.company.sso.common.CryptoSupport;
import com.company.sso.security.ClientCredentialService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/sso/ticket")
public class TicketController {
    private final TicketService tickets;
    private final ClientCredentialService clients;
    public TicketController(TicketService tickets, ClientCredentialService clients) { this.tickets = tickets; this.clients = clients; }

    @PostMapping("/validate")
    public ApiResponse<TicketIdentity> validate(@RequestHeader(value = "Authorization", required = false) String authorization,
                                                @Valid @RequestBody TicketValidationRequest request, HttpServletRequest http) {
        String system = CryptoSupport.normalizedCode(request.system());
        clients.requireClientForSystem(authorization, system);
        return ApiResponse.ok(tickets.validate(request.ticket(), system, http.getRemoteAddr(), http.getHeader("User-Agent")));
    }
}
