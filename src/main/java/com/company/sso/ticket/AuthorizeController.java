package com.company.sso.ticket;

import com.company.sso.common.ApiException;
import com.company.sso.common.CryptoSupport;
import com.company.sso.config.SsoProperties;
import com.company.sso.security.ClientCredentialService;
import com.company.sso.session.SsoSessionService;
import com.company.sso.user.UserIdentity;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Duration;
import java.util.Arrays;

@Controller
public class AuthorizeController {
    private final ClientCredentialService clients;
    private final TicketService tickets;
    private final SsoSessionService sessions;
    private final SsoProperties properties;
    public AuthorizeController(ClientCredentialService clients, TicketService tickets, SsoSessionService sessions, SsoProperties properties) {
        this.clients = clients;
        this.tickets = tickets;
        this.sessions = sessions;
        this.properties = properties;
    }

    @GetMapping("/sso/authorize")
    public String authorize(@RequestParam String client, @RequestParam String returnUrl,
                            @RequestParam(required = false) String prompt,
                            @AuthenticationPrincipal UserIdentity user,
                            HttpServletRequest request, HttpServletResponse response) {
        var registered = clients.findConfiguredClient(client);
        String clientCode = CryptoSupport.normalizedCode(registered.getId());
        if (!registered.getCallbackUrl().equals(returnUrl)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "INVALID_RETURN_URL", "Return URL is not registered for this client");
        }
        String rawSession = rawSession(request);
        if ("login".equalsIgnoreCase(prompt)) {
            sessions.revoke(rawSession);
            response.addHeader(HttpHeaders.SET_COOKIE, expiredCookie().toString());
            return loginRedirect(clientCode, returnUrl);
        }
        if (user == null) return loginRedirect(clientCode, returnUrl);
        if (user.mustChangePassword()) return passwordRedirect(clientCode, returnUrl);
        String ticket = tickets.issue(user, clientCode, request.getRemoteAddr(), request.getHeader("User-Agent"));
        return "redirect:" + UriComponentsBuilder.fromUriString(registered.getCallbackUrl()).queryParam("ticket", ticket).build().encode().toUriString();
    }

    private String loginRedirect(String client, String returnUrl) {
        return "redirect:" + UriComponentsBuilder.fromUriString(properties.getFrontendBaseUrl() + "/login")
                .queryParam("client", client).queryParam("returnUrl", returnUrl).build().encode().toUriString();
    }
    private String passwordRedirect(String client, String returnUrl) {
        return "redirect:" + UriComponentsBuilder.fromUriString(properties.getFrontendBaseUrl() + "/change-password")
                .queryParam("client", client).queryParam("returnUrl", returnUrl).build().encode().toUriString();
    }
    private String rawSession(HttpServletRequest request) {
        return Arrays.stream(request.getCookies() == null ? new Cookie[0] : request.getCookies()).filter(cookie ->
                properties.getCookie().getName().equals(cookie.getName())).map(Cookie::getValue).findFirst().orElse("");
    }
    private ResponseCookie expiredCookie() {
        return ResponseCookie.from(properties.getCookie().getName(), "").path("/").httpOnly(true)
                .secure(properties.getCookie().isSecure()).sameSite(properties.getCookie().getSameSite()).maxAge(Duration.ZERO).build();
    }
}
