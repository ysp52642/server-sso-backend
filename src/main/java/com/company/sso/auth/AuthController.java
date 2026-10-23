package com.company.sso.auth;

import com.company.sso.common.ApiResponse;
import com.company.sso.config.SsoProperties;
import com.company.sso.user.UserIdentity;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.Arrays;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final AuthService auth;
    private final SsoProperties properties;
    public AuthController(AuthService auth, SsoProperties properties) { this.auth = auth; this.properties = properties; }

    @GetMapping("/csrf")
    public ApiResponse<Map<String, String>> csrf(CsrfToken token) {
        return ApiResponse.ok(Map.of("headerName", token.getHeaderName()));
    }

    @PostMapping("/login")
    public ApiResponse<UserView> login(@Valid @RequestBody LoginRequest request, HttpServletRequest http, HttpServletResponse response) {
        AuthService.LoginResult login = auth.login(request, ip(http), http.getHeader("User-Agent"));
        response.addHeader(HttpHeaders.SET_COOKIE, sessionCookie(login.rawSession(), -1).toString());
        return ApiResponse.ok(login.user());
    }

    @GetMapping("/me")
    public ApiResponse<UserView> me(@AuthenticationPrincipal UserIdentity user) { return ApiResponse.ok(UserView.from(user)); }

    @PostMapping("/change-password")
    public ApiResponse<Void> changePassword(@AuthenticationPrincipal UserIdentity user, @Valid @RequestBody ChangePasswordRequest request,
                                            HttpServletRequest http) {
        auth.changePassword(user, request, rawSession(http));
        return ApiResponse.ok(null);
    }

    @PostMapping("/logout")
    public ApiResponse<Void> logout(@AuthenticationPrincipal UserIdentity user, HttpServletRequest http, HttpServletResponse response) {
        auth.logout(user, rawSession(http), ip(http), http.getHeader("User-Agent"));
        response.addHeader(HttpHeaders.SET_COOKIE, sessionCookie("", 0).toString());
        return ApiResponse.ok(null);
    }

    private ResponseCookie sessionCookie(String value, long maxAge) {
        ResponseCookie.ResponseCookieBuilder cookie = ResponseCookie.from(properties.getCookie().getName(), value)
                .httpOnly(true).secure(properties.getCookie().isSecure()).sameSite(properties.getCookie().getSameSite()).path("/");
        if (maxAge >= 0) cookie.maxAge(Duration.ofSeconds(maxAge));
        return cookie.build();
    }
    private String rawSession(HttpServletRequest request) {
        return Arrays.stream(request.getCookies() == null ? new Cookie[0] : request.getCookies())
                .filter(cookie -> properties.getCookie().getName().equals(cookie.getName())).map(Cookie::getValue).findFirst().orElse("");
    }
    private String ip(HttpServletRequest request) { return request.getRemoteAddr(); }
}
