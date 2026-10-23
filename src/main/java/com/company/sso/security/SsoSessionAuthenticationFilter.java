package com.company.sso.security;

import com.company.sso.config.SsoProperties;
import com.company.sso.session.SsoSessionService;
import com.company.sso.user.UserIdentity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;

@Component
public class SsoSessionAuthenticationFilter extends OncePerRequestFilter {
    private final SsoSessionService sessions;
    private final SsoProperties properties;
    public SsoSessionAuthenticationFilter(SsoSessionService sessions, SsoProperties properties) {
        this.sessions = sessions;
        this.properties = properties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String raw = Arrays.stream(request.getCookies() == null ? new Cookie[0] : request.getCookies())
                .filter(cookie -> properties.getCookie().getName().equals(cookie.getName()))
                .map(Cookie::getValue).findFirst().orElse(null);
        sessions.findActive(raw).filter(record -> record.user().canAuthenticate()).ifPresent(record -> authenticate(record.user()));
        chain.doFilter(request, response);
    }

    private void authenticate(UserIdentity user) {
        if (SecurityContextHolder.getContext().getAuthentication() != null) return;
        var authorities = user.roles().stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role)).toList();
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(user, null, authorities));
    }
}
