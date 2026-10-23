package com.company.sso.ticket;

import com.company.sso.audit.AuditRepository;
import com.company.sso.common.ApiException;
import com.company.sso.common.CryptoSupport;
import com.company.sso.config.SsoProperties;
import com.company.sso.user.UserIdentity;
import com.company.sso.user.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
public class TicketService {
    private final TicketRepository tickets;
    private final UserRepository users;
    private final AuditRepository audit;
    private final SsoProperties properties;
    public TicketService(TicketRepository tickets, UserRepository users, AuditRepository audit, SsoProperties properties) {
        this.tickets = tickets;
        this.users = users;
        this.audit = audit;
        this.properties = properties;
    }

    @Transactional
    public String issue(UserIdentity user, String system, String ip, String userAgent) {
        String ticket = CryptoSupport.newOpaqueToken();
        tickets.create(user.userId(), CryptoSupport.sha256(ticket), system, Instant.now().plus(properties.getTicket().getTtl()));
        audit.record(user.userId(), user.username(), "TICKET_ISSUED", true, system, ip, userAgent);
        return ticket;
    }

    @Transactional
    public TicketIdentity validate(String ticket, String system, String ip, String userAgent) {
        String hash = CryptoSupport.sha256(ticket);
        Instant now = Instant.now();
        Long userId = tickets.userIdForUnconsumed(hash, system, now).orElseThrow(this::invalidTicket);
        if (!tickets.consume(hash, system, now)) throw invalidTicket();
        UserIdentity user = users.findIdentity(userId).orElseThrow(this::invalidTicket);
        if (!user.canAuthenticate()) throw invalidTicket();
        audit.record(user.userId(), user.username(), "TICKET_VALIDATED", true, system, ip, userAgent);
        return TicketIdentity.from(user);
    }

    private ApiException invalidTicket() {
        return new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_TICKET", "Ticket is invalid, expired, or already used");
    }
}
