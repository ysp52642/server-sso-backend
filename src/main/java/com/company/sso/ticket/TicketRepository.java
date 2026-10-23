package com.company.sso.ticket;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Repository
public class TicketRepository {
    private final NamedParameterJdbcTemplate jdbc;
    public TicketRepository(NamedParameterJdbcTemplate jdbc) { this.jdbc = jdbc; }

    public void create(long userId, String ticketHash, String system, Instant expiresAt) {
        jdbc.update("INSERT INTO auth_ticket (user_id, ticket_hash, target_system, expires_at) VALUES (:userId, :hash, :system, :expiresAt)",
                new MapSqlParameterSource().addValue("userId", userId).addValue("hash", ticketHash).addValue("system", system).addValue("expiresAt", Timestamp.from(expiresAt)));
    }
    public Optional<Long> userIdForUnconsumed(String ticketHash, String system, Instant now) {
        List<Long> users = jdbc.query("SELECT user_id FROM auth_ticket WHERE ticket_hash=:hash AND target_system=:system AND consumed_at IS NULL AND expires_at>:now",
                Map.of("hash", ticketHash, "system", system, "now", Timestamp.from(now)), (rs, row) -> rs.getLong(1));
        return users.stream().findFirst();
    }
    public boolean consume(String ticketHash, String system, Instant now) {
        return jdbc.update("UPDATE auth_ticket SET consumed_at=:now WHERE ticket_hash=:hash AND target_system=:system AND consumed_at IS NULL AND expires_at>:now",
                Map.of("hash", ticketHash, "system", system, "now", Timestamp.from(now))) == 1;
    }
}
