package com.company.sso.session;

import com.company.sso.user.UserIdentity;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Repository
public class SessionRepository {
    private final NamedParameterJdbcTemplate jdbc;
    public SessionRepository(NamedParameterJdbcTemplate jdbc) { this.jdbc = jdbc; }

    public void create(long userId, String sessionHash, Instant now, Instant idleExpiresAt, Instant absoluteExpiresAt, String ip, String userAgent) {
        jdbc.update("INSERT INTO auth_session (user_id, session_hash, issued_at, last_seen_at, expires_at, absolute_expires_at, created_ip, created_user_agent) VALUES (:userId, :hash, :now, :now, :expiresAt, :absoluteExpiresAt, :ip, :userAgent)",
                new MapSqlParameterSource().addValue("userId", userId).addValue("hash", sessionHash).addValue("now", Timestamp.from(now))
                        .addValue("expiresAt", Timestamp.from(idleExpiresAt)).addValue("absoluteExpiresAt", Timestamp.from(absoluteExpiresAt))
                        .addValue("ip", ip).addValue("userAgent", userAgent));
    }

    public Optional<SessionRecord> findActive(String sessionHash, Instant now) {
        String sql = "SELECT s.id session_id, u.id user_id, u.employee_id, u.username, u.enabled user_enabled, u.locked, u.must_change_password, " +
                "e.employee_no, e.display_name, e.email, e.enabled employee_enabled, ou.name org_unit_name " +
                "FROM auth_session s JOIN sys_user u ON u.id=s.user_id JOIN employee e ON e.id=u.employee_id LEFT JOIN org_unit ou ON ou.id=e.org_unit_id " +
                "WHERE s.session_hash=:hash AND s.revoked_at IS NULL AND s.expires_at > :now AND s.absolute_expires_at > :now";
        List<SessionRecord> sessions = jdbc.query(sql, Map.of("hash", sessionHash, "now", Timestamp.from(now)), (rs, row) -> {
            long userId = rs.getLong("user_id");
            List<String> roles = jdbc.query("SELECT r.code FROM sys_role r JOIN user_role ur ON ur.role_id=r.id WHERE ur.user_id=:id ORDER BY r.code",
                    Map.of("id", userId), (roleRs, roleRow) -> roleRs.getString(1));
            UserIdentity user = new UserIdentity(userId, rs.getLong("employee_id"), rs.getString("username"), rs.getString("employee_no"),
                    rs.getString("display_name"), rs.getString("email"), rs.getString("org_unit_name"), rs.getBoolean("user_enabled"),
                    rs.getBoolean("employee_enabled"), rs.getBoolean("locked"), rs.getBoolean("must_change_password"), roles);
            return new SessionRecord(rs.getLong("session_id"), user);
        });
        return sessions.stream().findFirst();
    }

    public void touch(String sessionHash, Instant now, Instant proposedIdleExpiry) {
        jdbc.update("UPDATE auth_session SET last_seen_at=:now, expires_at=LEAST(absolute_expires_at, :idle) WHERE session_hash=:hash AND revoked_at IS NULL AND expires_at>:now AND absolute_expires_at>:now",
                Map.of("hash", sessionHash, "now", Timestamp.from(now), "idle", Timestamp.from(proposedIdleExpiry)));
    }
    public void revoke(String sessionHash, Instant now) {
        jdbc.update("UPDATE auth_session SET revoked_at=:now WHERE session_hash=:hash AND revoked_at IS NULL", Map.of("hash", sessionHash, "now", Timestamp.from(now)));
    }
    public void revokeOtherSessions(long userId, String currentSessionHash, Instant now) {
        jdbc.update("UPDATE auth_session SET revoked_at=:now WHERE user_id=:userId AND session_hash<>:hash AND revoked_at IS NULL",
                Map.of("userId", userId, "hash", currentSessionHash, "now", Timestamp.from(now)));
    }
    public void revokeAll(long userId, Instant now) {
        jdbc.update("UPDATE auth_session SET revoked_at=:now WHERE user_id=:userId AND revoked_at IS NULL", Map.of("userId", userId, "now", Timestamp.from(now)));
    }
}
