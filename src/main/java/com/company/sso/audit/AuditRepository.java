package com.company.sso.audit;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class AuditRepository {
    private final NamedParameterJdbcTemplate jdbc;
    public AuditRepository(NamedParameterJdbcTemplate jdbc) { this.jdbc = jdbc; }

    public void record(Long userId, String username, String eventType, boolean success, String reason, String ip, String userAgent) {
        jdbc.update("INSERT INTO login_audit (user_id, username, event_type, success, reason_code, ip, user_agent) VALUES (:userId, :username, :eventType, :success, :reason, :ip, :userAgent)",
                new MapSqlParameterSource().addValue("userId", userId).addValue("username", username).addValue("eventType", eventType)
                        .addValue("success", success).addValue("reason", reason).addValue("ip", ip).addValue("userAgent", userAgent));
    }
}
