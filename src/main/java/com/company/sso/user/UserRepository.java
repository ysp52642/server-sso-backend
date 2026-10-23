package com.company.sso.user;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Repository
public class UserRepository {
    private final NamedParameterJdbcTemplate jdbc;

    public UserRepository(NamedParameterJdbcTemplate jdbc) { this.jdbc = jdbc; }

    public Optional<UserAccount> findAccountByUsername(String username) {
        String sql = selectAccount() + " WHERE u.username = :username";
        List<UserAccount> accounts = jdbc.query(sql, Map.of("username", username), (rs, row) -> {
            long id = rs.getLong("user_id");
            return new UserAccount(identity(rs, id), rs.getString("password_hash"), rs.getInt("failed_login_count"));
        });
        return accounts.stream().findFirst();
    }

    public Optional<UserIdentity> findIdentity(long userId) {
        List<UserIdentity> users = jdbc.query(selectIdentity() + " WHERE u.id = :id", Map.of("id", userId),
                (rs, row) -> identity(rs, rs.getLong("user_id")));
        return users.stream().findFirst();
    }

    public Optional<UserIdentity> findIdentityByUsername(String username) {
        List<UserIdentity> users = jdbc.query(selectIdentity() + " WHERE u.username = :username", Map.of("username", username),
                (rs, row) -> identity(rs, rs.getLong("user_id")));
        return users.stream().findFirst();
    }

    public List<UserIdentity> findPage(String query, int limit, int offset) {
        String filter = query == null || query.isBlank() ? "" : " WHERE (u.username ILIKE :term OR e.employee_no ILIKE :term OR e.display_name ILIKE :term)";
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("limit", limit).addValue("offset", offset);
        if (!filter.isEmpty()) params.addValue("term", "%" + query.trim() + "%");
        return jdbc.query(selectIdentity() + filter + " ORDER BY u.id DESC LIMIT :limit OFFSET :offset", params,
                (rs, row) -> identity(rs, rs.getLong("user_id")));
    }

    public long count(String query) {
        String filter = query == null || query.isBlank() ? "" : " WHERE (u.username ILIKE :term OR e.employee_no ILIKE :term OR e.display_name ILIKE :term)";
        MapSqlParameterSource params = new MapSqlParameterSource();
        if (!filter.isEmpty()) params.addValue("term", "%" + query.trim() + "%");
        Long value = jdbc.queryForObject("SELECT COUNT(*) FROM sys_user u JOIN employee e ON e.id = u.employee_id" + filter,
                params, Long.class);
        return value == null ? 0 : value;
    }

    public long ensureOrgUnit(String code, String name) {
        List<Long> ids = jdbc.query("SELECT id FROM org_unit WHERE code = :code", Map.of("code", code),
                (rs, row) -> rs.getLong(1));
        if (!ids.isEmpty()) return ids.getFirst();
        GeneratedKeyHolder keys = new GeneratedKeyHolder();
        jdbc.update("INSERT INTO org_unit (code, name, enabled) VALUES (:code, :name, TRUE)",
                new MapSqlParameterSource().addValue("code", code).addValue("name", name), keys, new String[]{"id"});
        return keys.getKey().longValue();
    }

    public Optional<Long> findEmployeeId(String employeeNo) {
        List<Long> ids = jdbc.query("SELECT id FROM employee WHERE employee_no = :employeeNo", Map.of("employeeNo", employeeNo),
                (rs, row) -> rs.getLong(1));
        return ids.stream().findFirst();
    }

    public Optional<Long> findUserIdForEmployee(long employeeId) {
        List<Long> ids = jdbc.query("SELECT id FROM sys_user WHERE employee_id = :employeeId", Map.of("employeeId", employeeId),
                (rs, row) -> rs.getLong(1));
        return ids.stream().findFirst();
    }

    public long createEmployee(String employeeNo, String displayName, String email, long orgUnitId) {
        GeneratedKeyHolder keys = new GeneratedKeyHolder();
        jdbc.update("INSERT INTO employee (employee_no, display_name, email, org_unit_id, enabled) VALUES (:employeeNo, :displayName, :email, :orgUnitId, TRUE)",
                new MapSqlParameterSource().addValue("employeeNo", employeeNo).addValue("displayName", displayName)
                        .addValue("email", email).addValue("orgUnitId", orgUnitId), keys, new String[]{"id"});
        return keys.getKey().longValue();
    }

    public void updateEmployee(long employeeId, String displayName, String email, long orgUnitId) {
        jdbc.update("UPDATE employee SET display_name = :displayName, email = :email, org_unit_id = :orgUnitId WHERE id = :id",
                new MapSqlParameterSource().addValue("id", employeeId).addValue("displayName", displayName)
                        .addValue("email", email).addValue("orgUnitId", orgUnitId));
    }

    public long createUser(long employeeId, String username, String passwordHash, boolean enabled, boolean mustChangePassword) {
        GeneratedKeyHolder keys = new GeneratedKeyHolder();
        jdbc.update("INSERT INTO sys_user (employee_id, username, password_hash, enabled, must_change_password) VALUES (:employeeId, :username, :passwordHash, :enabled, :mustChangePassword)",
                new MapSqlParameterSource().addValue("employeeId", employeeId).addValue("username", username)
                        .addValue("passwordHash", passwordHash).addValue("enabled", enabled).addValue("mustChangePassword", mustChangePassword),
                keys, new String[]{"id"});
        return keys.getKey().longValue();
    }

    public void resetFailedLoginsAndUpdateLogin(long userId, Instant now) {
        jdbc.update("UPDATE sys_user SET failed_login_count = 0, last_login_at = :now WHERE id = :id",
                Map.of("id", userId, "now", Timestamp.from(now)));
    }

    public boolean recordFailedLogin(long userId, Instant now) {
        jdbc.update("UPDATE sys_user SET failed_login_count = failed_login_count + 1, locked = CASE WHEN failed_login_count + 1 >= 5 THEN TRUE ELSE locked END, locked_at = CASE WHEN failed_login_count + 1 >= 5 THEN :now ELSE locked_at END WHERE id = :id",
                Map.of("id", userId, "now", Timestamp.from(now)));
        Boolean locked = jdbc.queryForObject("SELECT locked FROM sys_user WHERE id = :id", Map.of("id", userId), Boolean.class);
        return Boolean.TRUE.equals(locked);
    }

    public void changePassword(long userId, String passwordHash, Instant now) {
        jdbc.update("UPDATE sys_user SET password_hash = :passwordHash, password_changed_at = :now, must_change_password = FALSE, failed_login_count = 0 WHERE id = :id",
                Map.of("id", userId, "passwordHash", passwordHash, "now", Timestamp.from(now)));
    }

    public void setPasswordForReset(long userId, String passwordHash, Instant now) {
        jdbc.update("UPDATE sys_user SET password_hash = :passwordHash, password_changed_at = :now, must_change_password = TRUE, failed_login_count = 0 WHERE id = :id",
                Map.of("id", userId, "passwordHash", passwordHash, "now", Timestamp.from(now)));
    }

    public void setEnabled(long userId, boolean enabled) {
        jdbc.update("UPDATE sys_user SET enabled = :enabled WHERE id = :id", Map.of("id", userId, "enabled", enabled));
    }

    public void unlock(long userId) {
        jdbc.update("UPDATE sys_user SET locked = FALSE, locked_at = NULL, failed_login_count = 0 WHERE id = :id", Map.of("id", userId));
    }

    public void replaceRoles(long userId, Collection<String> roleCodes) {
        jdbc.update("DELETE FROM user_role WHERE user_id = :userId", Map.of("userId", userId));
        if (roleCodes.isEmpty()) return;
        List<Long> roleIds = jdbc.query("SELECT id FROM sys_role WHERE code IN (:codes)", Map.of("codes", roleCodes), (rs, row) -> rs.getLong(1));
        if (roleIds.size() != roleCodes.size()) throw new IllegalArgumentException("One or more roles do not exist");
        for (Long roleId : roleIds) {
            jdbc.update("INSERT INTO user_role (user_id, role_id) VALUES (:userId, :roleId)", Map.of("userId", userId, "roleId", roleId));
        }
    }

    private String selectAccount() { return selectIdentity() + ", u.password_hash, u.failed_login_count"; }
    private String selectIdentity() {
        return "SELECT u.id AS user_id, u.employee_id, u.username, u.enabled AS user_enabled, u.locked, u.must_change_password, " +
                "e.employee_no, e.display_name, e.email, e.enabled AS employee_enabled, ou.name AS org_unit_name " +
                "FROM sys_user u JOIN employee e ON e.id = u.employee_id LEFT JOIN org_unit ou ON ou.id = e.org_unit_id";
    }
    private UserIdentity identity(java.sql.ResultSet rs, long userId) throws java.sql.SQLException {
        List<String> roles = jdbc.query("SELECT r.code FROM sys_role r JOIN user_role ur ON ur.role_id = r.id WHERE ur.user_id = :userId ORDER BY r.code",
                Map.of("userId", userId), (roleRs, row) -> roleRs.getString(1));
        return new UserIdentity(userId, rs.getLong("employee_id"), rs.getString("username"), rs.getString("employee_no"),
                rs.getString("display_name"), rs.getString("email"), rs.getString("org_unit_name"),
                rs.getBoolean("user_enabled"), rs.getBoolean("employee_enabled"), rs.getBoolean("locked"),
                rs.getBoolean("must_change_password"), roles);
    }
}
