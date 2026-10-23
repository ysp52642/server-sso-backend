package com.company.sso.auth;

import com.company.sso.common.ApiException;
import com.company.sso.user.UserIdentity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PasswordPolicyTest {
    private final PasswordPolicy policy = new PasswordPolicy();
    private final UserIdentity user = new UserIdentity(1, 1, "alice", "E100", "Alice", "alice@example.test", "IT", true, true, false, true, List.of("EMPLOYEE"));

    @Test
    void acceptsStrongDifferentPassword() {
        assertThatCode(() -> policy.verify("NewPassword2026", user, "OldPassword2025")).doesNotThrowAnyException();
    }
    @Test
    void rejectsUsernameEmployeeNumberAndCurrentPassword() {
        assertThatThrownBy(() -> policy.verify("alice", user, "OldPassword2025")).isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> policy.verify("E100", user, "OldPassword2025")).isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> policy.verify("OldPassword2025", user, "OldPassword2025")).isInstanceOf(ApiException.class);
    }
}
