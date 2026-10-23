package com.company.sso.user;

import com.company.sso.auth.UserView;
import com.company.sso.common.ApiResponse;
import com.company.sso.security.ClientCredentialService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserAdminController {
    private final UserAdminService users;
    private final ClientCredentialService clients;
    public UserAdminController(UserAdminService users, ClientCredentialService clients) { this.users = users; this.clients = clients; }

    @GetMapping("/api/v1/admin/users")
    public ApiResponse<UserPage> page(@RequestParam(required = false) String q,
                                      @RequestParam(defaultValue = "0") int page,
                                      @RequestParam(defaultValue = "20") int size) {
        return ApiResponse.ok(users.page(q, page, size));
    }
    @GetMapping("/api/v1/admin/users/{id}")
    public ApiResponse<UserView> get(@PathVariable long id) { return ApiResponse.ok(users.get(id)); }
    @PostMapping("/api/v1/admin/users")
    public ApiResponse<UserView> create(@Valid @RequestBody AdminUserCreateRequest request) { return ApiResponse.ok(users.create(request)); }
    @PutMapping("/api/v1/admin/users/{id}")
    public ApiResponse<UserView> enabled(@PathVariable long id, @Valid @RequestBody EnabledUpdateRequest request) { return ApiResponse.ok(users.setEnabled(id, request.enabled())); }
    @PostMapping("/api/v1/admin/users/{id}/unlock")
    public ApiResponse<UserView> unlock(@PathVariable long id) { return ApiResponse.ok(users.unlock(id)); }
    @PostMapping("/api/v1/admin/users/{id}/reset-password")
    public ApiResponse<Void> reset(@PathVariable long id, @Valid @RequestBody ResetPasswordRequest request) {
        users.resetPassword(id, request.temporaryPassword());
        return ApiResponse.ok(null);
    }
    @PutMapping("/api/v1/admin/users/{id}/roles")
    public ApiResponse<UserView> roles(@PathVariable long id, @Valid @RequestBody RoleUpdateRequest request) {
        return ApiResponse.ok(users.updateRoles(id, request.roles()));
    }

    @PostMapping("/api/v1/sso/users/provision")
    public ApiResponse<UserView> provision(@RequestHeader(value = "Authorization", required = false) String authorization,
                                            @Valid @RequestBody ProvisionRequest request) {
        clients.requireClientForSystem(authorization, "EMPLOYEE_PORTAL");
        return ApiResponse.ok(users.provision(request));
    }
}
