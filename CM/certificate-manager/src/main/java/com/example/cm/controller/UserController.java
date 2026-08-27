package com.example.cm.controller;

import com.example.cm.model.dto.PasswordResetRequest;
import com.example.cm.model.dto.UserCreateRequest;
import com.example.cm.model.dto.UserUpdateRequest;
import com.example.cm.model.entity.UserEntity;
import com.example.cm.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Tag(name = "User Management", description = "Admin-only user management: list, create, update roles, reset passwords, delete.")
@SecurityRequirement(name = "basicAuth")
@Slf4j
public class UserController {

    private final UserService userService;

    @Operation(summary = "List all users", description = "Returns all users with their roles and enabled state. Admin only.")
    @GetMapping
    public ResponseEntity<List<UserEntity>> list() {
        log.info("[CONTROLLER] UserController.list() called");
        List<UserEntity> result = userService.list();
        log.info("[CONTROLLER] UserController.list() completed");
        return ResponseEntity.ok(result);
    }

    @Operation(summary = "Create a user", description = "Create a new user with username, password, and optional admin role. Admin only.")
    @PostMapping
    public ResponseEntity<com.example.cm.model.dto.ApiResponse> create(@Valid @RequestBody UserCreateRequest request) {
        log.info("[CONTROLLER] UserController.create() called, username={}", request.getUsername());
        UserEntity user = userService.create(request);
        log.info("[CONTROLLER] UserController.create() completed, username={}", user.getUsername());
        return ResponseEntity.ok(com.example.cm.model.dto.ApiResponse.ok(
                "User '" + user.getUsername() + "' created", user));
    }

    @Operation(summary = "Update a user", description = "Grant/revoke admin role or enable/disable the account. The last admin cannot be demoted. Admin only.")
    @PutMapping("/{id}")
    public ResponseEntity<com.example.cm.model.dto.ApiResponse> update(@PathVariable Long id,
                                               @RequestBody UserUpdateRequest request) {
        log.info("[CONTROLLER] UserController.update() called, id={}", id);
        UserEntity user = userService.update(id, request);
        log.info("[CONTROLLER] UserController.update() completed, id={}", id);
        return ResponseEntity.ok(com.example.cm.model.dto.ApiResponse.ok("User updated", user));
    }

    @Operation(summary = "Reset password", description = "Reset a user's password. Admin only.")
    @PutMapping("/{id}/password")
    public ResponseEntity<com.example.cm.model.dto.ApiResponse> resetPassword(@PathVariable Long id,
                                                     @Valid @RequestBody PasswordResetRequest request) {
        log.info("[CONTROLLER] UserController.resetPassword() called, id={}", id);
        UserEntity user = userService.resetPassword(id, request);
        log.info("[CONTROLLER] UserController.resetPassword() completed, id={}", id);
        return ResponseEntity.ok(com.example.cm.model.dto.ApiResponse.ok(
                "Password reset for '" + user.getUsername() + "'", user));
    }

    @Operation(summary = "Delete a user", description = "Delete a user. Cannot delete yourself or the last administrator. Admin only.")
    @DeleteMapping("/{id}")
    public ResponseEntity<com.example.cm.model.dto.ApiResponse> delete(@PathVariable Long id) {
        log.info("[CONTROLLER] UserController.delete() called, id={}", id);
        userService.delete(id);
        log.info("[CONTROLLER] UserController.delete() completed, id={}", id);
        return ResponseEntity.ok(com.example.cm.model.dto.ApiResponse.ok("User deleted", null));
    }
}
