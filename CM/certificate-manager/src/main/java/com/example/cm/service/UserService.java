package com.example.cm.service;

import com.example.cm.exception.BusinessException;
import com.example.cm.model.dto.PasswordResetRequest;
import com.example.cm.model.dto.UserCreateRequest;
import com.example.cm.model.dto.UserUpdateRequest;
import com.example.cm.model.entity.UserEntity;
import com.example.cm.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Admin-facing user management. Guards: nobody can disable or delete their own
 * account, and the last administrator can never be demoted, disabled or deleted.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    public static final String ROLE_ADMIN = "ADMIN";
    public static final String ROLE_REQUESTER = "REQUESTER";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;

    @Transactional(readOnly = true)
    public List<UserEntity> list() {
        log.info("[SERVICE] UserService.list() called");
        List<UserEntity> result = userRepository.findAllByOrderByIdAsc();
        log.info("[SERVICE] UserService.list() completed");
        return result;
    }

    @Transactional(readOnly = true)
    public UserEntity get(Long id) {
        log.info("[SERVICE] UserService.get() called with id={}", id);
        UserEntity result = userRepository.findById(id)
                .orElseThrow(() -> new BusinessException("User not found: " + id));
        log.info("[SERVICE] UserService.get() completed");
        return result;
    }

    @Transactional
    public UserEntity create(UserCreateRequest request) {
        log.info("[SERVICE] UserService.create() called with username={}", request.getUsername());
        String username = request.getUsername().trim();
        if (userRepository.existsByUsername(username)) {
            throw new BusinessException("Username already exists: " + username);
        }
        Set<String> roles = new HashSet<>();
        roles.add(ROLE_REQUESTER);
        if (request.isAdmin()) {
            roles.add(ROLE_ADMIN);
        }
        LocalDateTime now = LocalDateTime.now();
        UserEntity user = UserEntity.builder()
                .username(username)
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(roles)
                .enabled(true)
                .createdAt(now)
                .updatedAt(now)
                .build();
        user = userRepository.save(user);
        auditService.record(AuditService.currentActor(), "USERS", "USER_CREATED",
                "username=" + username + (request.isAdmin() ? ", admin=true" : ""));
        log.info("[SERVICE] UserService.create() completed");
        log.info("User '{}' created by '{}'", username, AuditService.currentActor());
        return user;
    }

    @Transactional
    public UserEntity update(Long id, UserUpdateRequest request) {
        log.info("[SERVICE] UserService.update() called with id={}", id);
        UserEntity user = get(id);
        String actor = AuditService.currentActor();
        boolean self = user.getUsername().equals(actor);

        if (request.getAdmin() != null) {
            boolean makeAdmin = request.getAdmin();
            boolean isAdmin = user.getRoles().contains(ROLE_ADMIN);
            if (makeAdmin && !isAdmin) {
                user.getRoles().add(ROLE_ADMIN);
                auditService.record(actor, "USERS", "USER_ADMIN_GRANTED", "username=" + user.getUsername());
            } else if (!makeAdmin && isAdmin) {
                if (self) {
                    throw new BusinessException("You cannot remove your own administrator role");
                }
                if (userRepository.countByRole(ROLE_ADMIN) <= 1) {
                    throw new BusinessException("Cannot demote the last administrator");
                }
                user.getRoles().remove(ROLE_ADMIN);
                auditService.record(actor, "USERS", "USER_ADMIN_REVOKED", "username=" + user.getUsername());
            }
        }

        if (request.getEnabled() != null) {
            boolean enable = request.getEnabled();
            if (!enable && self) {
                throw new BusinessException("You cannot disable your own account");
            }
            if (!enable && user.getRoles().contains(ROLE_ADMIN) && userRepository.countByRole(ROLE_ADMIN) <= 1) {
                throw new BusinessException("Cannot disable the last administrator");
            }
            if (user.isEnabled() != enable) {
                user.setEnabled(enable);
                auditService.record(actor, "USERS", enable ? "USER_ENABLED" : "USER_DISABLED",
                        "username=" + user.getUsername());
            }
        }

        user.setUpdatedAt(LocalDateTime.now());
        log.info("[SERVICE] UserService.update() completed");
        return userRepository.save(user);
    }

    @Transactional
    public UserEntity resetPassword(Long id, PasswordResetRequest request) {
        log.info("[SERVICE] UserService.resetPassword() called with id={}", id);
        UserEntity user = get(id);
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setUpdatedAt(LocalDateTime.now());
        auditService.record(AuditService.currentActor(), "USERS", "USER_PASSWORD_RESET",
                "username=" + user.getUsername());
        log.info("[SERVICE] UserService.resetPassword() completed");
        return userRepository.save(user);
    }

    @Transactional
    public void delete(Long id) {
        log.info("[SERVICE] UserService.delete() called with id={}", id);
        UserEntity user = get(id);
        String actor = AuditService.currentActor();
        if (user.getUsername().equals(actor)) {
            throw new BusinessException("You cannot delete your own account");
        }
        if (user.getRoles().contains(ROLE_ADMIN) && userRepository.countByRole(ROLE_ADMIN) <= 1) {
            throw new BusinessException("Cannot delete the last administrator");
        }
        auditService.record(actor, "USERS", "USER_DELETED", "username=" + user.getUsername());
        userRepository.delete(user);
        log.info("User '{}' deleted by '{}'", user.getUsername(), actor);
    }
}
