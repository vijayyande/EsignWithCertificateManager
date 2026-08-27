package com.example.cm.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/me")
@RequiredArgsConstructor
@Tag(name = "Current User", description = "Returns information about the currently authenticated user.")
@SecurityRequirement(name = "basicAuth")
@Slf4j
public class MeController {

    @Operation(summary = "Get current user info", description = "Returns the authenticated username and their roles.")
    @GetMapping
    public ResponseEntity<Map<String, Object>> me(Authentication authentication) {
        log.info("[CONTROLLER] MeController.me() called, username={}", authentication.getName());
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("username", authentication.getName());
        body.put("roles", authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(authority -> authority.startsWith("ROLE_") ? authority.substring(5) : authority)
                .sorted()
                .toList());
        log.info("[CONTROLLER] MeController.me() completed, username={}", authentication.getName());
        return ResponseEntity.ok(body);
    }
}
