package com.example.cm.controller;

import com.example.cm.model.dto.ProfileRequest;
import com.example.cm.model.dto.ProfileTypeInfo;
import com.example.cm.model.entity.CertificateProfile;
import com.example.cm.model.enums.ProfileType;
import com.example.cm.service.ProfileService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/profiles")
@RequiredArgsConstructor
@Tag(name = "Certificate Profiles", description = "Manage certificate issuance profiles (templates). Any user can read; admin can create/update/delete.")
@SecurityRequirement(name = "basicAuth")
@Slf4j
public class ProfileController {

    private final ProfileService profileService;

    @Operation(summary = "List profile types", description = "Returns built-in profile type presets (SERVER, CLIENT, CODE_SIGNING, etc.) with their default parameters.")
    @GetMapping("/types")
    public ResponseEntity<List<ProfileTypeInfo>> types() {
        log.info("[CONTROLLER] ProfileController.types() called");
        List<ProfileTypeInfo> result = Arrays.stream(ProfileType.values())
                .map(t -> new ProfileTypeInfo(t.name(), t.getDescription(), t.getKeyAlgorithm(), t.getKeySize(),
                        t.getValidityDays(), t.isCaProfile(), t.getKeyUsage(), t.getExtendedKeyUsage()))
                .toList();
        log.info("[CONTROLLER] ProfileController.types() completed");
        return ResponseEntity.ok(result);
    }

    @Operation(summary = "List certificate profiles", description = "Returns all configured certificate profiles. Any authenticated user.")
    @GetMapping
    public ResponseEntity<List<CertificateProfile>> list() {
        log.info("[CONTROLLER] ProfileController.list() called");
        List<CertificateProfile> result = profileService.listAll();
        log.info("[CONTROLLER] ProfileController.list() completed");
        return ResponseEntity.ok(result);
    }

    @Operation(summary = "Get profile by ID")
    @GetMapping("/{id}")
    public ResponseEntity<CertificateProfile> get(@PathVariable Long id) {
        log.info("[CONTROLLER] ProfileController.get() called, id={}", id);
        CertificateProfile result = profileService.get(id);
        log.info("[CONTROLLER] ProfileController.get() completed, id={}", id);
        return ResponseEntity.ok(result);
    }

    @Operation(summary = "Create profile", description = "Create a new certificate profile. Admin only.")
    @PostMapping
    public ResponseEntity<com.example.cm.model.dto.ApiResponse> create(@Valid @RequestBody ProfileRequest request,
                                              Authentication authentication) {
        log.info("[CONTROLLER] ProfileController.create() called");
        CertificateProfile profile = profileService.create(request, authentication.getName());
        log.info("[CONTROLLER] ProfileController.create() completed, name={}", profile.getName());
        return ResponseEntity.ok(com.example.cm.model.dto.ApiResponse.ok(
                "Certificate profile '" + profile.getName() + "' created", profile));
    }

    @Operation(summary = "Update profile", description = "Update an existing certificate profile. Admin only.")
    @PutMapping("/{id}")
    public ResponseEntity<com.example.cm.model.dto.ApiResponse> update(@PathVariable Long id,
                                              @Valid @RequestBody ProfileRequest request) {
        log.info("[CONTROLLER] ProfileController.update() called, id={}", id);
        CertificateProfile profile = profileService.update(id, request);
        log.info("[CONTROLLER] ProfileController.update() completed, id={}", id);
        return ResponseEntity.ok(com.example.cm.model.dto.ApiResponse.ok(
                "Certificate profile '" + profile.getName() + "' updated", profile));
    }

    @Operation(summary = "Delete profile", description = "Delete a certificate profile. Admin only.")
    @DeleteMapping("/{id}")
    public ResponseEntity<com.example.cm.model.dto.ApiResponse> delete(@PathVariable Long id) {
        log.info("[CONTROLLER] ProfileController.delete() called, id={}", id);
        profileService.delete(id);
        log.info("[CONTROLLER] ProfileController.delete() completed, id={}", id);
        return ResponseEntity.ok(com.example.cm.model.dto.ApiResponse.ok("Certificate profile deleted", null));
    }
}
