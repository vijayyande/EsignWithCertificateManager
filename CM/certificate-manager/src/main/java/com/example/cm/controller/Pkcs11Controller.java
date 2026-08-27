package com.example.cm.controller;

import com.example.cm.model.dto.Pkcs11Preset;
import com.example.cm.model.dto.Pkcs11SettingsRequest;
import com.example.cm.model.entity.Pkcs11Settings;
import com.example.cm.service.Pkcs11Service;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/pkcs11")
@RequiredArgsConstructor
@Tag(name = "PKCS#11 Device", description = "Manage PKCS#11 (HSM/token) device settings: configure, test connection, disconnect. Admin only.")
@SecurityRequirement(name = "basicAuth")
@Slf4j
public class Pkcs11Controller {

    private final Pkcs11Service pkcs11Service;

    @Operation(summary = "Get PKCS#11 settings", description = "Returns current PKCS#11 device configuration (PIN is never returned). Admin only.")
    @GetMapping
    public ResponseEntity<Pkcs11Settings> get() {
        log.info("[CONTROLLER] Pkcs11Controller.get() called");
        Pkcs11Settings result = pkcs11Service.getSettings();
        log.info("[CONTROLLER] Pkcs11Controller.get() completed");
        return ResponseEntity.ok(result);
    }

    @Operation(summary = "List PKCS#11 presets", description = "Returns known PKCS#11 provider presets (SoftHSM2, OpenSC, YubiKey, etc.) with typical library paths per OS.")
    @GetMapping("/presets")
    public ResponseEntity<List<Pkcs11Preset>> presets() {
        log.info("[CONTROLLER] Pkcs11Controller.presets() called");
        List<Pkcs11Preset> result = pkcs11Service.listPresets();
        log.info("[CONTROLLER] Pkcs11Controller.presets() completed");
        return ResponseEntity.ok(result);
    }

    @Operation(summary = "Save PKCS#11 settings", description = "Update the PKCS#11 device configuration (provider, library path, slot, PIN). Admin only.")
    @PostMapping
    public ResponseEntity<com.example.cm.model.dto.ApiResponse> update(@Valid @RequestBody Pkcs11SettingsRequest request) {
        log.info("[CONTROLLER] Pkcs11Controller.update() called");
        Pkcs11Settings settings = pkcs11Service.updateSettings(request);
        log.info("[CONTROLLER] Pkcs11Controller.update() completed");
        return ResponseEntity.ok(com.example.cm.model.dto.ApiResponse.ok("PKCS#11 settings saved", settings));
    }

    @Operation(summary = "Test PKCS#11 connection", description = "Load the PKCS#11 provider and verify the token accepts the PIN + slot. Admin only.")
    @PostMapping("/test")
    public ResponseEntity<com.example.cm.model.dto.ApiResponse> test() {
        log.info("[CONTROLLER] Pkcs11Controller.test() called");
        Map<String, Object> result = pkcs11Service.testConnection();
        log.info("[CONTROLLER] Pkcs11Controller.test() completed");
        return ResponseEntity.ok(com.example.cm.model.dto.ApiResponse.ok("PKCS#11 connection OK", result));
    }

    @Operation(summary = "Disconnect PKCS#11 provider", description = "Unload the PKCS#11 provider from the JVM. Admin only.")
    @PostMapping("/disconnect")
    public ResponseEntity<com.example.cm.model.dto.ApiResponse> disconnect() {
        log.info("[CONTROLLER] Pkcs11Controller.disconnect() called");
        pkcs11Service.disconnect();
        log.info("[CONTROLLER] Pkcs11Controller.disconnect() completed");
        return ResponseEntity.ok(com.example.cm.model.dto.ApiResponse.ok("PKCS#11 provider disconnected", null));
    }
}
