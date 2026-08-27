package com.example.cm.controller;

import com.example.cm.model.dto.CaRequest;
import com.example.cm.model.entity.CaEntity;
import com.example.cm.service.CaService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/ca")
@RequiredArgsConstructor
@Tag(name = "CA Management", description = "Create, import, list, revoke, suspend and resume Certificate Authorities. Admin only (except active CA list and certificate download).")
@SecurityRequirement(name = "basicAuth")
@Slf4j
public class CaController {

    private final CaService caService;

    @Operation(summary = "Create a new CA", description = "Generate a new CA key pair (on database or PKCS#11 device) and a self-signed or parent-signed certificate. Admin only.")
    @PostMapping
    public ResponseEntity<com.example.cm.model.dto.ApiResponse> requestCa(@Valid @RequestBody CaRequest request) {
        log.info("[CONTROLLER] CaController.requestCa() called");
        CaEntity ca = caService.requestCa(request);
        log.info("[CONTROLLER] CaController.requestCa() completed");
        return ResponseEntity.ok(com.example.cm.model.dto.ApiResponse.ok(
                "CA '" + ca.getName() + "' created and activated", ca));
    }

    @Operation(summary = "Import an existing CA", description = "Register an existing CA certificate (from an HSM/PKCS#11 device or database) without generating new keys. Admin only.")
    @PostMapping("/import")
    public ResponseEntity<com.example.cm.model.dto.ApiResponse> importCa(@Valid @RequestBody CaRequest request) {
        log.info("[CONTROLLER] CaController.importCa() called");
        CaEntity ca = caService.importCa(request);
        log.info("[CONTROLLER] CaController.importCa() completed");
        return ResponseEntity.ok(com.example.cm.model.dto.ApiResponse.ok(
                "CA '" + ca.getName() + "' imported and activated", ca));
    }

    @Operation(summary = "List all CAs", description = "Returns every CA in the registry. Admin only.")
    @GetMapping
    public ResponseEntity<List<CaEntity>> list() {
        log.info("[CONTROLLER] CaController.list() called");
        List<CaEntity> result = caService.listAll();
        log.info("[CONTROLLER] CaController.list() completed");
        return ResponseEntity.ok(result);
    }

    @Operation(summary = "List active CAs", description = "Returns only CAs with ISSUED status. Readable by any authenticated user (powers CSR issuer / CRL dropdowns).")
    @GetMapping("/active")
    public ResponseEntity<List<CaEntity>> listActive() {
        log.info("[CONTROLLER] CaController.listActive() called");
        List<CaEntity> result = caService.listActive();
        log.info("[CONTROLLER] CaController.listActive() completed");
        return ResponseEntity.ok(result);
    }

    @Operation(summary = "Get CA by ID")
    @GetMapping("/{id}")
    public ResponseEntity<CaEntity> get(@PathVariable Long id) {
        log.info("[CONTROLLER] CaController.get() called, id={}", id);
        CaEntity result = caService.get(id);
        log.info("[CONTROLLER] CaController.get() completed, id={}", id);
        return ResponseEntity.ok(result);
    }

    @Operation(summary = "Revoke CA", description = "Revoke an active CA. Admin only.")
    @PostMapping("/{id}/revoke")
    public ResponseEntity<com.example.cm.model.dto.ApiResponse> revoke(@PathVariable Long id,
                                               @RequestBody(required = false) Map<String, String> body) {
        log.info("[CONTROLLER] CaController.revoke() called, id={}", id);
        String reason = body != null ? body.getOrDefault("reason", "CA revoked") : "CA revoked";
        String by = body != null ? body.getOrDefault("by", "admin") : "admin";
        CaEntity ca = caService.revoke(id, reason, by);
        log.info("[CONTROLLER] CaController.revoke() completed, id={}", id);
        return ResponseEntity.ok(com.example.cm.model.dto.ApiResponse.ok("CA revoked", ca));
    }

    @Operation(summary = "Suspend CA", description = "Suspend an active CA. Admin only.")
    @PostMapping("/{id}/suspend")
    public ResponseEntity<com.example.cm.model.dto.ApiResponse> suspend(@PathVariable Long id,
                                               @RequestBody(required = false) Map<String, String> body) {
        log.info("[CONTROLLER] CaController.suspend() called, id={}", id);
        String by = body != null ? body.getOrDefault("by", "admin") : "admin";
        CaEntity ca = caService.suspend(id, by);
        log.info("[CONTROLLER] CaController.suspend() completed, id={}", id);
        return ResponseEntity.ok(com.example.cm.model.dto.ApiResponse.ok("CA suspended", ca));
    }

    @Operation(summary = "Resume CA", description = "Resume a suspended CA. Admin only.")
    @PostMapping("/{id}/resume")
    public ResponseEntity<com.example.cm.model.dto.ApiResponse> resume(@PathVariable Long id,
                                               @RequestBody(required = false) Map<String, String> body) {
        log.info("[CONTROLLER] CaController.resume() called, id={}", id);
        String by = body != null ? body.getOrDefault("by", "admin") : "admin";
        CaEntity ca = caService.resume(id, by);
        log.info("[CONTROLLER] CaController.resume() completed, id={}", id);
        return ResponseEntity.ok(com.example.cm.model.dto.ApiResponse.ok("CA resumed", ca));
    }

    @Operation(summary = "Download CA certificate (PEM)", description = "Returns the CA certificate in PEM format.")
    @GetMapping("/{id}/certificate.pem")
    public ResponseEntity<String> certificatePem(@PathVariable Long id) {
        log.info("[CONTROLLER] CaController.certificatePem() called, id={}", id);
        CaEntity ca = caService.get(id);
        if (ca.getCertificatePem() == null) {
            log.info("[CONTROLLER] CaController.certificatePem() completed, id={}, notFound", id);
            return ResponseEntity.notFound().build();
        }
        log.info("[CONTROLLER] CaController.certificatePem() completed, id={}", id);
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/x-pem-file"))
                .body(ca.getCertificatePem());
    }
}
