package com.example.cm.controller;

import com.example.cm.model.enums.CertificateStatus;
import com.example.cm.repository.CaRepository;
import com.example.cm.repository.CertificateRepository;
import com.example.cm.service.CryptoService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/info")
@RequiredArgsConstructor
@Tag(name = "System Info", description = "Dashboard summary (counts + endpoint configuration). Any authenticated user can read; admin can update CRL/OCSP endpoints.")
@SecurityRequirement(name = "basicAuth")
@Slf4j
public class InfoController {

    private final CaRepository caRepository;
    private final CertificateRepository certificateRepository;
    private final CryptoService cryptoService;

    @Operation(summary = "Dashboard summary", description = "Returns certificate/CA counts and current CRL + OCSP endpoint configuration.")
    @GetMapping
    public ResponseEntity<Map<String, Object>> summary() {
        log.info("[CONTROLLER] InfoController.summary() called");
        Map<String, Object> counts = new LinkedHashMap<>();
        counts.put("casTotal", caRepository.count());
        counts.put("casActive", caRepository.findByStatus(CertificateStatus.ISSUED).size());
        counts.put("certificatesTotal", certificateRepository.count());
        counts.put("certificatesIssued", certificateRepository.findByStatus(CertificateStatus.ISSUED).size());
        counts.put("certificatesRevoked", certificateRepository.findByStatus(CertificateStatus.REVOKED).size());
        counts.put("certificatesSuspended", certificateRepository.findByStatus(CertificateStatus.SUSPENDED).size());
        counts.put("certificatesPending", certificateRepository.findByStatus(CertificateStatus.PENDING).size());

        Map<String, Object> cfg = new LinkedHashMap<>();
        cfg.put("crlUrlBase", cryptoService.getCrlUrlBase());
        cfg.put("ocspUrl", cryptoService.getOcspUrl());

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("counts", counts);
        response.put("config", cfg);
        log.info("[CONTROLLER] InfoController.summary() completed");
        return ResponseEntity.ok(response);
    }

    @Operation(summary = "Update CRL / OCSP endpoints", description = "Update the CRL distribution point base URL and OCSP responder URL at runtime. Admin only.")
    @PutMapping("/config")
    public ResponseEntity<Map<String, Object>> updateConfig(@RequestBody Map<String, String> body,
                                                            Authentication authentication) {
        log.info("[CONTROLLER] InfoController.updateConfig() called");
        boolean admin = authentication.getAuthorities().stream()
                .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
        if (!admin) {
            log.info("[CONTROLLER] InfoController.updateConfig() completed, deniedNotAdmin");
            return ResponseEntity.status(403).build();
        }

        if (body.containsKey("crlUrlBase")) {
            String val = body.get("crlUrlBase");
            if (val == null || val.isBlank()) {
                log.info("[CONTROLLER] InfoController.updateConfig() completed, badRequestEmptyCrlUrlBase");
                return ResponseEntity.badRequest().body(Map.of("error", "crlUrlBase cannot be empty"));
            }
            if (!val.endsWith("/")) val = val + "/";
            cryptoService.setCrlUrlBase(val);
        }
        if (body.containsKey("ocspUrl")) {
            String val = body.get("ocspUrl");
            if (val == null || val.isBlank()) {
                log.info("[CONTROLLER] InfoController.updateConfig() completed, badRequestEmptyOcspUrl");
                return ResponseEntity.badRequest().body(Map.of("error", "ocspUrl cannot be empty"));
            }
            cryptoService.setOcspUrl(val);
        }

        Map<String, Object> cfg = new LinkedHashMap<>();
        cfg.put("crlUrlBase", cryptoService.getCrlUrlBase());
        cfg.put("ocspUrl", cryptoService.getOcspUrl());
        log.info("[CONTROLLER] InfoController.updateConfig() completed");
        return ResponseEntity.ok(cfg);
    }
}
