package com.example.cm.controller;

import com.example.cm.model.entity.CrlEntity;
import com.example.cm.service.CrlService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/crl")
@RequiredArgsConstructor
@Tag(name = "CRL", description = "Certificate Revocation List management: generate, download (DER/PEM), and view history. CRL generation is admin-only; download is public.")
@SecurityRequirement(name = "basicAuth")
@Slf4j
public class CrlController {

    private final CrlService crlService;

    @Operation(summary = "Generate CRL", description = "Generate a fresh CRL for a CA. Admin only.")
    @PostMapping("/{caId}/generate")
    public ResponseEntity<com.example.cm.model.dto.ApiResponse> generate(@PathVariable Long caId) {
        log.info("[CONTROLLER] CrlController.generate() called, caId={}", caId);
        CrlEntity crl = crlService.generateCrl(caId);
        log.info("[CONTROLLER] CrlController.generate() completed, caId={}", caId);
        return ResponseEntity.ok(com.example.cm.model.dto.ApiResponse.ok(
                "CRL #" + crl.getCrlNumber() + " generated for CA " + caId, crl));
    }

    @Operation(summary = "Download CRL (DER)", description = "Download the current CRL in DER binary format. Public endpoint (no auth required).")
    @GetMapping(value = "/{caId}", produces = "application/pkix-crl")
    public ResponseEntity<byte[]> getDer(@PathVariable Long caId) {
        log.info("[CONTROLLER] CrlController.getDer() called, caId={}", caId);
        byte[] result = crlService.getCurrentCrlDer(caId);
        log.info("[CONTROLLER] CrlController.getDer() completed, caId={}", caId);
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/pkix-crl"))
                .header("Content-Disposition", "attachment; filename=crl-" + caId + ".der")
                .body(result);
    }

    @Operation(summary = "View CRL (PEM)", description = "Returns the current CRL in PEM text format. Public endpoint.")
    @GetMapping(value = "/{caId}/pem", produces = "application/x-pem-file")
    public ResponseEntity<String> getPem(@PathVariable Long caId) {
        log.info("[CONTROLLER] CrlController.getPem() called, caId={}", caId);
        String result = crlService.getCurrentCrl(caId).getCrlPem();
        log.info("[CONTROLLER] CrlController.getPem() completed, caId={}", caId);
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/x-pem-file"))
                .body(result);
    }

    @Operation(summary = "CRL history", description = "Returns the last 10 CRL versions for a CA.")
    @GetMapping("/{caId}/history")
    public ResponseEntity<List<CrlEntity>> history(@PathVariable Long caId) {
        log.info("[CONTROLLER] CrlController.history() called, caId={}", caId);
        List<CrlEntity> result = crlService.getCrlHistory(caId);
        log.info("[CONTROLLER] CrlController.history() completed, caId={}", caId);
        return ResponseEntity.ok(result);
    }
}
