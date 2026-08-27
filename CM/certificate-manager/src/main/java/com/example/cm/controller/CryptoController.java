package com.example.cm.controller;

import com.example.cm.model.dto.KeyAlgorithmInfo;
import com.example.cm.model.dto.KeyDeriveRequest;
import com.example.cm.model.dto.KeyDeriveResult;
import com.example.cm.model.dto.OidInfo;
import com.example.cm.service.CryptoService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/crypto")
@RequiredArgsConstructor
@Tag(name = "Crypto", description = "Key algorithm catalog, OID reference, and parameter derivation helpers. Any authenticated user.")
@SecurityRequirement(name = "basicAuth")
@Slf4j
public class CryptoController {

    private final CryptoService cryptoService;

    @Operation(summary = "List key algorithms", description = "Returns the catalog of supported key algorithms (RSA, EC, Ed25519, Ed448) with their valid key sizes and default signature algorithms.")
    @GetMapping("/algorithms")
    public ResponseEntity<List<KeyAlgorithmInfo>> algorithms() {
        log.info("[CONTROLLER] CryptoController.algorithms() called");
        List<KeyAlgorithmInfo> result = cryptoService.keyAlgorithmCatalog();
        log.info("[CONTROLLER] CryptoController.algorithms() completed");
        return ResponseEntity.ok(result);
    }

    @Operation(summary = "List OIDs", description = "Returns well-known X.509 extension OIDs with friendly labels and suggested value types.")
    @GetMapping("/oids")
    public ResponseEntity<List<OidInfo>> oids() {
        log.info("[CONTROLLER] CryptoController.oids() called");
        List<OidInfo> result = cryptoService.oidCatalog();
        log.info("[CONTROLLER] CryptoController.oids() completed");
        return ResponseEntity.ok(result);
    }

    @Operation(summary = "Derive key parameters", description = "Given an algorithm and optional key size, returns the resolved key size, signature algorithm, and curve name (for EC).")
    @PostMapping("/derive")
    public ResponseEntity<KeyDeriveResult> derive(@RequestBody KeyDeriveRequest request) {
        log.info("[CONTROLLER] CryptoController.derive() called, algorithm={}, keySize={}", request.getKeyAlgorithm(), request.getKeySize());
        KeyDeriveResult result = cryptoService.deriveKeyParameters(
                request.getKeyAlgorithm(), request.getKeySize());
        log.info("[CONTROLLER] CryptoController.derive() completed");
        return ResponseEntity.ok(result);
    }
}
