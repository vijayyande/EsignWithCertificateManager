package com.example.cm.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import com.example.cm.exception.BusinessException;
import com.example.cm.model.dto.CsrRequest;
import com.example.cm.model.dto.ManualCertificateRequest;
import com.example.cm.model.dto.RevokeRequest;
import com.example.cm.model.entity.CertificateEntity;
import com.example.cm.model.enums.CertificateStatus;
import com.example.cm.service.CertificateService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

@RestController
@RequestMapping("/api/certificates")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Certificates", description = "Certificate lifecycle: issue (CSR or manual), search, download, revoke, suspend, resume")
@SecurityRequirement(name = "basicAuth")
public class CertificateController {

    private final CertificateService certificateService;

    @Operation(summary = "Submit a CSR for signing", description = "Submit a PKCS#10 CSR in PEM format. The CSR is signed by the specified CA (or the default active CA) and the issued certificate is returned.")
    @PostMapping("/csr")
    public ResponseEntity<com.example.cm.model.dto.ApiResponse> submitCsr(@Valid @RequestBody CsrRequest request) {
        CertificateEntity cert = certificateService.submitCsr(request);
        return ResponseEntity.ok(com.example.cm.model.dto.ApiResponse.ok(
                "CSR for '" + cert.getCommonName() + "' signed and issued", cert));
    }

    @Operation(summary = "Request a certificate manually", description = "Issue a certificate by providing subject CN, SANs, validity, and key parameters directly (no CSR needed). Admins can issue immediately; requesters create a pending request.")
    @PostMapping("/request")
    public ResponseEntity<com.example.cm.model.dto.ApiResponse> requestCertificate(@Valid @RequestBody ManualCertificateRequest request,
                                                          Authentication authentication) {
        log.info("[CERT-REQ] Received certificate request: cn={}, user={}, issuerCaId={}, profileId={}",
                request.getCommonName(), authentication.getName(),
                request.getIssuerCaId(), request.getProfileId());
        if (request.getRequestedBy() == null || request.getRequestedBy().isBlank()) {
            request.setRequestedBy(authentication.getName());
        }
        boolean adminUser = authentication.getAuthorities().stream()
                .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
        log.info("[CERT-REQ] Processing request for user '{}' (admin={})", request.getRequestedBy(), adminUser);
        CertificateEntity cert = certificateService.requestCertificate(request, adminUser);
        log.info("[CERT-REQ] Certificate request completed: id={}, cn={}, serial={}", cert.getId(), cert.getCommonName(), cert.getSerialNumber());
        return ResponseEntity.ok(com.example.cm.model.dto.ApiResponse.ok(
                "Certificate issued for '" + cert.getCommonName() + "'", cert));
    }

    @Operation(summary = "Search / list certificates", description = "Filter by free-text query, status, or issuing CA. Any authenticated user can list certificates.")
    @GetMapping
    public ResponseEntity<List<CertificateEntity>> list(
            @Parameter(description = "Free-text search (matches common name, SANs, serial)") @RequestParam(required = false) String q,
            @Parameter(description = "Filter by status") @RequestParam(required = false) CertificateStatus status,
            @Parameter(description = "Filter by issuing CA ID") @RequestParam(required = false) Long caId) {
        return ResponseEntity.ok(certificateService.search(q, status, caId));
    }

    @Operation(summary = "Get certificate details", description = "Fetch a single certificate by its ID.")
    @GetMapping("/{id}")
    public ResponseEntity<CertificateEntity> get(@PathVariable Long id) {
        return ResponseEntity.ok(certificateService.get(id));
    }

    @Operation(summary = "Get certificate PEM", description = "Returns the certificate in PEM format.")
    @GetMapping("/{id}/pem")
    public ResponseEntity<String> getPem(@PathVariable Long id) {
        CertificateEntity cert = certificateService.get(id);
        if (cert.getCertificatePem() == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/x-pem-file"))
                .body(cert.getCertificatePem());
    }

    @Operation(summary = "Download certificate", description = "Download the certificate in PEM (full chain), DER (leaf only), or CER (full chain, Windows convention) format.")
    @GetMapping("/{id}/download")
    public ResponseEntity<byte[]> download(@PathVariable Long id,
            @Parameter(description = "Output format: pem, der, or cer") @RequestParam(defaultValue = "pem") String format) {
        CertificateEntity cert = certificateService.get(id);
        if (cert.getCertificatePem() == null) {
            return ResponseEntity.notFound().build();
        }

        String cn = safeFilename(cert.getCommonName());
        String suffix = cn.isEmpty() ? "cert-" + id : cn + "-" + id;

        return switch (format.toLowerCase(Locale.ROOT)) {
            case "der" -> {
                byte[] der = Base64.getMimeDecoder().decode(
                        cert.getCertificatePem()
                                .replaceAll("-----BEGIN CERTIFICATE-----", "")
                                .replaceAll("-----END CERTIFICATE-----", "")
                                .replaceAll("\\s", ""));
                yield ResponseEntity.ok()
                        .contentType(MediaType.parseMediaType("application/pkix-cert"))
                        .header("Content-Disposition", "attachment; filename=\"" + suffix + ".der\"")
                        .body(der);
            }
            case "cer" -> {
                String pemChain = String.join("\n", certificateService.getCertificateChain(id));
                yield ResponseEntity.ok()
                        .contentType(MediaType.parseMediaType("application/pkix-cert"))
                        .header("Content-Disposition", "attachment; filename=\"" + suffix + ".cer\"")
                        .body(pemChain.getBytes(StandardCharsets.UTF_8));
            }
            case "pem" -> {
                String chain = String.join("\n", certificateService.getCertificateChain(id));
                yield ResponseEntity.ok()
                        .contentType(MediaType.parseMediaType("application/x-pem-file"))
                        .header("Content-Disposition", "attachment; filename=\"" + suffix + ".pem\"")
                        .body(chain.getBytes(StandardCharsets.UTF_8));
            }
            default -> throw new BusinessException(
                    "Unsupported format '" + format + "'. Use pem, der, or cer");
        };
    }

    @Operation(summary = "Download private key", description = "Download the private key in PEM format. Only available to the certificate requester and only for DATABASE-stored keys.")
    @GetMapping("/{id}/key")
    public ResponseEntity<String> getPrivateKey(@PathVariable Long id, Authentication authentication) {
        CertificateEntity cert = certificateService.get(id);
        if (cert.getKeyStorage() == com.example.cm.model.enums.KeyStorage.PKCS11) {
            return ResponseEntity.badRequest()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"message\":\"The private key is stored on the PKCS#11 device and cannot be exported\"}");
        }
        if (cert.getPrivateKeyPem() == null) {
            return ResponseEntity.notFound().build();
        }
        boolean owner = authentication.getName().equals(cert.getRequestedBy());
        if (!owner) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/x-pem-file"))
                .body(cert.getPrivateKeyPem());
    }

    @Operation(summary = "Revoke certificate", description = "Revoke an active certificate. Admin only.")
    @PostMapping("/{id}/revoke")
    public ResponseEntity<com.example.cm.model.dto.ApiResponse> revoke(@PathVariable Long id, @Valid @RequestBody RevokeRequest request) {
        CertificateEntity cert = certificateService.revoke(id, request);
        return ResponseEntity.ok(com.example.cm.model.dto.ApiResponse.ok("Certificate revoked", cert));
    }

    @Operation(summary = "Suspend certificate", description = "Suspend an active certificate (can be resumed later). Admin only.")
    @PostMapping("/{id}/suspend")
    public ResponseEntity<com.example.cm.model.dto.ApiResponse> suspend(@PathVariable Long id) {
        CertificateEntity cert = certificateService.suspend(id);
        return ResponseEntity.ok(com.example.cm.model.dto.ApiResponse.ok("Certificate suspended", cert));
    }

    @Operation(summary = "Resume certificate", description = "Resume a previously suspended certificate. Admin only.")
    @PostMapping("/{id}/resume")
    public ResponseEntity<com.example.cm.model.dto.ApiResponse> resume(@PathVariable Long id) {
        CertificateEntity cert = certificateService.resume(id);
        return ResponseEntity.ok(com.example.cm.model.dto.ApiResponse.ok("Certificate resumed", cert));
    }

    private static String safeFilename(String s) {
        if (s == null) return "";
        return s.replaceAll("[^a-zA-Z0-9._-]", "_").replaceAll("_+", "_").replaceAll("^_|_$", "");
    }
}
