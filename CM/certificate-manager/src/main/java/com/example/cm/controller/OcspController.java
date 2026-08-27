package com.example.cm.controller;

import com.example.cm.model.dto.ApiResponse;
import com.example.cm.service.OcspService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/ocsp")
@RequiredArgsConstructor
@Tag(name = "OCSP", description = "OCSP responder: binary OCSP request processing and human-readable status queries. Public and authenticated endpoints.")
public class OcspController {

    private final OcspService ocspService;

    @Operation(summary = "OCSP request (binary)", description = "Process a DER-encoded OCSP request and return the binary OCSP response. Public endpoint (no auth required).",
            responses = {
                @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "OCSP response (application/ocsp-response)")
            })
    @PostMapping(consumes = {"application/ocsp-request", "application/octet-stream", "application/ocsp-response", "text/plain", "*/*"},
            produces = "application/ocsp-response")
    public ResponseEntity<byte[]> respond(@RequestBody byte[] body) {
        byte[] response = ocspService.respond(body);
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/ocsp-response"))
                .body(response);
    }

    @Operation(summary = "Check certificate status (path)", description = "Human-readable OCSP status for a certificate serial number (hex, path variable). Public endpoint.")
    @GetMapping("/status/{serialHex}")
    public ResponseEntity<ApiResponse> status(
            @Parameter(description = "Certificate serial number in hex") @PathVariable String serialHex) {
        String status = ocspService.checkStatus(serialHex);
        return ResponseEntity.ok(ApiResponse.ok("OCSP status check",
                Map.of("serial", serialHex, "status", status)));
    }

    @Operation(summary = "Check certificate status (query)", description = "Human-readable OCSP status for a certificate serial number (query parameter). Public endpoint.")
    @GetMapping("/status")
    public ResponseEntity<ApiResponse> statusQuery(
            @Parameter(description = "Certificate serial number in hex") @RequestParam String serial) {
        String status = ocspService.checkStatus(serial);
        return ResponseEntity.ok(ApiResponse.ok("OCSP status check",
                Map.of("serial", serial, "status", status)));
    }
}
