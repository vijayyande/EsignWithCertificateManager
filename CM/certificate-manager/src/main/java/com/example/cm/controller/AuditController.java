package com.example.cm.controller;

import com.example.cm.model.dto.AuditVerificationResult;
import com.example.cm.model.entity.AuditLog;
import com.example.cm.repository.AuditLogRepository;
import com.example.cm.service.AuditService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/audit")
@RequiredArgsConstructor
@Tag(name = "Audit Trail", description = "Signed audit log with hash-chain integrity and HMAC-SHA256 signatures. Admin only.")
@SecurityRequirement(name = "basicAuth")
@Slf4j
public class AuditController {

    private final AuditLogRepository auditLogRepository;
    private final AuditService auditService;

    @Operation(summary = "List audit log entries", description = "Returns all audit log entries in chronological order. Admin only.")
    @GetMapping
    public ResponseEntity<List<AuditLog>> list() {
        log.info("[CONTROLLER] AuditController.list() called");
        List<AuditLog> result = auditLogRepository.findAllByOrderByIdAsc();
        log.info("[CONTROLLER] AuditController.list() completed");
        return ResponseEntity.ok(result);
    }

    @Operation(summary = "Verify audit log integrity", description = "Recomputes the hash chain and verifies every HMAC-SHA256 signature. Returns valid/total/verified/failedAt. Admin only.")
    @GetMapping("/verify")
    public ResponseEntity<AuditVerificationResult> verify() {
        log.info("[CONTROLLER] AuditController.verify() called");
        AuditVerificationResult result = auditService.verify();
        log.info("[CONTROLLER] AuditController.verify() completed");
        return ResponseEntity.ok(result);
    }
}
