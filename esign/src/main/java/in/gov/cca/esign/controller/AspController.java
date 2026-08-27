package in.gov.cca.esign.controller;

import in.gov.cca.esign.domain.Asp;
import in.gov.cca.esign.domain.EsignTransaction;
import in.gov.cca.esign.repository.AspRepository;
import in.gov.cca.esign.repository.EsignTransactionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/asps")
@RequiredArgsConstructor
public class AspController {

    private final AspRepository aspRepository;
    private final EsignTransactionRepository transactionRepository;

    public record AspRequest(
            String aspId,
            String organisationName,
            String contactEmail,
            String contactPhone,
            String certificatePem,
            String allowedResponseUrlPrefix,
            String status,
            String notes) {
    }

    @GetMapping
    public List<Map<String, Object>> list(@RequestParam(required = false) String q) {
        List<Asp> asps = (q != null && !q.isBlank())
                ? aspRepository.search(q.trim())
                : aspRepository.findAll();
        return asps.stream().map(this::toMap).toList();
    }

    @GetMapping("/{aspId}")
    public ResponseEntity<Map<String, Object>> get(@PathVariable String aspId) {
        return aspRepository.findByAspId(aspId)
                .<ResponseEntity<Map<String, Object>>>map(asp -> ResponseEntity.ok(toMap(asp)))
                .orElse(notFound(aspId));
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> create(@RequestBody AspRequest req) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (req.aspId() == null || req.aspId().isBlank()) {
            out.put("error", "aspId is required");
            return ResponseEntity.badRequest().body(out);
        }
        if (req.organisationName() == null || req.organisationName().isBlank()) {
            out.put("error", "organisationName is required");
            return ResponseEntity.badRequest().body(out);
        }
        if (aspRepository.existsByAspId(req.aspId())) {
            out.put("error", "ASP already exists: " + req.aspId());
            return ResponseEntity.status(HttpStatus.CONFLICT).body(out);
        }
        Asp saved = aspRepository.save(builderFrom(req).build());
        log.info("Registered ASP: {} ({})", saved.getAspId(), saved.getOrganisationName());
        return ResponseEntity.status(HttpStatus.CREATED).body(toMap(saved));
    }

    @PutMapping("/{aspId}")
    public ResponseEntity<Map<String, Object>> update(@PathVariable String aspId,
                                                      @RequestBody AspRequest req) {
        Asp asp = aspRepository.findByAspId(aspId).orElse(null);
        if (asp == null) {
            return notFound(aspId);
        }
        if (req.organisationName() != null && !req.organisationName().isBlank()) {
            asp.setOrganisationName(req.organisationName());
        }
        asp.setContactEmail(req.contactEmail());
        asp.setContactPhone(req.contactPhone());
        asp.setCertificatePem(req.certificatePem());
        asp.setAllowedResponseUrlPrefix(req.allowedResponseUrlPrefix());
        asp.setNotes(req.notes());
        if (req.status() != null && !req.status().isBlank()) {
            try {
                asp.setStatus(Asp.AspStatus.valueOf(req.status().toUpperCase()));
            } catch (IllegalArgumentException e) {
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("error", "Invalid status: " + req.status());
                return ResponseEntity.badRequest().body(out);
            }
        }
        return ResponseEntity.ok(toMap(aspRepository.save(asp)));
    }

    @PostMapping("/{aspId}/status")
    public ResponseEntity<Map<String, Object>> changeStatus(@PathVariable String aspId,
                                                            @RequestParam String status) {
        Asp asp = aspRepository.findByAspId(aspId).orElse(null);
        if (asp == null) {
            return notFound(aspId);
        }
        try {
            asp.setStatus(Asp.AspStatus.valueOf(status.toUpperCase()));
        } catch (IllegalArgumentException e) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("error", "Invalid status: " + status + " (use ACTIVE, INACTIVE or SUSPENDED)");
            return ResponseEntity.badRequest().body(out);
        }
        log.info("ASP {} status changed to {}", aspId, asp.getStatus());
        return ResponseEntity.ok(toMap(aspRepository.save(asp)));
    }

    @DeleteMapping("/{aspId}")
    public ResponseEntity<Map<String, Object>> delete(@PathVariable String aspId) {
        Asp asp = aspRepository.findByAspId(aspId).orElse(null);
        if (asp == null) {
            return notFound(aspId);
        }
        long txnCount = transactionRepository.countByAspId(aspId);
        aspRepository.delete(asp);
        log.info("Deleted ASP: {} (had {} transactions)", aspId, txnCount);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "deleted");
        out.put("aspId", aspId);
        return ResponseEntity.ok(out);
    }

    @GetMapping("/{aspId}/stats")
    public ResponseEntity<Map<String, Object>> stats(@PathVariable String aspId) {
        if (aspRepository.findByAspId(aspId).isEmpty()) {
            return notFound(aspId);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("aspId", aspId);
        out.put("total", transactionRepository.countByAspId(aspId));
        for (EsignTransaction.TransactionStatus s : EsignTransaction.TransactionStatus.values()) {
            out.put(s.name().toLowerCase(), transactionRepository.countByAspIdAndStatus(aspId, s));
        }
        return ResponseEntity.ok(out);
    }

    @GetMapping("/{aspId}/transactions")
    public ResponseEntity<List<Map<String, Object>>> transactions(@PathVariable String aspId) {
        if (aspRepository.findByAspId(aspId).isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        List<Map<String, Object>> rows = transactionRepository
                .findTop25ByAspIdOrderByCreatedAtDesc(aspId).stream()
                .map(t -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("transactionId", t.getTransactionId());
                    m.put("status", t.getStatus().name());
                    m.put("signerId", t.getSignerId());
                    m.put("createdAt", t.getCreatedAt() != null ? t.getCreatedAt().toString() : null);
                    m.put("completedAt", t.getCompletedAt() != null ? t.getCompletedAt().toString() : null);
                    m.put("errorCode", t.getErrorCode());
                    return m;
                }).toList();
        return ResponseEntity.ok(rows);
    }

    private Asp.AspBuilder builderFrom(AspRequest req) {
        Asp.AspStatus status;
        try {
            status = req.status() != null && !req.status().isBlank()
                    ? Asp.AspStatus.valueOf(req.status().toUpperCase())
                    : Asp.AspStatus.ACTIVE;
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid status: " + req.status());
        }
        return Asp.builder()
                .aspId(req.aspId())
                .organisationName(req.organisationName())
                .contactEmail(req.contactEmail())
                .contactPhone(req.contactPhone())
                .certificatePem(req.certificatePem())
                .allowedResponseUrlPrefix(req.allowedResponseUrlPrefix())
                .status(status)
                .notes(req.notes());
    }

    private Map<String, Object> toMap(Asp a) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", a.getId());
        m.put("aspId", a.getAspId());
        m.put("organisationName", a.getOrganisationName());
        m.put("contactEmail", a.getContactEmail());
        m.put("contactPhone", a.getContactPhone());
        m.put("hasCertificate", a.getCertificatePem() != null && !a.getCertificatePem().isBlank());
        m.put("certificatePem", a.getCertificatePem());
        m.put("allowedResponseUrlPrefix", a.getAllowedResponseUrlPrefix());
        m.put("status", a.getStatus().name());
        m.put("notes", a.getNotes());
        m.put("registeredAt", a.getRegisteredAt() != null ? a.getRegisteredAt().toString() : null);
        m.put("updatedAt", a.getUpdatedAt() != null ? a.getUpdatedAt().toString() : null);
        return m;
    }

    private ResponseEntity<Map<String, Object>> notFound(String aspId) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("error", "ASP not found: " + aspId);
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(out);
    }
}