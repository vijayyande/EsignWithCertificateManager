package in.gov.cca.esign.controller;

import in.gov.cca.esign.domain.EsignAuditLog;
import in.gov.cca.esign.service.EsignAuditService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/esign-logs")
@RequiredArgsConstructor
public class EsignAuditController {

    private final EsignAuditService auditService;

    @GetMapping
    public Map<String, Object> search(
            @RequestParam(required = false) String q,
            @RequestParam(required = false) String type,
            @RequestParam(required = false) String outcome,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size) {

        Page<EsignAuditLog> result = auditService.search(q, parseEnum(type, EsignAuditLog.RequestType.class),
                parseEnum(outcome, EsignAuditLog.Outcome.class), parseDate(from), parseDate(to), page, size);

        List<Map<String, Object>> content = result.getContent().stream().map(this::toMap).toList();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("content", content);
        out.put("page", result.getNumber());
        out.put("size", result.getSize());
        out.put("totalElements", result.getTotalElements());
        out.put("totalPages", result.getTotalPages());
        return out;
    }

    @GetMapping("/{id}")
    public ResponseEntity<Map<String, Object>> detail(@PathVariable String id) {
        try {
            return auditService.findById(java.util.UUID.fromString(id))
                    .<ResponseEntity<Map<String, Object>>>map(l -> ResponseEntity.ok(toMap(l)))
                    .orElseGet(() -> ResponseEntity.notFound().build());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        }
    }

    private Map<String, Object> toMap(EsignAuditLog log) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", log.getId());
        out.put("createdAt", log.getCreatedAt() == null ? null : log.getCreatedAt().toString());
        out.put("endpoint", log.getEndpoint());
        out.put("transactionId", log.getTransactionId());
        out.put("aspId", log.getAspId());
        out.put("signerId", log.getSignerId());
        out.put("remoteIp", log.getRemoteIp());
        out.put("outcome", log.getOutcome());
        out.put("httpStatus", log.getHttpStatus());
        out.put("errorCode", log.getErrorCode());
        out.put("errorMessage", log.getErrorMessage());
        out.put("documentCount", log.getDocumentCount());
        out.put("requestBytes", log.getRequestBytes());
        out.put("responseSnippet", log.getResponseSnippet());
        if (log.getRequestXml() != null) {
            out.put("requestXml", log.getRequestXml());
        }
        return out;
    }

    private <T extends Enum<T>> T parseEnum(String value, Class<T> enumClass) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Enum.valueOf(enumClass, value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private LocalDateTime parseDate(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return LocalDateTime.parse(value);
        } catch (DateTimeParseException e) {
            return null;
        }
    }
}
