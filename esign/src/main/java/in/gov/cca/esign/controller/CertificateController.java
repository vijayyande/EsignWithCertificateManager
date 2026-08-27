package in.gov.cca.esign.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import in.gov.cca.esign.domain.EsignAuditLog;
import in.gov.cca.esign.model.CertificateEnrollmentRequest;
import in.gov.cca.esign.service.CertificateService;
import in.gov.cca.esign.service.EsignAuditService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Certificate enrollment proxy — accepts the CA enrollment JSON and forwards it
 * to the endpoint configured under {@code ca.*} in application.yml.
 * eSign metadata fields are captured in the audit trail; only CA-bound fields
 * are forwarded.
 */
@RestController
@RequestMapping("/api/certificates")
@RequiredArgsConstructor
public class CertificateController {

    private final CertificateService certificateService;
    private final EsignAuditService auditService;
    private final ObjectMapper objectMapper;

    @PostMapping(value = "/request", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> request(@RequestBody CertificateEnrollmentRequest request,
                                                       HttpServletRequest http) {
        ResponseEntity<Map<String, Object>> resp = certificateService.requestCertificate(request);

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("aspId", request.aspId());
        meta.put("signerId", request.signerId());
        meta.put("transactionId", request.transactionId());
        meta.put("docHash", request.docHash());
        meta.put("docInfo", request.docInfo());
        meta.put("signingAlgorithm", request.signingAlgorithm());
        meta.put("commonName", request.commonName());
        meta.put("keyAlgorithm", request.keyAlgorithm());

        try {
            auditService.record(
                    EsignAuditLog.RequestType.CERT_REQUEST,
                    objectMapper.writeValueAsString(meta),
                    resp.getBody() == null ? null : resp.getBody().toString(),
                    resp.getStatusCode().value(),
                    http.getRemoteAddr());
        } catch (Exception ignored) {
        }

        return resp;
    }

    @GetMapping("/settings")
    public Map<String, Object> settings() {
        return certificateService.settingsSummary();
    }
}
