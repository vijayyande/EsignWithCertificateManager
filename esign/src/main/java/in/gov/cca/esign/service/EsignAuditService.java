package in.gov.cca.esign.service;

import in.gov.cca.esign.domain.EsignAuditLog;
import org.springframework.data.domain.Page;

/**
 * Append-only audit trail for every inbound eSign request.
 */
public interface EsignAuditService {

    /**
     * Records one request/response exchange. Never throws — audit failures
     * must not break the eSign flow.
     *
     * @param type         which eSign endpoint was hit
     * @param rawRequest   raw request body (XML or form payload)
     * @param responseXml  raw response body produced for the caller
     * @param httpStatus   HTTP status returned
     * @param remoteIp     client IP (X-Forwarded-For aware)
     */
    void record(EsignAuditLog.RequestType type, String rawRequest, String responseXml,
                int httpStatus, String remoteIp);

    Page<EsignAuditLog> search(String q, EsignAuditLog.RequestType type,
                               EsignAuditLog.Outcome outcome, java.time.LocalDateTime from,
                               java.time.LocalDateTime to, int page, int size);

    java.util.Optional<EsignAuditLog> findById(java.util.UUID id);
}
