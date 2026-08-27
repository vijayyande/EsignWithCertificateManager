package in.gov.cca.esign.domain;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Immutable audit record for every inbound eSign request
 * (sign, status check, auth callback) — including requests that fail
 * validation before a transaction row is ever created.
 */
@Entity
@Table(name = "esign_audit_logs", indexes = {
    @Index(name = "idx_auditlog_txn_id", columnList = "transactionId"),
    @Index(name = "idx_auditlog_asp_id", columnList = "aspId"),
    @Index(name = "idx_auditlog_created_at", columnList = "createdAt"),
    @Index(name = "idx_auditlog_outcome", columnList = "outcome"),
    @Index(name = "idx_auditlog_endpoint", columnList = "endpoint")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EsignAuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private RequestType endpoint;

    @Column(name = "transaction_id", length = 100)
    private String transactionId;

    @Column(length = 100)
    private String aspId;

    @Column(name = "signer_id", length = 200)
    private String signerId;

    @Column(name = "remote_ip", length = 45)
    private String remoteIp;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Outcome outcome;

    @Column(name = "http_status", nullable = false)
    private Integer httpStatus;

    @Column(length = 10)
    private String errorCode;

    @Column(length = 500)
    private String errorMessage;

    @Column(name = "document_count")
    private Integer documentCount;

    @Column(name = "request_bytes")
    private Integer requestBytes;

    @Column(name = "response_snippet", length = 500)
    private String responseSnippet;

    @Column(name = "request_xml", columnDefinition = "TEXT")
    private String requestXml;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    public enum RequestType {
        SIGN,
        STATUS,
        AUTH_CALLBACK,
        CERT_REQUEST
    }

    public enum Outcome {
        SUCCESS,
        PENDING,
        REJECTED,
        ERROR
    }
}
