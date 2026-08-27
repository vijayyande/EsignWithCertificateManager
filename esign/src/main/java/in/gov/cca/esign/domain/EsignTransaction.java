package in.gov.cca.esign.domain;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "esign_transactions", indexes = {
    @Index(name = "idx_txn_id", columnList = "transactionId", unique = true),
    @Index(name = "idx_asp_id", columnList = "aspId"),
    @Index(name = "idx_signer_id", columnList = "signerId"),
    @Index(name = "idx_status", columnList = "status"),
    @Index(name = "idx_created_at", columnList = "createdAt")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EsignTransaction {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "transaction_id", nullable = false, unique = true, length = 100)
    private String transactionId;

    @Column(name = "asp_id", nullable = false, length = 100)
    private String aspId;

    @Column(name = "signer_id", length = 200)
    private String signerId;

    @Column(name = "version", nullable = false, length = 10)
    private String version;

    @Column(name = "timestamp", nullable = false)
    private LocalDateTime timestamp;

    @Column(name = "max_wait_period", nullable = false)
    private Integer maxWaitPeriod;

    @Column(name = "response_url", nullable = false, length = 500)
    private String responseUrl;

    @Column(name = "redirect_url", length = 500)
    private String redirectUrl;

    @Column(name = "signing_algorithm", nullable = false, length = 20)
    private String signingAlgorithm;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private TransactionStatus status;

    @Column(name = "response_code", length = 100)
    private String responseCode;

    @Column(name = "error_code", length = 10)
    private String errorCode;

    @Column(name = "error_message", length = 500)
    private String errorMessage;

    @Column(name = "user_certificate", columnDefinition = "TEXT")
    private String userCertificate;

    @Column(name = "esp_signature", columnDefinition = "TEXT")
    private String espSignature;

    @Column(name = "request_xml", columnDefinition = "TEXT")
    private String requestXml;

    @Column(name = "response_xml", columnDefinition = "TEXT")
    private String responseXml;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "completed_at")
    private LocalDateTime completedAt;

    @OneToMany(mappedBy = "transaction", cascade = CascadeType.ALL, orphanRemoval = true)
    private java.util.List<DocumentSignature> documentSignatures;

    public enum TransactionStatus {
        PENDING,
        IN_PROGRESS,
        COMPLETED,
        FAILED,
        EXPIRED,
        CANCELLED
    }
}