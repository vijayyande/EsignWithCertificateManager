package in.gov.cca.esign.domain;

import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

@Entity
@Table(name = "document_signatures", indexes = {
    @Index(name = "idx_doc_txn_id", columnList = "transaction_id"),
    @Index(name = "idx_doc_id", columnList = "documentId")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DocumentSignature {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "transaction_id", nullable = false)
    private EsignTransaction transaction;

    @Column(name = "document_id", nullable = false)
    private Integer documentId;

    @Column(name = "hash_algorithm", nullable = false, length = 20)
    private String hashAlgorithm;

    @Column(name = "doc_info", length = 100)
    private String docInfo;

    @Column(name = "doc_url", length = 500)
    private String docUrl;

    @Column(name = "response_sig_type", nullable = false, length = 20)
    private String responseSigType;

    @Column(name = "document_hash", nullable = false, columnDefinition = "TEXT")
    private String documentHash;

    @Column(name = "signature_value", columnDefinition = "TEXT")
    private String signatureValue;

    @Column(name = "error_code", length = 10)
    private String errorCode;

    @Column(name = "signed_at")
    private java.time.LocalDateTime signedAt;
}