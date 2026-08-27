package in.gov.cca.esign.domain;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "bank_kyc", indexes = {
    @Index(name = "idx_bankkyc_txn_id", columnList = "transactionId", unique = true),
    @Index(name = "idx_bankkyc_account", columnList = "accountNumber"),
    @Index(name = "idx_bankkyc_ifsc", columnList = "bankIfscCode"),
    @Index(name = "idx_bankkyc_status", columnList = "status")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class BankKyc {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "transaction_id", nullable = false, unique = true, length = 100)
    private String transactionId;

    @Column(name = "bank_ifsc_code", length = 11)
    private String bankIfscCode;

    @Column(name = "bank_name", nullable = false, length = 200)
    private String bankName;

    @Column(name = "account_number", nullable = false, length = 50)
    private String accountNumber;

    @Column(name = "name", nullable = false, length = 200)
    private String name;

    @Column(name = "mobile", nullable = false, length = 20)
    private String mobile;

    @Column(name = "email", length = 100)
    private String email;

    @Column(name = "address", columnDefinition = "TEXT")
    private String address;

    @Column(name = "state_province", length = 100)
    private String stateProvince;

    @Column(name = "country", length = 2)
    private String country;

    @Column(name = "postal_code", length = 20)
    private String postalCode;

    @Column(name = "date_of_birth")
    private LocalDate dateOfBirth;

    @Column(name = "gender", length = 1)
    private String gender;

    @Column(name = "pan", length = 20)
    private String pan;

    @Column(name = "aadhaar_last4", length = 4)
    private String aadhaarLast4;

    @Column(name = "photo", columnDefinition = "TEXT")
    private String photo;

    @Column(name = "photo_format", length = 10)
    private String photoFormat;

    @Column(name = "bank_signature", columnDefinition = "TEXT")
    private String bankSignature;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private KycStatus status;

    @Column(name = "response_code", length = 100)
    private String responseCode;

    @Column(name = "error_code", length = 10)
    private String errorCode;

    @Column(name = "error_message", length = 500)
    private String errorMessage;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "processed_at")
    private LocalDateTime processedAt;

    public enum KycStatus {
        PENDING,
        VERIFIED,
        REJECTED,
        EXPIRED
    }
}