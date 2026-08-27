package in.gov.cca.esign.domain;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "user_authentication_factors", indexes = {
    @Index(name = "idx_auth_user_id", columnList = "user_id"),
    @Index(name = "idx_auth_type", columnList = "factorType"),
    @Index(name = "idx_auth_status", columnList = "status")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserAuthenticationFactor {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private EKycUser user;

    @Enumerated(EnumType.STRING)
    @Column(name = "factor_type", nullable = false, length = 20)
    private AuthenticationFactorType factorType;

    @Column(name = "factor_data", columnDefinition = "TEXT")
    private String factorData;

    @Column(name = "secret_key", length = 255)
    private String secretKey;

    @Column(name = "public_key", columnDefinition = "TEXT")
    private String publicKey;

    @Column(name = "credential_id", length = 255)
    private String credentialId;

    @Column(name = "device_info", columnDefinition = "TEXT")
    private String deviceInfo;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private FactorStatus status;

    @Column(name = "registered_at", nullable = false)
    private LocalDateTime registeredAt;

    @Column(name = "last_used_at")
    private LocalDateTime lastUsedAt;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @Column(name = "counter", nullable = false)
    @Builder.Default
    private Long counter = 0L;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    public enum AuthenticationFactorType {
        SMSOTP,
        TOTP,
        MAT,
        FIDO2,
        PUBLIC_KEY
    }

    public enum FactorStatus {
        ACTIVE,
        INACTIVE,
        REVOKED,
        EXPIRED
    }
}