package in.gov.cca.esign.domain;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "authentication_logs", indexes = {
    @Index(name = "idx_authlog_user_id", columnList = "user_id"),
    @Index(name = "idx_authlog_txn_id", columnList = "transactionId"),
    @Index(name = "idx_authlog_created_at", columnList = "createdAt"),
    @Index(name = "idx_authlog_success", columnList = "success")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthenticationLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private EKycUser user;

    @Column(name = "transaction_id", length = 100)
    private String transactionId;

    @Enumerated(EnumType.STRING)
    @Column(name = "factor_type", nullable = false, length = 20)
    private UserAuthenticationFactor.AuthenticationFactorType factorType;

    @Enumerated(EnumType.STRING)
    @Column(name = "auth_mode", nullable = false, length = 20)
    private AuthMode authMode;

    @Column(name = "success", nullable = false)
    private Boolean success;

    @Column(name = "error_code", length = 10)
    private String errorCode;

    @Column(name = "error_message", length = 500)
    private String errorMessage;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    public enum AuthMode {
        COMPOSITE,
        INDEPENDENT
    }
}