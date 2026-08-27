package in.gov.cca.esign.domain;

import jakarta.persistence.*;
import in.gov.cca.esign.model.enums.EKycType;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "ekyc_users", indexes = {
    @Index(name = "idx_username", columnList = "username", unique = true),
    @Index(name = "idx_mobile", columnList = "mobile", unique = true),
    @Index(name = "idx_pan", columnList = "pan", unique = true),
    @Index(name = "idx_email", columnList = "email"),
    @Index(name = "idx_status", columnList = "status"),
    @Index(name = "idx_ekyc_type", columnList = "ekycType")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EKycUser {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "username", nullable = false, unique = true, length = 100)
    private String username;

    @Column(name = "pin_hash", nullable = false, length = 255)
    private String pinHash;

    @Column(name = "pin_salt", nullable = false, length = 255)
    private String pinSalt;

    @Column(name = "name", nullable = false, length = 200)
    private String name;

    @Column(name = "mobile", nullable = false, unique = true, length = 20)
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

    @Column(name = "photograph", columnDefinition = "TEXT")
    private String photograph;

    @Column(name = "dob")
    private LocalDate dob;

    @Column(name = "gender", length = 1)
    private String gender;

    @Column(name = "pan", unique = true, length = 20)
    private String pan;

    @Column(name = "aadhaar_last4", length = 4)
    private String aadhaarLast4;

    @Enumerated(EnumType.STRING)
    @Column(name = "ekyc_type", nullable = false, length = 30)
    private EKycType ekycType;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private UserStatus status;

    @Column(name = "ca_officer", length = 200)
    private String caOfficer;

    @Column(name = "failed_attempts", nullable = false)
    @Builder.Default
    private Integer failedAttempts = 0;

    @Column(name = "locked_until")
    private LocalDateTime lockedUntil;

    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "activated_at")
    private LocalDateTime activatedAt;

    @Column(name = "deactivated_at")
    private LocalDateTime deactivatedAt;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private java.util.List<UserAuthenticationFactor> authenticationFactors;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private java.util.List<AuthenticationLog> authenticationLogs;

    public enum UserStatus {
        PENDING_VERIFICATION,
        ACTIVE,
        SUSPENDED,
        DEACTIVATED,
        EXPIRED
    }
}