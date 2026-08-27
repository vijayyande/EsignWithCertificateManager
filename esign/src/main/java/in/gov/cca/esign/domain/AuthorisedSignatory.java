package in.gov.cca.esign.domain;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "authorised_signatories", indexes = {
    @Index(name = "idx_authsig_org_id", columnList = "organisation_id"),
    @Index(name = "idx_authsig_orgsig_id", columnList = "orgSigId", unique = true),
    @Index(name = "idx_authsig_cert_id", columnList = "certId", unique = true),
    @Index(name = "idx_authsig_status", columnList = "status")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthorisedSignatory {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "organisation_id", nullable = false)
    private Organisation organisation;

    @Column(name = "name", nullable = false, length = 200)
    private String name;

    @Column(name = "org_sig_id", nullable = false, unique = true, length = 100)
    private String orgSigId;

    @Column(name = "org_unit", length = 100)
    private String orgUnit;

    @Column(name = "cert_id", unique = true, length = 200)
    private String certId;

    @Column(name = "certificate", columnDefinition = "TEXT")
    private String certificate;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private SignatoryStatus status;

    @Column(name = "ca_officer", length = 200)
    private String caOfficer;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "verified_at")
    private LocalDateTime verifiedAt;

    public enum SignatoryStatus {
        PENDING_VERIFICATION,
        ACTIVE,
        SUSPENDED,
        REVOKED
    }
}