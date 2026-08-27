package in.gov.cca.esign.domain;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "organisations", indexes = {
    @Index(name = "idx_org_name", columnList = "name", unique = true),
    @Index(name = "idx_org_kyc_id", columnList = "kycOrgId", unique = true),
    @Index(name = "idx_org_status", columnList = "status")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Organisation {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "name", nullable = false, unique = true, length = 200)
    private String name;

    @Column(name = "address", columnDefinition = "TEXT")
    private String address;

    @Column(name = "kyc_org_id", nullable = false, unique = true, length = 100)
    private String kycOrgId;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private OrgStatus status;

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

    @OneToMany(mappedBy = "organisation", cascade = CascadeType.ALL, orphanRemoval = true)
    private java.util.List<AuthorisedSignatory> authorisedSignatories;

    public enum OrgStatus {
        PENDING_VERIFICATION,
        ACTIVE,
        SUSPENDED,
        DEACTIVATED
    }
}