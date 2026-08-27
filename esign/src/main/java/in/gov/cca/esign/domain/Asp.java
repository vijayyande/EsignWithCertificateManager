package in.gov.cca.esign.domain;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "asps", uniqueConstraints = {
    @UniqueConstraint(name = "uk_asp_id", columnNames = "asp_id")
}, indexes = {
    @Index(name = "idx_asp_status", columnList = "status")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Asp {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "asp_id", nullable = false, length = 100)
    private String aspId;

    @Column(name = "organisation_name", nullable = false, length = 200)
    private String organisationName;

    @Column(name = "contact_email", length = 200)
    private String contactEmail;

    @Column(name = "contact_phone", length = 30)
    private String contactPhone;

    /**
     * ASP X.509 certificate (PEM) used to verify ESP request signatures
     * when signature verification is enabled.
     */
    @Column(name = "certificate_pem", columnDefinition = "TEXT")
    private String certificatePem;

    /** Requests whose responseUrl does not start with this prefix may be rejected. */
    @Column(name = "allowed_response_url_prefix", length = 500)
    private String allowedResponseUrlPrefix;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private AspStatus status;

    @Column(name = "notes", columnDefinition = "TEXT")
    private String notes;

    @CreationTimestamp
    @Column(name = "registered_at", nullable = false, updatable = false)
    private LocalDateTime registeredAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    public enum AspStatus {
        ACTIVE,
        INACTIVE,
        SUSPENDED
    }
}