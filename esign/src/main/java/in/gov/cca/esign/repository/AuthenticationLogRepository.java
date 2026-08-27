package in.gov.cca.esign.repository;

import in.gov.cca.esign.domain.AuthenticationLog;
import in.gov.cca.esign.domain.EKycUser;
import in.gov.cca.esign.domain.UserAuthenticationFactor;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Repository
public interface AuthenticationLogRepository extends JpaRepository<AuthenticationLog, UUID> {

    List<AuthenticationLog> findByUserOrderByCreatedAtDesc(EKycUser user);

    List<AuthenticationLog> findByTransactionId(String transactionId);

    @Query("SELECT l FROM AuthenticationLog l WHERE l.user = :user AND l.factorType = :factorType AND l.success = false AND l.createdAt >= :since")
    List<AuthenticationLog> findRecentFailedAttempts(@Param("user") EKycUser user, @Param("factorType") AuthenticationLog.AuthMode factorType, @Param("since") LocalDateTime since);

    long countByUserAndFactorTypeAndSuccessFalseAndCreatedAtAfter(EKycUser user, UserAuthenticationFactor.AuthenticationFactorType factorType, LocalDateTime since);
}