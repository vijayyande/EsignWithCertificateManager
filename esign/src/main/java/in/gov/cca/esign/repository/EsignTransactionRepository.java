package in.gov.cca.esign.repository;

import in.gov.cca.esign.domain.EsignTransaction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface EsignTransactionRepository extends JpaRepository<EsignTransaction, UUID> {

    Optional<EsignTransaction> findByTransactionId(String transactionId);

    Optional<EsignTransaction> findByResponseCode(String responseCode);

    List<EsignTransaction> findByAspIdAndStatus(String aspId, EsignTransaction.TransactionStatus status);

    List<EsignTransaction> findBySignerIdAndStatus(String signerId, EsignTransaction.TransactionStatus status);

    @Query("SELECT t FROM EsignTransaction t WHERE t.createdAt >= :since AND t.status = :status")
    List<EsignTransaction> findExpiredTransactions(@Param("since") LocalDateTime since, @Param("status") EsignTransaction.TransactionStatus status);

    @Query("SELECT t FROM EsignTransaction t WHERE t.status = :status AND t.createdAt < :threshold")
    List<EsignTransaction> findStaleTransactions(@Param("status") EsignTransaction.TransactionStatus status, @Param("threshold") LocalDateTime threshold);

    long countByAspIdAndCreatedAtBetween(String aspId, LocalDateTime start, LocalDateTime end);

    long countByAspId(String aspId);

    long countByAspIdAndStatus(String aspId, EsignTransaction.TransactionStatus status);

    List<EsignTransaction> findTop25ByAspIdOrderByCreatedAtDesc(String aspId);
}