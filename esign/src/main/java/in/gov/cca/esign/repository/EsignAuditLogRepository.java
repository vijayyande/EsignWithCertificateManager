package in.gov.cca.esign.repository;

import in.gov.cca.esign.domain.EsignAuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.UUID;

public interface EsignAuditLogRepository extends JpaRepository<EsignAuditLog, UUID> {

    @Query("""
            select l from EsignAuditLog l
            where (:q is null or lower(l.transactionId) like lower(concat('%', :q, '%'))
                            or lower(l.aspId) like lower(concat('%', :q, '%'))
                            or lower(l.signerId) like lower(concat('%', :q, '%')))
              and (:type is null or l.endpoint = :type)
              and (:outcome is null or l.outcome = :outcome)
              and (:from is null or l.createdAt >= :from)
              and (:to is null or l.createdAt <= :to)
            order by l.createdAt desc
            """)
    Page<EsignAuditLog> search(
            @Param("q") String q,
            @Param("type") EsignAuditLog.RequestType type,
            @Param("outcome") EsignAuditLog.Outcome outcome,
            @Param("from") LocalDateTime from,
            @Param("to") LocalDateTime to,
            Pageable pageable);
}
