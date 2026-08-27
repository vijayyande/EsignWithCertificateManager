package in.gov.cca.esign.repository;

import in.gov.cca.esign.domain.Asp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AspRepository extends JpaRepository<Asp, UUID> {

    Optional<Asp> findByAspId(String aspId);

    boolean existsByAspId(String aspId);

    List<Asp> findByStatus(Asp.AspStatus status);

    @Query("SELECT a FROM Asp a WHERE lower(a.aspId) LIKE lower(concat('%', :q, '%')) " +
           "OR lower(a.organisationName) LIKE lower(concat('%', :q, '%')) ORDER BY a.registeredAt DESC")
    List<Asp> search(@Param("q") String q);
}