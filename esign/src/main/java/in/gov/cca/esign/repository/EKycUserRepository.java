package in.gov.cca.esign.repository;

import in.gov.cca.esign.domain.EKycUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface EKycUserRepository extends JpaRepository<EKycUser, UUID> {

    Optional<EKycUser> findByUsername(String username);

    Optional<EKycUser> findByMobile(String mobile);

    Optional<EKycUser> findByPan(String pan);

    Optional<EKycUser> findByEmail(String email);

    List<EKycUser> findByStatus(EKycUser.UserStatus status);

    List<EKycUser> findByEkycType(in.gov.cca.esign.model.enums.EKycType ekycType);

    @Query("SELECT u FROM EKycUser u WHERE u.mobile = :mobile AND u.pan = :pan")
    Optional<EKycUser> findByMobileAndPan(@Param("mobile") String mobile, @Param("pan") String pan);

    boolean existsByUsername(String username);

    boolean existsByMobile(String mobile);

    boolean existsByPan(String pan);
}