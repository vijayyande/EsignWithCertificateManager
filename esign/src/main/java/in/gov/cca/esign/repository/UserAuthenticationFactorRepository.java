package in.gov.cca.esign.repository;

import in.gov.cca.esign.domain.UserAuthenticationFactor;
import in.gov.cca.esign.domain.EKycUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserAuthenticationFactorRepository extends JpaRepository<UserAuthenticationFactor, UUID> {

    List<UserAuthenticationFactor> findByUser(EKycUser user);

    Optional<UserAuthenticationFactor> findByUserAndFactorType(EKycUser user, UserAuthenticationFactor.AuthenticationFactorType factorType);

    List<UserAuthenticationFactor> findAllByUserAndFactorType(EKycUser user, UserAuthenticationFactor.AuthenticationFactorType factorType);

    List<UserAuthenticationFactor> findByUserAndStatus(EKycUser user, UserAuthenticationFactor.FactorStatus status);

    Optional<UserAuthenticationFactor> findByCredentialId(String credentialId);
}