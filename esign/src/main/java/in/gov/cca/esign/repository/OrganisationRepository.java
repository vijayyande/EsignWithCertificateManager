package in.gov.cca.esign.repository;

import in.gov.cca.esign.domain.Organisation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface OrganisationRepository extends JpaRepository<Organisation, UUID> {

    Optional<Organisation> findByName(String name);

    Optional<Organisation> findByKycOrgId(String kycOrgId);

    List<Organisation> findByStatus(Organisation.OrgStatus status);
}