package in.gov.cca.esign.repository;

import in.gov.cca.esign.domain.BankKyc;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface BankKycRepository extends JpaRepository<BankKyc, UUID> {

    Optional<BankKyc> findByTransactionId(String transactionId);

    List<BankKyc> findByAccountNumber(String accountNumber);

    List<BankKyc> findByBankIfscCode(String bankIfscCode);

    List<BankKyc> findByStatus(BankKyc.KycStatus status);

    boolean existsByTransactionId(String transactionId);
}