package in.gov.cca.esign.config;

import in.gov.cca.esign.domain.AuthenticationLog;
import in.gov.cca.esign.domain.AuthorisedSignatory;
import in.gov.cca.esign.domain.BankKyc;
import in.gov.cca.esign.domain.DocumentSignature;
import in.gov.cca.esign.domain.EKycUser;
import in.gov.cca.esign.domain.EsignAuditLog;
import in.gov.cca.esign.domain.EsignTransaction;
import in.gov.cca.esign.domain.Organisation;
import in.gov.cca.esign.domain.UserAuthenticationFactor;
import in.gov.cca.esign.domain.Asp;
import in.gov.cca.esign.model.enums.EKycType;
import in.gov.cca.esign.repository.AspRepository;
import in.gov.cca.esign.repository.AuthenticationLogRepository;
import in.gov.cca.esign.repository.BankKycRepository;
import in.gov.cca.esign.repository.EKycUserRepository;
import in.gov.cca.esign.repository.EsignAuditLogRepository;
import in.gov.cca.esign.repository.EsignTransactionRepository;
import in.gov.cca.esign.repository.OrganisationRepository;
import in.gov.cca.esign.util.CryptoUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Seeds one demo row-set into every table at startup. Fully idempotent:
 * each section is skipped when its sentinel row already exists, so the
 * seeder also self-heals a database after an unclean shutdown.
 * Disable with esign.seed-default-data=false (forced off for the test profile).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DefaultDataSeeder implements CommandLineRunner {

    private final AspRepository aspRepository;
    private final OrganisationRepository organisationRepository;
    private final EKycUserRepository userRepository;
    private final EsignTransactionRepository transactionRepository;
    private final BankKycRepository bankKycRepository;
    private final AuthenticationLogRepository authenticationLogRepository;
    private final EsignAuditLogRepository auditLogRepository;

    @Value("${esign.seed-default-data:true}")
    private boolean seedEnabled;

    @Value("${ekyc.pin.hash-algorithm:PBKDF2WithHmacSHA256}")
    private String pinHashAlgorithm;

    @Value("${ekyc.pin.hash-iterations:100000}")
    private int pinHashIterations;

    @Override
    @Transactional
    public void run(String... args) {
        if (!seedEnabled) {
            log.info("Default data seeding disabled (esign.seed-default-data=false)");
            return;
        }
        seedAsps();
        seedOrganisationWithSignatory();
        seedDemoUser();
        seedDemoTransaction();
        seedBankKyc();
        seedEsignAuditLogs();
    }

    /* ------------------------- eSign audit logs ------------------------- */

    private void seedEsignAuditLogs() {
        if (auditLogRepository.count() > 0) {
            return;
        }
        String sampleRequest = """
                <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                <EsignRequest ver="3.3" txn="TXN-DEMO-001" aspId="ASP001" signerid="demosigner" \
                ts="2026-08-24T10:00:00+05:30" maxWaitPeriod="120000" responseUrl="https://acme.example/esign/callback">\
                <Docs hashAlgorithm="SHA256"><InputHash id="1" hashAlgorithm="SHA256" docInfo="DemoAgreement.pdf" \
                docUrl="https://acme.example/docs/demo-agreement.pdf" responseSigType="raw">\
                a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8</InputHash></Docs></EsignRequest>
                """;

        auditLogRepository.save(EsignAuditLog.builder()
                .endpoint(EsignAuditLog.RequestType.SIGN)
                .transactionId("TXN-DEMO-001")
                .aspId("ASP001")
                .signerId("demosigner")
                .remoteIp("127.0.0.1")
                .outcome(EsignAuditLog.Outcome.PENDING)
                .httpStatus(202)
                .documentCount(1)
                .requestBytes(sampleRequest.length())
                .responseSnippet("<EsignResp ver=\"3.3\" status=\"2\" txn=\"TXN-DEMO-001\" resCode=\"RESP-DEMO-001\"/>")
                .requestXml(sampleRequest)
                .build());

        auditLogRepository.save(EsignAuditLog.builder()
                .endpoint(EsignAuditLog.RequestType.STATUS)
                .transactionId("TXN-DEMO-001")
                .aspId("ASP001")
                .remoteIp("127.0.0.1")
                .outcome(EsignAuditLog.Outcome.SUCCESS)
                .httpStatus(200)
                .requestBytes(180)
                .responseSnippet("<EsignResp ver=\"3.3\" status=\"1\" txn=\"TXN-DEMO-001\" resCode=\"RESP-DEMO-001\"/>")
                .build());

        auditLogRepository.save(EsignAuditLog.builder()
                .endpoint(EsignAuditLog.RequestType.AUTH_CALLBACK)
                .transactionId(null)
                .remoteIp("10.20.30.40")
                .outcome(EsignAuditLog.Outcome.REJECTED)
                .httpStatus(400)
                .errorMessage("Invalid txnref format (seeded sample)")
                .responseSnippet("Invalid txnref format")
                .build());

        log.info("Seeded default eSign audit logs (3 entries)");
    }

    /* ---------------------------- ASPs ---------------------------- */

    private void seedAsps() {
        if (!aspRepository.existsByAspId("ASP001")) {
            aspRepository.save(Asp.builder()
                    .aspId("ASP001")
                    .organisationName("Acme Corp Ltd.")
                    .contactEmail("admin@acme.example")
                    .contactPhone("+919812345678")
                    .allowedResponseUrlPrefix("https://acme.example/")
                    .status(Asp.AspStatus.ACTIVE)
                    .notes("Default seeded ASP — primary integration partner")
                    .build());
            log.info("Seeded default ASP ASP001");
        }
        if (!aspRepository.existsByAspId("ASP002")) {
            aspRepository.save(Asp.builder()
                    .aspId("ASP002")
                    .organisationName("Bengal Fintech Solutions Pvt Ltd")
                    .contactEmail("ops@bengalfintech.example")
                    .contactPhone("+919898765432")
                    .allowedResponseUrlPrefix("https://bengalfintech.example/")
                    .status(Asp.AspStatus.ACTIVE)
                    .notes("Default seeded ASP — secondary integration partner")
                    .build());
            log.info("Seeded default ASP ASP002");
        }
    }

    /* -------------------- Organisation + signatory -------------------- */

    private void seedOrganisationWithSignatory() {
        if (organisationRepository.count() > 0) {
            return;
        }
        Organisation org = Organisation.builder()
                .name("Acme Corp Ltd.")
                .address("MG Road 1, Bengaluru 560001, Karnataka, India")
                .kycOrgId("KYCORG-DEMO-001")
                .status(Organisation.OrgStatus.ACTIVE)
                .caOfficer("CCA Demo Officer")
                .verifiedAt(LocalDateTime.now())
                .authorisedSignatories(new ArrayList<>())
                .build();

        AuthorisedSignatory signatory = AuthorisedSignatory.builder()
                .organisation(org)
                .name("Ravi Sharma")
                .orgSigId("ORGSIG-DEMO-001")
                .orgUnit("Finance & Legal")
                .certId("CERT-DEMO-001")
                .certificate("-----BEGIN CERTIFICATE-----\\nDEMOAuthorisedSignatoryCertificate\\n-----END CERTIFICATE-----")
                .status(AuthorisedSignatory.SignatoryStatus.ACTIVE)
                .caOfficer("CCA Demo Officer")
                .verifiedAt(LocalDateTime.now())
                .build();

        org.getAuthorisedSignatories().add(signatory);
        organisationRepository.save(org);
        log.info("Seeded default organisation + authorised signatory");
    }

    /* ------------------------ eKYC user ------------------------ */

    private void seedDemoUser() {
        if (userRepository.findByUsername("demosigner").isPresent()) {
            return;
        }
        String salt = CryptoUtils.generateSalt();
        String pinHash = CryptoUtils.hashPin("123456", salt, pinHashAlgorithm, pinHashIterations);

        UserAuthenticationFactor smsOtp = UserAuthenticationFactor.builder()
                .factorType(UserAuthenticationFactor.AuthenticationFactorType.SMSOTP)
                .factorData("+919999990000")
                .status(UserAuthenticationFactor.FactorStatus.ACTIVE)
                .registeredAt(LocalDateTime.now())
                .build();

        UserAuthenticationFactor totp = UserAuthenticationFactor.builder()
                .factorType(UserAuthenticationFactor.AuthenticationFactorType.TOTP)
                .secretKey("JBSWY3DPEHPK3PXP") // deterministic demo base32 secret
                .status(UserAuthenticationFactor.FactorStatus.ACTIVE)
                .registeredAt(LocalDateTime.now())
                .build();

        EKycUser user = EKycUser.builder()
                .username("demosigner")
                .name("Demo Signer")
                .mobile("+919999990000")
                .email("demosigner@acme.example")
                .address("MG Road 1")
                .stateProvince("Karnataka")
                .country("IN")
                .postalCode("560001")
                .dob(LocalDate.of(1990, 1, 15))
                .gender("M")
                .pan("ABCDE1234F")
                .aadhaarLast4("1234")
                .photograph("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")
                .ekycType(EKycType.OFFLINE_AADHAAR)
                .pinHash(pinHash)
                .pinSalt(salt)
                .status(EKycUser.UserStatus.ACTIVE)
                .activatedAt(LocalDateTime.now())
                .authenticationFactors(new ArrayList<>())
                .build();

        smsOtp.setUser(user);
        totp.setUser(user);
        user.getAuthenticationFactors().add(smsOtp);
        user.getAuthenticationFactors().add(totp);

        EKycUser saved = userRepository.save(user);
        log.info("Seeded default eKYC user 'demosigner' (PIN 123456) with SMSOTP+TOTP factors");

        if (authenticationLogRepository.count() == 0) {
            authenticationLogRepository.save(AuthenticationLog.builder()
                    .user(saved)
                    .transactionId("TXN-DEMO-001")
                    .factorType(UserAuthenticationFactor.AuthenticationFactorType.SMSOTP)
                    .authMode(AuthenticationLog.AuthMode.COMPOSITE)
                    .success(true)
                    .ipAddress("127.0.0.1")
                    .userAgent("DefaultDataSeeder/1.0")
                    .build());
            authenticationLogRepository.save(AuthenticationLog.builder()
                    .user(saved)
                    .transactionId("TXN-DEMO-001")
                    .factorType(UserAuthenticationFactor.AuthenticationFactorType.PUBLIC_KEY)
                    .authMode(AuthenticationLog.AuthMode.INDEPENDENT)
                    .success(false)
                    .errorCode("402")
                    .errorMessage("Seeded sample: public key not registered")
                    .ipAddress("127.0.0.1")
                    .userAgent("DefaultDataSeeder/1.0")
                    .build());
            log.info("Seeded default authentication logs (2 entries)");
        }
    }

    /* --------------------- Transaction + docs --------------------- */

    private void seedDemoTransaction() {
        if (transactionRepository.findByTransactionId("TXN-DEMO-001").isPresent()) {
            return;
        }
        EsignTransaction txn = EsignTransaction.builder()
                .transactionId("TXN-DEMO-001")
                .aspId("ASP001")
                .signerId("demosigner")
                .version("3.3")
                .timestamp(LocalDateTime.now())
                .maxWaitPeriod(120000)
                .responseUrl("https://acme.example/esign/callback")
                .redirectUrl("https://acme.example/esign/redirect")
                .signingAlgorithm("RSA")
                .status(EsignTransaction.TransactionStatus.COMPLETED)
                .responseCode("RESP-DEMO-001")
                .completedAt(LocalDateTime.now())
                .documentSignatures(new ArrayList<>())
                .build();

        DocumentSignature docSig = DocumentSignature.builder()
                .transaction(txn)
                .documentId(1)
                .hashAlgorithm("SHA256")
                .docInfo("DemoAgreement.pdf")
                .docUrl("https://acme.example/docs/demo-agreement.pdf")
                .responseSigType("raw")
                .documentHash("a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8")
                .signatureValue("DEMOBASE64SIGNATUREVALUE==")
                .signedAt(LocalDateTime.now())
                .build();

        txn.getDocumentSignatures().add(docSig);
        transactionRepository.save(txn);
        log.info("Seeded default eSign transaction TXN-DEMO-001 (COMPLETED) + document signature");
    }

    /* -------------------------- Bank KYC -------------------------- */

    private void seedBankKyc() {
        if (bankKycRepository.count() > 0) {
            return;
        }
        bankKycRepository.save(BankKyc.builder()
                .transactionId("BKYC-DEMO-001")
                .bankIfscCode("SBIN0001234")
                .bankName("State Bank of India")
                .accountNumber("XXXXXXXX1234")
                .name("Demo Signer")
                .mobile("+919999990000")
                .email("demosigner@acme.example")
                .address("MG Road 1")
                .stateProvince("Karnataka")
                .country("IN")
                .postalCode("560001")
                .dateOfBirth(LocalDate.of(1990, 1, 15))
                .gender("M")
                .pan("ABCDE1234F")
                .aadhaarLast4("1234")
                .photoFormat("PNG")
                .photo("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")
                .status(BankKyc.KycStatus.VERIFIED)
                .responseCode("BANK-KYC-DEMO-001")
                .processedAt(LocalDateTime.now())
                .build());
        log.info("Seeded default Bank KYC record BKYC-DEMO-001 (VERIFIED)");
    }
}