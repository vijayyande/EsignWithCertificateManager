package in.gov.cca.esign.service;

import in.gov.cca.esign.domain.DocumentSignature;
import in.gov.cca.esign.domain.EsignTransaction;
import in.gov.cca.esign.model.xml.esign.EsignResponse;
import in.gov.cca.esign.repository.EsignTransactionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Date;
import java.util.List;

/**
 * Core signing engine — called after authentication succeeds.
 * <p>
 * Flow:
 * 1. For each document hash → send hash to Certificate Manager (CM) for signing
 * 2. CM generates keypair, generates certificate, signs the hash → returns PKCS#7 CMS + cert
 * 3. Embed RFC 3161 timestamp into each CMS
 * 4. Store results and mark transaction COMPLETED
 * 5. Return the eSign response (CMS data + cert) for ASP to embed into PDF
 * <p>
 * The private key never leaves the CM. eSign is just the orchestration layer.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EsignSigningService {

    private static final DateTimeFormatter IST_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX");
    private static final ZoneId IST = ZoneId.of("Asia/Kolkata");

    private final EsignTransactionRepository transactionRepository;
    private final CertificateService certificateService;
    private final TimestampService timestampService;

    public record SignResult(EsignTransaction transaction, EsignResponse esignResponse, String certificatePem) {}

    /**
     * Sign all document hashes in a transaction by delegating to the CM.
     * Called after the user has been successfully authenticated (PIN + OTP verified).
     *
     * @param transactionId the pending/in-progress transaction
     * @param signerId      authenticated signer identity
     * @param signingTime   the exact time the user authenticated (browser time)
     * @return the signed transaction and eSign response
     */
    @Transactional
    public SignResult signTransaction(String transactionId, String signerId, Date signingTime) {
        EsignTransaction txn = transactionRepository.findByTransactionId(transactionId)
                .orElseThrow(() -> new IllegalArgumentException("Transaction not found: " + transactionId));

        if (txn.getStatus() != EsignTransaction.TransactionStatus.PENDING
                && txn.getStatus() != EsignTransaction.TransactionStatus.IN_PROGRESS) {
            throw new IllegalStateException("Transaction " + transactionId + " is " + txn.getStatus() + " — cannot sign");
        }

        try {
            String certPem = null;

            // 1. For each document hash → send to CM for signing
            for (DocumentSignature doc : txn.getDocumentSignatures()) {
                byte[] hashBytes = Base64.getDecoder().decode(doc.getDocumentHash());

                // CM generates keypair + cert, signs the hash, returns PKCS#7 CMS + cert
                CertificateService.SignHashResult signResult = certificateService.signHash(
                        hashBytes,
                        doc.getHashAlgorithm(),
                        signerId,
                        txn.getSigningAlgorithm(),
                        signingTime);

                // 2. Embed RFC 3161 timestamp into CMS
                byte[] timestampedBytes = timestampService.embedTimestamp(signResult.cmsBytes())
                        .orElse(signResult.cmsBytes());

                doc.setSignatureValue(Base64.getEncoder().encodeToString(timestampedBytes));
                doc.setSignedAt(signingTime.toInstant().atZone(IST).toLocalDateTime());

                // Use the certificate from the first document (all docs share the same cert)
                if (certPem == null && signResult.certificate() != null) {
                    certPem = "-----BEGIN CERTIFICATE-----\n"
                            + Base64.getEncoder().encodeToString(signResult.certificate().getEncoded())
                            + "\n-----END CERTIFICATE-----";
                }
            }

            // 3. Store cert + mark completed
            txn.setStatus(EsignTransaction.TransactionStatus.COMPLETED);
            txn.setSignerId(signerId);
            txn.setUserCertificate(certPem);
            txn.setCompletedAt(LocalDateTime.now());
            transactionRepository.save(txn);
            log.info("Transaction {} signed via CM — {} document(s)", transactionId,
                    txn.getDocumentSignatures().size());

            // 4. Build eSign response
            String now = ZonedDateTime.now(IST).format(IST_FORMATTER);
            List<EsignResponse.DocSignature> docSigs = txn.getDocumentSignatures().stream()
                    .map(d -> EsignResponse.DocSignature.builder()
                            .id(d.getDocumentId())
                            .sigHashAlgorithm(d.getHashAlgorithm())
                            .signatureValue(d.getSignatureValue())
                            .build())
                    .toList();

            EsignResponse esignResponse = EsignResponse.builder()
                    .version("3.3")
                    .status("1")
                    .timestamp(now)
                    .transactionId(transactionId)
                    .responseCode(txn.getResponseCode())
                    .userX509Certificate(certPem)
                    .signatures(EsignResponse.Signatures.builder().docSignatures(docSigs).build())
                    .build();

            return new SignResult(txn, esignResponse, certPem);

        } catch (Exception e) {
            log.error("Signing failed for txn {}", transactionId, e);
            txn.setStatus(EsignTransaction.TransactionStatus.FAILED);
            txn.setErrorCode("199");
            txn.setErrorMessage(e.getMessage());
            transactionRepository.save(txn);
            throw new RuntimeException("Signing failed: " + e.getMessage(), e);
        }
    }
}
