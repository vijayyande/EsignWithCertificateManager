package in.gov.cca.esign.service;

import in.gov.cca.esign.model.CertificateEnrollmentRequest;
import org.springframework.http.ResponseEntity;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;

/**
 * Certificate Manager (CM) integration.
 * <p>
 * Two operations:
 * <ul>
 *   <li>{@link #requestCertificate} — enroll a key pair and get a certificate</li>
 *   <li>{@link #signHash} — send a document hash to the CM which signs it
 *       and returns the PKCS#7 CMS signature + certificate</li>
 * </ul>
 * When the CM is disabled ({@code ca.enabled=false}), both operations fall
 * back to local BouncyCastle self-signed generation.
 */
public interface CertificateService {

    ResponseEntity<Map<String, Object>> requestCertificate(CertificateEnrollmentRequest request);

    X509Certificate generateCertificate(String subjectDN, KeyPair keyPair,
                                         int validityDays, String signatureAlgorithm);

    /**
     * Send a document hash to the CM for signing. The CM generates (or uses
     * an existing) key pair, signs the hash, and returns the PKCS#7 CMS
     * envelope plus the signer certificate.
     *
     * @param documentHash       the raw hash bytes (SHA-256)
     * @param hashAlgorithm      e.g. "SHA-256"
     * @param signerId           the signer identity (used as CN)
     * @param signingAlgorithm   e.g. "SHA256withRSA"
     * @param signingTime        the signing timestamp (browser time)
     * @return result containing the CMS bytes, the certificate, and the key pair
     */
    SignHashResult signHash(byte[] documentHash, String hashAlgorithm,
                            String signerId, String signingAlgorithm,
                            Date signingTime);

    Map<String, Object> settingsSummary();

    record SignHashResult(byte[] cmsBytes, X509Certificate certificate, KeyPair keyPair) {}
}
