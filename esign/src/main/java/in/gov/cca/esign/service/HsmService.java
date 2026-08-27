package in.gov.cca.esign.service;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

public interface HsmService {

    KeyPair generateKeyPair(String algorithm, int keySize);

    byte[] signData(byte[] data, String keyAlias, String algorithm);

    X509Certificate generateCertificate(String subjectDN, KeyPair keyPair, int validityDays, String signatureAlgorithm);

    X509Certificate getCertificate(String alias);

    List<X509Certificate> getCertificateChain(String alias);

    byte[] createPkcs7Signature(byte[] data, String keyAlias, List<X509Certificate> chain, boolean includeCrls);

    byte[] createPkcs7PdfSignature(byte[] data, String keyAlias, List<X509Certificate> chain, boolean includeOcsp);

    byte[] createPkcs7Signature(byte[] data, PrivateKey privateKey, List<X509Certificate> chain);

    byte[] createPkcs7Signature(byte[] data, PrivateKey privateKey, List<X509Certificate> chain, Date signingTime);

    String getProviderName();
}