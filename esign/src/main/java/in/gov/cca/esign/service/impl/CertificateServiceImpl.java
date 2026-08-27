package in.gov.cca.esign.service.impl;

import in.gov.cca.esign.model.CertificateEnrollmentRequest;
import in.gov.cca.esign.service.CertificateService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class CertificateServiceImpl implements CertificateService {

    private final RestTemplate caRestTemplate;

    @Value("${ca.enabled:false}")
    private boolean enabled;

    @Value("${ca.base-url:}")
    private String baseUrl;

    @Value("${ca.enroll-path:/api/certificates/request}")
    private String enrollPath;

    @Value("${ca.sign-path:/api/certificates/sign}")
    private String signPath;

    /** none | basic | api-key */
    @Value("${ca.auth-type:none}")
    private String authType;

    @Value("${ca.username:}")
    private String username;

    @Value("${ca.password:}")
    private String password;

    @Value("${ca.api-key-header:X-API-Key}")
    private String apiKeyHeader;

    @Value("${ca.api-key:}")
    private String apiKey;

    @Override
    public ResponseEntity<Map<String, Object>> requestCertificate(CertificateEnrollmentRequest request) {
        if (!enabled) {
            return error(HttpStatus.SERVICE_UNAVAILABLE,
                    "CA integration is disabled — set ca.enabled=true (env CA_ENABLED) to enable");
        }
        if (request == null || request.commonName() == null || request.commonName().isBlank()) {
            return error(HttpStatus.BAD_REQUEST, "commonName is required");
        }
        if (baseUrl == null || baseUrl.isBlank()) {
            return error(HttpStatus.SERVICE_UNAVAILABLE,
                    "CA endpoint not configured — set ca.base-url (env CA_BASE_URL)");
        }

        String url = endpointUrl();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        applyAuthentication(headers);

        try {
            ResponseEntity<Map<String, Object>> response = postForEntity(url, new HttpEntity<>(request, headers));
            log.info("Certificate enrollment for CN='{}' -> HTTP {}",
                    request.commonName(), response.getStatusCode().value());
            return ResponseEntity.status(response.getStatusCode()).body(response.getBody());
        } catch (HttpStatusCodeException ex) {
            log.warn("CA enrollment rejected for CN='{}': HTTP {} {}",
                    request.commonName(), ex.getStatusCode().value(), trim(ex.getResponseBodyAsString()));
            Map<String, Object> body = parseErrorBody(ex.getResponseBodyAsString());
            body.put("httpStatus", ex.getStatusCode().value());
            return ResponseEntity.status(ex.getStatusCode()).body(body);
        } catch (ResourceAccessException ex) {
            log.error("CA unreachable at {}: {}", url, ex.getMessage());
            return error(HttpStatus.BAD_GATEWAY, "CA endpoint unreachable: " + rootMessage(ex));
        }
    }

    @Override
    public X509Certificate generateCertificate(String subjectDN, KeyPair keyPair,
                                                int validityDays, String signatureAlgorithm) {
        if (enabled && baseUrl != null && !baseUrl.isBlank()) {
            return requestFromCa(subjectDN, keyPair, validityDays, signatureAlgorithm);
        }
        return generateSelfSigned(subjectDN, keyPair, validityDays, signatureAlgorithm);
    }

    @Override
    public SignHashResult signHash(byte[] documentHash, String hashAlgorithm,
                                   String signerId, String signingAlgorithm,
                                   Date signingTime) {
        if (enabled && baseUrl != null && !baseUrl.isBlank()) {
            try {
                return signHashViaCa(documentHash, hashAlgorithm, signerId, signingAlgorithm, signingTime);
            } catch (Exception e) {
                log.warn("CM signing failed for '{}', falling back to local: {}",
                        signerId, e.getMessage());
            }
        }
        return signHashLocally(documentHash, signerId, signingAlgorithm, signingTime);
    }

    @Override
    public Map<String, Object> settingsSummary() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("enabled", enabled);
        out.put("endpoint", enabled && baseUrl != null && !baseUrl.isBlank()
                ? endpointUrl()
                : "(not configured)");
        out.put("signEndpoint", enabled && baseUrl != null && !baseUrl.isBlank()
                ? signEndpointUrl()
                : "(not configured)");
        out.put("authType", authType == null || authType.isBlank() ? "none" : authType);
        if ("basic".equalsIgnoreCase(authType)) {
            out.put("username", username);
            out.put("passwordConfigured", password != null && !password.isBlank());
        } else if ("api-key".equalsIgnoreCase(authType)) {
            out.put("apiKeyHeader", apiKeyHeader);
            out.put("apiKeyConfigured", apiKey != null && !apiKey.isBlank());
        }
        return out;
    }

    // ── CM signing ────────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private SignHashResult signHashViaCa(byte[] documentHash, String hashAlgorithm,
                                         String signerId, String signingAlgorithm,
                                         Date signingTime) {
        log.info("CM signing flow for signer='{}': step 1 — request certificate from CM", signerId);

        // Step 1: ask CM to create a certificate + keypair for this signer
        String cmBase = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        applyAuthentication(headers);

        Map<String, Object> certRequest = new LinkedHashMap<>();
        certRequest.put("commonName", "esign-" + signerId);
        certRequest.put("organization", "CCA eSign");
        certRequest.put("country", "IN");
        certRequest.put("keyAlgorithm", "RSA");
        certRequest.put("keySize", 2048);
        certRequest.put("validityDays", 365);
        certRequest.put("requestedBy", username == null || username.isBlank() ? "esign-esp" : username);

        String certUrl = cmBase + "/api/certificates/request";
        ResponseEntity<Map> certResponse = caRestTemplate.postForEntity(
                certUrl, new HttpEntity<>(certRequest, headers), Map.class);

        Map<String, Object> certBody = certResponse.getBody();
        if (certBody == null) {
            throw new RuntimeException("CM /api/certificates/request returned empty response");
        }

        // CM wraps response in { success, message, data: { id, certificatePem, ... } }
        Map<String, Object> data = (Map<String, Object>) certBody.get("data");
        if (data == null) data = certBody;

        Number certIdNum = (Number) data.get("id");
        String certPem = (String) data.getOrDefault("certificatePem",
                data.getOrDefault("certificate", data.getOrDefault("cert", null)));
        if (certIdNum == null || certPem == null) {
            throw new RuntimeException("CM cert response missing id or certificatePem");
        }
        long certId = certIdNum.longValue();
        log.info("CM issued certificate id={} for signer='{}'", certId, signerId);

        // Step 2: fetch the private key from CM
        String keyUrl = cmBase + "/api/certificates/" + certId + "/key";
        HttpHeaders keyHeaders = new HttpHeaders();
        applyAuthentication(keyHeaders);

        ResponseEntity<String> keyResponse = caRestTemplate.exchange(
                keyUrl, org.springframework.http.HttpMethod.GET,
                new HttpEntity<>(keyHeaders), String.class);
        String privateKeyPem = keyResponse.getBody();
        if (privateKeyPem == null || privateKeyPem.isBlank()) {
            throw new RuntimeException("CM /api/certificates/" + certId + "/key returned empty response");
        }
        log.info("CM fetched private key for certificate id={}", certId);

        // Step 3: fetch the full chain (leaf + issuing CAs) so Adobe can build the trust path
        List<X509Certificate> chainCerts = new ArrayList<>();
        try {
            String chainUrl = cmBase + "/api/certificates/" + certId + "/download?format=cer";
            ResponseEntity<String> chainResponse = caRestTemplate.exchange(
                    chainUrl, HttpMethod.GET, new HttpEntity<>(chainHeaders()), String.class);
            String chainPem = chainResponse.getBody();
            if (chainPem != null && !chainPem.isBlank()) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                for (java.security.cert.Certificate c : cf.generateCertificates(
                        new ByteArrayInputStream(chainPem.getBytes()))) {
                    if (c instanceof X509Certificate xc) {
                        chainCerts.add(xc);
                    }
                }
            }
        } catch (Exception e) {
            log.warn("CM chain fetch for cert id={} failed, using leaf only: {}",
                    certId, rootMessage(e));
        }

        // Parse the leaf from the chain (cm-certificate.response.certificatePem) as fallback
        List<X509Certificate> parsedLeaf = new ArrayList<>();
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (java.security.cert.Certificate c : cf.generateCertificates(
                    new ByteArrayInputStream(certPem.getBytes()))) {
                if (c instanceof X509Certificate xc) {
                    parsedLeaf.add(xc);
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse CM certificate PEM", e);
        }
        if (chainCerts.isEmpty()) {
            chainCerts = parsedLeaf;
        }
        X509Certificate cert = chainCerts.get(0);
        log.info("CM chain for cert id={}: {} certificate(s)", certId, chainCerts.size());

        java.security.PrivateKey privateKey;
        try {
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
            String stripped = privateKeyPem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] keyBytes = Base64.getDecoder().decode(stripped);
            java.security.spec.PKCS8EncodedKeySpec keySpec = new java.security.spec.PKCS8EncodedKeySpec(keyBytes);
            privateKey = kf.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse CM private key PEM", e);
        }

        String jcaAlgo = "ECDSA".equalsIgnoreCase(signingAlgorithm) ? "SHA256withECDSA" : "SHA256withRSA";
        KeyPair keyPair = new KeyPair(cert.getPublicKey(), privateKey);

        try {
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            /* messageDigest must equal the supplied document hash — that is what Adobe
               recomputes from the ByteRange-covered bytes. Bouncy would otherwise hash
               the content (the hash itself) again, producing a mismatching digest. */
            generator.addSignerInfoGenerator(
                    signerInfoGenerator(privateKey, cert, jcaAlgo, documentHash));
            for (X509Certificate chainCert : chainCerts) {
                generator.addCertificate(
                        new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(chainCert));
            }

            CMSSignedData signedData = generator.generate(
                    new CMSProcessableByteArray(documentHash), false);

            log.info("CM signing complete for signer='{}': cert id={}, algorithm={}",
                    signerId, certId, jcaAlgo);
            return new SignHashResult(signedData.getEncoded(), cert, keyPair);
        } catch (Exception e) {
            throw new RuntimeException("CMS signature generation failed: " + e.getMessage(), e);
        }
    }

    private SignHashResult signHashLocally(byte[] documentHash, String signerId,
                                           String signingAlgorithm, Date signingTime) {
        try {
            String keyAlg = "ECDSA".equalsIgnoreCase(signingAlgorithm) ? "EC" : "RSA";
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlg, BouncyCastleProvider.PROVIDER_NAME);
            kpg.initialize(2048);
            KeyPair keyPair = kpg.generateKeyPair();

            String jcaAlgo = "ECDSA".equalsIgnoreCase(signingAlgorithm) ? "SHA256withECDSA" : "SHA256withRSA";
            String subjectDN = "CN=" + signerId + ", O=CCA eSign, C=IN";
            X509Certificate cert = generateSelfSigned(subjectDN, keyPair, 365, jcaAlgo);

            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            generator.addSignerInfoGenerator(
                    signerInfoGenerator(keyPair.getPrivate(), cert, jcaAlgo, documentHash));
            generator.addCertificate(
                    new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(cert));

            CMSSignedData signedData = generator.generate(
                    new CMSProcessableByteArray(documentHash), false);

            log.info("Local signing for signer='{}', algorithm={}", signerId, signingAlgorithm);
            return new SignHashResult(signedData.getEncoded(), cert, keyPair);
        } catch (Exception e) {
            throw new RuntimeException("Local signing failed: " + e.getMessage(), e);
        }
    }

    // ── private helpers ───────────────────────────────────────────────────

    /** SignerInfo where the messageDigest attribute equals the supplied document hash
     *  instead of Bouncy re-hashing the CMS content (which would double-hash it). */
    private SignerInfoGenerator signerInfoGenerator(java.security.PrivateKey privateKey,
                                                    X509Certificate cert,
                                                    String jcaAlgo, byte[] documentHash) throws Exception {
        ASN1EncodableVector attrs = new ASN1EncodableVector();
        attrs.add(new Attribute(CMSAttributes.messageDigest,
                new DERSet(new DEROctetString(documentHash))));
        return new JcaSimpleSignerInfoGeneratorBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .setSignedAttributeGenerator(new AttributeTable(attrs))
                .build(jcaAlgo, privateKey, cert);
    }

    @SuppressWarnings("unchecked")
    private X509Certificate requestFromCa(String subjectDN, KeyPair keyPair,
                                          int validityDays, String signatureAlgorithm) {
        String cn = extractCn(subjectDN);
        CertificateEnrollmentRequest req = new CertificateEnrollmentRequest(
                cn, "CCA eSign", null, "IN", null, null, null,
                keyPair.getPublic().getAlgorithm(), 2048,
                validityDays, null, null, null, null, null, null, null,
                null, null, null, null, null, null);
        try {
            ResponseEntity<Map<String, Object>> resp = requestCertificate(req);
            Map<String, Object> body = resp.getBody();
            if (body == null) {
                throw new RuntimeException("CA returned empty response");
            }
            String certPem = (String) body.getOrDefault("certificate",
                    body.getOrDefault("cert", body.getOrDefault("certificatePem", null)));
            if (certPem == null) {
                throw new RuntimeException("CA response missing certificate field");
            }
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(certPem.getBytes()));
        } catch (RuntimeException re) {
            throw re;
        } catch (Exception e) {
            log.warn("CA enrollment failed for CN='{}', falling back to self-signed: {}",
                    cn, e.getMessage());
            return generateSelfSigned(subjectDN, keyPair, validityDays, signatureAlgorithm);
        }
    }

    private X509Certificate generateSelfSigned(String subjectDN, KeyPair keyPair,
                                               int validityDays, String signatureAlgorithm) {
        try {
            X500Name subject = new X500Name(subjectDN);
            X500Name issuer = subject;
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
            Date notBefore = Date.from(Instant.now());
            Date notAfter = Date.from(Instant.now().plus(validityDays, ChronoUnit.DAYS));

            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                    issuer, serial, notBefore, notAfter, subject,
                    SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));

            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                    .build(keyPair.getPrivate());

            org.bouncycastle.cert.X509CertificateHolder holder = builder.build(signer);
            X509Certificate cert = new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(holder);
            log.info("Generated self-signed certificate for CN='{}', valid {} days", extractCn(subjectDN), validityDays);
            return cert;
        } catch (Exception e) {
            log.error("Error generating self-signed certificate for CN='{}'", extractCn(subjectDN), e);
            throw new RuntimeException("Failed to generate certificate", e);
        }
    }

    private String extractCn(String subjectDN) {
        if (subjectDN == null) return "unknown";
        for (String part : subjectDN.split(",")) {
            String trimmed = part.trim();
            if (trimmed.toUpperCase().startsWith("CN=")) {
                return trimmed.substring(3);
            }
        }
        return subjectDN;
    }

    private HttpHeaders chainHeaders() {
        HttpHeaders headers = new HttpHeaders();
        applyAuthentication(headers);
        return headers;
    }

    private void applyAuthentication(HttpHeaders headers) {
        String type = authType == null ? "" : authType.trim().toLowerCase();
        switch (type) {
            case "basic" -> headers.setBasicAuth(username == null ? "" : username,
                    password == null ? "" : password);
            case "api-key" -> {
                if (apiKey != null && !apiKey.isBlank()) {
                    headers.set(apiKeyHeader, apiKey);
                }
            }
            default -> { /* no auth */ }
        }
    }

    @SuppressWarnings("unchecked")
    private ResponseEntity<Map<String, Object>> postForEntity(String url, HttpEntity<CertificateEnrollmentRequest> entity) {
        return (ResponseEntity<Map<String, Object>>) (ResponseEntity<?>) caRestTemplate.postForEntity(url, entity, Map.class);
    }

    private String endpointUrl() {
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        String path = enrollPath == null || enrollPath.isBlank() ? "/api/certificates/request"
                : (enrollPath.startsWith("/") ? enrollPath : "/" + enrollPath);
        return base + path;
    }

    private String signEndpointUrl() {
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        String path = signPath == null || signPath.isBlank() ? "/api/certificates/sign"
                : (signPath.startsWith("/") ? signPath : "/" + signPath);
        return base + path;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> parseErrorBody(String raw) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (raw != null && !raw.isBlank()) {
            try {
                com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
                out = (Map<String, Object>) mapper.readValue(raw, Map.class);
                return out;
            } catch (Exception ignored) {
                out.put("rawResponse", raw);
            }
        }
        return out;
    }

    private ResponseEntity<Map<String, Object>> error(HttpStatus status, String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", message);
        return ResponseEntity.status(status).body(body);
    }

    private String rootMessage(Throwable t) {
        Throwable cur = t;
        while (cur.getCause() != null) {
            cur = cur.getCause();
        }
        return cur.getMessage() == null ? cur.getClass().getSimpleName() : cur.getMessage();
    }

    private String trim(String s) {
        if (s == null) {
            return "";
        }
        return s.length() > 500 ? s.substring(0, 500) + "..." : s;
    }
}
