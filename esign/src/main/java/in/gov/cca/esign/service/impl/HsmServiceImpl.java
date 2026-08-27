package in.gov.cca.esign.service.impl;

import in.gov.cca.esign.service.HsmService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

@Slf4j
@Service
@RequiredArgsConstructor
public class HsmServiceImpl implements HsmService {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Value("${esign.hsm.provider:SunPKCS11}")
    private String hsmProvider;

    @Value("${esign.hsm.slot:0}")
    private int hsmSlot;

    @Value("${esign.hsm.pin:1234}")
    private String hsmPin;

    @Value("${esign.hsm.key-algorithm:RSA}")
    private String keyAlgorithm;

    @Value("${esign.hsm.key-size:2048}")
    private int keySize;

    @Value("${esign.hsm.library:/usr/lib/softhsm/libsofthsm2.so}")
    private String hsmLibrary;

    private KeyStore hsmKeyStore;
    private volatile Provider pkcs11Provider;

    @Override
    public KeyPair generateKeyPair(String algorithm, int keySize) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm, getProvider());
            keyGen.initialize(keySize);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            log.error("Error generating key pair", e);
            throw new RuntimeException("Failed to generate key pair", e);
        }
    }

    @Override
    public byte[] signData(byte[] data, String keyAlias, String algorithm) {
        try {
            KeyStore keyStore = getKeyStore();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, hsmPin.toCharArray());

            if (privateKey == null) {
                throw new IllegalArgumentException("Private key not found for alias: " + keyAlias);
            }

            Signature signature = Signature.getInstance(algorithm, getProvider());
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();

        } catch (Exception e) {
            log.error("Error signing data with key: {}", keyAlias, e);
            throw new RuntimeException("Failed to sign data", e);
        }
    }

    @Override
    public X509Certificate generateCertificate(String subjectDN, KeyPair keyPair, int validityDays, String signatureAlgorithm) {
        try {
            X500Name subject = new X500Name(subjectDN);
            X500Name issuer = subject; // Self-signed for eSign

            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

            Date notBefore = Date.from(Instant.now());
            Date notAfter = Date.from(Instant.now().plus(validityDays, ChronoUnit.DAYS));

            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                    issuer,
                    serial,
                    notBefore,
                    notAfter,
                    subject,
                    SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())
            );

            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                    .build(keyPair.getPrivate());

            org.bouncycastle.cert.X509CertificateHolder holder = builder.build(signer);
            return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(holder);

        } catch (Exception e) {
            log.error("Error generating certificate", e);
            throw new RuntimeException("Failed to generate certificate", e);
        }
    }

    @Override
    public X509Certificate getCertificate(String alias) {
        try {
            KeyStore keyStore = getKeyStore();
            return (X509Certificate) keyStore.getCertificate(alias);
        } catch (Exception e) {
            log.error("Error getting certificate for alias: {}", alias, e);
            return null;
        }
    }

    @Override
    public List<X509Certificate> getCertificateChain(String alias) {
        try {
            KeyStore keyStore = getKeyStore();
            java.security.cert.Certificate[] chain = keyStore.getCertificateChain(alias);
            List<X509Certificate> certChain = new ArrayList<>();
            if (chain != null) {
                for (java.security.cert.Certificate cert : chain) {
                    certChain.add((X509Certificate) cert);
                }
            }
            return certChain;
        } catch (Exception e) {
            log.error("Error getting certificate chain for alias: {}", alias, e);
            return new ArrayList<>();
        }
    }

    @Override
    public byte[] createPkcs7Signature(byte[] data, String keyAlias, List<X509Certificate> chain, boolean includeCrls) {
        try {
            KeyStore keyStore = getKeyStore();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, hsmPin.toCharArray());

            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .build(privateKey);

            generator.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(
                            new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build()
                    ).build(signer, chain.get(0))
            );

            for (X509Certificate cert : chain) {
                generator.addCertificate(new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(cert));
            }

            CMSSignedData signedData = generator.generate(new CMSProcessableByteArray(data), false);
            return signedData.getEncoded();

        } catch (Exception e) {
            log.error("Error creating PKCS7 signature", e);
            throw new RuntimeException("Failed to create PKCS7 signature", e);
        }
    }

    @Override
    public byte[] createPkcs7PdfSignature(byte[] data, String keyAlias, List<X509Certificate> chain, boolean includeOcsp) {
        // For PDF signatures, we create a CMS signature with specific attributes
        // including OCSP responses and timestamp
        try {
            KeyStore keyStore = getKeyStore();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, hsmPin.toCharArray());

            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .build(privateKey);

            generator.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(
                            new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build()
                    ).build(signer, chain.get(0))
            );

            for (X509Certificate cert : chain) {
                generator.addCertificate(new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(cert));
            }

            // Add OCSP responses if requested
            if (includeOcsp) {
                // In real implementation, fetch OCSP responses for each cert
                log.debug("OCSP responses would be added here");
            }

            CMSSignedData signedData = generator.generate(new CMSProcessableByteArray(data), false);
            return signedData.getEncoded();

        } catch (Exception e) {
            log.error("Error creating PKCS7 PDF signature", e);
            throw new RuntimeException("Failed to create PKCS7 PDF signature", e);
        }
    }

    @Override
    public String getProviderName() {
        return hsmProvider;
    }

    @Override
    public byte[] createPkcs7Signature(byte[] data, PrivateKey privateKey, List<X509Certificate> chain) {
        try {
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .build(privateKey);
            generator.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(
                            new JcaDigestCalculatorProviderBuilder()
                                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build()
                    ).build(signer, chain.get(0))
            );
            for (X509Certificate cert : chain) {
                generator.addCertificate(new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(cert));
            }
            CMSSignedData signedData = generator.generate(new CMSProcessableByteArray(data), false);
            return signedData.getEncoded();
        } catch (Exception e) {
            log.error("Error creating PKCS7 signature with key pair", e);
            throw new RuntimeException("Failed to create PKCS7 signature", e);
        }
    }

    @Override
    public byte[] createPkcs7Signature(byte[] data, PrivateKey privateKey, List<X509Certificate> chain, Date signingTime) {
        try {
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .build(privateKey);

            org.bouncycastle.cms.CMSAttributeTableGenerator attrGen =
                    new org.bouncycastle.cms.CMSAttributeTableGenerator() {
                        @Override
                        @SuppressWarnings("rawtypes")
                        public AttributeTable getAttributes(Map parameters) {
                            AttributeTable table = new org.bouncycastle.cms.DefaultSignedAttributeTableGenerator()
                                    .getAttributes(parameters);
                            return table.add(PKCSObjectIdentifiers.pkcs_9_at_signingTime,
                                    new org.bouncycastle.asn1.cms.Time(signingTime));
                        }
                    };

            JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder()
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME).build());
            builder.setSignedAttributeGenerator(attrGen);
            generator.addSignerInfoGenerator(builder.build(signer, chain.get(0)));
            for (X509Certificate cert : chain) {
                generator.addCertificate(new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(cert));
            }
            CMSSignedData signedData = generator.generate(new CMSProcessableByteArray(data), false);
            return signedData.getEncoded();
        } catch (Exception e) {
            log.error("Error creating PKCS7 signature with signing time", e);
            throw new RuntimeException("Failed to create PKCS7 signature", e);
        }
    }

    private KeyStore getKeyStore() {
        if (hsmKeyStore == null) {
            try {
                hsmKeyStore = KeyStore.getInstance("PKCS11", getProvider());
                hsmKeyStore.load(null, hsmPin.toCharArray());
            } catch (Exception e) {
                log.error("Error initializing HSM KeyStore, falling back to software keystore", e);
                throw new RuntimeException("Failed to initialize HSM", e);
            }
        }
        return hsmKeyStore;
    }

    private Provider getProvider() {
        if ("SunPKCS11".equals(hsmProvider)) {
            if (pkcs11Provider == null) {
                synchronized (this) {
                    if (pkcs11Provider == null) {
                        try {
                            Provider base = Security.getProvider("SunPKCS11");
                            if (base != null) {
                                Provider configured = base.configure(getPkcs11Config());
                                Security.addProvider(configured);
                                pkcs11Provider = configured;
                                log.info("Initialized SunPKCS11 provider: {}", configured.getName());
                            }
                        } catch (Exception e) {
                            log.warn("SunPKCS11 unavailable ({}), using software provider {}",
                                    e.getMessage(), BouncyCastleProvider.PROVIDER_NAME);
                        }
                    }
                }
            }
            return pkcs11Provider != null
                    ? pkcs11Provider
                    : Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        }
        Provider provider = Security.getProvider(hsmProvider);
        return provider != null ? provider : Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    private String getPkcs11Config() {
        String config = String.format(
                "name=eSignHSM%nlibrary=%s%nslot=%d%nshowInfo=true",
                hsmLibrary,
                hsmSlot
        );
        return "--" + config;
    }
}