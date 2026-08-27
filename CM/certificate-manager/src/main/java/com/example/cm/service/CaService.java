package com.example.cm.service;

import com.example.cm.exception.BusinessException;
import com.example.cm.model.dto.CaRequest;
import com.example.cm.model.entity.CaEntity;
import com.example.cm.model.enums.CaType;
import com.example.cm.model.enums.CertificateStatus;
import com.example.cm.model.enums.KeyStorage;
import com.example.cm.model.entity.Pkcs11Settings;
import com.example.cm.repository.CaRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyPair;
import java.time.LocalDateTime;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class CaService {

    private final CaRepository caRepository;
    private final CryptoService cryptoService;
    private final CaKeyService caKeyService;
    private final Pkcs11Service pkcs11Service;
    private final AuditService auditService;

    @Value("${cm.ca.key-size:4096}")
    private int caKeySize;

    @Value("${cm.ca.signature-algorithm:SHA256withRSA}")
    private String caSignatureAlgorithm;

    @Value("${cm.ca.default-validity-days:3650}")
    private int defaultValidityDays;

    @Transactional
    public CaEntity requestCa(CaRequest request) {
        log.info("[SERVICE] CaService.requestCa() called");
        if (caRepository.existsByName(request.getName())) {
            throw new BusinessException("CA with name '" + request.getName() + "' already exists");
        }
        if (request.getCaType() == CaType.INTERMEDIATE && request.getParentCaId() == null) {
            throw new BusinessException("Intermediate CA must reference a parent CA (parentCaId)");
        }
        if (request.getCaType() == CaType.INTERMEDIATE) {
            CaEntity parent = caRepository.findById(request.getParentCaId())
                    .orElseThrow(() -> new BusinessException("Parent CA not found"));
            if (parent.getStatus() != CertificateStatus.ISSUED) {
                throw new BusinessException("Parent CA is not active");
            }
        }
        if (request.getCaType() == CaType.ROOT) {
            boolean hasActiveRoot = caRepository.findAll().stream()
                    .anyMatch(ca -> ca.getCaType() == CaType.ROOT && ca.getStatus() == CertificateStatus.ISSUED);
            if (hasActiveRoot) {
                throw new BusinessException("A root CA is already active. Create an intermediate CA instead.");
            }
        }

        KeyStorage keyStorage = resolveKeyStorage(request);
        if (keyStorage == KeyStorage.PKCS11) {
            Pkcs11Settings settings = pkcs11Service.getSettings();
            if (!settings.isEnabled()
                    || settings.getLibraryPath() == null || settings.getLibraryPath().isBlank()) {
                throw new BusinessException("PKCS#11 key storage requires the PKCS#11 device to be enabled "
                        + "and a library path configured in Settings > PKCS#11 device");
            }
        }

        String keyAlgorithm = cryptoService.normalizeKeyAlgorithm(
                request.getKeyAlgorithm() != null ? request.getKeyAlgorithm() : CryptoService.RSA);
        Integer requestedSize = request.getKeySize() != null && request.getKeySize() > 0
                ? request.getKeySize()
                : (CryptoService.RSA.equals(keyAlgorithm) ? caKeySize : null);
        int keySize = cryptoService.resolveKeySize(keyAlgorithm, requestedSize);
        // EC / EdDSA CAs need a signature algorithm that matches their key type;
        // RSA CAs keep the platform configured value (e.g. SHA256withRSA).
        String signatureAlgorithm = CryptoService.RSA.equals(keyAlgorithm)
                ? caSignatureAlgorithm
                : cryptoService.signatureAlgorithmFor(keyAlgorithm, keySize);

        CaEntity ca = CaEntity.builder()
                .name(request.getName())
                .subjectDn(request.getSubjectDn())
                .caType(request.getCaType())
                .status(CertificateStatus.PENDING)
                .keyAlgorithm(keyAlgorithm)
                .keySize(keySize)
                .signatureAlgorithm(signatureAlgorithm)
                .keyStorage(keyStorage)
                .pkcs11Alias(keyStorage == KeyStorage.PKCS11
                        ? (request.getPkcs11Alias() != null && !request.getPkcs11Alias().isBlank()
                                ? request.getPkcs11Alias() : request.getName())
                        : null)
                .parentCaId(request.getCaType() == CaType.INTERMEDIATE ? request.getParentCaId() : null)
                .requestedBy(request.getRequestedBy())
                .createdAt(LocalDateTime.now())
                .build();
        ca = caRepository.save(ca);

        generateCa(ca, request.getRequestedBy());
        auditService.record(AuditService.currentActor(), "CA", "CA_CREATED",
                "name=" + ca.getName() + ", type=" + ca.getCaType() + ", algorithm=" + ca.getKeyAlgorithm()
                        + ", size=" + ca.getKeySize() + ", storage=" + ca.getKeyStorage());
        log.info("[SERVICE] CaService.requestCa() completed");
        log.info("CA '{}' created and activated", ca.getName());
        return ca;
    }

    @Transactional
    public CaEntity importCa(CaRequest request) {
        log.info("[SERVICE] CaService.importCa() called");
        if (caRepository.existsByName(request.getName())) {
            throw new BusinessException("CA with name '" + request.getName() + "' already exists");
        }
        if (request.getCertificatePem() == null || request.getCertificatePem().isBlank()) {
            throw new BusinessException("Certificate PEM is required for importing an existing CA");
        }

        var holder = cryptoService.parseCertificate(request.getCertificatePem());
        org.bouncycastle.cert.X509CertificateHolder x509 = (org.bouncycastle.cert.X509CertificateHolder) holder;
        org.bouncycastle.asn1.x500.X500Name subject = x509.getSubject();
        String subjectDn = request.getSubjectDn() != null && !request.getSubjectDn().isBlank()
                ? request.getSubjectDn() : subject.toString();

        String serialNumber = x509.getSerialNumber().toString(16).toUpperCase();
        LocalDateTime validFrom = LocalDateTime.ofInstant(
                x509.getNotBefore().toInstant(), java.time.ZoneId.systemDefault());
        LocalDateTime validTo = LocalDateTime.ofInstant(
                x509.getNotAfter().toInstant(), java.time.ZoneId.systemDefault());

        java.security.cert.X509Certificate jcaCert = cryptoService.parseJcaCertificate(request.getCertificatePem());
        String keyAlgorithm = switch (jcaCert.getPublicKey().getAlgorithm()) {
            case "RSA" -> CryptoService.RSA;
            case "EC" -> CryptoService.EC;
            case "Ed25519" -> CryptoService.ED25519;
            case "Ed448" -> CryptoService.ED448;
            default -> CryptoService.RSA;
        };
        String signatureAlgorithm = cryptoService.signatureAlgorithmFor(keyAlgorithm);

        KeyStorage keyStorage = resolveKeyStorage(request);
        if (request.getCaType() == CaType.INTERMEDIATE && request.getParentCaId() == null) {
            throw new BusinessException("Intermediate CA must reference a parent CA (parentCaId)");
        }
        if (request.getCaType() == CaType.INTERMEDIATE && request.getParentCaId() != null) {
            CaEntity parent = caRepository.findById(request.getParentCaId())
                    .orElseThrow(() -> new BusinessException("Parent CA not found"));
            if (parent.getStatus() != CertificateStatus.ISSUED) {
                throw new BusinessException("Parent CA is not active");
            }
        }
        if (request.getCaType() == CaType.ROOT) {
            boolean hasActiveRoot = caRepository.findAll().stream()
                    .anyMatch(ca -> ca.getCaType() == CaType.ROOT && ca.getStatus() == CertificateStatus.ISSUED);
            if (hasActiveRoot) {
                throw new BusinessException("A root CA is already active. Import as intermediate CA instead.");
            }
        }

        if (keyStorage == KeyStorage.PKCS11) {
            Pkcs11Settings settings = pkcs11Service.getSettings();
            if (!settings.isEnabled()
                    || settings.getLibraryPath() == null || settings.getLibraryPath().isBlank()) {
                throw new BusinessException("PKCS#11 key storage requires the PKCS#11 device to be enabled "
                        + "and a library path configured in Settings > PKCS#11 device");
            }
        } else if (keyStorage == KeyStorage.DATABASE) {
            if (request.getPrivateKeyPem() == null || request.getPrivateKeyPem().isBlank()) {
                throw new BusinessException("Private key PEM is required when importing a CA with DATABASE key storage");
            }
        }

        CaEntity ca = CaEntity.builder()
                .name(request.getName())
                .subjectDn(subjectDn)
                .caType(request.getCaType())
                .status(CertificateStatus.PENDING)
                .keyAlgorithm(keyAlgorithm)
                .keySize(null)
                .signatureAlgorithm(signatureAlgorithm)
                .keyStorage(keyStorage)
                .pkcs11Alias(keyStorage == KeyStorage.PKCS11
                        ? (request.getPkcs11Alias() != null && !request.getPkcs11Alias().isBlank()
                                ? request.getPkcs11Alias() : request.getName())
                        : null)
                .parentCaId(request.getCaType() == CaType.INTERMEDIATE ? request.getParentCaId() : null)
                .requestedBy(request.getRequestedBy())
                .createdAt(LocalDateTime.now())
                .build();
        ca = caRepository.save(ca);

        ca.setCertificatePem(request.getCertificatePem());
        ca.setSerialNumber(serialNumber);
        ca.setValidFrom(validFrom);
        ca.setValidTo(validTo);
        ca.setCrlDistributionPoint(cryptoService.getCrlUrlBase() + ca.getId());
        ca.setOcspUrl(cryptoService.getOcspUrl());

        if (keyStorage == KeyStorage.DATABASE) {
            ca.setPrivateKeyPem(request.getPrivateKeyPem());
        }

        ca.setStatus(CertificateStatus.ISSUED);
        ca.setIssuedAt(LocalDateTime.now());
        ca.setApproverName(request.getRequestedBy());
        ca = caRepository.save(ca);

        auditService.record(AuditService.currentActor(), "CA", "CA_IMPORTED",
                "name=" + ca.getName() + ", type=" + ca.getCaType() + ", algorithm=" + ca.getKeyAlgorithm()
                        + ", storage=" + ca.getKeyStorage() + ", serial=" + ca.getSerialNumber());
        log.info("[SERVICE] CaService.importCa() completed");
        log.info("CA '{}' imported and activated (serial {})", ca.getName(), ca.getSerialNumber());
        return ca;
    }

    private KeyStorage resolveKeyStorage(CaRequest request) {
        if (request.getKeyStorage() != null) {
            return request.getKeyStorage();
        }
        Pkcs11Settings settings = pkcs11Service.getSettings();
        return settings.getKeyStorageDefault() != null
                ? settings.getKeyStorageDefault() : KeyStorage.DATABASE;
    }

    private void generateCa(CaEntity ca, String initiatedBy) {
        log.info("[SERVICE] CaService.generateCa() called for ca={}", ca.getName());
        try {
            var generated = caKeyService.generateCaKeys(ca, ca.getPkcs11Alias());
            KeyPair caKeys = generated.keyPair();
            String signerProvider = generated.signerProvider();
            int validityDays = defaultValidityDays;
            LocalDateTime now = LocalDateTime.now();

            if (ca.getCaType() == CaType.ROOT) {
                String certPem = cryptoService.buildSelfSignedCaCertificate(
                        ca.getSubjectDn(), caKeys, validityDays, ca.getSignatureAlgorithm(), true, signerProvider);
                ca.setCertificatePem(certPem);
                if (!caKeyService.isPkcs11(ca)) {
                    ca.setPrivateKeyPem(cryptoService.toPrivateKeyPem(caKeys.getPrivate()));
                }
                ca.setSerialNumber(cryptoService.parseCertificate(certPem).getSerialNumber().toString(16).toUpperCase());
                ca.setValidFrom(now);
                ca.setValidTo(now.plusDays(validityDays));
                caKeyService.storeCaCertificate(ca, caKeys.getPrivate(),
                        cryptoService.parseJcaCertificate(certPem));
            } else {
                CaEntity parent = caRepository.findById(ca.getParentCaId())
                        .orElseThrow(() -> new BusinessException("Parent CA not found"));
                var issuerHolder = cryptoService.parseCertificate(parent.getCertificatePem());
                var issuerKey = caKeyService.signingKey(parent);

                String certPem = cryptoService.buildSignedCaCertificate(
                        ca.getSubjectDn(), caKeys, issuerHolder, issuerKey.key(),
                        parent.getSignatureAlgorithm(), validityDays, issuerKey.signerProvider());
                ca.setCertificatePem(certPem);
                if (!caKeyService.isPkcs11(ca)) {
                    ca.setPrivateKeyPem(cryptoService.toPrivateKeyPem(caKeys.getPrivate()));
                }
                ca.setSerialNumber(cryptoService.parseCertificate(certPem).getSerialNumber().toString(16).toUpperCase());
                ca.setValidFrom(now);
                ca.setValidTo(now.plusDays(validityDays));
                caKeyService.storeCaCertificate(ca, caKeys.getPrivate(),
                        cryptoService.parseJcaCertificate(certPem));
            }

            ca.setStatus(CertificateStatus.ISSUED);
            ca.setIssuedAt(now);
            ca.setApproverName(initiatedBy);
            ca.setCrlDistributionPoint(cryptoService.getCrlUrlBase() + ca.getId());
            ca.setOcspUrl(cryptoService.getOcspUrl());
            caRepository.save(ca);
            log.info("[SERVICE] CaService.generateCa() completed");
            log.info("CA '{}' generated and active", ca.getName());
        } catch (Exception e) {
            log.error("[SERVICE] CaService.generateCa() FAILED: {}", e.getMessage(), e);
            throw new BusinessException("CA generation failed for '" + ca.getName() + "': " + e.getMessage(), e);
        }
    }

    @Transactional(readOnly = true)
    public List<CaEntity> listAll() {
        log.info("[SERVICE] CaService.listAll() called");
        List<CaEntity> result = caRepository.findAll();
        log.info("[SERVICE] CaService.listAll() completed");
        return result;
    }

    @Transactional(readOnly = true)
    public CaEntity get(Long id) {
        log.info("[SERVICE] CaService.get() called with id={}", id);
        CaEntity result = caRepository.findById(id)
                .orElseThrow(() -> new BusinessException("CA not found: " + id));
        log.info("[SERVICE] CaService.get() completed");
        return result;
    }

    @Transactional(readOnly = true)
    public List<CaEntity> listActive() {
        log.info("[SERVICE] CaService.listActive() called");
        List<CaEntity> result = caRepository.findByStatus(CertificateStatus.ISSUED);
        log.info("[SERVICE] CaService.listActive() completed");
        return result;
    }

    @Transactional
    public CaEntity revoke(Long id, String reason, String revokedBy) {
        log.info("[SERVICE] CaService.revoke() called with id={}, reason={}", id, reason);
        CaEntity ca = get(id);
        if (ca.getStatus() != CertificateStatus.ISSUED) {
            throw new BusinessException("Only active CAs can be revoked");
        }
        ca.setStatus(CertificateStatus.REVOKED);
        ca.setApproverName(revokedBy);
        ca = caRepository.save(ca);
        auditService.record(AuditService.currentActor(), "CA", "CA_REVOKED",
                "name=" + ca.getName() + ", reason=" + reason + ", by=" + revokedBy);
        log.info("[SERVICE] CaService.revoke() completed");
        return ca;
    }

    @Transactional
    public CaEntity suspend(Long id, String by) {
        log.info("[SERVICE] CaService.suspend() called with id={}", id);
        CaEntity ca = get(id);
        if (ca.getStatus() != CertificateStatus.ISSUED) {
            throw new BusinessException("Only active CAs can be suspended");
        }
        ca.setStatus(CertificateStatus.SUSPENDED);
        ca.setApproverName(by);
        ca = caRepository.save(ca);
        auditService.record(AuditService.currentActor(), "CA", "CA_SUSPENDED",
                "name=" + ca.getName() + ", by=" + by);
        log.info("[SERVICE] CaService.suspend() completed");
        return ca;
    }

    @Transactional
    public CaEntity resume(Long id, String by) {
        log.info("[SERVICE] CaService.resume() called with id={}", id);
        CaEntity ca = get(id);
        if (ca.getStatus() != CertificateStatus.SUSPENDED) {
            throw new BusinessException("Only suspended CAs can be resumed");
        }
        ca.setStatus(CertificateStatus.ISSUED);
        ca.setApproverName(by);
        ca = caRepository.save(ca);
        auditService.record(AuditService.currentActor(), "CA", "CA_RESUMED",
                "name=" + ca.getName() + ", by=" + by);
        log.info("[SERVICE] CaService.resume() completed");
        return ca;
    }
}
