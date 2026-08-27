package in.gov.cca.esign.service.impl;

import in.gov.cca.esign.domain.EKycUser;
import in.gov.cca.esign.domain.UserAuthenticationFactor;
import in.gov.cca.esign.repository.EKycUserRepository;
import in.gov.cca.esign.repository.UserAuthenticationFactorRepository;
import in.gov.cca.esign.service.PublicKeyAuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class PublicKeyAuthServiceImpl implements PublicKeyAuthService {

    private final EKycUserRepository userRepository;
    private final UserAuthenticationFactorRepository authFactorRepository;

    @Value("${ekyc.public-key.max-validity-years:3}")
    private int maxValidityYears;

    @Override
    public String startRegistration(String username, String algorithm) {
        EKycUser user = userRepository.findByUsername(username).orElseThrow();

        // Generate challenge
        byte[] challenge = new byte[32];
        new java.security.SecureRandom().nextBytes(challenge);
        String challengeB64 = Base64.getEncoder().encodeToString(challenge);

        // Store challenge temporarily (Redis in production)
        // Return challenge for client to sign

        return challengeB64;
    }

    @Override
    public boolean finishRegistration(String username, String publicKeyData, String signature) {
        EKycUser user = userRepository.findByUsername(username).orElseThrow();

        try {
            // Verify the signature on the public key data
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyData);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(spec);

            // Verify signature
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(publicKeyBytes);
            boolean valid = sig.verify(Base64.getDecoder().decode(signature));

            if (!valid) {
                log.warn("Public key registration signature verification failed for user: {}", username);
                return false;
            }

            // Store the public key
            UserAuthenticationFactor factor = UserAuthenticationFactor.builder()
                    .user(user)
                    .factorType(UserAuthenticationFactor.AuthenticationFactorType.PUBLIC_KEY)
                    .publicKey(publicKeyData)
                    .status(UserAuthenticationFactor.FactorStatus.ACTIVE)
                    .registeredAt(LocalDateTime.now())
                    .expiresAt(LocalDateTime.now().plusYears(maxValidityYears))
                    .build();

            authFactorRepository.save(factor);

            return true;

        } catch (Exception e) {
            log.error("Error finishing public key registration for user: {}", username, e);
            return false;
        }
    }

    @Override
    public String startAuthentication(String username) {
        // Generate challenge
        byte[] challenge = new byte[32];
        new java.security.SecureRandom().nextBytes(challenge);
        return Base64.getEncoder().encodeToString(challenge);
    }

    @Override
    public boolean verifySignature(String username, String signature, String challenge) {
        Optional<UserAuthenticationFactor> factorOpt = authFactorRepository
                .findByUserAndFactorType(userRepository.findByUsername(username).orElseThrow(),
                        UserAuthenticationFactor.AuthenticationFactorType.PUBLIC_KEY);

        if (factorOpt.isEmpty() || factorOpt.get().getPublicKey() == null) {
            return false;
        }

        try {
            UserAuthenticationFactor factor = factorOpt.get();

            byte[] publicKeyBytes = Base64.getDecoder().decode(factor.getPublicKey());
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(spec);

            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(Base64.getDecoder().decode(challenge));
            return sig.verify(Base64.getDecoder().decode(signature));

        } catch (Exception e) {
            log.error("Error verifying public key signature for user: {}", username, e);
            return false;
        }
    }

    @Override
    public void revokeKey(String username) {
        EKycUser user = userRepository.findByUsername(username).orElseThrow();

        authFactorRepository.findByUserAndFactorType(user, UserAuthenticationFactor.AuthenticationFactorType.PUBLIC_KEY)
                .ifPresent(factor -> {
                    factor.setStatus(UserAuthenticationFactor.FactorStatus.REVOKED);
                    authFactorRepository.save(factor);
                });
    }

    @Override
    public String getRegisteredAlgorithm(String username) {
        return authFactorRepository.findByUserAndFactorType(
                        userRepository.findByUsername(username).orElseThrow(),
                        UserAuthenticationFactor.AuthenticationFactorType.PUBLIC_KEY)
                .map(factor -> "RSA2048") // Default
                .orElse(null);
    }
}