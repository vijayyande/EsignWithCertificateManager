package in.gov.cca.esign.service.impl;

import in.gov.cca.esign.domain.EKycUser;
import in.gov.cca.esign.domain.UserAuthenticationFactor;
import in.gov.cca.esign.repository.EKycUserRepository;
import in.gov.cca.esign.repository.UserAuthenticationFactorRepository;
import in.gov.cca.esign.service.Fido2Service;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class Fido2ServiceImpl implements Fido2Service {

    private final EKycUserRepository userRepository;
    private final UserAuthenticationFactorRepository authFactorRepository;

    @Value("${ekyc.fido2.rp-id:esign.gov.in}")
    private String rpId;

    @Value("${ekyc.fido2.rp-name:eSign Service Provider}")
    private String rpName;

    @Value("${ekyc.fido2.origin:https://esign.gov.in}")
    private String origin;

    @Override
    public Map<String, Object> startRegistration(String username) {
        EKycUser user = userRepository.findByUsername(username).orElseThrow();

        // Generate challenge
        byte[] challenge = new byte[32];
        new java.security.SecureRandom().nextBytes(challenge);
        String challengeB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);

        // Store challenge in session (Redis in production)
        // For now, we'll return the challenge

        String userId = Base64.getUrlEncoder().withoutPadding().encodeToString(username.getBytes());

        return Map.of(
                "publicKey", Map.of(
                        "rp", Map.of("id", rpId, "name", rpName),
                        "user", Map.of(
                                "id", userId,
                                "name", username,
                                "displayName", user.getName()
                        ),
                        "challenge", challengeB64,
                        "pubKeyCredParams", List.of(
                                Map.of("type", "public-key", "alg", -7), // ES256
                                Map.of("type", "public-key", "alg", -257) // RS256
                        ),
                        "timeout", 60000,
                        "attestation", "none",
                        "authenticatorSelection", Map.of(
                                "authenticatorAttachment", "platform",
                                "userVerification", "required",
                                "residentKey", "preferred"
                        )
                )
        );
    }

    @Override
    public Map<String, Object> finishRegistration(String username, Map<String, Object> attestationResponse) {
        EKycUser user = userRepository.findByUsername(username).orElseThrow();

        // In real implementation:
        // 1. Verify attestation response
        // 2. Extract credential ID and public key
        // 3. Store in database

        // Mock implementation
        String credentialId = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(UUID.randomUUID().toString().getBytes());
        String publicKey = "mock_public_key_" + System.currentTimeMillis();

        UserAuthenticationFactor factor = UserAuthenticationFactor.builder()
                .user(user)
                .factorType(UserAuthenticationFactor.AuthenticationFactorType.FIDO2)
                .credentialId(credentialId)
                .publicKey(publicKey)
                .status(UserAuthenticationFactor.FactorStatus.ACTIVE)
                .registeredAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusYears(1))
                .build();

        authFactorRepository.save(factor);

        return Map.of("success", true, "credentialId", credentialId);
    }

    @Override
    public Map<String, Object> startAuthentication(String username) {
        EKycUser user = userRepository.findByUsername(username).orElseThrow();

        List<UserAuthenticationFactor> credentials = authFactorRepository
                .findAllByUserAndFactorType(user, UserAuthenticationFactor.AuthenticationFactorType.FIDO2);

        if (credentials.isEmpty()) {
            throw new IllegalStateException("No FIDO2 credentials registered for user: " + username);
        }

        // Generate challenge
        byte[] challenge = new byte[32];
        new java.security.SecureRandom().nextBytes(challenge);
        String challengeB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);

        List<String> credentialIds = credentials.stream()
                .map(UserAuthenticationFactor::getCredentialId)
                .collect(Collectors.toList());

        return Map.of(
                "publicKey", Map.of(
                        "challenge", challengeB64,
                        "timeout", 60000,
                        "rpId", rpId,
                        "allowCredentials", credentialIds.stream()
                                .map(id -> Map.of("type", "public-key", "id", id))
                                .collect(Collectors.toList()),
                        "userVerification", "required"
                )
        );
    }

    @Override
    public boolean verifyAssertion(String username, String assertion, String transactionId) {
        // In real implementation:
        // 1. Parse assertion
        // 2. Verify signature using stored public key
        // 3. Verify challenge matches
        // 4. Verify origin and rpId
        // 5. Update counter

        log.info("Verifying FIDO2 assertion for user: {}", username);
        return true; // Mock implementation
    }

    @Override
    public void revokeCredential(String username, String credentialId) {
        EKycUser user = userRepository.findByUsername(username).orElseThrow();

        authFactorRepository.findByCredentialId(credentialId)
                .filter(factor -> factor.getUser().getId().equals(user.getId()))
                .ifPresent(factor -> {
                    factor.setStatus(UserAuthenticationFactor.FactorStatus.REVOKED);
                    authFactorRepository.save(factor);
                });
    }

    @Override
    public List<Map<String, Object>> getUserCredentials(String username) {
        EKycUser user = userRepository.findByUsername(username).orElseThrow();

        return authFactorRepository.findAllByUserAndFactorType(user, UserAuthenticationFactor.AuthenticationFactorType.FIDO2)
                .stream()
                .map(factor -> {
                    Map<String, Object> info = new java.util.HashMap<>();
                    info.put("credentialId", factor.getCredentialId());
                    info.put("registeredAt", factor.getRegisteredAt());
                    info.put("lastUsedAt", factor.getLastUsedAt());
                    info.put("status", factor.getStatus());
                    return info;
                })
                .collect(Collectors.toList());
    }
}