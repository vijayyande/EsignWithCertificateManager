package in.gov.cca.esign.service.impl;

import in.gov.cca.esign.domain.AuthenticationLog;
import in.gov.cca.esign.domain.EKycUser;
import in.gov.cca.esign.domain.UserAuthenticationFactor;
import in.gov.cca.esign.model.enums.AuthenticationType;
import in.gov.cca.esign.model.enums.EKycType;
import in.gov.cca.esign.model.enums.EsignErrorCode;
import in.gov.cca.esign.model.xml.ekyc.EKycRequest;
import in.gov.cca.esign.model.xml.ekyc.EKycResponse;
import in.gov.cca.esign.model.xml.ekyc.SecondFactorRequest;
import in.gov.cca.esign.repository.AuthenticationLogRepository;
import in.gov.cca.esign.repository.EKycUserRepository;
import in.gov.cca.esign.repository.UserAuthenticationFactorRepository;
import in.gov.cca.esign.service.EKycService;
import in.gov.cca.esign.service.Fido2Service;
import in.gov.cca.esign.service.OtpService;
import in.gov.cca.esign.service.PublicKeyAuthService;
import in.gov.cca.esign.util.CryptoUtils;
import in.gov.cca.esign.util.XmlUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class EKycServiceImpl implements EKycService {

    private static final String ESIGN_VERSION = "3.3";
    private static final DateTimeFormatter IST_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX");
    private static final ZoneId IST = ZoneId.of("Asia/Kolkata");

    private final EKycUserRepository userRepository;
    private final UserAuthenticationFactorRepository authFactorRepository;
    private final AuthenticationLogRepository authLogRepository;
    private final OtpService otpService;
    private final Fido2Service fido2Service;
    private final PublicKeyAuthService publicKeyAuthService;
    private final XmlUtils xmlUtils;

    @Value("${ekyc.pin.hash-algorithm:PBKDF2WithHmacSHA256}")
    private String pinHashAlgorithm;

    @Value("${ekyc.pin.hash-iterations:100000}")
    private int pinHashIterations;

    @Value("${ekyc.authentication.max-failed-attempts:5}")
    private int maxFailedAttempts;

    @Value("${ekyc.authentication.lockout-duration-minutes:30}")
    private int lockoutDurationMinutes;

    @Value("${ekyc.authentication.signature-verification.enabled:true}")
    private boolean signatureVerificationEnabled;

    @Override
    @Transactional
    public EKycResponse authenticateUser(EKycRequest request, String requestXml, String espSignature) {
        log.info("Authenticating user: {} txn: {}", request.getSignerId(), request.getTransactionId());

        if (signatureVerificationEnabled && !verifyEspSignature(requestXml, espSignature)) {
            return buildErrorResponse(request, "XML signature validation failed");
        }

        EKycUser user = userRepository.findByUsername(request.getSignerId()).orElse(null);
        if (user == null) {
            return buildErrorResponse(request, "User not found");
        }

        if (isUserLocked(user)) {
            return buildErrorResponse(request, "Account locked due to failed attempts");
        }

        if (!verifyPinHash(request.getPinHash(), user, request.getTransactionId())) {
            recordFailedAttempt(user, toFactorType(AuthenticationType.SMSOTP), "PIN verification failed");
            return buildErrorResponse(request, "Invalid PIN");
        }

        SecondFactorRequest secondFactor = decodeSecondFactor(request.getSecondFactor());
        if (secondFactor != null) {
            return authenticateSecondFactorInternal(user, secondFactor, request.getTransactionId());
        }

        registerSuccessfulFirstFactor(user);
        return buildPendingResponse(request);
    }

    @Override
    @Transactional
    public EKycResponse authenticateSecondFactor(SecondFactorRequest request, String transactionId) {
        log.info("Authenticating second factor for txn: {}", transactionId);

        AuthenticationType authType;
        try {
            authType = AuthenticationType.fromValue(request.getAuthenticationType());
        } catch (IllegalArgumentException e) {
            return buildErrorResponse(request, "Unsupported authentication type");
        }

        EKycUser user = userRepository.findByUsername(request.getSignerId()).orElse(null);
        if (user == null) {
            return buildErrorResponse(request, "User not found");
        }

        if (request.getConsent() == null || request.getConsent().isBlank()) {
            return buildErrorResponse(request, "Missing consent for KYC authentication");
        }

        return authenticateSecondFactorInternal(user, request, transactionId);
    }

    private EKycResponse authenticateSecondFactorInternal(EKycUser user,
                                                          SecondFactorRequest request,
                                                          String transactionId) {
        AuthenticationType authType;
        try {
            authType = AuthenticationType.fromValue(request.getAuthenticationType());
        } catch (IllegalArgumentException e) {
            return buildErrorResponse(request, "Unsupported authentication type");
        }

        boolean success;
        String failureMessage;
        switch (authType) {
            case SMSOTP -> {
                success = otpService.verifySmsOtp(user.getUsername(), request.getSmsOtp(), transactionId);
                failureMessage = "Invalid SMS OTP";
            }
            case TOTP -> {
                success = otpService.verifyTotp(user.getUsername(), request.getTotp());
                failureMessage = "Invalid TOTP";
            }
            case MAT -> {
                success = verifyMat(user.getUsername(), request.getMat());
                failureMessage = "Invalid Mobile Access Token";
            }
            case FIDO -> {
                success = fido2Service.verifyAssertion(user.getUsername(), request.getFido(), transactionId);
                failureMessage = "FIDO2 verification failed";
            }
            case PUBSIGN -> {
                success = publicKeyAuthService.verifySignature(
                        user.getUsername(), request.getPubSign(), transactionId);
                failureMessage = "Public key verification failed";
            }
            default -> {
                return buildErrorResponse(request, "Unsupported authentication type");
            }
        }

        if (success) {
            recordSuccessfulAuth(user, authType);
            return buildSuccessResponse(user, transactionId);
        }
        recordFailedAttempt(user, toFactorType(authType), failureMessage);
        return buildErrorResponse(request, failureMessage);
    }

    @Override
    @Transactional
    public EKycUser createUser(EKycUser user, String pin) {
        if (user.getUsername() == null || user.getUsername().isBlank()) {
            throw new IllegalArgumentException("Username is required");
        }
        if (pin == null || pin.isBlank()) {
            throw new IllegalArgumentException("PIN is required");
        }
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            throw new IllegalArgumentException("User already exists: " + user.getUsername());
        }

        String salt = CryptoUtils.generateSalt();
        String pinHash = CryptoUtils.hashPin(pin, salt, pinHashAlgorithm, pinHashIterations);

        user.setPinHash(pinHash);
        user.setPinSalt(salt);
        user.setStatus(EKycUser.UserStatus.ACTIVE);
        user.setActivatedAt(LocalDateTime.now());

        if (user.getAuthenticationFactors() == null) {
            user.setAuthenticationFactors(new java.util.ArrayList<>());
        }
        user.getAuthenticationFactors().add(UserAuthenticationFactor.builder()
                .user(user)
                .factorType(UserAuthenticationFactor.AuthenticationFactorType.SMSOTP)
                .status(UserAuthenticationFactor.FactorStatus.ACTIVE)
                .registeredAt(LocalDateTime.now())
                .build());

        log.info("Created eKYC account: {} (type: {})", user.getUsername(),
                user.getEkycType() != null ? user.getEkycType() : EKycType.OFFLINE_AADHAAR);
        return userRepository.save(user);
    }

    @Override
    @Transactional
    public EKycUser updateUser(EKycUser user) {
        return userRepository.save(user);
    }

    @Override
    public EKycUser getUserByUsername(String username) {
        return userRepository.findByUsername(username).orElse(null);
    }

    @Override
    public EKycUser getUserByMobile(String mobile) {
        return userRepository.findByMobile(mobile).orElse(null);
    }

    @Override
    public boolean verifyPin(String username, String pin, String transactionId) {
        EKycUser user = userRepository.findByUsername(username).orElse(null);
        if (user == null) {
            return false;
        }
        String candidate = CryptoUtils.hash(transactionId + user.getPinHash());
        String provided = CryptoUtils.hash(transactionId
                + CryptoUtils.hashPin(pin, user.getPinSalt(), pinHashAlgorithm, pinHashIterations));
        return CryptoUtils.constantTimeEquals(candidate, provided);
    }

    @Override
    public void sendSmsOtp(String username, String transactionId) {
        otpService.sendSmsOtp(username, transactionId);
    }

    @Override
    public void sendEmailOtp(String email, String transactionId) {
        otpService.sendEmailOtp(email, transactionId);
    }

    @Override
    public boolean verifyTotp(String username, String totp) {
        return otpService.verifyTotp(username, totp);
    }

    @Override
    public boolean verifyMat(String username, String mat) {
        EKycUser user = userRepository.findByUsername(username).orElse(null);
        if (user == null || mat == null || mat.isBlank()) {
            return false;
        }
        UserAuthenticationFactor factor = authFactorRepository
                .findByUserAndFactorType(user, UserAuthenticationFactor.AuthenticationFactorType.MAT)
                .orElse(null);

        if (factor == null
                || factor.getStatus() != UserAuthenticationFactor.FactorStatus.ACTIVE
                || factor.getFactorData() == null) {
            return false;
        }
        return factor.getFactorData().equals(mat);
    }

    @Override
    public boolean verifyFido2(String username, String assertion) {
        return fido2Service.verifyAssertion(username, assertion, null);
    }

    @Override
    public boolean verifyPublicKey(String username, String signature, String challenge) {
        return publicKeyAuthService.verifySignature(username, signature, challenge);
    }

    private boolean verifyPinHash(String providedHash, EKycUser user, String transactionId) {
        if (providedHash == null || providedHash.isBlank()) {
            return false;
        }
        String expected = CryptoUtils.hash(transactionId + user.getPinHash());
        return CryptoUtils.constantTimeEquals(providedHash, expected);
    }

    private boolean isUserLocked(EKycUser user) {
        return user.getLockedUntil() != null && user.getLockedUntil().isAfter(LocalDateTime.now());
    }

    private void registerSuccessfulFirstFactor(EKycUser user) {
        user.setFailedAttempts(0);
        userRepository.save(user);
    }

    private void recordFailedAttempt(EKycUser user,
                                     UserAuthenticationFactor.AuthenticationFactorType factorType,
                                     String reason) {
        user.setFailedAttempts(user.getFailedAttempts() == null ? 1 : user.getFailedAttempts() + 1);
        if (user.getFailedAttempts() >= maxFailedAttempts) {
            user.setLockedUntil(LocalDateTime.now().plusMinutes(lockoutDurationMinutes));
        }
        userRepository.save(user);

        authLogRepository.save(AuthenticationLog.builder()
                .user(user)
                .factorType(factorType)
                .authMode(AuthenticationLog.AuthMode.COMPOSITE)
                .success(false)
                .errorCode(EsignErrorCode.AUTHENTICATION_FAILED.getCode())
                .errorMessage(reason)
                .build());
    }

    private void recordSuccessfulAuth(EKycUser user, AuthenticationType authType) {
        user.setFailedAttempts(0);
        user.setLockedUntil(null);
        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);

        UserAuthenticationFactor.AuthenticationFactorType factorType = toFactorType(authType);
        authFactorRepository.findByUserAndFactorType(user, factorType).ifPresent(factor -> {
            factor.setLastUsedAt(LocalDateTime.now());
            factor.setCounter(factor.getCounter() == null ? 1L : factor.getCounter() + 1);
            authFactorRepository.save(factor);
        });

        authLogRepository.save(AuthenticationLog.builder()
                .user(user)
                .factorType(factorType)
                .authMode(AuthenticationLog.AuthMode.COMPOSITE)
                .success(true)
                .build());
    }

    private UserAuthenticationFactor.AuthenticationFactorType toFactorType(AuthenticationType authType) {
        return switch (authType) {
            case SMSOTP -> UserAuthenticationFactor.AuthenticationFactorType.SMSOTP;
            case TOTP -> UserAuthenticationFactor.AuthenticationFactorType.TOTP;
            case MAT -> UserAuthenticationFactor.AuthenticationFactorType.MAT;
            case FIDO -> UserAuthenticationFactor.AuthenticationFactorType.FIDO2;
            case PUBSIGN -> UserAuthenticationFactor.AuthenticationFactorType.PUBLIC_KEY;
        };
    }

    private SecondFactorRequest decodeSecondFactor(String base64Encoded) {
        if (base64Encoded == null || base64Encoded.isBlank()) {
            return null;
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(base64Encoded);
            return xmlUtils.unmarshal(new String(decoded, StandardCharsets.UTF_8),
                    SecondFactorRequest.class);
        } catch (Exception e) {
            log.warn("Could not decode embedded second factor XML: {}", e.getMessage());
            return null;
        }
    }

    private boolean verifyEspSignature(String xmlContent, String espSignature) {
        try {
            return xmlContent != null && espSignature != null && !espSignature.isBlank();
        } catch (Exception e) {
            return false;
        }
    }

    private EKycResponse buildPendingResponse(EKycRequest request) {
        return EKycResponse.builder()
                .version(ESIGN_VERSION)
                .status("2")
                .signerId(request.getSignerId())
                .timestamp(now())
                .transactionId(request.getTransactionId())
                .responseCode(generateResponseCode())
                .build();
    }

    private EKycResponse buildSuccessResponse(EKycUser user, String transactionId) {
        EKycResponse.KycData kycData = EKycResponse.KycData.builder()
                .name(user.getName())
                .mobile(user.getMobile())
                .email(user.getEmail())
                .address(user.getAddress())
                .stateProvince(user.getStateProvince())
                .country(user.getCountry())
                .postalCode(user.getPostalCode())
                .pan(user.getPan())
                .dob(user.getDob() != null ? user.getDob().toString() : null)
                .gender(user.getGender())
                .aadhaar(user.getAadhaarLast4())
                .ekycType(user.getEkycType() != null ? user.getEkycType().getDescription() : null)
                .build();

        return EKycResponse.builder()
                .version(ESIGN_VERSION)
                .status("1")
                .signerId(user.getUsername())
                .timestamp(now())
                .transactionId(transactionId)
                .responseCode(generateResponseCode())
                .kycData(kycData)
                .photo(user.getPhotograph())
                .build();
    }

    private EKycResponse buildErrorResponse(SecondFactorRequest request, String message) {
        return EKycResponse.builder()
                .version(ESIGN_VERSION)
                .status("0")
                .signerId(request != null ? request.getSignerId() : "")
                .timestamp(now())
                .transactionId(request != null ? request.getTransactionId() : "")
                .responseCode(generateResponseCode())
                .error(message)
                .build();
    }

    private EKycResponse buildErrorResponse(EKycRequest request, String message) {
        return EKycResponse.builder()
                .version(ESIGN_VERSION)
                .status("0")
                .signerId(request != null ? request.getSignerId() : "")
                .timestamp(now())
                .transactionId(request != null ? request.getTransactionId() : "")
                .responseCode(generateResponseCode())
                .error(message)
                .build();
    }

    private String generateResponseCode() {
        return "KYC_" + java.util.UUID.randomUUID().toString().replace("-", "")
                .substring(0, 24).toUpperCase();
    }

    private String now() {
        return ZonedDateTime.now(IST).format(IST_FORMATTER);
    }
}