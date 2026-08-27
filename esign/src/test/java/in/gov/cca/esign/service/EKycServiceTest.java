package in.gov.cca.esign.service;

import in.gov.cca.esign.domain.EKycUser;
import in.gov.cca.esign.domain.UserAuthenticationFactor;
import in.gov.cca.esign.model.enums.EKycType;
import in.gov.cca.esign.model.xml.ekyc.EKycRequest;
import in.gov.cca.esign.model.xml.ekyc.EKycResponse;
import in.gov.cca.esign.model.xml.ekyc.SecondFactorRequest;
import in.gov.cca.esign.repository.AuthenticationLogRepository;
import in.gov.cca.esign.repository.EKycUserRepository;
import in.gov.cca.esign.repository.UserAuthenticationFactorRepository;
import in.gov.cca.esign.service.impl.EKycServiceImpl;
import in.gov.cca.esign.util.CryptoUtils;
import in.gov.cca.esign.util.XmlUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EKycServiceTest {

    @Mock
    private EKycUserRepository userRepository;

    @Mock
    private UserAuthenticationFactorRepository authFactorRepository;

    @Mock
    private AuthenticationLogRepository authLogRepository;

    @Mock
    private OtpService otpService;

    @Mock
    private Fido2Service fido2Service;

    @Mock
    private PublicKeyAuthService publicKeyAuthService;

    private EKycServiceImpl ekycService;

    @BeforeEach
    void setUp() {
        ekycService = new EKycServiceImpl(
                userRepository,
                authFactorRepository,
                authLogRepository,
                otpService,
                fido2Service,
                publicKeyAuthService,
                new XmlUtils()
        );

        ReflectionTestUtils.setField(ekycService, "pinHashAlgorithm", "PBKDF2WithHmacSHA256");
        ReflectionTestUtils.setField(ekycService, "pinHashIterations", 100000);
        ReflectionTestUtils.setField(ekycService, "maxFailedAttempts", 5);
        ReflectionTestUtils.setField(ekycService, "lockoutDurationMinutes", 30);
        ReflectionTestUtils.setField(ekycService, "signatureVerificationEnabled", false);
    }

    @Test
    void authenticateUser_ValidPinAndCompositeSecondFactor_ReturnsSuccess() {
        // Given
        EKycRequest request = createValidEkycRequest();
        String requestXml = "<eKycReq>...</eKycReq>";
        String espSignature = "valid-signature";

        EKycUser user = createUser();
        applyValidPinHash(request, user);

        // Provide second factor in composite mode
        String secondFactorXml = "<SecondFactorRequest ver=\"1.0\" signerid=\"testuser@username.ESP001\""
                + " txn=\"TXN_KYC_123\" authenticationType=\"SMSOTP\" consent=\"Y\">"
                + "<SMSOTP>123456</SMSOTP></SecondFactorRequest>";
        request.setSecondFactor(java.util.Base64.getEncoder().encodeToString(secondFactorXml.getBytes()));

        when(userRepository.findByUsername(request.getSignerId())).thenReturn(Optional.of(user));
        when(otpService.verifySmsOtp(anyString(), anyString(), anyString())).thenReturn(true);
        when(authFactorRepository.findByUserAndFactorType(any(), any())).thenReturn(Optional.empty());

        // When
        EKycResponse response = ekycService.authenticateUser(request, requestXml, espSignature);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getStatus()).isEqualTo("1"); // Success
        assertThat(response.getSignerId()).isEqualTo(request.getSignerId());
        assertThat(response.getKycData()).isNotNull();
        assertThat(response.getKycData().getName()).isEqualTo(user.getName());
    }

    @Test
    void authenticateUser_UserNotFound_ReturnsError() {
        // Given
        EKycRequest request = createValidEkycRequest();
        String requestXml = "<eKycReq>...</eKycReq>";
        String espSignature = "valid-signature";

        when(userRepository.findByUsername(request.getSignerId())).thenReturn(Optional.empty());

        // When
        EKycResponse response = ekycService.authenticateUser(request, requestXml, espSignature);

        // Then
        assertThat(response.getStatus()).isEqualTo("0"); // Failure
        assertThat(response.getError()).contains("User not found");
    }

    @Test
    void authenticateUser_InvalidPin_ReturnsError() {
        // Given
        EKycRequest request = createValidEkycRequest();
        String requestXml = "<eKycReq>...</eKycReq>";
        String espSignature = "valid-signature";

        EKycUser user = createUser();
        request.setPinHash("invalid-pin-hash");

        when(userRepository.findByUsername(request.getSignerId())).thenReturn(Optional.of(user));

        // When
        EKycResponse response = ekycService.authenticateUser(request, requestXml, espSignature);

        // Then
        assertThat(response.getStatus()).isEqualTo("0");
        assertThat(response.getError()).contains("Invalid PIN");
        verify(userRepository).save(any(EKycUser.class)); // Failed attempt recorded
    }

    @Test
    void authenticateUser_UserLocked_ReturnsError() {
        // Given
        EKycRequest request = createValidEkycRequest();
        String requestXml = "<eKycReq>...</eKycReq>";
        String espSignature = "valid-signature";

        EKycUser user = createUser();
        user.setLockedUntil(LocalDateTime.now().plusMinutes(10));
        user.setFailedAttempts(5);

        when(userRepository.findByUsername(request.getSignerId())).thenReturn(Optional.of(user));

        // When
        EKycResponse response = ekycService.authenticateUser(request, requestXml, espSignature);

        // Then
        assertThat(response.getStatus()).isEqualTo("0");
        assertThat(response.getError()).contains("Account locked");
    }

    @Test
    void authenticateUser_IndependentMode_ReturnsPending() {
        // Given
        EKycRequest request = createValidEkycRequest();
        request.setSecondFactor(null); // Independent mode
        String requestXml = "<eKycReq>...</eKycReq>";
        String espSignature = "valid-signature";

        EKycUser user = createUser();
        applyValidPinHash(request, user);

        when(userRepository.findByUsername(request.getSignerId())).thenReturn(Optional.of(user));

        // When
        EKycResponse response = ekycService.authenticateUser(request, requestXml, espSignature);

        // Then
        assertThat(response.getStatus()).isEqualTo("2"); // Pending for second factor
        assertThat(response.getResponseCode()).isNotNull();
    }

    @Test
    void authenticateSecondFactor_ValidSmsOtp_ReturnsSuccess() {
        // Given
        SecondFactorRequest request = createSecondFactorRequest("SMSOTP");
        request.setSmsOtp("123456");

        EKycUser user = createUser();
        when(userRepository.findByUsername(request.getSignerId())).thenReturn(Optional.of(user));
        when(otpService.verifySmsOtp(user.getUsername(), "123456", request.getTransactionId())).thenReturn(true);
        when(authFactorRepository.findByUserAndFactorType(any(), any())).thenReturn(Optional.empty());

        // When
        EKycResponse response = ekycService.authenticateSecondFactor(request, request.getTransactionId());

        // Then
        assertThat(response.getStatus()).isEqualTo("1");
        assertThat(response.getKycData()).isNotNull();
    }

    @Test
    void authenticateSecondFactor_InvalidSmsOtp_ReturnsError() {
        // Given
        SecondFactorRequest request = createSecondFactorRequest("SMSOTP");
        request.setSmsOtp("wrong-otp");

        EKycUser user = createUser();
        when(userRepository.findByUsername(request.getSignerId())).thenReturn(Optional.of(user));
        when(otpService.verifySmsOtp(user.getUsername(), "wrong-otp", request.getTransactionId())).thenReturn(false);

        // When
        EKycResponse response = ekycService.authenticateSecondFactor(request, request.getTransactionId());

        // Then
        assertThat(response.getStatus()).isEqualTo("0");
        assertThat(response.getError()).contains("Invalid SMS OTP");
    }

    @Test
    void createUser_HashesPinAndCreatesDefaultSmsFactor() {
        // Given
        EKycUser user = new EKycUser();
        user.setUsername("newuser");
        user.setMobile("9876543210");
        user.setName("New User");
        user.setEkycType(EKycType.OFFLINE_AADHAAR);
        String pin = "123456";

        when(userRepository.save(any(EKycUser.class))).thenAnswer(inv -> inv.getArgument(0));

        // When
        EKycUser created = ekycService.createUser(user, pin);

        // Then
        assertThat(created).isNotNull();
        assertThat(created.getPinHash()).isNotNull().isNotEqualTo(pin);
        assertThat(created.getPinSalt()).isNotNull();
        assertThat(created.getStatus()).isEqualTo(EKycUser.UserStatus.ACTIVE);
        assertThat(created.getAuthenticationFactors()).hasSize(1);
        assertThat(created.getAuthenticationFactors().get(0).getFactorType())
                .isEqualTo(UserAuthenticationFactor.AuthenticationFactorType.SMSOTP);
    }

    @Test
    void verifyMat_ActiveMatFactor_ReturnsTrue() {
        // Given
        EKycUser user = createUser();
        String matToken = "mat-token-abc";
        user.getAuthenticationFactors().add(UserAuthenticationFactor.builder()
                .user(user)
                .factorType(UserAuthenticationFactor.AuthenticationFactorType.MAT)
                .factorData(matToken)
                .status(UserAuthenticationFactor.FactorStatus.ACTIVE)
                .registeredAt(LocalDateTime.now())
                .build());

        when(userRepository.findByUsername(user.getUsername())).thenReturn(Optional.of(user));

        // The factor repository lookup happens inside the service via findByUserAndFactorType
        when(authFactorRepository.findByUserAndFactorType(any(), any()))
                .thenAnswer(inv -> Optional.of(user.getAuthenticationFactors().get(0)));

        // When
        boolean result = ekycService.verifyMat(user.getUsername(), matToken);

        // Then
        assertThat(result).isTrue();
    }

    // Helper methods

    private void applyValidPinHash(EKycRequest request, EKycUser user) {
        String expectedPinHash = CryptoUtils.hash(request.getTransactionId() + user.getPinHash());
        request.setPinHash(expectedPinHash);
    }

    private EKycRequest createValidEkycRequest() {
        EKycRequest request = new EKycRequest();
        request.setVersion("3.3");
        request.setSignerId("testuser@username.ESP001");
        request.setTimestamp(java.time.ZonedDateTime.now().toString());
        request.setTransactionId("TXN_KYC_123");
        return request;
    }

    private SecondFactorRequest createSecondFactorRequest(String authType) {
        SecondFactorRequest request = new SecondFactorRequest();
        request.setVersion("1.0");
        request.setSignerId("testuser@username.ESP001");
        request.setTimestamp(java.time.ZonedDateTime.now().toString());
        request.setTransactionId("TXN_KYC_123");
        request.setAuthenticationType(authType);
        request.setConsent("I hereby authorize this KYC Information authentication.");
        return request;
    }

    private EKycUser createUser() {
        EKycUser user = new EKycUser();
        user.setId(java.util.UUID.randomUUID());
        user.setUsername("testuser@username.ESP001");
        user.setName("Test User");
        user.setMobile("9876543210");
        user.setEmail("test@example.com");
        user.setAddress("123 Test Street");
        user.setStateProvince("Maharashtra");
        user.setCountry("IN");
        user.setPostalCode("400001");
        user.setPan("ABCDE1234F");
        user.setAadhaarLast4("1234");
        user.setDob(java.time.LocalDate.of(1995, 5, 10));
        user.setGender("M");
        user.setPhotograph("base64-photo");
        user.setEkycType(EKycType.OFFLINE_AADHAAR);
        user.setStatus(EKycUser.UserStatus.ACTIVE);
        user.setPinSalt(CryptoUtils.generateSalt());
        user.setPinHash(CryptoUtils.hashPin("123456", user.getPinSalt(), "PBKDF2WithHmacSHA256", 100000));
        user.setFailedAttempts(0);
        user.setAuthenticationFactors(new java.util.ArrayList<>());
        return user;
    }
}