package in.gov.cca.esign.service;

import in.gov.cca.esign.domain.EKycUser;
import in.gov.cca.esign.domain.UserAuthenticationFactor;
import in.gov.cca.esign.repository.EKycUserRepository;
import in.gov.cca.esign.repository.UserAuthenticationFactorRepository;
import in.gov.cca.esign.service.impl.OtpServiceImpl;
import in.gov.cca.esign.util.TokenStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OtpServiceTest {

    @Mock
    private EKycUserRepository userRepository;

    @Mock
    private UserAuthenticationFactorRepository authFactorRepository;

    @Mock
    private TokenStore tokenStore;

    private OtpServiceImpl otpService;

    @BeforeEach
    void setUp() {
        otpService = new OtpServiceImpl(userRepository, authFactorRepository, tokenStore);

        ReflectionTestUtils.setField(otpService, "smsOtpLength", 6);
        ReflectionTestUtils.setField(otpService, "smsOtpValidityMinutes", 15);
        ReflectionTestUtils.setField(otpService, "totpAlgorithm", "HmacSHA256");
        ReflectionTestUtils.setField(otpService, "totpDigits", 6);
        ReflectionTestUtils.setField(otpService, "totpPeriodSeconds", 30);
        ReflectionTestUtils.setField(otpService, "totpWindow", 1);
    }

    @Test
    void sendSmsOtp_ValidUser_StoresOtpInTokenStore() {
        // Given
        String username = "testuser";
        String transactionId = "TXN_123";
        EKycUser user = createUser(username);

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(user));

        // When
        String otp = otpService.sendSmsOtp(username, transactionId);

        // Then
        assertThat(otp).hasSize(6).containsOnlyDigits();
        verify(tokenStore).put(
                eq("sms_otp:" + username + ":" + transactionId),
                eq(otp),
                eq(15L),
                eq(TimeUnit.MINUTES)
        );
    }

    @Test
    void sendSmsOtp_UserNotFound_ThrowsException() {
        // Given
        String username = "nonexistent";
        String transactionId = "TXN_123";

        when(userRepository.findByUsername(username)).thenReturn(Optional.empty());

        // When/Then
        try {
            otpService.sendSmsOtp(username, transactionId);
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).contains("User not found");
        }
        verify(tokenStore, never()).put(anyString(), anyString(), anyLong(), any(TimeUnit.class));
    }

    @Test
    void verifySmsOtp_CorrectOtp_ReturnsTrue() {
        // Given
        String username = "testuser";
        String transactionId = "TXN_123";
        String otp = "123456";

        when(tokenStore.getAndDelete("sms_otp:" + username + ":" + transactionId))
                .thenReturn(Optional.of(otp));

        // When
        boolean result = otpService.verifySmsOtp(username, otp, transactionId);

        // Then
        assertThat(result).isTrue();
    }

    @Test
    void verifySmsOtp_IncorrectOtp_ReturnsFalse() {
        // Given
        String username = "testuser";
        String transactionId = "TXN_123";
        String otp = "123456";

        when(tokenStore.getAndDelete("sms_otp:" + username + ":" + transactionId))
                .thenReturn(Optional.of("654321"));

        // When
        boolean result = otpService.verifySmsOtp(username, otp, transactionId);

        // Then
        assertThat(result).isFalse();
    }

    @Test
    void verifySmsOtp_ExpiredOtp_ReturnsFalse() {
        // Given
        String username = "testuser";
        String transactionId = "TXN_123";
        String otp = "123456";

        when(tokenStore.getAndDelete("sms_otp:" + username + ":" + transactionId))
                .thenReturn(Optional.empty());

        // When
        boolean result = otpService.verifySmsOtp(username, otp, transactionId);

        // Then
        assertThat(result).isFalse();
    }

    @Test
    void generateTotpSecret_CreatesFactorAndReturnsSecret() {
        // Given
        String username = "testuser";
        EKycUser user = createUser(username);

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(user));
        when(authFactorRepository.save(any(UserAuthenticationFactor.class))).thenAnswer(inv -> inv.getArgument(0));

        // When
        String secret = otpService.generateTotpSecret(username);

        // Then
        assertThat(secret).isNotNull();
        assertThat(secret.length()).isGreaterThan(0);
        verify(authFactorRepository).save(argThat(factor ->
                factor.getFactorType() == UserAuthenticationFactor.AuthenticationFactorType.TOTP &&
                factor.getSecretKey() != null
        ));
    }

    @Test
    void getTotpUri_ReturnsValidUri() {
        // Given
        String username = "testuser";
        String secret = "JBSWY3DPEHPK3PXP";

        // When
        String uri = otpService.getTotpUri(username, secret);

        // Then
        assertThat(uri).startsWith("otpauth://totp/eSign:");
        assertThat(uri).contains("secret=" + secret);
        assertThat(uri).contains("issuer=eSign");
        assertThat(uri).contains("algorithm=HmacSHA256");
        assertThat(uri).contains("digits=6");
        assertThat(uri).contains("period=30");
    }

    @Test
    void verifyTotp_ValidTotp_ReturnsTrue() {
        // Given
        String username = "testuser";
        EKycUser user = createUser(username);

        // Create a TOTP factor with known secret
        String secret = "JBSWY3DPEHPK3PXP"; // Base32-style test vector (Base64-decodable)
        UserAuthenticationFactor factor = UserAuthenticationFactor.builder()
                .user(user)
                .factorType(UserAuthenticationFactor.AuthenticationFactorType.TOTP)
                .secretKey(secret)
                .status(UserAuthenticationFactor.FactorStatus.ACTIVE)
                .registeredAt(LocalDateTime.now())
                .build();

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(user));
        when(authFactorRepository.findByUserAndFactorType(user, UserAuthenticationFactor.AuthenticationFactorType.TOTP))
                .thenReturn(Optional.of(factor));

        // Generate current TOTP
        String currentOtp = generateCurrentTotp(secret);

        // When
        boolean result = otpService.verifyTotp(username, currentOtp);

        // Then
        assertThat(result).isTrue();
    }

    private String generateCurrentTotp(String secret) {
        return otpService.generateTotp(secret, System.currentTimeMillis() / 1000 / 30);
    }

    private EKycUser createUser(String username) {
        EKycUser user = new EKycUser();
        user.setId(java.util.UUID.randomUUID());
        user.setUsername(username);
        user.setMobile("9876543210");
        return user;
    }
}