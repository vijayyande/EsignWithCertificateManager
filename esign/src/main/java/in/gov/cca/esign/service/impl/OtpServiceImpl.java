package in.gov.cca.esign.service.impl;

import in.gov.cca.esign.domain.EKycUser;
import in.gov.cca.esign.domain.UserAuthenticationFactor;
import in.gov.cca.esign.repository.EKycUserRepository;
import in.gov.cca.esign.repository.UserAuthenticationFactorRepository;
import in.gov.cca.esign.service.OtpService;
import in.gov.cca.esign.util.TokenStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class OtpServiceImpl implements OtpService {

    private final EKycUserRepository userRepository;
    private final UserAuthenticationFactorRepository authFactorRepository;
    private final TokenStore tokenStore;

    @Value("${ekyc.otp.sms.length:6}")
    private int smsOtpLength;

    @Value("${ekyc.otp.sms.validity-minutes:15}")
    private int smsOtpValidityMinutes;

    @Value("${ekyc.otp.totp.algorithm:HmacSHA256}")
    private String totpAlgorithm;

    @Value("${ekyc.otp.totp.digits:6}")
    private int totpDigits;

    @Value("${ekyc.otp.totp.period-seconds:30}")
    private int totpPeriodSeconds;

    @Value("${ekyc.otp.totp.window:1}")
    private int totpWindow;

    private static final SecureRandom secureRandom = new SecureRandom();

    @Override
    public String sendSmsOtp(String username, String transactionId) {
        EKycUser user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

        String otp = generateNumericOtp(smsOtpLength);
        tokenStore.put(smsOtpKey(username, transactionId), otp,
                smsOtpValidityMinutes, TimeUnit.MINUTES);

        log.info("SMS OTP dispatched for user: {} txn: {} (masked: {})",
                username, transactionId, mask(otp));
        return otp;
    }

    @Override
    public String sendEmailOtp(String email, String transactionId) {
        String otp = generateNumericOtp(smsOtpLength);
        tokenStore.put(emailOtpKey(email, transactionId), otp,
                smsOtpValidityMinutes, TimeUnit.MINUTES);

        log.info("Email OTP dispatched for: {} txn: {} (masked: {})",
                email, transactionId, mask(otp));
        return otp;
    }

    @Override
    public boolean verifySmsOtp(String username, String otp, String transactionId) {
        if (otp == null || otp.isBlank()) {
            return false;
        }
        return tokenStore.getAndDelete(smsOtpKey(username, transactionId))
                .map(stored -> constantTimeEquals(stored, otp))
                .orElse(false);
    }

    @Override
    public boolean verifyEmailOtp(String email, String otp, String transactionId) {
        if (otp == null || otp.isBlank()) {
            return false;
        }
        return tokenStore.getAndDelete(emailOtpKey(email, transactionId))
                .map(stored -> constantTimeEquals(stored, otp))
                .orElse(false);
    }

    @Override
    public boolean verifyTotp(String username, String otp) {
        if (otp == null || otp.isBlank()) {
            return false;
        }
        EKycUser user = userRepository.findByUsername(username).orElse(null);
        if (user == null) {
            return false;
        }
        UserAuthenticationFactor factor = authFactorRepository
                .findByUserAndFactorType(user, UserAuthenticationFactor.AuthenticationFactorType.TOTP)
                .orElse(null);

        if (factor == null || factor.getSecretKey() == null) {
            return false;
        }

        long currentTimeStep = getCurrentTimeStep();
        for (int i = -totpWindow; i <= totpWindow; i++) {
            String expectedOtp = generateTotp(factor.getSecretKey(), currentTimeStep + i);
            if (constantTimeEquals(expectedOtp, otp)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String generateTotpSecret(String username) {
        byte[] secret = new byte[20];
        secureRandom.nextBytes(secret);
        String encodedSecret = Base64.getEncoder().encodeToString(secret);

        EKycUser user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

        UserAuthenticationFactor factor = UserAuthenticationFactor.builder()
                .user(user)
                .factorType(UserAuthenticationFactor.AuthenticationFactorType.TOTP)
                .secretKey(encodedSecret)
                .status(UserAuthenticationFactor.FactorStatus.ACTIVE)
                .registeredAt(LocalDateTime.now())
                .build();

        authFactorRepository.save(factor);
        return encodedSecret;
    }

    @Override
    public String getTotpUri(String username, String secret) {
        return String.format(
                "otpauth://totp/eSign:%s?secret=%s&issuer=eSign&algorithm=%s&digits=%d&period=%d",
                username, secret, totpAlgorithm, totpDigits, totpPeriodSeconds);
    }

    private String smsOtpKey(String username, String transactionId) {
        return "sms_otp:" + username + ":" + transactionId;
    }

    private String emailOtpKey(String email, String transactionId) {
        return "email_otp:" + email + ":" + transactionId;
    }

    private String generateNumericOtp(int length) {
        StringBuilder otp = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            otp.append(secureRandom.nextInt(10));
        }
        return otp.toString();
    }

    public String generateTotp(String base64Secret, long timeStep) {
        try {
            byte[] key = Base64.getDecoder().decode(base64Secret);
            byte[] timeBytes = new byte[8];
            long ts = timeStep;
            for (int i = 7; i >= 0; i--) {
                timeBytes[i] = (byte) (ts & 0xFF);
                ts >>= 8;
            }
            Mac mac = Mac.getInstance(totpAlgorithm);
            mac.init(new SecretKeySpec(key, totpAlgorithm));
            byte[] hash = mac.doFinal(timeBytes);

            int offset = hash[hash.length - 1] & 0xF;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);

            int mod = (int) Math.pow(10, totpDigits);
            return String.format("%0" + totpDigits + "d", binary % mod);
        } catch (Exception e) {
            log.error("Error generating TOTP", e);
            return "";
        }
    }

    private long getCurrentTimeStep() {
        return System.currentTimeMillis() / 1000L / totpPeriodSeconds;
    }

    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    private String mask(String otp) {
        return otp.charAt(0) + "****";
    }
}