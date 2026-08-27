package in.gov.cca.esign.service;

public interface OtpService {

    String sendSmsOtp(String username, String transactionId);

    String sendEmailOtp(String email, String transactionId);

    boolean verifySmsOtp(String username, String otp, String transactionId);

    boolean verifyEmailOtp(String email, String otp, String transactionId);

    boolean verifyTotp(String username, String otp);

    String generateTotpSecret(String username);

    String getTotpUri(String username, String secret);
}