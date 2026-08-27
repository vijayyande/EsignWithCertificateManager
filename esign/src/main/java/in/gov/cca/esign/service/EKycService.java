package in.gov.cca.esign.service;

import in.gov.cca.esign.domain.EKycUser;
import in.gov.cca.esign.model.xml.ekyc.EKycRequest;
import in.gov.cca.esign.model.xml.ekyc.EKycResponse;
import in.gov.cca.esign.model.xml.ekyc.SecondFactorRequest;

public interface EKycService {

    EKycResponse authenticateUser(EKycRequest request, String requestXml, String espSignature);

    EKycResponse authenticateSecondFactor(SecondFactorRequest request, String transactionId);

    EKycUser createUser(EKycUser user, String pin);

    EKycUser updateUser(EKycUser user);

    EKycUser getUserByUsername(String username);

    EKycUser getUserByMobile(String mobile);

    boolean verifyPin(String username, String pin, String transactionId);

    void sendSmsOtp(String username, String transactionId);

    void sendEmailOtp(String email, String transactionId);

    boolean verifyTotp(String username, String totp);

    boolean verifyMat(String username, String mat);

    boolean verifyFido2(String username, String assertion);

    boolean verifyPublicKey(String username, String signature, String challenge);
}